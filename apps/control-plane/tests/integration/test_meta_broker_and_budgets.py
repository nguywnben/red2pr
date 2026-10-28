"""PostgreSQL 16 + Real-TLS Integration & Security Suite for U16 Meta Muse Broker & Budgets.

Verifies against a real disposable PostgreSQL 16 instance (`pgserver` / `fsync=on`) and real
local `asyncio.start_server` TLS 1.2+ servers (zero live calls to `api.meta.ai`):
- Migration `0012_models_budgets_usage` expand/contract reversibility (`downgrade -> upgrade`),
  `52` `FORCE ROW LEVEL SECURITY` tables (`workspace_model_configs`, `model_capability_snapshots`,
  `budget_accounts`, `budget_reservations`, `usage_ledger`), cross-tenant RLS isolation (`SEC-032`),
  and append-only PL/pgSQL immutability triggers (`SQLSTATE 55000`) on
  `model_capability_snapshots` and `usage_ledger`.
- `T-AGT-01-P` & `T-AGT-01-N`, `A-20`, `S-18`, `S-22`, `ADR-008`, `ADR-020`, `ADR-037`,
  `SEC-012`, `SEC-013`, `SEC-017`, `SEC-018`, `SEC-023`:
  - Write-only Meta API key rotation (`PATCH /api/v1/workspaces/{ws}/models/config`) requires
    fresh 5-minute step-up (`403 step_up_required` without step-up, `200` with step-up), stores
    encrypted secret in `SecretBroker` (`capability="inference"`), never returns plaintext secret
    in `GET /models`, and enforces `If-Match` (`412`) + `Idempotency-Key` replay/mismatch (`409`).
  - Viewer read-only RBAC (`200` on `GET /models`, `403 insufficient_role` on all mutations).
  - Unallowlisted endpoints (`https://api.openai.com/v1`) and unsupported model names
    (`"Wonder Full"`) rejected (`403 meta_endpoint_not_allowlisted` + `security.policy.denied`,
    `422`), never falling back to non-Meta providers (`ADR-008`).
  - Probe/chat without active `inference` consent denied `403` + `security.policy.denied`
    (`SEC-018`); probe/chat without configured pricing denied `409 unknown_model_pricing`.
  - Consented `POST /api/v1/workspaces/{ws}/model-probes` on `muse-spark-1.3` over DNS-pinned
    TLS 1.2+ records `status="available"` + `UsageLedgerModel(status="settled")` and unlocks
    `SetupStepRegistry` `"model_consent"` readiness; revoking `inference` consent immediately
    flips `inference_consent_active=False`, `ready_for_repair_inference=False`, and `ready_repair`
    to `False`.
  - `POST /model-probes` on `muse-wonder-1.0` returning `403` (`probe_wonder_forbidden.json`)
    records `status="unavailable"` and blocks `escalation_enabled=True` (`409
    escalation_model_not_verified`).
  - Upstream `429` (`error_rate_limited_429.json` + `Retry-After: 42`) suspends workspace as
    `suspension_reason="model_unavailable"`, `retry_after_seconds=42`, and releases unexecuted
    budget reservation (`SEC-023`).
  - `complete_chat` structured output (`chat_completion_spark_structured.json`), tool-call
    provenance (`chat_completion_spark_tool_call.json` -> `ModelToolProvenance`), outbound secret
    canary scrubbing (`SEC-017`), upstream CoT (`reasoning_content`) stripping while retaining
    numeric `reasoning_tokens`, recursive `$ref` JSON schema & unsupported wire param (`stop`)
    rejection, cross-origin `302` redirect `Authorization` header stripping (`SEC-033`), and
    redirect SSRF block (`169.254.169.254`).
- `T-AGT-03-P`, `T-AGT-03-N`, `T-NFR-06` & `SEC-033`:
  - `ensure_strict_decimal` rejects binary `float` (`TypeError`); `NFR-06` defaults (`30` calls,
    `120,000` tokens, `2` patch attempts, `1800s` walltime, `$5.00` session cap, `$25.00` daily
    workspace cap) enforced with exact `NUMERIC(18, 6)` arithmetic.
  - 20-way `asyncio.gather` parallel reservation race serialized via `SELECT ... FOR UPDATE`
    without cap overshoot or deadlocks, emitting `usage.budget.exceeded` outbox events (`S-19`).
  - Post-dispatch read timeout marks reservation `unknown_outcome` and writes
    `UsageLedgerModel(status="unknown", settled_cost=None, input_tokens=None, output_tokens=None)`
    while retaining worst-case `unknown_cost` against subsequent calls (`SEC-033`).
  - Mid-session cancellation stops subsequent calls (`0` new upstream requests) and settles
    already in-flight completion with `late_after_cancel=True`.
  - `verify_audit_chain` passes cleanly across global and workspace hash chains with zero leaked
    secret canaries.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import ipaddress
import json
import os
import ssl
import sys
import tempfile
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpcore
import httpx
import pgserver
import pytest
from argon2 import PasswordHasher
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from py_contracts.crypto import KeyRing, MasterKeyRing, export_ed25519_public_key_record
from py_contracts.models import (
    ESCALATION_META_MODEL_ID,
    NFR06_DEFAULT_DAILY_WORKSPACE_COST_USD,
    NFR06_DEFAULT_MAX_CALLS,
    NFR06_DEFAULT_MAX_PATCH_ATTEMPTS,
    NFR06_DEFAULT_MAX_TOKENS,
    NFR06_DEFAULT_MAX_WALL_SECONDS,
    NFR06_DEFAULT_SESSION_COST_USD,
    PRIMARY_META_MODEL_ID,
    BudgetPolicyDefaults,
    MetaChatCompletionRequest,
    MetaChatMessage,
    MetaJsonSchemaSpec,
    MetaResponseFormat,
    MetaToolDefinition,
    MetaToolFunctionDefinition,
    ModelPricingRate,
)
from py_contracts.primitives import Money, new_uuid7
from red2pr_control.analytics_audit.audit_chain import (
    ExternalCheckpointStore,
    verify_audit_chain,
)
from red2pr_control.api.app import create_app
from red2pr_control.core.egress import (
    EgressBlockedError,
    EgressPolicyEngine,
    InMemoryCaBundleResolver,
)
from red2pr_control.core.errors import (
    BadRequestError,
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    UnprocessableEntityError,
)
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.base import (
    AuditLogModel,
    BudgetAccountModel,
    BudgetReservationModel,
    IdempotencyRecordModel,
    MembershipModel,
    ModelCapabilitySnapshotModel,
    OutboxEventModel,
    SchemaMigrationRecordModel,
    UsageLedgerModel,
    UserModel,
    WorkspaceModelConfigModel,
)
from red2pr_control.db.engine import (
    create_admin_engine,
    create_app_engine,
    create_session_factory,
    ensure_compatible_event_loop,
    run_alembic_downgrade,
    run_alembic_upgrade,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.sessions import IamService
from red2pr_control.inference.budgets import (
    AtomicBudgetLedger,
    BudgetExceededError,
    ensure_strict_decimal,
)
from red2pr_control.inference.meta_client import MetaMuseInferenceService
from red2pr_control.operations.setup_wizard import (
    DbEndpointAllowlistProvider,
    SetupStepProbeResult,
    SetupStepRegistry,
)
from red2pr_control.secrets.broker import SecretBroker, SecretBrokerTotpVault

APP_ROLE_NAME = "red2pr_app"
APP_ROLE_PASSWORD = "red2pr_app_local_test_pw_16"
PUBLIC_BASE_URL = "http://127.0.0.1:4286"
ORIGIN_HEADERS = {"Origin": PUBLIC_BASE_URL}
OWNER_CREDENTIAL = "OwnerSup3rStr0ng!Pass#16"
VIEWER_CREDENTIAL = "ViewerSup3rStr0ng!Pass#16"
META_FIXTURES_DIR = Path(__file__).resolve().parents[4] / "contracts" / "fixtures" / "meta"


def _load_meta_fixture_bytes(name: str) -> bytes:
    return (META_FIXTURES_DIR / name).read_bytes()


def _load_meta_fixture_json(name: str) -> dict[str, Any]:
    raw = json.loads((META_FIXTURES_DIR / name).read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return raw


class ManualClock:
    """Deterministic controllable UTC clock for step-up TTL, cooldown & budget window tests."""

    def __init__(self, initial: datetime | None = None) -> None:
        self._current = (initial or datetime(2026, 10, 28, 14, 0, 0, tzinfo=UTC)).astimezone(UTC)

    def __call__(self) -> datetime:
        return self._current

    def advance(self, **delta_kwargs: float) -> datetime:
        self._current = self._current + timedelta(**delta_kwargs)
        return self._current


@dataclass(frozen=True)
class PgTestUrls:
    admin_url: str
    app_url: str


def _build_role_url(base_uri: str, *, username: str, password: str) -> str:
    parsed = urlparse(base_uri)
    host = parsed.hostname or "127.0.0.1"
    port_part = f":{parsed.port}" if parsed.port else ""
    netloc = f"{username}:{password}@{host}{port_part}"
    return urlunparse(
        (
            "postgresql+psycopg",
            netloc,
            parsed.path or "/postgres",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def _csrf_headers(csrf_val: str, *, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    headers = {"X-CSRF-Token": csrf_val, **ORIGIN_HEADERS}
    if extra:
        headers.update(extra)
    return headers


@pytest.fixture(scope="module")
def pg_urls() -> Iterator[PgTestUrls]:
    """Provide a real PostgreSQL 16 test instance via env override or disposable pgserver."""
    ensure_compatible_event_loop()
    external_admin = os.environ.get("RED2PR_TEST_ADMIN_DATABASE_URL")
    if external_admin:
        app_url = os.environ.get("RED2PR_TEST_APP_DATABASE_URL") or _build_role_url(
            external_admin,
            username=APP_ROLE_NAME,
            password=APP_ROLE_PASSWORD,
        )
        yield PgTestUrls(admin_url=external_admin, app_url=app_url)
        return

    with (
        tempfile.TemporaryDirectory(prefix="red2pr_u16_pg16_") as tmp_dir,
        pgserver.get_server(tmp_dir, cleanup_mode="delete") as server,
    ):
        raw_uri = server.get_uri()
        parsed = urlparse(raw_uri)
        admin_url = urlunparse(
            (
                "postgresql+psycopg",
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
        app_url = _build_role_url(
            raw_uri,
            username=APP_ROLE_NAME,
            password=APP_ROLE_PASSWORD,
        )
        yield PgTestUrls(admin_url=admin_url, app_url=app_url)


@pytest.fixture
async def migrated_db(pg_urls: PgTestUrls) -> AsyncIterator[PgTestUrls]:
    """Reset schema cleanly to head before each test function."""
    run_alembic_downgrade(pg_urls.admin_url, "base", app_role_name=APP_ROLE_NAME)
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
    yield pg_urls


@dataclass(frozen=True)
class PkiMaterial:
    ca_pem: str
    server_cert_pem: str
    server_key_pem: str


def _generate_pki_material(dns_names: Sequence[str]) -> PkiMaterial:
    now = dt.datetime.now(tz=UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Red2PR U16 Test Root CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    srv_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_names[0])])
    san = x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names])
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(srv_subject)
        .issuer_name(ca_subject)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(san, critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    return PkiMaterial(
        ca_pem=ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        server_cert_pem=srv_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        server_key_pem=srv_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode("ascii"),
    )


@dataclass
class RecordedMetaWireRequest:
    method: str
    path: str
    headers: dict[str, str]
    body_bytes: bytes
    tls_sni: str | None


AsyncUpstreamHandler = Callable[
    [RecordedMetaWireRequest],
    Awaitable[tuple[int, dict[str, str], bytes]],
]


class LocalAsyncTlsMetaServer:
    """Real `asyncio.start_server` TLS 1.2+ HTTP/1.1 mock Meta server (zero internet)."""

    def __init__(self, *, pki: PkiMaterial, handler: AsyncUpstreamHandler) -> None:
        self._pki = pki
        self._handler = handler
        self._server: asyncio.AbstractServer | None = None
        self.port: int = 0
        self.requests: list[RecordedMetaWireRequest] = []

    async def __aenter__(self) -> LocalAsyncTlsMetaServer:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        sni_holder: dict[ssl.SSLObject, str] = {}

        def _on_servername(
            ssl_obj: ssl.SSLObject,
            server_name: str | None,
            _ctx: ssl.SSLContext,
        ) -> None:
            if server_name is not None:
                sni_holder[ssl_obj] = server_name

        ssl_ctx.sni_callback = _on_servername

        with tempfile.TemporaryDirectory(prefix="red2pr_u16_tls_") as cert_dir:
            cert_path = Path(cert_dir) / "server.pem"
            key_path = Path(cert_dir) / "server.key"
            cert_path.write_text(self._pki.server_cert_pem, encoding="utf-8")
            key_path.write_text(self._pki.server_key_pem, encoding="utf-8")
            ssl_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

        async def _client_cb(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            try:
                with contextlib.suppress(
                    OSError,
                    ssl.SSLError,
                    TimeoutError,
                    asyncio.IncompleteReadError,
                    asyncio.LimitOverrunError,
                ):
                    raw_head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
                    lines = raw_head.decode("latin1").split("\r\n")
                    req_parts = lines[0].split(" ")
                    method = req_parts[0]
                    path = req_parts[1] if len(req_parts) > 1 else "/"
                    hdrs: dict[str, str] = {}
                    for line in lines[1:]:
                        if ":" in line:
                            k, v = line.split(":", 1)
                            hdrs[k.strip().lower()] = v.strip()

                    content_len = int(hdrs.get("content-length", "0"))
                    body_bytes = (
                        await asyncio.wait_for(reader.readexactly(content_len), timeout=5.0)
                        if content_len > 0
                        else b""
                    )

                    ssl_obj = writer.get_extra_info("ssl_object")
                    recorded_sni = sni_holder.pop(ssl_obj, None) if ssl_obj is not None else None
                    rec = RecordedMetaWireRequest(
                        method=method,
                        path=path,
                        headers=hdrs,
                        body_bytes=body_bytes,
                        tls_sni=recorded_sni,
                    )
                    self.requests.append(rec)
                    status_code, resp_hdrs, resp_body = await self._handler(rec)
                    reason = {
                        200: "OK",
                        302: "Found",
                        401: "Unauthorized",
                        403: "Forbidden",
                        429: "Too Many Requests",
                        503: "Service Unavailable",
                    }.get(status_code, "Response")
                    out_lines = [
                        f"HTTP/1.1 {status_code} {reason}",
                        f"Content-Length: {len(resp_body)}",
                        "Connection: close",
                    ]
                    for hk, hv in resp_hdrs.items():
                        out_lines.append(f"{hk}: {hv}")
                    raw_resp = ("\r\n".join(out_lines) + "\r\n\r\n").encode("latin1") + resp_body
                    writer.write(raw_resp)
                    await writer.drain()
            finally:
                writer.close()
                with contextlib.suppress(OSError, ssl.SSLError):
                    await writer.wait_closed()

        self._server = await asyncio.start_server(
            _client_cb,
            host="127.0.0.1",
            port=0,
            ssl=ssl_ctx,
        )
        sockets = self._server.sockets
        assert sockets
        self.port = int(sockets[0].getsockname()[1])
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


class LoopbackTunnelNetworkBackend(httpcore.AsyncNetworkBackend):
    """Verify literal-IP DNS pinning in `EgressSafeHttpClient` while tunneling to loopback TLS."""

    def __init__(self, *, local_port: int) -> None:
        self._local_port = local_port
        self._delegate = httpcore.AnyIOBackend()
        self.connected_targets: list[tuple[str, int]] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        # Prove EgressSafeHttpClient NEVER passes an unpinned hostname to connect_tcp!
        ipaddress.ip_address(host)
        self.connected_targets.append((host, port))
        return await self._delegate.connect_tcp(
            host="127.0.0.1",
            port=self._local_port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        _ = (path, timeout, socket_options)
        raise RuntimeError("Unix sockets not used")

    async def sleep(self, seconds: float) -> None:
        await self._delegate.sleep(seconds)


class ScriptedDnsResolver:
    """Deterministic DNS resolver for `api.meta.ai` & redirect host tests (zero internet DNS)."""

    def __init__(self, answers: Mapping[str, Sequence[Sequence[str]]]) -> None:
        self._queues: dict[str, deque[tuple[str, ...]]] = {
            host.lower(): deque(tuple(batch) for batch in batches)
            for host, batches in answers.items()
        }

    async def resolve(self, host: str, port: int) -> Sequence[str]:
        _ = port
        q = self._queues.get(host.lower())
        if not q:
            return ()
        if len(q) > 1:
            return q.popleft()
        return q[0]


@dataclass
class U16Harness:
    app_engine: AsyncEngine
    app_factory: async_sessionmaker[AsyncSession]
    iam: IamService
    secret_broker: SecretBroker
    budget_ledger: AtomicBudgetLedger
    meta_service: MetaMuseInferenceService
    setup_registry: SetupStepRegistry
    transport: httpx.ASGITransport


def _build_u16_harness(
    app_url: str,
    *,
    clock: ManualClock,
    local_tls_port: int | None = None,
    ca_pem: str | None = None,
    dns_answers: Mapping[str, Sequence[Sequence[str]]] | None = None,
    timeout_seconds: float = 5.0,
    pool_size: int = 12,
    max_overflow: int = 12,
) -> U16Harness:
    app_engine = create_app_engine(app_url, pool_size=pool_size, max_overflow=max_overflow)
    app_factory = create_session_factory(app_engine)
    redactor = Redactor()
    kek_ring = MasterKeyRing(active_version=1, keys={1: b"\x61" * 32})
    secret_broker = SecretBroker(key_ring=kek_ring, redactor=redactor)
    totp_vault = SecretBrokerTotpVault(secret_broker)
    iam = IamService(
        session_factory=app_factory,
        totp_vault=totp_vault,
        iam_seed_key=b"\x71" * 32,
        public_base_url=PUBLIC_BASE_URL,
        clock=clock,
    )
    budget_ledger = AtomicBudgetLedger(
        session_factory=app_factory,
        redactor=redactor,
        clock=clock,
    )
    resolver = ScriptedDnsResolver(
        dns_answers
        or {
            "api.meta.ai": [["157.240.22.35"]],
            "cdn-redirect.meta.example": [["93.184.216.34"]],
        }
    )
    egress_policy = EgressPolicyEngine(
        dns_resolver=resolver,
        allowlist_provider=DbEndpointAllowlistProvider(app_factory),
    )
    ca_resolver = InMemoryCaBundleResolver({"system": ca_pem}) if ca_pem is not None else None
    net_backend = (
        LoopbackTunnelNetworkBackend(local_port=local_tls_port)
        if local_tls_port is not None
        else None
    )
    meta_service = MetaMuseInferenceService(
        iam_service=iam,
        secret_broker=secret_broker,
        budget_ledger=budget_ledger,
        egress_policy=egress_policy,
        ca_bundle_resolver=ca_resolver,
        network_backend=net_backend,
        timeout_seconds=timeout_seconds,
        redactor=redactor,
    )
    setup_registry = SetupStepRegistry()

    async def _ok_probe(_phase: str, _draft: Mapping[str, Any]) -> SetupStepProbeResult:
        return SetupStepProbeResult(probe_status="passed", detail="Verified in U16 harness.")

    setup_registry.register_probe("provider_connect", _ok_probe)
    setup_registry.register_probe("worker_readiness", _ok_probe)

    app = create_app(
        iam_service=iam,
        setup_step_registry=setup_registry,
        meta_inference_service=meta_service,
    )
    transport = httpx.ASGITransport(app=app)
    return U16Harness(
        app_engine=app_engine,
        app_factory=app_factory,
        iam=iam,
        secret_broker=secret_broker,
        budget_ledger=budget_ledger,
        meta_service=meta_service,
        setup_registry=setup_registry,
        transport=transport,
    )


async def _claim_owner_and_create_workspace(
    harness: U16Harness,
    *,
    ws_slug: str = "ws-meta-16",
    ws_name: str = "Meta Muse Workspace 16",
) -> tuple[httpx.AsyncClient, str, str, str]:
    raw_boot, _ = await harness.iam.issue_bootstrap_token()
    client = httpx.AsyncClient(transport=harness.transport, base_url=PUBLIC_BASE_URL)
    pre_csrf = (await client.get("/api/v1/auth/csrf")).json()["csrf_token"]
    claim_resp = await client.post(
        "/api/v1/setup/claim",
        headers=_csrf_headers(pre_csrf),
        json={
            "bootstrap_token": raw_boot,
            "display_name": "Owner U16",
            "email": "owner.u16@red2pr.local",
            "password": OWNER_CREDENTIAL,
        },
    )
    assert claim_resp.status_code == 201, claim_resp.text
    csrf_val = str(claim_resp.json()["csrf_token"])
    owner_id = str(claim_resp.json()["user"]["id"])

    ws_resp = await client.post(
        "/api/v1/workspaces",
        headers=_csrf_headers(csrf_val),
        json={"name": ws_name, "slug": ws_slug},
    )
    assert ws_resp.status_code == 201, ws_resp.text
    ws_id = str(ws_resp.json()["id"])
    return client, csrf_val, owner_id, ws_id


def _spark_and_wonder_pricing_payload() -> dict[str, Any]:
    return {
        PRIMARY_META_MODEL_ID: {
            "pricing_revision": "meta-2026-10",
            "input_per_1m_tokens": {"amount": "0.500000", "currency": "USD"},
            "output_per_1m_tokens": {"amount": "2.000000", "currency": "USD"},
            "configured": True,
        },
        ESCALATION_META_MODEL_ID: {
            "pricing_revision": "meta-2026-10",
            "input_per_1m_tokens": {"amount": "2.500000", "currency": "USD"},
            "output_per_1m_tokens": {"amount": "10.000000", "currency": "USD"},
            "configured": True,
        },
    }


def _spark_pricing_dto() -> ModelPricingRate:
    return ModelPricingRate(
        pricing_revision="meta-2026-10",
        input_per_1m_tokens=Money(amount=Decimal("0.500000"), currency="USD"),
        output_per_1m_tokens=Money(amount=Decimal("2.000000"), currency="USD"),
        configured=True,
    )


# ---------------------------------------------------------------------------
# 1. Migration `0012_models_budgets_usage`, 52 Forced-RLS Tables & Immutability
# ---------------------------------------------------------------------------


async def test_migration_0012_reversibility_rls_isolation_and_append_only_triggers(
    migrated_db: PgTestUrls,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify `0012` downgrade/upgrade, `52` forced-RLS tables, tenant isolation & `55000`."""
    run_alembic_downgrade(
        migrated_db.admin_url,
        "0011_profiles_and_reproduction_runs",
        app_role_name=APP_ROLE_NAME,
    )
    run_alembic_upgrade(
        migrated_db.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )

    admin_engine = create_admin_engine(migrated_db.admin_url)
    try:
        async with admin_engine.connect() as conn:
            forced_rows = (
                await conn.execute(
                    text(
                        "SELECT relname FROM pg_class c "
                        "JOIN pg_namespace n ON n.oid = c.relnamespace "
                        "WHERE n.nspname = 'public' AND c.relkind = 'r' "
                        "AND c.relrowsecurity = true AND c.relforcerowsecurity = true"
                    )
                )
            ).scalars()
            forced_names = set(forced_rows)
            assert len(forced_names) >= 52
            assert {
                "workspace_model_configs",
                "model_capability_snapshots",
                "budget_accounts",
                "budget_reservations",
                "usage_ledger",
            }.issubset(forced_names)

        rec_factory = create_session_factory(admin_engine)
        async with rec_factory() as db:
            rev = await db.scalar(
                select(SchemaMigrationRecordModel).where(
                    SchemaMigrationRecordModel.revision == "0012_models_budgets_usage"
                )
            )
            assert rev is not None
    finally:
        await admin_engine.dispose()

    # Create real tenant rows via API/ledger and prove cross-tenant RLS + append-only triggers
    pki = _generate_pki_material(["api.meta.ai"])
    ca_file = tmp_path / "meta_rls_ca.pem"
    ca_file.write_text(pki.ca_pem, encoding="utf-8")
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_file))

    async def _probe_ok(_req: RecordedMetaWireRequest) -> tuple[int, dict[str, str], bytes]:
        return (
            200,
            {"Content-Type": "application/json", "x-request-id": "req_rls_spark_01"},
            _load_meta_fixture_bytes("probe_spark_available.json"),
        )

    clock = ManualClock()
    async with LocalAsyncTlsMetaServer(pki=pki, handler=_probe_ok) as tls_srv:
        harness = _build_u16_harness(
            migrated_db.app_url,
            clock=clock,
            local_tls_port=tls_srv.port,
            ca_pem=pki.ca_pem,
        )
        try:
            owner_cli, csrf_val, _owner_id, ws_a_id = await _claim_owner_and_create_workspace(
                harness,
                ws_slug="ws-rls-alpha",
                ws_name="RLS Alpha",
            )
            try:
                ws_b_resp = await owner_cli.post(
                    "/api/v1/workspaces",
                    headers=_csrf_headers(csrf_val),
                    json={"name": "RLS Beta", "slug": "ws-rls-beta"},
                )
                assert ws_b_resp.status_code == 201
                ws_b_id = str(ws_b_resp.json()["id"])

                consent_resp = await owner_cli.post(
                    "/api/v1/workspaces/ws-rls-alpha/models/consents",
                    headers=_csrf_headers(
                        csrf_val, extra={"Idempotency-Key": new_uuid7(now=clock())}
                    ),
                    json={
                        "destination": "https://api.meta.ai/v1",
                        "data_classes": ["public", "workspace_internal"],
                        "policy_version": 1,
                    },
                )
                assert consent_resp.status_code == 201, consent_resp.text
                consent_id = str(consent_resp.json()["id"])

                cfg_resp = await owner_cli.patch(
                    "/api/v1/workspaces/ws-rls-alpha/models/config",
                    headers=_csrf_headers(
                        csrf_val,
                        extra={"Idempotency-Key": new_uuid7(now=clock()), "If-Match": '"2"'},
                    ),
                    json={
                        "api_key": "meta_secret_rls_alpha_key_123456",
                        "pricing_updates": _spark_and_wonder_pricing_payload(),
                    },
                )
                assert cfg_resp.status_code == 200, cfg_resp.text

                probe_resp = await owner_cli.post(
                    "/api/v1/workspaces/ws-rls-alpha/model-probes",
                    headers=_csrf_headers(
                        csrf_val, extra={"Idempotency-Key": new_uuid7(now=clock())}
                    ),
                    json={
                        "model_id": PRIMARY_META_MODEL_ID,
                        "consent_id": consent_id,
                        "max_cost": {"amount": "0.050000", "currency": "USD"},
                    },
                )
                assert probe_resp.status_code == 200, probe_resp.text
                snap_id = str(probe_resp.json()["snapshot"]["id"])
                usage_id = str(probe_resp.json()["usage_record"]["id"])
            finally:
                await owner_cli.aclose()

            # 1) Unscoped red2pr_app session sees ZERO rows across all 5 U16 tables
            async with harness.app_factory() as unscoped_db, unscoped_db.begin():
                assert (await unscoped_db.scalars(select(WorkspaceModelConfigModel))).all() == []
                assert (await unscoped_db.scalars(select(ModelCapabilitySnapshotModel))).all() == []
                assert (await unscoped_db.scalars(select(BudgetAccountModel))).all() == []
                assert (await unscoped_db.scalars(select(BudgetReservationModel))).all() == []
                assert (await unscoped_db.scalars(select(UsageLedgerModel))).all() == []

            # 2) Workspace B RLS session sees ZERO Workspace A rows
            async with workspace_rls_session(harness.app_factory, workspace_id=ws_b_id) as ws_b_db:
                assert (await ws_b_db.scalars(select(WorkspaceModelConfigModel))).all() == []
                assert (await ws_b_db.scalars(select(ModelCapabilitySnapshotModel))).all() == []
                assert (await ws_b_db.scalars(select(BudgetAccountModel))).all() == []
                assert (await ws_b_db.scalars(select(BudgetReservationModel))).all() == []
                assert (await ws_b_db.scalars(select(UsageLedgerModel))).all() == []

            # 3) Append-only triggers block UPDATE & DELETE on snapshots and usage_ledger (55000)
            for stmt in (
                update(ModelCapabilitySnapshotModel)
                .where(ModelCapabilitySnapshotModel.id == snap_id)
                .values(status="unavailable"),
                delete(ModelCapabilitySnapshotModel).where(
                    ModelCapabilitySnapshotModel.id == snap_id
                ),
                update(UsageLedgerModel)
                .where(UsageLedgerModel.id == usage_id)
                .values(status="released"),
                delete(UsageLedgerModel).where(UsageLedgerModel.id == usage_id),
            ):
                with pytest.raises(DBAPIError) as exc_info:
                    async with workspace_rls_session(
                        harness.app_factory, workspace_id=ws_a_id
                    ) as ws_a_db:
                        await ws_a_db.execute(stmt)
                assert getattr(exc_info.value.orig, "sqlstate", None) == "55000"
        finally:
            await harness.app_engine.dispose()


# ---------------------------------------------------------------------------
# 2. A-20 HTTP Flows, Consent Gates, Probes, Escalation, Rate Limit & Setup Readiness
# ---------------------------------------------------------------------------


async def test_meta_models_api_step_up_consent_probes_escalation_rate_limit_and_setup_readiness(
    migrated_db: PgTestUrls,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify `T-AGT-01-P`/`N`, `A-20`, `S-18`, `ADR-008`, `SEC-012`, `SEC-013`, `SEC-018`."""
    pki = _generate_pki_material(["api.meta.ai"])
    ca_file = tmp_path / "meta_agt01_ca.pem"
    ca_file.write_text(pki.ca_pem, encoding="utf-8")
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_file))
    next_upstream_mode = "spark_ok"

    async def _upstream_handler(
        req: RecordedMetaWireRequest,
    ) -> tuple[int, dict[str, str], bytes]:
        payload = json.loads(req.body_bytes.decode("utf-8"))
        if next_upstream_mode == "rate_limit_429":
            return (
                429,
                {
                    "Content-Type": "application/json",
                    "Retry-After": "42",
                    "x-request-id": "req_meta_429_01",
                },
                _load_meta_fixture_bytes("error_rate_limited_429.json"),
            )
        if payload.get("model") == ESCALATION_META_MODEL_ID:
            return (
                403,
                {"Content-Type": "application/json", "x-request-id": "req_wonder_403_01"},
                _load_meta_fixture_bytes("probe_wonder_forbidden.json"),
            )
        return (
            200,
            {"Content-Type": "application/json", "x-request-id": "req_spark_200_01"},
            _load_meta_fixture_bytes("probe_spark_available.json"),
        )

    clock = ManualClock()
    async with LocalAsyncTlsMetaServer(pki=pki, handler=_upstream_handler) as tls_srv:
        harness = _build_u16_harness(
            migrated_db.app_url,
            clock=clock,
            local_tls_port=tls_srv.port,
            ca_pem=pki.ca_pem,
        )
        try:
            owner_cli, csrf_val, _owner_id, ws_id = await _claim_owner_and_create_workspace(
                harness,
                ws_slug="ws-agt01",
                ws_name="AGT01 Workspace",
            )
            viewer_cli = httpx.AsyncClient(transport=harness.transport, base_url=PUBLIC_BASE_URL)
            try:
                # Seed a Viewer user in ws-agt01 to verify read-only RBAC
                viewer_id = new_uuid7(now=clock())
                pwd_hash = PasswordHasher().hash(VIEWER_CREDENTIAL)
                async with instance_rls_session(
                    harness.app_factory, mode="instance_admin"
                ) as admin_db:
                    admin_db.add(
                        UserModel(
                            id=viewer_id,
                            username="viewer-u16",
                            email="viewer.u16@red2pr.local",
                            display_name="Viewer U16",
                            password_hash=pwd_hash,
                            is_instance_owner=False,
                            status="active",
                            created_at=clock(),
                            updated_at=clock(),
                        )
                    )
                    await admin_db.flush()
                    admin_db.add(
                        MembershipModel(
                            id=new_uuid7(now=clock()),
                            workspace_id=ws_id,
                            user_id=viewer_id,
                            role="viewer",
                            created_at=clock(),
                            updated_at=clock(),
                        )
                    )

                v_csrf0 = (await viewer_cli.get("/api/v1/auth/csrf")).json()["csrf_token"]
                v_login = await viewer_cli.post(
                    "/api/v1/auth/login",
                    headers=_csrf_headers(v_csrf0),
                    json={"identifier": "viewer.u16@red2pr.local", "password": VIEWER_CREDENTIAL},
                )
                assert v_login.status_code == 200, v_login.text
                v_csrf = str(v_login.json()["csrf_token"])

                # 1) Initial GET /models has default NFR-06 caps, configured=False, ready=False
                init_get = await owner_cli.get("/api/v1/workspaces/ws-agt01/models")
                assert init_get.status_code == 200, init_get.text
                init_state = init_get.json()
                assert init_state["endpoint_base_url"] == "https://api.meta.ai/v1"
                assert init_state["api_key_presence"] == {
                    "configured": False,
                    "secret_version": None,
                }
                assert init_state["ready_for_repair_inference"] is False
                assert init_state["budget_policy"]["max_calls_per_session"] == (
                    NFR06_DEFAULT_MAX_CALLS
                )
                assert init_state["budget_policy"]["max_tokens_per_session"] == (
                    NFR06_DEFAULT_MAX_TOKENS
                )
                assert init_state["budget_policy"]["max_patch_attempts"] == (
                    NFR06_DEFAULT_MAX_PATCH_ATTEMPTS
                )
                assert init_state["budget_policy"]["max_wall_seconds"] == (
                    NFR06_DEFAULT_MAX_WALL_SECONDS
                )
                assert init_state["budget_policy"]["max_cost_per_session"]["amount"] == str(
                    NFR06_DEFAULT_SESSION_COST_USD
                )
                assert init_state["budget_policy"]["daily_workspace_cap"]["amount"] == str(
                    NFR06_DEFAULT_DAILY_WORKSPACE_COST_USD
                )

                # Viewer can GET /models (200) and is forbidden from mutating (403)
                assert (
                    await viewer_cli.get("/api/v1/workspaces/ws-agt01/models")
                ).status_code == 200
                v_denied = await viewer_cli.patch(
                    "/api/v1/workspaces/ws-agt01/models/config",
                    headers=_csrf_headers(
                        v_csrf,
                        extra={"Idempotency-Key": new_uuid7(now=clock()), "If-Match": '"1"'},
                    ),
                    json={"clear_suspension": True},
                )
                assert v_denied.status_code == 403
                assert v_denied.json()["code"] == "insufficient_role"

                # 2) Expire 5m step-up window -> API key write rejected with 403 step_up_required
                clock.advance(minutes=6)
                api_key_canary = "meta_live_secret_canary_998877665544332211"
                idem_key_cfg = new_uuid7(now=clock())
                no_stepup = await owner_cli.patch(
                    "/api/v1/workspaces/ws-agt01/models/config",
                    headers=_csrf_headers(
                        csrf_val,
                        extra={"Idempotency-Key": idem_key_cfg, "If-Match": '"1"'},
                    ),
                    json={"api_key": api_key_canary},
                )
                assert no_stepup.status_code == 403
                assert no_stepup.json()["code"] == "step_up_required"

                # Perform step-up re-authentication and retry with identical Idempotency-Key
                stepup_resp = await owner_cli.post(
                    "/api/v1/auth/step-up",
                    headers=_csrf_headers(csrf_val),
                    json={"password": OWNER_CREDENTIAL},
                )
                assert stepup_resp.status_code == 200
                csrf_val = str(stepup_resp.json()["csrf_token"])

                cfg_ok = await owner_cli.patch(
                    "/api/v1/workspaces/ws-agt01/models/config",
                    headers=_csrf_headers(
                        csrf_val,
                        extra={"Idempotency-Key": idem_key_cfg, "If-Match": '"1"'},
                    ),
                    json={"api_key": api_key_canary},
                )
                assert cfg_ok.status_code == 200, cfg_ok.text
                assert api_key_canary not in cfg_ok.text
                assert cfg_ok.json()["models_state"]["api_key_presence"] == {
                    "configured": True,
                    "secret_version": 1,
                }
                cur_ver = int(cfg_ok.json()["models_state"]["version"])

                # Exact Idempotency-Key replay returns cached 200; mutated payload returns 409;
                # stale If-Match returns 412
                replay_ok = await owner_cli.patch(
                    "/api/v1/workspaces/ws-agt01/models/config",
                    headers=_csrf_headers(
                        csrf_val,
                        extra={"Idempotency-Key": idem_key_cfg, "If-Match": '"1"'},
                    ),
                    json={"api_key": api_key_canary},
                )
                assert replay_ok.status_code == 200
                assert replay_ok.json() == cfg_ok.json()

                mismatch_resp = await owner_cli.patch(
                    "/api/v1/workspaces/ws-agt01/models/config",
                    headers=_csrf_headers(
                        csrf_val,
                        extra={"Idempotency-Key": idem_key_cfg, "If-Match": f'"{cur_ver}"'},
                    ),
                    json={"clear_suspension": True},
                )
                assert mismatch_resp.status_code == 409
                assert mismatch_resp.json()["code"] == "idempotency_payload_mismatch"

                stale_resp = await owner_cli.patch(
                    "/api/v1/workspaces/ws-agt01/models/config",
                    headers=_csrf_headers(
                        csrf_val,
                        extra={"Idempotency-Key": new_uuid7(now=clock()), "If-Match": '"1"'},
                    ),
                    json={"clear_suspension": True},
                )
                assert stale_resp.status_code == 412

                # 3) Non-Meta endpoint (`api.openai.com`) rejected with 403 + policy event
                bad_ep = await owner_cli.patch(
                    "/api/v1/workspaces/ws-agt01/models/config",
                    headers=_csrf_headers(
                        csrf_val,
                        extra={
                            "Idempotency-Key": new_uuid7(now=clock()),
                            "If-Match": f'"{cur_ver}"',
                        },
                    ),
                    json={"endpoint_base_url": "https://api.openai.com/v1"},
                )
                assert bad_ep.status_code == 403
                assert bad_ep.json()["code"] == "meta_endpoint_not_allowlisted"

                # 4) Unsupported `"Wonder Full"` model name rejected 422 (`T-AGT-01-N`)
                bad_model = await owner_cli.post(
                    "/api/v1/workspaces/ws-agt01/model-probes",
                    headers=_csrf_headers(
                        csrf_val, extra={"Idempotency-Key": new_uuid7(now=clock())}
                    ),
                    json={
                        "model_id": "Wonder Full",
                        "consent_id": new_uuid7(now=clock()),
                        "max_cost": {"amount": "0.050000", "currency": "USD"},
                    },
                )
                assert bad_model.status_code == 422

                # 5) Probe without verified consent denied 403 + zero network calls (`SEC-018`)
                no_consent_probe = await owner_cli.post(
                    "/api/v1/workspaces/ws-agt01/model-probes",
                    headers=_csrf_headers(
                        csrf_val, extra={"Idempotency-Key": new_uuid7(now=clock())}
                    ),
                    json={
                        "model_id": PRIMARY_META_MODEL_ID,
                        "consent_id": new_uuid7(now=clock()),
                        "max_cost": {"amount": "0.050000", "currency": "USD"},
                    },
                )
                assert no_consent_probe.status_code == 403
                assert no_consent_probe.json()["code"] == "inference_consent_required"
                assert len(tls_srv.requests) == 0

                # 6) Grant workspace `inference` consent; unconfigured pricing blocks 409
                consent_resp = await owner_cli.post(
                    "/api/v1/workspaces/ws-agt01/models/consents",
                    headers=_csrf_headers(
                        csrf_val, extra={"Idempotency-Key": new_uuid7(now=clock())}
                    ),
                    json={
                        "destination": "https://api.meta.ai/v1",
                        "data_classes": ["public", "workspace_internal"],
                        "policy_version": 1,
                    },
                )
                assert consent_resp.status_code == 201
                consent_id = str(consent_resp.json()["id"])

                no_pricing_probe = await owner_cli.post(
                    "/api/v1/workspaces/ws-agt01/model-probes",
                    headers=_csrf_headers(
                        csrf_val, extra={"Idempotency-Key": new_uuid7(now=clock())}
                    ),
                    json={
                        "model_id": PRIMARY_META_MODEL_ID,
                        "consent_id": consent_id,
                        "max_cost": {"amount": "0.050000", "currency": "USD"},
                    },
                )
                assert no_pricing_probe.status_code == 409
                assert no_pricing_probe.json()["code"] == "unknown_model_pricing"
                assert len(tls_srv.requests) == 0

                # 7) Configure pricing, run Spark probe -> available, Wonder -> unavailable (403)
                latest_models = (await owner_cli.get("/api/v1/workspaces/ws-agt01/models")).json()
                cur_ver = int(latest_models["version"])
                pricing_cfg = await owner_cli.patch(
                    "/api/v1/workspaces/ws-agt01/models/config",
                    headers=_csrf_headers(
                        csrf_val,
                        extra={
                            "Idempotency-Key": new_uuid7(now=clock()),
                            "If-Match": f'"{cur_ver}"',
                        },
                    ),
                    json={"pricing_updates": _spark_and_wonder_pricing_payload()},
                )
                assert pricing_cfg.status_code == 200, pricing_cfg.text
                cur_ver = int(pricing_cfg.json()["models_state"]["version"])

                spark_probe = await owner_cli.post(
                    "/api/v1/workspaces/ws-agt01/model-probes",
                    headers=_csrf_headers(
                        csrf_val, extra={"Idempotency-Key": new_uuid7(now=clock())}
                    ),
                    json={
                        "model_id": PRIMARY_META_MODEL_ID,
                        "consent_id": consent_id,
                        "max_cost": {"amount": "0.050000", "currency": "USD"},
                    },
                )
                assert spark_probe.status_code == 200, spark_probe.text
                spark_body = spark_probe.json()
                assert spark_body["snapshot"]["status"] == "available"
                assert spark_body["snapshot"]["capabilities"] == {
                    "tool_calls": "available",
                    "structured_output": "available",
                    "streaming": "available",
                    "context_window_tokens": 128000,
                    "max_output_tokens": 16384,
                    "rate_limit_rpm": None,
                    "rate_limit_tpm": None,
                }
                assert spark_body["usage_record"]["status"] == "settled"
                assert spark_body["models_state"]["ready_for_repair_inference"] is True
                assert len(tls_srv.requests) == 1
                assert tls_srv.requests[0].tls_sni == "api.meta.ai"
                assert tls_srv.requests[0].headers["authorization"] == f"Bearer {api_key_canary}"

                wonder_probe = await owner_cli.post(
                    "/api/v1/workspaces/ws-agt01/model-probes",
                    headers=_csrf_headers(
                        csrf_val, extra={"Idempotency-Key": new_uuid7(now=clock())}
                    ),
                    json={
                        "model_id": ESCALATION_META_MODEL_ID,
                        "consent_id": consent_id,
                        "max_cost": {"amount": "0.050000", "currency": "USD"},
                    },
                )
                assert wonder_probe.status_code == 200, wonder_probe.text
                assert wonder_probe.json()["snapshot"]["status"] == "unavailable"
                assert wonder_probe.json()["usage_record"] is None
                wonder_usage = [
                    u
                    for u in wonder_probe.json()["models_state"]["recent_usage"]
                    if u["model_id"] == ESCALATION_META_MODEL_ID
                ]
                assert len(wonder_usage) == 1
                assert wonder_usage[0]["status"] == "released"

                # Attempting to enable Wonder escalation when unavailable returns 409
                cur_ver = int(wonder_probe.json()["models_state"]["version"])
                esc_denied = await owner_cli.patch(
                    "/api/v1/workspaces/ws-agt01/models/config",
                    headers=_csrf_headers(
                        csrf_val,
                        extra={
                            "Idempotency-Key": new_uuid7(now=clock()),
                            "If-Match": f'"{cur_ver}"',
                        },
                    ),
                    json={
                        "escalation_policy": {
                            "escalation_enabled": True,
                            "escalate_after_failed_attempts": 1,
                        }
                    },
                )
                assert esc_denied.status_code == 409
                assert esc_denied.json()["code"] == "escalation_model_not_verified"
                assert (
                    await harness.meta_service.select_model_for_attempt(
                        workspace_id=ws_id,
                        failed_attempts=2,
                    )
                    == PRIMARY_META_MODEL_ID
                )

                # 8) Verify concrete SetupStepRegistry `"model_consent"` probe passes, and
                # revoking workspace consent immediately flips `ready_for_repair_inference` & probe
                probe_fn = harness.meta_service.build_setup_probe()
                pass_res = await probe_fn(
                    "model_consent",
                    {
                        "primary_model": PRIMARY_META_MODEL_ID,
                        "max_cost_per_session_amount": "5.000000",
                    },
                )
                assert pass_res.probe_status == "passed"

                revoke_resp = await owner_cli.request(
                    "DELETE",
                    f"/api/v1/workspaces/ws-agt01/models/consents/{consent_id}",
                    headers=_csrf_headers(csrf_val),
                    json={"reason": "Security audit revocation test"},
                )
                assert revoke_resp.status_code == 200
                assert revoke_resp.json()["status"] == "revoked"

                after_revoke = (await owner_cli.get("/api/v1/workspaces/ws-agt01/models")).json()
                assert after_revoke["inference_consent_active"] is False
                assert after_revoke["ready_for_repair_inference"] is False

                revoked_probe_res = await probe_fn(
                    "model_consent",
                    {
                        "primary_model": PRIMARY_META_MODEL_ID,
                        "max_cost_per_session_amount": "5.000000",
                    },
                )
                assert revoked_probe_res.probe_status == "needs_admin"
                assert "inference_consent_missing" in revoked_probe_res.blocking_reasons

                # 9) Re-grant consent and verify upstream 429 + Retry-After: 42 suspends workspace
                reconsent_resp = await owner_cli.post(
                    "/api/v1/workspaces/ws-agt01/models/consents",
                    headers=_csrf_headers(
                        csrf_val, extra={"Idempotency-Key": new_uuid7(now=clock())}
                    ),
                    json={
                        "destination": "https://api.meta.ai/v1",
                        "data_classes": ["public"],
                        "policy_version": 1,
                    },
                )
                assert reconsent_resp.status_code == 201
                consent_2_id = str(reconsent_resp.json()["id"])

                clock.advance(seconds=1)
                next_upstream_mode = "rate_limit_429"
                probe_429 = await owner_cli.post(
                    "/api/v1/workspaces/ws-agt01/model-probes",
                    headers=_csrf_headers(
                        csrf_val, extra={"Idempotency-Key": new_uuid7(now=clock())}
                    ),
                    json={
                        "model_id": PRIMARY_META_MODEL_ID,
                        "consent_id": consent_2_id,
                        "max_cost": {"amount": "0.050000", "currency": "USD"},
                    },
                )
                assert probe_429.status_code == 429, probe_429.text
                assert probe_429.headers.get("retry-after") == "42"
                assert probe_429.json()["code"] == "model_unavailable"

                suspended_state = (await owner_cli.get("/api/v1/workspaces/ws-agt01/models")).json()
                assert suspended_state["suspension_reason"] == "model_unavailable"
                assert suspended_state["retry_after_seconds"] == 42
                assert suspended_state["ready_for_repair_inference"] is False
                spark_entry = next(
                    m for m in suspended_state["models"] if m["model_id"] == PRIMARY_META_MODEL_ID
                )
                assert spark_entry["latest_snapshot"]["status"] == "degraded"
                assert spark_entry["latest_snapshot"]["suspension_reason"] == "model_unavailable"
                assert spark_entry["latest_snapshot"]["retry_after_seconds"] == 42

                # Verify security.policy.denied outbox events were recorded and zero secrets leaked
                async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
                    outbox_types = list(
                        (
                            await db.scalars(
                                select(OutboxEventModel.event_type).where(
                                    OutboxEventModel.workspace_id == ws_id
                                )
                            )
                        ).all()
                    )
                    assert "security.policy.denied" in outbox_types
                    idem_rows = list(
                        (
                            await db.scalars(
                                select(IdempotencyRecordModel).where(
                                    IdempotencyRecordModel.workspace_id == ws_id
                                )
                            )
                        ).all()
                    )
                    for row in idem_rows:
                        assert api_key_canary not in json.dumps(row.response_payload)
            finally:
                await viewer_cli.aclose()
                await owner_cli.aclose()
        finally:
            await harness.app_engine.dispose()


# ---------------------------------------------------------------------------
# 3. Chat Broker: Redaction, CoT Stripping, Tool Provenance, Wire Guards & Redirects
# ---------------------------------------------------------------------------


async def test_complete_chat_redaction_cot_stripping_provenance_schema_guards_and_redirects(
    migrated_db: PgTestUrls,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify `complete_chat` structured output, tool calls, `SEC-017`, `ADR-008`, and `SEC-033`."""
    pki = _generate_pki_material(["api.meta.ai", "cdn-redirect.meta.example"])
    ca_file = tmp_path / "meta_chat_ca.pem"
    ca_file.write_text(pki.ca_pem, encoding="utf-8")
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_file))
    mode = "structured_with_hidden_cot"

    async def _chat_handler(
        req: RecordedMetaWireRequest,
    ) -> tuple[int, dict[str, str], bytes]:
        if mode == "cross_origin_redirect":
            if req.headers.get("host") == "api.meta.ai":
                return (
                    302,
                    {"Location": "https://cdn-redirect.meta.example/v1/chat/completions"},
                    b"",
                )
            return (
                401,
                {"Content-Type": "application/json", "x-request-id": "req_redirect_hop2"},
                b'{"error":{"message":"missing auth after cross-origin strip"}}',
            )
        if mode == "ssrf_redirect":
            return (
                302,
                {"Location": "http://169.254.169.254/latest/meta-data/"},
                b"",
            )
        if mode == "tool_call":
            return (
                200,
                {"Content-Type": "application/json", "x-request-id": "req_tool_01"},
                _load_meta_fixture_bytes("chat_completion_spark_tool_call.json"),
            )
        # Inject upstream hidden CoT (`reasoning_content`) to prove `_strip_cot_fields` drops it
        structured_payload = _load_meta_fixture_json("chat_completion_spark_structured.json")
        structured_payload["choices"][0]["message"]["reasoning_content"] = (
            "PRIVATE_INTERNAL_CHAIN_OF_THOUGHT_MUST_NEVER_PERSIST"
        )
        return (
            200,
            {"Content-Type": "application/json", "x-request-id": "req_struct_01"},
            json.dumps(structured_payload).encode("utf-8"),
        )

    clock = ManualClock()
    async with LocalAsyncTlsMetaServer(pki=pki, handler=_chat_handler) as tls_srv:
        harness = _build_u16_harness(
            migrated_db.app_url,
            clock=clock,
            local_tls_port=tls_srv.port,
            ca_pem=pki.ca_pem,
        )
        try:
            owner_cli, csrf_val, _owner_id, ws_id = await _claim_owner_and_create_workspace(
                harness,
                ws_slug="ws-chat-16",
                ws_name="Chat Broker 16",
            )
            try:
                consent_resp = await owner_cli.post(
                    "/api/v1/workspaces/ws-chat-16/models/consents",
                    headers=_csrf_headers(
                        csrf_val, extra={"Idempotency-Key": new_uuid7(now=clock())}
                    ),
                    json={
                        "destination": "https://api.meta.ai/v1",
                        "data_classes": ["public", "workspace_internal"],
                        "policy_version": 1,
                    },
                )
                assert consent_resp.status_code == 201
                consent_id = str(consent_resp.json()["id"])

                cfg_resp = await owner_cli.patch(
                    "/api/v1/workspaces/ws-chat-16/models/config",
                    headers=_csrf_headers(
                        csrf_val,
                        extra={"Idempotency-Key": new_uuid7(now=clock()), "If-Match": '"2"'},
                    ),
                    json={
                        "api_key": "meta_broker_secret_key_abcdef123456",
                        "pricing_updates": _spark_and_wonder_pricing_payload(),
                    },
                )
                assert cfg_resp.status_code == 200
            finally:
                await owner_cli.aclose()

            # 1) Recursive `$ref` JSON schema rejected (`422 recursive_json_schema_unsupported`)
            with pytest.raises(UnprocessableEntityError) as rec_err:
                await harness.meta_service.complete_chat(
                    MetaChatCompletionRequest(
                        workspace_id=ws_id,
                        model_id=PRIMARY_META_MODEL_ID,
                        consent_id=consent_id,
                        messages=[MetaChatMessage(role="user", content="Analyze failure")],
                        response_format=MetaResponseFormat(
                            type="json_schema",
                            json_schema=MetaJsonSchemaSpec(
                                name="bad_recursive",
                                strict=True,
                                schema_def={
                                    "type": "object",
                                    "$defs": {"Node": {"type": "object"}},
                                    "properties": {"self": {"$ref": "#/$defs/Node"}},
                                },
                            ),
                        ),
                    )
                )
            assert rec_err.value.code == "recursive_json_schema_unsupported"

            # 2) Unsupported OpenAI wire param (`stop`) rejected (`400 unsupported_meta_parameter`)
            with pytest.raises(BadRequestError) as stop_err:
                await harness.meta_service._send_meta_http_post(
                    endpoint_base_url="https://api.meta.ai/v1",
                    api_key_str="unused",
                    wire_payload={"model": PRIMARY_META_MODEL_ID, "messages": [], "stop": ["\n"]},
                    correlation_id=new_uuid7(now=clock()),
                )
            assert stop_err.value.code == "unsupported_meta_parameter"
            assert len(tls_srv.requests) == 0

            # 3) Mismatched structured output fails closed (`422 malformed_model_structured_output`)
            # and valid structured output scrubs secret canary BEFORE wire dispatch & strips CoT
            with pytest.raises(UnprocessableEntityError) as mismatch_schema_err:
                await harness.meta_service.complete_chat(
                    MetaChatCompletionRequest(
                        workspace_id=ws_id,
                        model_id=PRIMARY_META_MODEL_ID,
                        consent_id=consent_id,
                        max_completion_tokens=256,
                        messages=[MetaChatMessage(role="user", content="Expecting wrong keys")],
                        response_format=MetaResponseFormat(
                            type="json_schema",
                            json_schema=MetaJsonSchemaSpec(
                                name="mismatched_v1",
                                strict=True,
                                schema_def={
                                    "type": "object",
                                    "additionalProperties": False,
                                    "required": ["missing_required_field"],
                                    "properties": {"missing_required_field": {"type": "string"}},
                                },
                            ),
                        ),
                    )
                )
            assert mismatch_schema_err.value.code == "malformed_model_structured_output"
            tls_srv.requests.clear()

            leaked_gh_pat = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
            diagnosis_schema = {
                "type": "object",
                "additionalProperties": False,
                "required": ["root_cause_code", "confidence", "candidate_files", "summary"],
                "properties": {
                    "root_cause_code": {"type": "string"},
                    "confidence": {"type": "string"},
                    "candidate_files": {"type": "array", "items": {"type": "string"}},
                    "summary": {"type": "string"},
                },
            }
            struct_res = await harness.meta_service.complete_chat(
                MetaChatCompletionRequest(
                    workspace_id=ws_id,
                    model_id=PRIMARY_META_MODEL_ID,
                    consent_id=consent_id,
                    reasoning_effort="medium",
                    max_completion_tokens=512,
                    messages=[
                        MetaChatMessage(
                            role="user",
                            content=f"CI log failed with token {leaked_gh_pat} in calculator.py",
                        )
                    ],
                    response_format=MetaResponseFormat(
                        type="json_schema",
                        json_schema=MetaJsonSchemaSpec(
                            name="diagnosis_v1",
                            strict=True,
                            schema_def=diagnosis_schema,
                        ),
                    ),
                )
            )
            assert len(tls_srv.requests) == 1
            sent_wire_text = tls_srv.requests[0].body_bytes.decode("utf-8")
            assert leaked_gh_pat not in sent_wire_text
            assert "[REDACTED" in sent_wire_text
            assert struct_res.parsed_structured_output is not None
            assert struct_res.parsed_structured_output["candidate_files"] == ["src/calculator.py"]
            assert struct_res.usage.prompt_tokens == 640
            assert struct_res.usage.completion_tokens == 180
            assert struct_res.usage.reasoning_tokens == 92
            assert struct_res.usage_record.status == "settled"
            assert struct_res.usage_record.settled_cost is not None
            # Exact math: (640 * 0.50 + 180 * 2.00) / 1_000_000 = (320 + 360)/1_000_000 = 0.000680
            assert struct_res.usage_record.settled_cost.amount == Decimal("0.000680")
            assert "PRIVATE_INTERNAL_CHAIN_OF_THOUGHT" not in struct_res.model_dump_json()

            # 4) Tool-call completion produces `ModelToolProvenance` (`S-22`) with SHA-256 digests
            mode = "tool_call"
            tool_res = await harness.meta_service.complete_chat(
                MetaChatCompletionRequest(
                    workspace_id=ws_id,
                    model_id=PRIMARY_META_MODEL_ID,
                    consent_id=consent_id,
                    max_completion_tokens=256,
                    messages=[MetaChatMessage(role="user", content="Inspect src/calculator.py")],
                    tools=[
                        MetaToolDefinition(
                            function=MetaToolFunctionDefinition(
                                name="read_file",
                                description="Read bounded repository file slice.",
                                strict=True,
                                parameters={
                                    "type": "object",
                                    "additionalProperties": False,
                                    "required": ["path", "start_line", "end_line"],
                                    "properties": {
                                        "path": {"type": "string"},
                                        "start_line": {"type": "integer"},
                                        "end_line": {"type": "integer"},
                                    },
                                },
                            )
                        )
                    ],
                )
            )
            assert len(tool_res.tool_calls) == 1
            assert tool_res.tool_calls[0].function.name == "read_file"
            assert len(tool_res.provenance.tool_call_digests) == 1
            assert len(tool_res.provenance.redacted_context_hashes) == 1
            assert tool_res.provenance.usage_record_id == tool_res.usage_record.id

            # 5) SSRF redirect hop (`302 -> http://169.254.169.254/...`) blocked & releases hold
            mode = "ssrf_redirect"
            with pytest.raises(EgressBlockedError):
                await harness.meta_service.complete_chat(
                    MetaChatCompletionRequest(
                        workspace_id=ws_id,
                        model_id=PRIMARY_META_MODEL_ID,
                        consent_id=consent_id,
                        max_completion_tokens=128,
                        messages=[MetaChatMessage(role="user", content="Test SSRF redirect")],
                    )
                )

            # 6) Cross-origin redirect (`api.meta.ai -> cdn-redirect.meta.example`) strips Bearer!
            mode = "cross_origin_redirect"
            req_count_before = len(tls_srv.requests)
            with pytest.raises(ForbiddenError) as hop2_err:
                await harness.meta_service.complete_chat(
                    MetaChatCompletionRequest(
                        workspace_id=ws_id,
                        model_id=PRIMARY_META_MODEL_ID,
                        consent_id=consent_id,
                        max_completion_tokens=128,
                        messages=[MetaChatMessage(role="user", content="Test cross-origin strip")],
                    )
                )
            assert hop2_err.value.code == "meta_auth_failed"
            hop_requests = tls_srv.requests[req_count_before:]
            assert len(hop_requests) == 2
            assert "authorization" in hop_requests[0].headers
            assert "authorization" not in hop_requests[1].headers
        finally:
            await harness.app_engine.dispose()


# ---------------------------------------------------------------------------
# 4. Atomic Budget Ledger: 20-Way Parallel Race, Timeout Unknown Outcome & Cancel
# ---------------------------------------------------------------------------


async def test_atomic_budget_20_way_race_unknown_timeout_cancellation_and_audit_chain(
    migrated_db: PgTestUrls,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify `T-AGT-03-P`/`N`, `T-NFR-06`, `SEC-033` 20-way race, timeout & mid-flight cancel."""
    # Reject binary float in monetary math (`NFR-06`)
    with pytest.raises(TypeError, match="float"):
        ensure_strict_decimal(0.1)  # type: ignore[arg-type]

    pki = _generate_pki_material(["api.meta.ai"])
    ca_file = tmp_path / "meta_race_ca.pem"
    ca_file.write_text(pki.ca_pem, encoding="utf-8")
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_file))
    server_mode = "timeout_after_dispatch"
    inflight_entered = asyncio.Event()
    release_inflight = asyncio.Event()

    async def _race_and_timeout_handler(
        _req: RecordedMetaWireRequest,
    ) -> tuple[int, dict[str, str], bytes]:
        if server_mode == "timeout_after_dispatch":
            await asyncio.sleep(0.75)
            return (
                200,
                {"Content-Type": "application/json"},
                _load_meta_fixture_bytes("chat_completion_spark_structured.json"),
            )
        if server_mode == "inflight_cancel_gate":
            inflight_entered.set()
            await release_inflight.wait()
        return (
            200,
            {"Content-Type": "application/json", "x-request-id": "req_late_cancel_01"},
            _load_meta_fixture_bytes("chat_completion_spark_structured.json"),
        )

    clock = ManualClock()
    async with LocalAsyncTlsMetaServer(pki=pki, handler=_race_and_timeout_handler) as tls_srv:
        harness = _build_u16_harness(
            migrated_db.app_url,
            clock=clock,
            local_tls_port=tls_srv.port,
            ca_pem=pki.ca_pem,
            timeout_seconds=0.25,
            pool_size=16,
            max_overflow=16,
        )
        try:
            owner_cli, csrf_val, _owner_id, ws_id = await _claim_owner_and_create_workspace(
                harness,
                ws_slug="ws-budgets-16",
                ws_name="Budgets Race 16",
            )
            try:
                consent_resp = await owner_cli.post(
                    "/api/v1/workspaces/ws-budgets-16/models/consents",
                    headers=_csrf_headers(
                        csrf_val, extra={"Idempotency-Key": new_uuid7(now=clock())}
                    ),
                    json={
                        "destination": "https://api.meta.ai/v1",
                        "data_classes": ["public"],
                        "policy_version": 1,
                    },
                )
                assert consent_resp.status_code == 201
                consent_id = str(consent_resp.json()["id"])

                cfg_resp = await owner_cli.patch(
                    "/api/v1/workspaces/ws-budgets-16/models/config",
                    headers=_csrf_headers(
                        csrf_val,
                        extra={"Idempotency-Key": new_uuid7(now=clock()), "If-Match": '"2"'},
                    ),
                    json={
                        "api_key": "meta_budget_race_key_987654321",
                        "pricing_updates": _spark_and_wonder_pricing_payload(),
                    },
                )
                assert cfg_resp.status_code == 200
            finally:
                await owner_cli.aclose()

            # 1) 20-way `asyncio.gather` parallel reservation race (`SEC-033` & `T-NFR-06`)
            # Pricing: input=$0.50/1M, output=$2.00/1M.
            # estimated_input=100_000 ($0.05) + max_output=25_000 ($0.05) => worst_cost=$0.100000
            # Cap = $0.500000 => EXACTLY 5 of 20 concurrent reservations succeed, 15 fail!
            race_policy = BudgetPolicyDefaults(
                max_calls_per_session=30,
                max_tokens_per_session=2_000_000,
                max_patch_attempts=2,
                max_wall_seconds=1800,
                max_cost_per_session=Money(amount=Decimal("0.500000"), currency="USD"),
                daily_workspace_cap=Money(amount=Decimal("25.000000"), currency="USD"),
            )
            race_repair_id = new_uuid7(now=clock())
            race_acct = await harness.budget_ledger.ensure_repair_session_account(
                workspace_id=ws_id,
                repair_id=race_repair_id,
                policy=race_policy,
                now=clock(),
            )
            pricing = _spark_pricing_dto()

            async def _attempt_reserve(idx: int) -> str:
                res = await harness.budget_ledger.reserve_for_call(
                    workspace_id=ws_id,
                    primary_account_id=race_acct.id,
                    consent_id=consent_id,
                    model_id=PRIMARY_META_MODEL_ID,
                    pricing=pricing,
                    estimated_input_tokens=100_000,
                    max_output_tokens=25_000,
                    prompt_redacted_digest=f"{idx:064x}",
                    correlation_id=new_uuid7(now=clock()),
                    repair_id=race_repair_id,
                    now=clock(),
                )
                return res.id

            outcomes = await asyncio.gather(
                *(_attempt_reserve(i) for i in range(20)),
                return_exceptions=True,
            )
            succeeded_ids = [o for o in outcomes if isinstance(o, str)]
            exceeded_errs = [
                o
                for o in outcomes
                if isinstance(o, BudgetExceededError) and o.code == "budget_cost_cap_exceeded"
            ]
            assert len(succeeded_ids) == 5
            assert len(exceeded_errs) == 15

            async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
                locked_acct = await db.get(BudgetAccountModel, race_acct.id)
                assert locked_acct is not None
                assert Decimal(locked_acct.reserved_cost) == Decimal("0.500000")
                assert Decimal(locked_acct.reserved_cost) <= Decimal(locked_acct.cost_cap)
                assert locked_acct.reserved_calls == 5
                exceeded_events = list(
                    (
                        await db.scalars(
                            select(OutboxEventModel).where(
                                OutboxEventModel.workspace_id == ws_id,
                                OutboxEventModel.event_type == "usage.budget.exceeded",
                            )
                        )
                    ).all()
                )
                assert len(exceeded_events) == 15

            # Patch attempt ceiling (`NFR-06` default `2`): 2 succeed, 3rd denied!
            await harness.budget_ledger.record_patch_attempt(
                workspace_id=ws_id,
                account_id=race_acct.id,
                correlation_id=new_uuid7(now=clock()),
                now=clock(),
            )
            p2_summary = await harness.budget_ledger.record_patch_attempt(
                workspace_id=ws_id,
                account_id=race_acct.id,
                correlation_id=new_uuid7(now=clock()),
                now=clock(),
            )
            assert p2_summary.patch_attempts_used == 2
            with pytest.raises(BudgetExceededError) as patch_cap_err:
                await harness.budget_ledger.record_patch_attempt(
                    workspace_id=ws_id,
                    account_id=race_acct.id,
                    correlation_id=new_uuid7(now=clock()),
                    now=clock(),
                )
            assert patch_cap_err.value.code == "budget_patch_attempt_cap_exceeded"

            # Walltime expiry (`NFR-06` 1800s): advancing past window_ends_at blocks reservation
            default_policy = BudgetPolicyDefaults(
                max_cost_per_session=Money(amount=NFR06_DEFAULT_SESSION_COST_USD, currency="USD"),
                daily_workspace_cap=Money(
                    amount=NFR06_DEFAULT_DAILY_WORKSPACE_COST_USD,
                    currency="USD",
                ),
            )
            wall_repair_id = new_uuid7(now=clock())
            wall_acct = await harness.budget_ledger.ensure_repair_session_account(
                workspace_id=ws_id,
                repair_id=wall_repair_id,
                policy=default_policy,
                now=clock(),
            )
            with pytest.raises(BudgetExceededError) as wall_err:
                await harness.budget_ledger.reserve_for_call(
                    workspace_id=ws_id,
                    primary_account_id=wall_acct.id,
                    consent_id=consent_id,
                    model_id=PRIMARY_META_MODEL_ID,
                    pricing=pricing,
                    estimated_input_tokens=100,
                    max_output_tokens=100,
                    prompt_redacted_digest="a" * 64,
                    correlation_id=new_uuid7(now=clock()),
                    now=clock() + timedelta(seconds=1801),
                )
            assert wall_err.value.code == "budget_walltime_exceeded"

            # 2) Post-dispatch read timeout -> `unknown_outcome` & worst-case `unknown_cost` kept
            timeout_repair_id = new_uuid7(now=clock())
            timeout_acct = await harness.budget_ledger.ensure_repair_session_account(
                workspace_id=ws_id,
                repair_id=timeout_repair_id,
                policy=BudgetPolicyDefaults(
                    max_cost_per_session=Money(amount=Decimal("0.015000"), currency="USD"),
                    daily_workspace_cap=Money(
                        amount=NFR06_DEFAULT_DAILY_WORKSPACE_COST_USD,
                        currency="USD",
                    ),
                ),
                now=clock(),
            )
            server_mode = "timeout_after_dispatch"
            with pytest.raises(DependencyUnavailableError) as timeout_err:
                await harness.meta_service.complete_chat(
                    MetaChatCompletionRequest(
                        workspace_id=ws_id,
                        repair_id=timeout_repair_id,
                        session_budget_account_id=timeout_acct.id,
                        model_id=PRIMARY_META_MODEL_ID,
                        consent_id=consent_id,
                        max_completion_tokens=5000,
                        messages=[MetaChatMessage(role="user", content="Trigger timeout")],
                    )
                )
            assert timeout_err.value.code == "model_unavailable"

            # Clear workspace suspension so we can verify retained `unknown_cost` blocks overshoot
            async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
                cfg = await db.scalar(
                    select(WorkspaceModelConfigModel).where(
                        WorkspaceModelConfigModel.workspace_id == ws_id
                    )
                )
                assert cfg is not None
                cfg.suspension_reason = None
                cfg.retry_after_until = None
                t_acct_row = await db.get(BudgetAccountModel, timeout_acct.id)
                assert t_acct_row is not None
                assert Decimal(t_acct_row.unknown_cost) > Decimal("0.010000")
                assert Decimal(t_acct_row.settled_cost) == Decimal("0.000000")

                unk_usage = await db.scalar(
                    select(UsageLedgerModel).where(
                        UsageLedgerModel.workspace_id == ws_id,
                        UsageLedgerModel.repair_id == timeout_repair_id,
                    )
                )
                assert unk_usage is not None
                assert unk_usage.status == "unknown"
                assert unk_usage.settled_cost is None
                assert unk_usage.input_tokens is None
                assert unk_usage.output_tokens is None

            # Because worst-case `unknown_cost` (> $0.010) is retained against the $0.015 cap,
            # a second call needing > $0.010 is blocked BEFORE opening any socket!
            reqs_before_second = len(tls_srv.requests)
            with pytest.raises(BudgetExceededError) as retained_err:
                await harness.meta_service.complete_chat(
                    MetaChatCompletionRequest(
                        workspace_id=ws_id,
                        repair_id=timeout_repair_id,
                        session_budget_account_id=timeout_acct.id,
                        model_id=PRIMARY_META_MODEL_ID,
                        consent_id=consent_id,
                        max_completion_tokens=5000,
                        messages=[MetaChatMessage(role="user", content="Blocked by unknown hold")],
                    )
                )
            assert retained_err.value.code == "budget_cost_cap_exceeded"
            assert len(tls_srv.requests) == reqs_before_second

            # 3) Mid-session cancellation: in-flight call settles `late_after_cancel=True`,
            # subsequent call is blocked with ZERO new wire requests!
            cancel_repair_id = new_uuid7(now=clock())
            cancel_acct = await harness.budget_ledger.ensure_repair_session_account(
                workspace_id=ws_id,
                repair_id=cancel_repair_id,
                policy=default_policy,
                now=clock(),
            )
            server_mode = "inflight_cancel_gate"
            cancelled_flag = False

            inflight_task = asyncio.create_task(
                harness.meta_service.complete_chat(
                    MetaChatCompletionRequest(
                        workspace_id=ws_id,
                        repair_id=cancel_repair_id,
                        session_budget_account_id=cancel_acct.id,
                        model_id=PRIMARY_META_MODEL_ID,
                        consent_id=consent_id,
                        max_completion_tokens=256,
                        messages=[MetaChatMessage(role="user", content="In-flight repair prompt")],
                    ),
                    cancel_check=lambda: cancelled_flag,
                )
            )
            await asyncio.wait_for(inflight_entered.wait(), timeout=3.0)

            cancelled_flag = True
            await harness.budget_ledger.cancel_budget_account(
                workspace_id=ws_id,
                account_id=cancel_acct.id,
                correlation_id=new_uuid7(now=clock()),
                actor_id="owner-cancel",
                now=clock(),
            )
            release_inflight.set()

            late_result = await inflight_task
            assert late_result.late_after_cancel is True
            assert late_result.reservation.late_after_cancel is True
            assert late_result.usage_record.status == "settled"

            reqs_after_inflight = len(tls_srv.requests)
            with pytest.raises(ConflictError) as post_cancel_err:
                await harness.meta_service.complete_chat(
                    MetaChatCompletionRequest(
                        workspace_id=ws_id,
                        repair_id=cancel_repair_id,
                        session_budget_account_id=cancel_acct.id,
                        model_id=PRIMARY_META_MODEL_ID,
                        consent_id=consent_id,
                        max_completion_tokens=256,
                        messages=[MetaChatMessage(role="user", content="Must never dispatch")],
                    )
                )
            assert post_cancel_err.value.code == "budget_session_cancelled"
            assert len(tls_srv.requests) == reqs_after_inflight

            # 4) Verify Ed25519 hash-chained audit log integrity + zero leaked secrets
            ed_priv = Ed25519PrivateKey.generate()
            pub_rec = export_ed25519_public_key_record(
                private_key=ed_priv,
                key_id="audit-key-u16",
                not_before=clock() - timedelta(days=1),
            )
            key_ring = KeyRing([pub_rec])
            ext_store = ExternalCheckpointStore(tmp_path / "audit_checkpoints")
            async with instance_rls_session(harness.app_factory, mode="audit_verifier") as db:
                verified_count = await verify_audit_chain(
                    db,
                    external_store=ext_store,
                    keyring=key_ring,
                )
                assert verified_count > 0

                audit_rows = list((await db.scalars(select(AuditLogModel))).all())
                for entry in audit_rows:
                    assert "meta_budget_race_key_987654321" not in json.dumps(entry.metadata_json)
        finally:
            await harness.app_engine.dispose()
