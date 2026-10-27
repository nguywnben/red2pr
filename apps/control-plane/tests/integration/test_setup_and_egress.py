"""PostgreSQL 16 integration & real-socket security tests for U07 Setup Wizard & Egress Proxy.

Verifies against a real disposable PostgreSQL 16 instance and real local `asyncio.start_server`
HTTP/TLS servers (never SQLite mocks):
- Migration `0004_setup_consents_endpoints` reversibility (`upgrade -> downgrade -> upgrade`),
  fail-closed `FORCE ROW LEVEL SECURITY` across `setup_checkpoints`, `consents`, and
  `endpoint_registrations`, cross-workspace `consents` isolation, and DB `CheckConstraint`
  forbidding `'secret'` in `consents.data_classes_json` (`SEC-032`).
- `T-INS-02-P` & `UX-01`:
  - Pre-claim `GET /api/v1/setup` returns `phase="owner_claim"`, `owner_claimed=False`,
    `ready_monitor=False`, `ready_repair=False` with zero secrets.
  - Full resumable 10-phase setup wizard progression, mid-wizard FastAPI/service restart
    resumption at exact persisted phase & `checkpoint`, secret canary redaction in PostgreSQL
    `setup_checkpoints.draft_payload_json`, optional phase skipping (`not_configured`, never
    green), `ready_monitor` vs `ready_repair` gating, explicit per-purpose `consents`
    (`inference` vs `notification` vs `telemetry`), and immediate `ready_repair -> False`
    recomputation upon `inference` consent revocation (`S-18`, `SEC-018`).
- `T-INS-02-N`:
  - Bootstrap token `<=15m` max TTL, expired (`410`) and replayed (`409`) tokens, query-string
    secret rejection (`400 secret_in_query_url`), remote HTTP topology rejection (`422`),
    mandatory `require_baseline=True` & `auto_merge=False` (`422`), mandatory phase skip
    rejection (`422`), stale `expected_checkpoint` (`409 checkpoint_conflict`), `$0.00` model
    budget & failed/skipped probe blocking `auto_repair` / `ready_repair` (`409`), non-owner
    access (`403 instance_owner_required`), and `5m` step-up enforcement on private endpoint
    registration/revocation (`403 step_up_required`).
- `SEC-014`, `SEC-033` & `ADR-037` Outbound Egress Proxy & DNS Rebinding Defense:
  - Default block on `127.0.0.1`, `::1`, `169.254.169.254`, `[::ffff:169.254.169.254]`,
    `[fd00:ec2::254]`, `fe80::1`, integer/hex IPv4 (`2130706433`, `0x7f.0.0.1`), `file://`,
    userinfo URLs, cleartext `http://`, and unregistered RFC1918/CGNAT/ULA addresses.
  - DNS rebinding proof: `rebind.attacker.example` resolves to `93.184.216.34` on lookup #1
    (socket connects strictly to literal `"93.184.216.34"` while preserving TLS SNI & `Host`
    header) and `169.254.169.254` on lookup #2 -> blocked (`403 egress_ip_permanently_denied`)
    before opening any socket; mixed round-robin `["93.184.216.34", "169.254.169.254"]` denied.
  - Step-up owner registration of `(gitlab, https, gitlab.corp.internal, 8443, ["10.24.0.0/16"],
    ca_ref="ref:corp-ca")` allows `DbEndpointAllowlistProvider` + `EgressSafeHttpClient` for
    `adapter="gitlab"` over real verified TLS 1.2+ with custom CA & SNI while denying
    `adapter="webhook"` (`403`) and immediately denying `adapter="gitlab"` once revoked; wrong
    CA bundle fails TLS verification (`httpx.ConnectError`).
  - Redirect SSRF hop (`302 -> http://169.254.169.254/latest/meta-data/`) blocked (`403`),
    cross-origin redirect (`https://public-a.example -> https://public-b.example`) strips
    `Authorization`, `Cookie`, `X-Gitlab-Token`, and `*-Secret` headers (`SEC-033`), `>3`
    redirects blocked (`403`), ambient `HTTP_PROXY`/`HTTPS_PROXY` ignored (`trust_env=False`),
    and `verify_audit_chain` passes across all U07 audit entries.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import ipaddress
import os
import ssl
import sys
import tempfile
from collections import deque
from collections.abc import AsyncIterator, Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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
from sqlalchemy import delete, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from py_contracts.crypto import KeyRing, MasterKeyRing, export_ed25519_public_key_record
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import (
    ExternalCheckpointStore,
    verify_audit_chain,
)
from red2pr_control.api.app import create_app
from red2pr_control.core.egress import (
    EgressAuditEvent,
    EgressBlockedError,
    EgressPolicyEngine,
    EgressSafeHttpClient,
    InMemoryCaBundleResolver,
)
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.base import (
    ConsentModel,
    EndpointRegistrationModel,
    InstanceModel,
    MembershipModel,
    SchemaMigrationRecordModel,
    SetupCheckpointModel,
    UserModel,
    WorkspaceModel,
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
from red2pr_control.operations.setup_wizard import (
    DbEndpointAllowlistProvider,
    SetupStepProbeResult,
    SetupStepRegistry,
)
from red2pr_control.secrets.broker import SecretBroker, SecretBrokerTotpVault

APP_ROLE_NAME = "red2pr_app"
APP_ROLE_PASSWORD = "red2pr_app_local_test_pw_07"
PUBLIC_BASE_URL = "http://127.0.0.1:4280"
ORIGIN_HEADERS = {"Origin": PUBLIC_BASE_URL}
OWNER_CREDENTIAL = "OwnerSup3rStr0ng!Pass#27"
MEMBER_CREDENTIAL = "MemberSup3rStr0ng!Pass#27"


class ManualClock:
    """Deterministic controllable UTC clock for bootstrap TTL, step-up & readiness tests."""

    def __init__(self, initial: datetime | None = None) -> None:
        self._current = (initial or datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)).astimezone(UTC)

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


def _csrf_headers(token: str, *, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    headers = {"X-CSRF-Token": token, **ORIGIN_HEADERS}
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
        tempfile.TemporaryDirectory(prefix="red2pr_u07_pg16_") as tmp_dir,
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


def _build_iam_stack(
    app_url: str,
    *,
    clock: ManualClock,
) -> tuple[AsyncEngine, IamService]:
    app_engine = create_app_engine(app_url, pool_size=4, max_overflow=4)
    app_factory = create_session_factory(app_engine)
    kek_ring = MasterKeyRing(active_version=1, keys={1: b"\x37" * 32})
    broker = SecretBroker(key_ring=kek_ring, redactor=Redactor())
    totp_vault = SecretBrokerTotpVault(broker)
    iam = IamService(
        session_factory=app_factory,
        totp_vault=totp_vault,
        iam_seed_key=b"\x47" * 32,
        public_base_url=PUBLIC_BASE_URL,
        clock=clock,
    )
    return app_engine, iam


async def _claim_owner_client(
    transport: httpx.ASGITransport,
    iam: IamService,
    *,
    email: str = "owner.u07@red2pr.local",
    display_name: str = "Owner U07",
) -> tuple[httpx.AsyncClient, str, str]:
    raw_boot, _ = await iam.issue_bootstrap_token()
    client = httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL)
    csrf_resp = await client.get("/api/v1/auth/csrf")
    assert csrf_resp.status_code == 200
    pre_csrf = csrf_resp.json()["csrf_token"]

    claim_resp = await client.post(
        "/api/v1/setup/claim",
        headers=_csrf_headers(pre_csrf),
        json={
            "bootstrap_token": raw_boot,
            "display_name": display_name,
            "email": email,
            "password": OWNER_CREDENTIAL,
        },
    )
    assert claim_resp.status_code == 201, claim_resp.text
    claim_body = claim_resp.json()
    return client, claim_body["csrf_token"], claim_body["user"]["id"]


# ---------------------------------------------------------------------------
# Certificate & Real Loopback HTTP/TLS Test Infrastructure (Zero Internet)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PkiMaterial:
    ca_pem: str
    wrong_ca_pem: str
    server_cert_pem: str
    server_key_pem: str


def _generate_pki_material(dns_names: Sequence[str]) -> PkiMaterial:
    now = dt.datetime.now(tz=UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Red2PR U07 Test Root CA")])
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

    wrong_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Untrusted Other CA")])
    wrong_ca_cert = (
        x509.CertificateBuilder()
        .subject_name(wrong_subject)
        .issuer_name(wrong_subject)
        .public_key(wrong_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(wrong_ca_key, hashes.SHA256())
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
        wrong_ca_pem=wrong_ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        server_cert_pem=srv_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        server_key_pem=srv_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode("ascii"),
    )


@dataclass
class RecordedUpstreamRequest:
    method: str
    path: str
    headers: dict[str, str]
    tls_sni: str | None


class LocalTlsHttpServer:
    """Real `asyncio.start_server` TLS HTTP/1.1 test server recording SNI & request headers."""

    def __init__(
        self,
        *,
        pki: PkiMaterial,
        handler: Callable[[RecordedUpstreamRequest], tuple[int, dict[str, str], bytes]],
    ) -> None:
        self._pki = pki
        self._handler = handler
        self._server: asyncio.AbstractServer | None = None
        self.port: int = 0
        self.requests: list[RecordedUpstreamRequest] = []

    async def __aenter__(self) -> LocalTlsHttpServer:
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

        with tempfile.TemporaryDirectory(prefix="red2pr_u07_tls_") as cert_dir:
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
                    if content_len > 0:
                        await asyncio.wait_for(reader.readexactly(content_len), timeout=5.0)

                    ssl_obj = writer.get_extra_info("ssl_object")
                    recorded_sni = sni_holder.pop(ssl_obj, None) if ssl_obj is not None else None
                    rec = RecordedUpstreamRequest(
                        method=method,
                        path=path,
                        headers=hdrs,
                        tls_sni=recorded_sni,
                    )
                    self.requests.append(rec)
                    status_code, resp_hdrs, body = self._handler(rec)
                    reason = {
                        200: "OK",
                        301: "Moved",
                        302: "Found",
                        307: "Temporary Redirect",
                    }.get(status_code, "Response")
                    out_lines = [
                        f"HTTP/1.1 {status_code} {reason}",
                        f"Content-Length: {len(body)}",
                        "Connection: close",
                    ]
                    for hk, hv in resp_hdrs.items():
                        out_lines.append(f"{hk}: {hv}")
                    raw_resp = ("\r\n".join(out_lines) + "\r\n\r\n").encode("latin1") + body
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
    """Test network backend verifying literal-IP socket pinning while tunneling to local server."""

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
        # Prove EgressPinnedAsyncTransport NEVER passes a DNS hostname to connect_tcp!
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
    """Deterministic DNS resolver supporting per-host queues for DNS rebinding tests."""

    def __init__(self, answers: Mapping[str, Sequence[Sequence[str]]]) -> None:
        self._queues: dict[str, deque[tuple[str, ...]]] = {
            host.lower(): deque(tuple(batch) for batch in batches)
            for host, batches in answers.items()
        }
        self.queries: list[tuple[str, int]] = []

    async def resolve(self, host: str, port: int) -> Sequence[str]:
        normalized = host.lower()
        self.queries.append((normalized, port))
        q = self._queues.get(normalized)
        if not q:
            return ()
        if len(q) > 1:
            return q.popleft()
        return q[0]


# ---------------------------------------------------------------------------
# 1. Migration 0004 Reversibility & Fail-Closed RLS (`SEC-032`)
# ---------------------------------------------------------------------------


async def test_migration_0004_reversibility_and_fail_closed_rls(migrated_db: PgTestUrls) -> None:
    """Verify 0004 upgrade/downgrade/upgrade cycle, RLS isolation, and DB secret check."""
    run_alembic_downgrade(
        migrated_db.admin_url,
        "0003_workspaces_rbac_grants",
        app_role_name=APP_ROLE_NAME,
    )
    run_alembic_upgrade(
        migrated_db.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )

    admin_engine = create_admin_engine(migrated_db.admin_url)
    app_engine = create_app_engine(migrated_db.app_url)
    admin_factory = create_session_factory(admin_engine)
    app_factory = create_session_factory(app_engine)
    now = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)

    try:
        async with admin_factory() as db, db.begin():
            mig = await db.get(SchemaMigrationRecordModel, "0004_setup_consents_endpoints")
            assert mig is not None

            owner_id = new_uuid7(now=now)
            ws_a_id = new_uuid7(now=now)
            ws_b_id = new_uuid7(now=now)
            db.add(
                UserModel(
                    id=owner_id,
                    username="rls-owner",
                    email="rls.owner@red2pr.local",
                    display_name="RLS Owner",
                    password_hash="argon2id$rls_test_stub",
                    is_instance_owner=True,
                    status="active",
                    created_at=now,
                    updated_at=now,
                )
            )
            await db.flush()
            db.add_all(
                [
                    WorkspaceModel(
                        id=ws_a_id,
                        name="Workspace Alpha",
                        slug="ws-alpha",
                        owner_user_id=owner_id,
                        status="active",
                        created_at=now,
                        updated_at=now,
                    ),
                    WorkspaceModel(
                        id=ws_b_id,
                        name="Workspace Beta",
                        slug="ws-beta",
                        owner_user_id=owner_id,
                        status="active",
                        created_at=now,
                        updated_at=now,
                    ),
                ]
            )
            await db.flush()

            inst = await db.scalar(select(InstanceModel))
            if inst is None:
                inst = InstanceModel(
                    id=new_uuid7(now=now),
                    singleton_guard=True,
                    deployment_mode="local",
                    public_base_url=PUBLIC_BASE_URL,
                    config_revision=1,
                    recovery_epoch=1,
                    initialized_at=now,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
                db.add(inst)
                await db.flush()

            db.add(
                SetupCheckpointModel(
                    id=new_uuid7(now=now),
                    instance_id=inst.id,
                    phase="owner_claim",
                    phase_order=1,
                    status="completed",
                    is_current_phase=True,
                    checkpoint_token="ckpt-rls-01",
                    draft_payload_json={},
                    probe_status="passed",
                    created_at=now,
                    updated_at=now,
                )
            )
            db.add_all(
                [
                    ConsentModel(
                        id=new_uuid7(now=now),
                        purpose="inference",
                        scope="workspace",
                        workspace_id=ws_a_id,
                        destination="api.llama.com",
                        data_classes_json=["public", "workspace_internal"],
                        granted_by_user_id=owner_id,
                        granted_at=now,
                        created_at=now,
                        updated_at=now,
                    ),
                    ConsentModel(
                        id=new_uuid7(now=now),
                        purpose="inference",
                        scope="workspace",
                        workspace_id=ws_b_id,
                        destination="api.llama.com",
                        data_classes_json=["restricted"],
                        granted_by_user_id=owner_id,
                        granted_at=now,
                        created_at=now,
                        updated_at=now,
                    ),
                    EndpointRegistrationModel(
                        id=new_uuid7(now=now),
                        adapter="gitlab",
                        scheme="https",
                        host="gitlab.internal.corp",
                        port=443,
                        cidrs_json=["10.10.0.0/16"],
                        created_by_user_id=owner_id,
                        created_at=now,
                        updated_at=now,
                    ),
                ]
            )

        # 1) Unscoped red2pr_app session sees ZERO rows (fail-closed RLS)
        async with app_factory() as unscoped_db, unscoped_db.begin():
            assert (await unscoped_db.scalars(select(SetupCheckpointModel))).all() == []
            assert (await unscoped_db.scalars(select(ConsentModel))).all() == []
            assert (await unscoped_db.scalars(select(EndpointRegistrationModel))).all() == []

        # 2) Workspace A RLS session sees ONLY Workspace A consents, ZERO setup_checkpoints,
        # and read-only SELECT visibility on active endpoint_registrations for adapter egress policy
        async with workspace_rls_session(app_factory, workspace_id=ws_a_id) as ws_a_db:
            ws_a_consents = (await ws_a_db.scalars(select(ConsentModel))).all()
            assert len(ws_a_consents) == 1
            assert ws_a_consents[0].workspace_id == ws_a_id
            assert (await ws_a_db.scalars(select(SetupCheckpointModel))).all() == []
            ws_visible_endpoints = (await ws_a_db.scalars(select(EndpointRegistrationModel))).all()
            assert len(ws_visible_endpoints) == 1
            assert ws_visible_endpoints[0].host == "gitlab.internal.corp"

        # 3) Workspace session CANNOT insert, update, or delete endpoint_registrations
        with pytest.raises(DBAPIError):
            async with workspace_rls_session(app_factory, workspace_id=ws_a_id) as ws_a_db:
                ws_a_db.add(
                    EndpointRegistrationModel(
                        id=new_uuid7(now=now),
                        adapter="webhook",
                        scheme="https",
                        host="evil.internal.corp",
                        port=443,
                        cidrs_json=["10.99.0.0/16"],
                        created_by_user_id=owner_id,
                        created_at=now,
                        updated_at=now,
                    )
                )
                await ws_a_db.flush()

        async with workspace_rls_session(app_factory, workspace_id=ws_a_id) as ws_a_db:
            upd_ids = (
                await ws_a_db.scalars(
                    update(EndpointRegistrationModel)
                    .values(description="tampered-by-ws")
                    .returning(EndpointRegistrationModel.id)
                )
            ).all()
            assert upd_ids == []
            del_ids = (
                await ws_a_db.scalars(
                    delete(EndpointRegistrationModel).returning(EndpointRegistrationModel.id)
                )
            ).all()
            assert del_ids == []

        async with instance_rls_session(app_factory, mode="instance_admin") as inst_db:
            intact_endpoints = (await inst_db.scalars(select(EndpointRegistrationModel))).all()
            assert len(intact_endpoints) == 1
            assert intact_endpoints[0].description is None

        # 4) DB CheckConstraint rejects 'secret' in consents.data_classes_json even under admin!
        with pytest.raises(DBAPIError):
            async with instance_rls_session(app_factory, mode="instance_admin") as inst_db:
                inst_db.add(
                    ConsentModel(
                        id=new_uuid7(now=now),
                        purpose="inference",
                        scope="instance",
                        workspace_id=None,
                        destination="api.llama.com",
                        data_classes_json=["public", "secret"],
                        granted_by_user_id=owner_id,
                        granted_at=now,
                        created_at=now,
                        updated_at=now,
                    )
                )
                await inst_db.flush()
    finally:
        await app_engine.dispose()
        await admin_engine.dispose()


# ---------------------------------------------------------------------------
# 2. 10-Phase Setup Wizard Positive Flow, Resumability & Consent Revocation (`T-INS-02-P`, `UX-01`)
# ---------------------------------------------------------------------------


async def test_setup_wizard_10_phase_resume_skip_and_consent_readiness_gates(
    migrated_db: PgTestUrls,
) -> None:
    """Verify 10-phase wizard, mid-wizard restart resume, redaction, skip, and consent gates."""
    clock = ManualClock()
    app_engine, iam = _build_iam_stack(migrated_db.app_url, clock=clock)

    registry = SetupStepRegistry()

    async def _provider_probe(_phase: str, _draft: Mapping[str, Any]) -> SetupStepProbeResult:
        return SetupStepProbeResult(
            probe_status="passed",
            detail="GitHub App webhook & API permissions verified.",
        )

    async def _model_probe(_phase: str, _draft: Mapping[str, Any]) -> SetupStepProbeResult:
        return SetupStepProbeResult(
            probe_status="passed",
            detail="Meta inference endpoint reachable.",
        )

    async def _worker_probe(_phase: str, _draft: Mapping[str, Any]) -> SetupStepProbeResult:
        return SetupStepProbeResult(
            probe_status="passed",
            detail="Rootless non-privileged Z3 sandbox self-test passed.",
        )

    registry.register_probe("provider_connect", _provider_probe)
    registry.register_probe("model_consent", _model_probe)
    registry.register_probe("worker_readiness", _worker_probe)

    app_1 = create_app()
    app_1.state.iam_service = iam
    app_1.state.setup_step_registry = registry
    transport_1 = httpx.ASGITransport(app=app_1)

    try:
        # 1) Pre-claim GET /api/v1/setup works unauthenticated and exposes ZERO secrets
        async with httpx.AsyncClient(transport=transport_1, base_url=PUBLIC_BASE_URL) as anon:
            pre_resp = await anon.get("/api/v1/setup")
            assert pre_resp.status_code == 200
            pre_state = pre_resp.json()
            assert pre_state["phase"] == "owner_claim"
            assert pre_state["owner_claimed"] is False
            assert pre_state["ready_monitor"] is False
            assert pre_state["ready_repair"] is False
            assert len(pre_state["steps"]) == 10

        # 2) Claim owner (`Phase 1`) and advance through Phases 2..4 with secret canary in notes
        owner_client, csrf, _owner_id = await _claim_owner_client(transport_1, iam)
        try:
            st_resp = await owner_client.get("/api/v1/setup")
            assert st_resp.status_code == 200
            state = st_resp.json()
            assert state["owner_claimed"] is True
            assert state["phase"] == "topology_tls"
            ckpt = state["checkpoint"]

            secret_canary = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
            p2 = await owner_client.post(
                "/api/v1/setup/steps/topology_tls",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": ckpt,
                    "action": "save",
                    "deployment_mode": "local",
                    "public_base_url": PUBLIC_BASE_URL,
                    "tls_mode": "loopback_http",
                    "draft_notes": {
                        "operator_note": f"Accidental pasted token {secret_canary}",
                        "api_token": "super-secret-inline-token-value",
                    },
                },
            )
            assert p2.status_code == 200, p2.text
            assert secret_canary not in p2.text
            assert "super-secret-inline-token-value" not in p2.text
            ckpt = p2.json()["checkpoint"]
            assert p2.json()["phase"] == "storage_keys"

            p3 = await owner_client.post(
                "/api/v1/setup/steps/storage_keys",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": ckpt,
                    "action": "save",
                    "storage_backend": "local",
                    "backup_retention_days": 45,
                    "master_key_custody_confirmed": True,
                },
            )
            assert p3.status_code == 200
            ckpt = p3.json()["checkpoint"]
            assert p3.json()["phase"] == "workspace_admin"

            p4 = await owner_client.post(
                "/api/v1/setup/steps/workspace_admin",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": ckpt,
                    "action": "save",
                    "workspace_name": "Platform Reliability",
                    "workspace_slug": "plat-rel",
                },
            )
            assert p4.status_code == 200, p4.text
            p4_body = p4.json()
            assert p4_body["phase"] == "provider_connect"
            assert p4_body["default_workspace_slug"] == "plat-rel"
            persisted_ckpt = p4_body["checkpoint"]
            session_cookies = dict(owner_client.cookies)
        finally:
            await owner_client.aclose()

        # Verify PostgreSQL `setup_checkpoints` stored ZERO raw secret canary bytes
        async with instance_rls_session(iam.session_factory, mode="instance_only") as db:
            rows = (await db.scalars(select(SetupCheckpointModel))).all()
            assert len(rows) == 10
            serialized_rows = repr([r.draft_payload_json for r in rows])
            assert secret_canary not in serialized_rows
            assert "super-secret-inline-token-value" not in serialized_rows

        # 3) Simulate control-plane restart: brand-new FastAPI app + SetupWizardService instance!
        app_2 = create_app()
        app_2.state.iam_service = iam
        app_2.state.setup_step_registry = registry
        transport_2 = httpx.ASGITransport(app=app_2)

        async with httpx.AsyncClient(
            transport=transport_2,
            base_url=PUBLIC_BASE_URL,
            cookies=session_cookies,
        ) as resumed_client:
            resumed = await resumed_client.get("/api/v1/setup")
            assert resumed.status_code == 200
            resumed_body = resumed.json()
            assert resumed_body["phase"] == "provider_connect"
            assert resumed_body["checkpoint"] == persisted_ckpt
            assert resumed_body["default_workspace_slug"] == "plat-rel"
            ckpt = resumed_body["checkpoint"]

            # Phase 5: provider_connect passes -> monitor prerequisites progressing
            p5 = await resumed_client.post(
                "/api/v1/setup/steps/provider_connect",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": ckpt,
                    "action": "save",
                    "provider": "github",
                    "provider_base_url": "https://api.github.com",
                    "auth_mode": "github_app",
                    "secret_ref": "sec_github_app_01",
                },
            )
            assert p5.status_code == 200, p5.text
            ckpt = p5.json()["checkpoint"]
            assert p5.json()["phase"] == "model_consent"

            # Skip optional Phase 6 (`model_consent`) & Phase 7 (`worker_readiness`)
            p6_skip = await resumed_client.post(
                "/api/v1/setup/steps/model_consent",
                headers=_csrf_headers(csrf),
                json={"expected_checkpoint": ckpt, "action": "skip"},
            )
            assert p6_skip.status_code == 200
            ckpt = p6_skip.json()["checkpoint"]

            p7_skip = await resumed_client.post(
                "/api/v1/setup/steps/worker_readiness",
                headers=_csrf_headers(csrf),
                json={"expected_checkpoint": ckpt, "action": "skip"},
            )
            assert p7_skip.status_code == 200
            ckpt = p7_skip.json()["checkpoint"]

            # Phase 8: repo_policy in monitor mode -> ready_monitor=True, ready_repair=False!
            p8 = await resumed_client.post(
                "/api/v1/setup/steps/repo_policy",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": ckpt,
                    "action": "save",
                    "default_repo_mode": "monitor",
                    "require_baseline": True,
                    "auto_merge": False,
                },
            )
            assert p8.status_code == 200
            p8_body = p8.json()
            assert p8_body["ready_monitor"] is True
            assert p8_body["ready_repair"] is False
            assert p8_body["readiness"] == "ready_monitor"
            ckpt = p8_body["checkpoint"]

            # Skip Phase 9 (`notifications`) -> status is `not_configured` (never `completed`)
            p9_skip = await resumed_client.post(
                "/api/v1/setup/steps/notifications",
                headers=_csrf_headers(csrf),
                json={"expected_checkpoint": ckpt, "action": "skip"},
            )
            assert p9_skip.status_code == 200
            notif_step = next(s for s in p9_skip.json()["steps"] if s["phase"] == "notifications")
            assert notif_step["status"] == "not_configured"
            ckpt = p9_skip.json()["checkpoint"]

            # Certify `ready_monitor` at Phase 10 (`readiness_review`)
            p10_mon = await resumed_client.post(
                "/api/v1/setup/steps/readiness_review",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": ckpt,
                    "action": "save",
                    "target_readiness": "ready_monitor",
                },
            )
            assert p10_mon.status_code == 200
            assert p10_mon.json()["completed_at"] is not None
            assert p10_mon.json()["ready_monitor"] is True
            assert p10_mon.json()["ready_repair"] is False
            ckpt = p10_mon.json()["checkpoint"]

            # 4) Grant ONLY `notification` consent first -> does NOT satisfy `inference` consent!
            notif_consent_resp = await resumed_client.post(
                "/api/v1/setup/consents",
                headers=_csrf_headers(csrf),
                json={
                    "purpose": "notification",
                    "scope": "instance",
                    "destination": "api.telegram.org",
                    "data_classes": ["public"],
                    "policy_notice_acknowledged": True,
                },
            )
            assert notif_consent_resp.status_code == 201

            # Grant explicit `inference` consent, revisit Phases 6 & 7, and certify `ready_repair`!
            inf_consent_resp = await resumed_client.post(
                "/api/v1/setup/consents",
                headers=_csrf_headers(csrf),
                json={
                    "purpose": "inference",
                    "scope": "instance",
                    "destination": "api.llama.com",
                    "data_classes": ["public", "workspace_internal"],
                    "policy_notice_acknowledged": True,
                },
            )
            assert inf_consent_resp.status_code == 201
            inf_consent_id = inf_consent_resp.json()["id"]

            back_6 = await resumed_client.post(
                "/api/v1/setup/steps/model_consent",
                headers=_csrf_headers(csrf),
                json={"expected_checkpoint": ckpt, "action": "back"},
            )
            assert back_6.status_code == 200
            assert back_6.json()["phase"] == "model_consent"
            ckpt = back_6.json()["checkpoint"]

            save_6 = await resumed_client.post(
                "/api/v1/setup/steps/model_consent",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": ckpt,
                    "action": "save",
                    "primary_model": "llama-4-maverick-17b-128e",
                    "inference_consent_id": inf_consent_id,
                    "max_cost_per_session": {"amount": "5.00", "currency": "USD"},
                    "max_tokens_per_session": 64000,
                    "max_calls_per_session": 12,
                },
            )
            assert save_6.status_code == 200, save_6.text
            ckpt = save_6.json()["checkpoint"]

            save_7 = await resumed_client.post(
                "/api/v1/setup/steps/worker_readiness",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": ckpt,
                    "action": "save",
                    "sandbox_backend": "docker_isolated",
                    "runtime_profile_id": "python-3.12-node-22",
                    "host_escape_risk_acknowledged": True,
                    "run_self_test": True,
                },
            )
            assert save_7.status_code == 200, save_7.text
            assert save_7.json()["ready_monitor"] is True
            assert save_7.json()["ready_repair"] is True
            assert save_7.json()["readiness"] == "ready_repair"
            ckpt = save_7.json()["checkpoint"]

            # Revisit Phase 10 and certify `ready_repair`
            back_10 = await resumed_client.post(
                "/api/v1/setup/steps/readiness_review",
                headers=_csrf_headers(csrf),
                json={"expected_checkpoint": ckpt, "action": "back"},
            )
            ckpt = back_10.json()["checkpoint"]

            p10_rep = await resumed_client.post(
                "/api/v1/setup/steps/readiness_review",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": ckpt,
                    "action": "save",
                    "target_readiness": "ready_repair",
                },
            )
            assert p10_rep.status_code == 200
            assert p10_rep.json()["ready_repair"] is True

            # 5) Revoke `inference` consent -> `ready_repair` immediately drops to False!
            rev_resp = await resumed_client.request(
                "DELETE",
                f"/api/v1/setup/consents/{inf_consent_id}",
                headers=_csrf_headers(csrf),
                json={"reason": "Security audit revocation test"},
            )
            assert rev_resp.status_code == 200
            assert rev_resp.json()["status"] == "revoked"

            after_rev = await resumed_client.get("/api/v1/setup")
            assert after_rev.status_code == 200
            assert after_rev.json()["ready_monitor"] is True
            assert after_rev.json()["ready_repair"] is False
            assert after_rev.json()["readiness"] == "ready_monitor"

        # 6) Verify Ed25519 hash-chained audit log integrity across the full wizard run!
        with tempfile.TemporaryDirectory(prefix="red2pr_u07_ckpt_") as ckpt_dir:
            ed_priv = Ed25519PrivateKey.generate()
            pub_rec = export_ed25519_public_key_record(
                private_key=ed_priv,
                key_id="audit-key-u07",
                not_before=clock() - timedelta(days=1),
            )
            key_ring = KeyRing([pub_rec])
            ext_store = ExternalCheckpointStore(Path(ckpt_dir))
            async with instance_rls_session(iam.session_factory, mode="audit_verifier") as db:
                verified_count = await verify_audit_chain(
                    db,
                    external_store=ext_store,
                    keyring=key_ring,
                )
                assert verified_count >= 10
    finally:
        await app_engine.dispose()


# ---------------------------------------------------------------------------
# 3. Negative Setup, Bootstrap TTL, Checkpoint Conflict & Step-Up Cases (`T-INS-02-N`)
# ---------------------------------------------------------------------------


async def test_setup_wizard_negative_security_and_guardrail_invariants(
    migrated_db: PgTestUrls,
) -> None:
    """Verify bootstrap 15m TTL, query-secret rejection, guardrails, conflicts & step-up RBAC."""
    clock = ManualClock()
    app_engine, iam = _build_iam_stack(migrated_db.app_url, clock=clock)
    app = create_app()
    app.state.iam_service = iam
    transport = httpx.ASGITransport(app=app)

    try:
        # 1) Bootstrap token > 15m (901s) rejected; expired (410) & replayed (409) rejected
        with pytest.raises(ValueError, match="900 seconds"):
            await iam.issue_bootstrap_token(ttl_seconds=901)

        raw_expired_boot, _ = await iam.issue_bootstrap_token(ttl_seconds=900)
        clock.advance(minutes=16)

        async with httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL) as anon:
            csrf_0 = (await anon.get("/api/v1/auth/csrf")).json()["csrf_token"]

            # Query-string secret rejected (`400 secret_in_query_url`)
            q_setup = await anon.get("/api/v1/setup?bootstrap_token=leak123")
            assert q_setup.status_code == 400
            assert q_setup.json()["code"] == "secret_in_query_url"

            q_claim = await anon.post(
                "/api/v1/setup/claim?token=leak123",
                headers=_csrf_headers(csrf_0),
                json={
                    "bootstrap_token": raw_expired_boot,
                    "display_name": "Owner",
                    "email": "o@red2pr.local",
                    "password": OWNER_CREDENTIAL,
                },
            )
            assert q_claim.status_code == 400
            assert q_claim.json()["code"] == "secret_in_query_url"

            exp_claim = await anon.post(
                "/api/v1/setup/claim",
                headers=_csrf_headers(csrf_0),
                json={
                    "bootstrap_token": raw_expired_boot,
                    "display_name": "Owner",
                    "email": "o@red2pr.local",
                    "password": OWNER_CREDENTIAL,
                },
            )
            assert exp_claim.status_code == 410

        # Claim owner with fresh token, then verify replay returns 409
        raw_valid_boot, _ = await iam.issue_bootstrap_token(ttl_seconds=900)
        owner_client = httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL)
        try:
            pre_csrf = (await owner_client.get("/api/v1/auth/csrf")).json()["csrf_token"]
            ok_claim = await owner_client.post(
                "/api/v1/setup/claim",
                headers=_csrf_headers(pre_csrf),
                json={
                    "bootstrap_token": raw_valid_boot,
                    "display_name": "Owner U07 Neg",
                    "email": "owner.neg@red2pr.local",
                    "password": OWNER_CREDENTIAL,
                },
            )
            assert ok_claim.status_code == 201
            csrf = ok_claim.json()["csrf_token"]

            replay_claim = await owner_client.post(
                "/api/v1/setup/claim",
                headers=_csrf_headers(csrf),
                json={
                    "bootstrap_token": raw_valid_boot,
                    "display_name": "Replay Attacker",
                    "email": "replay@red2pr.local",
                    "password": OWNER_CREDENTIAL,
                },
            )
            assert replay_claim.status_code == 409

            ckpt = (await owner_client.get("/api/v1/setup")).json()["checkpoint"]

            # 2) Stale expected_checkpoint -> 409 checkpoint_conflict
            stale_resp = await owner_client.post(
                "/api/v1/setup/steps/topology_tls",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": "ckpt-stale-0000",
                    "action": "save",
                    "deployment_mode": "local",
                    "public_base_url": PUBLIC_BASE_URL,
                },
            )
            assert stale_resp.status_code == 409
            assert stale_resp.json()["code"] == "checkpoint_conflict"

            # 3) Mandatory phase cannot be skipped -> 422 mandatory_phase_cannot_skip
            skip_mand = await owner_client.post(
                "/api/v1/setup/steps/topology_tls",
                headers=_csrf_headers(csrf),
                json={"expected_checkpoint": ckpt, "action": "skip"},
            )
            assert skip_mand.status_code == 422
            assert skip_mand.json()["code"] == "mandatory_phase_cannot_skip"

            # 4) Remote topology with http:// rejected -> 422 tls_required_for_remote_topology
            rem_http = await owner_client.post(
                "/api/v1/setup/steps/topology_tls",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": ckpt,
                    "action": "save",
                    "deployment_mode": "server",
                    "public_base_url": "http://red2pr.corp.example:4280",
                    "tls_mode": "loopback_http",
                },
            )
            assert rem_http.status_code == 422
            assert rem_http.json()["code"] == "tls_required_for_remote_topology"

            # 5) require_baseline=False & auto_merge=True rejected -> 422
            bad_base = await owner_client.post(
                "/api/v1/setup/steps/repo_policy",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": ckpt,
                    "action": "save",
                    "require_baseline": False,
                },
            )
            assert bad_base.status_code == 422
            assert bad_base.json()["code"] == "baseline_proof_mandatory"

            bad_merge = await owner_client.post(
                "/api/v1/setup/steps/repo_policy",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": ckpt,
                    "action": "save",
                    "auto_merge": True,
                },
            )
            assert bad_merge.status_code == 422
            assert bad_merge.json()["code"] == "auto_merge_forbidden"

            # 6) auto_repair & ready_repair blocked (`409`) when gates unmet or $0 budget
            inf_c = (
                await owner_client.post(
                    "/api/v1/setup/consents",
                    headers=_csrf_headers(csrf),
                    json={
                        "purpose": "inference",
                        "scope": "instance",
                        "destination": "api.llama.com",
                        "data_classes": ["public"],
                        "policy_notice_acknowledged": True,
                    },
                )
            ).json()["id"]

            zero_budget = await owner_client.post(
                "/api/v1/setup/steps/model_consent",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": ckpt,
                    "action": "save",
                    "primary_model": "llama-4-maverick-17b-128e",
                    "inference_consent_id": inf_c,
                    "max_cost_per_session": {"amount": "0.00", "currency": "USD"},
                },
            )
            assert zero_budget.status_code == 200
            assert "Model budget is set to $0.00" in str(zero_budget.json())
            ckpt = zero_budget.json()["checkpoint"]

            auto_rep_blocked = await owner_client.post(
                "/api/v1/setup/steps/repo_policy",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": ckpt,
                    "action": "save",
                    "default_repo_mode": "auto_repair",
                },
            )
            assert auto_rep_blocked.status_code == 409
            assert auto_rep_blocked.json()["code"] == "readiness_gate_unmet"

            cert_rep_blocked = await owner_client.post(
                "/api/v1/setup/steps/readiness_review",
                headers=_csrf_headers(csrf),
                json={
                    "expected_checkpoint": ckpt,
                    "action": "save",
                    "target_readiness": "ready_repair",
                },
            )
            assert cert_rep_blocked.status_code == 409
            assert cert_rep_blocked.json()["code"] == "readiness_gate_unmet"

            # 7) Consent with 'secret' data class rejected (`422`)
            secret_consent = await owner_client.post(
                "/api/v1/setup/consents",
                headers=_csrf_headers(csrf),
                json={
                    "purpose": "inference",
                    "scope": "instance",
                    "destination": "api.llama.com",
                    "data_classes": ["secret"],
                    "policy_notice_acknowledged": True,
                },
            )
            assert secret_consent.status_code == 422

            # 8) Advance clock > 5m -> POST /api/v1/setup/endpoints requires fresh step-up!
            clock.advance(minutes=6)
            no_stepup_ep = await owner_client.post(
                "/api/v1/setup/endpoints",
                headers=_csrf_headers(csrf),
                json={
                    "adapter": "gitlab",
                    "scheme": "https",
                    "host": "gitlab.corp.internal",
                    "port": 443,
                    "cidrs": ["10.24.0.0/16"],
                },
            )
            assert no_stepup_ep.status_code == 403
            assert no_stepup_ep.json()["code"] == "step_up_required"

            # 9) Non-owner authenticated user gets audited 403 on `/api/v1/setup` & `/endpoints`
            bob_id = new_uuid7(now=clock())
            pwd_hash = PasswordHasher().hash(MEMBER_CREDENTIAL)
            async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
                ws_id = new_uuid7(now=clock())
                db.add(
                    UserModel(
                        id=bob_id,
                        username="bob-member",
                        email="bob.member@red2pr.local",
                        display_name="Bob Member",
                        password_hash=pwd_hash,
                        is_instance_owner=False,
                        status="active",
                        created_at=clock(),
                        updated_at=clock(),
                    )
                )
                await db.flush()
                db.add(
                    WorkspaceModel(
                        id=ws_id,
                        name="Bob WS",
                        slug="bob-ws",
                        owner_user_id=bob_id,
                        status="active",
                        created_at=clock(),
                        updated_at=clock(),
                    )
                )
                await db.flush()
                db.add(
                    MembershipModel(
                        id=new_uuid7(now=clock()),
                        workspace_id=ws_id,
                        user_id=bob_id,
                        role="admin",
                        invited_by_user_id=bob_id,
                        created_at=clock(),
                        updated_at=clock(),
                    )
                )

            async with httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL) as bob_cli:
                bob_pre = (await bob_cli.get("/api/v1/auth/csrf")).json()["csrf_token"]
                bob_login = await bob_cli.post(
                    "/api/v1/auth/login",
                    headers=_csrf_headers(bob_pre),
                    json={"identifier": "bob.member@red2pr.local", "password": MEMBER_CREDENTIAL},
                )
                assert bob_login.status_code == 200
                bob_csrf = bob_login.json()["csrf_token"]

                bob_setup = await bob_cli.get("/api/v1/setup")
                assert bob_setup.status_code == 403
                assert bob_setup.json()["code"] == "instance_owner_required"

                bob_ep = await bob_cli.post(
                    "/api/v1/setup/endpoints",
                    headers=_csrf_headers(bob_csrf),
                    json={
                        "adapter": "gitlab",
                        "scheme": "https",
                        "host": "gitlab.corp.internal",
                        "port": 443,
                        "cidrs": ["10.24.0.0/16"],
                    },
                )
                assert bob_ep.status_code == 403
                assert bob_ep.json()["code"] == "instance_owner_required"
        finally:
            await owner_client.aclose()
    finally:
        await app_engine.dispose()


# ---------------------------------------------------------------------------
# 4. Egress Proxy, DNS Rebinding, Private Endpoint TLS & Redirects (`SEC-014`, `SEC-033`, `ADR-037`)
# ---------------------------------------------------------------------------


async def test_egress_proxy_ssrf_blocks_dns_rebinding_custom_ca_and_redirects(
    migrated_db: PgTestUrls,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify SSRF blocklists, DNS pinning, step-up private TLS endpoints, and safe redirects."""
    clock = ManualClock()
    app_engine, iam = _build_iam_stack(migrated_db.app_url, clock=clock)
    app = create_app()
    app.state.iam_service = iam
    transport = httpx.ASGITransport(app=app)

    pki = _generate_pki_material(
        [
            "gitlab.corp.internal",
            "rebind.attacker.example",
            "public-a.example",
            "public-b.example",
        ]
    )

    def _upstream_handler(req: RecordedUpstreamRequest) -> tuple[int, dict[str, str], bytes]:
        if req.path == "/api/v4/version":
            return (200, {"Content-Type": "application/json"}, b'{"version":"17.5.0-ee"}')
        if req.path == "/probe":
            return (200, {"Content-Type": "text/plain"}, b"pinned-ok")
        if req.path == "/redirect-ssrf":
            return (302, {"Location": "http://169.254.169.254/latest/meta-data/"}, b"")
        if req.path == "/cross-start":
            return (302, {"Location": "https://public-b.example/cross-final"}, b"")
        if req.path == "/cross-final":
            return (200, {"Content-Type": "text/plain"}, b"cross-ok")
        if req.path.startswith("/loop-"):
            hop_n = int(req.path.split("-")[1])
            return (302, {"Location": f"https://public-a.example/loop-{hop_n + 1}"}, b"")
        return (200, {"Content-Type": "text/plain"}, b"default-ok")

    audit_events: list[EgressAuditEvent] = []

    try:
        async with LocalTlsHttpServer(pki=pki, handler=_upstream_handler) as tls_srv:
            tunnel = LoopbackTunnelNetworkBackend(local_port=tls_srv.port)
            dns = ScriptedDnsResolver(
                {
                    "gitlab.corp.internal": [("10.24.1.50",)],
                    "rebind.attacker.example": [
                        ("93.184.216.34",),
                        ("169.254.169.254",),
                    ],
                    "mixed-rr.attacker.example": [("93.184.216.34", "169.254.169.254")],
                    "public-a.example": [("93.184.216.34",)],
                    "public-b.example": [("93.184.216.35",)],
                }
            )
            allowlist = DbEndpointAllowlistProvider(iam.session_factory)
            engine = EgressPolicyEngine(
                dns_resolver=dns,
                allowlist_provider=allowlist,
                audit_sink=audit_events.append,
            )
            ca_resolver = InMemoryCaBundleResolver(
                {
                    "ref:corp-ca": pki.ca_pem,
                    "ref:wrong-ca": pki.wrong_ca_pem,
                }
            )

            # Poison ambient proxy env vars to prove `trust_env=False` ignores them!
            monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
            monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")

            # 1) Permanently forbidden & default-denied URLs blocked BEFORE any TCP socket opens
            forbidden_urls = [
                "https://127.0.0.1/admin",
                "https://[::1]/admin",
                "https://169.254.169.254/latest/meta-data/",
                "https://[::ffff:169.254.169.254]/latest/meta-data/",
                "https://[fd00:ec2::254]/latest/meta-data/",
                "https://[fe80::1]/link-local",
                "https://2130706433/int-loopback",
                "https://0x7f.0.0.1/hex-loopback",
                "file:///etc/passwd",
                "https://user:secret@public-a.example/probe",
                "http://public-a.example/cleartext",
                "https://10.24.1.50/unregistered-rfc1918",
                "https://172.16.5.4/unregistered-rfc1918",
                "https://192.168.1.10/unregistered-rfc1918",
                "https://100.64.1.1/unregistered-cgnat",
                "https://[fd12:3456::1]/unregistered-ula",
                "https://gitlab.corp.internal:8443/api/v4/version",
            ]
            async with EgressSafeHttpClient(
                adapter="gitlab",
                policy_engine=engine,
                ca_bundle_resolver=ca_resolver,
                network_backend=tunnel,
            ) as gitlab_client:
                for bad_url in forbidden_urls:
                    with pytest.raises(EgressBlockedError):
                        await gitlab_client.request("GET", bad_url)
                assert tunnel.connected_targets == []

            # 2) Owner step-up registers `gitlab.corp.internal:8443` (`10.24.0.0/16`, `ref:corp-ca`)
            owner_client, csrf, _ = await _claim_owner_client(transport, iam)
            try:
                # Verify API registration rejects loopback/metadata CIDRs (`422`)
                bad_ep_1 = await owner_client.post(
                    "/api/v1/setup/endpoints",
                    headers=_csrf_headers(csrf),
                    json={
                        "adapter": "gitlab",
                        "scheme": "https",
                        "host": "127.0.0.1",
                        "port": 443,
                        "cidrs": ["127.0.0.0/8"],
                    },
                )
                assert bad_ep_1.status_code == 422

                bad_ep_2 = await owner_client.post(
                    "/api/v1/setup/endpoints",
                    headers=_csrf_headers(csrf),
                    json={
                        "adapter": "gitlab",
                        "scheme": "https",
                        "host": "gitlab.corp.internal",
                        "port": 8443,
                        "cidrs": ["169.254.0.0/16"],
                    },
                )
                assert bad_ep_2.status_code == 422

                # Perform fresh step-up and register private GitLab endpoint
                clock.advance(minutes=10)
                step_up = await owner_client.post(
                    "/api/v1/auth/step-up",
                    headers=_csrf_headers(csrf),
                    json={"password": OWNER_CREDENTIAL},
                )
                assert step_up.status_code == 200
                csrf = owner_client.cookies.get("red2pr_csrf") or csrf

                reg_resp = await owner_client.post(
                    "/api/v1/setup/endpoints",
                    headers=_csrf_headers(csrf),
                    json={
                        "adapter": "gitlab",
                        "scheme": "https",
                        "host": "gitlab.corp.internal",
                        "port": 8443,
                        "cidrs": ["10.24.0.0/16"],
                        "ca_ref": "ref:corp-ca",
                        "description": "Internal GitLab Enterprise",
                    },
                )
                assert reg_resp.status_code == 201, reg_resp.text
                endpoint_id = reg_resp.json()["id"]

                # `adapter="gitlab"` now succeeds over REAL verified TLS + custom CA + SNI,
                # connecting strictly to literal `"10.24.1.50"`!
                async with EgressSafeHttpClient(
                    adapter="gitlab",
                    policy_engine=engine,
                    ca_bundle_resolver=ca_resolver,
                    network_backend=tunnel,
                ) as gitlab_client:
                    ok_priv = await gitlab_client.request(
                        "GET",
                        "https://gitlab.corp.internal:8443/api/v4/version",
                    )
                    assert ok_priv.status_code == 200
                    assert ok_priv.json()["version"] == "17.5.0-ee"
                    assert tunnel.connected_targets[-1] == ("10.24.1.50", 8443)
                    assert tls_srv.requests[-1].tls_sni == "gitlab.corp.internal"
                    assert tls_srv.requests[-1].headers["host"] == "gitlab.corp.internal:8443"

                # Different adapter (`adapter="webhook"`) for the SAME host is STILL DENIED!
                async with EgressSafeHttpClient(
                    adapter="webhook",
                    policy_engine=engine,
                    ca_bundle_resolver=ca_resolver,
                    network_backend=tunnel,
                ) as webhook_client:
                    with pytest.raises(EgressBlockedError) as exc_wrong_adapter:
                        await webhook_client.request(
                            "GET",
                            "https://gitlab.corp.internal:8443/api/v4/version",
                        )
                    assert exc_wrong_adapter.value.code == "egress_private_ip_denied"

                # Wrong CA bundle (`ref:wrong-ca`) fails TLS verification (`ConnectError`)!
                wrong_ca_map = InMemoryCaBundleResolver({"ref:corp-ca": pki.wrong_ca_pem})
                async with EgressSafeHttpClient(
                    adapter="gitlab",
                    policy_engine=engine,
                    ca_bundle_resolver=wrong_ca_map,
                    network_backend=tunnel,
                ) as untrusted_tls_client:
                    with pytest.raises(httpx.ConnectError):
                        await untrusted_tls_client.request(
                            "GET",
                            "https://gitlab.corp.internal:8443/api/v4/version",
                        )

                # Revoke endpoint -> `adapter="gitlab"` is immediately denied again!
                rev_ep = await owner_client.delete(
                    f"/api/v1/setup/endpoints/{endpoint_id}",
                    headers=_csrf_headers(csrf),
                )
                assert rev_ep.status_code == 200
                assert rev_ep.json()["revoked_at"] is not None

                async with EgressSafeHttpClient(
                    adapter="gitlab",
                    policy_engine=engine,
                    ca_bundle_resolver=ca_resolver,
                    network_backend=tunnel,
                ) as gitlab_client:
                    with pytest.raises(EgressBlockedError) as exc_revoked:
                        await gitlab_client.request(
                            "GET",
                            "https://gitlab.corp.internal:8443/api/v4/version",
                        )
                    assert exc_revoked.value.code == "egress_private_ip_denied"
            finally:
                await owner_client.aclose()

            # 3) Public HTTPS DNS Rebinding, Mixed RR, Redirect SSRF & Cross-Host Header Stripping
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".pem",
                encoding="utf-8",
                delete=False,
            ) as tmp_ca:
                tmp_ca.write(pki.ca_pem)
                public_ca_path = tmp_ca.name
            try:
                monkeypatch.setenv("SSL_CERT_FILE", public_ca_path)

                async with EgressSafeHttpClient(
                    adapter="github",
                    policy_engine=engine,
                    network_backend=tunnel,
                    max_redirects=3,
                ) as pub_client:
                    # Lookup #1 -> 93.184.216.34 (allowed & pinned at TCP connect)
                    r1 = await pub_client.request("GET", "https://rebind.attacker.example/probe")
                    assert r1.status_code == 200
                    assert r1.text == "pinned-ok"
                    assert tunnel.connected_targets[-1] == ("93.184.216.34", 443)
                    assert tls_srv.requests[-1].tls_sni == "rebind.attacker.example"
                    assert tls_srv.requests[-1].headers["host"] == "rebind.attacker.example"

                    # Lookup #2 -> 169.254.169.254 (DNS rebinding!) -> DENIED before socket connect!
                    before_count = len(tunnel.connected_targets)
                    with pytest.raises(EgressBlockedError) as exc_rebind:
                        await pub_client.request("GET", "https://rebind.attacker.example/probe")
                    assert exc_rebind.value.code == "egress_ip_permanently_denied"
                    assert len(tunnel.connected_targets) == before_count

                    # Mixed round-robin ["93.184.216.34", "169.254.169.254"] -> DENIED immediately!
                    with pytest.raises(EgressBlockedError) as exc_mixed:
                        await pub_client.request("GET", "https://mixed-rr.attacker.example/probe")
                    assert exc_mixed.value.code == "egress_ip_permanently_denied"
                    assert len(tunnel.connected_targets) == before_count

                    # Redirect hop to cloud metadata `http://169.254.169.254/...` -> DENIED (`403`)!
                    with pytest.raises(EgressBlockedError) as exc_redir_ssrf:
                        await pub_client.request("GET", "https://public-a.example/redirect-ssrf")
                    assert exc_redir_ssrf.value.status == 403

                    # Valid cross-host redirect strips credential headers (`SEC-033`)!
                    cross_resp = await pub_client.request(
                        "GET",
                        "https://public-a.example/cross-start",
                        headers={
                            "Authorization": "Bearer ghs_secret_123",
                            "Cookie": "session=secret_cookie",
                            "X-Gitlab-Token": "glpat-secret",
                            "X-Webhook-Secret": "whsec-123",
                            "Accept": "text/plain",
                        },
                    )
                    assert cross_resp.status_code == 200
                    assert cross_resp.text == "cross-ok"
                    hop_1_req = tls_srv.requests[-2]
                    hop_2_req = tls_srv.requests[-1]
                    assert hop_1_req.path == "/cross-start"
                    assert "authorization" in hop_1_req.headers
                    assert hop_2_req.path == "/cross-final"
                    assert hop_2_req.tls_sni == "public-b.example"
                    assert "authorization" not in hop_2_req.headers
                    assert "cookie" not in hop_2_req.headers
                    assert "x-gitlab-token" not in hop_2_req.headers
                    assert "x-webhook-secret" not in hop_2_req.headers
                    assert hop_2_req.headers.get("accept") == "text/plain"

                    # >3 redirect hops -> DENIED (`egress_redirect_limit_exceeded`)
                    with pytest.raises(EgressBlockedError) as exc_loop:
                        await pub_client.request("GET", "https://public-a.example/loop-0")
                    assert exc_loop.value.code == "egress_redirect_limit_exceeded"
            finally:
                os.unlink(public_ca_path)

            assert any(ev.decision == "deny" for ev in audit_events)
            assert any(ev.decision == "allow" for ev in audit_events)
    finally:
        await app_engine.dispose()
