"""PostgreSQL 16 + Real TLS 1.3 mTLS Worker Broker, Enrollment, Fence & Isolation Suite (`U14`).

Verifies against a real disposable PostgreSQL 16 instance (`pgserver` / `fsync=on`) and live
loopback `TLS 1.3` mTLS `MtlsH11Protocol` listeners:
- `0010_workers_and_sandbox_leases` expand/contract reversibility (`downgrade -> upgrade`), `>= 45`
  `FORCE ROW LEVEL SECURITY` tables (`workers`, `worker_enrollments`, `signing_keys`,
  `sandbox_leases`), and strict cross-workspace tenant isolation (`SEC-032`).
- `A-13`, `ADR-016`, `ADR-034`, `S-15`, `S-21`, `SEC-006`:
  - Non-owner workspace member denied `403 instance_owner_required` on `/api/v1/system/workers*`
    while `GET /api/v1/workspaces/{ws}/workers/readiness` succeeds without leaking global host IDs.
  - Instance owner step-up enforcement (`403 step_up_required` without 5-minute step-up),
    `ADR-016` `oci_trusted_local` risk-acknowledgement gate (`422`), and SHA-256 hashed one-time
    enrollment token persistence (zero plaintext tokens stored in PostgreSQL).
  - Real `TLS 1.3` bootstrap CSR exchange (`WorkerEnroller.enroll`) + `409` replay rejection +
    `410` expiry rejection + `400` browser `Cookie`/`Origin` rejection on `/internal/v1/*`.
  - Real `TLS 1.3` `ssl.CERT_REQUIRED` kernel socket enforcement: unauthenticated clients and
    clients presenting a rogue-CA certificate fail the TLS handshake; Worker A cert polling
    Worker B's `{worker_id}` returns `403 worker_identity_mismatch`.
- `T-SAN-01-P`, `T-SAN-01-N`, `W-04`, `W-08`, `NFR-02`, `NFR-14`, `ADR-035`, `SEC-013`, `SEC-017`,
  `SEC-021`, `SEC-029`, `SEC-030`:
  - End-to-end `WorkerSupervisor.poll_and_execute_once` over real loopback `TLS 1.3` mTLS:
    `poll -> 15s heartbeat -> HMAC upload (Redactor scrubbing before encrypted ArtifactStore write,
    403 disallowed slot, 413 >output_bytes cap) -> verified ephemeral cleanup -> external Ed25519
    DOMAIN_RESULT_V1 signed ResultV1 -> TaskJob completion`.
  - Idempotent identical `ResultV1` replay (`idempotent_replay=True`) vs conflicting duplicate
    `ResultV1` (`409 conflicting_duplicate_result` + auto-quarantine + `worker.quarantined` event).
  - Monotonic `lease_epoch` fence (`<=90s` stale reconciler emitting `worker.offline`, re-lease at
    `lease_epoch=2`, delayed `lease_epoch=1` heartbeat/upload/result rejected `409` with `0` stale
    DB writes).
  - Tampered `ResultV1` signature (`403`), substituted artifact ref (`409`), and failed
    `ephemeral_cleanup` check (`SEC-029`) all quarantine the worker.
  - Live cooperative cancellation (`cancel_requested=True` on heartbeat -> guest container killed ->
    verified cleanup -> `cancel-ack`).
  - `ADR-034` multi-workspace gate (`oci_trusted_local` blocked when `>1` active workspace exists),
    `SetupStepRegistry` `worker_readiness` live probe, operator `drain | resume | quarantine |
    revoke` actions (`S-05` `Idempotency-Key` + `409` mismatch + `412` stale `If-Match` + `403`
    revoked mTLS cert), and `verify_audit_chain`.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import io
import os
import ssl
import sys
import tarfile
import tempfile
from collections.abc import AsyncIterator, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import httpx
import pgserver
import pytest
import uvicorn
from fastapi import FastAPI
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from uvicorn.server import ServerState

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from py_contracts.crypto import (
    KeyRing,
    MasterKeyRing,
    generate_worker_ca_keypair,
    generate_worker_csr,
    issue_worker_client_certificate,
)
from py_contracts.primitives import new_uuid7
from py_contracts.worker import (
    IsolationCheckResult,
    ResultArtifactRef,
    ResultV1,
    SandboxJobV1,
    SandboxResourceLimits,
    SandboxResourceUsage,
    WorkerArtifactUploadRequest,
    WorkerIsolationAttestation,
    WorkerIsolationMode,
    WorkerJobHeartbeatRequest,
    WorkerPollRequest,
)
from red2pr_control.analytics_audit.audit_chain import (
    ExternalCheckpointStore,
    verify_audit_chain,
)
from red2pr_control.api.app import create_app
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.base import (
    ArtifactBlobModel,
    ArtifactModel,
    OutboxEventModel,
    ProviderConnectionModel,
    RepositoryModel,
    SandboxLeaseModel,
    SchemaMigrationRecordModel,
    SigningKeyModel,
    TaskJobModel,
    WorkerEnrollmentModel,
    WorkerModel,
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
from red2pr_control.operations.setup_wizard import SetupStepRegistry, SetupWizardService
from red2pr_control.orchestrator import (
    DurableTaskQueueService,
    MtlsH11Protocol,
    OperationReceiptService,
    ServerTlsMaterial,
    WorkerBrokerService,
)
from red2pr_control.secrets.broker import SecretBroker, SecretBrokerTotpVault
from red2pr_control.triage_evidence import (
    LocalEncryptedArtifactStore,
    read_artifact_for_authorized_caller,
)
from red2pr_worker import (
    ExternalResultSigner,
    GuestExecutionResult,
    HardenedOciInvocation,
    JobSandboxDirectories,
    MtlsWorkerCredentials,
    WorkerEnroller,
    WorkerSupervisor,
    build_worker_ssl_context,
    validate_oci_invocation_security,
)

APP_ROLE_NAME = "red2pr_app"
APP_ROLE_PASSWORD = "red2pr_app_local_test_pw_14"
PUBLIC_BASE_URL = "http://127.0.0.1:4280"
ORIGIN_HEADERS = {"Origin": PUBLIC_BASE_URL}
OWNER_CREDENTIAL = "OwnerSup3rStr0ng!Pass#14"
MEMBER_CREDENTIAL = "MemberSup3rStr0ng!Pass#14"
SECRET_CANARY_GH = "ghp_SecretCanaryTokenValue1234567890ABCD"


class ManualClock:
    """Deterministic controllable UTC clock for lease TTL, step-up & cert validity checks."""

    def __init__(self, initial: datetime | None = None) -> None:
        self._current = (initial or datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)).astimezone(UTC)

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


def _csrf_headers(
    token: str,
    *,
    idem_key: str | None = None,
    if_match: str | None = None,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    headers: dict[str, str] = {"X-CSRF-Token": token, **ORIGIN_HEADERS}
    if idem_key is not None:
        headers["Idempotency-Key"] = idem_key
    if if_match is not None:
        headers["If-Match"] = if_match
    if extra:
        headers.update(extra)
    return headers


def _make_tar_gz_bytes(entries: Mapping[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


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
        tempfile.TemporaryDirectory(prefix="red2pr_u14_pg16_") as tmp_dir,
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
    """Reset schema cleanly to head (`0010`) before each test."""
    run_alembic_downgrade(pg_urls.admin_url, "base", app_role_name=APP_ROLE_NAME)
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
    yield pg_urls


@dataclass
class U14Harness:
    app_engine: AsyncEngine
    app_factory: async_sessionmaker[AsyncSession]
    iam: IamService
    redactor: Redactor
    kek_ring: MasterKeyRing
    artifact_store: LocalEncryptedArtifactStore
    queue_service: DurableTaskQueueService
    worker_broker: WorkerBrokerService
    step_registry: SetupStepRegistry
    api_app: FastAPI
    store_dir: Path


def _build_u14_harness(
    app_url: str,
    *,
    clock: ManualClock,
    store_dir: Path,
) -> U14Harness:
    app_engine = create_app_engine(app_url, pool_size=8, max_overflow=8)
    app_factory = create_session_factory(app_engine)
    redactor = Redactor()
    kek_ring = MasterKeyRing(active_version=1, keys={1: b"\x7c" * 32})
    broker = SecretBroker(key_ring=kek_ring, redactor=redactor)
    totp_vault = SecretBrokerTotpVault(broker)

    iam = IamService(
        session_factory=app_factory,
        totp_vault=totp_vault,
        iam_seed_key=b"\x6d" * 32,
        public_base_url=PUBLIC_BASE_URL,
        clock=clock,
    )
    queue_service = DurableTaskQueueService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        redactor=redactor,
    )
    op_service = OperationReceiptService(session_factory=app_factory)
    artifact_store = LocalEncryptedArtifactStore(root_dir=store_dir, key_ring=kek_ring)
    worker_broker = WorkerBrokerService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        queue_service=queue_service,
        artifact_store=artifact_store,
        master_key_ring=kek_ring,
        redactor=redactor,
        clock=clock,
    )
    step_registry = SetupStepRegistry()
    setup_service = SetupWizardService(
        iam_service=iam,
        step_registry=step_registry,
        redactor=redactor,
    )
    api_app = create_app(
        iam_service=iam,
        setup_wizard_service=setup_service,
        setup_step_registry=step_registry,
        task_queue_service=queue_service,
        operation_receipt_service=op_service,
        worker_broker_service=worker_broker,
        artifact_store=artifact_store,
    )
    return U14Harness(
        app_engine=app_engine,
        app_factory=app_factory,
        iam=iam,
        redactor=redactor,
        kek_ring=kek_ring,
        artifact_store=artifact_store,
        queue_service=queue_service,
        worker_broker=worker_broker,
        step_registry=step_registry,
        api_app=api_app,
        store_dir=store_dir,
    )


@contextlib.asynccontextmanager
async def _start_loopback_tls13_server(
    app: FastAPI,
    tls_material: ServerTlsMaterial,
    *,
    cert_reqs: ssl.VerifyMode,
) -> AsyncIterator[str]:
    """Start a real OS TCP + OpenSSL TLS 1.3 `MtlsH11Protocol` listener on `127.0.0.1:0`."""
    ssl_ctx = tls_material.build_ssl_context(cert_reqs=cert_reqs)
    cfg = uvicorn.Config(
        app=app,
        host="127.0.0.1",
        port=0,
        http=MtlsH11Protocol,
        lifespan="off",
        access_log=False,
    )
    cfg.load()
    srv_state = ServerState()
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: MtlsH11Protocol(config=cfg, server_state=srv_state, app_state={}),
        host="127.0.0.1",
        port=0,
        ssl=ssl_ctx,
    )
    try:
        sock_port = int(server.sockets[0].getsockname()[1])
        yield f"https://127.0.0.1:{sock_port}"
    finally:
        server.close()
        await server.wait_closed()


def _build_bootstrap_tls_client(ca_cert_pem: str, *, base_url: str) -> httpx.AsyncClient:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations(cadata=ca_cert_pem)
    return httpx.AsyncClient(base_url=base_url, verify=ctx)


def _build_mtls_worker_client(
    credentials: MtlsWorkerCredentials,
    *,
    base_url: str,
) -> httpx.AsyncClient:
    ctx = build_worker_ssl_context(credentials, check_hostname=True)
    return httpx.AsyncClient(base_url=base_url, verify=ctx)


def _vm_attestation(host_id: str = "vm-worker-01.internal") -> WorkerIsolationAttestation:
    return WorkerIsolationAttestation(
        isolation_mode="vm_isolated",
        runtime_name="firecracker",
        host_id=host_id,
        rootless_verified=True,
        seccomp_verified=True,
        no_new_privileges_verified=True,
        network_none_supported=True,
        cpu_limit=4,
        memory_limit_bytes=8_589_934_592,
        disk_limit_bytes=21_474_836_480,
        pids_limit=512,
    )


def _trusted_local_attestation(host_id: str = "docker-dev-01.local") -> WorkerIsolationAttestation:
    return WorkerIsolationAttestation(
        isolation_mode="oci_trusted_local",
        runtime_name="docker",
        host_id=host_id,
        rootless_verified=False,
        seccomp_verified=True,
        no_new_privileges_verified=True,
        network_none_supported=True,
        cpu_limit=4,
        memory_limit_bytes=8_589_934_592,
        disk_limit_bytes=21_474_836_480,
        pids_limit=512,
    )


class _HermeticIsolatedDriver:
    """Hermetic `SandboxRuntimeDriver` validating `HardenedOciInvocation` and staging worktree."""

    def __init__(
        self,
        attestation: WorkerIsolationAttestation,
        *,
        stdout_payload: bytes = b"1 passed in 0.04s\n",
        stderr_payload: bytes = b"",
        junit_xml: bytes | None = None,
        exit_code: int = 0,
        wait_for_cancel: bool = False,
        on_started: asyncio.Event | None = None,
    ) -> None:
        self._attestation = attestation
        self._stdout = stdout_payload
        self._stderr = stderr_payload
        self._junit = junit_xml
        self._exit_code = exit_code
        self._wait_for_cancel = wait_for_cancel
        self._on_started = on_started
        self.invocations: list[HardenedOciInvocation] = []
        self.observed_files: list[str] = []

    @property
    def isolation_mode(self) -> WorkerIsolationMode:
        return self._attestation.isolation_mode

    async def probe_isolation(self) -> WorkerIsolationAttestation:
        return self._attestation

    async def execute_job(
        self,
        job: SandboxJobV1,
        *,
        invocation: HardenedOciInvocation,
        dirs: JobSandboxDirectories,
        cancel_event: asyncio.Event,
    ) -> GuestExecutionResult:
        _ = job
        validate_oci_invocation_security(invocation)
        self.invocations.append(invocation)
        self.observed_files = sorted(
            p.relative_to(dirs.worktree_dir).as_posix()
            for p in dirs.worktree_dir.rglob("*")
            if p.is_file()
        )
        if self._on_started is not None:
            self._on_started.set()

        if self._wait_for_cancel:
            await asyncio.wait_for(cancel_event.wait(), timeout=5.0)
            return GuestExecutionResult(
                exit_code=130,
                timed_out=False,
                cancelled=True,
                oom_killed=False,
                infrastructure_error=False,
                stdout_bytes=b"Execution interrupted by operator cancel.\n",
                stderr_bytes=b"",
                stdout_truncated=False,
                stderr_truncated=False,
                resource_usage=SandboxResourceUsage(
                    wall_ms=120,
                    max_memory_bytes=32_000_000,
                    disk_written_bytes=0,
                    output_bytes=42,
                ),
                isolation_checks=(
                    IsolationCheckResult(
                        check_id="network_none",
                        passed=True,
                        detail="Verified network=none",
                    ),
                ),
                output_files={},
            )

        out_files: dict[str, bytes] = {}
        if self._junit is not None:
            out_files["junit_xml"] = self._junit

        return GuestExecutionResult(
            exit_code=self._exit_code,
            timed_out=False,
            cancelled=False,
            oom_killed=False,
            infrastructure_error=False,
            stdout_bytes=self._stdout,
            stderr_bytes=self._stderr,
            stdout_truncated=False,
            stderr_truncated=False,
            resource_usage=SandboxResourceUsage(
                wall_ms=85,
                max_memory_bytes=64_000_000,
                disk_written_bytes=len(self._junit or b""),
                output_bytes=len(self._stdout) + len(self._stderr),
            ),
            isolation_checks=(
                IsolationCheckResult(
                    check_id="network_none",
                    passed=True,
                    detail="Verified network=none (--network=none)",
                ),
                IsolationCheckResult(
                    check_id="read_only_rootfs",
                    passed=True,
                    detail="Verified --read-only rootfs",
                ),
                IsolationCheckResult(
                    check_id="seccomp_capdrop_nnp",
                    passed=True,
                    detail="Verified --cap-drop=ALL + no-new-privileges + seccomp",
                ),
            ),
            output_files=out_files,
        )

    async def force_kill_job(self, job_id: str) -> Sequence[str]:
        _ = job_id
        return ()

    async def run_self_test(self) -> tuple[bool, tuple[IsolationCheckResult, ...], str]:
        return True, (), "Hermetic self-test passed."


async def _claim_owner_and_seed_repo(
    harness: U14Harness,
    *,
    now: datetime,
    ws_slug: str = "acme",
    ws_name: str = "Acme Core",
) -> tuple[httpx.AsyncClient, str, str, str, str]:
    transport = httpx.ASGITransport(app=harness.api_app)
    raw_boot, _ = await harness.iam.issue_bootstrap_token()
    client = httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL)
    pre_csrf = str((await client.get("/api/v1/auth/csrf")).json()["csrf_token"])

    claim_resp = await client.post(
        "/api/v1/setup/claim",
        headers=_csrf_headers(pre_csrf),
        json={
            "bootstrap_token": raw_boot,
            "display_name": "Owner U14",
            "email": "owner.u14@red2pr.local",
            "password": OWNER_CREDENTIAL,
        },
    )
    assert claim_resp.status_code == 201, claim_resp.text
    csrf = str(claim_resp.json()["csrf_token"])
    owner_id = str(claim_resp.json()["user"]["id"])

    ws_resp = await client.post(
        "/api/v1/workspaces",
        headers=_csrf_headers(csrf),
        json={"name": ws_name, "slug": ws_slug},
    )
    assert ws_resp.status_code == 201, ws_resp.text
    ws_id = str(ws_resp.json()["id"])

    conn_id = new_uuid7(now=now)
    repo_id = new_uuid7(now=now)
    async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as ws_db:
        ws_db.add(
            ProviderConnectionModel(
                id=conn_id,
                workspace_id=ws_id,
                provider="github",
                auth_mode="github_app",
                display_name="GitHub U14",
                base_url="https://api.github.com",
                status="ready",
                capabilities_json={"checks": "read", "contents": "read"},
                created_at=now,
                updated_at=now,
            )
        )
        await ws_db.flush()
        ws_db.add(
            RepositoryModel(
                id=repo_id,
                workspace_id=ws_id,
                provider_connection_id=conn_id,
                external_repo_id="repo-ext-u14-01",
                name="acme/core-service",
                default_branch="main",
                visibility="private",
                mode="approval",
                archived=False,
                created_at=now,
                updated_at=now,
            )
        )
        await ws_db.flush()

    return client, csrf, owner_id, ws_id, repo_id


async def _step_up_owner(client: httpx.AsyncClient, csrf: str) -> str:
    resp = await client.post(
        "/api/v1/auth/step-up",
        headers=_csrf_headers(csrf),
        json={"password": OWNER_CREDENTIAL},
    )
    assert resp.status_code == 200, resp.text
    return str(resp.json().get("csrf_token") or csrf)


async def test_migration_0010_reversibility_and_rls_isolation(
    migrated_db: PgTestUrls,
    tmp_path: Path,
) -> None:
    """Verify `0010` downgrade/upgrade reversibility, `>=45` forced-RLS tables & `SEC-032` RLS."""
    run_alembic_downgrade(
        migrated_db.admin_url,
        "0009_ci_runs_jobs_artifacts",
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
            assert len(forced_names) >= 45
            assert {
                "workers",
                "worker_enrollments",
                "signing_keys",
                "sandbox_leases",
            }.issubset(forced_names)

            rec_session_factory = create_session_factory(admin_engine)
            async with rec_session_factory() as db:
                rev = await db.scalar(
                    select(SchemaMigrationRecordModel).where(
                        SchemaMigrationRecordModel.revision == "0010_workers_and_sandbox_leases"
                    )
                )
                assert rev is not None
    finally:
        await admin_engine.dispose()

    clock = ManualClock()
    harness = _build_u14_harness(migrated_db.app_url, clock=clock, store_dir=tmp_path / "artifacts")
    try:
        owner_client, csrf, _, ws_a_id, repo_a_id = await _claim_owner_and_seed_repo(
            harness,
            now=clock(),
            ws_slug="ws-alpha",
            ws_name="Alpha",
        )
        ws_b_resp = await owner_client.post(
            "/api/v1/workspaces",
            headers=_csrf_headers(csrf),
            json={"name": "Beta", "slug": "ws-beta"},
        )
        assert ws_b_resp.status_code == 201
        ws_b_id = str(ws_b_resp.json()["id"])

        # Seed a worker + job + SandboxLease in Workspace A
        worker_id = new_uuid7(now=clock())
        async with instance_rls_session(harness.app_factory, mode="instance_only") as db:
            db.add(
                WorkerModel(
                    id=worker_id,
                    host_id="rls-test-host",
                    trust_domain="worker-supervisor",
                    isolation_mode="vm_isolated",
                    runtime_name="firecracker",
                    profile_ids_json=["python-3.12-node-22"],
                    capabilities_json={"network_none": True, "rootless": True},
                    cpu_limit=2,
                    memory_limit_bytes=2_147_483_648,
                    disk_limit_bytes=10_737_418_240,
                    pids_limit=256,
                    status="online",
                    heartbeat_at=clock(),
                    mtls_cert_serial="01aa22bb",
                    mtls_cert_fingerprint_sha256="a" * 64,
                    mtls_cert_pem="-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
                    mtls_cert_expires_at=clock() + timedelta(hours=12),
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
            await db.flush()

        job_id = await harness.worker_broker.enqueue_sandbox_job(
            workspace_id=ws_a_id,
            repository_id=repo_a_id,
            repair_id=new_uuid7(now=clock()),
            profile_id="python-3.12-node-22",
            image_digest=("b" * 64),
            base_sha="1" * 40,
            source_archive_digest="c" * 64,
            command_ids=["pytest-unit"],
            correlation_id="corr-rls-01",
            now=clock(),
        )

        lease_id = new_uuid7(now=clock())
        async with workspace_rls_session(harness.app_factory, workspace_id=ws_a_id) as ws_db:
            ws_db.add(
                SandboxLeaseModel(
                    id=lease_id,
                    workspace_id=ws_a_id,
                    repository_id=repo_a_id,
                    repair_id=new_uuid7(now=clock()),
                    job_id=job_id,
                    worker_id=worker_id,
                    lease_epoch=1,
                    capability_nonce="nonce_rls_01",
                    expected_worker_trust_domain="worker-supervisor",
                    profile_id="python-3.12-node-22",
                    profile_revision=1,
                    image_digest=("b" * 64),
                    base_sha="1" * 40,
                    source_archive_digest="c" * 64,
                    network_policy_digest="d" * 64,
                    supervisor_policy_digest="e" * 64,
                    sandbox_job_json={"job_id": job_id},
                    upload_slots_json=["stdout"],
                    uploaded_artifacts_json=[],
                    output_bytes_uploaded=0,
                    status="leased",
                    issued_at=clock(),
                    heartbeat_at=clock(),
                    lease_expires_at=clock() + timedelta(seconds=60),
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
            await ws_db.flush()

        # Workspace B MUST see 0 Workspace A sandbox leases AND cannot insert into Workspace A!
        async with workspace_rls_session(harness.app_factory, workspace_id=ws_b_id) as ws_b_db:
            visible = (await ws_b_db.scalars(select(SandboxLeaseModel))).all()
            assert visible == []

        with pytest.raises(DBAPIError):
            async with workspace_rls_session(harness.app_factory, workspace_id=ws_b_id) as ws_b_db:
                ws_b_db.add(
                    SandboxLeaseModel(
                        id=new_uuid7(now=clock()),
                        workspace_id=ws_a_id,
                        repository_id=repo_a_id,
                        repair_id=new_uuid7(now=clock()),
                        job_id=job_id,
                        worker_id=worker_id,
                        lease_epoch=99,
                        capability_nonce="cross_tenant_attempt",
                        expected_worker_trust_domain="worker-supervisor",
                        profile_id="python-3.12-node-22",
                        profile_revision=1,
                        image_digest=("b" * 64),
                        base_sha="1" * 40,
                        source_archive_digest="c" * 64,
                        network_policy_digest="d" * 64,
                        supervisor_policy_digest="e" * 64,
                        sandbox_job_json={},
                        upload_slots_json=[],
                        uploaded_artifacts_json=[],
                        output_bytes_uploaded=0,
                        status="leased",
                        issued_at=clock(),
                        heartbeat_at=clock(),
                        lease_expires_at=clock() + timedelta(seconds=60),
                        created_at=clock(),
                        updated_at=clock(),
                    )
                )
                await ws_b_db.flush()

        await owner_client.aclose()
    finally:
        await harness.app_engine.dispose()


async def test_a13_rbac_step_up_adr016_enrollment_and_real_tls13_mtls_handshake(
    migrated_db: PgTestUrls,
    tmp_path: Path,
) -> None:
    """Verify `A-13` owner RBAC, step-up, `ADR-016` gate, CSR replay & real `TLS 1.3` mTLS."""
    clock = ManualClock(datetime.now(tz=UTC) - timedelta(hours=2))
    harness = _build_u14_harness(migrated_db.app_url, clock=clock, store_dir=tmp_path / "artifacts")
    try:
        owner_client, owner_csrf, _, _ws_id, _ = await _claim_owner_and_seed_repo(
            harness,
            now=clock(),
        )

        # Provision non-owner workspace admin and verify strict `ADR-034` owner boundary:
        await harness.iam.provision_local_user(
            display_name="Workspace Admin Bob",
            email="bob.admin@red2pr.local",
            password=MEMBER_CREDENTIAL,
        )
        inv_resp = await owner_client.post(
            "/api/v1/workspaces/acme/invitations",
            headers=_csrf_headers(owner_csrf),
            json={"email": "bob.admin@red2pr.local", "role": "admin", "repository_grants": []},
        )
        assert inv_resp.status_code == 201, inv_resp.text
        invite_token = str(inv_resp.json()["invite_token"])

        transport = httpx.ASGITransport(app=harness.api_app)
        member_client = httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL)
        m_pre_csrf = str((await member_client.get("/api/v1/auth/csrf")).json()["csrf_token"])
        m_login = await member_client.post(
            "/api/v1/auth/login",
            headers=_csrf_headers(m_pre_csrf),
            json={"identifier": "bob.admin@red2pr.local", "password": MEMBER_CREDENTIAL},
        )
        assert m_login.status_code == 200
        member_csrf = str(m_login.json()["csrf_token"])

        acc_resp = await member_client.post(
            "/api/v1/invitations/accept",
            headers=_csrf_headers(member_csrf),
            json={"token": invite_token},
        )
        assert acc_resp.status_code == 200, acc_resp.text

        assert (await member_client.get("/api/v1/system/workers")).status_code == 403
        deny_enroll = await member_client.post(
            "/api/v1/system/workers/enrollments",
            headers=_csrf_headers(member_csrf),
            json={
                "trust_domain": "worker-supervisor",
                "profile_ids": ["python-3.12-node-22"],
                "isolation_mode": "vm_isolated",
                "ttl_minutes": 15,
            },
        )
        assert deny_enroll.status_code == 403
        assert deny_enroll.json()["code"] == "instance_owner_required"

        # Workspace-scoped readiness endpoint IS accessible to workspace members with zero host IDs:
        ws_ready_0 = await member_client.get("/api/v1/workspaces/acme/workers/readiness")
        assert ws_ready_0.status_code == 200
        assert ws_ready_0.json()["ready"] is False
        assert "host_id" not in ws_ready_0.text

        # Advance past initial setup claim step-up window (6m) -> 403 step_up_required
        clock.advance(minutes=6)
        no_step_up = await owner_client.post(
            "/api/v1/system/workers/enrollments",
            headers=_csrf_headers(owner_csrf),
            json={
                "trust_domain": "worker-supervisor",
                "profile_ids": ["python-3.12-node-22"],
                "isolation_mode": "vm_isolated",
                "ttl_minutes": 15,
            },
        )
        assert no_step_up.status_code == 403
        assert no_step_up.json()["code"] == "step_up_required"

        owner_csrf = await _step_up_owner(owner_client, owner_csrf)

        # ADR-016: `oci_trusted_local` without `host_escape_risk_acknowledged=True` MUST fail 422!
        unacked = await owner_client.post(
            "/api/v1/system/workers/enrollments",
            headers=_csrf_headers(owner_csrf),
            json={
                "trust_domain": "worker-supervisor",
                "profile_ids": ["python-3.12-node-22"],
                "isolation_mode": "oci_trusted_local",
                "host_escape_risk_acknowledged": False,
                "ttl_minutes": 15,
            },
        )
        assert unacked.status_code == 422

        # Mint valid one-time enrollment token for `vm_isolated` worker:
        enroll_create = await owner_client.post(
            "/api/v1/system/workers/enrollments",
            headers=_csrf_headers(owner_csrf),
            json={
                "trust_domain": "worker-supervisor",
                "profile_ids": ["python-3.12-node-22"],
                "isolation_mode": "vm_isolated",
                "ttl_minutes": 15,
            },
        )
        assert enroll_create.status_code == 201, enroll_create.text
        enroll_data = enroll_create.json()
        raw_token = str(enroll_data["enrollment_token"])
        ca_cert_pem = str(enroll_data["ca_cert_pem"])

        # Verify DB stores ONLY SHA-256 hash, never raw token (`SEC-017` / Principle 6):
        async with instance_rls_session(harness.app_factory, mode="instance_only") as db:
            e_row = await db.scalar(
                select(WorkerEnrollmentModel).where(
                    WorkerEnrollmentModel.id == enroll_data["enrollment_id"]
                )
            )
            assert e_row is not None
            assert e_row.token_hash == hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
            assert raw_token not in e_row.token_hash

        # Mint a second token to prove expiry (`410`) and a third for Worker B identity mismatch:
        exp_token_resp = await owner_client.post(
            "/api/v1/system/workers/enrollments",
            headers=_csrf_headers(owner_csrf),
            json={
                "trust_domain": "worker-supervisor",
                "profile_ids": ["python-3.12-node-22"],
                "isolation_mode": "vm_isolated",
                "ttl_minutes": 5,
            },
        )
        assert exp_token_resp.status_code == 201
        exp_raw_token = str(exp_token_resp.json()["enrollment_token"])

        wb_token_resp = await owner_client.post(
            "/api/v1/system/workers/enrollments",
            headers=_csrf_headers(owner_csrf),
            json={
                "trust_domain": "worker-supervisor",
                "profile_ids": ["python-3.12-node-22"],
                "isolation_mode": "vm_isolated",
                "ttl_minutes": 30,
            },
        )
        assert wb_token_resp.status_code == 201
        wb_raw_token = str(wb_token_resp.json()["enrollment_token"])

        server_tls = await harness.worker_broker.ca.issue_server_bundle(now=clock())
        async with (
            _start_loopback_tls13_server(
                harness.api_app,
                server_tls,
                cert_reqs=ssl.CERT_OPTIONAL,
            ) as bootstrap_url,
            _start_loopback_tls13_server(
                harness.api_app,
                server_tls,
                cert_reqs=ssl.CERT_REQUIRED,
            ) as strict_mtls_url,
        ):
            enroller = WorkerEnroller()
            signer_a = ExternalResultSigner.generate(
                key_id="ed25519-worker-a-01",
                not_before=clock(),
            )
            signer_b = ExternalResultSigner.generate(
                key_id="ed25519-worker-b-01",
                not_before=clock(),
            )

            async with _build_bootstrap_tls_client(ca_cert_pem, base_url=bootstrap_url) as boot_cli:
                # Browser Cookie/Origin headers on /internal/v1/* MUST fail 400 (`S-21`):
                bad_cookie = await boot_cli.post(
                    "/internal/v1/workers/enroll",
                    headers={"Cookie": "__Host-red2pr_session=forged"},
                    json={
                        "enrollment_token": raw_token,
                        "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n",
                        "signer_public_key": signer_a.public_key_record.model_dump(mode="json"),
                        "attestation": _vm_attestation().model_dump(mode="json"),
                        "profile_ids": ["python-3.12-node-22"],
                    },
                )
                assert bad_cookie.status_code == 400
                assert bad_cookie.json()["code"] == "browser_session_forbidden_on_worker_protocol"

                # Enroll Worker A + Worker B over real TLS 1.3:
                creds_a = await enroller.enroll(
                    client=boot_cli,
                    enrollment_token=raw_token,
                    supported_profiles=["python-3.12-node-22"],
                    signer=signer_a,
                    attestation=_vm_attestation("vm-host-alpha.internal"),
                    now=clock(),
                )
                creds_b = await enroller.enroll(
                    client=boot_cli,
                    enrollment_token=wb_raw_token,
                    supported_profiles=["python-3.12-node-22"],
                    signer=signer_b,
                    attestation=_vm_attestation("vm-host-beta.internal"),
                    now=clock(),
                )

                # Replaying consumed one-time token MUST fail 409 (`enrollment_token_already_used`):
                csr_replay, _ = generate_worker_csr(
                    host_id="replay-host",
                    trust_domain="worker-supervisor",
                )
                replay_signer = ExternalResultSigner.generate(
                    key_id="ed25519-replay-01",
                    not_before=clock(),
                )
                replay_resp = await boot_cli.post(
                    "/internal/v1/workers/enroll",
                    json={
                        "enrollment_token": raw_token,
                        "csr_pem": csr_replay,
                        "signer_public_key": replay_signer.public_key_record.model_dump(
                            mode="json"
                        ),
                        "attestation": _vm_attestation("replay-host").model_dump(mode="json"),
                        "profile_ids": ["python-3.12-node-22"],
                    },
                )
                assert replay_resp.status_code == 409
                assert replay_resp.json()["code"] == "enrollment_token_already_used"

                # Unauthenticated poll on CERT_OPTIONAL port fails 401 defense-in-depth:
                unauth_poll = await boot_cli.post(
                    f"/internal/v1/workers/{creds_a.worker_id}/poll",
                    json=WorkerPollRequest().model_dump(mode="json"),
                )
                assert unauth_poll.status_code == 401
                assert unauth_poll.json()["code"] == "mtls_client_certificate_required"

                # Advance clock 6m -> `exp_raw_token` (ttl=5m) MUST fail 410!
                clock.advance(minutes=6)
                exp_signer = ExternalResultSigner.generate(
                    key_id="ed25519-exp-01",
                    not_before=clock(),
                )
                exp_resp = await boot_cli.post(
                    "/internal/v1/workers/enroll",
                    json={
                        "enrollment_token": exp_raw_token,
                        "csr_pem": csr_replay,
                        "signer_public_key": exp_signer.public_key_record.model_dump(mode="json"),
                        "attestation": _vm_attestation("exp-host").model_dump(mode="json"),
                        "profile_ids": ["python-3.12-node-22"],
                    },
                )
                assert exp_resp.status_code == 410
                assert exp_resp.json()["code"] == "enrollment_token_expired"

            # Strict `ssl.CERT_REQUIRED` mTLS listener:
            # 1) Client WITHOUT client certificate MUST fail TLS 1.3 handshake!
            async with _build_bootstrap_tls_client(
                ca_cert_pem,
                base_url=strict_mtls_url,
            ) as no_cert_cli:
                with pytest.raises((httpx.HTTPError, ssl.SSLError)):
                    await no_cert_cli.post(
                        f"/internal/v1/workers/{creds_a.worker_id}/poll",
                        json=WorkerPollRequest().model_dump(mode="json"),
                    )

            # 2) Client with ROGUE CA certificate MUST fail TLS 1.3 handshake!
            rogue_ca_cert, rogue_ca_key = generate_worker_ca_keypair(now=clock())
            rogue_csr, rogue_key = generate_worker_csr(
                host_id="rogue-host",
                trust_domain="worker-supervisor",
            )
            rogue_leaf, _, _, _ = issue_worker_client_certificate(
                ca_cert_pem=rogue_ca_cert,
                ca_private_key_pem=rogue_ca_key,
                csr_pem=rogue_csr,
                worker_id=creds_a.worker_id,
                trust_domain="worker-supervisor",
                now=clock(),
            )
            rogue_creds = MtlsWorkerCredentials(
                worker_id=creds_a.worker_id,
                spiffe_id=creds_a.spiffe_id,
                cert_serial="deadbeef",
                cert_fingerprint_sha256="f" * 64,
                cert_expires_at=clock() + timedelta(hours=1),
                client_key_pem=rogue_key,
                client_cert_pem=rogue_leaf,
                ca_cert_pem=ca_cert_pem,
                signer_key_id=signer_a.key_id,
                isolation_mode="vm_isolated",
                trust_domain="worker-supervisor",
            )
            async with _build_mtls_worker_client(
                rogue_creds,
                base_url=strict_mtls_url,
            ) as rogue_cli:
                with pytest.raises((httpx.HTTPError, ssl.SSLError)):
                    await rogue_cli.post(
                        f"/internal/v1/workers/{creds_a.worker_id}/poll",
                        json=WorkerPollRequest().model_dump(mode="json"),
                    )

            # 3) Enrolled Worker A mTLS cert succeeds on own worker_id (`200`) and fails `403`
            #    when attempting to impersonate Worker B (`worker_identity_mismatch`):
            async with _build_mtls_worker_client(
                creds_a,
                base_url=strict_mtls_url,
            ) as worker_a_cli:
                own_poll = await worker_a_cli.post(
                    f"/internal/v1/workers/{creds_a.worker_id}/poll",
                    json=WorkerPollRequest().model_dump(mode="json"),
                )
                assert own_poll.status_code == 200
                assert own_poll.json()["worker_status"] == "online"

                cross_poll = await worker_a_cli.post(
                    f"/internal/v1/workers/{creds_b.worker_id}/poll",
                    json=WorkerPollRequest().model_dump(mode="json"),
                )
                assert cross_poll.status_code == 403
                assert cross_poll.json()["code"] == "worker_identity_mismatch"

        await member_client.aclose()
        await owner_client.aclose()
    finally:
        await harness.app_engine.dispose()


async def test_end_to_end_mtls_worker_supervisor_cycle_redaction_and_idempotency(
    migrated_db: PgTestUrls,
    tmp_path: Path,
) -> None:
    """`T-SAN-01-P`, `W-04`, `W-08`, `SEC-017`, `SEC-030`: Full supervisor execution over TLS 1.3,
    secret redaction before encrypted storage, slot/size caps, and duplicate result quarantine."""
    clock = ManualClock(datetime.now(tz=UTC) - timedelta(hours=2))
    harness = _build_u14_harness(migrated_db.app_url, clock=clock, store_dir=tmp_path / "artifacts")
    try:
        owner_client, owner_csrf, _, ws_id, repo_id = await _claim_owner_and_seed_repo(
            harness,
            now=clock(),
        )
        owner_csrf = await _step_up_owner(owner_client, owner_csrf)

        enroll_resp = await owner_client.post(
            "/api/v1/system/workers/enrollments",
            headers=_csrf_headers(owner_csrf),
            json={
                "trust_domain": "worker-supervisor",
                "profile_ids": ["python-3.12-node-22"],
                "isolation_mode": "vm_isolated",
                "ttl_minutes": 30,
            },
        )
        assert enroll_resp.status_code == 201
        raw_token = str(enroll_resp.json()["enrollment_token"])
        ca_cert_pem = str(enroll_resp.json()["ca_cert_pem"])

        server_tls = await harness.worker_broker.ca.issue_server_bundle(now=clock())
        async with (
            _start_loopback_tls13_server(
                harness.api_app,
                server_tls,
                cert_reqs=ssl.CERT_OPTIONAL,
            ) as bootstrap_url,
            _start_loopback_tls13_server(
                harness.api_app,
                server_tls,
                cert_reqs=ssl.CERT_REQUIRED,
            ) as strict_mtls_url,
        ):
            signer = ExternalResultSigner.generate(key_id="ed25519-e2e-01", not_before=clock())
            signer.save_to_directory(tmp_path / "worker_keys")
            async with _build_bootstrap_tls_client(ca_cert_pem, base_url=bootstrap_url) as boot_cli:
                creds = await WorkerEnroller().enroll(
                    client=boot_cli,
                    enrollment_token=raw_token,
                    supported_profiles=["python-3.12-node-22"],
                    signer=signer,
                    attestation=_vm_attestation("vm-e2e-01.internal"),
                    now=clock(),
                )
            creds.save_to_directory(tmp_path / "worker_state")
            reloaded_creds = MtlsWorkerCredentials.load_from_directory(tmp_path / "worker_state")

            # Stage a repository tar.gz snapshot and enqueue a `sandbox.execute` job:
            archive_bytes = _make_tar_gz_bytes(
                {
                    "src/calc.py": b"def mul(a: int, b: int) -> int:\n    return a * b\n",
                    "tests/test_calc.py": (
                        b"from src.calc import mul\ndef test_mul(): assert mul(6, 7) == 42\n"
                    ),
                }
            )
            archive_digest = harness.worker_broker.register_source_archive(archive_bytes)
            job_id = await harness.worker_broker.enqueue_sandbox_job(
                workspace_id=ws_id,
                repository_id=repo_id,
                repair_id=new_uuid7(now=clock()),
                profile_id="python-3.12-node-22",
                image_digest=("9" * 64),
                base_sha="a" * 40,
                source_archive_digest=archive_digest,
                command_ids=["pytest-unit"],
                correlation_id="corr-u14-e2e-01",
                now=clock(),
                resource_limits=SandboxResourceLimits(
                    cpu=2,
                    memory_bytes=2_147_483_648,
                    disk_bytes=10_737_418_240,
                    pids=256,
                    wall_seconds=120,
                    output_bytes=4096,
                ),
                allowed_output_slots=("stdout", "stderr", "junit_xml"),
                requires_vm_isolation=True,
            )

            stdout_with_secret = (
                f"pytest collected 1 item\nTOKEN={SECRET_CANARY_GH}\n1 passed in 0.03s\n"
            ).encode()
            junit_bytes = (
                b'<testsuite tests="1" failures="0"><testcase name="test_mul"/></testsuite>'
            )
            driver = _HermeticIsolatedDriver(
                _vm_attestation("vm-e2e-01.internal"),
                stdout_payload=stdout_with_secret,
                stderr_payload=b"",
                junit_xml=junit_bytes,
                exit_code=0,
            )
            scratch_dir = tmp_path / "guest_scratch"
            supervisor = WorkerSupervisor(
                credentials=reloaded_creds,
                signer=signer,
                driver=driver,
                scratch_dir=scratch_dir,
                state_dir=tmp_path / "supervisor_runtime",
                heartbeat_interval_seconds=0.25,
            )

            async with _build_mtls_worker_client(
                reloaded_creds,
                base_url=strict_mtls_url,
            ) as mtls_cli:
                outcome = await supervisor.poll_and_execute_once(mtls_cli, now_fn=clock)
                assert outcome is not None
                assert outcome.disposition == "completed"
                assert outcome.cleanup.passed is True
                assert outcome.result is not None
                assert outcome.result.passed_cleanly() is True
                assert outcome.receipt is not None
                assert outcome.receipt.accepted is True
                assert outcome.receipt.worker_quarantined is False
                assert driver.observed_files == ["src/calc.py", "tests/test_calc.py"]
                assert "--network=none" in driver.invocations[0].cli_args
                assert "--read-only" in driver.invocations[0].cli_args
                assert not list(scratch_dir.iterdir())

                # Verify secret canary was redacted BEFORE ArtifactStore write (`SEC-017`):
                stdout_ref = outcome.result.artifact_refs[0]
                for blob_file in (tmp_path / "artifacts").rglob("*"):
                    if blob_file.is_file():
                        raw_disk = blob_file.read_bytes()
                        assert SECRET_CANARY_GH.encode("utf-8") not in raw_disk
                        assert b"pytest collected 1 item" not in raw_disk

                async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as ws_db:
                    art_model = await ws_db.scalar(
                        select(ArtifactModel).where(ArtifactModel.id == stdout_ref.id)
                    )
                    assert art_model is not None
                    decrypted_stdout = await read_artifact_for_authorized_caller(
                        ws_db,
                        store=harness.artifact_store,
                        artifact_row=art_model,
                        now=clock(),
                    )
                    assert art_model.kind == "sandbox_stdout"
                    assert SECRET_CANARY_GH.encode("utf-8") not in decrypted_stdout
                    assert b"1 passed in 0.03s" in decrypted_stdout

                # Verify TaskJob & SandboxLease state in DB:
                async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as ws_db:
                    t_job = await ws_db.scalar(
                        select(TaskJobModel).where(TaskJobModel.id == job_id)
                    )
                    assert t_job is not None
                    assert t_job.state == "succeeded"
                    lease = await ws_db.scalar(
                        select(SandboxLeaseModel).where(SandboxLeaseModel.job_id == job_id)
                    )
                    assert lease is not None
                    assert lease.status == "completed"
                    assert lease.cleanup_verified is True

                # Verify disallowed slot (`403`) and `> output_bytes` cap (`413`, `NFR-14`):
                cap_job_id = await harness.worker_broker.enqueue_sandbox_job(
                    workspace_id=ws_id,
                    repository_id=repo_id,
                    repair_id=new_uuid7(now=clock()),
                    profile_id="python-3.12-node-22",
                    image_digest=("8" * 64),
                    base_sha="b" * 40,
                    source_archive_digest=archive_digest,
                    command_ids=["pytest-unit"],
                    correlation_id="corr-u14-cap-02",
                    now=clock(),
                    resource_limits=SandboxResourceLimits(
                        cpu=2,
                        memory_bytes=2_147_483_648,
                        disk_bytes=10_737_418_240,
                        pids=256,
                        wall_seconds=120,
                        output_bytes=1024,
                    ),
                    allowed_output_slots=("stdout",),
                )
                poll_2 = await mtls_cli.post(
                    f"/internal/v1/workers/{reloaded_creds.worker_id}/poll",
                    json=WorkerPollRequest().model_dump(mode="json"),
                )
                assert poll_2.status_code == 200
                sjob_2 = poll_2.json()["sandbox_job"]
                assert sjob_2["job_id"] == cap_job_id

                bad_slot_bytes = b"attempt disallowed slot"
                bad_slot_resp = await mtls_cli.post(
                    f"/internal/v1/jobs/{cap_job_id}/upload",
                    headers={"X-Upload-Capability": sjob_2["artifact_upload_capability"]},
                    json=WorkerArtifactUploadRequest(
                        lease_epoch=sjob_2["lease_epoch"],
                        capability_nonce=sjob_2["capability_nonce"],
                        slot_name="exfiltrated_tar",
                        mime="application/octet-stream",
                        content_b64=base64.b64encode(bad_slot_bytes).decode("ascii"),
                        digest=hashlib.sha256(bad_slot_bytes).hexdigest(),
                    ).model_dump(mode="json"),
                )
                assert bad_slot_resp.status_code == 403
                assert bad_slot_resp.json()["code"] == "upload_slot_not_permitted"

                huge_bytes = b"X" * 2048  # Exceeds job output_bytes=1024
                oversize_resp = await mtls_cli.post(
                    f"/internal/v1/jobs/{cap_job_id}/upload",
                    headers={"X-Upload-Capability": sjob_2["artifact_upload_capability"]},
                    json=WorkerArtifactUploadRequest(
                        lease_epoch=sjob_2["lease_epoch"],
                        capability_nonce=sjob_2["capability_nonce"],
                        slot_name="stdout",
                        mime="text/plain; charset=utf-8",
                        content_b64=base64.b64encode(huge_bytes).decode("ascii"),
                        digest=hashlib.sha256(huge_bytes).hexdigest(),
                    ).model_dump(mode="json"),
                )
                assert oversize_resp.status_code == 413

                # SEC-030: Identical ResultV1 replay returns 200 `idempotent_replay=True`:
                idem_replay = await mtls_cli.post(
                    f"/internal/v1/jobs/{job_id}/result",
                    json=outcome.result.model_dump(mode="json"),
                )
                assert idem_replay.status_code == 200
                assert idem_replay.json()["idempotent_replay"] is True

                # SEC-030: Conflicting duplicate ResultV1 (mutated exit_code=1, validly re-signed)
                # MUST fail 409 `conflicting_duplicate_result` and quarantine the worker!
                forged_conflict = signer.sign_result(
                    outcome.result.model_copy(
                        update={"exit_code": 1, "termination": "exited", "signature": "00" * 32}
                    ),
                    guest_workspace_root=scratch_dir,
                )
                conflict_resp = await mtls_cli.post(
                    f"/internal/v1/jobs/{job_id}/result",
                    json=forged_conflict.model_dump(mode="json"),
                )
                assert conflict_resp.status_code == 409
                assert conflict_resp.json()["code"] == "conflicting_duplicate_result"

                async with instance_rls_session(harness.app_factory, mode="instance_only") as db:
                    w_row = await db.scalar(
                        select(WorkerModel).where(WorkerModel.id == reloaded_creds.worker_id)
                    )
                    assert w_row is not None
                    assert w_row.status == "quarantined"
                    assert "conflicting_duplicate_result" in (w_row.quarantine_reason or "")
                    q_events = (
                        await db.scalars(
                            select(OutboxEventModel).where(
                                OutboxEventModel.aggregate_id == reloaded_creds.worker_id,
                                OutboxEventModel.event_type == "worker.quarantined",
                            )
                        )
                    ).all()
                    assert len(q_events) >= 1

        await owner_client.aclose()
    finally:
        await harness.app_engine.dispose()


async def test_stale_lease_epoch_fence_reconciler_tampering_cleanup_and_cancellation(
    migrated_db: PgTestUrls,
    tmp_path: Path,
) -> None:
    """`NFR-02`, `SEC-021`, `SEC-029`, `SEC-030`, `W-08`: Prove `<=90s` orphan detection,
    monotonic `lease_epoch` `409` fencing (`0` stale writes), signature/artifact/cleanup
    quarantines, and live cooperative cancellation."""
    clock = ManualClock(datetime.now(tz=UTC) - timedelta(hours=2))
    harness = _build_u14_harness(migrated_db.app_url, clock=clock, store_dir=tmp_path / "artifacts")
    try:
        owner_client, owner_csrf, _, ws_id, repo_id = await _claim_owner_and_seed_repo(
            harness,
            now=clock(),
        )
        owner_csrf = await _step_up_owner(owner_client, owner_csrf)

        server_tls = await harness.worker_broker.ca.issue_server_bundle(now=clock())
        async with (
            _start_loopback_tls13_server(
                harness.api_app,
                server_tls,
                cert_reqs=ssl.CERT_OPTIONAL,
            ) as bootstrap_url,
            _start_loopback_tls13_server(
                harness.api_app,
                server_tls,
                cert_reqs=ssl.CERT_REQUIRED,
            ) as strict_mtls_url,
        ):

            async def _enroll_vm_worker(
                idx: int,
            ) -> tuple[MtlsWorkerCredentials, ExternalResultSigner]:
                er = await owner_client.post(
                    "/api/v1/system/workers/enrollments",
                    headers=_csrf_headers(owner_csrf),
                    json={
                        "trust_domain": "worker-supervisor",
                        "profile_ids": ["python-3.12-node-22"],
                        "isolation_mode": "vm_isolated",
                        "ttl_minutes": 30,
                    },
                )
                assert er.status_code == 201, er.text
                sgn = ExternalResultSigner.generate(
                    key_id=f"ed25519-fence-{idx}",
                    not_before=clock(),
                )
                async with _build_bootstrap_tls_client(
                    str(er.json()["ca_cert_pem"]),
                    base_url=bootstrap_url,
                ) as b_cli:
                    cr = await WorkerEnroller().enroll(
                        client=b_cli,
                        enrollment_token=str(er.json()["enrollment_token"]),
                        supported_profiles=["python-3.12-node-22"],
                        signer=sgn,
                        attestation=_vm_attestation(f"vm-fence-{idx}.internal"),
                        now=clock(),
                    )
                return cr, sgn

            w1_creds, w1_signer = await _enroll_vm_worker(1)
            w2_creds, w2_signer = await _enroll_vm_worker(2)
            w3_creds, w3_signer = await _enroll_vm_worker(3)
            w4_creds, w4_signer = await _enroll_vm_worker(4)
            w5_creds, w5_signer = await _enroll_vm_worker(5)

            archive_digest = harness.worker_broker.register_source_archive(
                _make_tar_gz_bytes({"tests/test_ok.py": b"def test_ok(): assert True\n"})
            )

            # 1) Stale `lease_epoch=1` fencing & `<=90s` orphan reconciler (`NFR-02`, `SEC-021`):
            fenced_job_id = await harness.worker_broker.enqueue_sandbox_job(
                workspace_id=ws_id,
                repository_id=repo_id,
                repair_id=new_uuid7(now=clock()),
                profile_id="python-3.12-node-22",
                image_digest=("7" * 64),
                base_sha="c" * 40,
                source_archive_digest=archive_digest,
                command_ids=["pytest-unit"],
                correlation_id="corr-fence-01",
                now=clock(),
                max_attempts=3,
            )

            async with (
                _build_mtls_worker_client(w1_creds, base_url=strict_mtls_url) as w1_cli,
                _build_mtls_worker_client(w2_creds, base_url=strict_mtls_url) as w2_cli,
            ):
                p1 = await w1_cli.post(
                    f"/internal/v1/workers/{w1_creds.worker_id}/poll",
                    json=WorkerPollRequest().model_dump(mode="json"),
                )
                assert p1.status_code == 200
                lease_1 = p1.json()["sandbox_job"]
                assert lease_1["job_id"] == fenced_job_id
                assert lease_1["lease_epoch"] == 1

                # Keep Worker 2 alive while Worker 1 goes silent for 91s (>60s lease, >90s worker):
                clock.advance(seconds=50)
                await w2_cli.post(
                    f"/internal/v1/workers/{w2_creds.worker_id}/poll",
                    json=WorkerPollRequest().model_dump(mode="json"),
                )
                clock.advance(seconds=41)

                offlined, swept = await harness.worker_broker.reconcile_stale_workers_and_leases(
                    now=clock(),
                    correlation_id="corr-reconcile-01",
                )
                assert offlined == 4  # w1, w3, w4, w5 silent for 91s (>90s); w2 polled at +50s
                assert swept >= 1

                async with instance_rls_session(harness.app_factory, mode="instance_only") as db:
                    w1_row = await db.scalar(
                        select(WorkerModel).where(WorkerModel.id == w1_creds.worker_id)
                    )
                    assert w1_row is not None and w1_row.status == "offline"
                    w2_row = await db.scalar(
                        select(WorkerModel).where(WorkerModel.id == w2_creds.worker_id)
                    )
                    assert w2_row is not None and w2_row.status == "online"
                    offline_ev = await db.scalar(
                        select(OutboxEventModel).where(
                            OutboxEventModel.aggregate_id == w1_creds.worker_id,
                            OutboxEventModel.event_type == "worker.offline",
                        )
                    )
                    assert offline_ev is not None

                # Worker 2 now acquires `fenced_job_id` at `lease_epoch == 2`!
                p2 = await w2_cli.post(
                    f"/internal/v1/workers/{w2_creds.worker_id}/poll",
                    json=WorkerPollRequest().model_dump(mode="json"),
                )
                assert p2.status_code == 200
                lease_2 = p2.json()["sandbox_job"]
                assert lease_2["job_id"] == fenced_job_id
                assert lease_2["lease_epoch"] == 2

                # Delayed zombie Worker 1 (`lease_epoch=1`) attempts heartbeat, upload & result:
                zombie_hb = await w1_cli.post(
                    f"/internal/v1/jobs/{fenced_job_id}/heartbeat",
                    json=WorkerJobHeartbeatRequest(
                        lease_epoch=1,
                        capability_nonce=lease_1["capability_nonce"],
                    ).model_dump(mode="json"),
                )
                assert zombie_hb.status_code == 409
                assert zombie_hb.json()["code"] == "stale_job_lease"

                # Mint a non-expired upload test using lease_1's epoch=1 against active epoch=2:
                # Note: lease_1's ticket also expired after 91s (403) OR if replayed within ticket
                # TTL after manual requeue would hit 409; let's assert zero blob rows written!
                blobs_before = 0
                async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as ws_db:
                    blobs_before = int(
                        (await ws_db.scalar(select(func.count()).select_from(ArtifactBlobModel)))
                        or 0
                    )

                zombie_up = await w1_cli.post(
                    f"/internal/v1/jobs/{fenced_job_id}/upload",
                    headers={"X-Upload-Capability": lease_1["artifact_upload_capability"]},
                    json=WorkerArtifactUploadRequest(
                        lease_epoch=1,
                        capability_nonce=lease_1["capability_nonce"],
                        slot_name="stdout",
                        mime="text/plain",
                        content_b64=base64.b64encode(b"zombie output").decode("ascii"),
                        digest=hashlib.sha256(b"zombie output").hexdigest(),
                    ).model_dump(mode="json"),
                )
                assert zombie_up.status_code in (403, 409)

                zombie_res = w1_signer.sign_result(
                    ResultV1(
                        job_id=fenced_job_id,
                        lease_epoch=1,
                        capability_nonce=lease_1["capability_nonce"],
                        worker_id=w1_creds.worker_id,
                        started_at=clock() - timedelta(seconds=95),
                        ended_at=clock(),
                        exit_code=0,
                        termination="exited",
                        command_digest="1" * 64,
                        image_digest="7" * 64,
                        environment_digest="2" * 64,
                        source_digest=archive_digest,
                        artifact_refs=[],
                        resource_usage=SandboxResourceUsage(
                            wall_ms=100,
                            max_memory_bytes=1024,
                            disk_written_bytes=0,
                            output_bytes=0,
                        ),
                        isolation_checks=[
                            IsolationCheckResult(
                                check_id="ephemeral_cleanup",
                                passed=True,
                                detail="clean",
                            )
                        ],
                        signer_key_id=w1_signer.key_id,
                        signature="00" * 32,
                    ),
                    guest_workspace_root=tmp_path / "scratch_z",
                )
                zombie_res_http = await w1_cli.post(
                    f"/internal/v1/jobs/{fenced_job_id}/result",
                    json=zombie_res.model_dump(mode="json"),
                )
                assert zombie_res_http.status_code == 409
                assert zombie_res_http.json()["code"] == "stale_job_lease"

                # Assert 0 stale writes: epoch 2 lease stays `leased` on Worker 2 & 0 blobs!
                async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as ws_db:
                    blobs_after = int(
                        (await ws_db.scalar(select(func.count()).select_from(ArtifactBlobModel)))
                        or 0
                    )
                    assert blobs_after == blobs_before
                    active_l2 = await ws_db.scalar(
                        select(SandboxLeaseModel).where(
                            SandboxLeaseModel.job_id == fenced_job_id,
                            SandboxLeaseModel.lease_epoch == 2,
                        )
                    )
                    assert active_l2 is not None
                    assert active_l2.status == "leased"
                    assert active_l2.worker_id == w2_creds.worker_id

                # Worker 2 submits valid epoch=2 ResultV1 -> 200 completed!
                valid_l2_res = w2_signer.sign_result(
                    ResultV1(
                        job_id=fenced_job_id,
                        lease_epoch=2,
                        capability_nonce=lease_2["capability_nonce"],
                        worker_id=w2_creds.worker_id,
                        started_at=clock() - timedelta(seconds=2),
                        ended_at=clock(),
                        exit_code=0,
                        termination="exited",
                        command_digest="1" * 64,
                        image_digest="7" * 64,
                        environment_digest="2" * 64,
                        source_digest=archive_digest,
                        artifact_refs=[],
                        resource_usage=SandboxResourceUsage(
                            wall_ms=100,
                            max_memory_bytes=1024,
                            disk_written_bytes=0,
                            output_bytes=0,
                        ),
                        isolation_checks=[
                            IsolationCheckResult(
                                check_id="ephemeral_cleanup",
                                passed=True,
                                detail="clean",
                            )
                        ],
                        signer_key_id=w2_signer.key_id,
                        signature="00" * 32,
                    ),
                    guest_workspace_root=tmp_path / "scratch_w2",
                )
                l2_http = await w2_cli.post(
                    f"/internal/v1/jobs/{fenced_job_id}/result",
                    json=valid_l2_res.model_dump(mode="json"),
                )
                assert l2_http.status_code == 200
                assert l2_http.json()["accepted"] is True

            # 2) Tampered Ed25519 signature (`SEC-030`) -> 403 + auto-quarantines Worker 3:
            tamper_job = await harness.worker_broker.enqueue_sandbox_job(
                workspace_id=ws_id,
                repository_id=repo_id,
                repair_id=new_uuid7(now=clock()),
                profile_id="python-3.12-node-22",
                image_digest=("6" * 64),
                base_sha="d" * 40,
                source_archive_digest=archive_digest,
                command_ids=["pytest-unit"],
                correlation_id="corr-tamper-01",
                now=clock(),
                max_attempts=1,
            )
            async with _build_mtls_worker_client(w3_creds, base_url=strict_mtls_url) as w3_cli:
                p3 = (
                    await w3_cli.post(
                        f"/internal/v1/workers/{w3_creds.worker_id}/poll",
                        json=WorkerPollRequest().model_dump(mode="json"),
                    )
                ).json()["sandbox_job"]
                signed_w3 = w3_signer.sign_result(
                    ResultV1(
                        job_id=tamper_job,
                        lease_epoch=p3["lease_epoch"],
                        capability_nonce=p3["capability_nonce"],
                        worker_id=w3_creds.worker_id,
                        started_at=clock() - timedelta(seconds=1),
                        ended_at=clock(),
                        exit_code=1,
                        termination="exited",
                        command_digest="1" * 64,
                        image_digest="6" * 64,
                        environment_digest="2" * 64,
                        source_digest=archive_digest,
                        artifact_refs=[],
                        resource_usage=SandboxResourceUsage(
                            wall_ms=50,
                            max_memory_bytes=1024,
                            disk_written_bytes=0,
                            output_bytes=0,
                        ),
                        isolation_checks=[
                            IsolationCheckResult(
                                check_id="ephemeral_cleanup",
                                passed=True,
                                detail="clean",
                            )
                        ],
                        signer_key_id=w3_signer.key_id,
                        signature="00" * 32,
                    ),
                    guest_workspace_root=tmp_path / "scratch_w3",
                )
                tampered_payload = signed_w3.model_dump(mode="json")
                tampered_payload["exit_code"] = 0  # Mutated AFTER signing!
                t_resp = await w3_cli.post(
                    f"/internal/v1/jobs/{tamper_job}/result",
                    json=tampered_payload,
                )
                assert t_resp.status_code == 403
                assert t_resp.json()["code"] == "invalid_result_signature"

            # 3) Substituted artifact_ref (`SEC-030`) -> 409 + auto-quarantines Worker 4:
            sub_job = await harness.worker_broker.enqueue_sandbox_job(
                workspace_id=ws_id,
                repository_id=repo_id,
                repair_id=new_uuid7(now=clock()),
                profile_id="python-3.12-node-22",
                image_digest=("5" * 64),
                base_sha="e" * 40,
                source_archive_digest=archive_digest,
                command_ids=["pytest-unit"],
                correlation_id="corr-sub-01",
                now=clock(),
                max_attempts=1,
            )
            async with _build_mtls_worker_client(w4_creds, base_url=strict_mtls_url) as w4_cli:
                p4 = (
                    await w4_cli.post(
                        f"/internal/v1/workers/{w4_creds.worker_id}/poll",
                        json=WorkerPollRequest().model_dump(mode="json"),
                    )
                ).json()["sandbox_job"]
                sub_signed = w4_signer.sign_result(
                    ResultV1(
                        job_id=sub_job,
                        lease_epoch=p4["lease_epoch"],
                        capability_nonce=p4["capability_nonce"],
                        worker_id=w4_creds.worker_id,
                        started_at=clock() - timedelta(seconds=1),
                        ended_at=clock(),
                        exit_code=0,
                        termination="exited",
                        command_digest="1" * 64,
                        image_digest="5" * 64,
                        environment_digest="2" * 64,
                        source_digest=archive_digest,
                        artifact_refs=[
                            ResultArtifactRef(
                                id=new_uuid7(now=clock()),
                                digest="a" * 64,
                                size=128,
                            )
                        ],
                        resource_usage=SandboxResourceUsage(
                            wall_ms=50,
                            max_memory_bytes=1024,
                            disk_written_bytes=0,
                            output_bytes=128,
                        ),
                        isolation_checks=[
                            IsolationCheckResult(
                                check_id="ephemeral_cleanup",
                                passed=True,
                                detail="clean",
                            )
                        ],
                        signer_key_id=w4_signer.key_id,
                        signature="00" * 32,
                    ),
                    guest_workspace_root=tmp_path / "scratch_w4",
                )
                sub_resp = await w4_cli.post(
                    f"/internal/v1/jobs/{sub_job}/result",
                    json=sub_signed.model_dump(mode="json"),
                )
                assert sub_resp.status_code == 409
                assert sub_resp.json()["code"] == "unverified_result_artifact"

            # Expire & dead-letter quarantined workers' orphaned leases to free capacity:
            clock.advance(seconds=65)
            _, swept_quarantined = await harness.worker_broker.reconcile_stale_workers_and_leases(
                now=clock(),
                correlation_id="corr-reconcile-quarantined-02",
            )
            assert swept_quarantined >= 2

            # 4) Live cooperative cancellation (`W-08`) + failed cleanup quarantine (`SEC-029`):
            cancel_job = await harness.worker_broker.enqueue_sandbox_job(
                workspace_id=ws_id,
                repository_id=repo_id,
                repair_id=new_uuid7(now=clock()),
                profile_id="python-3.12-node-22",
                image_digest=("4" * 64),
                base_sha="f" * 40,
                source_archive_digest=archive_digest,
                command_ids=["pytest-unit"],
                correlation_id="corr-cancel-01",
                now=clock(),
            )
            started_evt = asyncio.Event()
            cancel_driver = _HermeticIsolatedDriver(
                _vm_attestation("vm-fence-2.internal"),
                wait_for_cancel=True,
                on_started=started_evt,
            )
            cancel_sup = WorkerSupervisor(
                credentials=w2_creds,
                signer=w2_signer,
                driver=cancel_driver,
                scratch_dir=tmp_path / "cancel_scratch",
                state_dir=tmp_path / "cancel_state",
                heartbeat_interval_seconds=0.10,
            )
            async with _build_mtls_worker_client(w2_creds, base_url=strict_mtls_url) as w2_cli:
                exec_task = asyncio.create_task(
                    cancel_sup.poll_and_execute_once(w2_cli, now_fn=clock)
                )
                await asyncio.wait_for(started_evt.wait(), timeout=5.0)

                cancel_api = await owner_client.post(
                    f"/api/v1/workspaces/acme/task-jobs/{cancel_job}/actions",
                    headers=_csrf_headers(owner_csrf, idem_key=new_uuid7(now=clock())),
                    json={"action": "cancel", "reason": "Operator aborted verification"},
                )
                assert cancel_api.status_code == 202, cancel_api.text

                c_outcome = await asyncio.wait_for(exec_task, timeout=5.0)
                assert c_outcome is not None
                assert c_outcome.disposition == "cancelled"
                assert c_outcome.cleanup.passed is True

                async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as ws_db:
                    c_job_row = await ws_db.scalar(
                        select(TaskJobModel).where(TaskJobModel.id == cancel_job)
                    )
                    assert c_job_row is not None and c_job_row.state == "cancelled"
                    c_lease_row = await ws_db.scalar(
                        select(SandboxLeaseModel).where(SandboxLeaseModel.job_id == cancel_job)
                    )
                    assert c_lease_row is not None and c_lease_row.status == "cancelled"

            # 5) Failed `ephemeral_cleanup` check in `ResultV1` (`SEC-029`) quarantines Worker 5:
            dirty_job = await harness.worker_broker.enqueue_sandbox_job(
                workspace_id=ws_id,
                repository_id=repo_id,
                repair_id=new_uuid7(now=clock()),
                profile_id="python-3.12-node-22",
                image_digest=("3" * 64),
                base_sha="0" * 40,
                source_archive_digest=archive_digest,
                command_ids=["pytest-unit"],
                correlation_id="corr-dirty-01",
                now=clock(),
            )
            async with _build_mtls_worker_client(w5_creds, base_url=strict_mtls_url) as w5_cli:
                p5 = (
                    await w5_cli.post(
                        f"/internal/v1/workers/{w5_creds.worker_id}/poll",
                        json=WorkerPollRequest().model_dump(mode="json"),
                    )
                ).json()["sandbox_job"]
                dirty_signed = w5_signer.sign_result(
                    ResultV1(
                        job_id=dirty_job,
                        lease_epoch=p5["lease_epoch"],
                        capability_nonce=p5["capability_nonce"],
                        worker_id=w5_creds.worker_id,
                        started_at=clock() - timedelta(seconds=1),
                        ended_at=clock(),
                        exit_code=0,
                        termination="exited",
                        command_digest="1" * 64,
                        image_digest="3" * 64,
                        environment_digest="2" * 64,
                        source_digest=archive_digest,
                        artifact_refs=[],
                        resource_usage=SandboxResourceUsage(
                            wall_ms=50,
                            max_memory_bytes=1024,
                            disk_written_bytes=0,
                            output_bytes=0,
                        ),
                        isolation_checks=[
                            IsolationCheckResult(
                                check_id="ephemeral_cleanup",
                                passed=False,
                                detail="Residual locked file remained in scratch dir",
                            )
                        ],
                        signer_key_id=w5_signer.key_id,
                        signature="00" * 32,
                    ),
                    guest_workspace_root=tmp_path / "scratch_w5",
                )
                dirty_resp = await w5_cli.post(
                    f"/internal/v1/jobs/{dirty_job}/result",
                    json=dirty_signed.model_dump(mode="json"),
                )
                assert dirty_resp.status_code == 200
                assert dirty_resp.json()["worker_quarantined"] is True

        await owner_client.aclose()
    finally:
        await harness.app_engine.dispose()


async def test_adr034_multi_workspace_isolation_operator_actions_and_audit_chain(
    migrated_db: PgTestUrls,
    tmp_path: Path,
) -> None:
    """`ADR-016`, `ADR-034`, `A-13`, `S-05`: Multi-workspace trusted-local block, setup probe,
    operator `drain | resume | quarantine | revoke` + self-test, and `verify_audit_chain`."""
    clock = ManualClock(datetime.now(tz=UTC) - timedelta(hours=2))
    harness = _build_u14_harness(migrated_db.app_url, clock=clock, store_dir=tmp_path / "artifacts")
    try:
        owner_client, owner_csrf, _, ws_id, repo_id = await _claim_owner_and_seed_repo(
            harness,
            now=clock(),
        )
        owner_csrf = await _step_up_owner(owner_client, owner_csrf)

        # Enroll an `oci_trusted_local` worker with explicit `ADR-016` risk acknowledgement:
        tl_enroll = await owner_client.post(
            "/api/v1/system/workers/enrollments",
            headers=_csrf_headers(owner_csrf),
            json={
                "trust_domain": "worker-supervisor",
                "profile_ids": ["python-3.12-node-22"],
                "isolation_mode": "oci_trusted_local",
                "host_escape_risk_acknowledged": True,
                "ttl_minutes": 30,
            },
        )
        assert tl_enroll.status_code == 201, tl_enroll.text
        ca_cert_pem = str(tl_enroll.json()["ca_cert_pem"])

        server_tls = await harness.worker_broker.ca.issue_server_bundle(now=clock())
        async with (
            _start_loopback_tls13_server(
                harness.api_app,
                server_tls,
                cert_reqs=ssl.CERT_OPTIONAL,
            ) as bootstrap_url,
            _start_loopback_tls13_server(
                harness.api_app,
                server_tls,
                cert_reqs=ssl.CERT_REQUIRED,
            ) as strict_mtls_url,
        ):
            tl_signer = ExternalResultSigner.generate(
                key_id="ed25519-tl-01",
                not_before=clock(),
            )
            async with _build_bootstrap_tls_client(ca_cert_pem, base_url=bootstrap_url) as boot_cli:
                tl_creds = await WorkerEnroller().enroll(
                    client=boot_cli,
                    enrollment_token=str(tl_enroll.json()["enrollment_token"]),
                    supported_profiles=["python-3.12-node-22"],
                    signer=tl_signer,
                    attestation=_trusted_local_attestation(),
                    now=clock(),
                )

            # Single-workspace readiness is ready=True with `trusted_local_warning=True`:
            r1 = await owner_client.get("/api/v1/workspaces/acme/workers/readiness")
            assert r1.status_code == 200
            assert r1.json()["ready"] is True
            assert r1.json()["trusted_local_warning"] is True

            # Verify live `SetupStepRegistry` `worker_readiness` probe (`U07` -> `U14`):
            probe_fn = harness.step_registry.get_probe("worker_readiness")
            assert probe_fn is not None
            probe_unacked = await probe_fn(
                "worker_readiness",
                {
                    "sandbox_backend": "oci_trusted_local",
                    "runtime_profile_id": "python-3.12-node-22",
                    "host_escape_risk_acknowledged": False,
                },
            )
            assert probe_unacked.probe_status == "failed"

            probe_acked = await probe_fn(
                "worker_readiness",
                {
                    "sandbox_backend": "oci_trusted_local",
                    "runtime_profile_id": "python-3.12-node-22",
                    "host_escape_risk_acknowledged": True,
                },
            )
            assert probe_acked.probe_status == "passed"

            # Create a SECOND active workspace (`ADR-034`) -> `oci_trusted_local` MUST be blocked!
            ws2 = await owner_client.post(
                "/api/v1/workspaces",
                headers=_csrf_headers(owner_csrf),
                json={"name": "Second Tenant", "slug": "second-tenant"},
            )
            assert ws2.status_code == 201

            archive_digest = harness.worker_broker.register_source_archive(
                _make_tar_gz_bytes({"a.py": b"x = 1\n"})
            )
            await harness.worker_broker.enqueue_sandbox_job(
                workspace_id=ws_id,
                repository_id=repo_id,
                repair_id=new_uuid7(now=clock()),
                profile_id="python-3.12-node-22",
                image_digest=("2" * 64),
                base_sha="a" * 40,
                source_archive_digest=archive_digest,
                command_ids=["pytest-unit"],
                correlation_id="corr-multiws-01",
                now=clock(),
            )

            async with _build_mtls_worker_client(tl_creds, base_url=strict_mtls_url) as tl_cli:
                blocked_poll = await tl_cli.post(
                    f"/internal/v1/workers/{tl_creds.worker_id}/poll",
                    json=WorkerPollRequest().model_dump(mode="json"),
                )
                assert blocked_poll.status_code == 200
                assert blocked_poll.json()["sandbox_job"] is None  # Refused due to ADR-034!

            r_multi = await owner_client.get("/api/v1/workspaces/acme/workers/readiness")
            assert r_multi.status_code == 200
            assert r_multi.json()["ready"] is False
            assert "ADR-034" in (r_multi.json()["degraded_reason"] or "")

            # Operator self-test & lifecycle actions (`A-13` + `S-05` idempotency + `If-Match`):
            st_ok = await owner_client.post(
                f"/api/v1/system/workers/{tl_creds.worker_id}/self-test",
                headers=_csrf_headers(owner_csrf),
            )
            assert st_ok.status_code == 200
            assert st_ok.json()["passed"] is True

            # List fleet + signed cursor pagination (`limit=1`):
            fleet_p1 = await owner_client.get("/api/v1/system/workers?limit=1")
            assert fleet_p1.status_code == 200
            assert fleet_p1.json()["summary"]["trusted_local_warning_count"] == 1
            v_initial = int(fleet_p1.json()["items"][0]["version"])

            # Drain with Idempotency-Key + exact replay + 409 payload mismatch + 412 stale If-Match:
            idem_drain = new_uuid7(now=clock())
            drain_1 = await owner_client.post(
                f"/api/v1/system/workers/{tl_creds.worker_id}/actions",
                headers=_csrf_headers(
                    owner_csrf,
                    idem_key=idem_drain,
                    if_match=f'"v{v_initial}"',
                ),
                json={
                    "action": "drain",
                    "reason": "Host kernel maintenance",
                    "expected_version": v_initial,
                },
            )
            assert drain_1.status_code == 202, drain_1.text

            drain_replay = await owner_client.post(
                f"/api/v1/system/workers/{tl_creds.worker_id}/actions",
                headers=_csrf_headers(
                    owner_csrf,
                    idem_key=idem_drain,
                    if_match=f'"v{v_initial}"',
                ),
                json={
                    "action": "drain",
                    "reason": "Host kernel maintenance",
                    "expected_version": v_initial,
                },
            )
            assert drain_replay.status_code == 202
            assert drain_replay.json()["operation_id"] == drain_1.json()["operation_id"]

            drain_mismatch = await owner_client.post(
                f"/api/v1/system/workers/{tl_creds.worker_id}/actions",
                headers=_csrf_headers(owner_csrf, idem_key=idem_drain),
                json={
                    "action": "quarantine",
                    "reason": "Different payload on same Idempotency-Key",
                },
            )
            assert drain_mismatch.status_code == 409
            assert drain_mismatch.json()["code"] == "idempotency_payload_mismatch"

            stale_if_match = await owner_client.post(
                f"/api/v1/system/workers/{tl_creds.worker_id}/actions",
                headers=_csrf_headers(
                    owner_csrf,
                    idem_key=new_uuid7(now=clock()),
                    if_match=f'"v{v_initial}"',
                ),
                json={
                    "action": "resume",
                    "reason": "Stale version test",
                    "expected_version": v_initial,
                },
            )
            assert stale_if_match.status_code == 412

            # Revoke worker -> mTLS certificate & Ed25519 key permanently revoked!
            revoke_resp = await owner_client.post(
                f"/api/v1/system/workers/{tl_creds.worker_id}/actions",
                headers=_csrf_headers(owner_csrf, idem_key=new_uuid7(now=clock())),
                json={"action": "revoke", "reason": "Decommission shared-daemon worker"},
            )
            assert revoke_resp.status_code == 202

            async with _build_mtls_worker_client(tl_creds, base_url=strict_mtls_url) as tl_cli:
                revoked_poll = await tl_cli.post(
                    f"/internal/v1/workers/{tl_creds.worker_id}/poll",
                    json=WorkerPollRequest().model_dump(mode="json"),
                )
                assert revoked_poll.status_code == 403
                assert revoked_poll.json()["code"] == "worker_certificate_revoked"

            resume_revoked = await owner_client.post(
                f"/api/v1/system/workers/{tl_creds.worker_id}/actions",
                headers=_csrf_headers(owner_csrf, idem_key=new_uuid7(now=clock())),
                json={"action": "resume", "reason": "Try resuming revoked cert"},
            )
            assert resume_revoked.status_code == 409
            assert resume_revoked.json()["code"] == "worker_certificate_revoked_or_expired"

            async with instance_rls_session(harness.app_factory, mode="instance_only") as db:
                sk = await db.scalar(
                    select(SigningKeyModel).where(SigningKeyModel.key_id == tl_signer.key_id)
                )
                assert sk is not None and sk.revoked_at is not None

            async with instance_rls_session(harness.app_factory, mode="audit_verifier") as aud_db:
                verified_entries = await verify_audit_chain(
                    aud_db,
                    external_store=ExternalCheckpointStore(tmp_path / "audit_ckpts"),
                    keyring=KeyRing(()),
                )
                assert verified_entries >= 5

        await owner_client.aclose()
    finally:
        await harness.app_engine.dispose()
