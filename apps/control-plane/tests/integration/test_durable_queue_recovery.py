"""PostgreSQL + Redis 7 + Dramatiq integration & fault-injection suite for Unit U08.

Verifies against a real disposable PostgreSQL instance (`pgserver` /
`RED2PR_TEST_ADMIN_DATABASE_URL`) and a real TCP Redis 7 wire-protocol server
(`RED2PR_TEST_REDIS_URL` or `fakeredis.TcpFakeServer` with LuaJIT driving unmodified
`dramatiq.brokers.redis.RedisBroker` over loopback TCP sockets):
- Migration `0005_task_jobs_leases_dlq` reversibility (`upgrade -> downgrade -> upgrade`),
  fail-closed `FORCE ROW LEVEL SECURITY` across `task_jobs`, `task_attempts`,
  `dead_letter_jobs`, and `operation_receipts`, cross-workspace tenant isolation, and
  composite `(workspace_id, job_id)` foreign-key enforcement (`SEC-032`).
- `T-JOB-01-P`, `T-JOB-01-N` & `T-NFR-01` Durability & Catastrophic Redis Wipe (`FLUSHALL`):
  - Enqueue commits durably in PostgreSQL before wakeup hint; secret canaries in `payload_json`
    are redacted at rest while Redis carries ONLY opaque `(workspace_id, job_id)` hints.
  - Active `(workspace_id, dedup_key)` deduplicates duplicate enqueues without creating extra rows.
  - Wiping Redis mid-flight (`FLUSHALL`) loses `0` acknowledged jobs;
    `QueueLeaseSweeper.rebuild_transport_from_db` deterministically re-enqueues wakeup hints for
    all eligible ready jobs, consumed via `dramatiq.Worker`, completing `100%` of jobs with `0`
    duplicate side effects (`EffectTombstoneModel` blocks duplicate `logical_effect_key`).
  - Unreachable Redis degrades `summary.transport_status` truthfully to `"degraded"` while still
    committing durable PostgreSQL jobs without error (`AGENTS.md` #8).
- `T-NFR-02` & `SEC-021` Lease Heartbeats (`15s`), Expiry (`60s`), Orphan Sweep (`<=90s`), &
  Monotonic `lease_epoch` Fencing (`0` Stale Writes):
  - Worker 1 heartbeats at `+15s` and `+30s`, then stalls; sweeper at `+95s` (`65s <= 90s` from
    last heartbeat) marks attempt 1 `orphaned` and returns job to `queued`; Worker 2 acquires
    `lease_epoch=2` within `<=120s`; late Worker 1 (`lease_epoch=1`) is deterministically fenced
    out on `heartbeat_lease`, `complete_lease`, and `fail_lease` with `409 stale_job_lease`,
    producing `0` stale DB writes and emitting `security.policy.denied` outbox + audit entries.
- `T-NFR-05` Per-Workspace Concurrency Cap (`2` default) & Noisy-Tenant Fairness:
  - Noisy Workspace A (`50` queued repair jobs) cannot exceed `2` concurrent running/leased
    repairs while non-repair jobs remain schedulable; quiet Workspace B (`4` queued repair jobs)
    is scheduled immediately on free worker capacity via `last_dispatch_seq` watermark fairness
    without starvation.
- `T-JOB-02-P`, `T-JOB-02-N`, `A-14`, `A-24`, `W-08` HTTP Queue Controls, Scoped DLQ Requeue,
  Reconciliation & Anti-Enumeration RBAC:
  - Signed `S-04` cursor pagination, `ETag`, `cancel` on `queued` and `running` jobs (cooperative
    heartbeat `cancel_requested=True` -> `acknowledge_cancel` -> `GET /operations/{id}` syncs to
    `succeeded`), jittered retry backoff -> `dead_letter` exhaustion, live `paused` workspace
    recheck blocking `requeue` (`409`), preserved `logical_effect_key` & `budget_key` across DLQ
    replay, `reconcile_required` blocking blind replay (`409`) until explicit `reconcile`
    (`confirmed_absent` vs `confirmed_applied`), cross-workspace/repo-grant `404` anti-enumeration,
    `viewer` `403`, live rights revocation on demoted `maintainer` (`403` on `/operations/{id}`),
    and intact `verify_audit_chain`.
"""

from __future__ import annotations

import asyncio
import base64
import os
import sys
import tempfile
import threading
import time
from collections.abc import AsyncIterator, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx
import pgserver
import pytest
import redis
from fakeredis import TcpFakeServer
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from py_contracts.crypto import KeyRing, MasterKeyRing
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import (
    ExternalCheckpointStore,
    verify_audit_chain,
)
from red2pr_control.api.app import create_app
from red2pr_control.core.errors import ConflictError
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.base import (
    AuditLogModel,
    DeadLetterJobModel,
    OperationReceiptModel,
    OutboxEventModel,
    SchemaMigrationRecordModel,
    TaskAttemptModel,
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
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.iam.mfa import generate_totp_code_at
from red2pr_control.iam.sessions import IamService
from red2pr_control.orchestrator import (
    DurableTaskQueueService,
    OperationReceiptService,
    QueueLeaseSweeper,
    QueueWakeupHint,
    Red2PrQueueTransport,
)
from red2pr_control.secrets.broker import SecretBroker, SecretBrokerTotpVault

APP_ROLE_NAME = "red2pr_app"
APP_ROLE_PASSWORD = "red2pr_app_local_test_pw_08"
PUBLIC_BASE_URL = "http://127.0.0.1:4280"
ORIGIN_HEADERS = {"Origin": PUBLIC_BASE_URL}
OWNER_CREDENTIAL = "OwnerSup3rStr0ng!Pass#28"
MEMBER_CREDENTIAL = "MemberSup3rStr0ng!Pass#28"


class ManualClock:
    """Deterministic controllable UTC clock for lease TTL, sweeper, and idempotency tests."""

    def __init__(self, initial: datetime | None = None) -> None:
        self._current = (initial or datetime(2026, 10, 27, 13, 0, 0, tzinfo=UTC)).astimezone(UTC)

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
    """Provide a real disposable PostgreSQL server (`RED2PR_TEST_ADMIN_DATABASE_URL` / pgserver)."""
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
        tempfile.TemporaryDirectory(prefix="red2pr_u08_pg_") as tmp_dir,
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
def redis_url() -> Iterator[str]:
    """Provide a clean Redis 7 TCP server (`RED2PR_TEST_REDIS_URL` or `TcpFakeServer` + LuaJIT)."""
    external_redis = os.environ.get("RED2PR_TEST_REDIS_URL")
    if external_redis:
        clean_cli = redis.Redis.from_url(external_redis)
        try:
            clean_cli.flushall()
            yield external_redis
        finally:
            clean_cli.flushall()
            clean_cli.connection_pool.disconnect()
            clean_cli.close()
        return

    server = TcpFakeServer(("127.0.0.1", 0), server_type="redis", server_version=(7, 0))
    server.daemon_threads = True
    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()
    host = str(server.server_address[0])
    port = int(server.server_address[1])
    try:
        yield f"redis://{host}:{port}/0"
    finally:
        server.shutdown()
        server.server_close()
        srv_thread.join(timeout=2.0)


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
    pool_size: int = 6,
    max_overflow: int = 6,
) -> tuple[AsyncEngine, IamService]:
    app_engine = create_app_engine(app_url, pool_size=pool_size, max_overflow=max_overflow)
    app_factory = create_session_factory(app_engine)
    kek_ring = MasterKeyRing(active_version=1, keys={1: b"\x38" * 32})
    broker = SecretBroker(key_ring=kek_ring, redactor=Redactor())
    totp_vault = SecretBrokerTotpVault(broker)
    iam = IamService(
        session_factory=app_factory,
        totp_vault=totp_vault,
        iam_seed_key=b"\x48" * 32,
        public_base_url=PUBLIC_BASE_URL,
        clock=clock,
    )
    return app_engine, iam


async def _claim_owner_client(
    transport: httpx.ASGITransport,
    iam: IamService,
    *,
    email: str = "owner.u08@red2pr.local",
    display_name: str = "Owner U08",
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
    body = claim_resp.json()
    return client, body["csrf_token"], body["user"]["id"]


async def _provision_and_login_client(
    transport: httpx.ASGITransport,
    iam: IamService,
    *,
    email: str,
    display_name: str,
) -> tuple[httpx.AsyncClient, str, str]:
    user_dto = await iam.provision_local_user(
        display_name=display_name,
        email=email,
        password=MEMBER_CREDENTIAL,
    )
    client = httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL)
    csrf_resp = await client.get("/api/v1/auth/csrf")
    assert csrf_resp.status_code == 200
    pre_csrf = csrf_resp.json()["csrf_token"]

    login_resp = await client.post(
        "/api/v1/auth/login",
        headers=_csrf_headers(pre_csrf),
        json={"identifier": email, "password": MEMBER_CREDENTIAL},
    )
    assert login_resp.status_code == 200, login_resp.text
    body = login_resp.json()
    return client, body["csrf_token"], user_dto.id


async def _enroll_mfa_and_step_up(
    client: httpx.AsyncClient,
    csrf_token: str,
    *,
    password: str,
    clock: ManualClock,
) -> str:
    init_resp = await client.post(
        "/api/v1/me/mfa",
        headers=_csrf_headers(csrf_token),
        json={},
    )
    assert init_resp.status_code == 200, init_resp.text
    init_body = init_resp.json()
    challenge_id = str(init_body["challenge_id"])
    secret_b32 = str(init_body["secret_base32"])
    padded = secret_b32 + ("=" * ((8 - (len(secret_b32) % 8)) % 8))
    raw_secret = base64.b32decode(padded.upper())

    confirm_resp = await client.post(
        "/api/v1/me/mfa",
        headers=_csrf_headers(csrf_token),
        json={
            "challenge_id": challenge_id,
            "otp": generate_totp_code_at(raw_secret, at_time=clock()),
        },
    )
    assert confirm_resp.status_code == 200, confirm_resp.text
    csrf_after_mfa = confirm_resp.json()["csrf_token"] or csrf_token

    # Advance 31s past the enrollment timestep so TOTP replay protection accepts fresh code
    step_at = clock.advance(seconds=31)
    step_resp = await client.post(
        "/api/v1/auth/step-up",
        headers=_csrf_headers(csrf_after_mfa),
        json={"password": password, "otp": generate_totp_code_at(raw_secret, at_time=step_at)},
    )
    assert step_resp.status_code == 200, step_resp.text
    return str(step_resp.json()["csrf_token"])


async def _create_workspace_via_api(
    owner_client: httpx.AsyncClient,
    csrf_token: str,
    *,
    name: str,
    slug: str,
) -> dict[str, Any]:
    resp = await owner_client.post(
        "/api/v1/workspaces",
        headers=_csrf_headers(csrf_token),
        json={"name": name, "slug": slug},
    )
    assert resp.status_code == 201, resp.text
    res: dict[str, Any] = resp.json()
    return res


async def test_migration_0005_reversible_rls_fail_closed_and_composite_fks(
    pg_urls: PgTestUrls,
) -> None:
    """Verify 0005 downgrade/upgrade reversibility, fail-closed RLS, and composite tenant FKs."""
    run_alembic_downgrade(pg_urls.admin_url, "base", app_role_name=APP_ROLE_NAME)
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
    run_alembic_downgrade(
        pg_urls.admin_url,
        "0004_setup_consents_endpoints",
        app_role_name=APP_ROLE_NAME,
    )
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )

    clock = ManualClock()
    admin_engine = create_admin_engine(pg_urls.admin_url)
    app_engine, iam = _build_iam_stack(pg_urls.app_url, clock=clock, pool_size=1, max_overflow=0)
    try:
        admin_factory = create_session_factory(admin_engine)
        app_factory = create_session_factory(app_engine)

        async with admin_factory() as adm:
            mig_row = await adm.scalar(
                select(SchemaMigrationRecordModel).where(
                    SchemaMigrationRecordModel.revision == "0005_task_jobs_leases_dlq"
                )
            )
            assert mig_row is not None
            assert mig_row.phase == "expand"

        queue_svc = DurableTaskQueueService(
            session_factory=app_factory,
            signing_key=iam.csrf_signing_key,
        )
        app = create_app(iam_service=iam, task_queue_service=queue_svc)
        transport = httpx.ASGITransport(app=app)
        owner_client, owner_csrf, _ = await _claim_owner_client(transport, iam)
        try:
            ws_a = await _create_workspace_via_api(
                owner_client,
                owner_csrf,
                name="Workspace Alpha",
                slug="ws-alpha",
            )
            ws_b = await _create_workspace_via_api(
                owner_client,
                owner_csrf,
                name="Workspace Beta",
                slug="ws-beta",
            )
            ws_a_id = str(ws_a["id"])
            ws_b_id = str(ws_b["id"])

            job_a = await queue_svc.enqueue_job(
                workspace_id=ws_a_id,
                kind="repair.reproduce",
                resource_id=new_uuid7(now=clock()),
                correlation_id="corr-rls-a",
                max_attempts=1,
                now=clock(),
            )
            job_b = await queue_svc.enqueue_job(
                workspace_id=ws_b_id,
                kind="repair.reproduce",
                resource_id=new_uuid7(now=clock.advance(seconds=1)),
                correlation_id="corr-rls-b",
                max_attempts=1,
                now=clock(),
            )

            # Lease & exhaust job_a so task_attempts and dead_letter_jobs contain rows
            worker_id = new_uuid7(now=clock())
            leased_a = await queue_svc.acquire_next_lease(worker_id=worker_id, now=clock())
            assert leased_a is not None and leased_a.job.id == job_a.id
            await queue_svc.fail_lease(
                job_id=leased_a.job.id,
                worker_id=worker_id,
                lease_epoch=leased_a.job.lease_epoch,
                error_code="sandbox_failed",
                error_detail="Deterministic test failure.",
                now=clock.advance(seconds=5),
            )

            # Create an operation_receipts row in Workspace B via cancel action
            idem_cancel = new_uuid7(now=clock())
            cancel_resp = await owner_client.post(
                f"/api/v1/workspaces/{ws_b_id}/task-jobs/{job_b.id}/actions",
                headers=_csrf_headers(owner_csrf, extra={"Idempotency-Key": idem_cancel}),
                json={"action": "cancel", "reason": "Cancel queued job in WS B."},
            )
            assert cancel_resp.status_code == 202, cancel_resp.text

            # 1. Fail-closed unscoped session on red2pr_app sees 0 rows across all 4 U08 tables
            async with app_factory() as unscoped_db:
                assert list((await unscoped_db.scalars(select(TaskJobModel))).all()) == []
                assert list((await unscoped_db.scalars(select(TaskAttemptModel))).all()) == []
                assert list((await unscoped_db.scalars(select(DeadLetterJobModel))).all()) == []
                assert list((await unscoped_db.scalars(select(OperationReceiptModel))).all()) == []

                with pytest.raises(DBAPIError):
                    unscoped_db.add(
                        TaskJobModel(
                            id=new_uuid7(now=clock()),
                            workspace_id=ws_a_id,
                            kind="repair.illegal",
                            is_repair_job=True,
                            resource_id=new_uuid7(now=clock()),
                            state="queued",
                            priority=100,
                            logical_effect_key="eff:illegal",
                            correlation_id="corr-illegal",
                            payload_json={},
                            attempt=1,
                            max_attempts=1,
                            lease_epoch=0,
                            not_before=clock(),
                            deadline=clock() + timedelta(minutes=10),
                            recoverable=True,
                            reconcile_required=False,
                            version=1,
                            created_at=clock(),
                            updated_at=clock(),
                        )
                    )
                    await unscoped_db.flush()
                await unscoped_db.rollback()

            # 2. Workspace A RLS session sees ONLY Workspace A rows, never Workspace B rows
            async with workspace_rls_session(app_factory, workspace_id=ws_a_id) as ws_a_db:
                jobs_in_a = list((await ws_a_db.scalars(select(TaskJobModel))).all())
                assert [j.id for j in jobs_in_a] == [job_a.id]
                dlqs_in_a = list((await ws_a_db.scalars(select(DeadLetterJobModel))).all())
                assert len(dlqs_in_a) == 1
                assert dlqs_in_a[0].original_job_id == job_a.id
                ops_in_a = list((await ws_a_db.scalars(select(OperationReceiptModel))).all())
                assert ops_in_a == []

            # 3. Cross-tenant composite FK violation: Workspace A attempt referencing WS B job
            with pytest.raises(DBAPIError):
                async with workspace_rls_session(app_factory, workspace_id=ws_a_id) as ws_a_fk_db:
                    ws_a_fk_db.add(
                        TaskAttemptModel(
                            id=new_uuid7(now=clock()),
                            workspace_id=ws_a_id,
                            job_id=job_b.id,
                            attempt_number=1,
                            lease_epoch=1,
                            worker_id=worker_id,
                            state="leased",
                            started_at=clock(),
                            heartbeat_at=clock(),
                            lease_expires_at=clock() + timedelta(seconds=60),
                            created_at=clock(),
                        )
                    )
                    await ws_a_fk_db.flush()
        finally:
            await owner_client.aclose()
    finally:
        await app_engine.dispose()
        await admin_engine.dispose()


async def test_nfr01_durable_enqueue_redaction_dedup_redis_flushall_rebuild_and_degraded_mode(
    migrated_db: PgTestUrls,
    redis_url: str,
) -> None:
    """Verify T-JOB-01-P/N & T-NFR-01: 0 job loss & 0 duplicate effects across Redis FLUSHALL."""
    clock = ManualClock()
    app_engine, iam = _build_iam_stack(migrated_db.app_url, clock=clock)
    app_factory = create_session_factory(app_engine)

    received_hints: list[QueueWakeupHint] = []
    hint_lock = threading.Lock()

    def _record_hint(hint: QueueWakeupHint) -> None:
        with hint_lock:
            received_hints.append(hint)

    transport = Red2PrQueueTransport(
        redis_url=redis_url,
        namespace="red2pr_u08_test",
        on_wakeup=_record_hint,
    )
    queue_svc = DurableTaskQueueService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        transport=transport,
    )
    sweeper = QueueLeaseSweeper(session_factory=app_factory, transport=transport)
    app = create_app(iam_service=iam, task_queue_service=queue_svc)
    asgi = httpx.ASGITransport(app=app)
    owner_client, owner_csrf, _ = await _claim_owner_client(asgi, iam)

    try:
        ws_a = await _create_workspace_via_api(
            owner_client,
            owner_csrf,
            name="Durable WS A",
            slug="durable-a",
        )
        ws_b = await _create_workspace_via_api(
            owner_client,
            owner_csrf,
            name="Durable WS B",
            slug="durable-b",
        )
        ws_a_id = str(ws_a["id"])
        ws_b_id = str(ws_b["id"])

        health_status, _ = transport.probe_health()
        assert health_status == "healthy"

        secret_canary = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        enqueued_ids: list[str] = []

        # Enqueue 8 acknowledged jobs across 2 workspaces (first carries secret canary + dedup_key)
        first_job = await queue_svc.enqueue_job(
            workspace_id=ws_a_id,
            kind="repair.diagnose",
            resource_id=new_uuid7(now=clock()),
            correlation_id="corr-nfr01-0",
            dedup_key="dedup:run-9001",
            logical_effect_key="eff:diagnose:0",
            budget_key="budget:0",
            payload={"auth_header": f"Bearer {secret_canary}", "step": "diagnose"},
            now=clock.advance(seconds=1),
        )
        enqueued_ids.append(first_job.id)

        # Duplicate active dedup_key returns the exact existing job without creating a second row
        dedup_hit = await queue_svc.enqueue_job(
            workspace_id=ws_a_id,
            kind="repair.diagnose",
            resource_id=new_uuid7(now=clock()),
            correlation_id="corr-nfr01-dup",
            dedup_key="dedup:run-9001",
            now=clock.advance(seconds=1),
        )
        assert dedup_hit.id == first_job.id

        for idx in range(1, 8):
            target_ws = ws_a_id if idx % 2 == 0 else ws_b_id
            created = await queue_svc.enqueue_job(
                workspace_id=target_ws,
                kind="repair.verify",
                resource_id=new_uuid7(now=clock()),
                correlation_id=f"corr-nfr01-{idx}",
                logical_effect_key=f"eff:verify:{idx}",
                budget_key=f"budget:{idx}",
                payload={"job_index": idx},
                now=clock.advance(seconds=1),
            )
            enqueued_ids.append(created.id)

        assert len(enqueued_ids) == 8

        # Secret canary must NEVER exist in PostgreSQL payload_json OR anywhere in Redis keys/values
        async with workspace_rls_session(app_factory, workspace_id=ws_a_id) as db:
            stored_first = await db.scalar(
                select(TaskJobModel).where(TaskJobModel.id == first_job.id)
            )
            assert stored_first is not None
            assert secret_canary not in str(stored_first.payload_json)
            assert "REDACTED" in str(stored_first.payload_json)

        raw_redis_keys = [
            k.decode("utf-8", errors="replace") if isinstance(k, bytes) else str(k)
            for k in transport.redis_client.keys("*")
        ]
        assert len(raw_redis_keys) > 0
        for rkey in raw_redis_keys:
            assert secret_canary not in rkey
            rtype = transport.redis_client.type(rkey)
            rtype_str = rtype.decode() if isinstance(rtype, bytes) else str(rtype)
            if rtype_str == "hash":
                hvals = transport.redis_client.hvals(rkey)
                for hv in hvals:
                    text_val = (
                        hv.decode("utf-8", errors="replace") if isinstance(hv, bytes) else str(hv)
                    )
                    assert secret_canary not in text_val
                    assert "job_index" not in text_val

        # Consume a partial batch and complete 2 jobs BEFORE wiping Redis
        pre_hints = transport.consume_wakeup_batch(max_messages=2, timeout_ms=100)
        assert len(pre_hints) == 2

        worker_id = new_uuid7(now=clock())
        completed_ids: set[str] = set()
        for _ in range(2):
            lease = await queue_svc.acquire_next_lease(worker_id=worker_id, now=clock())
            assert lease is not None
            await queue_svc.mark_lease_running(
                job_id=lease.job.id,
                worker_id=worker_id,
                lease_epoch=lease.job.lease_epoch,
                now=clock(),
            )
            done = await queue_svc.complete_lease(
                job_id=lease.job.id,
                worker_id=worker_id,
                lease_epoch=lease.job.lease_epoch,
                now=clock.advance(seconds=2),
            )
            assert done.state == "succeeded"
            completed_ids.add(done.id)

        assert len(completed_ids) == 2

        # Catastrophic Redis wipe mid-flight (`FLUSHALL`)!
        transport.redis_client.flushall()
        assert transport.consume_wakeup_batch(max_messages=16, timeout_ms=50) == []

        # Deterministic DB -> Redis transport rebuild (`NFR-01`, `ADR-035`)
        with hint_lock:
            received_hints.clear()

        rebuild_report = await sweeper.rebuild_transport_from_db(now=clock())
        assert rebuild_report.eligible_jobs == 6
        assert rebuild_report.published_wakeups == 6

        # Run real background `dramatiq.Worker` to consume all 6 rebuilt wakeup messages
        transport.start_worker(worker_threads=1)
        deadline_monotonic = time.monotonic() + 4.0
        while time.monotonic() < deadline_monotonic:
            with hint_lock:
                if len(received_hints) >= 6:
                    break
            await asyncio.sleep(0.05)
        transport.stop_worker()

        with hint_lock:
            rebuilt_job_ids = {h.job_id for h in received_hints}
        assert len(rebuilt_job_ids) == 6
        assert rebuilt_job_ids == (set(enqueued_ids) - completed_ids)

        # Lease and complete all remaining 6 jobs -> 8/8 succeeded, 0 lost!
        while True:
            lease = await queue_svc.acquire_next_lease(worker_id=worker_id, now=clock())
            if lease is None:
                break
            assert lease.job.id not in completed_ids
            done = await queue_svc.complete_lease(
                job_id=lease.job.id,
                worker_id=worker_id,
                lease_epoch=lease.job.lease_epoch,
                now=clock.advance(seconds=1),
            )
            assert done.state == "succeeded"
            completed_ids.add(done.id)

        assert completed_ids == set(enqueued_ids)

        # Attempting to re-enqueue an already-completed logical_effect_key is blocked (`409`)
        with pytest.raises(ConflictError) as dup_exc:
            await queue_svc.enqueue_job(
                workspace_id=ws_a_id,
                kind="repair.diagnose",
                resource_id=new_uuid7(now=clock()),
                correlation_id="corr-dup-effect",
                logical_effect_key="eff:diagnose:0",
                now=clock.advance(seconds=1),
            )
        assert dup_exc.value.code == "duplicate_logical_effect"

        # Degraded Redis mode (`AGENTS.md` #8): close transport -> enqueue still commits in PG!
        transport.close()
        deg_status, deg_detail = transport.probe_health()
        assert deg_status == "degraded"
        assert deg_detail is not None

        offline_job = await queue_svc.enqueue_job(
            workspace_id=ws_a_id,
            kind="repair.offline_durable",
            resource_id=new_uuid7(now=clock()),
            correlation_id="corr-redis-down",
            now=clock.advance(seconds=1),
        )
        assert offline_job.state == "queued"

        list_resp = await owner_client.get(f"/api/v1/workspaces/{ws_a_id}/task-jobs")
        assert list_resp.status_code == 200, list_resp.text
        page_body = list_resp.json()
        assert page_body["summary"]["transport_status"] == "degraded"
        assert any(item["id"] == offline_job.id for item in page_body["items"])
    finally:
        transport.close()
        await owner_client.aclose()
        await app_engine.dispose()


async def test_nfr02_sec021_heartbeat_expiry_orphan_sweep_and_stale_lease_epoch_fencing(
    migrated_db: PgTestUrls,
    redis_url: str,
) -> None:
    """Verify 15s heartbeat, 60s TTL, <=90s orphan sweep, <=120s re-lease & 409 epoch fencing."""
    clock = ManualClock()
    app_engine, iam = _build_iam_stack(migrated_db.app_url, clock=clock)
    app_factory = create_session_factory(app_engine)
    transport = Red2PrQueueTransport(redis_url=redis_url, namespace="red2pr_u08_fence")
    queue_svc = DurableTaskQueueService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        transport=transport,
    )
    sweeper = QueueLeaseSweeper(session_factory=app_factory, transport=transport)
    app = create_app(iam_service=iam, task_queue_service=queue_svc)
    asgi = httpx.ASGITransport(app=app)
    owner_client, owner_csrf, _ = await _claim_owner_client(asgi, iam)

    try:
        ws = await _create_workspace_via_api(
            owner_client,
            owner_csrf,
            name="Fencing Workspace",
            slug="fencing-ws",
        )
        ws_id = str(ws["id"])

        job = await queue_svc.enqueue_job(
            workspace_id=ws_id,
            kind="repair.test_patch",
            resource_id=new_uuid7(now=clock()),
            correlation_id="corr-fence-01",
            logical_effect_key="eff:fence:01",
            budget_key="budget:fence:01",
            max_attempts=3,
            now=clock(),
        )

        worker_1 = new_uuid7(now=clock())
        worker_2 = new_uuid7(now=clock.advance(milliseconds=10))

        # t=0s: Worker 1 leases job (lease_epoch=1, TTL=60s) and marks running
        lease_1 = await queue_svc.acquire_next_lease(worker_id=worker_1, now=clock())
        assert lease_1 is not None
        assert lease_1.job.id == job.id
        assert lease_1.job.lease_epoch == 1
        assert lease_1.job.attempt == 1

        running_1 = await queue_svc.mark_lease_running(
            job_id=job.id,
            worker_id=worker_1,
            lease_epoch=1,
            now=clock(),
        )
        assert running_1.state == "running"

        # Worker 1 heartbeats on 15s cadence at +15s and +30s (extends lease_expires_at to +90s)
        hb_1 = await queue_svc.heartbeat_lease(
            job_id=job.id,
            worker_id=worker_1,
            lease_epoch=1,
            now=clock.advance(seconds=15),
        )
        assert hb_1.cancel_requested is False
        last_hb_at = clock.advance(seconds=15)  # t = +30s
        hb_2 = await queue_svc.heartbeat_lease(
            job_id=job.id,
            worker_id=worker_1,
            lease_epoch=1,
            now=last_hb_at,
        )
        assert hb_2.job.lease_expires_at == last_hb_at + timedelta(seconds=60)

        # Sweep at +75s (45s after last heartbeat, before 60s TTL expires) -> NOT orphaned yet
        early_sweep = await sweeper.sweep_expired_leases(now=clock.advance(seconds=45))
        assert early_sweep.requeued_job_ids == ()

        # Worker 1 stalls; sweep at +95s (65s after last_hb_at -> strictly <=90s NFR-02 target!)
        orphan_detected_at = clock.advance(seconds=20)
        assert (orphan_detected_at - last_hb_at) <= timedelta(seconds=90)
        sweep_report = await sweeper.sweep_expired_leases(now=orphan_detected_at)
        assert sweep_report.requeued_job_ids == (job.id,)

        # Worker 2 acquires re-leased job at +100s (70s after last_hb_at -> strictly <=120s NFR-02!)
        re_leased_at = clock.advance(seconds=5)
        assert (re_leased_at - last_hb_at) <= timedelta(seconds=120)
        lease_2 = await queue_svc.acquire_next_lease(worker_id=worker_2, now=re_leased_at)
        assert lease_2 is not None
        assert lease_2.job.id == job.id
        assert lease_2.job.lease_epoch == 2
        assert lease_2.job.attempt == 2
        assert lease_2.job.logical_effect_key == "eff:fence:01"
        assert lease_2.job.budget_key == "budget:fence:01"

        await queue_svc.mark_lease_running(
            job_id=job.id,
            worker_id=worker_2,
            lease_epoch=2,
            now=re_leased_at,
        )

        # Zombie Worker 1 wakes up late at +105s carrying stale lease_epoch=1 -> ALL writes 409!
        zombie_now = clock.advance(seconds=5)
        with pytest.raises(ConflictError) as stale_hb:
            await queue_svc.heartbeat_lease(
                job_id=job.id,
                worker_id=worker_1,
                lease_epoch=1,
                now=zombie_now,
            )
        assert stale_hb.value.status == 409
        assert stale_hb.value.code == "stale_job_lease"

        with pytest.raises(ConflictError) as stale_complete:
            await queue_svc.complete_lease(
                job_id=job.id,
                worker_id=worker_1,
                lease_epoch=1,
                now=zombie_now,
            )
        assert stale_complete.value.status == 409
        assert stale_complete.value.code == "stale_job_lease"

        with pytest.raises(ConflictError) as stale_fail:
            await queue_svc.fail_lease(
                job_id=job.id,
                worker_id=worker_1,
                lease_epoch=1,
                error_code="zombie_crash",
                error_detail="Late failure from zombie worker.",
                now=zombie_now,
            )
        assert stale_fail.value.status == 409
        assert stale_fail.value.code == "stale_job_lease"

        # Verify 0 stale mutations occurred: job is still owned by worker_2 at lease_epoch=2
        detail_resp = await owner_client.get(f"/api/v1/workspaces/{ws_id}/task-jobs/{job.id}")
        assert detail_resp.status_code == 200, detail_resp.text
        detail_json = detail_resp.json()
        assert detail_json["state"] == "running"
        assert detail_json["lease_epoch"] == 2
        assert detail_json["leased_by_worker_id"] == worker_2
        assert [a["state"] for a in detail_json["attempts_history"]] == ["running", "orphaned"]

        # Verify security.policy.denied outbox events and deny audit records were emitted
        async with workspace_rls_session(app_factory, workspace_id=ws_id) as db:
            sec_events = list(
                (
                    await db.scalars(
                        select(OutboxEventModel).where(
                            OutboxEventModel.workspace_id == ws_id,
                            OutboxEventModel.event_type == "security.policy.denied",
                        )
                    )
                ).all()
            )
            assert len(sec_events) == 3
            deny_audits = list(
                (
                    await db.scalars(
                        select(AuditLogModel).where(
                            AuditLogModel.workspace_id == ws_id,
                            AuditLogModel.decision == "deny",
                            AuditLogModel.reason_code == "stale_job_lease",
                        )
                    )
                ).all()
            )
            assert len(deny_audits) == 3

        # Worker 2 finishes cleanly with valid lease_epoch=2
        done = await queue_svc.complete_lease(
            job_id=job.id,
            worker_id=worker_2,
            lease_epoch=2,
            now=clock.advance(seconds=10),
        )
        assert done.state == "succeeded"

        admin_engine = create_admin_engine(migrated_db.admin_url)
        try:
            admin_factory = create_session_factory(admin_engine)
            with tempfile.TemporaryDirectory(prefix="red2pr_u08_ckpt1_") as ckpt_dir:
                async with admin_factory() as adm_db:
                    verified_entries = await verify_audit_chain(
                        adm_db,
                        external_store=ExternalCheckpointStore(Path(ckpt_dir)),
                        keyring=KeyRing(),
                    )
                    assert verified_entries >= 6
        finally:
            await admin_engine.dispose()
    finally:
        transport.close()
        await owner_client.aclose()
        await app_engine.dispose()


async def test_nfr05_per_workspace_running_cap_and_noisy_tenant_fairness(
    migrated_db: PgTestUrls,
    redis_url: str,
) -> None:
    """Verify T-NFR-05: noisy Workspace A (50 jobs) obeys cap=2 & never starves Workspace B."""
    clock = ManualClock()
    app_engine, iam = _build_iam_stack(
        migrated_db.app_url, clock=clock, pool_size=8, max_overflow=8
    )
    app_factory = create_session_factory(app_engine)
    transport = Red2PrQueueTransport(redis_url=redis_url, namespace="red2pr_u08_fair")
    queue_svc = DurableTaskQueueService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        transport=transport,
        max_running_repairs_per_workspace=2,
    )
    app = create_app(iam_service=iam, task_queue_service=queue_svc)
    asgi = httpx.ASGITransport(app=app)
    owner_client, owner_csrf, _ = await _claim_owner_client(asgi, iam)

    try:
        ws_a = await _create_workspace_via_api(
            owner_client,
            owner_csrf,
            name="Noisy Tenant A",
            slug="noisy-a",
        )
        ws_b = await _create_workspace_via_api(
            owner_client,
            owner_csrf,
            name="Quiet Tenant B",
            slug="quiet-b",
        )
        ws_a_id = str(ws_a["id"])
        ws_b_id = str(ws_b["id"])

        # Enqueue 50 high-priority repair jobs in noisy Workspace A
        for idx in range(50):
            await queue_svc.enqueue_job(
                workspace_id=ws_a_id,
                kind="repair.reproduce",
                is_repair_job=True,
                priority=1,
                resource_id=new_uuid7(now=clock()),
                correlation_id=f"corr-noisy-a-{idx}",
                now=clock.advance(milliseconds=5),
            )

        # Enqueue 4 lower-priority repair jobs in Workspace B AFTER Workspace A's 50 jobs
        ws_b_job_ids: list[str] = []
        for idx in range(4):
            jb = await queue_svc.enqueue_job(
                workspace_id=ws_b_id,
                kind="repair.reproduce",
                is_repair_job=True,
                priority=500,
                resource_id=new_uuid7(now=clock()),
                correlation_id=f"corr-quiet-b-{idx}",
                now=clock.advance(milliseconds=5),
            )
            ws_b_job_ids.append(jb.id)

        # 1. Single-worker sequential fairness check: Workspace B MUST interleave immediately
        #    (A, B, A, B, A, B, A, B) rather than waiting behind all 50 Workspace A jobs!
        single_worker = new_uuid7(now=clock())
        dispatch_sequence: list[str] = []
        for _ in range(8):
            leased = await queue_svc.acquire_next_lease(
                worker_id=single_worker,
                now=clock.advance(seconds=1),
            )
            assert leased is not None
            dispatch_sequence.append(leased.job.workspace_id)
            await queue_svc.complete_lease(
                job_id=leased.job.id,
                worker_id=single_worker,
                lease_epoch=leased.job.lease_epoch,
                now=clock.advance(seconds=1),
            )

        assert dispatch_sequence == [
            ws_a_id,
            ws_b_id,
            ws_a_id,
            ws_b_id,
            ws_a_id,
            ws_b_id,
            ws_a_id,
            ws_b_id,
        ]

        # 2. Per-workspace running repair concurrency cap (2 default) under concurrent workers:
        #    Workspace A still has 46 queued repair jobs; Workspace B has 0 queued jobs.
        workers = [new_uuid7(now=clock.advance(milliseconds=2)) for _ in range(4)]
        concurrent_leases = await asyncio.gather(
            *(queue_svc.acquire_next_lease(worker_id=w, now=clock()) for w in workers)
        )
        non_null_leases = [item for item in concurrent_leases if item is not None]
        assert len(non_null_leases) == 2
        assert all(item.job.workspace_id == ws_a_id for item in non_null_leases)

        # Backpressure summary reflects active_running_repairs == 2 == max_running_repairs
        page_resp = await owner_client.get(f"/api/v1/workspaces/{ws_a_id}/task-jobs")
        assert page_resp.status_code == 200
        summary = page_resp.json()["summary"]
        assert summary["active_running_repairs"] == 2
        assert summary["max_running_repairs"] == 2
        assert summary["queued_count"] == 44
        assert summary["backpressure_active"] is True

        # Non-repair ingestion/housekeeping job in Workspace A is NOT blocked by repair cap!
        non_repair_job = await queue_svc.enqueue_job(
            workspace_id=ws_a_id,
            kind="webhook.ingest",
            is_repair_job=False,
            resource_id=new_uuid7(now=clock()),
            correlation_id="corr-non-repair",
            now=clock.advance(seconds=1),
        )
        extra_lease = await queue_svc.acquire_next_lease(
            worker_id=single_worker,
            now=clock.advance(seconds=1),
        )
        assert extra_lease is not None
        assert extra_lease.job.id == non_repair_job.id
    finally:
        transport.close()
        await owner_client.aclose()
        await app_engine.dispose()


async def test_a14_a24_http_queue_controls_dlq_scoped_requeue_reconcile_and_rbac(
    migrated_db: PgTestUrls,
    redis_url: str,
) -> None:
    """Verify A-14 & A-24 HTTP contracts, DLQ replay invariants, W-08 reconcile, and RBAC."""
    clock = ManualClock()
    app_engine, iam = _build_iam_stack(migrated_db.app_url, clock=clock)
    app_factory = create_session_factory(app_engine)
    transport = Red2PrQueueTransport(redis_url=redis_url, namespace="red2pr_u08_http")
    queue_svc = DurableTaskQueueService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        transport=transport,
        base_backoff_seconds=5,
    )
    op_svc = OperationReceiptService(session_factory=app_factory)
    app = create_app(
        iam_service=iam,
        task_queue_service=queue_svc,
        operation_receipt_service=op_svc,
    )
    asgi = httpx.ASGITransport(app=app)

    owner_client, owner_csrf, _ = await _claim_owner_client(asgi, iam)
    maint_client, maint_csrf, maint_user_id = await _provision_and_login_client(
        asgi,
        iam,
        email="maint.u08@red2pr.local",
        display_name="Maintainer U08",
    )
    viewer_client, viewer_csrf, _ = await _provision_and_login_client(
        asgi,
        iam,
        email="viewer.u08@red2pr.local",
        display_name="Viewer U08",
    )
    outsider_client, outsider_csrf, _ = await _provision_and_login_client(
        asgi,
        iam,
        email="outsider.u08@red2pr.local",
        display_name="Outsider U08",
    )

    try:
        ws_main = await _create_workspace_via_api(
            owner_client,
            owner_csrf,
            name="Queue Control WS",
            slug="queue-ctrl",
        )
        ws_other = await _create_workspace_via_api(
            owner_client,
            owner_csrf,
            name="Other Isolated WS",
            slug="other-ws",
        )
        ws_temp = await _create_workspace_via_api(
            owner_client,
            owner_csrf,
            name="Temp Delete WS",
            slug="temp-del",
        )
        ws_id = str(ws_main["id"])
        ws_other_id = str(ws_other["id"])
        ws_temp_id = str(ws_temp["id"])

        repo_1 = new_uuid7(now=clock())
        repo_2 = new_uuid7(now=clock.advance(milliseconds=5))

        # Invite & accept maintainer (scoped strictly to repo_1) and viewer (scoped to repo_1)
        inv_maint = await owner_client.post(
            f"/api/v1/workspaces/{ws_id}/invitations",
            headers=_csrf_headers(owner_csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={
                "email": "maint.u08@red2pr.local",
                "role": "maintainer",
                "repository_grants": [repo_1],
            },
        )
        assert inv_maint.status_code == 201, inv_maint.text
        acc_maint = await maint_client.post(
            "/api/v1/invitations/accept",
            headers=_csrf_headers(maint_csrf),
            json={"token": inv_maint.json()["invite_token"]},
        )
        assert acc_maint.status_code == 200, acc_maint.text

        inv_viewer = await owner_client.post(
            f"/api/v1/workspaces/{ws_id}/invitations",
            headers=_csrf_headers(
                owner_csrf,
                extra={"Idempotency-Key": new_uuid7(now=clock.advance(milliseconds=5))},
            ),
            json={
                "email": "viewer.u08@red2pr.local",
                "role": "viewer",
                "repository_grants": [repo_1],
            },
        )
        assert inv_viewer.status_code == 201, inv_viewer.text
        acc_viewer = await viewer_client.post(
            "/api/v1/invitations/accept",
            headers=_csrf_headers(viewer_csrf),
            json={"token": inv_viewer.json()["invite_token"]},
        )
        assert acc_viewer.status_code == 200, acc_viewer.text

        # Invite outsider ONLY to ws_other
        inv_out = await owner_client.post(
            f"/api/v1/workspaces/{ws_other_id}/invitations",
            headers=_csrf_headers(
                owner_csrf,
                extra={"Idempotency-Key": new_uuid7(now=clock.advance(milliseconds=5))},
            ),
            json={"email": "outsider.u08@red2pr.local", "role": "admin"},
        )
        assert inv_out.status_code == 201
        acc_out = await outsider_client.post(
            "/api/v1/invitations/accept",
            headers=_csrf_headers(outsider_csrf),
            json={"token": inv_out.json()["invite_token"]},
        )
        assert acc_out.status_code == 200

        # Enqueue 4 distinct jobs in ws_main:
        # 1. job_running_cancel (repo_1): test cooperative cancel + A-24 receipt state sync
        # 2. job_dlq_replay (repo_1): test retry backoff -> DLQ -> paused block -> scoped requeue
        # 3. job_ambiguous_absent (repo_1): test reconcile_required -> confirmed_absent -> requeue
        # 4. job_repo2_secret (repo_2): test repo-grant isolation & reconcile confirmed_applied
        job_running_cancel = await queue_svc.enqueue_job(
            workspace_id=ws_id,
            repository_id=repo_1,
            kind="repair.reproduce",
            resource_id=new_uuid7(now=clock()),
            correlation_id="corr-cancel-run",
            now=clock.advance(seconds=1),
        )
        job_dlq_replay = await queue_svc.enqueue_job(
            workspace_id=ws_id,
            repository_id=repo_1,
            kind="repair.verify",
            resource_id=new_uuid7(now=clock()),
            correlation_id="corr-dlq-replay",
            logical_effect_key="eff:publish:repair-77",
            budget_key="budget:session-77",
            max_attempts=2,
            now=clock.advance(seconds=1),
        )
        job_ambiguous = await queue_svc.enqueue_job(
            workspace_id=ws_id,
            repository_id=repo_1,
            kind="publish.draft_pr",
            resource_id=new_uuid7(now=clock()),
            correlation_id="corr-ambiguous-1",
            logical_effect_key="eff:draft_pr:88",
            budget_key="budget:session-88",
            max_attempts=2,
            now=clock.advance(seconds=1),
        )
        job_repo2 = await queue_svc.enqueue_job(
            workspace_id=ws_id,
            repository_id=repo_2,
            kind="publish.draft_pr",
            resource_id=new_uuid7(now=clock()),
            correlation_id="corr-repo2-applied",
            logical_effect_key="eff:draft_pr:99",
            budget_key="budget:session-99",
            max_attempts=1,
            now=clock.advance(seconds=1),
        )

        # Signed S-04 cursor pagination & filter binding check
        p1 = await owner_client.get(f"/api/v1/workspaces/{ws_id}/task-jobs?limit=2")
        assert p1.status_code == 200
        p1_body = p1.json()
        assert len(p1_body["items"]) == 2
        assert p1_body["next_cursor"] is not None

        # Using a cursor across a different state filter is rejected with 400
        bad_cursor_resp = await owner_client.get(
            f"/api/v1/workspaces/{ws_id}/task-jobs",
            params={"limit": 2, "state": "dead_letter", "cursor": p1_body["next_cursor"]},
        )
        assert bad_cursor_resp.status_code == 400

        p2 = await owner_client.get(
            f"/api/v1/workspaces/{ws_id}/task-jobs",
            params={"limit": 2, "cursor": p1_body["next_cursor"]},
        )
        assert p2.status_code == 200
        assert len(p2.json()["items"]) == 2

        # Maintainer (granted ONLY repo_1) sees 3 jobs (never repo_2!), gets 404 on repo_2 job
        maint_list = await maint_client.get(f"/api/v1/workspaces/{ws_id}/task-jobs")
        assert maint_list.status_code == 200
        maint_job_ids = {item["id"] for item in maint_list.json()["items"]}
        assert job_repo2.id not in maint_job_ids
        assert maint_job_ids == {job_running_cancel.id, job_dlq_replay.id, job_ambiguous.id}

        maint_repo2_get = await maint_client.get(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_repo2.id}"
        )
        assert maint_repo2_get.status_code == 404

        # Outsider from ws_other gets 404 on ws_id task-jobs & detail
        assert (
            await outsider_client.get(f"/api/v1/workspaces/{ws_id}/task-jobs")
        ).status_code == 404
        assert (
            await outsider_client.get(
                f"/api/v1/workspaces/{ws_id}/task-jobs/{job_running_cancel.id}"
            )
        ).status_code == 404

        # Viewer can read repo_1 job (200) but gets 403 on POST /actions
        assert (
            await viewer_client.get(f"/api/v1/workspaces/{ws_id}/task-jobs/{job_running_cancel.id}")
        ).status_code == 200
        viewer_act = await viewer_client.post(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_running_cancel.id}/actions",
            headers=_csrf_headers(viewer_csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={"action": "cancel", "reason": "Viewer should be denied."},
        )
        assert viewer_act.status_code == 403
        assert viewer_act.json()["code"] == "insufficient_role"

        # Missing Idempotency-Key returns 400
        missing_idem = await maint_client.post(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_running_cancel.id}/actions",
            headers=_csrf_headers(maint_csrf),
            json={"action": "cancel", "reason": "Missing idempotency header."},
        )
        assert missing_idem.status_code == 400
        assert missing_idem.json()["code"] == "missing_idempotency_key"

        # --- Flow 1: Cooperative cancel on running job + A-24 operation receipt polling ---
        worker_a = new_uuid7(now=clock())
        worker_b = new_uuid7(now=clock.advance(milliseconds=2))
        # Drain leases until job_running_cancel is running
        leased_first = await queue_svc.acquire_next_lease(worker_id=worker_a, now=clock())
        assert leased_first is not None and leased_first.job.id == job_running_cancel.id
        await queue_svc.mark_lease_running(
            job_id=job_running_cancel.id,
            worker_id=worker_a,
            lease_epoch=leased_first.job.lease_epoch,
            now=clock(),
        )

        det_before_cancel = await maint_client.get(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_running_cancel.id}"
        )
        assert det_before_cancel.status_code == 200
        etag_before = det_before_cancel.headers["ETag"]

        cancel_idem = new_uuid7(now=clock())
        cancel_resp = await maint_client.post(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_running_cancel.id}/actions",
            headers=_csrf_headers(
                maint_csrf,
                extra={"Idempotency-Key": cancel_idem, "If-Match": etag_before},
            ),
            json={"action": "cancel", "reason": "Operator requested safe stop."},
        )
        assert cancel_resp.status_code == 202, cancel_resp.text
        cancel_receipt = cancel_resp.json()
        assert cancel_receipt["state"] == "running"
        cancel_op_id = cancel_receipt["operation_id"]

        # Polling A-24 while worker is still tearing down returns state='running'
        op_poll_1 = await maint_client.get(f"/api/v1/operations/{cancel_op_id}")
        assert op_poll_1.status_code == 200
        assert op_poll_1.json()["state"] == "running"

        # Outsider gets 404 on /operations/{id}; viewer gets 403 insufficient_role
        assert (await outsider_client.get(f"/api/v1/operations/{cancel_op_id}")).status_code == 404
        assert (await viewer_client.get(f"/api/v1/operations/{cancel_op_id}")).status_code == 403

        # Worker heartbeat receives cancel_requested=True and acknowledges cancellation
        hb_cancel = await queue_svc.heartbeat_lease(
            job_id=job_running_cancel.id,
            worker_id=worker_a,
            lease_epoch=leased_first.job.lease_epoch,
            now=clock.advance(seconds=5),
        )
        assert hb_cancel.cancel_requested is True
        acked = await queue_svc.acknowledge_cancel(
            job_id=job_running_cancel.id,
            worker_id=worker_a,
            lease_epoch=leased_first.job.lease_epoch,
            now=clock.advance(seconds=1),
        )
        assert acked.state == "cancelled"

        # Polling A-24 now observes terminal 'succeeded' receipt!
        op_poll_2 = await maint_client.get(f"/api/v1/operations/{cancel_op_id}")
        assert op_poll_2.status_code == 200
        assert op_poll_2.json()["state"] == "succeeded"
        assert op_poll_2.json()["result_id"] == job_running_cancel.id

        # --- Flow 2: Retry backoff -> DLQ -> live paused workspace block -> scoped requeue ---
        lease_dlq_1 = await queue_svc.acquire_next_lease(worker_id=worker_a, now=clock())
        assert lease_dlq_1 is not None and lease_dlq_1.job.id == job_dlq_replay.id
        failed_1 = await queue_svc.fail_lease(
            job_id=job_dlq_replay.id,
            worker_id=worker_a,
            lease_epoch=lease_dlq_1.job.lease_epoch,
            error_code="runner_transient_io",
            error_detail="Temporary network timeout fetching artifact.",
            recoverable=True,
            now=clock.advance(seconds=1),
        )
        assert failed_1.state == "queued"
        assert failed_1.attempt == 2
        assert failed_1.not_before > clock()

        # Advance clock past jittered backoff so attempt 2 leases, then exhaust into DLQ
        clock.advance(seconds=15)
        lease_dlq_2 = await queue_svc.acquire_next_lease(
            worker_id=worker_a,
            now=clock(),
            allowed_kinds={"repair.verify"},
        )
        assert lease_dlq_2 is not None and lease_dlq_2.job.id == job_dlq_replay.id
        failed_2 = await queue_svc.fail_lease(
            job_id=job_dlq_replay.id,
            worker_id=worker_a,
            lease_epoch=lease_dlq_2.job.lease_epoch,
            error_code="runner_transient_io",
            error_detail="Exhausted max_attempts=2.",
            recoverable=True,
            now=clock.advance(seconds=1),
        )
        assert failed_2.state == "dead_letter"

        # Pause workspace -> DLQ requeue MUST fail live policy recheck with 409!
        ws_get = await owner_client.get(f"/api/v1/workspaces/{ws_id}")
        pause_resp = await owner_client.patch(
            f"/api/v1/workspaces/{ws_id}",
            headers=_csrf_headers(owner_csrf, extra={"If-Match": ws_get.headers["ETag"]}),
            json={"paused": True},
        )
        assert pause_resp.status_code == 200

        requeue_while_paused = await owner_client.post(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_dlq_replay.id}/actions",
            headers=_csrf_headers(owner_csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={"action": "requeue", "reason": "Attempt replay while paused."},
        )
        assert requeue_while_paused.status_code == 409
        assert requeue_while_paused.json()["code"] == "workspace_paused_or_inactive"

        # Unpause workspace -> requeue succeeds idempotently and preserves effect & budget keys!
        unpause_resp = await owner_client.patch(
            f"/api/v1/workspaces/{ws_id}",
            headers=_csrf_headers(owner_csrf, extra={"If-Match": pause_resp.headers["ETag"]}),
            json={"paused": False},
        )
        assert unpause_resp.status_code == 200

        dlq_det = await owner_client.get(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_dlq_replay.id}"
        )
        assert dlq_det.status_code == 200
        assert dlq_det.json()["dead_letter_entry"]["status"] == "open"

        # Stale If-Match rejected
        stale_if_match = await owner_client.post(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_dlq_replay.id}/actions",
            headers=_csrf_headers(
                owner_csrf,
                extra={"Idempotency-Key": new_uuid7(now=clock()), "If-Match": '"v1"'},
            ),
            json={"action": "requeue", "reason": "Stale version check."},
        )
        assert stale_if_match.status_code in {409, 412}

        requeue_idem = new_uuid7(now=clock())
        requeue_resp = await owner_client.post(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_dlq_replay.id}/actions",
            headers=_csrf_headers(
                owner_csrf,
                extra={"Idempotency-Key": requeue_idem, "If-Match": dlq_det.headers["ETag"]},
            ),
            json={"action": "requeue", "reason": "Transient runner outage resolved."},
        )
        assert requeue_resp.status_code == 202, requeue_resp.text

        # Idempotent replay of exact same Idempotency-Key returns identical receipt without bump
        requeue_dup = await owner_client.post(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_dlq_replay.id}/actions",
            headers=_csrf_headers(
                owner_csrf,
                extra={"Idempotency-Key": requeue_idem, "If-Match": dlq_det.headers["ETag"]},
            ),
            json={"action": "requeue", "reason": "Transient runner outage resolved."},
        )
        assert requeue_dup.status_code == 202
        assert requeue_dup.json()["operation_id"] == requeue_resp.json()["operation_id"]

        after_requeue = await owner_client.get(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_dlq_replay.id}"
        )
        assert after_requeue.status_code == 200
        after_body = after_requeue.json()
        assert after_body["state"] == "queued"
        assert after_body["attempt"] == 3
        assert after_body["logical_effect_key"] == "eff:publish:repair-77"
        assert after_body["budget_key"] == "budget:session-77"
        assert after_body["dead_letter_entry"]["status"] == "requeued"

        # --- Flow 3: W-08 Ambiguous side-effect blocks blind requeue until reconcile ---
        # Lease job_ambiguous and job_repo2 and fail both with reconcile_required=True
        lease_amb = await queue_svc.acquire_next_lease(
            worker_id=worker_b,
            now=clock(),
            allowed_kinds={"publish.draft_pr"},
        )
        assert lease_amb is not None and lease_amb.job.id == job_ambiguous.id
        await queue_svc.fail_lease(
            job_id=job_ambiguous.id,
            worker_id=worker_b,
            lease_epoch=lease_amb.job.lease_epoch,
            error_code="provider_timeout_post_write",
            error_detail="HTTP timeout after sending POST /pulls; external state unknown.",
            recoverable=True,
            reconcile_required=True,
            now=clock.advance(seconds=1),
        )

        lease_r2 = await queue_svc.acquire_next_lease(
            worker_id=worker_b,
            now=clock(),
            allowed_kinds={"publish.draft_pr"},
        )
        assert lease_r2 is not None and lease_r2.job.id == job_repo2.id
        await queue_svc.fail_lease(
            job_id=job_repo2.id,
            worker_id=worker_b,
            lease_epoch=lease_r2.job.lease_epoch,
            error_code="provider_timeout_post_write",
            error_detail="HTTP timeout; PR actually created on provider.",
            recoverable=True,
            reconcile_required=True,
            now=clock.advance(seconds=1),
        )

        # Blind requeue on reconcile_required job MUST fail with 409!
        blind_requeue = await owner_client.post(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_ambiguous.id}/actions",
            headers=_csrf_headers(owner_csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={"action": "requeue", "reason": "Try blind replay without reconciling."},
        )
        assert blind_requeue.status_code == 409
        assert blind_requeue.json()["code"] == "reconcile_required_before_requeue"

        # Reconcile confirmed_absent -> clears reconcile_required -> requeue now succeeds!
        rec_absent = await owner_client.post(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_ambiguous.id}/actions",
            headers=_csrf_headers(owner_csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={
                "action": "reconcile",
                "reason": "Checked GitHub pulls API: no draft PR exists for branch.",
                "reconciled_outcome": "confirmed_absent",
            },
        )
        assert rec_absent.status_code == 202

        safe_requeue = await owner_client.post(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_ambiguous.id}/actions",
            headers=_csrf_headers(
                owner_csrf,
                extra={"Idempotency-Key": new_uuid7(now=clock.advance(milliseconds=5))},
            ),
            json={"action": "requeue", "reason": "Safe replay after confirmed_absent."},
        )
        assert safe_requeue.status_code == 202

        # Maintainer without repo_2 grant gets 404 on POST /actions for job_repo2
        maint_r2_act = await maint_client.post(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_repo2.id}/actions",
            headers=_csrf_headers(maint_csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={
                "action": "reconcile",
                "reason": "Ungranted repo attempt.",
                "reconciled_outcome": "confirmed_applied",
            },
        )
        assert maint_r2_act.status_code == 404

        # Owner reconciles job_repo2 as confirmed_applied -> marks succeeded & seals tombstone!
        rec_applied = await owner_client.post(
            f"/api/v1/workspaces/{ws_id}/task-jobs/{job_repo2.id}/actions",
            headers=_csrf_headers(owner_csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={
                "action": "reconcile",
                "reason": "Draft PR #42 confirmed present on GitHub.",
                "reconciled_outcome": "confirmed_applied",
            },
        )
        assert rec_applied.status_code == 202
        r2_op_id = rec_applied.json()["operation_id"]

        # Maintainer without repo_2 grant gets 404 on /operations/{r2_op_id}
        assert (await maint_client.get(f"/api/v1/operations/{r2_op_id}")).status_code == 404

        r2_det = await owner_client.get(f"/api/v1/workspaces/{ws_id}/task-jobs/{job_repo2.id}")
        assert r2_det.status_code == 200
        assert r2_det.json()["state"] == "succeeded"
        assert r2_det.json()["dead_letter_entry"]["status"] == "reconciled"

        # --- Flow 4: Live rights revocation on A-24 when Maintainer is demoted to Viewer ---
        members_resp = await owner_client.get(f"/api/v1/workspaces/{ws_id}/members")
        maint_member = next(
            m for m in members_resp.json()["items"] if m["user_id"] == maint_user_id
        )
        demote_resp = await owner_client.patch(
            f"/api/v1/workspaces/{ws_id}/members/{maint_member['id']}",
            headers=_csrf_headers(
                owner_csrf, extra={"expected_version": str(maint_member["version"])}
            ),
            json={
                "role": "viewer",
                "repository_grants": [repo_1],
                "expected_version": maint_member["version"],
            },
        )
        assert demote_resp.status_code == 200, demote_resp.text

        # Maintainer (now viewer) polling their OWN earlier cancel_op_id gets 403!
        demoted_poll = await maint_client.get(f"/api/v1/operations/{cancel_op_id}")
        assert demoted_poll.status_code == 403
        assert demoted_poll.json()["code"] == "insufficient_role"

        # --- Flow 5: Workspace deletion ActionReceipt is queryable via A-24 by Instance Owner ---
        owner_csrf = await _enroll_mfa_and_step_up(
            owner_client,
            owner_csrf,
            password=OWNER_CREDENTIAL,
            clock=clock,
        )
        del_resp = await owner_client.request(
            "DELETE",
            f"/api/v1/workspaces/{ws_temp_id}",
            headers=_csrf_headers(owner_csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={"confirm_name": "Temp Delete WS"},
        )
        assert del_resp.status_code == 202, del_resp.text
        del_op_id = del_resp.json()["operation_id"]

        owner_del_poll = await owner_client.get(f"/api/v1/operations/{del_op_id}")
        assert owner_del_poll.status_code == 200
        assert owner_del_poll.json()["state"] == "succeeded"
        assert (await viewer_client.get(f"/api/v1/operations/{del_op_id}")).status_code == 404

        # Verify cryptographic SHA-256 audit hash chain across all U08 entries
        admin_engine = create_admin_engine(migrated_db.admin_url)
        try:
            admin_factory = create_session_factory(admin_engine)
            with tempfile.TemporaryDirectory(prefix="red2pr_u08_ckpt2_") as ckpt_dir:
                async with admin_factory() as adm_db:
                    verified_entries = await verify_audit_chain(
                        adm_db,
                        external_store=ExternalCheckpointStore(Path(ckpt_dir)),
                        keyring=KeyRing(),
                    )
                    assert verified_entries >= 15
        finally:
            await admin_engine.dispose()
    finally:
        transport.close()
        await owner_client.aclose()
        await maint_client.aclose()
        await viewer_client.aclose()
        await outsider_client.aclose()
        await app_engine.dispose()
