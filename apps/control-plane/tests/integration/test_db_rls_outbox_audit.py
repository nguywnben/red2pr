"""PostgreSQL 16 integration & security tests for U03 foundation spine.

Verifies against a real disposable PostgreSQL 16 instance (never SQLite mocks):
- Alembic 0001_foundation_spine expand/contract reversibility (upgrade -> downgrade -> upgrade),
  PostgreSQL >= 16 check, fsync durability check (NFR-01), and instances singleton guard.
- Non-superuser / non-BYPASSRLS enforcement and pooled connection context-leak defense
  including hostile session-level GUC contamination & composite tenant FK guard (SEC-032).
- Atomic transaction commit & rollback across domain mutation + S-19 outbox_events +
  S-17 audit_log, plus FOR UPDATE SKIP LOCKED outbox claiming and lease_epoch fencing.
- S-05 Idempotency-Key UUIDv7 validation, 10-way concurrent duplicate race (exact-once
  side effect), payload mismatch 409, running 202 receipt, and 90-day effect_tombstones
  blocking duplicate logical effects after 7-day response cache expiry (NFR-07).
- Z2 SecretBroker external master-key loading, AES-256-GCM AAD tenant/purpose binding,
  caller capability isolation, live KEK rotation, revocation, and canary redaction (OPS-03).
- Append-only audit_log privilege/trigger protection and deterministic detection of
  mutated rows, deleted audit tails, and forged checkpoints against ExternalCheckpointStore
  (SEC-037).
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import tempfile
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import pgserver
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from py_contracts.crypto import (
    CryptoVerificationError,
    KeyRing,
    MasterKeyRing,
    export_ed25519_public_key_record,
)
from py_contracts.events import EventEnvelope, RepairPhaseEventPayload
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import (
    GENESIS_PREV_HASH,
    AuditIntegrityError,
    ExternalCheckpointStore,
    append_audit_entry,
    create_audit_checkpoint,
    verify_audit_chain,
)
from red2pr_control.core.errors import (
    BadRequestError,
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
)
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.base import (
    AuditLogModel,
    EffectReplayGuardModel,
    EffectTombstoneModel,
    IdempotencyRecordModel,
    InstanceModel,
    OutboxClaimModel,
    OutboxEventModel,
    SchemaMigrationRecordModel,
    SecretEntryModel,
    WorkspaceModel,
)
from red2pr_control.db.engine import (
    assert_non_bypassrls_role,
    assert_postgres_16_and_durability,
    create_admin_engine,
    create_app_engine,
    create_session_factory,
    ensure_compatible_event_loop,
    run_alembic_downgrade,
    run_alembic_upgrade,
)
from red2pr_control.db.idempotency import (
    claim_idempotent_operation,
    complete_idempotent_operation,
    purge_expired_idempotency_records,
)
from red2pr_control.db.outbox import (
    ack_outbox_claim,
    claim_pending_outbox_events,
    enqueue_outbox_event,
    fail_outbox_claim,
)
from red2pr_control.db.rls import (
    RlsConfigurationError,
    instance_rls_session,
    workspace_rls_session,
)
from red2pr_control.operations.retention import RetentionPurgeWorker
from red2pr_control.secrets.broker import (
    INFERENCE_SECRET_CAPABILITY,
    PUBLISHER_SECRET_CAPABILITY,
    SecretBroker,
    load_master_key_ring_from_file,
)

APP_ROLE_NAME = "red2pr_app"
APP_ROLE_PASSWORD = "red2pr_app_local_test_pw_01"


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
        tempfile.TemporaryDirectory(prefix="red2pr_u03_pg16_") as tmp_dir,
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


async def test_alembic_upgrade_downgrade_upgrade_and_durability_check(
    pg_urls: PgTestUrls,
) -> None:
    """Verify reversible 0001_foundation_spine migration, PG16+fsync check, and singleton guard."""
    run_alembic_downgrade(pg_urls.admin_url, "base", app_role_name=APP_ROLE_NAME)
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )

    expected_tables = {
        "instances",
        "workspaces",
        "secret_entries",
        "idempotency_records",
        "effect_tombstones",
        "outbox_events",
        "outbox_claims",
        "audit_log",
        "audit_checkpoints",
        "schema_migrations",
    }

    admin_engine = create_admin_engine(pg_urls.admin_url)
    app_engine = create_app_engine(pg_urls.app_url, pool_size=1, max_overflow=0)
    try:
        admin_factory = create_session_factory(admin_engine)
        app_factory = create_session_factory(app_engine)

        async with app_factory() as app_sess, app_sess.begin():
            durability = await assert_postgres_16_and_durability(app_sess)
            assert int(durability["server_version_num"]) >= 160000
            assert durability["fsync"] == "on"
            active_role = await assert_non_bypassrls_role(app_sess)
            assert active_role == APP_ROLE_NAME

        # Superuser engine must be rejected if passed to assert_non_bypassrls_role
        async with admin_factory() as admin_sess, admin_sess.begin():
            with pytest.raises(RlsConfigurationError):
                await assert_non_bypassrls_role(admin_sess)

            res = await admin_sess.execute(
                text(
                    "SELECT tablename FROM pg_tables "
                    "WHERE schemaname = 'public' AND tablename <> 'alembic_version'"
                )
            )
            present_tables = {row[0] for row in res.fetchall()}
            assert expected_tables.issubset(present_tables)

            mig = await admin_sess.scalar(
                select(SchemaMigrationRecordModel).where(
                    SchemaMigrationRecordModel.revision == "0001_foundation_spine"
                )
            )
            assert mig is not None
            assert mig.phase == "expand"
            assert mig.reversible is True
            assert len(mig.checksum_sha256) == 64

        # Downgrade to base must remove all 10 foundation tables cleanly
        run_alembic_downgrade(pg_urls.admin_url, "base", app_role_name=APP_ROLE_NAME)
        async with admin_factory() as admin_sess, admin_sess.begin():
            res_after_down = await admin_sess.execute(
                text(
                    "SELECT tablename FROM pg_tables "
                    "WHERE schemaname = 'public' AND tablename <> 'alembic_version'"
                )
            )
            remaining = {row[0] for row in res_after_down.fetchall()}
            assert expected_tables.isdisjoint(remaining)

        # Re-upgrade to head and verify instances singleton constraint
        run_alembic_upgrade(
            pg_urls.admin_url,
            "head",
            app_role_name=APP_ROLE_NAME,
            app_role_password=APP_ROLE_PASSWORD,
        )
        now = datetime.now(tz=UTC)
        async with instance_rls_session(app_factory, mode="instance_admin") as sess:
            sess.add(
                InstanceModel(
                    id=new_uuid7(now=now),
                    deployment_mode="local",
                    public_base_url="http://127.0.0.1:4280",
                    config_revision=1,
                    recovery_epoch=1,
                    initialized_at=now,
                )
            )

        with pytest.raises(IntegrityError):
            async with instance_rls_session(app_factory, mode="instance_admin") as sess:
                sess.add(
                    InstanceModel(
                        id=new_uuid7(now=now),
                        deployment_mode="local",
                        public_base_url="http://127.0.0.1:4280",
                        config_revision=1,
                        recovery_epoch=1,
                        initialized_at=now,
                    )
                )
    finally:
        await app_engine.dispose()
        await admin_engine.dispose()


async def test_rls_non_superuser_and_pool_reset_guard_sec_032(
    migrated_db: PgTestUrls,
) -> None:
    """Verify pooled connection reuse across Workspace A -> unscoped -> Workspace B leaks 0 rows."""
    app_engine = create_app_engine(migrated_db.app_url, pool_size=1, max_overflow=0)
    app_factory = create_session_factory(app_engine)
    now = datetime.now(tz=UTC)
    ws_a = new_uuid7(now=now)
    ws_b = new_uuid7(now=now)

    try:
        async with instance_rls_session(app_factory, mode="instance_admin") as sess:
            sess.add_all(
                [
                    WorkspaceModel(
                        id=ws_a,
                        name="Workspace Alpha",
                        slug="ws-alpha",
                        status="active",
                    ),
                    WorkspaceModel(
                        id=ws_b,
                        name="Workspace Beta",
                        slug="ws-beta",
                        status="active",
                    ),
                ]
            )

        event_a_id = new_uuid7(now=now)
        repair_a_id = new_uuid7(now=now)

        # 1. Populate Workspace A on the single pooled backend connection
        async with workspace_rls_session(app_factory, workspace_id=ws_a) as sess:
            pid_a = await sess.scalar(text("SELECT pg_backend_pid()"))
            evt_a = EventEnvelope(
                event_id=event_a_id,
                type="repair.session.created",
                occurred_at=now,
                workspace_id=ws_a,
                aggregate_id=repair_a_id,
                aggregate_version=1,
                correlation_id="corr-rls-a",
                payload=RepairPhaseEventPayload(repair_id=repair_a_id, state="received"),
            )
            seq_a = await enqueue_outbox_event(sess, evt_a, now=now)
            assert seq_a == 1

            claim_a = await claim_idempotent_operation(
                sess,
                workspace_id=ws_a,
                principal_id="usr_alpha",
                operation="repairs.create",
                idempotency_key=new_uuid7(now=now),
                request_payload={"run_id": "run_1"},
                logical_effect_key="repair:run_1",
                resource_id=repair_a_id,
                status_url=f"/api/v1/operations/{repair_a_id}",
                correlation_id="corr-rls-a",
                now=now,
            )
            assert claim_a.is_new_claim is True

        # 2. Reuse the EXACT SAME pooled connection WITHOUT setting workspace context
        async with app_factory() as raw_sess, raw_sess.begin():
            pid_raw = await raw_sess.scalar(text("SELECT pg_backend_pid()"))
            assert pid_raw == pid_a
            assert (await raw_sess.scalars(select(WorkspaceModel))).all() == []
            assert (await raw_sess.scalars(select(OutboxEventModel))).all() == []
            assert (await raw_sess.scalars(select(IdempotencyRecordModel))).all() == []
            assert (await raw_sess.scalars(select(EffectTombstoneModel))).all() == []

        # 3. Reuse the EXACT SAME pooled connection under Workspace B
        async with workspace_rls_session(app_factory, workspace_id=ws_b) as sess_b:
            pid_b = await sess_b.scalar(text("SELECT pg_backend_pid()"))
            assert pid_b == pid_a
            visible_ws = (await sess_b.scalars(select(WorkspaceModel))).all()
            assert [w.id for w in visible_ws] == [ws_b]
            assert (await sess_b.scalars(select(OutboxEventModel))).all() == []
            assert (await sess_b.scalars(select(IdempotencyRecordModel))).all() == []
            assert (await sess_b.scalars(select(EffectTombstoneModel))).all() == []

        # 4. Cross-tenant write attempt (inserting ws_a row inside ws_b context) must fail RLS
        with pytest.raises(DBAPIError):
            async with workspace_rls_session(app_factory, workspace_id=ws_b) as sess_b:
                sess_b.add(
                    EffectTombstoneModel(
                        id=new_uuid7(now=now),
                        workspace_id=ws_a,
                        logical_effect_key="forged:effect",
                        operation="repairs.create",
                        origin_operation_id=new_uuid7(now=now),
                        idempotency_key=new_uuid7(now=now),
                        request_hash="a" * 64,
                        resource_id=repair_a_id,
                        retained_until=now + timedelta(days=90),
                        created_at=now,
                    )
                )

        # 5. Hostile session-level GUC leak (`is_local=false`) must be scrubbed on pool reset
        async with app_factory() as leaky_sess:
            await leaky_sess.execute(
                text("SELECT set_config('red2pr.scope_mode', 'workspace', false)")
            )
            await leaky_sess.execute(
                text("SELECT set_config('red2pr.workspace_id', :ws, false)"),
                {"ws": ws_a},
            )
            await leaky_sess.commit()

        async with app_factory() as clean_sess, clean_sess.begin():
            pid_after_leak = await clean_sess.scalar(text("SELECT pg_backend_pid()"))
            assert pid_after_leak == pid_a
            leaked_ws = await clean_sess.scalar(
                text("SELECT current_setting('red2pr.workspace_id', true)")
            )
            assert not leaked_ws
            assert (await clean_sess.scalars(select(OutboxEventModel))).all() == []

        # 6. Composite tenant FK guard: outbox_claims in ws_b referencing ws_a event_id must fail
        admin_engine = create_admin_engine(migrated_db.admin_url)
        try:
            admin_factory = create_session_factory(admin_engine)
            with pytest.raises(IntegrityError):
                async with admin_factory() as admin_sess, admin_sess.begin():
                    admin_sess.add(
                        OutboxClaimModel(
                            id=new_uuid7(now=now),
                            workspace_id=ws_b,
                            event_id=event_a_id,
                            consumer_group="sse_fanout",
                            worker_id="wrk-1",
                            lease_epoch=1,
                            claimed_at=now,
                            lease_expires_at=now + timedelta(seconds=60),
                        )
                    )
        finally:
            await admin_engine.dispose()
    finally:
        await app_engine.dispose()


async def test_atomic_mutation_outbox_audit_rollback_and_fenced_claims(
    migrated_db: PgTestUrls,
) -> None:
    """Verify atomic commit/rollback of domain+outbox+audit and lease_epoch outbox fencing."""
    app_engine = create_app_engine(migrated_db.app_url, pool_size=4, max_overflow=2)
    app_factory = create_session_factory(app_engine)
    now = datetime.now(tz=UTC)
    ws_id = new_uuid7(now=now)

    try:
        async with instance_rls_session(app_factory, mode="instance_admin") as sess:
            sess.add(WorkspaceModel(id=ws_id, name="Outbox WS", slug="outbox-ws", status="active"))

        # 1. Simulated mid-transaction crash rolls back domain + outbox + audit together
        aborted_repair_id = new_uuid7(now=now)
        with pytest.raises(RuntimeError, match="simulated_failure_before_commit"):
            async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
                await enqueue_outbox_event(
                    sess,
                    EventEnvelope(
                        event_id=new_uuid7(now=now),
                        type="repair.session.created",
                        occurred_at=now,
                        workspace_id=ws_id,
                        aggregate_id=aborted_repair_id,
                        aggregate_version=1,
                        correlation_id="corr-rollback",
                        payload=RepairPhaseEventPayload(
                            repair_id=aborted_repair_id,
                            state="received",
                        ),
                    ),
                    now=now,
                )
                await append_audit_entry(
                    sess,
                    actor_type="user",
                    actor_id="usr_1",
                    action="repairs.create",
                    target=f"repair:{aborted_repair_id}",
                    decision="allow",
                    reason_code="policy_permitted",
                    correlation_id="corr-rollback",
                    workspace_id=ws_id,
                    occurred_at=now,
                )
                raise RuntimeError("simulated_failure_before_commit")

        async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
            assert (await sess.scalars(select(OutboxEventModel))).all() == []
            ws_row = await sess.get(WorkspaceModel, ws_id)
            assert ws_row is not None and ws_row.last_event_seq == 0

        # 2. Successful atomic commit assigns workspace_seq=1 and persists audit entry
        committed_repair_id = new_uuid7(now=now)
        committed_event_id = new_uuid7(now=now)
        async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
            seq = await enqueue_outbox_event(
                sess,
                EventEnvelope(
                    event_id=committed_event_id,
                    type="repair.session.created",
                    occurred_at=now,
                    workspace_id=ws_id,
                    aggregate_id=committed_repair_id,
                    aggregate_version=1,
                    correlation_id="corr-commit",
                    payload=RepairPhaseEventPayload(
                        repair_id=committed_repair_id,
                        state="received",
                    ),
                ),
                now=now,
            )
            assert seq == 1
            audit_rec = await append_audit_entry(
                sess,
                actor_type="user",
                actor_id="usr_1",
                action="repairs.create",
                target=f"repair:{committed_repair_id}",
                decision="allow",
                reason_code="policy_permitted",
                correlation_id="corr-commit",
                workspace_id=ws_id,
                occurred_at=now,
            )
            assert audit_rec.prev_hash == GENESIS_PREV_HASH

        # 3. Claim via FOR UPDATE SKIP LOCKED, test lease expiry & stale lease_epoch rejection
        async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
            claimed_1 = await claim_pending_outbox_events(
                sess,
                consumer_group="notification_dispatcher",
                worker_id="disp-1",
                workspace_id=ws_id,
                lease_seconds=30,
                now=now,
            )
            assert len(claimed_1) == 1
            assert claimed_1[0].event.event_id == committed_event_id
            assert claimed_1[0].lease_epoch == 1

            # Second consumer before lease expiry claims 0 events
            claimed_dup = await claim_pending_outbox_events(
                sess,
                consumer_group="notification_dispatcher",
                worker_id="disp-2",
                workspace_id=ws_id,
                lease_seconds=30,
                now=now + timedelta(seconds=10),
            )
            assert claimed_dup == []

        # After lease expires (+35s), disp-2 reclaims with lease_epoch == 2
        later = now + timedelta(seconds=35)
        async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
            claimed_2 = await claim_pending_outbox_events(
                sess,
                consumer_group="notification_dispatcher",
                worker_id="disp-2",
                workspace_id=ws_id,
                lease_seconds=30,
                now=later,
            )
            assert len(claimed_2) == 1
            assert claimed_2[0].lease_epoch == 2

        # Stale worker disp-1 attempting ack with lease_epoch=1 is fenced off (409)
        with pytest.raises(ConflictError) as exc_info:
            async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
                await ack_outbox_claim(
                    sess,
                    event_id=committed_event_id,
                    consumer_group="notification_dispatcher",
                    worker_id="disp-1",
                    lease_epoch=1,
                    now=later + timedelta(seconds=1),
                )
        assert exc_info.value.code == "stale_outbox_lease"

        # Current lease holder disp-2 fails at attempt 2 (max_attempts=3 -> retries as 'pending')
        async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
            status_after_fail = await fail_outbox_claim(
                sess,
                event_id=committed_event_id,
                consumer_group="notification_dispatcher",
                worker_id="disp-2",
                lease_epoch=2,
                error_code="smtp_timeout",
                retry_delay_seconds=5,
                max_attempts=3,
                now=later + timedelta(seconds=2),
            )
            assert status_after_fail == "pending"

        retry_time = later + timedelta(seconds=10)
        async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
            claimed_3 = await claim_pending_outbox_events(
                sess,
                consumer_group="notification_dispatcher",
                worker_id="disp-2",
                workspace_id=ws_id,
                lease_seconds=30,
                now=retry_time,
            )
            assert len(claimed_3) == 1
            assert claimed_3[0].lease_epoch == 3
            await ack_outbox_claim(
                sess,
                event_id=committed_event_id,
                consumer_group="notification_dispatcher",
                worker_id="disp-2",
                lease_epoch=3,
                now=retry_time + timedelta(seconds=1),
            )

        # 4. Exhausted max_attempts=1 transitions outbox event to 'dead_letter'
        dlq_event_id = new_uuid7(now=retry_time)
        async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
            seq_2 = await enqueue_outbox_event(
                sess,
                EventEnvelope(
                    event_id=dlq_event_id,
                    type="repair.session.created",
                    occurred_at=retry_time,
                    workspace_id=ws_id,
                    aggregate_id=committed_repair_id,
                    aggregate_version=2,
                    correlation_id="corr-dlq",
                    payload=RepairPhaseEventPayload(
                        repair_id=committed_repair_id,
                        state="received",
                    ),
                ),
                now=retry_time,
            )
            assert seq_2 == 2
            dlq_claimed = await claim_pending_outbox_events(
                sess,
                consumer_group="notification_dispatcher",
                worker_id="disp-2",
                workspace_id=ws_id,
                lease_seconds=30,
                now=retry_time,
            )
            assert len(dlq_claimed) == 1
            dlq_status = await fail_outbox_claim(
                sess,
                event_id=dlq_event_id,
                consumer_group="notification_dispatcher",
                worker_id="disp-2",
                lease_epoch=1,
                error_code="permanent_webhook_410",
                max_attempts=1,
                now=retry_time + timedelta(seconds=1),
            )
            assert dlq_status == "dead_letter"
            assert (
                await claim_pending_outbox_events(
                    sess,
                    consumer_group="notification_dispatcher",
                    worker_id="disp-2",
                    workspace_id=ws_id,
                    lease_seconds=30,
                    now=retry_time + timedelta(minutes=5),
                )
                == []
            )
    finally:
        await app_engine.dispose()


async def test_s05_idempotency_concurrency_mismatch_expiry_and_tombstones(
    migrated_db: PgTestUrls,
) -> None:
    """Verify S-05 concurrent exact-once claim, 409 mismatch, 202 running, and 90d tombstones."""
    app_engine = create_app_engine(migrated_db.app_url, pool_size=12, max_overflow=4)
    app_factory = create_session_factory(app_engine)
    now = datetime.now(tz=UTC)
    ws_id = new_uuid7(now=now)

    try:
        async with instance_rls_session(app_factory, mode="instance_admin") as sess:
            sess.add(WorkspaceModel(id=ws_id, name="Idem WS", slug="idem-ws", status="active"))

        # 1. Malformed / future-skewed / >7d expired UUIDv7 keys
        with pytest.raises(BadRequestError) as bad_err:
            async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
                await claim_idempotent_operation(
                    sess,
                    workspace_id=ws_id,
                    principal_id="usr_1",
                    operation="repairs.create",
                    idempotency_key="not-a-uuid",
                    request_payload={"a": 1},
                    logical_effect_key="eff:bad",
                    resource_id=new_uuid7(now=now),
                    status_url="/api/v1/operations/bad",
                    correlation_id="corr-bad",
                    now=now,
                )
        assert bad_err.value.code == "invalid_idempotency_key"

        future_key = new_uuid7(now=now + timedelta(minutes=10))
        with pytest.raises(BadRequestError) as skew_err:
            async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
                await claim_idempotent_operation(
                    sess,
                    workspace_id=ws_id,
                    principal_id="usr_1",
                    operation="repairs.create",
                    idempotency_key=future_key,
                    request_payload={"a": 1},
                    logical_effect_key="eff:skew",
                    resource_id=new_uuid7(now=now),
                    status_url="/api/v1/operations/skew",
                    correlation_id="corr-skew",
                    now=now,
                )
        assert skew_err.value.code == "invalid_idempotency_key"

        stale_key = new_uuid7(now=now - timedelta(days=8))
        with pytest.raises(ConflictError) as exp_err:
            async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
                await claim_idempotent_operation(
                    sess,
                    workspace_id=ws_id,
                    principal_id="usr_1",
                    operation="repairs.create",
                    idempotency_key=stale_key,
                    request_payload={"a": 1},
                    logical_effect_key="eff:stale",
                    resource_id=new_uuid7(now=now),
                    status_url="/api/v1/operations/stale",
                    correlation_id="corr-stale",
                    now=now,
                )
        assert exp_err.value.code == "key_expired"

        # 2. 10-way concurrent race with identical Idempotency-Key -> exact 1 winner
        shared_key = new_uuid7(now=now)
        shared_payload = {"run_id": "run_concurrent", "mode": "approval"}
        barrier = asyncio.Event()

        async def _worker(idx: int) -> tuple[bool, int, str]:
            await barrier.wait()
            candidate_res_id = new_uuid7(now=now)
            async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
                outcome = await claim_idempotent_operation(
                    sess,
                    workspace_id=ws_id,
                    principal_id="usr_1",
                    operation="repairs.create",
                    idempotency_key=shared_key,
                    request_payload=shared_payload,
                    logical_effect_key="repair:run_concurrent:attempt_1",
                    resource_id=candidate_res_id,
                    status_url=f"/api/v1/operations/{candidate_res_id}",
                    correlation_id=f"corr-race-{idx}",
                    now=now,
                )
                return (outcome.is_new_claim, outcome.http_status, outcome.receipt.operation_id)

        tasks = [asyncio.create_task(_worker(i)) for i in range(10)]
        await asyncio.sleep(0.02)
        barrier.set()
        results = await asyncio.gather(*tasks)

        new_claims = [r for r in results if r[0] is True]
        dup_claims = [r for r in results if r[0] is False]
        assert len(new_claims) == 1
        assert len(dup_claims) == 9
        winning_op_id = new_claims[0][2]
        for _, status_code, op_id in dup_claims:
            assert status_code == 202
            assert op_id == winning_op_id

        # 3. Same Idempotency-Key with different payload -> 409 idempotency_payload_mismatch
        with pytest.raises(ConflictError) as mismatch_err:
            async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
                await claim_idempotent_operation(
                    sess,
                    workspace_id=ws_id,
                    principal_id="usr_1",
                    operation="repairs.create",
                    idempotency_key=shared_key,
                    request_payload={"run_id": "run_concurrent", "mode": "auto_repair"},
                    logical_effect_key="repair:run_concurrent:attempt_1",
                    resource_id=new_uuid7(now=now),
                    status_url="/api/v1/operations/mismatch",
                    correlation_id="corr-mismatch",
                    now=now,
                )
        assert mismatch_err.value.code == "idempotency_payload_mismatch"

        # 4. Complete operation and verify replay returns completed status + cached payload
        result_id = new_uuid7(now=now)
        async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
            completed = await complete_idempotent_operation(
                sess,
                workspace_id=ws_id,
                operation_id=winning_op_id,
                state="succeeded",
                status_code=201,
                result_id=result_id,
                response_payload={"repair_id": result_id, "state": "received"},
                now=now + timedelta(seconds=2),
            )
            assert completed.state == "succeeded"
            assert completed.result_id == result_id

        async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
            replay = await claim_idempotent_operation(
                sess,
                workspace_id=ws_id,
                principal_id="usr_1",
                operation="repairs.create",
                idempotency_key=shared_key,
                request_payload=shared_payload,
                logical_effect_key="repair:run_concurrent:attempt_1",
                resource_id=new_uuid7(now=now),
                status_url="/api/v1/operations/replay",
                correlation_id="corr-replay",
                now=now + timedelta(seconds=5),
            )
            assert replay.is_new_claim is False
            assert replay.http_status == 201
            assert replay.cached_response == {"repair_id": result_id, "state": "received"}

        # 5. Fast-forward +8 days: purge 7d idempotency_records cache while 90d tombstone remains
        eight_days_later = now + timedelta(days=8)
        async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
            purged = await purge_expired_idempotency_records(
                sess,
                workspace_id=ws_id,
                now=eight_days_later,
            )
            assert purged == 1
            remaining_tombstones = (await sess.scalars(select(EffectTombstoneModel))).all()
            assert len(remaining_tombstones) == 1

        # Fresh UUIDv7 key attempting the SAME logical_effect_key at +8d is blocked by tombstone!
        fresh_key_day8 = new_uuid7(now=eight_days_later)
        with pytest.raises(ConflictError) as tomb_err:
            async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
                await claim_idempotent_operation(
                    sess,
                    workspace_id=ws_id,
                    principal_id="usr_1",
                    operation="repairs.create",
                    idempotency_key=fresh_key_day8,
                    request_payload=shared_payload,
                    logical_effect_key="repair:run_concurrent:attempt_1",
                    resource_id=new_uuid7(now=eight_days_later),
                    status_url="/api/v1/operations/dup-effect",
                    correlation_id="corr-dup-effect",
                    now=eight_days_later,
                )
        assert tomb_err.value.code == "duplicate_logical_effect"

        # 6. After the 90d window, purge sensitive tombstone details but keep a hash-only guard.
        ninety_one_days_later = now + timedelta(days=91)
        retention = RetentionPurgeWorker(session_factory=app_factory, store=None)
        purged_tombstones = await retention.purge_expired_tombstones(
            workspace_id=ws_id,
            now=ninety_one_days_later,
        )
        assert purged_tombstones == 1
        async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
            assert await sess.scalar(select(EffectTombstoneModel.id)) is None
            guard = await sess.scalar(select(EffectReplayGuardModel))
            assert guard is not None
            assert len(guard.logical_effect_key_digest) == 64
            assert not hasattr(guard, "logical_effect_key")
        with pytest.raises(ConflictError) as long_term_guard_err:
            async with workspace_rls_session(app_factory, workspace_id=ws_id) as sess:
                await claim_idempotent_operation(
                    sess,
                    workspace_id=ws_id,
                    principal_id="usr_1",
                    operation="repairs.create",
                    idempotency_key=new_uuid7(now=ninety_one_days_later),
                    request_payload=shared_payload,
                    logical_effect_key="repair:run_concurrent:attempt_1",
                    resource_id=new_uuid7(now=ninety_one_days_later),
                    status_url="/api/v1/operations/dup-after-90d",
                    correlation_id="corr-dup-after-90d",
                    now=ninety_one_days_later,
                )
        assert long_term_guard_err.value.code == "duplicate_logical_effect"
    finally:
        await app_engine.dispose()


async def test_z2_secret_broker_envelope_aad_rotation_and_revocation(
    migrated_db: PgTestUrls,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify external MasterKeyRing loading, Z2 capability isolation, AAD, rotation & revoke."""
    # Missing master key file raises 503 DependencyUnavailableError
    with pytest.raises(DependencyUnavailableError) as missing_key_err:
        load_master_key_ring_from_file(tmp_path / "nonexistent_master_key.json")
    assert missing_key_err.value.code == "master_key_unavailable"

    k1 = os.urandom(32)
    k2 = os.urandom(32)
    key_file = tmp_path / "master_keys.json"
    key_file.write_text(
        json.dumps(
            {
                "active_version": 1,
                "keys": {"1": base64.b64encode(k1).decode("ascii")},
            }
        ),
        encoding="utf-8",
    )
    ring_v1 = load_master_key_ring_from_file(env={"RED2PR_MASTER_KEY_FILE": str(key_file)})
    redactor = Redactor()
    broker = SecretBroker(key_ring=ring_v1, redactor=redactor)

    app_engine = create_app_engine(migrated_db.app_url, pool_size=2, max_overflow=0)
    app_factory = create_session_factory(app_engine)
    now = datetime.now(tz=UTC)
    ws_a = new_uuid7(now=now)
    ws_b = new_uuid7(now=now)

    try:
        async with instance_rls_session(app_factory, mode="instance_admin") as sess:
            sess.add_all(
                [
                    WorkspaceModel(id=ws_a, name="Sec WS A", slug="sec-ws-a", status="active"),
                    WorkspaceModel(id=ws_b, name="Sec WS B", slug="sec-ws-b", status="active"),
                ]
            )

        raw_meta_secret = b"meta_muse_live_canary_secret_998877"
        raw_pub_secret = b"ghs_publisher_write_token_canary_112233445566"

        async with workspace_rls_session(app_factory, workspace_id=ws_a) as sess:
            meta_dto = await broker.store_secret(
                sess,
                plaintext=raw_meta_secret,
                purpose="meta_inference",
                workspace_id=ws_a,
                now=now,
            )
            pub_dto = await broker.store_secret(
                sess,
                plaintext=raw_pub_secret,
                purpose="provider_write",
                workspace_id=ws_a,
                now=now,
            )
            assert meta_dto.secret_ref.startswith("sec_")
            assert meta_dto.kek_version == 1
            assert "meta_muse_live_canary" not in meta_dto.model_dump_json()

            # Raw DB row must store ciphertext only, never plaintext
            db_row = await sess.scalar(
                select(SecretEntryModel).where(SecretEntryModel.secret_ref == meta_dto.secret_ref)
            )
            assert db_row is not None
            assert "meta_muse_live_canary" not in json.dumps(db_row.envelope_json)

        async with workspace_rls_session(app_factory, workspace_id=ws_b) as sess:
            workspace_b_secret = await broker.store_secret(
                sess,
                plaintext=b"workspace_b_rotation_canary_5566778899",
                purpose="meta_inference",
                workspace_id=ws_b,
                now=now,
            )

        # Redactor must automatically scrub the stored secret canary
        assert "[REDACTED:" in redactor.redact_text(
            f"Outbound error with key={raw_meta_secret.decode('utf-8')}"
        )

        # Z2 capability check: inference caller can read meta_inference, DENIED on provider_write
        async with workspace_rls_session(app_factory, workspace_id=ws_a) as sess:
            resolved = await broker.resolve_secret_bytes(
                sess,
                secret_ref=meta_dto.secret_ref,
                capability=INFERENCE_SECRET_CAPABILITY,
                workspace_id=ws_a,
            )
            assert resolved == raw_meta_secret

            with pytest.raises(ForbiddenError) as cap_err:
                await broker.resolve_secret_bytes(
                    sess,
                    secret_ref=pub_dto.secret_ref,
                    capability=INFERENCE_SECRET_CAPABILITY,
                    workspace_id=ws_a,
                )
            assert cap_err.value.code == "secret_purpose_denied"

        # Live KEK rotation v1 -> v2
        key_file.write_text(
            json.dumps(
                {
                    "active_version": 2,
                    "keys": {
                        "1": base64.b64encode(k1).decode("ascii"),
                        "2": base64.b64encode(k2).decode("ascii"),
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("RED2PR_MASTER_KEY_FILE", str(key_file))
        rotated = await broker.rotate_all_secret_keks(
            session_factory=app_factory,
            actor_id="u25-key-rotation-test",
            correlation_id="u25-key-rotation-correlation",
            now=now + timedelta(minutes=1),
        )
        assert rotated.active_kek_version == 2
        assert rotated.rotated_count == 3

        monkeypatch.delenv("RED2PR_MASTER_KEY_FILE")
        broker_v2_only = SecretBroker(key_ring=MasterKeyRing(active_version=2, keys={2: k2}))
        stale_broker = SecretBroker(key_ring=ring_v1)
        async with workspace_rls_session(app_factory, workspace_id=ws_a) as sess:
            resolved_pub = await broker_v2_only.resolve_secret_bytes(
                sess,
                secret_ref=pub_dto.secret_ref,
                capability=PUBLISHER_SECRET_CAPABILITY,
                workspace_id=ws_a,
            )
            assert resolved_pub == raw_pub_secret
            with pytest.raises(DependencyUnavailableError) as stale_process_err:
                await stale_broker.resolve_secret_bytes(
                    sess,
                    secret_ref=meta_dto.secret_ref,
                    capability=INFERENCE_SECRET_CAPABILITY,
                    workspace_id=ws_a,
                )
            assert stale_process_err.value.code == "master_key_rotation_reload_required"
        async with workspace_rls_session(app_factory, workspace_id=ws_b) as sess:
            assert (
                await broker_v2_only.resolve_secret_bytes(
                    sess,
                    secret_ref=workspace_b_secret.secret_ref,
                    capability=INFERENCE_SECRET_CAPABILITY,
                    workspace_id=ws_b,
                )
                == b"workspace_b_rotation_canary_5566778899"
            )

        # Cross-tenant ciphertext transplant attack (AAD mismatch check)
        async with workspace_rls_session(app_factory, workspace_id=ws_b) as sess_b:
            victim_b = await broker.store_secret(
                sess_b,
                plaintext=b"benign_ws_b_meta_secret_value",
                purpose="meta_inference",
                workspace_id=ws_b,
                now=now,
            )

        admin_engine = create_admin_engine(migrated_db.admin_url)
        try:
            admin_factory = create_session_factory(admin_engine)
            async with admin_factory() as admin_sess, admin_sess.begin():
                row_a = await admin_sess.scalar(
                    select(SecretEntryModel).where(
                        SecretEntryModel.secret_ref == meta_dto.secret_ref
                    )
                )
                row_b = await admin_sess.scalar(
                    select(SecretEntryModel).where(
                        SecretEntryModel.secret_ref == victim_b.secret_ref
                    )
                )
                assert row_a is not None and row_b is not None
                row_b.envelope_json = dict(row_a.envelope_json)
                row_b.aad_digest = row_a.aad_digest
        finally:
            await admin_engine.dispose()

        with pytest.raises(CryptoVerificationError) as aad_err:
            async with workspace_rls_session(app_factory, workspace_id=ws_b) as sess_b:
                await broker.resolve_secret_bytes(
                    sess_b,
                    secret_ref=victim_b.secret_ref,
                    capability=INFERENCE_SECRET_CAPABILITY,
                    workspace_id=ws_b,
                )
        assert aad_err.value.code == "aad_mismatch"

        # Revocation blocks any further resolution immediately
        async with workspace_rls_session(app_factory, workspace_id=ws_a) as sess:
            await broker.revoke_secret(
                sess,
                secret_ref=meta_dto.secret_ref,
                workspace_id=ws_a,
                now=now + timedelta(minutes=2),
            )
            with pytest.raises(ForbiddenError) as rev_err:
                await broker.resolve_secret_bytes(
                    sess,
                    secret_ref=meta_dto.secret_ref,
                    capability=INFERENCE_SECRET_CAPABILITY,
                    workspace_id=ws_a,
                )
            assert rev_err.value.code == "secret_revoked"
    finally:
        await app_engine.dispose()


async def test_audit_hash_chain_append_only_and_tamper_detection_sec_037(
    migrated_db: PgTestUrls,
    tmp_path: Path,
) -> None:
    """Verify append-only audit_log privileges/triggers and SEC-037 tail/rewrite detection."""
    checkpoint_dir = tmp_path / "external_audit_checkpoints"
    ext_store = ExternalCheckpointStore(checkpoint_dir)

    now = datetime.now(tz=UTC)
    signer_priv = Ed25519PrivateKey.generate()
    pub_rec = export_ed25519_public_key_record(
        private_key=signer_priv,
        key_id="audit-ckpt-key-1",
        not_before=now - timedelta(hours=1),
    )
    keyring = KeyRing([pub_rec])

    app_engine = create_app_engine(migrated_db.app_url, pool_size=4, max_overflow=2)
    app_factory = create_session_factory(app_engine)
    ws_id = new_uuid7(now=now)
    ws_other_id = new_uuid7(now=now)

    try:
        async with instance_rls_session(app_factory, mode="instance_admin") as sess:
            sess.add_all(
                [
                    WorkspaceModel(id=ws_id, name="Audit WS", slug="audit-ws", status="active"),
                    WorkspaceModel(
                        id=ws_other_id,
                        name="Audit WS 2",
                        slug="audit-ws-2",
                        status="active",
                    ),
                ]
            )

        # Append 4 entries across concurrent multi-workspace transactions (contiguity across RLS!)
        async def _append_one(idx: int) -> str:
            target_ws = ws_id if idx % 2 == 1 else ws_other_id
            async with workspace_rls_session(app_factory, workspace_id=target_ws) as sess:
                rec = await append_audit_entry(
                    sess,
                    actor_type="user",
                    actor_id=f"usr_{idx}",
                    action="policy.update",
                    target=f"repo:{idx}",
                    decision="allow",
                    reason_code="step_up_verified",
                    correlation_id=f"corr-audit-{idx}",
                    workspace_id=target_ws,
                    occurred_at=now + timedelta(seconds=idx),
                )
                return rec.entry_hash

        hashes = await asyncio.gather(*(_append_one(i) for i in range(1, 5)))
        assert len(set(hashes)) == 4

        # Workspace-scoped session sees ONLY its own 2 audit_log rows (RLS enforced)
        async with workspace_rls_session(app_factory, workspace_id=ws_id) as ws_sess:
            ws_audit_rows = (await ws_sess.scalars(select(AuditLogModel))).all()
            assert len(ws_audit_rows) == 2
            assert all(r.workspace_id == ws_id for r in ws_audit_rows)

        # App role attempting UPDATE or DELETE on audit_log must fail at DB level
        with pytest.raises(DBAPIError):
            async with instance_rls_session(app_factory, mode="audit_verifier") as sess:
                await sess.execute(text("DELETE FROM audit_log WHERE seq = 4"))

        with pytest.raises(DBAPIError):
            async with instance_rls_session(app_factory, mode="audit_verifier") as sess:
                await sess.execute(
                    text("UPDATE audit_log SET reason_code = 'tampered' WHERE seq = 1")
                )

        # Create signed checkpoint covering seq 1..4 in ExternalCheckpointStore + DB
        async with instance_rls_session(app_factory, mode="audit_verifier") as sess:
            ckpt = await create_audit_checkpoint(
                sess,
                external_store=ext_store,
                private_key=signer_priv,
                signer_key_id="audit-ckpt-key-1",
                now=now + timedelta(seconds=10),
            )
            assert ckpt.start_seq == 1
            assert ckpt.end_seq == 4
            assert ckpt.entry_count == 4

        async with instance_rls_session(app_factory, mode="audit_verifier") as sess:
            verified_count = await verify_audit_chain(
                sess,
                external_store=ext_store,
                keyring=keyring,
            )
            assert verified_count == 4

        admin_engine = create_admin_engine(migrated_db.admin_url)
        try:
            admin_factory = create_session_factory(admin_engine)

            # Tamper Case 1 (SEC-037): Superuser bypasses trigger to mutate row 2
            async with admin_factory() as admin_sess, admin_sess.begin():
                await admin_sess.execute(text("SET LOCAL session_replication_role = 'replica'"))
                await admin_sess.execute(
                    text("UPDATE audit_log SET reason_code = 'forged_reason' WHERE seq = 2")
                )

            with pytest.raises(AuditIntegrityError) as hash_err:
                async with instance_rls_session(app_factory, mode="audit_verifier") as sess:
                    await verify_audit_chain(
                        sess,
                        external_store=ext_store,
                        keyring=keyring,
                    )
            assert hash_err.value.code == "audit_hash_mismatch"

            # Restore row 2, then test Tamper Case 2 (SEC-037): Superuser deletes tail rows 3..4
            async with admin_factory() as admin_sess, admin_sess.begin():
                await admin_sess.execute(text("SET LOCAL session_replication_role = 'replica'"))
                await admin_sess.execute(
                    text("UPDATE audit_log SET reason_code = 'step_up_verified' WHERE seq = 2")
                )
                await admin_sess.execute(text("DELETE FROM audit_log WHERE seq >= 3"))

            with pytest.raises(AuditIntegrityError) as tail_err:
                async with instance_rls_session(app_factory, mode="audit_verifier") as sess:
                    await verify_audit_chain(
                        sess,
                        external_store=ext_store,
                        keyring=keyring,
                    )
            assert tail_err.value.code == "audit_tail_truncated"

            # Tamper Case 3 (SEC-037): Superuser also deletes DB checkpoint to hide tail deletion,
            # or mutates external checkpoint signature -> ExternalCheckpointStore catches both!
            async with admin_factory() as admin_sess, admin_sess.begin():
                await admin_sess.execute(text("SET LOCAL session_replication_role = 'replica'"))
                await admin_sess.execute(text("DELETE FROM audit_checkpoints"))

            with pytest.raises(AuditIntegrityError) as ckpt_missing_err:
                async with instance_rls_session(app_factory, mode="audit_verifier") as sess:
                    await verify_audit_chain(
                        sess,
                        external_store=ext_store,
                        keyring=keyring,
                    )
            assert ckpt_missing_err.value.code == "audit_checkpoint_tampered"

            # Corrupt signature in external checkpoint JSON -> signature verification fails
            ckpt_file = next(checkpoint_dir.glob("ckpt_*.json"))
            forged_json = json.loads(ckpt_file.read_text(encoding="utf-8"))
            forged_json["chain_digest"] = "f" * 64
            ckpt_file.write_text(json.dumps(forged_json), encoding="utf-8")

            with pytest.raises(AuditIntegrityError) as sig_err:
                async with instance_rls_session(app_factory, mode="audit_verifier") as sess:
                    await verify_audit_chain(
                        sess,
                        external_store=ext_store,
                        keyring=keyring,
                    )
            assert sig_err.value.code == "audit_checkpoint_signature_invalid"
        finally:
            await admin_engine.dispose()
    finally:
        await app_engine.dispose()
