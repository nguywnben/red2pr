"""Durable retention queue worker; database state commits before object-store deletion."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, or_, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.db.base import (
    ArtifactBlobModel,
    ArtifactDeletionJobModel,
    EffectReplayGuardModel,
    EffectTombstoneModel,
    WorkspaceModel,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.operations.backup_restore import BACKUP_HOLD_LOCK
from red2pr_control.triage_evidence.artifact_store import (
    ArtifactStoreProtocol,
    purge_expired_artifacts_in_tx,
)


class RetentionPurgeWorker:
    """Claim one tenant job at a time and safely retry idempotent object deletion."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        store: ArtifactStoreProtocol | None,
        poll_interval: float = 15,
    ) -> None:
        self.session_factory = session_factory
        self.store = store
        self.poll_interval = poll_interval

    async def process_one(self, *, workspace_id: str, now: datetime | None = None) -> bool:
        """Hold the shared backup/deletion fence through physical object deletion."""
        async with self.session_factory() as hold_db:
            await hold_db.execute(
                text("SELECT pg_advisory_lock(:lock_id)"), {"lock_id": BACKUP_HOLD_LOCK}
            )
            try:
                return await self._process_one_under_backup_hold(workspace_id=workspace_id, now=now)
            finally:
                await hold_db.execute(
                    text("SELECT pg_advisory_unlock(:lock_id)"), {"lock_id": BACKUP_HOLD_LOCK}
                )
                await hold_db.commit()

    async def _process_one_under_backup_hold(
        self, *, workspace_id: str, now: datetime | None = None
    ) -> bool:
        ref_now = now.astimezone(UTC) if now else datetime.now(tz=UTC)
        if self.store is None:
            return False
        async with workspace_rls_session(self.session_factory, workspace_id=workspace_id) as db:
            job = await db.scalar(
                select(ArtifactDeletionJobModel)
                .where(
                    or_(
                        ArtifactDeletionJobModel.state == "pending",
                        ArtifactDeletionJobModel.state == "claimed",
                    ),
                    ArtifactDeletionJobModel.available_at <= ref_now,
                )
                .order_by(
                    ArtifactDeletionJobModel.available_at, ArtifactDeletionJobModel.created_at
                )
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            if job is None:
                return False
            blob = await db.scalar(
                select(ArtifactBlobModel).where(
                    ArtifactBlobModel.workspace_id == workspace_id,
                    ArtifactBlobModel.id == job.blob_id,
                )
            )
            if blob is None or blob.blob_state == "purged":
                job.state = "deleted"
                job.completed_at = ref_now
                job.error_code = None
                return True
            if blob.blob_state != "finalized":
                job.state = "failed"
                job.error_code = "blob_state_invalid"
                return True
            storage_ref = blob.storage_ref
            job_id = job.id
            blob_id = job.blob_id
            job.state = "claimed"
            job.attempts += 1
            attempt = job.attempts
            job.available_at = ref_now + timedelta(minutes=5)

        try:
            await self.store.delete_blob(workspace_id=workspace_id, storage_ref=storage_ref)
        except Exception:
            async with workspace_rls_session(self.session_factory, workspace_id=workspace_id) as db:
                job = await db.scalar(
                    select(ArtifactDeletionJobModel)
                    .where(ArtifactDeletionJobModel.id == job_id)
                    .with_for_update()
                )
                if job is not None and job.state == "claimed":
                    job.state = "pending"
                    job.error_code = "storage_delete_failed"
                    job.available_at = ref_now + timedelta(seconds=min(3600, 2 ** min(attempt, 10)))
                    await append_audit_entry(
                        db,
                        actor_type="system",
                        actor_id="retention-worker",
                        action="artifact.retention.delete_retry",
                        target=f"artifact_blob:{blob_id}",
                        decision="error",
                        reason_code="storage_delete_failed",
                        correlation_id=job.correlation_id,
                        workspace_id=workspace_id,
                        occurred_at=ref_now,
                        metadata={"attempt": attempt},
                    )
            return True

        async with workspace_rls_session(self.session_factory, workspace_id=workspace_id) as db:
            job = await db.scalar(
                select(ArtifactDeletionJobModel)
                .where(
                    ArtifactDeletionJobModel.workspace_id == workspace_id,
                    ArtifactDeletionJobModel.id == job_id,
                )
                .with_for_update()
            )
            blob = await db.scalar(
                select(ArtifactBlobModel)
                .where(
                    ArtifactBlobModel.workspace_id == workspace_id,
                    ArtifactBlobModel.id == blob_id,
                )
                .with_for_update()
            )
            if job is not None and blob is not None and job.state == "claimed":
                blob.blob_state = "purged"
                blob.version += 1
                blob.updated_at = ref_now
                job.state = "deleted"
                job.completed_at = ref_now
                job.error_code = None
                await append_audit_entry(
                    db,
                    actor_type="system",
                    actor_id="retention-worker",
                    action="artifact.retention.blob_deleted",
                    target=f"artifact_blob:{blob_id}",
                    decision="allow",
                    reason_code="retention_expired",
                    correlation_id=job.correlation_id,
                    workspace_id=workspace_id,
                    occurred_at=ref_now,
                    metadata={"attempt": job.attempts},
                )
        return True

    async def purge_expired_tombstones(
        self, *, workspace_id: str, now: datetime | None = None, batch_size: int = 500
    ) -> int:
        """Delete only replay tombstones past their configured anti-replay horizon."""
        if not 1 <= batch_size <= 5000:
            raise ValueError("Retention batch size must be between 1 and 5000.")
        ref_now = now.astimezone(UTC) if now else datetime.now(tz=UTC)
        async with workspace_rls_session(self.session_factory, workspace_id=workspace_id) as db:
            expired_rows = list(
                (
                    await db.execute(
                        select(
                            EffectTombstoneModel.id,
                            EffectTombstoneModel.operation,
                            EffectTombstoneModel.logical_effect_key,
                        )
                        .where(EffectTombstoneModel.retained_until <= ref_now)
                        .order_by(EffectTombstoneModel.retained_until, EffectTombstoneModel.id)
                        .limit(batch_size)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
            )
            if not expired_rows:
                return 0
            for row in expired_rows:
                digest = hashlib.sha256(
                    row.logical_effect_key.encode("utf-8", errors="strict")
                ).hexdigest()
                await db.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                    {"key": f"effect-replay:{workspace_id}:{row.operation}:{digest}"},
                )
            await db.execute(
                pg_insert(EffectReplayGuardModel)
                .values(
                    [
                        {
                            "id": new_uuid7(now=ref_now),
                            "workspace_id": workspace_id,
                            "operation": row.operation,
                            "logical_effect_key_digest": hashlib.sha256(
                                row.logical_effect_key.encode("utf-8", errors="strict")
                            ).hexdigest(),
                            "created_at": ref_now,
                        }
                        for row in expired_rows
                    ]
                )
                .on_conflict_do_nothing(constraint="uq_effect_replay_guard_digest")
            )
            result = await db.execute(
                delete(EffectTombstoneModel)
                .where(EffectTombstoneModel.id.in_([row.id for row in expired_rows]))
                .returning(EffectTombstoneModel.id)
            )
            deleted_count = len(result.scalars().all())
            if deleted_count:
                await append_audit_entry(
                    db,
                    actor_type="system",
                    actor_id="retention-worker",
                    action="effect_tombstone.retention.purged",
                    target=f"workspace:{workspace_id}",
                    decision="allow",
                    reason_code="detail_expired_hash_guard_retained",
                    correlation_id=f"retention:tombstone:{workspace_id}:{ref_now.date().isoformat()}",
                    workspace_id=workspace_id,
                    occurred_at=ref_now,
                    metadata={"purged_details": deleted_count, "guard": "sha256"},
                )
            return deleted_count

    async def run_forever(self) -> None:
        """Poll each workspace, preserving tenant RLS for every data mutation."""
        from red2pr_control.operations.runtime import shared_operation_lease

        while True:
            worked = False
            async with shared_operation_lease(self.session_factory) as state:
                if not state.enabled:
                    async with instance_rls_session(
                        self.session_factory, mode="instance_admin"
                    ) as db:
                        workspace_ids = list(await db.scalars(select(WorkspaceModel.id)))
                    for workspace_id in workspace_ids:
                        async with workspace_rls_session(
                            self.session_factory, workspace_id=workspace_id
                        ) as db:
                            if self.store is not None:
                                await purge_expired_artifacts_in_tx(
                                    db,
                                    store=self.store,
                                    workspace_id=workspace_id,
                                    now=datetime.now(tz=UTC),
                                )
                        await self.purge_expired_tombstones(workspace_id=workspace_id)
                        worked = await self.process_one(workspace_id=workspace_id) or worked
            if not worked:
                await asyncio.sleep(self.poll_interval)
