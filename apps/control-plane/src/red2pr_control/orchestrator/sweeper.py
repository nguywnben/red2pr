"""Orphaned lease sweeper and Redis-loss queue transport rebuilder (U08, NFR-01, NFR-02).

Enforces:
- `NFR-02`: Worker heartbeats every `15s` on `60s` leases; `sweep_expired_leases`
  (cadence `<=30s`) detects orphaned leases within `<=90s` from last heartbeat,
  fences out dead/slow workers by clearing active ownership (the next lease bumps
  `lease_epoch + 1`), and immediately returns recoverable orphans to `queued`
  (`not_before = ref_now` -> `<=120s` re-lease when worker capacity exists) or routes
  exhausted / ambiguous side-effect jobs to `dead_letter_jobs`.
- `NFR-01` & `ADR-035`: `rebuild_transport_from_db` deterministically re-enqueues
  Dramatiq wakeup hints for all eligible PostgreSQL `task_jobs` when Redis restarts
  empty (`FLUSHALL`), achieving `0` acknowledged job loss and `0` duplicate effects.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.db.base import (
    DeadLetterJobModel,
    TaskAttemptModel,
    TaskJobModel,
    WorkspaceModel,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.orchestrator.dramatiq_broker import (
    NullQueueTransport,
    QueueWakeupTransport,
)

SWEEPABLE_STATES: tuple[str, ...] = ("leased", "running", "cancel_requested")
DEFAULT_SWEEPER_INTERVAL_SECONDS = 15


@dataclass(frozen=True)
class SweepReport:
    """Deterministic summary of an orphan lease sweep pass (`NFR-02`)."""

    requeued_job_ids: tuple[str, ...]
    dead_lettered_job_ids: tuple[str, ...]
    cancelled_job_ids: tuple[str, ...]


@dataclass(frozen=True)
class TransportRebuildReport:
    """Summary of rebuilding Redis wakeup hints from PostgreSQL (`NFR-01`, `ADR-035`)."""

    eligible_jobs: int
    published_wakeups: int


class QueueLeaseSweeper:
    """Background/on-demand orphan lease sweeper and Redis wakeup rebuilder."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        transport: QueueWakeupTransport | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._transport: QueueWakeupTransport = transport or NullQueueTransport()

    async def sweep_expired_leases(
        self,
        *,
        now: datetime,
        batch_size: int = 100,
    ) -> SweepReport:
        """Sweep expired worker leases (`FOR UPDATE SKIP LOCKED`) and recover/DLQ safely."""
        ref_now = now.astimezone(UTC)
        requeued_ids: list[str] = []
        dead_lettered_ids: list[str] = []
        cancelled_ids: list[str] = []
        wakeup_targets: list[tuple[str, str]] = []

        async with instance_rls_session(self._session_factory, mode="instance_admin") as inst_db:
            cand_pairs = (
                await inst_db.execute(
                    select(TaskJobModel.workspace_id, TaskJobModel.id)
                    .where(
                        TaskJobModel.state.in_(SWEEPABLE_STATES),
                        TaskJobModel.lease_expires_at.is_not(None),
                        TaskJobModel.lease_expires_at <= ref_now,
                    )
                    .order_by(TaskJobModel.lease_expires_at.asc(), TaskJobModel.id.asc())
                    .limit(max(1, batch_size))
                )
            ).all()

        jobs_by_ws: dict[str, list[str]] = {}
        for raw_ws_id, raw_job_id in cand_pairs:
            jobs_by_ws.setdefault(str(raw_ws_id), []).append(str(raw_job_id))

        for ws_id, cand_job_ids in jobs_by_ws.items():
            async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
                expired_rows = list(
                    (
                        await db.scalars(
                            select(TaskJobModel)
                            .where(
                                TaskJobModel.workspace_id == ws_id,
                                TaskJobModel.id.in_(cand_job_ids),
                                TaskJobModel.state.in_(SWEEPABLE_STATES),
                                TaskJobModel.lease_expires_at.is_not(None),
                                TaskJobModel.lease_expires_at <= ref_now,
                            )
                            .order_by(TaskJobModel.lease_expires_at.asc(), TaskJobModel.id.asc())
                            .with_for_update(skip_locked=True)
                        )
                    ).all()
                )

                for job_row in expired_rows:
                    prior_worker = job_row.leased_by_worker_id or "unknown_worker"
                    prior_epoch = job_row.lease_epoch

                    attempt_row = await db.scalar(
                        select(TaskAttemptModel)
                        .where(
                            TaskAttemptModel.job_id == job_row.id,
                            TaskAttemptModel.lease_epoch == prior_epoch,
                        )
                        .with_for_update()
                    )
                    if attempt_row is not None and attempt_row.ended_at is None:
                        attempt_row.state = (
                            "cancelled" if job_row.state == "cancel_requested" else "orphaned"
                        )
                        attempt_row.ended_at = ref_now
                        attempt_row.error_code = "lease_expired"
                        attempt_row.error_detail = (
                            f"Worker {prior_worker} missed heartbeat past lease_expires_at."
                        )

                    if job_row.state == "cancel_requested":
                        job_row.state = "cancelled"
                        job_row.leased_by_worker_id = None
                        job_row.lease_expires_at = None
                        job_row.last_error_code = "cancelled_after_lease_expiry"
                        job_row.last_error_detail = (
                            "Cancel-requested job transitioned to cancelled upon lease expiry."
                        )
                        job_row.version += 1
                        job_row.updated_at = ref_now
                        await db.flush()
                        await append_audit_entry(
                            db,
                            workspace_id=job_row.workspace_id,
                            actor_type="system",
                            actor_id="lease_sweeper",
                            action="task_job.cancelled",
                            target=f"task_job:{job_row.id}",
                            decision="allow",
                            reason_code="cancelled_after_lease_expiry",
                            correlation_id=job_row.correlation_id,
                            metadata={
                                "expired_lease_epoch": prior_epoch,
                                "orphaned_worker_id": prior_worker,
                            },
                            occurred_at=ref_now,
                        )
                        cancelled_ids.append(job_row.id)
                    elif (
                        job_row.recoverable
                        and not job_row.reconcile_required
                        and job_row.attempt < job_row.max_attempts
                        and ref_now < job_row.deadline
                    ):
                        job_row.attempt += 1
                        job_row.state = "queued"
                        job_row.leased_by_worker_id = None
                        job_row.lease_expires_at = None
                        job_row.not_before = ref_now
                        job_row.last_error_code = "lease_expired"
                        job_row.last_error_detail = (
                            f"Orphaned lease (epoch={prior_epoch}) reclaimed for immediate"
                            " re-lease."
                        )
                        job_row.version += 1
                        job_row.updated_at = ref_now
                        await db.flush()
                        await append_audit_entry(
                            db,
                            workspace_id=job_row.workspace_id,
                            actor_type="system",
                            actor_id="lease_sweeper",
                            action="task_job.orphan_requeued",
                            target=f"task_job:{job_row.id}",
                            decision="allow",
                            reason_code="lease_expired",
                            correlation_id=job_row.correlation_id,
                            metadata={
                                "expired_lease_epoch": prior_epoch,
                                "orphaned_worker_id": prior_worker,
                                "next_attempt": job_row.attempt,
                                "logical_effect_key": job_row.logical_effect_key,
                                "budget_key": job_row.budget_key,
                            },
                            occurred_at=ref_now,
                        )
                        requeued_ids.append(job_row.id)
                        wakeup_targets.append((job_row.workspace_id, job_row.id))
                    else:
                        dlq_code = (
                            "lease_expired_reconcile_required"
                            if job_row.reconcile_required
                            else "lease_expired_exhausted"
                        )
                        dlq_detail = (
                            "Orphaned lease had ambiguous side effects requiring reconciliation."
                            if job_row.reconcile_required
                            else "Orphaned lease exceeded max_attempts or deadline; moved to DLQ."
                        )
                        job_row.state = "dead_letter"
                        job_row.leased_by_worker_id = None
                        job_row.lease_expires_at = None
                        job_row.last_error_code = dlq_code
                        job_row.last_error_detail = dlq_detail
                        job_row.version += 1
                        job_row.updated_at = ref_now

                        existing_open = await db.scalar(
                            select(DeadLetterJobModel)
                            .where(
                                DeadLetterJobModel.workspace_id == job_row.workspace_id,
                                DeadLetterJobModel.original_job_id == job_row.id,
                                DeadLetterJobModel.status == "open",
                            )
                            .with_for_update()
                        )
                        if existing_open is None:
                            db.add(
                                DeadLetterJobModel(
                                    id=new_uuid7(now=ref_now),
                                    workspace_id=job_row.workspace_id,
                                    repository_id=job_row.repository_id,
                                    original_job_id=job_row.id,
                                    kind=job_row.kind,
                                    resource_id=job_row.resource_id,
                                    logical_effect_key=job_row.logical_effect_key,
                                    budget_key=job_row.budget_key,
                                    error_code=dlq_code,
                                    error_detail=dlq_detail,
                                    attempts=job_row.attempt,
                                    recoverable=job_row.recoverable,
                                    reconcile_required=job_row.reconcile_required,
                                    status="open",
                                    requeued_at=None,
                                    requeued_by_user_id=None,
                                    version=1,
                                    created_at=ref_now,
                                    updated_at=ref_now,
                                )
                            )
                        else:
                            existing_open.error_code = dlq_code
                            existing_open.error_detail = dlq_detail
                            existing_open.attempts = job_row.attempt
                            existing_open.version += 1
                            existing_open.updated_at = ref_now

                        await db.flush()
                        await append_audit_entry(
                            db,
                            workspace_id=job_row.workspace_id,
                            actor_type="system",
                            actor_id="lease_sweeper",
                            action="task_job.orphan_dead_lettered",
                            target=f"task_job:{job_row.id}",
                            decision="allow",
                            reason_code=dlq_code,
                            correlation_id=job_row.correlation_id,
                            metadata={
                                "expired_lease_epoch": prior_epoch,
                                "orphaned_worker_id": prior_worker,
                                "attempts": job_row.attempt,
                            },
                            occurred_at=ref_now,
                        )
                        dead_lettered_ids.append(job_row.id)

        for ws_id, jid in wakeup_targets:
            self._transport.publish_wakeup(
                workspace_id=ws_id,
                job_id=jid,
                now=ref_now,
                force=True,
            )

        return SweepReport(
            requeued_job_ids=tuple(requeued_ids),
            dead_lettered_job_ids=tuple(dead_lettered_ids),
            cancelled_job_ids=tuple(cancelled_ids),
        )

    async def rebuild_transport_from_db(
        self,
        *,
        now: datetime,
        batch_size: int = 500,
    ) -> TransportRebuildReport:
        """Deterministically rebuild Redis wakeup hints from PostgreSQL `task_jobs` (`ADR-035`)."""
        ref_now = now.astimezone(UTC)
        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            rows = (
                await db.execute(
                    select(TaskJobModel.workspace_id, TaskJobModel.id)
                    .join(WorkspaceModel, WorkspaceModel.id == TaskJobModel.workspace_id)
                    .where(
                        TaskJobModel.state == "queued",
                        TaskJobModel.not_before <= ref_now,
                        WorkspaceModel.status == "active",
                        WorkspaceModel.paused.is_(False),
                        WorkspaceModel.deleted_at.is_(None),
                    )
                    .order_by(
                        TaskJobModel.priority.asc(),
                        TaskJobModel.created_at.asc(),
                        TaskJobModel.id.asc(),
                    )
                    .limit(max(1, batch_size))
                )
            ).all()

        published = 0
        for ws_id, job_id in rows:
            if self._transport.publish_wakeup(
                workspace_id=str(ws_id),
                job_id=str(job_id),
                now=ref_now,
            ):
                published += 1

        return TransportRebuildReport(
            eligible_jobs=len(rows),
            published_wakeups=published,
        )
