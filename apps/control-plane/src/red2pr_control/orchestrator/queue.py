"""Authoritative PostgreSQL durable task queue, fairness scheduler, and fencing (U08).

Implements `JOB-01`, `JOB-02`, `A-14`, `A-24`, `S-15`, `W-08`, `NFR-01`, `NFR-02`,
`NFR-05`, `SEC-015`, `SEC-020`, `SEC-021`, and `SEC-032`:
- Transactional job enqueue (`fsync=on` PostgreSQL commit prior to wakeup hint) with
  `Redactor` payload scrubbing and active `(workspace_id, dedup_key)` deduplication.
- Per-workspace running repair concurrency cap (`2` default) and deficit/watermark
  round-robin fairness (`last_dispatch_seq` watermark ordering + `FOR UPDATE SKIP LOCKED`)
  preventing noisy-tenant starvation (`NFR-05`).
- Monotonic `lease_epoch` (`15s` heartbeat target, `60s` lease TTL) rejecting stale or
  expired worker heartbeats/completions/failures with audited `409 stale_job_lease`
  (`SEC-021`, `NFR-02`: `0` stale writes).
- Scoped operator queue controls (`cancel`, `requeue`, `reconcile`) re-evaluating live
  workspace/repository grants, preserving original `logical_effect_key` and `budget_key`,
  and blocking blind replay when `reconcile_required` is set (`W-08`).
"""

from __future__ import annotations

import hashlib
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast

from pydantic import TypeAdapter, ValidationError
from sqlalchemy import Select, and_, func, or_, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.events import EventEnvelope, SecurityIdentityEventPayload
from py_contracts.iam import WorkspaceRole
from py_contracts.primitives import (
    ActionReceipt,
    ActionState,
    InternalId,
    Problem,
    new_uuid7,
)
from py_contracts.worker import (
    DeadLetterJobSummary,
    DeadLetterStatus,
    TaskAttemptState,
    TaskAttemptSummary,
    TaskJob,
    TaskJobActionRequest,
    TaskJobDetail,
    TaskJobPage,
    TaskJobState,
    WorkspaceQueueFairnessSummary,
)
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    BadRequestError,
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    NotFoundError,
)
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.base import (
    BreakGlassGrantModel,
    DeadLetterJobModel,
    EffectTombstoneModel,
    IdempotencyRecordModel,
    MembershipModel,
    OperationReceiptModel,
    RepoGrantModel,
    TaskAttemptModel,
    TaskJobModel,
    WorkspaceModel,
)
from red2pr_control.db.idempotency import (
    claim_idempotent_operation,
    complete_idempotent_operation,
    upsert_operation_receipt,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.rbac import (
    ROLE_PRIVILEGE_RANK,
    WorkspaceAccessContext,
    compute_query_filter_hash,
    decode_signed_cursor,
    encode_signed_cursor,
    enforce_optimistic_version,
)
from red2pr_control.iam.sessions import AuthenticatedContext
from red2pr_control.orchestrator.dramatiq_broker import (
    NullQueueTransport,
    QueueWakeupTransport,
)

DEFAULT_MAX_RUNNING_REPAIRS_PER_WORKSPACE = 2
DEFAULT_LEASE_TTL = timedelta(seconds=60)
DEFAULT_HEARTBEAT_INTERVAL = timedelta(seconds=15)
DEFAULT_JOB_DEADLINE = timedelta(minutes=30)
DEFAULT_BASE_BACKOFF_SECONDS = 5
DEFAULT_MAX_BACKOFF_SECONDS = 300
DEFAULT_TOMBSTONE_TTL = timedelta(days=90)

QUEUE_OPERATOR_ROLES: frozenset[WorkspaceRole] = frozenset({"admin", "maintainer"})
ACTIVE_DEDUP_STATES: tuple[str, ...] = ("queued", "leased", "running", "cancel_requested")
RUNNING_CAP_STATES: tuple[str, ...] = ("leased", "running")

_UUID_ADAPTER: TypeAdapter[str] = TypeAdapter(InternalId)


@dataclass(frozen=True)
class LeasedTaskJob:
    """Authoritative lease assignment returned to a worker dispatcher."""

    job: TaskJob
    payload: dict[str, Any]


@dataclass(frozen=True)
class HeartbeatOutcome:
    """Result of a worker `15s` lease heartbeat check."""

    job: TaskJob
    cancel_requested: bool


def _validate_uuid_or_404(raw_id: str, *, code: str, detail: str) -> str:
    try:
        return _UUID_ADAPTER.validate_python(raw_id.strip())
    except ValidationError as exc:
        raise NotFoundError(code=code, detail=detail) from exc


def _compute_jittered_backoff_seconds(*, job_id: str, attempt: int, base_seconds: int) -> float:
    exp = min(DEFAULT_MAX_BACKOFF_SECONDS, base_seconds * (2 ** max(0, attempt - 1)))
    digest = hashlib.sha256(f"{job_id}:{attempt}".encode()).digest()
    jitter_fraction = (int.from_bytes(digest[:2], "big") / 65535.0) * 0.25
    return float(exp) * (1.0 + jitter_fraction)


def to_task_job_dto(row: TaskJobModel) -> TaskJob:
    """Convert `TaskJobModel` ORM entity to canonical `S-15` `TaskJob` DTO."""
    return TaskJob(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        repair_id=row.repair_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        kind=row.kind,
        resource_id=row.resource_id,
        state=cast(TaskJobState, row.state),
        lease_epoch=row.lease_epoch,
        attempt=row.attempt,
        not_before=row.not_before,
        deadline=row.deadline,
        priority=row.priority,
        max_attempts=row.max_attempts,
        logical_effect_key=row.logical_effect_key,
        budget_key=row.budget_key,
        correlation_id=row.correlation_id,
        leased_by_worker_id=row.leased_by_worker_id,
        heartbeat_at=row.heartbeat_at,
        lease_expires_at=row.lease_expires_at,
        last_error_code=row.last_error_code,
        last_error_detail=row.last_error_detail,
        cancel_reason=row.cancel_reason,
        recoverable=row.recoverable,
        reconcile_required=row.reconcile_required,
    )


def to_task_attempt_dto(row: TaskAttemptModel) -> TaskAttemptSummary:
    """Convert `TaskAttemptModel` ORM entity to canonical `TaskAttemptSummary` DTO."""
    return TaskAttemptSummary(
        id=row.id,
        job_id=row.job_id,
        attempt_number=row.attempt_number,
        lease_epoch=row.lease_epoch,
        worker_id=row.worker_id,
        state=cast(TaskAttemptState, row.state),
        started_at=row.started_at,
        heartbeat_at=row.heartbeat_at,
        lease_expires_at=row.lease_expires_at,
        ended_at=row.ended_at,
        error_code=row.error_code,
        error_detail=row.error_detail,
    )


def to_dead_letter_dto(row: DeadLetterJobModel) -> DeadLetterJobSummary:
    """Convert `DeadLetterJobModel` ORM entity to canonical `DeadLetterJobSummary` DTO."""
    return DeadLetterJobSummary(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        original_job_id=row.original_job_id,
        kind=row.kind,
        resource_id=row.resource_id,
        logical_effect_key=row.logical_effect_key,
        budget_key=row.budget_key,
        error_code=row.error_code,
        error_detail=row.error_detail,
        attempts=row.attempts,
        recoverable=row.recoverable,
        reconcile_required=row.reconcile_required,
        status=cast(DeadLetterStatus, row.status),
        requeued_at=row.requeued_at,
        requeued_by_user_id=row.requeued_by_user_id,
    )


def _job_effect_operation_name(kind: str) -> str:
    return f"task_job.execute:{kind}"


class DurableTaskQueueService:
    """PostgreSQL-backed durable scheduler, lease fence, and operator queue service."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        signing_key: bytes,
        transport: QueueWakeupTransport | None = None,
        redactor: Redactor | None = None,
        max_running_repairs_per_workspace: int = DEFAULT_MAX_RUNNING_REPAIRS_PER_WORKSPACE,
        lease_ttl: timedelta = DEFAULT_LEASE_TTL,
        base_backoff_seconds: int = DEFAULT_BASE_BACKOFF_SECONDS,
    ) -> None:
        if max_running_repairs_per_workspace < 1:
            raise ValueError("max_running_repairs_per_workspace must be >= 1")
        self._session_factory = session_factory
        self._signing_key = signing_key
        self._transport: QueueWakeupTransport = transport or NullQueueTransport()
        self._redactor = redactor or Redactor()
        self._max_running_repairs = max_running_repairs_per_workspace
        self._lease_ttl = lease_ttl
        self._base_backoff_seconds = max(1, base_backoff_seconds)
        self._storage_admission_paused = False

    def set_storage_admission_paused(self, paused: bool) -> None:
        """Stop only new repair/sandbox jobs while preserving active proof and cleanup work."""
        self._storage_admission_paused = bool(paused)

    @property
    def max_running_repairs_per_workspace(self) -> int:
        return self._max_running_repairs

    @property
    def lease_ttl(self) -> timedelta:
        return self._lease_ttl

    @property
    def transport(self) -> QueueWakeupTransport:
        return self._transport

    async def enqueue_job(
        self,
        *,
        workspace_id: str,
        kind: str,
        resource_id: str,
        correlation_id: str,
        now: datetime,
        repository_id: str | None = None,
        repair_id: str | None = None,
        is_repair_job: bool | None = None,
        priority: int = 100,
        max_attempts: int = 3,
        dedup_key: str | None = None,
        logical_effect_key: str | None = None,
        budget_key: str | None = None,
        payload: Mapping[str, Any] | None = None,
        not_before: datetime | None = None,
        deadline: datetime | None = None,
        recoverable: bool = True,
        actor_type: Literal["system", "user", "service"] = "system",
        actor_id: str = "orchestrator",
        client_ip: str | None = None,
    ) -> TaskJob:
        """Persist a durable task job in PostgreSQL BEFORE emitting a Redis wakeup hint."""
        ref_now = now.astimezone(UTC)
        eff_not_before = not_before.astimezone(UTC) if not_before is not None else ref_now
        eff_deadline = (
            deadline.astimezone(UTC)
            if deadline is not None
            else eff_not_before + DEFAULT_JOB_DEADLINE
        )
        if eff_deadline < eff_not_before:
            raise BadRequestError(
                code="invalid_job_deadline",
                detail="Task job deadline must not precede not_before.",
            )
        if not (0 <= priority <= 1000) or max_attempts < 1:
            raise BadRequestError(
                code="invalid_job_bounds",
                detail="Task job priority must be within 0..1000 and max_attempts >= 1.",
            )

        clean_kind = kind.strip()
        if not clean_kind or len(clean_kind) > 120:
            raise BadRequestError(
                code="invalid_job_kind",
                detail="Task job kind must be 1..120 characters.",
            )

        repair_flag = (
            is_repair_job
            if is_repair_job is not None
            else (repair_id is not None or clean_kind.startswith("repair."))
        )
        if repair_flag and self._storage_admission_paused:
            raise DependencyUnavailableError(
                code="storage_capacity_exceeded",
                detail="New repair admission is paused at the storage safety watermark.",
            )
        scrubbed_payload = cast(dict[str, Any], self._redactor.redact_value(dict(payload or {})))
        effect_op = _job_effect_operation_name(clean_kind)

        should_wakeup = False
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            ws_row = await db.scalar(
                select(WorkspaceModel).where(WorkspaceModel.id == workspace_id)
            )
            if ws_row is None or ws_row.status != "active" or ws_row.deleted_at is not None:
                raise ConflictError(
                    code="workspace_not_active",
                    detail="Cannot enqueue task jobs into an inactive or deleting workspace.",
                )

            if dedup_key is not None:
                existing_active = await db.scalar(
                    select(TaskJobModel).where(
                        TaskJobModel.workspace_id == workspace_id,
                        TaskJobModel.dedup_key == dedup_key,
                        TaskJobModel.state.in_(ACTIVE_DEDUP_STATES),
                    )
                )
                if existing_active is not None:
                    return to_task_job_dto(existing_active)

            job_id = new_uuid7(now=ref_now)
            eff_logical_key = logical_effect_key or f"{clean_kind}:{resource_id}:{job_id}"

            prior_effect = await db.scalar(
                select(EffectTombstoneModel.id).where(
                    EffectTombstoneModel.workspace_id == workspace_id,
                    EffectTombstoneModel.operation == effect_op,
                    EffectTombstoneModel.logical_effect_key == eff_logical_key,
                    EffectTombstoneModel.retained_until > ref_now,
                )
            )
            if prior_effect is not None:
                raise ConflictError(
                    code="duplicate_logical_effect",
                    detail=(
                        f"Logical effect {eff_logical_key!r} for {clean_kind!r} has already "
                        "completed within tombstone retention."
                    ),
                )

            row = TaskJobModel(
                id=job_id,
                workspace_id=workspace_id,
                repository_id=repository_id,
                repair_id=repair_id,
                kind=clean_kind,
                is_repair_job=repair_flag,
                resource_id=resource_id,
                state="queued",
                priority=priority,
                dedup_key=dedup_key,
                logical_effect_key=eff_logical_key,
                budget_key=budget_key,
                correlation_id=correlation_id[:120],
                payload_json=scrubbed_payload,
                attempt=1,
                max_attempts=max_attempts,
                lease_epoch=0,
                last_dispatch_seq=None,
                leased_by_worker_id=None,
                heartbeat_at=None,
                lease_expires_at=None,
                not_before=eff_not_before,
                deadline=eff_deadline,
                last_error_code=None,
                last_error_detail=None,
                cancel_reason=None,
                cancelled_by_user_id=None,
                recoverable=recoverable,
                reconcile_required=False,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(row)
            await db.flush()

            await append_audit_entry(
                db,
                workspace_id=workspace_id,
                actor_type=actor_type,
                actor_id=actor_id,
                action="task_job.enqueued",
                target=f"task_job:{row.id}",
                decision="allow",
                reason_code="durable_enqueue",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={
                    "kind": clean_kind,
                    "resource_id": resource_id,
                    "logical_effect_key": eff_logical_key,
                    "budget_key": budget_key,
                    "priority": priority,
                },
                occurred_at=ref_now,
            )
            dto = to_task_job_dto(row)
            should_wakeup = (not ws_row.paused) and (eff_not_before <= ref_now)

        # Wakeup transport emitted strictly AFTER durable PostgreSQL commit (NFR-01).
        if should_wakeup:
            self._transport.publish_wakeup(
                workspace_id=workspace_id,
                job_id=dto.id,
                now=ref_now,
            )
        return dto

    async def acquire_next_lease(
        self,
        *,
        worker_id: str,
        now: datetime,
        lease_ttl: timedelta | None = None,
        allowed_kinds: Collection[str] | None = None,
    ) -> LeasedTaskJob | None:
        """Select and lease the next eligible job using deficit watermark fairness (`NFR-05`)."""
        ref_now = now.astimezone(UTC)
        eff_ttl = lease_ttl if lease_ttl is not None else self._lease_ttl
        clean_worker_id = _validate_uuid_or_404(
            worker_id,
            code="invalid_worker_id",
            detail="Worker identifier must be a valid UUID.",
        )

        # Phase 1: Discover candidate workspaces ordered by lowest `last_dispatch_seq` watermark.
        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            cand_stmt = (
                select(
                    TaskJobModel.workspace_id,
                    func.min(TaskJobModel.created_at).label("min_ready_at"),
                )
                .join(WorkspaceModel, WorkspaceModel.id == TaskJobModel.workspace_id)
                .where(
                    TaskJobModel.state == "queued",
                    TaskJobModel.not_before <= ref_now,
                    WorkspaceModel.status == "active",
                    WorkspaceModel.paused.is_(False),
                    WorkspaceModel.deleted_at.is_(None),
                )
                .group_by(TaskJobModel.workspace_id)
            )
            if allowed_kinds is not None:
                kind_list = sorted({k.strip() for k in allowed_kinds if k.strip()})
                if not kind_list:
                    return None
                cand_stmt = cand_stmt.where(TaskJobModel.kind.in_(kind_list))
            else:
                kind_list = []

            cand_rows = (await db.execute(cand_stmt)).all()
            if not cand_rows:
                return None

            cand_ws_ids = [str(r[0]) for r in cand_rows]
            min_ready_by_ws: dict[str, datetime] = {str(r[0]): r[1] for r in cand_rows}

            wm_rows = (
                await db.execute(
                    select(
                        TaskJobModel.workspace_id,
                        func.coalesce(func.max(TaskJobModel.last_dispatch_seq), 0),
                    )
                    .where(TaskJobModel.workspace_id.in_(cand_ws_ids))
                    .group_by(TaskJobModel.workspace_id)
                )
            ).all()
            watermark_by_ws: dict[str, int] = {str(r[0]): int(r[1]) for r in wm_rows}

        ordered_workspaces = sorted(
            cand_ws_ids,
            key=lambda wid: (
                watermark_by_ws.get(wid, 0),
                min_ready_by_ws[wid],
                wid,
            ),
        )

        # Phase 2: Attempt fair per-workspace lease under workspace advisory cap serialization.
        for ws_id in ordered_workspaces:
            leased = await self._try_lease_from_workspace(
                workspace_id=ws_id,
                worker_id=clean_worker_id,
                ref_now=ref_now,
                lease_ttl=eff_ttl,
                kind_filter=kind_list,
            )
            if leased is not None:
                return leased

        return None

    async def _try_lease_from_workspace(
        self,
        *,
        workspace_id: str,
        worker_id: str,
        ref_now: datetime,
        lease_ttl: timedelta,
        kind_filter: list[str],
    ) -> LeasedTaskJob | None:
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            await db.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
                {"lock_key": f"red2pr:queue_sched:{workspace_id}"},
            )

            ws_row = await db.scalar(
                select(WorkspaceModel).where(WorkspaceModel.id == workspace_id)
            )
            if (
                ws_row is None
                or ws_row.status != "active"
                or ws_row.paused
                or ws_row.deleted_at is not None
            ):
                return None

            while True:
                active_repairs = int(
                    (
                        await db.scalar(
                            select(func.count())
                            .select_from(TaskJobModel)
                            .where(
                                TaskJobModel.workspace_id == workspace_id,
                                TaskJobModel.is_repair_job.is_(True),
                                TaskJobModel.state.in_(RUNNING_CAP_STATES),
                            )
                        )
                    )
                    or 0
                )

                job_stmt = select(TaskJobModel).where(
                    TaskJobModel.workspace_id == workspace_id,
                    TaskJobModel.state == "queued",
                    TaskJobModel.not_before <= ref_now,
                )
                if active_repairs >= self._max_running_repairs:
                    job_stmt = job_stmt.where(TaskJobModel.is_repair_job.is_(False))
                if kind_filter:
                    job_stmt = job_stmt.where(TaskJobModel.kind.in_(kind_filter))

                job_stmt = (
                    job_stmt.order_by(
                        TaskJobModel.priority.asc(),
                        TaskJobModel.created_at.asc(),
                        TaskJobModel.id.asc(),
                    )
                    .with_for_update(skip_locked=True)
                    .limit(1)
                )

                job_row = await db.scalar(job_stmt)
                if job_row is None:
                    return None

                if job_row.deadline < ref_now:
                    await self._transition_job_to_dlq_in_tx(
                        db,
                        job_row=job_row,
                        error_code="job_deadline_exceeded",
                        error_detail=(
                            "Task job exceeded its configured deadline prior to execution."
                        ),
                        recoverable=True,
                        reconcile_required=False,
                        actor_type="system",
                        actor_id="scheduler",
                        reason_code="job_deadline_exceeded",
                        ref_now=ref_now,
                    )
                    continue

                dispatch_seq = int(
                    (
                        await db.execute(text("SELECT nextval('public.seq_task_job_dispatch')"))
                    ).scalar_one()
                )
                next_epoch = job_row.lease_epoch + 1
                expires_at = ref_now + lease_ttl

                job_row.state = "leased"
                job_row.lease_epoch = next_epoch
                job_row.last_dispatch_seq = dispatch_seq
                job_row.leased_by_worker_id = worker_id
                job_row.heartbeat_at = ref_now
                job_row.lease_expires_at = expires_at
                job_row.version += 1
                job_row.updated_at = ref_now

                attempt_row = TaskAttemptModel(
                    id=new_uuid7(now=ref_now),
                    workspace_id=workspace_id,
                    job_id=job_row.id,
                    attempt_number=job_row.attempt,
                    lease_epoch=next_epoch,
                    worker_id=worker_id,
                    state="leased",
                    started_at=ref_now,
                    heartbeat_at=ref_now,
                    lease_expires_at=expires_at,
                    ended_at=None,
                    error_code=None,
                    error_detail=None,
                    created_at=ref_now,
                )
                db.add(attempt_row)
                await db.flush()

                await append_audit_entry(
                    db,
                    workspace_id=workspace_id,
                    actor_type="service",
                    actor_id=f"worker:{worker_id}",
                    action="task_job.leased",
                    target=f"task_job:{job_row.id}",
                    decision="allow",
                    reason_code="fair_lease_acquired",
                    correlation_id=job_row.correlation_id,
                    metadata={
                        "lease_epoch": next_epoch,
                        "attempt": job_row.attempt,
                        "dispatch_seq": dispatch_seq,
                        "lease_expires_at": expires_at.isoformat().replace("+00:00", "Z"),
                    },
                    occurred_at=ref_now,
                )
                return LeasedTaskJob(
                    job=to_task_job_dto(job_row),
                    payload=dict(job_row.payload_json),
                )

    async def _load_job_workspace_id_or_404(self, job_id: str) -> str:
        clean_id = _validate_uuid_or_404(
            job_id,
            code="task_job_not_found",
            detail="Task job not found.",
        )
        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            ws_id = await db.scalar(
                select(TaskJobModel.workspace_id).where(TaskJobModel.id == clean_id)
            )
        if ws_id is None:
            raise NotFoundError(code="task_job_not_found", detail="Task job not found.")
        return str(ws_id)

    async def _record_stale_fence_violation_in_tx(
        self,
        db: AsyncSession,
        *,
        job_row: TaskJobModel,
        worker_id: str,
        submitted_epoch: int,
        action: str,
        ref_now: datetime,
    ) -> ConflictError:
        await append_audit_entry(
            db,
            workspace_id=job_row.workspace_id,
            actor_type="service",
            actor_id=f"worker:{worker_id}",
            action=action,
            target=f"task_job:{job_row.id}",
            decision="deny",
            reason_code="stale_job_lease",
            correlation_id=job_row.correlation_id,
            metadata={
                "submitted_lease_epoch": submitted_epoch,
                "current_lease_epoch": job_row.lease_epoch,
                "submitted_worker_id": worker_id,
                "current_worker_id": job_row.leased_by_worker_id,
                "current_state": job_row.state,
            },
            occurred_at=ref_now,
        )
        await enqueue_outbox_event(
            db,
            EventEnvelope(
                event_id=new_uuid7(now=ref_now),
                type="security.policy.denied",
                occurred_at=ref_now,
                workspace_id=job_row.workspace_id,
                repository_id=job_row.repository_id,
                aggregate_id=job_row.id,
                aggregate_version=job_row.version,
                correlation_id=job_row.correlation_id,
                payload=SecurityIdentityEventPayload(
                    target_id=job_row.id,
                    reason_code="stale_job_lease",
                ),
            ),
            now=ref_now,
        )
        return ConflictError(
            code="stale_job_lease",
            detail=(
                f"Worker lease_epoch {submitted_epoch} is stale or expired for job {job_row.id} "
                f"(current epoch={job_row.lease_epoch}, state={job_row.state})."
            ),
        )

    def _is_lease_fence_valid(
        self,
        job_row: TaskJobModel,
        *,
        worker_id: str,
        lease_epoch: int,
        allowed_states: Collection[str],
        ref_now: datetime,
    ) -> bool:
        return (
            job_row.lease_epoch == lease_epoch
            and job_row.leased_by_worker_id == worker_id
            and job_row.state in allowed_states
            and job_row.lease_expires_at is not None
            and job_row.lease_expires_at > ref_now
        )

    async def mark_lease_running(
        self,
        *,
        job_id: str,
        worker_id: str,
        lease_epoch: int,
        now: datetime,
        lease_ttl: timedelta | None = None,
    ) -> TaskJob:
        """Transition a fenced worker lease from `leased` to `running` (`SEC-021`)."""
        ref_now = now.astimezone(UTC)
        eff_ttl = lease_ttl if lease_ttl is not None else self._lease_ttl
        ws_id = await self._load_job_workspace_id_or_404(job_id)

        fence_err: ConflictError | None = None
        result_dto: TaskJob | None = None
        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            job_row = await db.scalar(
                select(TaskJobModel).where(TaskJobModel.id == job_id).with_for_update()
            )
            if job_row is None:
                raise NotFoundError(code="task_job_not_found", detail="Task job not found.")

            if not self._is_lease_fence_valid(
                job_row,
                worker_id=worker_id,
                lease_epoch=lease_epoch,
                allowed_states={"leased", "running", "cancel_requested"},
                ref_now=ref_now,
            ):
                fence_err = await self._record_stale_fence_violation_in_tx(
                    db,
                    job_row=job_row,
                    worker_id=worker_id,
                    submitted_epoch=lease_epoch,
                    action="task_job.mark_running",
                    ref_now=ref_now,
                )
            elif job_row.state == "cancel_requested":
                result_dto = to_task_job_dto(job_row)
            else:
                expires_at = ref_now + eff_ttl
                job_row.state = "running"
                job_row.heartbeat_at = ref_now
                job_row.lease_expires_at = expires_at
                job_row.version += 1
                job_row.updated_at = ref_now

                attempt_row = await db.scalar(
                    select(TaskAttemptModel)
                    .where(
                        TaskAttemptModel.job_id == job_row.id,
                        TaskAttemptModel.lease_epoch == lease_epoch,
                    )
                    .with_for_update()
                )
                if attempt_row is not None:
                    attempt_row.state = "running"
                    attempt_row.heartbeat_at = ref_now
                    attempt_row.lease_expires_at = expires_at
                await db.flush()
                result_dto = to_task_job_dto(job_row)

        if fence_err is not None:
            raise fence_err
        assert result_dto is not None
        return result_dto

    async def heartbeat_lease(
        self,
        *,
        job_id: str,
        worker_id: str,
        lease_epoch: int,
        now: datetime,
        lease_ttl: timedelta | None = None,
    ) -> HeartbeatOutcome:
        """Extend an active worker lease (`15s` cadence, `60s` TTL) or signal cancellation."""
        ref_now = now.astimezone(UTC)
        eff_ttl = lease_ttl if lease_ttl is not None else self._lease_ttl
        ws_id = await self._load_job_workspace_id_or_404(job_id)

        fence_err: ConflictError | None = None
        outcome: HeartbeatOutcome | None = None
        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            job_row = await db.scalar(
                select(TaskJobModel).where(TaskJobModel.id == job_id).with_for_update()
            )
            if job_row is None:
                raise NotFoundError(code="task_job_not_found", detail="Task job not found.")

            if not self._is_lease_fence_valid(
                job_row,
                worker_id=worker_id,
                lease_epoch=lease_epoch,
                allowed_states={"leased", "running", "cancel_requested"},
                ref_now=ref_now,
            ):
                fence_err = await self._record_stale_fence_violation_in_tx(
                    db,
                    job_row=job_row,
                    worker_id=worker_id,
                    submitted_epoch=lease_epoch,
                    action="task_job.heartbeat",
                    ref_now=ref_now,
                )
            elif job_row.state == "cancel_requested":
                outcome = HeartbeatOutcome(
                    job=to_task_job_dto(job_row),
                    cancel_requested=True,
                )
            else:
                expires_at = ref_now + eff_ttl
                job_row.heartbeat_at = ref_now
                job_row.lease_expires_at = expires_at
                job_row.updated_at = ref_now

                attempt_row = await db.scalar(
                    select(TaskAttemptModel)
                    .where(
                        TaskAttemptModel.job_id == job_row.id,
                        TaskAttemptModel.lease_epoch == lease_epoch,
                    )
                    .with_for_update()
                )
                if attempt_row is not None:
                    attempt_row.heartbeat_at = ref_now
                    attempt_row.lease_expires_at = expires_at
                await db.flush()
                outcome = HeartbeatOutcome(
                    job=to_task_job_dto(job_row),
                    cancel_requested=False,
                )

        if fence_err is not None:
            raise fence_err
        assert outcome is not None
        return outcome

    async def complete_lease(
        self,
        *,
        job_id: str,
        worker_id: str,
        lease_epoch: int,
        now: datetime,
    ) -> TaskJob:
        """Complete a fenced worker lease and seal its `EffectTombstoneModel` (`SEC-021`)."""
        ref_now = now.astimezone(UTC)
        ws_id = await self._load_job_workspace_id_or_404(job_id)

        fence_err: ConflictError | None = None
        result_dto: TaskJob | None = None
        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            job_row = await db.scalar(
                select(TaskJobModel).where(TaskJobModel.id == job_id).with_for_update()
            )
            if job_row is None:
                raise NotFoundError(code="task_job_not_found", detail="Task job not found.")

            if not self._is_lease_fence_valid(
                job_row,
                worker_id=worker_id,
                lease_epoch=lease_epoch,
                allowed_states={"leased", "running", "cancel_requested"},
                ref_now=ref_now,
            ):
                fence_err = await self._record_stale_fence_violation_in_tx(
                    db,
                    job_row=job_row,
                    worker_id=worker_id,
                    submitted_epoch=lease_epoch,
                    action="task_job.complete",
                    ref_now=ref_now,
                )
            elif job_row.state == "cancel_requested":
                fence_err = ConflictError(
                    code="job_cancel_requested",
                    detail="Task job cancellation was requested; worker must acknowledge cancel.",
                )
            else:
                effect_op = _job_effect_operation_name(job_row.kind)
                tombstone_stmt = (
                    pg_insert(EffectTombstoneModel)
                    .values(
                        id=new_uuid7(now=ref_now),
                        workspace_id=ws_id,
                        logical_effect_key=job_row.logical_effect_key,
                        operation=effect_op,
                        origin_operation_id=job_row.id,
                        idempotency_key=job_row.id,
                        request_hash=hashlib.sha256(
                            f"{job_row.id}:{lease_epoch}".encode()
                        ).hexdigest(),
                        resource_id=job_row.resource_id,
                        retained_until=ref_now + DEFAULT_TOMBSTONE_TTL,
                        created_at=ref_now,
                    )
                    .on_conflict_do_nothing(constraint="uq_effect_tombstones_logical_effect")
                    .returning(EffectTombstoneModel.id)
                )
                inserted_tomb = await db.scalar(tombstone_stmt)
                if inserted_tomb is None:
                    fence_err = ConflictError(
                        code="duplicate_logical_effect",
                        detail=(
                            f"Logical effect {job_row.logical_effect_key!r} was already completed."
                        ),
                    )
                else:
                    job_row.state = "succeeded"
                    job_row.leased_by_worker_id = None
                    job_row.lease_expires_at = None
                    job_row.reconcile_required = False
                    job_row.version += 1
                    job_row.updated_at = ref_now

                    attempt_row = await db.scalar(
                        select(TaskAttemptModel)
                        .where(
                            TaskAttemptModel.job_id == job_row.id,
                            TaskAttemptModel.lease_epoch == lease_epoch,
                        )
                        .with_for_update()
                    )
                    if attempt_row is not None:
                        attempt_row.state = "succeeded"
                        attempt_row.ended_at = ref_now
                    await db.flush()

                    await append_audit_entry(
                        db,
                        workspace_id=ws_id,
                        actor_type="service",
                        actor_id=f"worker:{worker_id}",
                        action="task_job.succeeded",
                        target=f"task_job:{job_row.id}",
                        decision="allow",
                        reason_code="lease_completed",
                        correlation_id=job_row.correlation_id,
                        metadata={
                            "lease_epoch": lease_epoch,
                            "attempt": job_row.attempt,
                            "logical_effect_key": job_row.logical_effect_key,
                        },
                        occurred_at=ref_now,
                    )
                    result_dto = to_task_job_dto(job_row)

        if fence_err is not None:
            raise fence_err
        assert result_dto is not None
        return result_dto

    async def acknowledge_cancel(
        self,
        *,
        job_id: str,
        worker_id: str,
        lease_epoch: int,
        now: datetime,
    ) -> TaskJob:
        """Finalize cooperative worker teardown for a `cancel_requested` job."""
        ref_now = now.astimezone(UTC)
        ws_id = await self._load_job_workspace_id_or_404(job_id)

        fence_err: ConflictError | None = None
        result_dto: TaskJob | None = None
        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            job_row = await db.scalar(
                select(TaskJobModel).where(TaskJobModel.id == job_id).with_for_update()
            )
            if job_row is None:
                raise NotFoundError(code="task_job_not_found", detail="Task job not found.")

            if not self._is_lease_fence_valid(
                job_row,
                worker_id=worker_id,
                lease_epoch=lease_epoch,
                allowed_states={"cancel_requested"},
                ref_now=ref_now,
            ):
                fence_err = await self._record_stale_fence_violation_in_tx(
                    db,
                    job_row=job_row,
                    worker_id=worker_id,
                    submitted_epoch=lease_epoch,
                    action="task_job.acknowledge_cancel",
                    ref_now=ref_now,
                )
            else:
                job_row.state = "cancelled"
                job_row.leased_by_worker_id = None
                job_row.lease_expires_at = None
                job_row.version += 1
                job_row.updated_at = ref_now

                attempt_row = await db.scalar(
                    select(TaskAttemptModel)
                    .where(
                        TaskAttemptModel.job_id == job_row.id,
                        TaskAttemptModel.lease_epoch == lease_epoch,
                    )
                    .with_for_update()
                )
                if attempt_row is not None:
                    attempt_row.state = "cancelled"
                    attempt_row.ended_at = ref_now
                await db.flush()

                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    actor_type="service",
                    actor_id=f"worker:{worker_id}",
                    action="task_job.cancelled",
                    target=f"task_job:{job_row.id}",
                    decision="allow",
                    reason_code="worker_acknowledged_cancel",
                    correlation_id=job_row.correlation_id,
                    metadata={"lease_epoch": lease_epoch, "attempt": job_row.attempt},
                    occurred_at=ref_now,
                )
                result_dto = to_task_job_dto(job_row)

        if fence_err is not None:
            raise fence_err
        assert result_dto is not None
        return result_dto

    async def _transition_job_to_dlq_in_tx(
        self,
        db: AsyncSession,
        *,
        job_row: TaskJobModel,
        error_code: str,
        error_detail: str,
        recoverable: bool,
        reconcile_required: bool,
        actor_type: Literal["system", "user", "service"],
        actor_id: str,
        reason_code: str,
        ref_now: datetime,
    ) -> DeadLetterJobModel:
        safe_code = error_code.strip()[:120] or "job_failed"
        safe_detail = self._redactor.redact_text(error_detail)[:4096] or "Job failed."

        job_row.state = "dead_letter"
        job_row.leased_by_worker_id = None
        job_row.lease_expires_at = None
        job_row.last_error_code = safe_code
        job_row.last_error_detail = safe_detail
        job_row.recoverable = recoverable
        job_row.reconcile_required = reconcile_required
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
            dlq_row = DeadLetterJobModel(
                id=new_uuid7(now=ref_now),
                workspace_id=job_row.workspace_id,
                repository_id=job_row.repository_id,
                original_job_id=job_row.id,
                kind=job_row.kind,
                resource_id=job_row.resource_id,
                logical_effect_key=job_row.logical_effect_key,
                budget_key=job_row.budget_key,
                error_code=safe_code,
                error_detail=safe_detail,
                attempts=job_row.attempt,
                recoverable=recoverable,
                reconcile_required=reconcile_required,
                status="open",
                requeued_at=None,
                requeued_by_user_id=None,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(dlq_row)
        else:
            existing_open.error_code = safe_code
            existing_open.error_detail = safe_detail
            existing_open.attempts = job_row.attempt
            existing_open.recoverable = recoverable
            existing_open.reconcile_required = reconcile_required
            existing_open.version += 1
            existing_open.updated_at = ref_now
            dlq_row = existing_open

        await db.flush()
        await append_audit_entry(
            db,
            workspace_id=job_row.workspace_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action="task_job.dead_lettered",
            target=f"task_job:{job_row.id}",
            decision="allow",
            reason_code=reason_code,
            correlation_id=job_row.correlation_id,
            metadata={
                "dlq_id": dlq_row.id,
                "error_code": safe_code,
                "attempts": job_row.attempt,
                "recoverable": recoverable,
                "reconcile_required": reconcile_required,
                "logical_effect_key": job_row.logical_effect_key,
                "budget_key": job_row.budget_key,
            },
            occurred_at=ref_now,
        )
        return dlq_row

    async def fail_lease(
        self,
        *,
        job_id: str,
        worker_id: str,
        lease_epoch: int,
        error_code: str,
        error_detail: str,
        now: datetime,
        recoverable: bool = True,
        reconcile_required: bool = False,
    ) -> TaskJob:
        """Record fenced worker failure, scheduling jittered retry or DLQ (`JOB-02`)."""
        ref_now = now.astimezone(UTC)
        ws_id = await self._load_job_workspace_id_or_404(job_id)
        safe_code = error_code.strip()[:120] or "worker_execution_failed"
        safe_detail = self._redactor.redact_text(error_detail)[:4096] or "Execution failed."

        fence_err: ConflictError | None = None
        result_dto: TaskJob | None = None
        wakeup_ready = False

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            job_row = await db.scalar(
                select(TaskJobModel).where(TaskJobModel.id == job_id).with_for_update()
            )
            if job_row is None:
                raise NotFoundError(code="task_job_not_found", detail="Task job not found.")

            if not self._is_lease_fence_valid(
                job_row,
                worker_id=worker_id,
                lease_epoch=lease_epoch,
                allowed_states={"leased", "running", "cancel_requested"},
                ref_now=ref_now,
            ):
                fence_err = await self._record_stale_fence_violation_in_tx(
                    db,
                    job_row=job_row,
                    worker_id=worker_id,
                    submitted_epoch=lease_epoch,
                    action="task_job.fail",
                    ref_now=ref_now,
                )
            else:
                attempt_row = await db.scalar(
                    select(TaskAttemptModel)
                    .where(
                        TaskAttemptModel.job_id == job_row.id,
                        TaskAttemptModel.lease_epoch == lease_epoch,
                    )
                    .with_for_update()
                )
                if attempt_row is not None:
                    attempt_row.state = (
                        "cancelled" if job_row.state == "cancel_requested" else "failed"
                    )
                    attempt_row.ended_at = ref_now
                    attempt_row.error_code = safe_code
                    attempt_row.error_detail = safe_detail

                if job_row.state == "cancel_requested":
                    job_row.state = "cancelled"
                    job_row.leased_by_worker_id = None
                    job_row.lease_expires_at = None
                    job_row.last_error_code = safe_code
                    job_row.last_error_detail = safe_detail
                    job_row.version += 1
                    job_row.updated_at = ref_now
                    await db.flush()
                    await append_audit_entry(
                        db,
                        workspace_id=ws_id,
                        actor_type="service",
                        actor_id=f"worker:{worker_id}",
                        action="task_job.cancelled",
                        target=f"task_job:{job_row.id}",
                        decision="allow",
                        reason_code="cancelled_on_failure",
                        correlation_id=job_row.correlation_id,
                        occurred_at=ref_now,
                    )
                    result_dto = to_task_job_dto(job_row)
                elif (
                    recoverable
                    and not reconcile_required
                    and job_row.attempt < job_row.max_attempts
                    and ref_now < job_row.deadline
                ):
                    backoff_sec = _compute_jittered_backoff_seconds(
                        job_id=job_row.id,
                        attempt=job_row.attempt,
                        base_seconds=self._base_backoff_seconds,
                    )
                    next_not_before = min(
                        job_row.deadline,
                        ref_now + timedelta(seconds=backoff_sec),
                    )
                    job_row.attempt += 1
                    job_row.state = "queued"
                    job_row.leased_by_worker_id = None
                    job_row.lease_expires_at = None
                    job_row.not_before = next_not_before
                    job_row.last_error_code = safe_code
                    job_row.last_error_detail = safe_detail
                    job_row.version += 1
                    job_row.updated_at = ref_now
                    await db.flush()
                    await append_audit_entry(
                        db,
                        workspace_id=ws_id,
                        actor_type="service",
                        actor_id=f"worker:{worker_id}",
                        action="task_job.retry_scheduled",
                        target=f"task_job:{job_row.id}",
                        decision="allow",
                        reason_code=safe_code,
                        correlation_id=job_row.correlation_id,
                        metadata={
                            "next_attempt": job_row.attempt,
                            "not_before": next_not_before.isoformat().replace("+00:00", "Z"),
                            "logical_effect_key": job_row.logical_effect_key,
                            "budget_key": job_row.budget_key,
                        },
                        occurred_at=ref_now,
                    )
                    result_dto = to_task_job_dto(job_row)
                    wakeup_ready = next_not_before <= ref_now
                else:
                    dlq_reason = (
                        "reconcile_required"
                        if reconcile_required
                        else ("unrecoverable_failure" if not recoverable else "attempts_exhausted")
                    )
                    await self._transition_job_to_dlq_in_tx(
                        db,
                        job_row=job_row,
                        error_code=safe_code,
                        error_detail=safe_detail,
                        recoverable=recoverable,
                        reconcile_required=reconcile_required,
                        actor_type="service",
                        actor_id=f"worker:{worker_id}",
                        reason_code=dlq_reason,
                        ref_now=ref_now,
                    )
                    result_dto = to_task_job_dto(job_row)

        if fence_err is not None:
            raise fence_err
        assert result_dto is not None
        if wakeup_ready:
            self._transport.publish_wakeup(
                workspace_id=ws_id,
                job_id=result_dto.id,
                now=ref_now,
                force=True,
            )
        return result_dto

    def _apply_repo_read_scope(
        self,
        stmt: Select[Any],
        ws_ctx: WorkspaceAccessContext,
    ) -> Select[Any]:
        if ws_ctx.has_workspace_wide_repo_read:
            return stmt
        if not ws_ctx.repository_grants:
            return stmt.where(TaskJobModel.repository_id.is_(None))
        return stmt.where(
            or_(
                TaskJobModel.repository_id.is_(None),
                TaskJobModel.repository_id.in_(sorted(ws_ctx.repository_grants)),
            )
        )

    async def _compute_fairness_summary_in_tx(
        self,
        db: AsyncSession,
        *,
        ws_ctx: WorkspaceAccessContext,
        repository_id_filter: str | None,
    ) -> WorkspaceQueueFairnessSummary:
        base_stmt = select(
            TaskJobModel.state,
            TaskJobModel.is_repair_job,
            func.count().label("cnt"),
        ).where(TaskJobModel.workspace_id == ws_ctx.workspace_id)
        base_stmt = self._apply_repo_read_scope(base_stmt, ws_ctx)
        if repository_id_filter is not None:
            base_stmt = base_stmt.where(TaskJobModel.repository_id == repository_id_filter)
        base_stmt = base_stmt.group_by(TaskJobModel.state, TaskJobModel.is_repair_job)

        rows = (await db.execute(base_stmt)).all()
        counts_by_state: dict[str, int] = {}
        active_running_repairs = 0
        for st_val, is_rep, cnt_val in rows:
            st_str = str(st_val)
            cnt_int = int(cnt_val)
            counts_by_state[st_str] = counts_by_state.get(st_str, 0) + cnt_int
            if bool(is_rep) and st_str in RUNNING_CAP_STATES:
                active_running_repairs += cnt_int

        queued_count = counts_by_state.get("queued", 0)
        leased_count = counts_by_state.get("leased", 0)
        running_count = counts_by_state.get("running", 0)
        cancel_requested_count = counts_by_state.get("cancel_requested", 0)
        dead_letter_count = counts_by_state.get("dead_letter", 0)

        transport_status, transport_detail = self._transport.probe_health()
        backpressure_active = ws_ctx.workspace.paused or (
            queued_count > 0 and active_running_repairs >= self._max_running_repairs
        )
        return WorkspaceQueueFairnessSummary(
            max_running_repairs=self._max_running_repairs,
            active_running_repairs=active_running_repairs,
            queued_count=queued_count,
            leased_count=leased_count,
            running_count=running_count,
            cancel_requested_count=cancel_requested_count,
            dead_letter_count=dead_letter_count,
            workspace_paused=ws_ctx.workspace.paused,
            backpressure_active=backpressure_active,
            transport_status=transport_status,
            transport_detail=transport_detail,
        )

    async def list_workspace_jobs(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        state: TaskJobState | None,
        kind: str | None,
        repository_id: str | None,
        cursor: str | None,
        limit: int,
        now: datetime,
    ) -> TaskJobPage:
        """List workspace task jobs (`A-14`) with signed `S-04` cursor and fairness summary."""
        ref_now = now.astimezone(UTC)
        clean_repo_id: str | None = None
        if repository_id is not None:
            clean_repo_id = _validate_uuid_or_404(
                repository_id,
                code="repository_not_found",
                detail="Repository not found.",
            )
            if not ws_ctx.can_read_repository(clean_repo_id):
                raise NotFoundError(
                    code="repository_not_found",
                    detail="Repository not found.",
                )

        clean_kind = kind.strip() if kind is not None and kind.strip() else None
        q_hash = compute_query_filter_hash(
            {
                "endpoint": "task_jobs.list",
                "state": state,
                "kind": clean_kind,
                "repository_id": clean_repo_id,
            }
        )
        decoded = (
            decode_signed_cursor(
                cursor,
                signing_key=self._signing_key,
                expected_workspace_scope=ws_ctx.workspace_id,
                expected_principal_id=ws_ctx.auth.user.id,
                current_grant_epoch=ws_ctx.auth.user.grant_epoch,
                expected_query_hash=q_hash,
                now=ref_now,
            )
            if cursor is not None
            else None
        )

        stmt = select(TaskJobModel).where(TaskJobModel.workspace_id == ws_ctx.workspace_id)
        stmt = self._apply_repo_read_scope(stmt, ws_ctx)
        if state is not None:
            stmt = stmt.where(TaskJobModel.state == state)
        if clean_kind is not None:
            stmt = stmt.where(TaskJobModel.kind == clean_kind)
        if clean_repo_id is not None:
            stmt = stmt.where(TaskJobModel.repository_id == clean_repo_id)

        if decoded is not None:
            stmt = stmt.where(
                or_(
                    TaskJobModel.created_at < decoded.created_at,
                    and_(
                        TaskJobModel.created_at == decoded.created_at,
                        TaskJobModel.id < decoded.item_id,
                    ),
                )
            )
        stmt = stmt.order_by(TaskJobModel.created_at.desc(), TaskJobModel.id.desc()).limit(
            limit + 1
        )

        async with workspace_rls_session(
            self._session_factory,
            workspace_id=ws_ctx.workspace_id,
        ) as db:
            rows = list((await db.scalars(stmt)).all())
            summary = await self._compute_fairness_summary_in_tx(
                db,
                ws_ctx=ws_ctx,
                repository_id_filter=clean_repo_id,
            )

        has_more = len(rows) > limit
        page_rows = rows[:limit]
        next_cursor: str | None = None
        if has_more and page_rows:
            last_row = page_rows[-1]
            next_cursor = encode_signed_cursor(
                signing_key=self._signing_key,
                workspace_scope=ws_ctx.workspace_id,
                principal_id=ws_ctx.auth.user.id,
                grant_epoch=ws_ctx.auth.user.grant_epoch,
                query_hash=q_hash,
                created_at=last_row.created_at,
                item_id=last_row.id,
                now=ref_now,
            )

        return TaskJobPage(
            items=[to_task_job_dto(r) for r in page_rows],
            next_cursor=next_cursor,
            snapshot_at=ref_now,
            summary=summary,
        )

    async def get_workspace_job(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        job_id: str,
    ) -> TaskJobDetail:
        """Fetch detailed `TaskJobDetail` (`A-14`) enforcing workspace & repository grants."""
        clean_id = _validate_uuid_or_404(
            job_id,
            code="task_job_not_found",
            detail="Task job not found.",
        )
        async with workspace_rls_session(
            self._session_factory,
            workspace_id=ws_ctx.workspace_id,
        ) as db:
            job_row = await db.scalar(
                select(TaskJobModel).where(
                    TaskJobModel.workspace_id == ws_ctx.workspace_id,
                    TaskJobModel.id == clean_id,
                )
            )
            if job_row is None:
                raise NotFoundError(code="task_job_not_found", detail="Task job not found.")
            if job_row.repository_id is not None and not ws_ctx.can_read_repository(
                job_row.repository_id
            ):
                raise NotFoundError(code="task_job_not_found", detail="Task job not found.")

            attempt_rows = list(
                (
                    await db.scalars(
                        select(TaskAttemptModel)
                        .where(
                            TaskAttemptModel.workspace_id == ws_ctx.workspace_id,
                            TaskAttemptModel.job_id == job_row.id,
                        )
                        .order_by(TaskAttemptModel.lease_epoch.desc())
                    )
                ).all()
            )
            dlq_row = await db.scalar(
                select(DeadLetterJobModel)
                .where(
                    DeadLetterJobModel.workspace_id == ws_ctx.workspace_id,
                    DeadLetterJobModel.original_job_id == job_row.id,
                )
                .order_by(DeadLetterJobModel.created_at.desc(), DeadLetterJobModel.id.desc())
                .limit(1)
            )

            base_dto = to_task_job_dto(job_row)
            return TaskJobDetail(
                **base_dto.model_dump(mode="python"),
                attempts_history=[to_task_attempt_dto(a) for a in attempt_rows],
                dead_letter_entry=to_dead_letter_dto(dlq_row) if dlq_row is not None else None,
            )

    async def perform_job_action(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        job_id: str,
        payload: TaskJobActionRequest,
        idempotency_key: str | None,
        if_match_header: str | None,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> ActionReceipt:
        """Execute an idempotent operator queue control action (`cancel | requeue | reconcile`)."""
        ref_now = now.astimezone(UTC)
        if not idempotency_key:
            raise BadRequestError(
                code="missing_idempotency_key",
                detail=(
                    "POST /api/v1/workspaces/{ws}/task-jobs/{id}/actions requires an "
                    "S-05 Idempotency-Key header."
                ),
            )

        clean_id = _validate_uuid_or_404(
            job_id,
            code="task_job_not_found",
            detail="Task job not found.",
        )
        ws_id = ws_ctx.workspace_id
        actor_id = ws_ctx.auth.user.id
        safe_reason = self._redactor.redact_text(payload.reason.strip())[:1000]
        op_name = f"task_job.{payload.action}"

        should_wakeup = False
        raised_error: Exception | None = None
        receipt: ActionReceipt | None = None

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            ws_row = await db.scalar(
                select(WorkspaceModel).where(WorkspaceModel.id == ws_id).with_for_update()
            )
            if ws_row is None or ws_row.status == "deleting" or ws_row.deleted_at is not None:
                raise NotFoundError(code="workspace_not_found", detail="Workspace not found.")

            job_row = await db.scalar(
                select(TaskJobModel)
                .where(
                    TaskJobModel.workspace_id == ws_id,
                    TaskJobModel.id == clean_id,
                )
                .with_for_update()
            )
            if job_row is None:
                raise NotFoundError(code="task_job_not_found", detail="Task job not found.")

            if job_row.repository_id is not None and not ws_ctx.can_act_on_repository(
                job_row.repository_id,
                allowed_roles=QUEUE_OPERATOR_ROLES,
            ):
                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    actor_type="user",
                    actor_id=actor_id,
                    action=op_name,
                    target=f"task_job:{job_row.id}",
                    decision="deny",
                    reason_code="repository_grant_missing",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={"repository_id": job_row.repository_id},
                    occurred_at=ref_now,
                )
                raised_error = NotFoundError(
                    code="task_job_not_found",
                    detail="Task job not found.",
                )
            else:
                # Replay idempotency record BEFORE optimistic version check if exact same key!
                claim_check = await db.scalar(
                    select(IdempotencyRecordModel).where(
                        IdempotencyRecordModel.workspace_id == ws_id,
                        IdempotencyRecordModel.principal_id == actor_id,
                        IdempotencyRecordModel.operation == op_name,
                        IdempotencyRecordModel.idempotency_key == idempotency_key,
                    )
                )
                if claim_check is None:
                    enforce_optimistic_version(
                        current_version=job_row.version,
                        if_match_header=if_match_header,
                        expected_version=payload.expected_version,
                    )

                action_effect_key = (
                    f"task_job.action:{job_row.id}:v{job_row.version}:{payload.action}"
                )
                claim = await claim_idempotent_operation(
                    db,
                    workspace_id=ws_id,
                    principal_id=actor_id,
                    operation=op_name,
                    idempotency_key=idempotency_key,
                    request_payload=payload.model_dump(mode="json", exclude_none=True),
                    logical_effect_key=action_effect_key,
                    resource_id=job_row.id,
                    status_url=None,
                    correlation_id=correlation_id,
                    now=ref_now,
                )
                if not claim.is_new_claim:
                    return claim.receipt

                if payload.action == "cancel":
                    if job_row.state == "queued":
                        job_row.state = "cancelled"
                        job_row.cancel_reason = safe_reason
                        job_row.cancelled_by_user_id = actor_id
                        job_row.version += 1
                        job_row.updated_at = ref_now
                    elif job_row.state in {"leased", "running"}:
                        job_row.state = "cancel_requested"
                        job_row.cancel_reason = safe_reason
                        job_row.cancelled_by_user_id = actor_id
                        job_row.version += 1
                        job_row.updated_at = ref_now
                    elif job_row.state == "cancel_requested":
                        job_row.cancel_reason = safe_reason
                        job_row.updated_at = ref_now
                    else:
                        raise ConflictError(
                            code="invalid_job_transition",
                            detail=(f"Cannot cancel task job in terminal state {job_row.state!r}."),
                        )

                    await db.flush()
                    await append_audit_entry(
                        db,
                        workspace_id=ws_id,
                        actor_type="user",
                        actor_id=actor_id,
                        action="task_job.cancel",
                        target=f"task_job:{job_row.id}",
                        decision="allow",
                        reason_code="operator_cancel",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        metadata={
                            "resulting_state": job_row.state,
                            "reason": safe_reason,
                        },
                        occurred_at=ref_now,
                    )

                elif payload.action == "requeue":
                    if job_row.state not in {"dead_letter", "failed"}:
                        raise ConflictError(
                            code="invalid_job_transition",
                            detail=(
                                f"Task job in state {job_row.state!r} cannot be requeued; "
                                "expected 'dead_letter' or 'failed'."
                            ),
                        )
                    if job_row.reconcile_required:
                        raise ConflictError(
                            code="reconcile_required_before_requeue",
                            detail=(
                                "Task job failed with ambiguous external side effects and "
                                "requires explicit reconciliation before requeue (W-08)."
                            ),
                        )
                    if not job_row.recoverable:
                        raise ConflictError(
                            code="job_not_recoverable",
                            detail="Task job is marked non-recoverable and cannot be requeued.",
                        )
                    if ws_row.status != "active" or ws_row.paused:
                        raise ConflictError(
                            code="workspace_paused_or_inactive",
                            detail=(
                                "Live workspace policy check failed: workspace is paused or "
                                "not active; unpause before requeuing DLQ jobs."
                            ),
                        )

                    effect_op = _job_effect_operation_name(job_row.kind)
                    completed_effect = await db.scalar(
                        select(EffectTombstoneModel.id).where(
                            EffectTombstoneModel.workspace_id == ws_id,
                            EffectTombstoneModel.operation == effect_op,
                            EffectTombstoneModel.logical_effect_key == job_row.logical_effect_key,
                            EffectTombstoneModel.retained_until > ref_now,
                        )
                    )
                    if completed_effect is not None:
                        raise ConflictError(
                            code="duplicate_logical_effect",
                            detail=(
                                "Original logical_effect_key was already completed; "
                                "replay is blocked to prevent duplicate side effects."
                            ),
                        )

                    # Preserve original logical_effect_key & budget_key unchanged (T-JOB-02-P/N)!
                    preserved_effect_key = job_row.logical_effect_key
                    preserved_budget_key = job_row.budget_key

                    job_row.attempt += 1
                    job_row.max_attempts = max(job_row.max_attempts, job_row.attempt)
                    job_row.state = "queued"
                    job_row.leased_by_worker_id = None
                    job_row.heartbeat_at = None
                    job_row.lease_expires_at = None
                    job_row.not_before = ref_now
                    if job_row.deadline <= ref_now:
                        job_row.deadline = ref_now + DEFAULT_JOB_DEADLINE
                    job_row.version += 1
                    job_row.updated_at = ref_now

                    open_dlq = await db.scalar(
                        select(DeadLetterJobModel)
                        .where(
                            DeadLetterJobModel.workspace_id == ws_id,
                            DeadLetterJobModel.original_job_id == job_row.id,
                            DeadLetterJobModel.status == "open",
                        )
                        .with_for_update()
                    )
                    if open_dlq is not None:
                        open_dlq.status = "requeued"
                        open_dlq.requeued_at = ref_now
                        open_dlq.requeued_by_user_id = actor_id
                        open_dlq.version += 1
                        open_dlq.updated_at = ref_now

                    await db.flush()
                    assert job_row.logical_effect_key == preserved_effect_key
                    assert job_row.budget_key == preserved_budget_key

                    await append_audit_entry(
                        db,
                        workspace_id=ws_id,
                        actor_type="user",
                        actor_id=actor_id,
                        action="task_job.requeue",
                        target=f"task_job:{job_row.id}",
                        decision="allow",
                        reason_code="operator_scoped_requeue",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        metadata={
                            "attempt": job_row.attempt,
                            "logical_effect_key": preserved_effect_key,
                            "budget_key": preserved_budget_key,
                            "reason": safe_reason,
                        },
                        occurred_at=ref_now,
                    )
                    should_wakeup = True

                else:  # reconcile
                    if job_row.state not in {"dead_letter", "failed", "cancel_requested"}:
                        raise ConflictError(
                            code="invalid_job_transition",
                            detail=(
                                f"Task job in state {job_row.state!r} does not accept "
                                "reconciliation."
                            ),
                        )

                    outcome = payload.reconciled_outcome or "confirmed_absent"
                    open_dlq = await db.scalar(
                        select(DeadLetterJobModel)
                        .where(
                            DeadLetterJobModel.workspace_id == ws_id,
                            DeadLetterJobModel.original_job_id == job_row.id,
                            DeadLetterJobModel.status == "open",
                        )
                        .with_for_update()
                    )

                    if outcome == "confirmed_applied":
                        effect_op = _job_effect_operation_name(job_row.kind)
                        tombstone_stmt = (
                            pg_insert(EffectTombstoneModel)
                            .values(
                                id=new_uuid7(now=ref_now),
                                workspace_id=ws_id,
                                logical_effect_key=job_row.logical_effect_key,
                                operation=effect_op,
                                origin_operation_id=claim.receipt.operation_id,
                                idempotency_key=idempotency_key,
                                request_hash=hashlib.sha256(
                                    f"reconcile:{job_row.id}:{idempotency_key}".encode()
                                ).hexdigest(),
                                resource_id=job_row.resource_id,
                                retained_until=ref_now + DEFAULT_TOMBSTONE_TTL,
                                created_at=ref_now,
                            )
                            .on_conflict_do_nothing(
                                constraint="uq_effect_tombstones_logical_effect"
                            )
                        )
                        await db.execute(tombstone_stmt)
                        job_row.state = "succeeded"
                        job_row.leased_by_worker_id = None
                        job_row.lease_expires_at = None
                        job_row.reconcile_required = False
                        if open_dlq is not None:
                            open_dlq.status = "reconciled"
                            open_dlq.reconcile_required = False
                            open_dlq.requeued_by_user_id = actor_id
                            open_dlq.version += 1
                            open_dlq.updated_at = ref_now
                    else:
                        job_row.reconcile_required = False
                        job_row.recoverable = True
                        if open_dlq is not None:
                            open_dlq.reconcile_required = False
                            open_dlq.recoverable = True
                            open_dlq.version += 1
                            open_dlq.updated_at = ref_now

                    job_row.version += 1
                    job_row.updated_at = ref_now
                    await db.flush()

                    await append_audit_entry(
                        db,
                        workspace_id=ws_id,
                        actor_type="user",
                        actor_id=actor_id,
                        action="task_job.reconcile",
                        target=f"task_job:{job_row.id}",
                        decision="allow",
                        reason_code=f"reconciled_{outcome}",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        metadata={
                            "reconciled_outcome": outcome,
                            "resulting_state": job_row.state,
                            "logical_effect_key": job_row.logical_effect_key,
                            "reason": safe_reason,
                        },
                        occurred_at=ref_now,
                    )

                final_state: Literal["succeeded", "running"] = (
                    "running" if job_row.state == "cancel_requested" else "succeeded"
                )
                if final_state == "succeeded":
                    receipt = await complete_idempotent_operation(
                        db,
                        workspace_id=ws_id,
                        operation_id=claim.receipt.operation_id,
                        state="succeeded",
                        status_code=202,
                        result_id=job_row.id,
                        now=ref_now,
                    )
                else:
                    receipt = claim.receipt

                await upsert_operation_receipt(
                    db,
                    operation_id=receipt.operation_id,
                    scope="workspace",
                    workspace_id=ws_id,
                    repository_id=job_row.repository_id,
                    principal_id=actor_id,
                    required_role="maintainer",
                    operation_kind=op_name,
                    resource_id=job_row.id,
                    state=receipt.state,
                    correlation_id=receipt.correlation_id,
                    status_url=receipt.status_url,
                    logical_effect_key=action_effect_key,
                    result_id=receipt.result_id,
                    now=ref_now,
                )

        if raised_error is not None:
            raise raised_error
        assert receipt is not None
        if should_wakeup:
            self._transport.publish_wakeup(
                workspace_id=ws_id,
                job_id=clean_id,
                now=ref_now,
                force=True,
            )
        return receipt


class OperationReceiptService:
    """Implements A-24 `GET /api/v1/operations/{id}` with strict live scope recheck."""

    def __init__(self, *, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_operation_receipt(
        self,
        auth: AuthenticatedContext,
        *,
        operation_id: str,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> ActionReceipt:
        """Return `ActionReceipt` iff caller holds live rights in the originating scope."""
        ref_now = now.astimezone(UTC)
        clean_op_id = _validate_uuid_or_404(
            operation_id,
            code="operation_not_found",
            detail="Operation receipt not found.",
        )

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            row = await db.scalar(
                select(OperationReceiptModel).where(OperationReceiptModel.id == clean_op_id)
            )
            if row is None:
                raise NotFoundError(
                    code="operation_not_found",
                    detail="Operation receipt not found.",
                )
            db.expunge(row)

        if row.scope == "instance":
            if row.required_role == "instance_owner" and not auth.user.is_instance_owner:
                async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
                    await append_audit_entry(
                        db,
                        actor_type="user",
                        actor_id=auth.user.id,
                        action="operation_receipt.read",
                        target=f"operation:{clean_op_id}",
                        decision="deny",
                        reason_code="cross_scope_operation_denied",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        occurred_at=ref_now,
                    )
                raise NotFoundError(
                    code="operation_not_found",
                    detail="Operation receipt not found.",
                )
            if row.required_role == "self" and auth.user.id != row.principal_id:
                raise NotFoundError(
                    code="operation_not_found",
                    detail="Operation receipt not found.",
                )
            return self._to_receipt_dto(row)

        # Workspace-scoped operation receipt
        ws_id = row.workspace_id
        if ws_id is None:
            raise NotFoundError(
                code="operation_not_found",
                detail="Operation receipt not found.",
            )

        # Special case: Instance Owner polling their own completed `workspace.delete` receipt
        if (
            row.operation_kind == "workspace.delete"
            and auth.user.is_instance_owner
            and auth.user.id == row.principal_id
        ):
            return self._to_receipt_dto(row)

        denied_exc: Exception | None = None
        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as ws_db:
            ws_row = await ws_db.scalar(select(WorkspaceModel).where(WorkspaceModel.id == ws_id))
            if ws_row is None or ws_row.status == "deleting" or ws_row.deleted_at is not None:
                denied_exc = NotFoundError(
                    code="operation_not_found",
                    detail="Operation receipt not found.",
                )
            else:
                membership = await ws_db.scalar(
                    select(MembershipModel).where(
                        MembershipModel.workspace_id == ws_id,
                        MembershipModel.user_id == auth.user.id,
                    )
                )
                bg_row: BreakGlassGrantModel | None = None
                if auth.user.is_instance_owner:
                    bg_row = await ws_db.scalar(
                        select(BreakGlassGrantModel)
                        .where(
                            BreakGlassGrantModel.workspace_id == ws_id,
                            BreakGlassGrantModel.user_id == auth.user.id,
                            BreakGlassGrantModel.revoked_at.is_(None),
                            BreakGlassGrantModel.expires_at > ref_now,
                        )
                        .limit(1)
                    )

                if membership is None and bg_row is None:
                    await append_audit_entry(
                        ws_db,
                        workspace_id=ws_id,
                        actor_type="user",
                        actor_id=auth.user.id,
                        action="operation_receipt.read",
                        target=f"operation:{clean_op_id}",
                        decision="deny",
                        reason_code="cross_workspace_operation_denied",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        occurred_at=ref_now,
                    )
                    denied_exc = NotFoundError(
                        code="operation_not_found",
                        detail="Operation receipt not found.",
                    )
                else:
                    if row.repository_id is not None and bg_row is None:
                        assert membership is not None
                        if membership.role != "admin":
                            has_repo = await ws_db.scalar(
                                select(RepoGrantModel.id).where(
                                    RepoGrantModel.workspace_id == ws_id,
                                    RepoGrantModel.membership_id == membership.id,
                                    RepoGrantModel.repository_id == row.repository_id,
                                )
                            )
                            if has_repo is None:
                                await append_audit_entry(
                                    ws_db,
                                    workspace_id=ws_id,
                                    actor_type="user",
                                    actor_id=auth.user.id,
                                    action="operation_receipt.read",
                                    target=f"operation:{clean_op_id}",
                                    decision="deny",
                                    reason_code="repository_grant_missing",
                                    correlation_id=correlation_id,
                                    client_ip=client_ip,
                                    occurred_at=ref_now,
                                )
                                denied_exc = NotFoundError(
                                    code="operation_not_found",
                                    detail="Operation receipt not found.",
                                )

                    if denied_exc is None and bg_row is None:
                        assert membership is not None
                        if row.required_role == "self" and auth.user.id != row.principal_id:
                            denied_exc = NotFoundError(
                                code="operation_not_found",
                                detail="Operation receipt not found.",
                            )
                        elif row.required_role in ROLE_PRIVILEGE_RANK:
                            req_rank = ROLE_PRIVILEGE_RANK[row.required_role]
                            caller_rank = next(
                                (
                                    rank
                                    for role_key, rank in ROLE_PRIVILEGE_RANK.items()
                                    if role_key == membership.role
                                ),
                                0,
                            )
                            if caller_rank < req_rank:
                                await append_audit_entry(
                                    ws_db,
                                    workspace_id=ws_id,
                                    actor_type="user",
                                    actor_id=auth.user.id,
                                    action="operation_receipt.read",
                                    target=f"operation:{clean_op_id}",
                                    decision="deny",
                                    reason_code="insufficient_role",
                                    correlation_id=correlation_id,
                                    client_ip=client_ip,
                                    occurred_at=ref_now,
                                )
                                denied_exc = ForbiddenError(
                                    code="insufficient_role",
                                    detail=(
                                        "Your workspace role does not have live rights to "
                                        "inspect this operation receipt."
                                    ),
                                )

                    # Sync state if underlying job finished cancel_requested -> cancelled!
                    if (
                        denied_exc is None
                        and row.state == "running"
                        and row.operation_kind == "task_job.cancel"
                    ):
                        job_state = await ws_db.scalar(
                            select(TaskJobModel.state).where(
                                TaskJobModel.workspace_id == ws_id,
                                TaskJobModel.id == row.resource_id,
                            )
                        )
                        if job_state == "cancelled":
                            live_row = await ws_db.scalar(
                                select(OperationReceiptModel)
                                .where(OperationReceiptModel.id == clean_op_id)
                                .with_for_update()
                            )
                            if live_row is not None:
                                live_row.state = "succeeded"
                                live_row.result_id = row.resource_id
                                live_row.version += 1
                                live_row.updated_at = ref_now
                                await ws_db.flush()
                                ws_db.expunge(live_row)
                                row = live_row

        if denied_exc is not None:
            raise denied_exc
        return self._to_receipt_dto(row)

    @staticmethod
    def _to_receipt_dto(row: OperationReceiptModel) -> ActionReceipt:
        prob = (
            Problem.model_validate(row.problem_payload) if row.problem_payload is not None else None
        )
        return ActionReceipt(
            operation_id=row.id,
            resource_id=row.resource_id,
            state=cast(ActionState, row.state),
            correlation_id=row.correlation_id,
            status_url=row.status_url,
            result_id=row.result_id,
            problem=prob,
        )
