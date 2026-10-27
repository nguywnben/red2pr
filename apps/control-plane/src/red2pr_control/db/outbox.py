"""Transactional S-19 domain event outbox and fenced consumer-group lease claims.

Implements docs/08_EVENTS_STATE_MACHINES.md and docs/36_CANONICAL_CONTRACTS.md (S-19):
- `enqueue_outbox_event` commits validated S-19 `EventEnvelope` rows inside the exact
  same PostgreSQL transaction as domain state changes, allocating dense monotonic
  per-workspace `workspace_seq` values for SSE cursor replay.
- `claim_pending_outbox_events` acquires `FOR UPDATE SKIP LOCKED` leases per
  `consumer_group` and increments monotonic `lease_epoch` fencing tokens on expiry reclaim.
- `ack_outbox_claim` and `fail_outbox_claim` verify `(worker_id, lease_epoch)` to reject
  stale/slow workers (`409 stale_outbox_lease`, SEC-021 pattern) and route exhausted
  events to `dead_letter`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from sqlalchemy import and_, exists, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts.events import EventEnvelope
from py_contracts.primitives import new_uuid7
from red2pr_control.core.errors import ConflictError, NotFoundError
from red2pr_control.db.base import OutboxClaimModel, OutboxEventModel, WorkspaceModel


@dataclass(frozen=True)
class ClaimedOutboxEvent:
    """Fenced outbox event lease granted to a consumer worker."""

    event: EventEnvelope
    workspace_seq: int | None
    consumer_group: str
    worker_id: str
    lease_epoch: int
    attempts: int
    lease_expires_at: datetime


def _row_to_event_envelope(row: OutboxEventModel) -> EventEnvelope:
    return EventEnvelope.model_validate(
        {
            "event_id": row.id,
            "schema_version": row.schema_version,
            "type": row.event_type,
            "occurred_at": row.occurred_at,
            "workspace_id": row.workspace_id,
            "repository_id": row.repository_id,
            "session_id": row.session_id,
            "aggregate_id": row.aggregate_id,
            "aggregate_version": row.aggregate_version,
            "correlation_id": row.correlation_id,
            "causation_id": row.causation_id,
            "payload": row.payload,
        }
    )


async def enqueue_outbox_event(
    session: AsyncSession,
    event: EventEnvelope,
    *,
    now: datetime | None = None,
) -> int | None:
    """Validate and insert an S-19 EventEnvelope atomically inside the active transaction."""
    validated = EventEnvelope.model_validate(event.model_dump(mode="python"))
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)

    workspace_seq: int | None = None
    if validated.workspace_id is not None:
        seq_val = await session.scalar(
            update(WorkspaceModel)
            .where(WorkspaceModel.id == validated.workspace_id)
            .values(
                last_event_seq=WorkspaceModel.last_event_seq + 1,
                updated_at=ref_now,
            )
            .returning(WorkspaceModel.last_event_seq)
        )
        if seq_val is None:
            raise NotFoundError(
                code="workspace_not_found",
                detail="Cannot enqueue workspace outbox event for nonexistent workspace.",
            )
        workspace_seq = int(seq_val)

    outbox_row = OutboxEventModel(
        id=validated.event_id,
        workspace_id=validated.workspace_id,
        workspace_seq=workspace_seq,
        event_type=validated.type,
        schema_version=validated.schema_version,
        repository_id=validated.repository_id,
        session_id=validated.session_id,
        aggregate_id=validated.aggregate_id,
        aggregate_version=validated.aggregate_version,
        correlation_id=validated.correlation_id,
        causation_id=validated.causation_id,
        payload=validated.payload.model_dump(mode="json"),
        status="pending",
        attempts=0,
        next_attempt_at=ref_now,
        published_at=None,
        last_error_code=None,
        occurred_at=validated.occurred_at,
        created_at=ref_now,
    )
    session.add(outbox_row)
    await session.flush()
    return workspace_seq


async def claim_pending_outbox_events(
    session: AsyncSession,
    *,
    consumer_group: str,
    worker_id: str,
    workspace_id: str | None = None,
    lease_seconds: int = 60,
    limit: int = 25,
    now: datetime | None = None,
) -> list[ClaimedOutboxEvent]:
    """Claim ready outbox events for `consumer_group` using `FOR UPDATE SKIP LOCKED`."""
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    bounded_limit = max(1, min(limit, 100))
    lease_until = ref_now + timedelta(seconds=max(5, lease_seconds))

    active_or_completed_claim = exists(
        select(OutboxClaimModel.id).where(
            and_(
                OutboxClaimModel.event_id == OutboxEventModel.id,
                OutboxClaimModel.consumer_group == consumer_group,
                or_(
                    OutboxClaimModel.completed_at.is_not(None),
                    OutboxClaimModel.lease_expires_at > ref_now,
                ),
            )
        )
    )

    scope_filter = (
        OutboxEventModel.workspace_id == workspace_id
        if workspace_id is not None
        else OutboxEventModel.workspace_id.is_(None)
    )

    stmt = (
        select(OutboxEventModel)
        .where(
            scope_filter,
            OutboxEventModel.status.in_(("pending", "claimed")),
            OutboxEventModel.next_attempt_at <= ref_now,
            ~active_or_completed_claim,
        )
        .order_by(OutboxEventModel.next_attempt_at.asc(), OutboxEventModel.id.asc())
        .limit(bounded_limit)
        .with_for_update(skip_locked=True)
    )
    rows = (await session.scalars(stmt)).all()
    claimed_items: list[ClaimedOutboxEvent] = []

    for event_row in rows:
        claim_row = await session.scalar(
            select(OutboxClaimModel)
            .where(
                OutboxClaimModel.event_id == event_row.id,
                OutboxClaimModel.consumer_group == consumer_group,
            )
            .with_for_update()
        )
        if claim_row is None:
            lease_epoch = 1
            claim_row = OutboxClaimModel(
                id=new_uuid7(now=ref_now),
                workspace_id=event_row.workspace_id,
                event_id=event_row.id,
                consumer_group=consumer_group,
                worker_id=worker_id,
                lease_epoch=lease_epoch,
                claimed_at=ref_now,
                lease_expires_at=lease_until,
                completed_at=None,
            )
            session.add(claim_row)
        else:
            if claim_row.completed_at is not None or claim_row.lease_expires_at > ref_now:
                continue
            lease_epoch = int(claim_row.lease_epoch) + 1
            claim_row.lease_epoch = lease_epoch
            claim_row.worker_id = worker_id
            claim_row.claimed_at = ref_now
            claim_row.lease_expires_at = lease_until

        event_row.status = "claimed"
        event_row.attempts = int(event_row.attempts) + 1

        claimed_items.append(
            ClaimedOutboxEvent(
                event=_row_to_event_envelope(event_row),
                workspace_seq=event_row.workspace_seq,
                consumer_group=consumer_group,
                worker_id=worker_id,
                lease_epoch=lease_epoch,
                attempts=event_row.attempts,
                lease_expires_at=lease_until,
            )
        )

    await session.flush()
    return claimed_items


async def ack_outbox_claim(
    session: AsyncSession,
    *,
    event_id: str,
    consumer_group: str,
    worker_id: str,
    lease_epoch: int,
    now: datetime | None = None,
) -> None:
    """Acknowledge successful outbox delivery, rejecting stale lease_epoch tokens."""
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    claim_row = await session.scalar(
        select(OutboxClaimModel)
        .where(
            OutboxClaimModel.event_id == event_id,
            OutboxClaimModel.consumer_group == consumer_group,
        )
        .with_for_update()
    )
    if (
        claim_row is None
        or claim_row.completed_at is not None
        or claim_row.worker_id != worker_id
        or int(claim_row.lease_epoch) != lease_epoch
    ):
        raise ConflictError(
            code="stale_outbox_lease",
            detail="Outbox claim lease_epoch or worker ownership is stale or already completed.",
        )

    event_row = await session.scalar(
        select(OutboxEventModel).where(OutboxEventModel.id == event_id).with_for_update()
    )
    if event_row is None:
        raise NotFoundError(code="outbox_event_not_found", detail="Outbox event not found.")

    claim_row.completed_at = ref_now
    event_row.status = "published"
    event_row.published_at = ref_now
    await session.flush()


async def fail_outbox_claim(
    session: AsyncSession,
    *,
    event_id: str,
    consumer_group: str,
    worker_id: str,
    lease_epoch: int,
    error_code: str,
    retry_delay_seconds: int = 15,
    max_attempts: int = 8,
    now: datetime | None = None,
) -> Literal["pending", "dead_letter"]:
    """Record a failed delivery attempt with backoff or transition to dead_letter."""
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    claim_row = await session.scalar(
        select(OutboxClaimModel)
        .where(
            OutboxClaimModel.event_id == event_id,
            OutboxClaimModel.consumer_group == consumer_group,
        )
        .with_for_update()
    )
    if (
        claim_row is None
        or claim_row.completed_at is not None
        or claim_row.worker_id != worker_id
        or int(claim_row.lease_epoch) != lease_epoch
    ):
        raise ConflictError(
            code="stale_outbox_lease",
            detail="Outbox claim lease_epoch or worker ownership is stale.",
        )

    event_row = await session.scalar(
        select(OutboxEventModel).where(OutboxEventModel.id == event_id).with_for_update()
    )
    if event_row is None:
        raise NotFoundError(code="outbox_event_not_found", detail="Outbox event not found.")

    claim_row.lease_expires_at = ref_now
    event_row.last_error_code = error_code.strip()[:120] or "delivery_failed"

    if int(event_row.attempts) >= max_attempts:
        event_row.status = "dead_letter"
        await session.flush()
        return "dead_letter"

    event_row.status = "pending"
    event_row.next_attempt_at = ref_now + timedelta(seconds=max(1, retry_delay_seconds))
    await session.flush()
    return "pending"
