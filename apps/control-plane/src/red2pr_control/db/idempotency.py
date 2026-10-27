"""Atomic S-05 Idempotency-Key store and NFR-07 logical-effect tombstones.

Enforces docs/36_CANONICAL_CONTRACTS.md (S-05) and docs/37_NFR_AND_RECOVERY.md (NFR-07):
- First-claim `Idempotency-Key` must be RFC 9562 UUIDv7 within `<=7d` age and `<=5m` future skew.
- Atomically unique on `(workspace_id, principal_id, operation, idempotency_key)`:
  - Same key + different canonical request payload -> `409 idempotency_payload_mismatch`.
  - Duplicate claim while `accepted` or `running` -> `202` with identical `ActionReceipt`.
  - Duplicate claim after completion -> replays identical status & cached payload.
  - Expired key (`>7d` age or past `expires_at`) -> `409 key_expired`.
- Retains `effect_tombstones` across `>=90d` default horizon so purging expired 7-day
  response caches never permits recreating a side effect under a fresh UUIDv7 key.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts.crypto import sha256_canonical_json
from py_contracts.primitives import (
    ActionReceipt,
    ActionState,
    Problem,
    new_uuid7,
    parse_uuid7_timestamp_ms,
    validate_idempotency_key_window,
)
from red2pr_control.core.errors import BadRequestError, ConflictError, NotFoundError
from red2pr_control.db.base import (
    EffectTombstoneModel,
    IdempotencyRecordModel,
    OperationReceiptModel,
)

CompletedActionState = Literal["succeeded", "failed", "unknown"]


@dataclass(frozen=True)
class IdempotencyClaimOutcome:
    """Result of claiming or replaying an S-05 idempotent mutation."""

    is_new_claim: bool
    http_status: int
    receipt: ActionReceipt
    cached_response: dict[str, Any] | None = None


def _record_to_receipt(record: IdempotencyRecordModel) -> ActionReceipt:
    problem = (
        Problem.model_validate(record.problem_payload)
        if record.problem_payload is not None
        else None
    )
    return ActionReceipt(
        operation_id=record.id,
        resource_id=record.resource_id,
        state=cast(ActionState, record.state),
        correlation_id=record.correlation_id,
        status_url=record.status_url,
        result_id=record.result_id,
        problem=problem,
    )


def _evaluate_existing_record(
    record: IdempotencyRecordModel,
    *,
    request_hash: str,
    ref_now: datetime,
) -> IdempotencyClaimOutcome:
    if record.expires_at <= ref_now:
        raise ConflictError(
            code="key_expired",
            detail="Idempotency-Key record has expired; re-execution is prohibited.",
        )
    if record.request_hash != request_hash:
        raise ConflictError(
            code="idempotency_payload_mismatch",
            detail="Idempotency-Key was already claimed with a different request payload.",
        )
    receipt = _record_to_receipt(record)
    http_status = 202 if record.state in {"accepted", "running"} else record.status_code
    cached_payload = dict(record.response_payload) if record.response_payload is not None else None
    return IdempotencyClaimOutcome(
        is_new_claim=False,
        http_status=http_status,
        receipt=receipt,
        cached_response=cached_payload,
    )


async def claim_idempotent_operation(
    session: AsyncSession,
    *,
    workspace_id: str,
    principal_id: str,
    operation: str,
    idempotency_key: str,
    request_payload: Mapping[str, Any],
    logical_effect_key: str,
    resource_id: str,
    status_url: str | None = None,
    correlation_id: str = "",
    now: datetime | None = None,
    record_ttl: timedelta = timedelta(days=7),
    tombstone_ttl: timedelta = timedelta(days=90),
) -> IdempotencyClaimOutcome:
    """Atomically claim an S-05 idempotent mutation or return its prior receipt/conflict."""
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)

    try:
        parse_uuid7_timestamp_ms(idempotency_key)
    except ValueError as exc:
        raise BadRequestError(
            code="invalid_idempotency_key",
            detail=str(exc),
        ) from exc

    request_hash = sha256_canonical_json(dict(request_payload))

    existing = await session.scalar(
        select(IdempotencyRecordModel).where(
            IdempotencyRecordModel.workspace_id == workspace_id,
            IdempotencyRecordModel.principal_id == principal_id,
            IdempotencyRecordModel.operation == operation,
            IdempotencyRecordModel.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        return _evaluate_existing_record(
            existing,
            request_hash=request_hash,
            ref_now=ref_now,
        )

    try:
        validate_idempotency_key_window(
            idempotency_key,
            now=ref_now,
            max_age=record_ttl,
            max_future_skew=timedelta(minutes=5),
        )
    except ValueError as exc:
        msg = str(exc)
        if msg.startswith("key_expired:"):
            raise ConflictError(code="key_expired", detail=msg) from exc
        raise BadRequestError(code="invalid_idempotency_key", detail=msg) from exc

    operation_id = new_uuid7(now=ref_now)
    effective_status_url = status_url or f"/api/v1/operations/{operation_id}"
    expires_at = ref_now + record_ttl

    insert_record_stmt = (
        pg_insert(IdempotencyRecordModel)
        .values(
            id=operation_id,
            workspace_id=workspace_id,
            principal_id=principal_id,
            operation=operation,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            logical_effect_key=logical_effect_key,
            resource_id=resource_id,
            state="running",
            status_code=202,
            status_url=effective_status_url,
            correlation_id=correlation_id,
            result_id=None,
            response_payload=None,
            problem_payload=None,
            claimed_at=ref_now,
            expires_at=expires_at,
            version=1,
            created_at=ref_now,
            updated_at=ref_now,
        )
        .on_conflict_do_nothing(constraint="uq_idempotency_records_claim_scope")
        .returning(IdempotencyRecordModel.id)
    )
    inserted_op_id = await session.scalar(insert_record_stmt)

    if inserted_op_id is None:
        winner = await session.scalar(
            select(IdempotencyRecordModel)
            .where(
                IdempotencyRecordModel.workspace_id == workspace_id,
                IdempotencyRecordModel.principal_id == principal_id,
                IdempotencyRecordModel.operation == operation,
                IdempotencyRecordModel.idempotency_key == idempotency_key,
            )
            .execution_options(populate_existing=True)
        )
        if winner is None:
            raise ConflictError(
                code="idempotency_race_unresolved",
                detail="Concurrent idempotency claim aborted; retry safely with same key.",
            )
        return _evaluate_existing_record(
            winner,
            request_hash=request_hash,
            ref_now=ref_now,
        )

    tombstone_id = new_uuid7(now=ref_now)
    insert_tombstone_stmt = (
        pg_insert(EffectTombstoneModel)
        .values(
            id=tombstone_id,
            workspace_id=workspace_id,
            logical_effect_key=logical_effect_key,
            operation=operation,
            origin_operation_id=operation_id,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            resource_id=resource_id,
            retained_until=ref_now + max(record_ttl, tombstone_ttl),
            created_at=ref_now,
        )
        .on_conflict_do_nothing(constraint="uq_effect_tombstones_logical_effect")
        .returning(EffectTombstoneModel.id)
    )
    inserted_tombstone = await session.scalar(insert_tombstone_stmt)
    if inserted_tombstone is None:
        raise ConflictError(
            code="duplicate_logical_effect",
            detail=(
                f"Logical side effect {logical_effect_key!r} for operation {operation!r} "
                "was already executed within tombstone retention."
            ),
        )

    receipt = ActionReceipt(
        operation_id=operation_id,
        resource_id=resource_id,
        state="running",
        correlation_id=correlation_id,
        status_url=effective_status_url,
    )
    return IdempotencyClaimOutcome(
        is_new_claim=True,
        http_status=202,
        receipt=receipt,
        cached_response=None,
    )


async def complete_idempotent_operation(
    session: AsyncSession,
    *,
    workspace_id: str,
    operation_id: str,
    state: CompletedActionState,
    status_code: int,
    result_id: str | None = None,
    response_payload: Mapping[str, Any] | None = None,
    problem: Problem | None = None,
    now: datetime | None = None,
) -> ActionReceipt:
    """Persist terminal or unknown outcome on a claimed S-05 idempotency record."""
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    record = await session.scalar(
        select(IdempotencyRecordModel)
        .where(
            IdempotencyRecordModel.workspace_id == workspace_id,
            IdempotencyRecordModel.id == operation_id,
        )
        .with_for_update()
    )
    if record is None:
        raise NotFoundError(
            code="operation_not_found",
            detail="Operation receipt not found in active workspace.",
        )

    record.state = state
    record.status_code = status_code
    record.result_id = result_id
    record.response_payload = dict(response_payload) if response_payload is not None else None
    record.problem_payload = problem.model_dump(mode="json") if problem is not None else None
    record.version += 1
    record.updated_at = ref_now
    await session.flush()
    return _record_to_receipt(record)


async def purge_expired_idempotency_records(
    session: AsyncSession,
    *,
    workspace_id: str,
    now: datetime | None = None,
) -> int:
    """Purge expired 7-day idempotency response caches while retaining effect_tombstones."""
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    deleted_ids = (
        await session.scalars(
            delete(IdempotencyRecordModel)
            .where(
                IdempotencyRecordModel.workspace_id == workspace_id,
                IdempotencyRecordModel.expires_at <= ref_now,
            )
            .returning(IdempotencyRecordModel.id)
        )
    ).all()
    return len(deleted_ids)


async def upsert_operation_receipt(
    session: AsyncSession,
    *,
    operation_id: str,
    scope: Literal["workspace", "instance"],
    workspace_id: str | None,
    repository_id: str | None = None,
    principal_id: str,
    required_role: Literal[
        "instance_owner",
        "admin",
        "maintainer",
        "reviewer",
        "viewer",
        "auditor",
        "self",
    ],
    operation_kind: str,
    resource_id: str,
    state: ActionState,
    correlation_id: str,
    status_url: str,
    logical_effect_key: str,
    result_id: str | None = None,
    problem: Problem | None = None,
    now: datetime | None = None,
) -> ActionReceipt:
    """Create or update an A-24 durable `operation_receipts` row inside the active transaction."""
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    existing = await session.scalar(
        select(OperationReceiptModel)
        .where(OperationReceiptModel.id == operation_id)
        .with_for_update()
    )
    prob_json = problem.model_dump(mode="json") if problem is not None else None
    if existing is None:
        row = OperationReceiptModel(
            id=operation_id,
            scope=scope,
            workspace_id=workspace_id,
            repository_id=repository_id,
            principal_id=principal_id,
            required_role=required_role,
            operation_kind=operation_kind,
            resource_id=resource_id,
            state=state,
            correlation_id=correlation_id,
            status_url=status_url,
            result_id=result_id,
            problem_payload=prob_json,
            logical_effect_key=logical_effect_key,
            version=1,
            created_at=ref_now,
            updated_at=ref_now,
        )
        session.add(row)
        await session.flush()
    else:
        existing.state = state
        existing.result_id = result_id
        existing.problem_payload = prob_json
        existing.version += 1
        existing.updated_at = ref_now
        await session.flush()

    return ActionReceipt(
        operation_id=operation_id,
        resource_id=resource_id,
        state=state,
        correlation_id=correlation_id,
        status_url=status_url,
        result_id=result_id,
        problem=problem,
    )
