"""Atomic row-locked NUMERIC(18, 6) token, time, attempt & cost budget ledger (U16, AGT-03).

Implements `AGT-03`, `NFR-06`, `S-17`, `S-19`, and `SEC-033`:
- Exact Python `Decimal` / PostgreSQL `NUMERIC(18, 6)` monetary arithmetic (binary `float`
  is explicitly rejected with `TypeError`).
- Deterministic ascending-ID `SELECT ... FOR UPDATE` row locking across hierarchical
  budget accounts (`repair_session` / `model_probe` + `workspace_daily`) inside short
  pre-network transactions so row locks are never held across outbound HTTP sockets and
  parallel reservation races (`SEC-033`) serialize without deadlocks or cap overshoot.
- Ambiguous post-dispatch failures (network read timeout, dropped stream, missing `usage`
  payload) transition reservations to `unknown_outcome`, retaining the full worst-case
  reserved spend against account caps while recording `ModelUsageRecord(status='unknown',
  settled_cost=None, input_tokens=None, output_tokens=None)` — never coercing unknown
  billing to `$0.00`.
- Mid-session cancellation stamps `cancelled_at` atomically so zero subsequent calls can
  reserve budget, while any already in-flight response settles truthfully with
  `late_after_cancel=True`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import ROUND_CEILING, Decimal
from typing import Literal, cast

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.events import BudgetEventPayload, EventEnvelope
from py_contracts.evidence import ModelUsageRecord, UsageStatus
from py_contracts.models import (
    BudgetAccountSummary,
    BudgetPolicyDefaults,
    BudgetReservationRecord,
    BudgetReservationStatus,
    BudgetScopeKind,
    ModelPricingRate,
    validate_supported_meta_model_id,
)
from py_contracts.primitives import Money, new_uuid7
from red2pr_control.analytics_audit.audit_chain import AuditActorType, append_audit_entry
from red2pr_control.core.errors import ConflictError, NotFoundError
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.db.base import (
    BudgetAccountModel,
    BudgetReservationModel,
    UsageLedgerModel,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import workspace_rls_session

NUMERIC_QUANT = Decimal("0.000001")
ZERO_DECIMAL = Decimal("0.000000")
ONE_MILLION = Decimal("1000000")
ONE_HUNDRED = Decimal("100")


def _default_utc_clock() -> datetime:
    return datetime.now(tz=UTC)


def ensure_strict_decimal(value: Decimal | int | str) -> Decimal:
    """Reject `float`/`bool` and quantize nonnegative monetary `Decimal` to 6 places."""
    if isinstance(value, (bool, float)):
        raise TypeError("Binary float or bool is forbidden for monetary budget math")
    dec = value if isinstance(value, Decimal) else Decimal(value)
    if not dec.is_finite() or dec < Decimal("0"):
        raise ValueError("Monetary Decimal must be finite and nonnegative")
    return dec.quantize(NUMERIC_QUANT, rounding=ROUND_CEILING)


def compute_exact_token_cost(
    *,
    input_tokens: int,
    output_tokens: int,
    pricing: ModelPricingRate,
) -> Money:
    """Compute exact `ROUND_CEILING` `NUMERIC(18, 6)` token cost under a verified pricing rate."""
    if isinstance(input_tokens, bool) or isinstance(output_tokens, bool):
        raise TypeError("Token counts must be strict integers")
    if input_tokens < 0 or output_tokens < 0:
        raise ValueError("Token counts must be nonnegative")
    if not pricing.configured or pricing.pricing_revision.strip().lower() in {
        "",
        "unknown",
        "unconfigured",
        "none",
    }:
        raise ConflictError(
            code="unknown_model_pricing",
            detail=(
                f"Pricing revision {pricing.pricing_revision!r} is unconfigured or unknown; "
                "autonomous inference cannot reserve budget without verified pricing (AGT-03)."
            ),
        )
    in_rate = ensure_strict_decimal(pricing.input_per_1m_tokens.amount)
    out_rate = ensure_strict_decimal(pricing.output_per_1m_tokens.amount)
    raw_total = ((Decimal(input_tokens) * in_rate) + (Decimal(output_tokens) * out_rate)) / (
        ONE_MILLION
    )
    quantized = raw_total.quantize(NUMERIC_QUANT, rounding=ROUND_CEILING)
    return Money(amount=quantized, currency=pricing.input_per_1m_tokens.currency)


def estimate_worst_case_input_tokens(redacted_serialized_payload: str, *, item_count: int) -> int:
    """Compute a deterministic upper-bound input token estimate (`>=` UTF-8 BPE token count)."""
    utf8_len = len(redacted_serialized_payload.encode("utf-8"))
    # Even single-byte BPE fallback cannot exceed 1 token per UTF-8 byte + framing overhead.
    return max(16, utf8_len + (max(1, item_count) * 16) + 64)


class BudgetExceededError(ConflictError):
    """Raised when an atomic budget reservation or patch attempt exceeds configured caps."""

    def __init__(self, *, code: str, detail: str, budget_account_id: str) -> None:
        super().__init__(code=code, detail=detail)
        self.budget_account_id = budget_account_id


@dataclass(frozen=True, slots=True)
class SettlementOutcome:
    """Result of settling, releasing, or marking unknown an active budget reservation."""

    reservation: BudgetReservationRecord
    usage_record: ModelUsageRecord
    primary_account: BudgetAccountSummary


def budget_account_row_to_dto(row: BudgetAccountModel) -> BudgetAccountSummary:
    """Project `BudgetAccountModel` row to canonical `BudgetAccountSummary` DTO."""
    cur = row.currency
    cap = Decimal(row.cost_cap).quantize(NUMERIC_QUANT)
    res = Decimal(row.reserved_cost).quantize(NUMERIC_QUANT)
    stl = Decimal(row.settled_cost).quantize(NUMERIC_QUANT)
    unk = Decimal(row.unknown_cost).quantize(NUMERIC_QUANT)
    rem = max(ZERO_DECIMAL, (cap - res - stl - unk).quantize(NUMERIC_QUANT))
    return BudgetAccountSummary(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        scope_kind=cast(BudgetScopeKind, row.scope_kind),
        scope_key=row.scope_key,
        currency=cur,
        cost_cap=Money(amount=cap, currency=cur),
        reserved_cost=Money(amount=res, currency=cur),
        settled_cost=Money(amount=stl, currency=cur),
        unknown_cost=Money(amount=unk, currency=cur),
        remaining_cost=Money(amount=rem, currency=cur),
        token_cap=row.token_cap,
        reserved_tokens=row.reserved_tokens,
        settled_tokens=row.settled_tokens,
        unknown_tokens=row.unknown_tokens,
        call_cap=row.call_cap,
        reserved_calls=row.reserved_calls,
        settled_calls=row.settled_calls,
        unknown_calls=row.unknown_calls,
        max_patch_attempts=row.max_patch_attempts,
        patch_attempts_used=row.patch_attempts_used,
        max_wall_seconds=row.max_wall_seconds,
        window_started_at=row.window_started_at,
        window_ends_at=row.window_ends_at,
        cancelled_at=row.cancelled_at,
    )


def reservation_row_to_dto(row: BudgetReservationModel) -> BudgetReservationRecord:
    """Project `BudgetReservationModel` row to canonical `BudgetReservationRecord` DTO."""
    cur = row.currency
    res_amt = Decimal(row.reserved_cost).quantize(NUMERIC_QUANT)
    stl_amt = (
        Decimal(row.settled_cost).quantize(NUMERIC_QUANT) if row.settled_cost is not None else None
    )
    return BudgetReservationRecord(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        budget_account_id=row.budget_account_id,
        repair_id=row.repair_id,
        model_id=validate_supported_meta_model_id(row.model_id),
        pricing_revision=row.pricing_revision,
        status=cast(BudgetReservationStatus, row.status),
        estimated_input_tokens=row.estimated_input_tokens,
        max_output_tokens=row.max_output_tokens,
        actual_input_tokens=row.actual_input_tokens,
        actual_output_tokens=row.actual_output_tokens,
        reserved_cost=Money(amount=res_amt, currency=cur),
        settled_cost=Money(amount=stl_amt, currency=cur) if stl_amt is not None else None,
        currency=cur,
        provider_request_id=row.provider_request_id,
        prompt_redacted_digest=row.prompt_redacted_digest,
        response_redacted_digest=row.response_redacted_digest,
        late_after_cancel=row.late_after_cancel,
        correlation_id=row.correlation_id,
    )


def usage_row_to_dto(row: UsageLedgerModel) -> ModelUsageRecord:
    """Project `UsageLedgerModel` row to canonical `S-17` `ModelUsageRecord` DTO."""
    cur = row.currency
    est_amt = Decimal(row.estimated_cost).quantize(NUMERIC_QUANT)
    stl_amt = (
        Decimal(row.settled_cost).quantize(NUMERIC_QUANT) if row.settled_cost is not None else None
    )
    return ModelUsageRecord(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        reservation_id=row.reservation_id,
        provider_request_id=row.provider_request_id,
        model_id=row.model_id,
        input_tokens=row.input_tokens,
        output_tokens=row.output_tokens,
        estimated_cost=Money(amount=est_amt, currency=cur),
        settled_cost=Money(amount=stl_amt, currency=cur) if stl_amt is not None else None,
        currency=cur,
        pricing_revision=row.pricing_revision,
        status=cast(UsageStatus, row.status),
    )


class AtomicBudgetLedger:
    """PostgreSQL `SELECT ... FOR UPDATE` token/call/attempt/walltime/cost budget ledger."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        redactor: Redactor | None = None,
        clock: Callable[[], datetime] = _default_utc_clock,
    ) -> None:
        self._session_factory = session_factory
        self._redactor = redactor if redactor is not None else DEFAULT_REDACTOR
        self._clock = clock

    async def ensure_workspace_daily_account_in_tx(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        policy: BudgetPolicyDefaults,
        sync_caps: bool = False,
        now: datetime | None = None,
    ) -> BudgetAccountModel:
        """Create or fetch today's UTC `workspace_daily` budget account inside an active tx."""
        ref_now = now.astimezone(UTC) if now is not None else self._clock().astimezone(UTC)
        day_start = datetime(ref_now.year, ref_now.month, ref_now.day, tzinfo=UTC)
        day_end = day_start + timedelta(days=1)
        scope_key = f"daily:{day_start.strftime('%Y-%m-%d')}"
        daily_cap = ensure_strict_decimal(policy.daily_workspace_cap.amount)
        token_cap = max(policy.max_tokens_per_session * 20, 1_000_000)
        call_cap = max(policy.max_calls_per_session * 20, 500)
        patch_cap = max(policy.max_patch_attempts * 25, 50)

        stmt = (
            pg_insert(BudgetAccountModel)
            .values(
                id=new_uuid7(now=ref_now),
                workspace_id=workspace_id,
                repository_id=None,
                repair_id=None,
                scope_kind="workspace_daily",
                scope_key=scope_key,
                currency=policy.daily_workspace_cap.currency,
                cost_cap=daily_cap,
                reserved_cost=ZERO_DECIMAL,
                settled_cost=ZERO_DECIMAL,
                unknown_cost=ZERO_DECIMAL,
                token_cap=token_cap,
                reserved_tokens=0,
                settled_tokens=0,
                unknown_tokens=0,
                call_cap=call_cap,
                reserved_calls=0,
                settled_calls=0,
                unknown_calls=0,
                max_patch_attempts=patch_cap,
                patch_attempts_used=0,
                max_wall_seconds=86_400,
                threshold_alert_emitted=False,
                window_started_at=day_start,
                window_ends_at=day_end,
                cancelled_at=None,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            .on_conflict_do_nothing(constraint="uq_budget_accounts_ws_scope_kind_key")
        )
        await session.execute(stmt)

        row = await session.scalar(
            select(BudgetAccountModel)
            .where(
                BudgetAccountModel.workspace_id == workspace_id,
                BudgetAccountModel.scope_kind == "workspace_daily",
                BudgetAccountModel.scope_key == scope_key,
            )
            .with_for_update()
        )
        if row is None:
            raise NotFoundError(
                code="budget_account_not_found",
                detail="Workspace daily budget account could not be initialized.",
            )
        if sync_caps and row.currency == policy.daily_workspace_cap.currency:
            if row.reserved_calls > 0:
                min_active_cost = (
                    Decimal(row.reserved_cost)
                    + Decimal(row.settled_cost)
                    + Decimal(row.unknown_cost)
                )
                if daily_cap < min_active_cost:
                    raise ConflictError(
                        code="budget_cap_below_active_reservations",
                        detail=(
                            "Cannot lower daily_workspace_cap below active in-flight "
                            "reservations; wait for in-flight calls to settle or cancel first."
                        ),
                    )
            row.cost_cap = daily_cap
            row.token_cap = max(
                token_cap,
                row.reserved_tokens + row.settled_tokens + row.unknown_tokens,
            )
            row.call_cap = max(call_cap, row.reserved_calls + row.settled_calls + row.unknown_calls)
            row.version += 1
            row.updated_at = ref_now
            await session.flush()
        return row

    async def ensure_repair_session_account(
        self,
        *,
        workspace_id: str,
        repair_id: str,
        policy: BudgetPolicyDefaults,
        repository_id: str | None = None,
        now: datetime | None = None,
    ) -> BudgetAccountSummary:
        """Create or fetch an `NFR-06` per-repair-session budget account."""
        ref_now = now.astimezone(UTC) if now is not None else self._clock().astimezone(UTC)
        scope_key = f"repair:{repair_id}"
        session_cap = ensure_strict_decimal(policy.max_cost_per_session.amount)
        ends_at = ref_now + timedelta(seconds=policy.max_wall_seconds)

        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            stmt = (
                pg_insert(BudgetAccountModel)
                .values(
                    id=new_uuid7(now=ref_now),
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    scope_kind="repair_session",
                    scope_key=scope_key,
                    currency=policy.max_cost_per_session.currency,
                    cost_cap=session_cap,
                    reserved_cost=ZERO_DECIMAL,
                    settled_cost=ZERO_DECIMAL,
                    unknown_cost=ZERO_DECIMAL,
                    token_cap=policy.max_tokens_per_session,
                    reserved_tokens=0,
                    settled_tokens=0,
                    unknown_tokens=0,
                    call_cap=policy.max_calls_per_session,
                    reserved_calls=0,
                    settled_calls=0,
                    unknown_calls=0,
                    max_patch_attempts=policy.max_patch_attempts,
                    patch_attempts_used=0,
                    max_wall_seconds=policy.max_wall_seconds,
                    threshold_alert_emitted=False,
                    window_started_at=ref_now,
                    window_ends_at=ends_at,
                    cancelled_at=None,
                    version=1,
                    created_at=ref_now,
                    updated_at=ref_now,
                )
                .on_conflict_do_nothing(constraint="uq_budget_accounts_ws_scope_kind_key")
            )
            await db.execute(stmt)
            row = await db.scalar(
                select(BudgetAccountModel).where(
                    BudgetAccountModel.workspace_id == workspace_id,
                    BudgetAccountModel.scope_kind == "repair_session",
                    BudgetAccountModel.scope_key == scope_key,
                )
            )
            if row is None:
                raise NotFoundError(
                    code="budget_account_not_found",
                    detail="Repair session budget account could not be initialized.",
                )
            return budget_account_row_to_dto(row)

    async def create_probe_account_in_tx(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        probe_key: str,
        max_cost: Money,
        max_tokens: int,
        now: datetime | None = None,
    ) -> BudgetAccountModel:
        """Create a single-call `model_probe` budget account bounded by explicit `max_cost`."""
        ref_now = now.astimezone(UTC) if now is not None else self._clock().astimezone(UTC)
        cap_dec = ensure_strict_decimal(max_cost.amount)
        row = BudgetAccountModel(
            id=new_uuid7(now=ref_now),
            workspace_id=workspace_id,
            repository_id=None,
            repair_id=None,
            scope_kind="model_probe",
            scope_key=f"probe:{probe_key}",
            currency=max_cost.currency,
            cost_cap=cap_dec,
            reserved_cost=ZERO_DECIMAL,
            settled_cost=ZERO_DECIMAL,
            unknown_cost=ZERO_DECIMAL,
            token_cap=max(256, max_tokens),
            reserved_tokens=0,
            settled_tokens=0,
            unknown_tokens=0,
            call_cap=1,
            reserved_calls=0,
            settled_calls=0,
            unknown_calls=0,
            max_patch_attempts=1,
            patch_attempts_used=0,
            max_wall_seconds=120,
            threshold_alert_emitted=False,
            window_started_at=ref_now,
            window_ends_at=ref_now + timedelta(seconds=120),
            cancelled_at=None,
            version=1,
            created_at=ref_now,
            updated_at=ref_now,
        )
        session.add(row)
        await session.flush()
        return row

    async def _emit_budget_exceeded_event(
        self,
        session: AsyncSession,
        *,
        account: BudgetAccountModel,
        reason_code: str,
        correlation_id: str,
        now: datetime,
    ) -> None:
        envelope = EventEnvelope(
            event_id=new_uuid7(now=now),
            type="usage.budget.exceeded",
            occurred_at=now,
            workspace_id=account.workspace_id,
            repository_id=account.repository_id,
            session_id=account.repair_id,
            aggregate_id=account.id,
            aggregate_version=account.version,
            correlation_id=correlation_id,
            payload=BudgetEventPayload(
                budget_id=account.id,
                reason_code=reason_code,
            ),
        )
        await enqueue_outbox_event(session, envelope, now=now)

    async def reserve_for_call(
        self,
        *,
        workspace_id: str,
        primary_account_id: str,
        secondary_account_id: str | None = None,
        consent_id: str,
        model_id: str,
        pricing: ModelPricingRate,
        estimated_input_tokens: int,
        max_output_tokens: int,
        prompt_redacted_digest: str,
        correlation_id: str,
        actor_type: AuditActorType = "service",
        actor_id: str = "meta-inference-broker",
        repository_id: str | None = None,
        repair_id: str | None = None,
        alert_threshold_percent: int = 80,
        now: datetime | None = None,
    ) -> BudgetReservationRecord:
        """Atomically lock budget account(s) `FOR UPDATE` and reserve worst-case token/cost."""
        del alert_threshold_percent
        validated_model = validate_supported_meta_model_id(model_id)
        worst_cost_money = compute_exact_token_cost(
            input_tokens=estimated_input_tokens,
            output_tokens=max_output_tokens,
            pricing=pricing,
        )
        worst_cost = ensure_strict_decimal(worst_cost_money.amount)
        worst_tokens = estimated_input_tokens + max_output_tokens
        ref_now = now.astimezone(UTC) if now is not None else self._clock().astimezone(UTC)

        target_ids = sorted(
            {
                primary_account_id,
                *([secondary_account_id] if secondary_account_id else []),
            }
        )

        denial_error: BudgetExceededError | ConflictError | None = None

        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            locked_rows = (
                await db.scalars(
                    select(BudgetAccountModel)
                    .where(
                        BudgetAccountModel.workspace_id == workspace_id,
                        BudgetAccountModel.id.in_(target_ids),
                    )
                    .order_by(BudgetAccountModel.id.asc())
                    .with_for_update()
                )
            ).all()
            by_id = {r.id: r for r in locked_rows}
            if len(by_id) != len(target_ids):
                raise NotFoundError(
                    code="budget_account_not_found",
                    detail="Referenced budget account does not exist in workspace.",
                )

            ordered_check = [by_id[primary_account_id]]
            if secondary_account_id and secondary_account_id != primary_account_id:
                ordered_check.append(by_id[secondary_account_id])

            for acct in ordered_check:
                if acct.cancelled_at is not None:
                    denial_error = ConflictError(
                        code="budget_session_cancelled",
                        detail=(
                            f"Budget account '{acct.scope_key}' has been cancelled; "
                            "subsequent outbound model calls are blocked."
                        ),
                    )
                    await append_audit_entry(
                        db,
                        actor_type=actor_type,
                        actor_id=actor_id,
                        action="inference.budget.reserve",
                        target=f"budget_account:{acct.id}",
                        decision="deny",
                        reason_code="budget_session_cancelled",
                        correlation_id=correlation_id,
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        occurred_at=ref_now,
                        redactor=self._redactor,
                    )
                    break

                if acct.currency != worst_cost_money.currency:
                    denial_error = ConflictError(
                        code="budget_currency_mismatch",
                        detail=(
                            f"Budget account currency {acct.currency!r} does not match "
                            f"model pricing currency {worst_cost_money.currency!r}."
                        ),
                    )
                    break

                if acct.window_ends_at is not None and ref_now > acct.window_ends_at:
                    acct.version += 1
                    acct.updated_at = ref_now
                    await self._emit_budget_exceeded_event(
                        db,
                        account=acct,
                        reason_code="session_walltime_exceeded",
                        correlation_id=correlation_id,
                        now=ref_now,
                    )
                    await append_audit_entry(
                        db,
                        actor_type=actor_type,
                        actor_id=actor_id,
                        action="inference.budget.reserve",
                        target=f"budget_account:{acct.id}",
                        decision="deny",
                        reason_code="session_walltime_exceeded",
                        correlation_id=correlation_id,
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        occurred_at=ref_now,
                        redactor=self._redactor,
                    )
                    denial_error = BudgetExceededError(
                        code="budget_walltime_exceeded",
                        detail=f"Budget window walltime expired for '{acct.scope_key}'.",
                        budget_account_id=acct.id,
                    )
                    break

                acct_cap = Decimal(acct.cost_cap).quantize(NUMERIC_QUANT)
                if acct_cap <= ZERO_DECIMAL:
                    acct.version += 1
                    acct.updated_at = ref_now
                    await self._emit_budget_exceeded_event(
                        db,
                        account=acct,
                        reason_code="budget_zero",
                        correlation_id=correlation_id,
                        now=ref_now,
                    )
                    await append_audit_entry(
                        db,
                        actor_type=actor_type,
                        actor_id=actor_id,
                        action="inference.budget.reserve",
                        target=f"budget_account:{acct.id}",
                        decision="deny",
                        reason_code="budget_zero",
                        correlation_id=correlation_id,
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        occurred_at=ref_now,
                        redactor=self._redactor,
                    )
                    denial_error = BudgetExceededError(
                        code="budget_zero",
                        detail=f"Budget cap is $0.00 for '{acct.scope_key}'; inference is blocked.",
                        budget_account_id=acct.id,
                    )
                    break

                projected_calls = acct.reserved_calls + acct.settled_calls + acct.unknown_calls + 1
                if projected_calls > acct.call_cap:
                    acct.version += 1
                    acct.updated_at = ref_now
                    await self._emit_budget_exceeded_event(
                        db,
                        account=acct,
                        reason_code="call_cap_exceeded",
                        correlation_id=correlation_id,
                        now=ref_now,
                    )
                    await append_audit_entry(
                        db,
                        actor_type=actor_type,
                        actor_id=actor_id,
                        action="inference.budget.reserve",
                        target=f"budget_account:{acct.id}",
                        decision="deny",
                        reason_code="call_cap_exceeded",
                        correlation_id=correlation_id,
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        occurred_at=ref_now,
                        redactor=self._redactor,
                    )
                    denial_error = BudgetExceededError(
                        code="budget_call_cap_exceeded",
                        detail=(
                            f"Model call ceiling ({acct.call_cap}) reached for '{acct.scope_key}'."
                        ),
                        budget_account_id=acct.id,
                    )
                    break

                projected_tokens = (
                    acct.reserved_tokens + acct.settled_tokens + acct.unknown_tokens + worst_tokens
                )
                if projected_tokens > acct.token_cap:
                    acct.version += 1
                    acct.updated_at = ref_now
                    await self._emit_budget_exceeded_event(
                        db,
                        account=acct,
                        reason_code="token_cap_exceeded",
                        correlation_id=correlation_id,
                        now=ref_now,
                    )
                    await append_audit_entry(
                        db,
                        actor_type=actor_type,
                        actor_id=actor_id,
                        action="inference.budget.reserve",
                        target=f"budget_account:{acct.id}",
                        decision="deny",
                        reason_code="token_cap_exceeded",
                        correlation_id=correlation_id,
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        occurred_at=ref_now,
                        redactor=self._redactor,
                    )
                    denial_error = BudgetExceededError(
                        code="budget_token_cap_exceeded",
                        detail=(
                            f"Token budget ceiling ({acct.token_cap}) exceeded for "
                            f"'{acct.scope_key}'."
                        ),
                        budget_account_id=acct.id,
                    )
                    break

                projected_cost = (
                    Decimal(acct.reserved_cost)
                    + Decimal(acct.settled_cost)
                    + Decimal(acct.unknown_cost)
                    + worst_cost
                ).quantize(NUMERIC_QUANT)
                if projected_cost > acct_cap:
                    acct.version += 1
                    acct.updated_at = ref_now
                    await self._emit_budget_exceeded_event(
                        db,
                        account=acct,
                        reason_code="cost_cap_exceeded",
                        correlation_id=correlation_id,
                        now=ref_now,
                    )
                    await append_audit_entry(
                        db,
                        actor_type=actor_type,
                        actor_id=actor_id,
                        action="inference.budget.reserve",
                        target=f"budget_account:{acct.id}",
                        decision="deny",
                        reason_code="cost_cap_exceeded",
                        correlation_id=correlation_id,
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        occurred_at=ref_now,
                        redactor=self._redactor,
                    )
                    denial_error = BudgetExceededError(
                        code="budget_cost_cap_exceeded",
                        detail=(
                            f"Worst-case call reservation ({format(worst_cost, 'f')} "
                            f"{acct.currency}) exceeds remaining cap on '{acct.scope_key}'."
                        ),
                        budget_account_id=acct.id,
                    )
                    break

            if denial_error is None:
                for acct in ordered_check:
                    acct.reserved_cost = (Decimal(acct.reserved_cost) + worst_cost).quantize(
                        NUMERIC_QUANT
                    )
                    acct.reserved_tokens += worst_tokens
                    acct.reserved_calls += 1
                    acct.version += 1
                    acct.updated_at = ref_now

                res_row = BudgetReservationModel(
                    id=new_uuid7(now=ref_now),
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    budget_account_id=primary_account_id,
                    secondary_budget_account_id=(
                        secondary_account_id
                        if secondary_account_id and secondary_account_id != primary_account_id
                        else None
                    ),
                    consent_id=consent_id,
                    model_id=validated_model,
                    pricing_revision=pricing.pricing_revision,
                    status="reserved",
                    estimated_input_tokens=estimated_input_tokens,
                    max_output_tokens=max_output_tokens,
                    actual_input_tokens=None,
                    actual_output_tokens=None,
                    reserved_cost=worst_cost,
                    settled_cost=None,
                    currency=worst_cost_money.currency,
                    provider_request_id=None,
                    prompt_redacted_digest=prompt_redacted_digest,
                    response_redacted_digest=None,
                    tool_call_digests_json=[],
                    late_after_cancel=False,
                    correlation_id=correlation_id,
                    version=1,
                    created_at=ref_now,
                    updated_at=ref_now,
                )
                db.add(res_row)
                await db.flush()
                dto = reservation_row_to_dto(res_row)

        if denial_error is not None:
            raise denial_error
        return dto

    async def settle_reservation(
        self,
        *,
        workspace_id: str,
        reservation_id: str,
        pricing: ModelPricingRate,
        actual_input_tokens: int,
        actual_output_tokens: int,
        provider_request_id: str | None,
        response_redacted_digest: str | None,
        tool_call_digests: list[str] | None = None,
        alert_threshold_percent: int = 80,
        actor_type: AuditActorType = "service",
        actor_id: str = "meta-inference-broker",
        now: datetime | None = None,
    ) -> SettlementOutcome:
        """Atomically settle exact token usage & release unused worst-case delta."""
        settled_money = compute_exact_token_cost(
            input_tokens=actual_input_tokens,
            output_tokens=actual_output_tokens,
            pricing=pricing,
        )
        settled_dec = ensure_strict_decimal(settled_money.amount)
        actual_total_tokens = actual_input_tokens + actual_output_tokens
        ref_now = now.astimezone(UTC) if now is not None else self._clock().astimezone(UTC)

        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            res_row = await db.scalar(
                select(BudgetReservationModel)
                .where(
                    BudgetReservationModel.workspace_id == workspace_id,
                    BudgetReservationModel.id == reservation_id,
                )
                .with_for_update()
            )
            if res_row is None:
                raise NotFoundError(
                    code="budget_reservation_not_found",
                    detail="Budget reservation was not found in active workspace.",
                )
            if res_row.status != "reserved":
                raise ConflictError(
                    code="reservation_already_finalized",
                    detail=(
                        f"Reservation {reservation_id!r} is already in status {res_row.status!r}."
                    ),
                )

            acct_ids = sorted(
                {
                    res_row.budget_account_id,
                    *(
                        [res_row.secondary_budget_account_id]
                        if res_row.secondary_budget_account_id
                        else []
                    ),
                }
            )
            locked_accts = (
                await db.scalars(
                    select(BudgetAccountModel)
                    .where(
                        BudgetAccountModel.workspace_id == workspace_id,
                        BudgetAccountModel.id.in_(acct_ids),
                    )
                    .order_by(BudgetAccountModel.id.asc())
                    .with_for_update()
                )
            ).all()
            acct_map = {a.id: a for a in locked_accts}
            primary_acct = acct_map[res_row.budget_account_id]

            reserved_dec = Decimal(res_row.reserved_cost).quantize(NUMERIC_QUANT)
            reserved_toks = res_row.estimated_input_tokens + res_row.max_output_tokens
            late_cancelled = any(a.cancelled_at is not None for a in locked_accts)

            for acct in locked_accts:
                acct.reserved_cost = max(
                    ZERO_DECIMAL,
                    (Decimal(acct.reserved_cost) - reserved_dec).quantize(NUMERIC_QUANT),
                )
                acct.reserved_tokens = max(0, acct.reserved_tokens - reserved_toks)
                acct.reserved_calls = max(0, acct.reserved_calls - 1)
                # Cap settled addition if another in-flight call is still reserved so DB check holds
                effective_settled_add = settled_dec
                if acct.reserved_calls > 0:
                    headroom = max(
                        ZERO_DECIMAL,
                        (
                            Decimal(acct.cost_cap)
                            - Decimal(acct.reserved_cost)
                            - Decimal(acct.settled_cost)
                            - Decimal(acct.unknown_cost)
                        ).quantize(NUMERIC_QUANT),
                    )
                    effective_settled_add = min(settled_dec, headroom)
                acct.settled_cost = (Decimal(acct.settled_cost) + effective_settled_add).quantize(
                    NUMERIC_QUANT
                )
                acct.settled_tokens += actual_total_tokens
                acct.settled_calls += 1
                acct.version += 1
                acct.updated_at = ref_now

                cap_dec = Decimal(acct.cost_cap).quantize(NUMERIC_QUANT)
                committed_spend = (
                    Decimal(acct.settled_cost) + Decimal(acct.unknown_cost)
                ).quantize(NUMERIC_QUANT)
                if (
                    not acct.threshold_alert_emitted
                    and cap_dec > ZERO_DECIMAL
                    and (committed_spend * ONE_HUNDRED)
                    >= (cap_dec * Decimal(alert_threshold_percent))
                ):
                    acct.threshold_alert_emitted = True
                    await self._emit_budget_exceeded_event(
                        db,
                        account=acct,
                        reason_code="budget_threshold_reached",
                        correlation_id=res_row.correlation_id,
                        now=ref_now,
                    )

            res_row.status = "settled"
            res_row.actual_input_tokens = actual_input_tokens
            res_row.actual_output_tokens = actual_output_tokens
            res_row.settled_cost = settled_dec
            res_row.provider_request_id = provider_request_id
            res_row.response_redacted_digest = response_redacted_digest
            res_row.tool_call_digests_json = list(tool_call_digests or [])
            res_row.late_after_cancel = late_cancelled
            res_row.version += 1
            res_row.updated_at = ref_now

            usage_row = UsageLedgerModel(
                id=new_uuid7(now=ref_now),
                workspace_id=workspace_id,
                repository_id=res_row.repository_id,
                repair_id=res_row.repair_id,
                reservation_id=res_row.id,
                provider_request_id=provider_request_id,
                model_id=res_row.model_id,
                input_tokens=actual_input_tokens,
                output_tokens=actual_output_tokens,
                estimated_cost=reserved_dec,
                settled_cost=settled_dec,
                currency=res_row.currency,
                pricing_revision=res_row.pricing_revision,
                status="settled",
                correlation_id=res_row.correlation_id,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(usage_row)
            await db.flush()

            await append_audit_entry(
                db,
                actor_type=actor_type,
                actor_id=actor_id,
                action="inference.budget.settle",
                target=f"reservation:{res_row.id}",
                decision="allow",
                reason_code="late_after_cancel_settled" if late_cancelled else "usage_settled",
                correlation_id=res_row.correlation_id,
                workspace_id=workspace_id,
                repository_id=res_row.repository_id,
                metadata={
                    "model_id": res_row.model_id,
                    "input_tokens": actual_input_tokens,
                    "output_tokens": actual_output_tokens,
                    "settled_cost": format(settled_dec, "f"),
                    "currency": res_row.currency,
                    "late_after_cancel": late_cancelled,
                },
                occurred_at=ref_now,
                redactor=self._redactor,
            )

            return SettlementOutcome(
                reservation=reservation_row_to_dto(res_row),
                usage_record=usage_row_to_dto(usage_row),
                primary_account=budget_account_row_to_dto(primary_acct),
            )

    async def mark_unknown_outcome(
        self,
        *,
        workspace_id: str,
        reservation_id: str,
        reason_code: str,
        provider_request_id: str | None = None,
        actor_type: AuditActorType = "service",
        actor_id: str = "meta-inference-broker",
        now: datetime | None = None,
    ) -> SettlementOutcome:
        """Retain full worst-case reserved spend on ambiguous failure (`SEC-033`)."""
        ref_now = now.astimezone(UTC) if now is not None else self._clock().astimezone(UTC)

        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            res_row = await db.scalar(
                select(BudgetReservationModel)
                .where(
                    BudgetReservationModel.workspace_id == workspace_id,
                    BudgetReservationModel.id == reservation_id,
                )
                .with_for_update()
            )
            if res_row is None:
                raise NotFoundError(
                    code="budget_reservation_not_found",
                    detail="Budget reservation was not found in active workspace.",
                )
            if res_row.status != "reserved":
                raise ConflictError(
                    code="reservation_already_finalized",
                    detail=(
                        f"Reservation {reservation_id!r} is already in status {res_row.status!r}."
                    ),
                )

            acct_ids = sorted(
                {
                    res_row.budget_account_id,
                    *(
                        [res_row.secondary_budget_account_id]
                        if res_row.secondary_budget_account_id
                        else []
                    ),
                }
            )
            locked_accts = (
                await db.scalars(
                    select(BudgetAccountModel)
                    .where(
                        BudgetAccountModel.workspace_id == workspace_id,
                        BudgetAccountModel.id.in_(acct_ids),
                    )
                    .order_by(BudgetAccountModel.id.asc())
                    .with_for_update()
                )
            ).all()
            acct_map = {a.id: a for a in locked_accts}
            primary_acct = acct_map[res_row.budget_account_id]

            reserved_dec = Decimal(res_row.reserved_cost).quantize(NUMERIC_QUANT)
            reserved_toks = res_row.estimated_input_tokens + res_row.max_output_tokens
            late_cancelled = any(a.cancelled_at is not None for a in locked_accts)

            for acct in locked_accts:
                acct.reserved_cost = max(
                    ZERO_DECIMAL,
                    (Decimal(acct.reserved_cost) - reserved_dec).quantize(NUMERIC_QUANT),
                )
                acct.unknown_cost = (Decimal(acct.unknown_cost) + reserved_dec).quantize(
                    NUMERIC_QUANT
                )
                acct.reserved_tokens = max(0, acct.reserved_tokens - reserved_toks)
                acct.unknown_tokens += reserved_toks
                acct.reserved_calls = max(0, acct.reserved_calls - 1)
                acct.unknown_calls += 1
                acct.version += 1
                acct.updated_at = ref_now

            res_row.status = "unknown_outcome"
            res_row.actual_input_tokens = None
            res_row.actual_output_tokens = None
            res_row.settled_cost = None
            res_row.provider_request_id = provider_request_id
            res_row.late_after_cancel = late_cancelled
            res_row.version += 1
            res_row.updated_at = ref_now

            usage_row = UsageLedgerModel(
                id=new_uuid7(now=ref_now),
                workspace_id=workspace_id,
                repository_id=res_row.repository_id,
                repair_id=res_row.repair_id,
                reservation_id=res_row.id,
                provider_request_id=provider_request_id,
                model_id=res_row.model_id,
                input_tokens=None,
                output_tokens=None,
                estimated_cost=reserved_dec,
                settled_cost=None,
                currency=res_row.currency,
                pricing_revision=res_row.pricing_revision,
                status="unknown",
                correlation_id=res_row.correlation_id,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(usage_row)
            await db.flush()

            await append_audit_entry(
                db,
                actor_type=actor_type,
                actor_id=actor_id,
                action="inference.budget.unknown_outcome",
                target=f"reservation:{res_row.id}",
                decision="reconcile",
                reason_code=reason_code,
                correlation_id=res_row.correlation_id,
                workspace_id=workspace_id,
                repository_id=res_row.repository_id,
                metadata={
                    "model_id": res_row.model_id,
                    "retained_worst_case_cost": format(reserved_dec, "f"),
                    "currency": res_row.currency,
                },
                occurred_at=ref_now,
                redactor=self._redactor,
            )

            return SettlementOutcome(
                reservation=reservation_row_to_dto(res_row),
                usage_record=usage_row_to_dto(usage_row),
                primary_account=budget_account_row_to_dto(primary_acct),
            )

    async def release_unexecuted_reservation(
        self,
        *,
        workspace_id: str,
        reservation_id: str,
        reason_code: str,
        usage_status: Literal["released", "failed"] = "released",
        provider_request_id: str | None = None,
        actor_type: AuditActorType = "service",
        actor_id: str = "meta-inference-broker",
        now: datetime | None = None,
    ) -> SettlementOutcome:
        """Release a reservation ONLY when verified that zero upstream inference tokens ran."""
        ref_now = now.astimezone(UTC) if now is not None else self._clock().astimezone(UTC)

        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            res_row = await db.scalar(
                select(BudgetReservationModel)
                .where(
                    BudgetReservationModel.workspace_id == workspace_id,
                    BudgetReservationModel.id == reservation_id,
                )
                .with_for_update()
            )
            if res_row is None:
                raise NotFoundError(
                    code="budget_reservation_not_found",
                    detail="Budget reservation was not found in active workspace.",
                )
            if res_row.status != "reserved":
                raise ConflictError(
                    code="reservation_already_finalized",
                    detail=(
                        f"Reservation {reservation_id!r} is already in status {res_row.status!r}."
                    ),
                )

            acct_ids = sorted(
                {
                    res_row.budget_account_id,
                    *(
                        [res_row.secondary_budget_account_id]
                        if res_row.secondary_budget_account_id
                        else []
                    ),
                }
            )
            locked_accts = (
                await db.scalars(
                    select(BudgetAccountModel)
                    .where(
                        BudgetAccountModel.workspace_id == workspace_id,
                        BudgetAccountModel.id.in_(acct_ids),
                    )
                    .order_by(BudgetAccountModel.id.asc())
                    .with_for_update()
                )
            ).all()
            acct_map = {a.id: a for a in locked_accts}
            primary_acct = acct_map[res_row.budget_account_id]

            reserved_dec = Decimal(res_row.reserved_cost).quantize(NUMERIC_QUANT)
            reserved_toks = res_row.estimated_input_tokens + res_row.max_output_tokens

            for acct in locked_accts:
                acct.reserved_cost = max(
                    ZERO_DECIMAL,
                    (Decimal(acct.reserved_cost) - reserved_dec).quantize(NUMERIC_QUANT),
                )
                acct.reserved_tokens = max(0, acct.reserved_tokens - reserved_toks)
                acct.reserved_calls = max(0, acct.reserved_calls - 1)
                acct.version += 1
                acct.updated_at = ref_now

            res_row.status = "released"
            res_row.actual_input_tokens = 0
            res_row.actual_output_tokens = 0
            res_row.settled_cost = ZERO_DECIMAL
            res_row.provider_request_id = provider_request_id
            res_row.version += 1
            res_row.updated_at = ref_now

            usage_row = UsageLedgerModel(
                id=new_uuid7(now=ref_now),
                workspace_id=workspace_id,
                repository_id=res_row.repository_id,
                repair_id=res_row.repair_id,
                reservation_id=res_row.id,
                provider_request_id=provider_request_id,
                model_id=res_row.model_id,
                input_tokens=0,
                output_tokens=0,
                estimated_cost=reserved_dec,
                settled_cost=ZERO_DECIMAL,
                currency=res_row.currency,
                pricing_revision=res_row.pricing_revision,
                status=usage_status,
                correlation_id=res_row.correlation_id,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(usage_row)
            await db.flush()

            await append_audit_entry(
                db,
                actor_type=actor_type,
                actor_id=actor_id,
                action="inference.budget.release",
                target=f"reservation:{res_row.id}",
                decision="allow",
                reason_code=reason_code,
                correlation_id=res_row.correlation_id,
                workspace_id=workspace_id,
                repository_id=res_row.repository_id,
                occurred_at=ref_now,
                redactor=self._redactor,
            )

            return SettlementOutcome(
                reservation=reservation_row_to_dto(res_row),
                usage_record=usage_row_to_dto(usage_row),
                primary_account=budget_account_row_to_dto(primary_acct),
            )

    async def record_patch_attempt(
        self,
        *,
        workspace_id: str,
        account_id: str,
        correlation_id: str,
        actor_type: AuditActorType = "service",
        actor_id: str = "meta-inference-broker",
        now: datetime | None = None,
    ) -> BudgetAccountSummary:
        """Atomically enforce & increment `max_patch_attempts` (`NFR-06` default `2`)."""
        ref_now = now.astimezone(UTC) if now is not None else self._clock().astimezone(UTC)
        exceeded: BudgetExceededError | ConflictError | None = None

        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            acct = await db.scalar(
                select(BudgetAccountModel)
                .where(
                    BudgetAccountModel.workspace_id == workspace_id,
                    BudgetAccountModel.id == account_id,
                )
                .with_for_update()
            )
            if acct is None:
                raise NotFoundError(
                    code="budget_account_not_found",
                    detail="Budget account not found in workspace.",
                )
            if acct.cancelled_at is not None:
                exceeded = ConflictError(
                    code="budget_session_cancelled",
                    detail=f"Budget account '{acct.scope_key}' is cancelled.",
                )
            elif acct.patch_attempts_used + 1 > acct.max_patch_attempts:
                acct.version += 1
                acct.updated_at = ref_now
                await self._emit_budget_exceeded_event(
                    db,
                    account=acct,
                    reason_code="patch_attempt_cap_exceeded",
                    correlation_id=correlation_id,
                    now=ref_now,
                )
                await append_audit_entry(
                    db,
                    actor_type=actor_type,
                    actor_id=actor_id,
                    action="inference.budget.patch_attempt",
                    target=f"budget_account:{acct.id}",
                    decision="deny",
                    reason_code="patch_attempt_cap_exceeded",
                    correlation_id=correlation_id,
                    workspace_id=workspace_id,
                    repository_id=acct.repository_id,
                    occurred_at=ref_now,
                    redactor=self._redactor,
                )
                exceeded = BudgetExceededError(
                    code="budget_patch_attempt_cap_exceeded",
                    detail=(
                        f"Patch attempt ceiling ({acct.max_patch_attempts}) reached for "
                        f"'{acct.scope_key}'."
                    ),
                    budget_account_id=acct.id,
                )
            else:
                acct.patch_attempts_used += 1
                acct.version += 1
                acct.updated_at = ref_now
                await db.flush()
                summary = budget_account_row_to_dto(acct)

        if exceeded is not None:
            raise exceeded
        return summary

    async def cancel_budget_account(
        self,
        *,
        workspace_id: str,
        account_id: str,
        correlation_id: str,
        actor_type: AuditActorType = "user",
        actor_id: str = "system",
        now: datetime | None = None,
    ) -> BudgetAccountSummary:
        """Stamp `cancelled_at` atomically so zero subsequent calls reserve budget (`AGT-03`)."""
        ref_now = now.astimezone(UTC) if now is not None else self._clock().astimezone(UTC)
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            acct = await db.scalar(
                select(BudgetAccountModel)
                .where(
                    BudgetAccountModel.workspace_id == workspace_id,
                    BudgetAccountModel.id == account_id,
                )
                .with_for_update()
            )
            if acct is None:
                raise NotFoundError(
                    code="budget_account_not_found",
                    detail="Budget account not found in workspace.",
                )
            if acct.cancelled_at is None:
                acct.cancelled_at = ref_now
                acct.version += 1
                acct.updated_at = ref_now
                await db.flush()
                await append_audit_entry(
                    db,
                    actor_type=actor_type,
                    actor_id=actor_id,
                    action="inference.budget.cancel",
                    target=f"budget_account:{acct.id}",
                    decision="allow",
                    reason_code="session_budget_cancelled",
                    correlation_id=correlation_id,
                    workspace_id=workspace_id,
                    repository_id=acct.repository_id,
                    occurred_at=ref_now,
                    redactor=self._redactor,
                )
            return budget_account_row_to_dto(acct)
