"""Z1-safe PostgreSQL budget account helpers shared by orchestrator, setup, and extensions.

Maintains strict Z1/Z2 boundaries (`control-plane-z1-z2-boundaries` in `pyproject.toml`):
this module imports only canonical contracts, SQLAlchemy, and Z1 DB models, never Z2
secret/inference/publisher brokers.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import ROUND_CEILING, Decimal

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts.models import (
    NFR06_DEFAULT_MAX_CALLS,
    NFR06_DEFAULT_MAX_PATCH_ATTEMPTS,
    NFR06_DEFAULT_MAX_TOKENS,
    NFR06_DEFAULT_MAX_WALL_SECONDS,
    BudgetPolicyDefaults,
)
from py_contracts.primitives import Money, new_uuid7
from red2pr_control.core.errors import ConflictError, NotFoundError
from red2pr_control.db.base import BudgetAccountModel, WorkspaceModelConfigModel

_NUMERIC_QUANT = Decimal("0.000001")
_ZERO_DECIMAL = Decimal("0.000000")


def _quantize_money_amount(value: Decimal | int | str) -> Decimal:
    if isinstance(value, (bool, float)):
        raise TypeError("Binary float or bool is forbidden for monetary budget math")
    dec = value if isinstance(value, Decimal) else Decimal(value)
    if not dec.is_finite() or dec < Decimal("0"):
        raise ValueError("Monetary Decimal must be finite and nonnegative")
    return dec.quantize(_NUMERIC_QUANT, rounding=ROUND_CEILING)


async def resolve_workspace_budget_policy_in_tx(
    db: AsyncSession,
    *,
    workspace_id: str,
    fallback_account: BudgetAccountModel | None = None,
) -> BudgetPolicyDefaults:
    """Resolve `BudgetPolicyDefaults` from `workspace_model_configs` or a fallback account."""
    cfg = await db.scalar(
        select(WorkspaceModelConfigModel).where(
            WorkspaceModelConfigModel.workspace_id == workspace_id
        )
    )
    if cfg is not None and cfg.budget_policy_json:
        return BudgetPolicyDefaults.model_validate(cfg.budget_policy_json)

    if fallback_account is not None:
        currency = fallback_account.currency
        raw_cap = _quantize_money_amount(Decimal(fallback_account.cost_cap))
        if fallback_account.scope_kind == "repair_session":
            session_cap = raw_cap
            daily_cap = max(raw_cap * Decimal("5"), Decimal("25.000000"))
        else:
            session_cap = min(raw_cap, Decimal("5.000000"))
            daily_cap = max(raw_cap, session_cap)
        max_tokens = max(256, min(2_000_000, int(fallback_account.token_cap)))
        max_calls = max(1, min(500, int(fallback_account.call_cap)))
        max_attempts = max(1, min(10, int(fallback_account.max_patch_attempts or 2)))
        max_wall = max(60, min(14_400, int(fallback_account.max_wall_seconds or 1800)))
        return BudgetPolicyDefaults(
            max_calls_per_session=max_calls,
            max_tokens_per_session=max_tokens,
            max_patch_attempts=max_attempts,
            max_wall_seconds=max_wall,
            max_cost_per_session=Money(amount=session_cap, currency=currency),
            daily_workspace_cap=Money(amount=daily_cap, currency=currency),
            alert_threshold_percent=80,
        )

    return BudgetPolicyDefaults(
        max_calls_per_session=NFR06_DEFAULT_MAX_CALLS,
        max_tokens_per_session=NFR06_DEFAULT_MAX_TOKENS,
        max_patch_attempts=NFR06_DEFAULT_MAX_PATCH_ATTEMPTS,
        max_wall_seconds=NFR06_DEFAULT_MAX_WALL_SECONDS,
        max_cost_per_session=Money(amount=Decimal("5.000000"), currency="USD"),
        daily_workspace_cap=Money(amount=Decimal("25.000000"), currency="USD"),
        alert_threshold_percent=80,
    )


async def ensure_workspace_daily_budget_account_in_tx(
    db: AsyncSession,
    *,
    workspace_id: str,
    policy: BudgetPolicyDefaults,
    sync_caps: bool = False,
    now: datetime | None = None,
) -> BudgetAccountModel:
    """Create or fetch today's UTC `workspace_daily` budget account inside an active tx."""
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    day_start = datetime(ref_now.year, ref_now.month, ref_now.day, tzinfo=UTC)
    day_end = day_start + timedelta(days=1)
    scope_key = f"daily:{day_start.strftime('%Y-%m-%d')}"
    daily_cap = _quantize_money_amount(policy.daily_workspace_cap.amount)
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
            reserved_cost=_ZERO_DECIMAL,
            settled_cost=_ZERO_DECIMAL,
            unknown_cost=_ZERO_DECIMAL,
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
    await db.execute(stmt)

    row = await db.scalar(
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
                Decimal(row.reserved_cost) + Decimal(row.settled_cost) + Decimal(row.unknown_cost)
            )
            if daily_cap < min_active_cost:
                raise ConflictError(
                    code="budget_cap_below_active_reservations",
                    detail=(
                        "Cannot lower daily_workspace_cap below active in-flight reservations; "
                        "wait for in-flight calls to settle or cancel first."
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
        await db.flush()
    return row


async def ensure_repair_session_budget_account_in_tx(
    db: AsyncSession,
    *,
    workspace_id: str,
    scope_key: str,
    policy: BudgetPolicyDefaults,
    repository_id: str | None = None,
    repair_id: str | None = None,
    now: datetime | None = None,
) -> BudgetAccountModel:
    """Create or fetch an isolated `NFR-06` `repair_session` budget account inside an active tx."""
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    bounded_scope_key = scope_key.strip()[:120]
    session_cap = _quantize_money_amount(policy.max_cost_per_session.amount)
    ends_at = ref_now + timedelta(seconds=policy.max_wall_seconds)

    stmt = (
        pg_insert(BudgetAccountModel)
        .values(
            id=new_uuid7(now=ref_now),
            workspace_id=workspace_id,
            repository_id=repository_id,
            repair_id=repair_id,
            scope_kind="repair_session",
            scope_key=bounded_scope_key,
            currency=policy.max_cost_per_session.currency,
            cost_cap=session_cap,
            reserved_cost=_ZERO_DECIMAL,
            settled_cost=_ZERO_DECIMAL,
            unknown_cost=_ZERO_DECIMAL,
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
        select(BudgetAccountModel)
        .where(
            BudgetAccountModel.workspace_id == workspace_id,
            BudgetAccountModel.scope_kind == "repair_session",
            BudgetAccountModel.scope_key == bounded_scope_key,
        )
        .with_for_update()
    )
    if row is None:
        raise NotFoundError(
            code="budget_account_not_found",
            detail="Per-session repair budget account could not be initialized.",
        )
    if repair_id is not None and row.repair_id is None:
        row.repair_id = repair_id
        await db.flush()
    return row
