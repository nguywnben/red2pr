"""Deterministic repair funnel projection over authoritative U13/U15/U18/U20/U16 ledgers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal


@dataclass(frozen=True)
class AnalyticsSource:
    ingested_runs: int
    eligible_repairs: int
    executed_repairs: int
    confirmed_reproductions: int
    locally_verified_repairs: int
    locally_verified_eligible_publications: int
    observed_publications: int
    remotely_verified_publications: int
    unknown: int
    pending: int
    abstained: int
    usage_rows: int
    settled_costs: dict[str, Decimal]
    estimated_unsettled_costs: dict[str, Decimal]
    unknown_cost_rows_by_currency: dict[str, int]
    usage_rows_by_currency: dict[str, int]
    watermark: datetime


@dataclass(frozen=True)
class FunnelStage:
    key: str
    value: int
    numerator: int | None
    denominator: int | None


@dataclass(frozen=True)
class CurrencyCost:
    currency: str
    settled: Decimal
    estimated_unsettled: Decimal
    total: Decimal
    unknown_rows: int
    usage_rows: int


@dataclass(frozen=True)
class AnalyticsProjection:
    funnel: tuple[FunnelStage, ...]
    local_success_count: int
    remote_success_count: int
    unknown_count: int
    pending_count: int
    abstained_count: int
    usage_rows: int
    costs: tuple[CurrencyCost, ...]
    watermark: datetime


def build_analytics_projection(source: AnalyticsSource) -> AnalyticsProjection:
    """Build eight stage counts and preserve their exact authoritative denominators."""
    stages = (
        FunnelStage("ingested", source.ingested_runs, None, None),
        FunnelStage(
            "eligible", source.eligible_repairs, source.eligible_repairs, source.ingested_runs
        ),
        FunnelStage(
            "executed", source.executed_repairs, source.executed_repairs, source.eligible_repairs
        ),
        FunnelStage(
            "reproduced",
            source.confirmed_reproductions,
            source.confirmed_reproductions,
            source.executed_repairs,
        ),
        FunnelStage(
            "locally_verified",
            source.locally_verified_repairs,
            source.locally_verified_repairs,
            source.confirmed_reproductions,
        ),
        FunnelStage(
            "publication_eligible",
            source.locally_verified_eligible_publications,
            source.locally_verified_eligible_publications,
            source.locally_verified_repairs,
        ),
        FunnelStage(
            "published_observed",
            source.observed_publications,
            source.observed_publications,
            source.locally_verified_eligible_publications,
        ),
        FunnelStage(
            "remotely_verified",
            source.remotely_verified_publications,
            source.remotely_verified_publications,
            source.observed_publications,
        ),
    )
    for stage in stages:
        if stage.value < 0 or (
            stage.denominator is not None and stage.denominator < stage.numerator
        ):
            raise ValueError(f"Invalid authoritative funnel count for {stage.key}.")
    costs: list[CurrencyCost] = []
    currencies = sorted(set(source.settled_costs) | set(source.estimated_unsettled_costs))
    for currency in currencies:
        settled = source.settled_costs.get(currency, Decimal(0))
        estimated = source.estimated_unsettled_costs.get(currency, Decimal(0))
        if settled < 0 or estimated < 0:
            raise ValueError("Cost ledger totals cannot be negative.")
        costs.append(
            CurrencyCost(
                currency=currency,
                settled=settled,
                estimated_unsettled=estimated,
                total=settled + estimated,
                unknown_rows=source.unknown_cost_rows_by_currency.get(currency, 0),
                usage_rows=source.usage_rows_by_currency.get(currency, 0),
            )
        )
    return AnalyticsProjection(
        funnel=stages,
        local_success_count=source.locally_verified_repairs,
        remote_success_count=source.remotely_verified_publications,
        unknown_count=source.unknown,
        pending_count=source.pending,
        abstained_count=source.abstained,
        usage_rows=source.usage_rows,
        costs=tuple(costs),
        watermark=source.watermark,
    )
