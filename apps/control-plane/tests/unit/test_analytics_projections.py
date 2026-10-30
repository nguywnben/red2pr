from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace

import pytest

from red2pr_control.analytics_audit.exporter import csv_safe_value, render_csv, render_json
from red2pr_control.analytics_audit.projections import AnalyticsSource, build_analytics_projection
from red2pr_control.analytics_audit.router import _build_payload

NOW = datetime(2026, 10, 30, tzinfo=UTC)
LATEST_INPUT = datetime(2026, 10, 30, 1, tzinfo=UTC)


def test_funnel_uses_unique_authoritative_sessions_and_separates_local_remote() -> None:
    source = AnalyticsSource(
        ingested_runs=3,
        eligible_repairs=3,
        executed_repairs=2,
        confirmed_reproductions=1,
        locally_verified_repairs=1,
        locally_verified_eligible_publications=1,
        observed_publications=1,
        remotely_verified_publications=0,
        unknown=1,
        pending=1,
        abstained=1,
        usage_rows=4,
        settled_costs={"USD": Decimal("1.250000")},
        estimated_unsettled_costs={"USD": Decimal("0.500000")},
        unknown_cost_rows_by_currency={"USD": 1},
        usage_rows_by_currency={"USD": 4},
        watermark=NOW,
    )

    result = build_analytics_projection(source)

    assert result.funnel[0].value == 3
    assert [(step.numerator, step.denominator) for step in result.funnel[1:]] == [
        (3, 3),
        (2, 3),
        (1, 2),
        (1, 1),
        (1, 1),
        (1, 1),
        (0, 1),
    ]
    assert result.funnel[-1].value == 0
    assert result.local_success_count == 1
    assert result.remote_success_count == 0
    assert result.costs[0].total == Decimal("1.750000")
    assert result.costs[0].unknown_rows == 1
    assert result.watermark == NOW


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r", "\n"])
def test_csv_cell_neutralizes_formula_prefixes(prefix: str) -> None:
    assert csv_safe_value(prefix + "CMD|payload") == "'" + prefix + "CMD|payload"


def test_csv_quotes_separators_and_safe_export_is_valid_csv() -> None:
    payload = [{"repository": '=CMD|x,"y', "value": 2}]
    rendered = render_csv(payload)
    assert rendered == '"repository","value"\r\n"\'=CMD|x,""y","2"\r\n'


def test_json_export_is_deterministic_and_does_not_mutate_payload() -> None:
    payload = {"cost": Decimal("0.300000"), "private": "visible only in authorized scope"}
    first = render_json(payload)
    assert first == render_json(payload)
    assert '"cost":"0.300000"' in first
    assert payload["cost"] == Decimal("0.300000")


def test_anl_01_counts_authoritative_rows_once_and_includes_failed_retry_spend() -> None:
    runs = [
        SimpleNamespace(
            id="run-1", ingestion_state="ingested", repository_id="repo-1", updated_at=NOW
        ),
        SimpleNamespace(
            id="run-2", ingestion_state="ingested", repository_id="repo-2", updated_at=NOW
        ),
        SimpleNamespace(
            id="run-failed", ingestion_state="failed", repository_id="repo-1", updated_at=NOW
        ),
    ]
    repairs = [
        SimpleNamespace(
            id="repair-1",
            ci_run_id="run-1",
            state="remote_verified",
            proof_grade="locally_verified",
            remote_status="passed",
            updated_at=NOW,
        ),
        SimpleNamespace(
            id="repair-2",
            ci_run_id="run-2",
            state="repro_unconfirmed",
            proof_grade="none",
            remote_status=None,
            updated_at=NOW,
        ),
    ]
    reproductions = [
        SimpleNamespace(
            repair_id="repair-1",
            phase="baseline_a",
            status="repro_confirmed",
            created_at=LATEST_INPUT,
        ),
        SimpleNamespace(
            repair_id="repair-2", phase="baseline_a", status="repro_unconfirmed", created_at=NOW
        ),
    ]
    publications = [SimpleNamespace(repair_id="repair-1", status="published", created_at=NOW)]
    approvals = [
        SimpleNamespace(
            repair_id="repair-1", intent_type="publish_draft_pr", status="approved", created_at=NOW
        )
    ]
    usage = [
        SimpleNamespace(
            currency="USD",
            status="settled",
            settled_cost=Decimal("1.25"),
            estimated_cost=Decimal("1.25"),
            created_at=NOW,
        ),
        SimpleNamespace(
            currency="USD",
            status="failed",
            settled_cost=None,
            estimated_cost=Decimal("0.50"),
            created_at=NOW,
        ),
        SimpleNamespace(
            currency="USD",
            status="unknown",
            settled_cost=None,
            estimated_cost=Decimal("0.25"),
            created_at=NOW,
        ),
        SimpleNamespace(
            currency="USD",
            status="released",
            settled_cost=None,
            estimated_cost=Decimal("10.00"),
            created_at=NOW,
        ),
    ]
    empty = ()
    payload = _build_payload(
        (runs, repairs, reproductions, publications, usage, approvals, list(empty), list(empty)),
        workspace_id="workspace-1",
        start=NOW,
        end=NOW,
        repos=frozenset({"repo-1", "repo-2"}),
        now=NOW,
    )

    assert [(row["key"], row["value"]) for row in payload["funnel"]] == [
        ("ingested", 2),
        ("eligible", 2),
        ("executed", 2),
        ("reproduced", 1),
        ("locally_verified", 1),
        ("publication_eligible", 1),
        ("published_observed", 1),
        ("remotely_verified", 1),
    ]
    assert payload["unknown_count"] == 2  # unconfirmed repair + failed ingestion
    assert payload["costs"] == [
        {
            "currency": "USD",
            "settled": "1.25",
            "estimated_unsettled": "0.75",
            "total": "2.00",
            "unknown_rows": 1,
            "usage_rows": 4,
        }
    ]
    assert payload["watermark"] == LATEST_INPUT
