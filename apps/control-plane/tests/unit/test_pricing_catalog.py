from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from red2pr_control.core.egress import EgressPolicyEngine
from red2pr_control.core.pricing_catalog import (
    LiteLlmPricingCatalog,
    parse_litellm_pricing_catalog,
)


def _payload() -> bytes:
    return b'''{
      "meta/muse-spark-1.3": {
        "litellm_provider": "meta",
        "mode": "chat",
        "input_cost_per_token": 0.00000125,
        "output_cost_per_token": 0.0000045,
        "max_input_tokens": 1048576
      },
      "meta/muse-wonder-1.0": {
        "litellm_provider": "meta",
        "mode": "chat",
        "input_cost_per_token": 0.000004,
        "output_cost_per_token": 0.00002
      },
      "other-provider/muse-spark-1.3": {
        "litellm_provider": "other-provider",
        "mode": "chat",
        "input_cost_per_token": 0.00000001,
        "output_cost_per_token": 0.00000002
      }
    }'''


def test_parser_maps_supported_meta_models_and_converts_usd_per_token_to_per_million() -> None:
    snapshot = parse_litellm_pricing_catalog(
        _payload(), fetched_at=datetime(2026, 11, 3, tzinfo=UTC)
    )

    assert set(snapshot.rates) == {"muse-spark-1.3", "muse-wonder-1.0"}
    spark = snapshot.rates["muse-spark-1.3"]
    assert spark.input_per_1m_tokens.amount == Decimal("1.250000")
    assert spark.output_per_1m_tokens.amount == Decimal("4.500000")
    assert spark.pricing_revision == snapshot.revision
    assert spark.pricing_revision.startswith("litellm-")


def test_parser_rejects_unknown_or_zero_pricing_instead_of_treating_it_as_free() -> None:
    payload = b'''{"meta/muse-spark-1.3":{"litellm_provider":"meta","mode":"chat",
      "input_cost_per_token":0,"output_cost_per_token":0}}'''

    with pytest.raises(ValueError, match="no valid supported Meta model prices"):
        parse_litellm_pricing_catalog(payload, fetched_at=datetime.now(tz=UTC))


def test_cache_serves_prices_from_ram_only_inside_the_bounded_stale_window() -> None:
    now = datetime(2026, 11, 3, tzinfo=UTC)
    cache = LiteLlmPricingCatalog(
        egress_policy=EgressPolicyEngine(),
        clock=lambda: now,
    )
    cache._snapshot = parse_litellm_pricing_catalog(_payload(), fetched_at=now)
    cache._last_checked_at = now
    assert cache.current_rates()["muse-spark-1.3"].input_per_1m_tokens.amount == Decimal(
        "1.250000"
    )

    now += timedelta(hours=49)
    assert cache.current_rates() == {}
