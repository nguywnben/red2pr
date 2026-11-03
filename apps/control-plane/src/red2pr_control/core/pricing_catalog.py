"""Cached LiteLLM model price catalog used for bounded Meta inference budgets.

Source format: https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json
LiteLLM's ``input_cost_per_token`` and ``output_cost_per_token`` values are USD per token;
Red2PR converts them to its canonical per-million-token money contract using Decimal only.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from typing import Any

import httpcore
import httpx

from py_contracts.models import ModelPricingRate, validate_supported_meta_model_id
from py_contracts.primitives import Money
from red2pr_control.core.egress import EgressPolicyEngine, EgressSafeHttpClient
from red2pr_control.core.logging import get_structured_logger

logger = get_structured_logger("red2pr_control.inference.pricing_catalog")

LITELLM_PRICING_URL = (
    "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
)
PRICING_CATALOG_REFRESH_SECONDS = 6 * 60 * 60
PRICING_CATALOG_MAX_STALE = timedelta(hours=48)
PRICING_CATALOG_MAX_BYTES = 32 * 1024 * 1024
_ONE_MILLION = Decimal("1000000")
_MONEY_QUANTUM = Decimal("0.000001")
_LITELLM_KEYS: Mapping[str, str] = {
    "muse-spark-1.3": "meta/muse-spark-1.3",
    "muse-wonder-1.0": "meta/muse-wonder-1.0",
}


@dataclass(frozen=True, slots=True)
class PricingCatalogSnapshot:
    rates: Mapping[str, ModelPricingRate]
    revision: str
    etag: str | None
    fetched_at: datetime


PricingCatalogFetcher = Callable[[str | None], Awaitable[httpx.Response]]


def _strict_decimal(value: Any) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (Decimal, int)):
        raise ValueError("LiteLLM token price must be a JSON number")
    amount = Decimal(value)
    if not amount.is_finite() or amount <= 0:
        raise ValueError("LiteLLM token price must be finite and greater than zero")
    return amount


def parse_litellm_pricing_catalog(
    payload: bytes,
    *,
    fetched_at: datetime,
) -> PricingCatalogSnapshot:
    if not payload or len(payload) > PRICING_CATALOG_MAX_BYTES:
        raise ValueError("LiteLLM pricing catalog is empty or exceeds the size limit")

    def reject_constant(value: str) -> None:
        raise ValueError(f"Invalid JSON numeric constant: {value}")

    try:
        raw = json.loads(payload, parse_float=Decimal, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("LiteLLM pricing catalog is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError("LiteLLM pricing catalog root must be an object")

    revision = f"litellm-{hashlib.sha256(payload).hexdigest()[:20]}"
    rates: dict[str, ModelPricingRate] = {}
    for model_id, catalog_key in _LITELLM_KEYS.items():
        entry = raw.get(catalog_key)
        if not isinstance(entry, dict):
            continue
        if entry.get("litellm_provider") != "meta" or entry.get("mode") != "chat":
            continue
        try:
            input_cost = _strict_decimal(entry.get("input_cost_per_token"))
            output_cost = _strict_decimal(entry.get("output_cost_per_token"))
            input_per_million = (input_cost * _ONE_MILLION).quantize(
                _MONEY_QUANTUM, rounding=ROUND_CEILING
            )
            output_per_million = (output_cost * _ONE_MILLION).quantize(
                _MONEY_QUANTUM, rounding=ROUND_CEILING
            )
            canonical_id = validate_supported_meta_model_id(model_id)
            rates[canonical_id] = ModelPricingRate(
                pricing_revision=revision,
                input_per_1m_tokens=Money(amount=input_per_million, currency="USD"),
                output_per_1m_tokens=Money(amount=output_per_million, currency="USD"),
                configured=True,
            )
        except (ValueError, InvalidOperation, TypeError):
            # A malformed or incomplete model record remains unpriced; never infer zero.
            continue

    if not rates:
        raise ValueError("LiteLLM catalog has no valid supported Meta model prices")
    return PricingCatalogSnapshot(
        rates=rates,
        revision=revision,
        etag=None,
        fetched_at=fetched_at.astimezone(UTC),
    )


class LiteLlmPricingCatalog:
    """Refresh a bounded supported-model subset and serve it from process memory."""

    def __init__(
        self,
        *,
        egress_policy: EgressPolicyEngine,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
        timeout_seconds: float = 10.0,
        fetcher: PricingCatalogFetcher | None = None,
        clock: Callable[[], datetime] | None = None,
        refresh_seconds: int = PRICING_CATALOG_REFRESH_SECONDS,
    ) -> None:
        self._egress_policy = egress_policy
        self._network_backend = network_backend
        self._timeout_seconds = timeout_seconds
        self._fetcher = fetcher
        self._clock = clock or (lambda: datetime.now(tz=UTC))
        self._refresh_seconds = max(60, refresh_seconds)
        self._snapshot: PricingCatalogSnapshot | None = None
        self._last_checked_at: datetime | None = None
        self._refresh_lock = asyncio.Lock()

    def current_rates(self) -> dict[str, ModelPricingRate]:
        snapshot = self._snapshot
        if snapshot is None:
            return {}
        age = self._clock().astimezone(UTC) - (self._last_checked_at or snapshot.fetched_at)
        if age > PRICING_CATALOG_MAX_STALE:
            return {}
        return dict(snapshot.rates)

    async def refresh_once(self) -> None:
        async with self._refresh_lock:
            etag = self._snapshot.etag if self._snapshot is not None else None
            response = await self._fetch(etag)
            now = self._clock().astimezone(UTC)
            if response.status_code == httpx.codes.NOT_MODIFIED:
                if self._snapshot is None:
                    raise ValueError("LiteLLM returned 304 without a cached catalog")
                self._last_checked_at = now
                return
            if response.status_code != httpx.codes.OK:
                raise ValueError(f"LiteLLM pricing catalog returned HTTP {response.status_code}")
            if len(response.content) > PRICING_CATALOG_MAX_BYTES:
                raise ValueError("LiteLLM pricing catalog exceeds the size limit")
            parsed = parse_litellm_pricing_catalog(response.content, fetched_at=now)
            self._snapshot = PricingCatalogSnapshot(
                rates=parsed.rates,
                revision=parsed.revision,
                etag=response.headers.get("etag"),
                fetched_at=parsed.fetched_at,
            )
            self._last_checked_at = now

    async def run_forever(self) -> None:
        while True:
            try:
                await self.refresh_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "LiteLLM pricing catalog refresh failed; retaining bounded cached prices",
                    extra={
                        "event": "pricing_catalog.refresh_failed",
                        "error_type": type(exc).__name__,
                    },
                )
            await asyncio.sleep(self._refresh_seconds)

    async def _fetch(self, etag: str | None) -> httpx.Response:
        if self._fetcher is not None:
            return await self._fetcher(etag)
        headers = {"Accept": "application/json"}
        if etag:
            headers["If-None-Match"] = etag
        async with EgressSafeHttpClient(
            adapter="pricing_catalog",
            policy_engine=self._egress_policy,
            network_backend=self._network_backend,
            timeout_seconds=self._timeout_seconds,
            max_redirects=0,
        ) as client:
            return await client.request("GET", LITELLM_PRICING_URL, headers=headers)


__all__ = [
    "LITELLM_PRICING_URL",
    "PRICING_CATALOG_MAX_STALE",
    "PRICING_CATALOG_REFRESH_SECONDS",
    "LiteLlmPricingCatalog",
    "PricingCatalogSnapshot",
    "parse_litellm_pricing_catalog",
]
