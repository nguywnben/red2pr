"""Consent and capability gates for same-vendor Meta model fallback (U29)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from py_contracts.models import MetaModelId

FallbackReason = Literal["429", "503", "capability_unavailable"]
ALLOWED_FALLBACK_REASONS: frozenset[str] = frozenset(
    {"429", "503", "capability_unavailable"}
)


@dataclass(frozen=True, slots=True)
class FallbackDecision:
    model_id: MetaModelId
    reason: FallbackReason | None


def select_fallback_model(
    *,
    requested_model: MetaModelId,
    primary_model: MetaModelId,
    secondary_model: MetaModelId,
    reason: FallbackReason,
    policy_enabled: bool,
    consent_active: bool,
    secondary_available: bool,
    repository_scope_matches: bool,
) -> FallbackDecision | None:
    """Return a secondary model only when every policy, consent and capability gate passes."""
    if (
        not policy_enabled
        or not consent_active
        or not secondary_available
        or not repository_scope_matches
        or requested_model != primary_model
        or primary_model == secondary_model
        or primary_model not in {"muse-spark-1.3", "muse-wonder-1.0"}
        or secondary_model not in {"muse-spark-1.3", "muse-wonder-1.0"}
        or reason not in ALLOWED_FALLBACK_REASONS
    ):
        return None
    return FallbackDecision(model_id=secondary_model, reason=reason)


def transient_fallback_reason(*, status_code: int) -> FallbackReason | None:
    """Retry only definitive quota/unavailability responses, never ambiguous transport errors."""
    if status_code == 429:
        return "429"
    if status_code == 503:
        return "503"
    return None
