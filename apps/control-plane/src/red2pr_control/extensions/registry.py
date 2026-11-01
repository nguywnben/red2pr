"""Deterministic capability inventory for optional extension modules (W-10)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypeGuard

CapabilityStatus = Literal["enabled", "disabled", "not_configured", "unsupported"]


def is_capability_status(value: str) -> TypeGuard[CapabilityStatus]:
    """Validate a persisted capability status before exposing it in the API."""
    return value in {"enabled", "disabled", "not_configured", "unsupported"}


@dataclass(frozen=True, slots=True)
class ExtensionCapability:
    """Public, non-secret summary of an optional extension's availability."""

    id: str
    status: CapabilityStatus
    reason: str


# Optional capabilities are deliberately closed by default. A module is enabled only by
# an explicit runtime integration, never by UI assumptions or a successful health check.
_DEFAULT_CAPABILITIES: tuple[ExtensionCapability, ...] = (
    ExtensionCapability("iam-03-oidc", "not_configured", "provider_not_configured"),
    ExtensionCapability("src-05-relay", "disabled", "feature_disabled"),
    ExtensionCapability("agt-04-model-fallback", "disabled", "feature_disabled"),
    ExtensionCapability("san-04-fleet-sandbox", "unsupported", "runtime_not_supported"),
    ExtensionCapability("ext-02-mcp", "disabled", "feature_disabled"),
)


def list_capabilities(
    configured_oidc_providers: tuple[str, ...] = (),
    *,
    oidc_status: CapabilityStatus | None = None,
    oidc_reason: str | None = None,
) -> tuple[ExtensionCapability, ...]:
    """Return a stable capability list; OIDC is enabled only when an active provider exists."""
    resolved_status = oidc_status or ("enabled" if configured_oidc_providers else "not_configured")
    resolved_reason = oidc_reason or (
        "provider_probed" if configured_oidc_providers else "provider_not_configured"
    )
    return (
        ExtensionCapability("iam-03-oidc", resolved_status, resolved_reason),
        *_DEFAULT_CAPABILITIES[1:],
    )
