"""Canonical provider connections, repositories, CI runs/jobs, and notifications (S-08..S-10, S-16).

Enforces:
- S-08: Write-only opaque secret references; read DTOs expose SecretPresence only.
- S-09: Non-coerced opaque external_id, safe path globs, and non-waivable require_baseline=True.
- S-10: GitHub/GitLab run attempt_key and job retry_of_id preserved as opaque strings.
- S-16: Six-channel notification destinations, delivery state machine, and preferences.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field, StrictBool, StrictInt, StrictStr, StringConstraints

from py_contracts.events import EventType
from py_contracts.primitives import (
    BoundedName,
    BoundedText,
    BoundedUrl,
    InstanceResourceBase,
    InternalId,
    OpaqueProviderId,
    PositiveVersion,
    StrictContractModel,
    UtcTimestamp,
    WorkspaceResourceBase,
)

_OPAQUE_SECRET_REF_RE = re.compile(
    r"^(?:sec_[A-Za-z0-9_-]{3,120}|ref:[A-Za-z0-9_.:/-]{3,120})$"
)


def _validate_opaque_secret_ref(value: Any) -> str:
    if not isinstance(value, str) or not _OPAQUE_SECRET_REF_RE.fullmatch(value):
        raise ValueError(
            "secret_ref must be an opaque broker reference matching 'sec_*' or 'ref:*'"
        )
    return value


def _validate_canonical_glob(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Glob pattern must be a string")
    cleaned = value.strip().replace("\\", "/")
    if not cleaned or len(cleaned) > 256 or "\x00" in cleaned:
        raise ValueError("Glob pattern must be 1..256 characters without null bytes")
    segments = [seg for seg in cleaned.split("/") if seg]
    if ".." in segments:
        raise ValueError("Glob pattern must not contain '..' path traversal segments")
    return cleaned


OpaqueSecretRef = Annotated[StrictStr, BeforeValidator(_validate_opaque_secret_ref)]
CanonicalGlobPattern = Annotated[StrictStr, BeforeValidator(_validate_canonical_glob)]
GitSha = Annotated[StrictStr, StringConstraints(pattern=r"^[0-9a-f]{40}$")]

# S-08 Connection & Capability
ProviderKind = Literal["github", "gitlab"]
ConnectionAuthMode = Literal["github_app", "signed_webhook", "secret_token"]
ConnectionStatus = Literal[
    "not_configured",
    "checking",
    "ready",
    "degraded",
    "revoked",
    "unsupported",
]
CapabilityAvailability = Literal["available", "unavailable", "unknown"]


class SecretPresence(StrictContractModel):
    """Safe read-only secret metadata (never exposes secret values or internal refs)."""

    configured: StrictBool
    secret_version: PositiveVersion | None = None


class ConnectionWrite(StrictContractModel):
    """S-08 write input accepting an opaque secret_ref."""

    provider: ProviderKind
    base_url: BoundedUrl
    auth_mode: ConnectionAuthMode
    secret_ref: OpaqueSecretRef | None = None


class Connection(WorkspaceResourceBase):
    """S-08 provider connection & capability snapshot read DTO."""

    provider: ProviderKind
    base_url: BoundedUrl
    auth_mode: ConnectionAuthMode
    secret_presence: SecretPresence
    status: ConnectionStatus
    capabilities: dict[BoundedName, CapabilityAvailability] = Field(default_factory=dict)
    checked_at: UtcTimestamp | None = None
    vendor_version: BoundedName | None = None
    api_version: BoundedName | None = None


# S-09 Repository & Policy
RepositoryVisibility = Literal["public", "private", "internal", "unknown"]
RepositoryMode = Literal["monitor", "approval", "auto_repair"]


class RepositoryPolicy(StrictContractModel):
    """S-09 repository repair automation policy (require_baseline=True invariant per ADR-031)."""

    branch_allowlist: list[CanonicalGlobPattern] = Field(default_factory=list)
    file_denylist: list[CanonicalGlobPattern] = Field(default_factory=list)
    sensitive_rules: list[CanonicalGlobPattern] = Field(default_factory=list)
    max_attempts: Annotated[StrictInt, Field(ge=1, le=5)] = 2
    max_diff_lines: Annotated[StrictInt, Field(ge=1, le=2000)] = 500
    require_baseline: Literal[True] = True
    inference_consent_id: InternalId | None = None
    runtime_profile_id: BoundedName


class Repository(WorkspaceResourceBase):
    """S-09 workspace-scoped repository catalog entry."""

    external_id: OpaqueProviderId
    connection_id: InternalId
    name: BoundedName
    default_branch: BoundedName
    visibility: RepositoryVisibility
    mode: RepositoryMode
    paused: StrictBool = False
    policy_revision: PositiveVersion
    tags: list[BoundedName] = Field(default_factory=list)


# S-10 CiRun & CiJob
CiRunStatus = Literal["queued", "in_progress", "completed", "unknown"]
CiConclusion = Literal[
    "success",
    "failure",
    "cancelled",
    "timed_out",
    "skipped",
    "neutral",
    "action_required",
    "unknown",
]


class CiRun(WorkspaceResourceBase):
    """S-10 normalized CI pipeline/workflow run attempt."""

    repository_id: InternalId
    external_id: OpaqueProviderId
    attempt_key: OpaqueProviderId
    head_sha: GitSha
    ref: BoundedName
    event_type: BoundedName
    status: CiRunStatus
    conclusion: CiConclusion | None = None
    jobs_complete: StrictBool
    raw_vendor_status: BoundedName | None = None


class CiJob(WorkspaceResourceBase):
    """S-10 normalized CI job with matrix dimensions and retry lineage."""

    repository_id: InternalId
    external_id: OpaqueProviderId
    run_id: InternalId
    name: BoundedName
    matrix_dimensions: dict[BoundedName, BoundedText] = Field(default_factory=dict)
    retry_of_id: OpaqueProviderId | None = None
    started_at: UtcTimestamp | None = None
    completed_at: UtcTimestamp | None = None
    conclusion: CiConclusion | None = None


# S-16 Notification Destination, Delivery & Preference
NotificationChannel = Literal["in_app", "telegram", "email", "slack", "discord", "webhook"]
DestinationScope = Literal["user", "workspace"]
DestinationStatus = Literal[
    "not_configured",
    "pending_verification",
    "ready",
    "degraded",
    "suppressed",
    "quarantined",
    "disabled",
]
DeliveryState = Literal[
    "pending",
    "sending",
    "accepted",
    "delivered",
    "bounced",
    "retry_wait",
    "unknown",
    "possible_duplicate",
    "failed_final",
    "suppressed",
]
NotificationSeverity = Literal[
    "info",
    "warning",
    "action",
    "success",
    "error",
    "high",
    "critical",
]
HhMmTime = Annotated[StrictStr, StringConstraints(pattern=r"^([01]\d|2[0-3]):[0-5]\d$")]


class QuietHoursWindow(StrictContractModel):
    """Daily local quiet-hours window in HH:MM 24-hour format."""

    start_hhmm: HhMmTime
    end_hhmm: HhMmTime


class NotificationDestination(WorkspaceResourceBase):
    """S-16 configured notification target (credentials remain write-only)."""

    channel: NotificationChannel
    scope: DestinationScope
    verified_at: UtcTimestamp | None = None
    consent_id: InternalId | None = None
    status: DestinationStatus
    secret_presence: SecretPresence


class NotificationDelivery(WorkspaceResourceBase):
    """S-16 durable outbox delivery attempt record (docs/32)."""

    event_id: InternalId
    destination_id: InternalId
    template_revision: PositiveVersion
    state: DeliveryState
    attempt: Annotated[StrictInt, Field(ge=0)]
    next_retry_at: UtcTimestamp | None = None
    provider_id: OpaqueProviderId | None = None
    last_error_code: BoundedName | None = None


class NotificationPreference(InstanceResourceBase):
    """S-16 user or workspace notification routing preferences."""

    workspace_id: InternalId | None = None
    event_types: list[EventType] = Field(default_factory=list)
    min_severity: NotificationSeverity = "info"
    quiet_hours: QuietHoursWindow | None = None
    timezone: BoundedName = "UTC"
