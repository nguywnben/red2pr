"""Canonical provider connections, repositories, CI runs/jobs, and notifications (S-08..S-10, S-16).

Enforces:
- S-08: Write-only secret inputs / opaque secret references; read DTOs expose SecretPresence only.
- S-09: Non-coerced opaque external_id, safe path globs, workflow hazard metadata (`SEC-031`),
  and non-waivable require_baseline=True.
- S-10: GitHub/GitLab run attempt_key and job retry_of_id preserved as opaque strings.
- S-16: Six-channel notification destinations, delivery state machine, and preferences.
- A-06 / A-23: GitHub App connection lifecycle, capability snapshots, single-use 10m install state,
  and repository discovery contracts (`SRC-01`, `U09`).
- ADR-037 / INS-02: Per-purpose outbound consent records and step-up-registered private endpoints.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Annotated, Any, Literal

from pydantic import (
    BeforeValidator,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    StringConstraints,
    model_validator,
)

from py_contracts.events import EventType
from py_contracts.iam import WorkspaceRole
from py_contracts.primitives import (
    ActionReceipt,
    BoundedName,
    BoundedReason,
    BoundedText,
    BoundedUrl,
    InstanceResourceBase,
    InternalId,
    Money,
    OpaqueProviderId,
    Page,
    PositiveVersion,
    Sha256Digest,
    StrictContractModel,
    UtcTimestamp,
    WorkspaceResourceBase,
)

_OPAQUE_SECRET_REF_RE = re.compile(r"^(?:sec_[A-Za-z0-9_-]{3,120}|ref:[A-Za-z0-9_.:/-]{3,120})$")
_GLOB_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:")


def _validate_opaque_secret_ref(value: Any) -> str:
    if not isinstance(value, str) or not _OPAQUE_SECRET_REF_RE.fullmatch(value):
        raise ValueError(
            "secret_ref must be an opaque broker reference matching 'sec_*' or 'ref:*'"
        )
    return value


def _validate_canonical_glob(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Glob pattern must be a string")
    if "\\" in value:
        raise ValueError("Glob pattern must use POSIX '/' separators without backslashes")
    normalized = unicodedata.normalize("NFC", value).strip()
    if (
        not normalized
        or len(normalized) > 256
        or _GLOB_CONTROL_CHAR_RE.search(normalized) is not None
    ):
        raise ValueError("Glob pattern must be 1..256 characters without control bytes")
    if normalized.startswith("/") or _WINDOWS_DRIVE_PREFIX_RE.match(normalized) is not None:
        raise ValueError("Glob pattern must be repository-relative without root or drive prefixes")
    raw_segments = normalized.split("/")
    if any(seg == "" for seg in raw_segments):
        raise ValueError("Glob pattern must not contain empty '//' path segments")
    if any(seg in {".", ".."} for seg in raw_segments):
        raise ValueError("Glob pattern must not contain '.' or '..' path traversal segments")
    return normalized


OpaqueSecretRef = Annotated[StrictStr, BeforeValidator(_validate_opaque_secret_ref)]
CanonicalGlobPattern = Annotated[StrictStr, BeforeValidator(_validate_canonical_glob)]
GitSha = Annotated[StrictStr, StringConstraints(pattern=r"^[0-9a-f]{40}$")]

# S-08 Connection & Capability
ProviderKind = Literal["github", "gitlab"]
ConnectionAuthMode = Literal[
    "github_app",
    "gitlab_signed_v19",
    "gitlab_legacy_token",
    "signed_webhook",
    "secret_token",
]
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
    """S-08 / A-06 write input accepting opaque secret_ref or write-only credential material."""

    provider: ProviderKind
    base_url: BoundedUrl
    auth_mode: ConnectionAuthMode
    secret_ref: OpaqueSecretRef | None = None
    display_name: BoundedName | None = None
    app_id: OpaqueProviderId | None = None
    client_id: BoundedName | None = None
    private_key_pem: Annotated[StrictStr, Field(min_length=32, max_length=16384)] | None = None
    access_token: Annotated[StrictStr, Field(min_length=12, max_length=512)] | None = None
    webhook_secret_ref: OpaqueSecretRef | None = None
    webhook_secret: Annotated[StrictStr, Field(min_length=16, max_length=512)] | None = None

    @model_validator(mode="after")
    def _validate_mutually_exclusive_secret_inputs(self) -> ConnectionWrite:
        cred_inputs = sum(
            1
            for item in (self.secret_ref, self.private_key_pem, self.access_token)
            if item is not None
        )
        if cred_inputs > 1:
            raise ValueError("Provide at most one of secret_ref, private_key_pem, or access_token")
        if self.webhook_secret_ref is not None and self.webhook_secret is not None:
            raise ValueError("Provide either webhook_secret_ref or webhook_secret, not both")
        return self


class ConnectionPatchRequest(StrictContractModel):
    """A-06 partial connection update & credential rotation payload (`S-02` version-checked)."""

    expected_version: PositiveVersion | None = None
    display_name: BoundedName | None = None
    base_url: BoundedUrl | None = None
    auth_mode: ConnectionAuthMode | None = None
    app_id: OpaqueProviderId | None = None
    client_id: BoundedName | None = None
    secret_ref: OpaqueSecretRef | None = None
    private_key_pem: Annotated[StrictStr, Field(min_length=32, max_length=16384)] | None = None
    access_token: Annotated[StrictStr, Field(min_length=12, max_length=512)] | None = None
    webhook_secret_ref: OpaqueSecretRef | None = None
    webhook_secret: Annotated[StrictStr, Field(min_length=16, max_length=512)] | None = None

    @model_validator(mode="after")
    def _validate_patch_secret_inputs(self) -> ConnectionPatchRequest:
        cred_inputs = sum(
            1
            for item in (self.secret_ref, self.private_key_pem, self.access_token)
            if item is not None
        )
        if cred_inputs > 1:
            raise ValueError("Provide at most one of secret_ref, private_key_pem, or access_token")
        if self.webhook_secret_ref is not None and self.webhook_secret is not None:
            raise ValueError("Provide either webhook_secret_ref or webhook_secret, not both")
        return self


class Connection(WorkspaceResourceBase):
    """S-08 provider connection & capability snapshot read DTO (never exposes secret values)."""

    provider: ProviderKind
    base_url: BoundedUrl
    auth_mode: ConnectionAuthMode
    secret_presence: SecretPresence
    status: ConnectionStatus
    capabilities: dict[BoundedName, CapabilityAvailability] = Field(default_factory=dict)
    checked_at: UtcTimestamp | None = None
    vendor_version: BoundedName | None = None
    api_version: BoundedName | None = None
    display_name: BoundedName | None = None
    app_id: OpaqueProviderId | None = None
    client_id: BoundedName | None = None
    installation_id: OpaqueProviderId | None = None
    account_login: BoundedName | None = None
    webhook_secret_presence: SecretPresence | None = None
    granted_permissions: dict[BoundedName, BoundedName] = Field(default_factory=dict)
    missing_permissions: list[BoundedName] = Field(default_factory=list)
    repository_count: Annotated[StrictInt, Field(ge=0)] = 0
    flagged_hazard_repo_count: Annotated[StrictInt, Field(ge=0)] = 0
    grant_review_required: StrictBool = False
    status_detail: BoundedReason | None = None
    last_synced_at: UtcTimestamp | None = None


ConnectionPage = Page[Connection]


class CapabilitySnapshot(WorkspaceResourceBase):
    """Immutable observed provider capability & permission snapshot (`S-08`, `SRC-01`)."""

    connection_id: InternalId
    provider: ProviderKind
    status: ConnectionStatus
    capabilities: dict[BoundedName, CapabilityAvailability] = Field(default_factory=dict)
    granted_permissions: dict[BoundedName, BoundedName] = Field(default_factory=dict)
    missing_permissions: list[BoundedName] = Field(default_factory=list)
    vendor_version: BoundedName | None = None
    api_version: BoundedName | None = None
    checked_at: UtcTimestamp
    detail: BoundedReason | None = None


# S-09 Repository, Policy & Workflow Hazard Metadata (`SEC-031`)
RepositoryVisibility = Literal["public", "private", "internal", "unknown"]
RepositoryMode = Literal["monitor", "approval", "auto_repair"]
WorkflowHazardCode = Literal[
    "pull_request_target",
    "privileged_workflow_run",
    "write_all_permissions",
    "deploy_trigger",
    "workflow_parse_warning",
]
WorkflowHazardSeverity = Literal["high", "medium", "low"]
WorkflowHazardStatus = Literal["clean", "flagged", "unscanned"]


# S-10 CI Run/Conclusion Status Literals (shared with S-09 catalog summaries)
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
SyncCursorStatus = Literal[
    "idle",
    "ok",
    "not_modified",
    "rate_limited",
    "gap_detected",
    "error",
    "revoked",
]


class WorkflowHazardFinding(StrictContractModel):
    """Structured workflow hazard finding from `.github/workflows` inspection (`SEC-031`)."""

    code: WorkflowHazardCode
    severity: WorkflowHazardSeverity
    workflow_path: BoundedText
    detail: BoundedReason


class RepositoryPolicy(StrictContractModel):
    """S-09 repository repair automation policy (require_baseline=True invariant per ADR-031)."""

    branch_allowlist: list[CanonicalGlobPattern] = Field(default_factory=list)
    branch_denylist: list[CanonicalGlobPattern] = Field(default_factory=list)
    file_allowlist: list[CanonicalGlobPattern] = Field(default_factory=list)
    file_denylist: list[CanonicalGlobPattern] = Field(default_factory=list)
    sensitive_rules: list[CanonicalGlobPattern] = Field(default_factory=list)
    allow_test_edits: StrictBool = False
    allow_config_edits: StrictBool = False
    max_attempts: Annotated[StrictInt, Field(ge=1, le=5)] = 2
    max_diff_lines: Annotated[StrictInt, Field(ge=1, le=2000)] = 500
    max_calls_per_session: Annotated[StrictInt, Field(ge=1, le=100)] | None = None
    max_tokens_per_session: Annotated[StrictInt, Field(ge=1, le=1_000_000)] | None = None
    max_wall_seconds: Annotated[StrictInt, Field(ge=60, le=7200)] | None = None
    max_cost_per_session: Money | None = None
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
    archived: StrictBool = False
    is_fork: StrictBool = False
    workflow_hazard_status: WorkflowHazardStatus = "unscanned"
    workflow_hazards: list[WorkflowHazardFinding] = Field(default_factory=list)
    auto_repair_blocked: StrictBool = False
    provider: ProviderKind | None = None
    organization: BoundedName | None = None
    active: StrictBool = True
    grant_review_required: StrictBool = False
    sync_status: SyncCursorStatus | None = None
    last_synced_at: UtcTimestamp | None = None
    last_ci_conclusion: CiConclusion | None = None
    last_ci_at: UtcTimestamp | None = None


# U11 Webhook Ingress, Resumable Polling & Reconciliation (`SRC-03`, `SRC-04`, `A-22`)
WebhookInboxStatus = Literal[
    "received",
    "normalized",
    "duplicate_semantic",
    "ignored",
    "reconcile_pending",
    "quarantined",
]
WebhookIngressDisposition = Literal[
    "accepted_trigger",
    "duplicate_delivery",
    "duplicate_semantic",
    "reconcile_scheduled",
    "ignored_non_failure",
    "ignored_bot_loop",
    "ignored_untracked_repo",
    "ignored_repository_paused",
    "ignored_stale_replay",
    "installation_revoked",
]


class WebhookIngressReceipt(StrictContractModel):
    """A-22 durable webhook receipt returned strictly after PostgreSQL fsync commit."""

    inbox_id: InternalId
    connection_id: InternalId
    provider: ProviderKind
    delivery_id: OpaqueProviderId
    status: WebhookInboxStatus
    disposition: WebhookIngressDisposition
    duplicate: StrictBool = False
    trigger_id: InternalId | None = None
    job_id: InternalId | None = None
    correlation_id: BoundedName
    received_at: UtcTimestamp


class ProviderSyncCursor(WorkspaceResourceBase):
    """SRC-04 resumable per-repository polling checkpoint, rate-limit backoff & gap status."""

    connection_id: InternalId
    repository_id: InternalId
    provider: ProviderKind
    etag: BoundedText | None = None
    high_water_mark_at: UtcTimestamp | None = None
    last_seen_run_id: OpaqueProviderId | None = None
    last_stable_page: Annotated[StrictInt, Field(ge=1)] = 1
    overlap_seconds: Annotated[StrictInt, Field(ge=0, le=3600)] = 300
    poll_interval_seconds: Annotated[StrictInt, Field(ge=10, le=3600)] = 60
    last_polled_at: UtcTimestamp | None = None
    last_success_at: UtcTimestamp | None = None
    next_poll_after: UtcTimestamp | None = None
    rate_limit_remaining: Annotated[StrictInt, Field(ge=0)] | None = None
    rate_limit_reset_at: UtcTimestamp | None = None
    consecutive_failures: Annotated[StrictInt, Field(ge=0)] = 0
    last_status: SyncCursorStatus = "idle"
    last_error_code: BoundedName | None = None
    last_error_detail: BoundedReason | None = None
    history_gap_detected: StrictBool = False
    history_gap_since: UtcTimestamp | None = None
    history_gap_until: UtcTimestamp | None = None
    history_gap_detail: BoundedReason | None = None


class ConnectionReconcileRequest(StrictContractModel):
    """A-06 / SRC-04 operator-triggered run polling & missed-event reconciliation request."""

    repository_ids: list[InternalId] | None = None
    acknowledge_history_gap: StrictBool = False
    force_poll: StrictBool = False


class ConnectionReconcileResponse(StrictContractModel):
    """A-06 / SRC-04 reconciliation summary (complete_recovery=False on history gaps or 429)."""

    receipt: ActionReceipt
    connection_id: InternalId
    polled_repository_count: Annotated[StrictInt, Field(ge=0)] = 0
    rate_limited_count: Annotated[StrictInt, Field(ge=0)] = 0
    history_gap_count: Annotated[StrictInt, Field(ge=0)] = 0
    triggers_created_count: Annotated[StrictInt, Field(ge=0)] = 0
    pending_inbox_reconciled_count: Annotated[StrictInt, Field(ge=0)] = 0
    complete_recovery: StrictBool = True
    sync_cursors: list[ProviderSyncCursor] = Field(default_factory=list)


class ConnectionDetailResponse(StrictContractModel):
    """A-06 detailed connection view with latest capability snapshot, repos & sync cursors."""

    connection: Connection
    latest_snapshot: CapabilitySnapshot | None = None
    repositories: list[Repository] = Field(default_factory=list)
    sync_cursors: list[ProviderSyncCursor] = Field(default_factory=list)


class ConnectionProbeResponse(StrictContractModel):
    """A-06 live capability & permission probe result."""

    receipt: ActionReceipt
    connection: Connection
    snapshot: CapabilitySnapshot


class ConnectionSyncResponse(StrictContractModel):
    """A-06 paginated repository discovery & workflow hazard scan result."""

    receipt: ActionReceipt
    connection: Connection
    discovered_count: Annotated[StrictInt, Field(ge=0)]
    partial_sync: StrictBool = False
    flagged_hazard_count: Annotated[StrictInt, Field(ge=0)] = 0
    repositories: list[Repository] = Field(default_factory=list)


class GitHubInstallStateCreateRequest(StrictContractModel):
    """A-23 request to mint a single-use 10-minute GitHub App callback/installation state nonce."""

    expected_origin: BoundedUrl | None = None


class GitHubInstallStateResponse(StrictContractModel):
    """A-23 single-use 10-minute GitHub installation state nonce bound to user/workspace/origin."""

    connection_id: InternalId
    workspace_id: InternalId
    state: Annotated[StrictStr, Field(min_length=16, max_length=256)]
    expires_at: UtcTimestamp
    install_url: BoundedUrl | None = None


class GitHubCallbackResponse(StrictContractModel):
    """A-23 safe read-only validation of GitHub OAuth / App installation redirect parameters."""

    state_valid: StrictBool
    workspace_id: InternalId
    workspace_slug: BoundedName
    connection_id: InternalId
    installation_id: OpaqueProviderId | None = None
    setup_action: BoundedName | None = None
    expires_at: UtcTimestamp


class GitHubInstallationConfirmRequest(StrictContractModel):
    """A-23 CSRF-protected mutation confirming & binding a GitHub App installation."""

    installation_id: OpaqueProviderId
    state: Annotated[StrictStr, Field(min_length=16, max_length=256)]
    expected_origin: BoundedUrl | None = None
    selected_external_repo_ids: list[OpaqueProviderId] | None = None


class GitHubInstallationConfirmResponse(StrictContractModel):
    """A-23 confirmed GitHub App installation binding, permission diff & discovered repos."""

    receipt: ActionReceipt
    connection: Connection
    snapshot: CapabilitySnapshot
    repositories: list[Repository] = Field(default_factory=list)
    partial_sync: StrictBool = False
    grant_review_required: StrictBool = False


# S-10 CiRun, CiJob & U13 Triage/Flaky Contracts (`A-08`, `TRI-01`, `TRI-03`)
FlakyClassification = Literal[
    "flaky",
    "persistent_failure",
    "single_pass_unproven",
    "insufficient_history",
    "unknown",
]
JobLogStatus = Literal[
    "pending",
    "available",
    "truncated",
    "expired",
    "unavailable",
]
CiRunIngestionState = Literal[
    "pending",
    "collecting",
    "ingested",
    "incomplete",
    "stale_sha",
    "failed",
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
    provider: ProviderKind = "github"
    repository_name: BoundedName | None = None
    attempt_number: Annotated[StrictInt, Field(ge=1)] = 1
    is_rerun: StrictBool = False
    untrusted_fork: StrictBool = False
    head_sha_verified: StrictBool = True
    observed_head_sha: BoundedName | None = None
    ingestion_state: CiRunIngestionState = "ingested"
    incomplete_reason: BoundedReason | None = None
    failed_job_count: Annotated[StrictInt, Field(ge=0)] = 0
    total_job_count: Annotated[StrictInt, Field(ge=0)] = 0
    artifact_count: Annotated[StrictInt, Field(ge=0)] = 0
    flaky_classification: FlakyClassification = "unknown"
    child_pipeline_ids: list[OpaqueProviderId] = Field(default_factory=list)
    started_at: UtcTimestamp | None = None
    completed_at: UtcTimestamp | None = None


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
    status: CiRunStatus = "completed"
    stage: BoundedName | None = None
    is_child_pipeline_job: StrictBool = False
    child_pipeline_id: OpaqueProviderId | None = None
    log_artifact_id: InternalId | None = None
    log_status: JobLogStatus = "unavailable"
    log_size_bytes: Annotated[StrictInt, Field(ge=0)] = 0
    log_truncated: StrictBool = False
    failure_excerpt: BoundedReason | None = None
    failure_fingerprint_id: InternalId | None = None
    failure_fingerprint_hash: Sha256Digest | None = None
    flaky_classification: FlakyClassification = "unknown"


CiRunPage = Page[CiRun]


class CiJobListResponse(StrictContractModel):
    """A-08 normalized CI job list for a specific `CiRun` attempt."""

    run_id: InternalId
    items: list[CiJob] = Field(default_factory=list)


class JobLogChunkResponse(StrictContractModel):
    """A-08 bounded, redacted CI job log slice (`max_bytes <= 65536`, `NFR-14`)."""

    job_id: InternalId
    run_id: InternalId
    log_status: JobLogStatus
    content: Annotated[StrictStr, Field(max_length=65536)]
    start_offset: Annotated[StrictInt, Field(ge=0)]
    next_offset: Annotated[StrictInt, Field(ge=0)]
    returned_bytes: Annotated[StrictInt, Field(ge=0, le=65536)]
    total_bytes: Annotated[StrictInt, Field(ge=0)]
    has_more: StrictBool
    truncated: StrictBool
    log_complete: StrictBool
    redaction_version: BoundedName
    incomplete_marker: BoundedReason | None = None


class FailureFingerprintObservation(StrictContractModel):
    """Single historical run-attempt outcome recorded against a failure fingerprint (`TRI-03`)."""

    run_id: InternalId
    attempt_key: OpaqueProviderId
    head_sha: GitSha
    conclusion: CiConclusion
    observed_at: UtcTimestamp


class FailureFingerprintSummary(WorkspaceResourceBase):
    """TRI-03 historical failure fingerprint & bounded flaky classification summary."""

    fingerprint_hash: Sha256Digest
    signature_label: BoundedReason
    test_identifier: BoundedText | None = None
    error_kind: BoundedName | None = None
    classification: FlakyClassification
    confidence_reason: BoundedReason
    failure_count: Annotated[StrictInt, Field(ge=0)]
    pass_on_same_sha_count: Annotated[StrictInt, Field(ge=0)]
    distinct_sha_count: Annotated[StrictInt, Field(ge=0)]
    first_seen_at: UtcTimestamp
    last_seen_at: UtcTimestamp
    recent_observations: list[FailureFingerprintObservation] = Field(default_factory=list)


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


# U07 / ADR-037 Outbound Consents & Private Endpoint Registrations
ConsentPurpose = Literal["inference", "notification", "telemetry", "provider"]
ConsentScope = Literal["instance", "workspace", "repository"]
ConsentDataClass = Literal["public", "workspace_internal", "restricted"]
ConsentStatus = Literal["active", "revoked"]

EgressAdapterKind = Literal[
    "github",
    "gitlab",
    "meta_inference",
    "oidc",
    "s3_artifacts",
    "telegram",
    "slack",
    "discord",
    "webhook",
    "smtp",
]
EndpointScheme = Literal["https", "http"]
EndpointRegistrationStatus = Literal["active", "revoked"]

_FORBIDDEN_V4_CIDRS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
)
_FORBIDDEN_V6_CIDRS: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.IPv6Network("::/128"),
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fd00:ec2::254/128"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("ff00::/8"),
    ipaddress.IPv6Network("2002::/16"),
    ipaddress.IPv6Network("2001::/32"),
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("64:ff9b:1::/48"),
)
_IPV4_MAPPED_V6_NET = ipaddress.IPv6Network("::ffff:0:0/96")
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NUMERIC_OR_HEX_LABEL_RE = re.compile(r"^(?:0x[0-9a-f]+|0[0-7]+|\d+)$")


def _is_permanently_forbidden_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip_obj, ipaddress.IPv6Address):
        if ip_obj.ipv4_mapped is not None:
            return _is_permanently_forbidden_ip(ip_obj.ipv4_mapped)
        if ip_obj.sixtofour is not None or ip_obj.teredo is not None:
            return True
        return any(ip_obj in net for net in _FORBIDDEN_V6_CIDRS)
    return any(ip_obj in net for net in _FORBIDDEN_V4_CIDRS)


def _validate_endpoint_host(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Endpoint host must be a string")
    candidate = value.strip().lower().rstrip(".")
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if not candidate or len(candidate) > 253:
        raise ValueError("Endpoint host must be 1..253 characters")
    if any(ch in candidate for ch in ("/", "@", "?", "#", " ", "\t", "\r", "\n", "\x00")):
        raise ValueError("Endpoint host must not contain path, userinfo, or control characters")

    try:
        ip_obj = ipaddress.ip_address(candidate)
    except ValueError:
        if ":" in candidate:
            raise ValueError(
                "Endpoint host must not include a port; specify port separately"
            ) from None
        try:
            ascii_host = candidate.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Endpoint host is not valid IDNA hostname") from exc
        labels = ascii_host.split(".")
        if all(_NUMERIC_OR_HEX_LABEL_RE.fullmatch(lbl) is not None for lbl in labels):
            raise ValueError("Obfuscated integer/octal/hex IPv4 hostnames are forbidden") from None
        if not all(_DNS_LABEL_RE.fullmatch(lbl) is not None for lbl in labels):
            raise ValueError("Endpoint host contains invalid DNS label characters") from None
        return ascii_host

    if _is_permanently_forbidden_ip(ip_obj):
        raise ValueError(
            "Loopback, link-local, cloud metadata, multicast, and unspecified IPs are forbidden"
        )
    return ip_obj.compressed


def _validate_registrable_cidr(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("CIDR must be a string")
    raw = value.strip()
    if "/" not in raw:
        raise ValueError("CIDR must include an explicit prefix length (e.g. 10.24.0.0/16)")
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise ValueError("Invalid IPv4 or IPv6 CIDR notation") from exc

    if isinstance(net, ipaddress.IPv4Network):
        if net.prefixlen < 8:
            raise ValueError("IPv4 CIDR prefix length must be >= 8 (no blanket wildcard ranges)")
        if any(net.overlaps(forbidden) for forbidden in _FORBIDDEN_V4_CIDRS):
            raise ValueError(
                "CIDR overlaps forbidden loopback, link-local, metadata, or reserved space"
            )
        return net.with_prefixlen

    if net.prefixlen < 16:
        raise ValueError("IPv6 CIDR prefix length must be >= 16 (no blanket wildcard ranges)")
    if net.overlaps(_IPV4_MAPPED_V6_NET):
        raise ValueError("Register canonical IPv4 CIDRs instead of IPv4-mapped IPv6 CIDRs")
    if any(net.overlaps(forbidden) for forbidden in _FORBIDDEN_V6_CIDRS):
        raise ValueError(
            "CIDR overlaps forbidden loopback, link-local, multicast, or transition space"
        )
    return net.with_prefixlen


EndpointHostStr = Annotated[StrictStr, BeforeValidator(_validate_endpoint_host)]
RegistrableCidrStr = Annotated[StrictStr, BeforeValidator(_validate_registrable_cidr)]


class ConsentCreateRequest(StrictContractModel):
    """Explicit per-purpose outbound data-sharing consent grant (ADR-037, INS-02)."""

    purpose: ConsentPurpose
    scope: ConsentScope = "instance"
    workspace_id: InternalId | None = None
    repository_id: InternalId | None = None
    destination: BoundedUrl
    data_classes: Annotated[list[ConsentDataClass], Field(min_length=1, max_length=3)]
    policy_notice_acknowledged: Literal[True] = True

    @model_validator(mode="after")
    def _validate_scope_workspace_consistency(self) -> ConsentCreateRequest:
        if self.scope == "instance" and (
            self.workspace_id is not None or self.repository_id is not None
        ):
            raise ValueError("workspace_id and repository_id must be omitted when scope='instance'")
        if self.scope == "workspace":
            if self.workspace_id is None:
                raise ValueError("workspace_id is required when scope='workspace'")
            if self.repository_id is not None:
                raise ValueError("repository_id must be omitted when scope='workspace'")
        if self.scope == "repository" and (self.workspace_id is None or self.repository_id is None):
            raise ValueError(
                "workspace_id and repository_id are both required when scope='repository'"
            )
        deduped = list(dict.fromkeys(self.data_classes))
        object.__setattr__(self, "data_classes", deduped)
        return self


class ConsentRevokeRequest(StrictContractModel):
    """Revocation payload for an active outbound consent grant."""

    reason: BoundedReason | None = None


class ConsentRecord(InstanceResourceBase):
    """Durable outbound consent record isolated by purpose (`S-18`, `SEC-018`)."""

    purpose: ConsentPurpose
    scope: ConsentScope
    workspace_id: InternalId | None = None
    repository_id: InternalId | None = None
    destination: BoundedUrl
    data_classes: list[ConsentDataClass]
    granted_by_user_id: InternalId
    policy_revision: PositiveVersion
    status: ConsentStatus
    revoked_at: UtcTimestamp | None = None
    revoke_reason: BoundedReason | None = None


ConsentRecordPage = Page[ConsentRecord]


class EndpointRegistrationCreateRequest(StrictContractModel):
    """Owner step-up-authorized private endpoint allowlist registration (ADR-037)."""

    adapter: EgressAdapterKind
    scheme: EndpointScheme = "https"
    host: EndpointHostStr
    port: Annotated[StrictInt, Field(ge=1, le=65535)] = 443
    cidrs: Annotated[list[RegistrableCidrStr], Field(min_length=1, max_length=32)]
    ca_ref: OpaqueSecretRef | None = None
    description: BoundedText | None = None

    @model_validator(mode="after")
    def _deduplicate_cidrs(self) -> EndpointRegistrationCreateRequest:
        deduped = list(dict.fromkeys(self.cidrs))
        object.__setattr__(self, "cidrs", deduped)
        return self


class EndpointRegistration(InstanceResourceBase):
    """Registered private service endpoint bound to exact adapter, host, port, CIDRs & CA ref."""

    owner_user_id: InternalId
    adapter: EgressAdapterKind
    scheme: EndpointScheme
    host: EndpointHostStr
    port: Annotated[StrictInt, Field(ge=1, le=65535)]
    cidrs: list[RegistrableCidrStr]
    ca_ref: OpaqueSecretRef | None = None
    description: BoundedText | None = None
    status: EndpointRegistrationStatus
    revoked_at: UtcTimestamp | None = None


EndpointRegistrationPage = Page[EndpointRegistration]


# U12 Repository Catalog, Versioned Policy Engine & Dry-Run Simulator (`A-07`, `REP-01..03`)
PolicyScopeLayer = Literal["hard_invariant", "instance", "workspace", "repository"]
PolicyEvaluationVerdict = Literal["allow", "requires_approval", "deny"]
RunEligibilityDisposition = Literal[
    "eligible_auto_repair",
    "eligible_approval_gated",
    "diagnose_only_monitor",
    "blocked_paused",
    "blocked_branch_policy",
    "blocked_untrusted_fork",
    "blocked_workflow_hazard",
    "blocked_grant_review",
    "blocked_worker_unready",
    "blocked_missing_consent",
]


class RepositoryFacetSummary(StrictContractModel):
    """Scoped catalog facets computed over the caller's authorized repositories (`UX-02`)."""

    tags: list[BoundedName] = Field(default_factory=list)
    organizations: list[BoundedName] = Field(default_factory=list)
    mode_counts: dict[BoundedName, Annotated[StrictInt, Field(ge=0)]] = Field(default_factory=dict)
    paused_count: Annotated[StrictInt, Field(ge=0)] = 0
    hazard_flagged_count: Annotated[StrictInt, Field(ge=0)] = 0
    partial_sync_connection_ids: list[InternalId] = Field(default_factory=list)


class RepositoryCatalogPage(Page[Repository]):
    """A-07 cursor-paginated repository catalog page (`S-04`) with strictly scoped facets."""

    facets: RepositoryFacetSummary = Field(default_factory=RepositoryFacetSummary)


class RepositoryUpdateRequest(StrictContractModel):
    """A-07 partial repository mode, pause, tag, and W-02 grant-review update (`S-02`)."""

    expected_version: PositiveVersion | None = None
    mode: RepositoryMode | None = None
    paused: StrictBool | None = None
    tags: Annotated[list[BoundedName], Field(max_length=32)] | None = None
    acknowledge_grant_review: StrictBool = False
    reason: BoundedReason | None = None


class PolicyReadinessGates(StrictContractModel):
    """Authoritative safety & operational readiness prerequisites for repository automation."""

    worker_isolation_ready: StrictBool
    inference_consent_ready: StrictBool
    workflow_hazard_blocked: StrictBool
    grant_review_required: StrictBool
    instance_paused: StrictBool = False
    workspace_paused: StrictBool = False
    blocking_reasons: list[BoundedReason] = Field(default_factory=list)


class EffectiveRepositoryPolicy(StrictContractModel):
    """Resolved policy after `hard_invariant > instance > workspace > repository` merge."""

    mode: RepositoryMode
    effective_mode: RepositoryMode
    paused: StrictBool
    effective_paused: StrictBool
    allow_sandbox_execution: StrictBool
    allow_auto_publication: StrictBool
    require_baseline: Literal[True] = True
    auto_merge: Literal[False] = False
    branch_allowlist: list[CanonicalGlobPattern] = Field(default_factory=list)
    branch_denylist: list[CanonicalGlobPattern] = Field(default_factory=list)
    file_allowlist: list[CanonicalGlobPattern] = Field(default_factory=list)
    file_denylist: list[CanonicalGlobPattern] = Field(default_factory=list)
    hard_denied_paths: list[CanonicalGlobPattern] = Field(default_factory=list)
    sensitive_rules: list[CanonicalGlobPattern] = Field(default_factory=list)
    protected_paths: list[CanonicalGlobPattern] = Field(default_factory=list)
    allow_test_edits: StrictBool = False
    allow_config_edits: StrictBool = False
    max_attempts: Annotated[StrictInt, Field(ge=1, le=5)]
    max_diff_lines: Annotated[StrictInt, Field(ge=1, le=2000)]
    max_calls_per_session: Annotated[StrictInt, Field(ge=1, le=100)]
    max_tokens_per_session: Annotated[StrictInt, Field(ge=1, le=1_000_000)]
    max_wall_seconds: Annotated[StrictInt, Field(ge=60, le=7200)]
    max_cost_per_session: Money
    inference_consent_id: InternalId | None = None
    runtime_profile_id: BoundedName
    field_sources: dict[BoundedName, PolicyScopeLayer] = Field(default_factory=dict)


class RepositoryPolicyRevision(WorkspaceResourceBase):
    """Immutable versioned `repository_policies` snapshot (`S-09`, `REP-02`)."""

    repository_id: InternalId
    revision: PositiveVersion
    mode: RepositoryMode
    paused: StrictBool
    policy: RepositoryPolicy
    change_reason: BoundedReason | None = None
    created_by_user_id: InternalId | None = None


class RepositoryPolicyStateResponse(StrictContractModel):
    """A-07 current policy snapshot, merged effective policy, gates, and revision history."""

    repository_id: InternalId
    workspace_id: InternalId
    current_revision: PositiveVersion
    mode: RepositoryMode
    paused: StrictBool
    policy: RepositoryPolicy
    effective_policy: EffectiveRepositoryPolicy
    readiness_gates: PolicyReadinessGates
    revisions: list[RepositoryPolicyRevision] = Field(default_factory=list)


class RepositoryPolicyUpdateRequest(StrictContractModel):
    """A-07 optimistic-concurrency update creating an immutable `repository_policies` revision."""

    expected_revision: PositiveVersion | None = None
    mode: RepositoryMode | None = None
    paused: StrictBool | None = None
    policy: RepositoryPolicy
    reason: BoundedReason | None = None


class PolicyRuleChange(StrictContractModel):
    """Structured rule diff entry produced during dry-run policy preview (`A-07`)."""

    field: BoundedName
    before: Any
    after: Any
    impact: BoundedReason
    requires_step_up: StrictBool = False


class PolicyDenialItem(StrictContractModel):
    """Explicit invariant, hazard, readiness, or scope denial reported by the policy engine."""

    code: BoundedName
    source_layer: PolicyScopeLayer
    detail: BoundedReason
    blocking_save: StrictBool = False


class BranchPolicyEvaluation(StrictContractModel):
    """Per-branch dry-run policy decision (`deny` always overrides `allow`)."""

    branch: BoundedText
    canonical_branch: BoundedName | None = None
    verdict: PolicyEvaluationVerdict
    matched_rule: BoundedText | None = None
    source_layer: PolicyScopeLayer
    reason: BoundedReason


class PathPolicyEvaluation(StrictContractModel):
    """Per-file-path canonicalization & glob evaluation (`SEC-007`, `SEC-009`)."""

    raw_path: BoundedText
    canonical_path: BoundedText | None = None
    verdict: PolicyEvaluationVerdict
    category: Literal[
        "standard",
        "hard_denied",
        "denied_glob",
        "outside_allowlist",
        "protected_sensitive",
        "test_file",
        "config_file",
        "invalid_path",
    ]
    matched_rule: BoundedText | None = None
    source_layer: PolicyScopeLayer
    reason: BoundedReason


class HistoricalRunSimulation(StrictContractModel):
    """Dry-run simulation of a historical `ci_run_triggers` attempt under candidate policy."""

    trigger_id: InternalId
    provider_run_id: OpaqueProviderId
    attempt_key: OpaqueProviderId
    ref: BoundedName
    head_sha: BoundedName
    conclusion: CiConclusion
    untrusted_fork: StrictBool = False
    triggered_at: UtcTimestamp
    disposition: RunEligibilityDisposition
    allow_sandbox_execution: StrictBool
    allow_auto_publication: StrictBool
    reason: BoundedReason


class AffectedInFlightItem(StrictContractModel):
    """Active in-flight job/session summary showing pinned policy revision isolation."""

    job_id: InternalId
    repair_id: InternalId | None = None
    kind: BoundedName
    state: BoundedName
    pinned_policy_revision: PositiveVersion
    impact_summary: BoundedReason
    created_at: UtcTimestamp


class RepositoryPolicyPreviewRequest(StrictContractModel):
    """A-07 zero-mutation dry-run policy simulator input (`UX-POLICY-001`, `T-REP-02-P`)."""

    mode: RepositoryMode | None = None
    paused: StrictBool | None = None
    policy: RepositoryPolicy | None = None
    sample_branches: Annotated[list[BoundedText], Field(max_length=32)] = Field(
        default_factory=list
    )
    sample_paths: Annotated[list[BoundedText], Field(max_length=64)] = Field(default_factory=list)
    sample_diff_lines: Annotated[StrictInt, Field(ge=0, le=100_000)] | None = None


class RepositoryPolicyPreviewResponse(StrictContractModel):
    """A-07 dry-run policy preview result (mutates zero rows; surfaces diffs & simulations)."""

    repository_id: InternalId
    current_revision: PositiveVersion
    next_revision: PositiveVersion
    requires_step_up: StrictBool
    can_apply: StrictBool
    effective_policy: EffectiveRepositoryPolicy
    readiness_gates: PolicyReadinessGates
    changed_rules: list[PolicyRuleChange] = Field(default_factory=list)
    denials: list[PolicyDenialItem] = Field(default_factory=list)
    branch_evaluations: list[BranchPolicyEvaluation] = Field(default_factory=list)
    path_evaluations: list[PathPolicyEvaluation] = Field(default_factory=list)
    historical_run_simulations: list[HistoricalRunSimulation] = Field(default_factory=list)
    affected_in_flight: list[AffectedInFlightItem] = Field(default_factory=list)
    diff_lines_verdict: PolicyEvaluationVerdict | None = None
    diff_lines_reason: BoundedReason | None = None


class BulkRepositoryPreviewItem(StrictContractModel):
    """Per-repository preview outcome for `UI-S04` explicit bulk policy/mode preview."""

    repository_id: InternalId
    repository_name: BoundedName
    current_version: PositiveVersion
    current_mode: RepositoryMode
    target_mode: RepositoryMode
    current_paused: StrictBool
    target_paused: StrictBool
    can_apply: StrictBool
    requires_step_up: StrictBool
    active_job_count: Annotated[StrictInt, Field(ge=0)] = 0
    denials: list[PolicyDenialItem] = Field(default_factory=list)


class BulkRepositoryPreviewRequest(StrictContractModel):
    """A-07 / `UI-S04` zero-mutation bulk repository mode/pause/tag preview request."""

    repository_ids: Annotated[list[InternalId], Field(min_length=1, max_length=100)]
    mode: RepositoryMode | None = None
    paused: StrictBool | None = None
    add_tags: Annotated[list[BoundedName], Field(max_length=32)] = Field(default_factory=list)
    remove_tags: Annotated[list[BoundedName], Field(max_length=32)] = Field(default_factory=list)


class BulkRepositoryPreviewResponse(StrictContractModel):
    """A-07 / `UI-S04` zero-mutation bulk repository preview response."""

    can_apply_all: StrictBool
    requires_step_up: StrictBool
    items: list[BulkRepositoryPreviewItem] = Field(default_factory=list)


class BulkRepositoryUpdateRequest(StrictContractModel):
    """A-07 / `UI-S04` version-checked bulk repository mode/pause/tag mutation request."""

    repository_ids: Annotated[list[InternalId], Field(min_length=1, max_length=100)]
    expected_versions: dict[InternalId, PositiveVersion]
    mode: RepositoryMode | None = None
    paused: StrictBool | None = None
    add_tags: Annotated[list[BoundedName], Field(max_length=32)] = Field(default_factory=list)
    remove_tags: Annotated[list[BoundedName], Field(max_length=32)] = Field(default_factory=list)
    reason: BoundedReason | None = None


class BulkRepositoryUpdateResponse(StrictContractModel):
    """A-07 / `UI-S04` atomic bulk repository update response."""

    updated_repositories: list[Repository] = Field(default_factory=list)


class RepositoryRunTriggerSummary(StrictContractModel):
    """Normalized CI failure trigger summary for `UI-S05` Overview, Runs & Branches tabs."""

    id: InternalId
    provider: ProviderKind
    provider_run_id: OpaqueProviderId
    attempt_key: OpaqueProviderId
    head_sha: BoundedName
    ref: BoundedName
    event_type: BoundedName
    status: CiRunStatus
    conclusion: CiConclusion
    is_rerun: StrictBool
    untrusted_fork: StrictBool
    first_source: Literal["webhook", "poll", "reconcile"]
    job_id: InternalId | None = None
    triggered_at: UtcTimestamp


class RepositoryAccessGrantSummary(StrictContractModel):
    """Authorized principal summary for `UI-S05` Access tab (`ADR-030`, `SEC-010`)."""

    membership_id: InternalId
    user_id: InternalId
    display_name: BoundedName
    email: BoundedText
    role: WorkspaceRole
    grant_origin: Literal["workspace_admin", "explicit_repo_grant"]


class RepositoryHistoryEntry(StrictContractModel):
    """Audit & policy revision history item for `UI-S05` History tab."""

    id: InternalId
    occurred_at: UtcTimestamp
    actor_type: BoundedName
    actor_id: BoundedName
    action: BoundedName
    decision: BoundedName
    reason_code: BoundedName | None = None
    policy_revision: PositiveVersion | None = None
    summary: BoundedReason


class RepositoryDetailResponse(StrictContractModel):
    """A-07 comprehensive repository detail DTO powering all 7 `UI-S05` tabs."""

    repository: Repository
    connection_display_name: BoundedName | None = None
    connection_status: ConnectionStatus
    current_policy_revision: PositiveVersion
    policy: RepositoryPolicy
    effective_policy: EffectiveRepositoryPolicy
    readiness_gates: PolicyReadinessGates
    sync_cursor: ProviderSyncCursor | None = None
    recent_runs: list[RepositoryRunTriggerSummary] = Field(default_factory=list)
    active_jobs: list[AffectedInFlightItem] = Field(default_factory=list)
    access_grants: list[RepositoryAccessGrantSummary] = Field(default_factory=list)
    recent_history: list[RepositoryHistoryEntry] = Field(default_factory=list)
    policy_revisions: list[RepositoryPolicyRevision] = Field(default_factory=list)
