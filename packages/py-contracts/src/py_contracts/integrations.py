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
from py_contracts.primitives import (
    ActionReceipt,
    BoundedName,
    BoundedReason,
    BoundedText,
    BoundedUrl,
    InstanceResourceBase,
    InternalId,
    OpaqueProviderId,
    Page,
    PositiveVersion,
    StrictContractModel,
    UtcTimestamp,
    WorkspaceResourceBase,
)

_OPAQUE_SECRET_REF_RE = re.compile(r"^(?:sec_[A-Za-z0-9_-]{3,120}|ref:[A-Za-z0-9_.:/-]{3,120})$")


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
    """S-08 / A-06 write input accepting opaque secret_ref or write-only credential material."""

    provider: ProviderKind
    base_url: BoundedUrl
    auth_mode: ConnectionAuthMode
    secret_ref: OpaqueSecretRef | None = None
    display_name: BoundedName | None = None
    app_id: OpaqueProviderId | None = None
    client_id: BoundedName | None = None
    private_key_pem: Annotated[StrictStr, Field(min_length=32, max_length=16384)] | None = None
    webhook_secret_ref: OpaqueSecretRef | None = None
    webhook_secret: Annotated[StrictStr, Field(min_length=16, max_length=512)] | None = None

    @model_validator(mode="after")
    def _validate_mutually_exclusive_secret_inputs(self) -> ConnectionWrite:
        if self.secret_ref is not None and self.private_key_pem is not None:
            raise ValueError("Provide either secret_ref or private_key_pem, not both")
        if self.webhook_secret_ref is not None and self.webhook_secret is not None:
            raise ValueError("Provide either webhook_secret_ref or webhook_secret, not both")
        return self


class ConnectionPatchRequest(StrictContractModel):
    """A-06 partial connection update & credential rotation payload (`S-02` version-checked)."""

    expected_version: PositiveVersion | None = None
    display_name: BoundedName | None = None
    base_url: BoundedUrl | None = None
    app_id: OpaqueProviderId | None = None
    client_id: BoundedName | None = None
    secret_ref: OpaqueSecretRef | None = None
    private_key_pem: Annotated[StrictStr, Field(min_length=32, max_length=16384)] | None = None
    webhook_secret_ref: OpaqueSecretRef | None = None
    webhook_secret: Annotated[StrictStr, Field(min_length=16, max_length=512)] | None = None

    @model_validator(mode="after")
    def _validate_patch_secret_inputs(self) -> ConnectionPatchRequest:
        if self.secret_ref is not None and self.private_key_pem is not None:
            raise ValueError("Provide either secret_ref or private_key_pem, not both")
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


class WorkflowHazardFinding(StrictContractModel):
    """Structured workflow hazard finding from `.github/workflows` inspection (`SEC-031`)."""

    code: WorkflowHazardCode
    severity: WorkflowHazardSeverity
    workflow_path: BoundedText
    detail: BoundedReason


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
    archived: StrictBool = False
    is_fork: StrictBool = False
    workflow_hazard_status: WorkflowHazardStatus = "unscanned"
    workflow_hazards: list[WorkflowHazardFinding] = Field(default_factory=list)
    auto_repair_blocked: StrictBool = False


class ConnectionDetailResponse(StrictContractModel):
    """A-06 detailed connection view with latest capability snapshot and scoped repositories."""

    connection: Connection
    latest_snapshot: CapabilitySnapshot | None = None
    repositories: list[Repository] = Field(default_factory=list)


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
