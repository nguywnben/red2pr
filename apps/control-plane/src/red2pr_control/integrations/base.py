"""Unified SourceProviderAdapter contract, normalized provider errors & Z1/Z2 vault protocol.

Implements `docs/12_PROVIDER_INTEGRATIONS.md` and `docs/40_EXECUTION_MASTER_PLAN.md` (`U09`):
- Unified `SourceProviderAdapter` protocol shared across GitHub (`U09`) and GitLab (`U10`).
- Normalized `ProviderError` taxonomy:
  `RATE_LIMIT`, `FORBIDDEN`, `NOT_FOUND`, `REVOKED`, `STALE_SHA`, `TRANSIENT`, `UNSUPPORTED`.
- `ProviderCredentialVaultProtocol`: `Z1`-safe interface keeping raw RSA private keys and
  webhook secrets inside `Z2` `SecretBroker` while caching JIT installation tokens encrypted.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Literal, Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts.integrations import (
    CapabilityAvailability,
    ConnectionAuthMode,
    ProviderKind,
    RepositoryVisibility,
    WorkflowHazardFinding,
    WorkflowHazardStatus,
)

ProviderErrorCode = Literal[
    "RATE_LIMIT",
    "FORBIDDEN",
    "NOT_FOUND",
    "REVOKED",
    "STALE_SHA",
    "TRANSIENT",
    "UNSUPPORTED",
]


class ProviderError(Exception):
    """Normalized source-provider error decoupling orchestrator/UI from vendor HTTP quirks."""

    def __init__(
        self,
        *,
        code: ProviderErrorCode,
        detail: str,
        provider: ProviderKind = "github",
        status_code: int | None = None,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(f"{provider}:{code}: {detail}")
        self.code = code
        self.detail = detail
        self.provider = provider
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True, slots=True)
class ProviderConnectionContext:
    """Immutable Z1 connection context passed into `SourceProviderAdapter` operations."""

    workspace_id: str
    connection_id: str
    provider: ProviderKind
    base_url: str
    app_id: str | None
    client_id: str | None
    installation_id: str | None
    credential_secret_ref: str | None
    webhook_secret_ref: str | None
    auth_mode: ConnectionAuthMode = "github_app"
    vendor_version: str | None = None


@dataclass(frozen=True, slots=True)
class ProviderPermissionSummary:
    """Observed provider capability & permission verification snapshot."""

    account_login: str | None
    vendor_version: str | None
    api_version: str
    granted_permissions: dict[str, str]
    missing_required_permissions: tuple[str, ...]
    missing_optional_permissions: tuple[str, ...]
    excess_unused_permissions: tuple[str, ...]
    capabilities: dict[str, CapabilityAvailability]
    suspended: bool = False
    unsupported_auth_mode: bool = False
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class DiscoveredRepositoryRecord:
    """Normalized discovered repository metadata returned by `list_repos`."""

    external_repo_id: str
    short_name: str
    full_name: str
    default_branch: str
    visibility: RepositoryVisibility
    archived: bool
    disabled: bool
    is_fork: bool
    workflow_hazard_status: WorkflowHazardStatus = "unscanned"
    workflow_hazards: tuple[WorkflowHazardFinding, ...] = ()
    auto_repair_blocked: bool = False


@dataclass(frozen=True, slots=True)
class PaginatedRepoDiscoveryResult:
    """Result of paginated repository discovery, surfacing mid-pagination partial failures."""

    repositories: tuple[DiscoveredRepositoryRecord, ...]
    total_reported: int
    partial_sync: bool = False
    warning_detail: str | None = None


@dataclass(frozen=True, slots=True)
class ProviderRunRecord:
    """Normalized CI workflow/pipeline run metadata (`get_run`)."""

    external_run_id: str
    attempt_key: str
    head_sha: str
    ref: str
    event_type: str
    status: str
    conclusion: str | None
    jobs_complete: bool
    raw_vendor_status: str | None = None
    head_repo_id: str | None = None
    base_repo_id: str | None = None
    head_repo_fork: bool = False


@dataclass(frozen=True, slots=True)
class ProviderJobRecord:
    """Normalized CI job metadata (`list_jobs`)."""

    external_job_id: str
    name: str
    status: str
    conclusion: str | None
    started_at: datetime | None
    completed_at: datetime | None
    matrix_dimensions: dict[str, str] = field(default_factory=dict)
    retry_of_id: str | None = None


@dataclass(frozen=True, slots=True)
class ProviderArtifactRecord:
    """Normalized CI artifact metadata (`get_artifact_metadata`)."""

    external_artifact_id: str
    name: str
    size_bytes: int
    expired: bool
    created_at: datetime | None = None
    expires_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ProviderDraftReviewRecord:
    """Normalized draft PR/MR record (`create_draft_review`, `find_review_by_marker`)."""

    external_review_id: str
    number: str
    html_url: str
    head_branch: str
    base_branch: str
    head_sha: str
    draft: bool
    state: str


@dataclass(frozen=True, slots=True)
class ProviderRemoteCheckRecord:
    """Normalized commit check-run / commit-status record (`get_remote_checks`)."""

    external_check_id: str
    name: str
    head_sha: str
    status: str
    conclusion: str | None
    required: bool = False


@dataclass(frozen=True, slots=True)
class ForkPullRequestTrustVerdict:
    """`SEC-031` untrusted fork pull-request head classification verdict."""

    trusted_same_repo: bool
    untrusted_fork: bool
    allow_auto_repair: bool
    reason_code: str


@dataclass(frozen=True, slots=True)
class ProviderPollItem:
    """Single run/pipeline observation returned during conditional polling (`SRC-04`)."""

    run: ProviderRunRecord
    observed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ProviderPollRunsResult:
    """Conditional polling result with `ETag`, rate-limit metadata & pagination (`SRC-04`)."""

    items: tuple[ProviderPollItem, ...]
    not_modified: bool = False
    etag: str | None = None
    rate_limit_remaining: int | None = None
    rate_limit_reset_at: datetime | None = None
    has_next_page: bool = False
    next_page: int | None = None
    oldest_observed_at: datetime | None = None
    newest_observed_at: datetime | None = None
    retention_expired: bool = False


def parse_retry_after_seconds(
    raw_value: str | None,
    *,
    now: datetime,
    max_seconds: int = 3600,
) -> int | None:
    """Parse HTTP `Retry-After` delta-seconds or RFC 7231 HTTP-date into bounded seconds."""
    if raw_value is None:
        return None
    cleaned = raw_value.strip()
    if not cleaned:
        return None
    if cleaned.isdigit():
        return max(1, min(int(cleaned), max_seconds))
    try:
        dt = parsedate_to_datetime(cleaned)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    delta = int((dt.astimezone(UTC) - now.astimezone(UTC)).total_seconds())
    return max(1, min(delta, max_seconds))


class ProviderCredentialVaultProtocol(Protocol):
    """`Z1`-safe interface for `Z2` provider secret operations & encrypted JIT token caching."""

    async def store_provider_credential(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        plaintext: bytes,
        purpose: Literal["provider_read", "webhook_auth"],
        require_rsa_pem: bool = False,
        now: datetime | None = None,
    ) -> tuple[str, int]: ...

    async def inspect_secret_presence(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        secret_ref: str,
        expected_purpose: Literal["provider_read", "webhook_auth"],
    ) -> tuple[bool, int | None]: ...

    async def revoke_provider_credential(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        secret_ref: str,
        connection_id: str | None = None,
        now: datetime | None = None,
    ) -> None: ...

    async def mint_github_app_jwt(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        secret_ref: str,
        issuer: str,
        now: datetime,
    ) -> str: ...

    async def verify_webhook_hmac(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        secret_ref: str,
        raw_body: bytes,
        signature_header: str,
    ) -> bool: ...

    async def rotate_provider_credential(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        secret_ref: str,
        new_plaintext: bytes,
        purpose: Literal["provider_read", "webhook_auth"],
        retain_previous_for_overlap: bool = False,
        now: datetime | None = None,
    ) -> tuple[str, int]: ...

    async def resolve_provider_access_token(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        secret_ref: str,
    ) -> str: ...

    async def verify_gitlab_webhook_auth(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        secret_ref: str,
        pinned_auth_mode: ConnectionAuthMode,
        headers: Mapping[str, str],
        raw_body: bytes,
        now: datetime,
    ) -> bool: ...

    def get_cached_jit_installation_token(
        self,
        *,
        workspace_id: str,
        connection_id: str,
        installation_id: str,
        scope_key: str,
        now: datetime,
    ) -> str | None: ...

    def cache_jit_installation_token(
        self,
        *,
        workspace_id: str,
        connection_id: str,
        installation_id: str,
        scope_key: str,
        token: str,
        expires_at: datetime,
        now: datetime,
    ) -> None: ...

    def invalidate_cached_tokens(
        self,
        *,
        workspace_id: str,
        connection_id: str | None = None,
    ) -> int: ...


class SourceProviderAdapter(Protocol):
    """Unified source-provider interface (`docs/12_PROVIDER_INTEGRATIONS.md`)."""

    async def list_repos(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        per_page: int = 50,
        scan_workflows: bool = True,
        now: datetime | None = None,
    ) -> PaginatedRepoDiscoveryResult: ...

    async def get_run(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        external_run_id: str,
        now: datetime | None = None,
    ) -> ProviderRunRecord: ...

    async def list_jobs(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        external_run_id: str,
        attempt_number: int | None = None,
        now: datetime | None = None,
    ) -> Sequence[ProviderJobRecord]: ...

    async def get_job_log(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        external_job_id: str,
        max_bytes: int = 2_097_152,
        now: datetime | None = None,
    ) -> bytes: ...

    async def get_artifact_metadata(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        external_run_id: str,
        now: datetime | None = None,
    ) -> Sequence[ProviderArtifactRecord]: ...

    async def download_artifact_archive(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        external_artifact_id: str,
        max_bytes: int = 104_857_601,
        now: datetime | None = None,
    ) -> bytes: ...

    async def get_commit_diff(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        base_sha: str,
        head_sha: str,
        max_bytes: int = 1_048_576,
        now: datetime | None = None,
    ) -> str: ...

    async def resolve_workflow_config(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        ref: str,
        now: datetime | None = None,
    ) -> Mapping[str, str]: ...

    async def get_permissions(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        installation_id_override: str | None = None,
        now: datetime | None = None,
    ) -> ProviderPermissionSummary: ...

    async def create_branch(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        branch_name: str,
        from_sha: str,
        now: datetime | None = None,
    ) -> str: ...

    async def push_commit(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        branch_name: str,
        expected_parent_sha: str,
        commit_message: str,
        file_changes: Mapping[str, str],
        now: datetime | None = None,
    ) -> str: ...

    async def create_draft_review(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        head_branch: str,
        base_branch: str,
        title: str,
        body: str,
        now: datetime | None = None,
    ) -> ProviderDraftReviewRecord: ...

    async def find_review_by_marker(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        head_branch: str,
        marker: str,
        now: datetime | None = None,
    ) -> ProviderDraftReviewRecord | None: ...

    async def get_remote_checks(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        head_sha: str,
        now: datetime | None = None,
    ) -> Sequence[ProviderRemoteCheckRecord]: ...

    async def verify_webhook(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        headers: Mapping[str, str],
        raw_body: bytes,
        now: datetime | None = None,
    ) -> bool: ...

    async def sync_cursor(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        since_cursor: str | None = None,
        now: datetime | None = None,
    ) -> tuple[Sequence[ProviderRunRecord], str | None]: ...

    async def poll_runs(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        since_cursor: str | None = None,
        etag: str | None = None,
        page: int = 1,
        per_page: int = 50,
        now: datetime | None = None,
    ) -> ProviderPollRunsResult: ...

    async def revoke_connection(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        now: datetime | None = None,
    ) -> None: ...
