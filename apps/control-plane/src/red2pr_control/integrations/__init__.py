"""Source provider integrations package (`U09`..`U11`: GitHub, GitLab, Webhooks & Polling)."""

from red2pr_control.integrations.base import (
    DiscoveredRepositoryRecord,
    ForkPullRequestTrustVerdict,
    PaginatedRepoDiscoveryResult,
    ProviderArtifactRecord,
    ProviderConnectionContext,
    ProviderCredentialVaultProtocol,
    ProviderDraftReviewRecord,
    ProviderError,
    ProviderErrorCode,
    ProviderJobRecord,
    ProviderPermissionSummary,
    ProviderPollItem,
    ProviderPollRunsResult,
    ProviderRemoteCheckRecord,
    ProviderRunRecord,
    SourceProviderAdapter,
    parse_retry_after_seconds,
)
from red2pr_control.integrations.github_app import (
    GITHUB_API_VERSION,
    GitHubAppAdapter,
    GitHubIntegrationService,
    WorkflowHazardScanner,
)
from red2pr_control.integrations.gitlab_client import (
    GITLAB_API_VERSION,
    GitLabAdapter,
    GitLabChildPipelineRecord,
    parse_gitlab_semver,
    scan_gitlab_ci_yaml,
)
from red2pr_control.integrations.poller import (
    ConnectionPollSummary,
    LocalPollingService,
    RepoPollOutcome,
    compute_poll_jitter_seconds,
)
from red2pr_control.integrations.reconciler import (
    MissedEventReconciler,
    PendingInboxReconcileSummary,
)
from red2pr_control.integrations.router import build_integrations_router
from red2pr_control.integrations.webhooks import (
    NormalizedRunCandidate,
    TriggerResolution,
    WebhookIngestService,
    build_webhooks_router,
    is_bot_authored_repair_loop,
    record_normalized_run_failure_trigger,
    sanitize_webhook_headers,
)

ProviderIntegrationService = GitHubIntegrationService

__all__ = [
    "GITHUB_API_VERSION",
    "GITLAB_API_VERSION",
    "ConnectionPollSummary",
    "DiscoveredRepositoryRecord",
    "ForkPullRequestTrustVerdict",
    "GitHubAppAdapter",
    "GitHubIntegrationService",
    "GitLabAdapter",
    "GitLabChildPipelineRecord",
    "LocalPollingService",
    "MissedEventReconciler",
    "NormalizedRunCandidate",
    "PaginatedRepoDiscoveryResult",
    "PendingInboxReconcileSummary",
    "ProviderArtifactRecord",
    "ProviderConnectionContext",
    "ProviderCredentialVaultProtocol",
    "ProviderDraftReviewRecord",
    "ProviderError",
    "ProviderErrorCode",
    "ProviderIntegrationService",
    "ProviderJobRecord",
    "ProviderPermissionSummary",
    "ProviderPollItem",
    "ProviderPollRunsResult",
    "ProviderRemoteCheckRecord",
    "ProviderRunRecord",
    "RepoPollOutcome",
    "SourceProviderAdapter",
    "TriggerResolution",
    "WebhookIngestService",
    "WorkflowHazardScanner",
    "build_integrations_router",
    "build_webhooks_router",
    "compute_poll_jitter_seconds",
    "is_bot_authored_repair_loop",
    "parse_gitlab_semver",
    "parse_retry_after_seconds",
    "record_normalized_run_failure_trigger",
    "sanitize_webhook_headers",
    "scan_gitlab_ci_yaml",
]
