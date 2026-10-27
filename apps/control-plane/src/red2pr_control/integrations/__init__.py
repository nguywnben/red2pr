"""Source provider integrations package (`U09`: unified adapter + GitHub App + `A-06`/`A-23`)."""

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
    ProviderRemoteCheckRecord,
    ProviderRunRecord,
    SourceProviderAdapter,
)
from red2pr_control.integrations.github_app import (
    GITHUB_API_VERSION,
    GitHubAppAdapter,
    GitHubIntegrationService,
    WorkflowHazardScanner,
)
from red2pr_control.integrations.router import build_integrations_router

__all__ = [
    "GITHUB_API_VERSION",
    "DiscoveredRepositoryRecord",
    "ForkPullRequestTrustVerdict",
    "GitHubAppAdapter",
    "GitHubIntegrationService",
    "PaginatedRepoDiscoveryResult",
    "ProviderArtifactRecord",
    "ProviderConnectionContext",
    "ProviderCredentialVaultProtocol",
    "ProviderDraftReviewRecord",
    "ProviderError",
    "ProviderErrorCode",
    "ProviderJobRecord",
    "ProviderPermissionSummary",
    "ProviderRemoteCheckRecord",
    "ProviderRunRecord",
    "SourceProviderAdapter",
    "WorkflowHazardScanner",
    "build_integrations_router",
]
