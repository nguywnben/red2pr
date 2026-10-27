"""Source provider integrations package (`U09`..`U10`: GitHub App + GitLab + `A-06`/`A-23`)."""

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
from red2pr_control.integrations.gitlab_client import (
    GITLAB_API_VERSION,
    GitLabAdapter,
    GitLabChildPipelineRecord,
    parse_gitlab_semver,
    scan_gitlab_ci_yaml,
)
from red2pr_control.integrations.router import build_integrations_router

ProviderIntegrationService = GitHubIntegrationService

__all__ = [
    "GITHUB_API_VERSION",
    "GITLAB_API_VERSION",
    "DiscoveredRepositoryRecord",
    "ForkPullRequestTrustVerdict",
    "GitHubAppAdapter",
    "GitHubIntegrationService",
    "GitLabAdapter",
    "GitLabChildPipelineRecord",
    "PaginatedRepoDiscoveryResult",
    "ProviderArtifactRecord",
    "ProviderConnectionContext",
    "ProviderCredentialVaultProtocol",
    "ProviderDraftReviewRecord",
    "ProviderError",
    "ProviderErrorCode",
    "ProviderIntegrationService",
    "ProviderJobRecord",
    "ProviderPermissionSummary",
    "ProviderRemoteCheckRecord",
    "ProviderRunRecord",
    "SourceProviderAdapter",
    "WorkflowHazardScanner",
    "build_integrations_router",
    "parse_gitlab_semver",
    "scan_gitlab_ci_yaml",
]
