"""GitHub App adapter, JIT scoped installation tokens, workflow hazard scanner & service (`U09`).

Implements `SRC-01`, `A-06` (GitHub slice), `A-23`, `S-08`, `S-09`, `W-02`, `SEC-001`,
`SEC-011`, `SEC-031`, `SEC-032`, and `ADR-037`:
- `WorkflowHazardScanner`: safe YAML inspection of `.github/workflows/*.yml|*.yaml` flagging
  `pull_request_target`, privileged `workflow_run`, `permissions: write-all`, and deployment
  triggers, plus untrusted fork pull-request head classification (`SEC-031`).
- `GitHubAppAdapter`: unified `SourceProviderAdapter` pinning `X-GitHub-Api-Version: 2026-03-10`,
  routing all outbound calls through `ADR-037` `EgressPolicyEngine` / `EgressSafeHttpClient`,
  separating RS256 App JWTs from encrypted cached JIT scoped installation tokens, and preserving
  prior repositories on mid-pagination transient failures.
- `GitHubIntegrationService`: workspace-RLS-isolated `A-06` & `A-23` lifecycle, single-use
  10-minute installation callback state nonces, durable revocation cascade (`SEC-011`) suspending
  active `task_jobs`, reconnect safety (`W-02`), and `SetupStepRegistry` `provider_connect` probe.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import secrets
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast
from urllib.parse import quote, urlparse

import httpx
import yaml
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.crypto import (
    CryptoVerificationError,
    decode_gitlab_signing_key,
    sha256_canonical_json,
)
from py_contracts.events import EventEnvelope, ProviderConnectionEventPayload
from py_contracts.integrations import (
    CapabilityAvailability,
    CapabilitySnapshot,
    Connection,
    ConnectionAuthMode,
    ConnectionDetailResponse,
    ConnectionPage,
    ConnectionPatchRequest,
    ConnectionProbeResponse,
    ConnectionStatus,
    ConnectionSyncResponse,
    ConnectionWrite,
    GitHubCallbackResponse,
    GitHubInstallationConfirmRequest,
    GitHubInstallationConfirmResponse,
    GitHubInstallStateCreateRequest,
    GitHubInstallStateResponse,
    ProviderKind,
    Repository,
    RepositoryMode,
    RepositoryVisibility,
    SecretPresence,
    WorkflowHazardFinding,
    WorkflowHazardStatus,
)
from py_contracts.primitives import ActionReceipt, InternalId, new_uuid7
from py_contracts.repairs import SetupWizardPhase
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.egress import (
    CaBundleResolverProtocol,
    EgressBlockedError,
    EgressPolicyEngine,
    EgressSafeHttpClient,
)
from red2pr_control.core.errors import (
    BadRequestError,
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    GoneError,
    NotFoundError,
    UnprocessableEntityError,
)
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.db.base import (
    CapabilitySnapshotModel,
    ProviderConnectionModel,
    ProviderInstallStateModel,
    RepositoryModel,
    TaskJobModel,
    WorkspaceModel,
)
from red2pr_control.db.idempotency import (
    claim_idempotent_operation,
    complete_idempotent_operation,
    upsert_operation_receipt,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.rbac import (
    WorkspaceAccessContext,
    compute_query_filter_hash,
    decode_signed_cursor,
    encode_signed_cursor,
    enforce_optimistic_version,
)
from red2pr_control.iam.sessions import AuthenticatedContext
from red2pr_control.integrations.base import (
    DiscoveredRepositoryRecord,
    ForkPullRequestTrustVerdict,
    PaginatedRepoDiscoveryResult,
    ProviderArtifactRecord,
    ProviderConnectionContext,
    ProviderCredentialVaultProtocol,
    ProviderDraftReviewRecord,
    ProviderError,
    ProviderJobRecord,
    ProviderPermissionSummary,
    ProviderRemoteCheckRecord,
    ProviderRunRecord,
)
from red2pr_control.integrations.gitlab_client import GITLAB_API_VERSION, GitLabAdapter
from red2pr_control.operations.setup_wizard import (
    SetupStepProbeCallable,
    SetupStepProbeResult,
    SetupStepRegistry,
)

GITHUB_API_VERSION = "2026-03-10"
INSTALL_STATE_TTL = timedelta(minutes=10)
MAX_WORKFLOW_YAML_BYTES = 262_144
MAX_WORKFLOW_FILES_PER_REPO = 50

REQUIRED_GITHUB_READ_PERMISSIONS: dict[str, str] = {
    "metadata": "read",
    "contents": "read",
    "actions": "read",
}
OPTIONAL_GITHUB_REPAIR_PERMISSIONS: dict[str, str] = {
    "checks": "read",
    "pull_requests": "write",
    "contents": "write",
}
EXCESS_DISCOURAGED_PERMISSIONS: frozenset[str] = frozenset(
    {
        "administration",
        "organization_administration",
        "workflows",
        "members",
        "secrets",
    }
)

_PERMISSION_RANK: dict[str, int] = {"none": 0, "read": 1, "write": 2, "admin": 3}
_UUID_ADAPTER: TypeAdapter[str] = TypeAdapter(InternalId)


def _permission_satisfies(granted: str | None, required: str) -> bool:
    if granted is None:
        return False
    return _PERMISSION_RANK.get(granted.lower(), 0) >= _PERMISSION_RANK.get(required.lower(), 99)


def _hash_install_state(raw_state: str) -> str:
    return hashlib.sha256(raw_state.encode("utf-8")).hexdigest()


def _normalize_origin(raw_url: str | None) -> str | None:
    if raw_url is None:
        return None
    parsed = urlparse(raw_url.strip())
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _parse_iso_dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _split_repo_full_name(repo_full_name: str) -> tuple[str, str]:
    cleaned = repo_full_name.strip().strip("/")
    parts = cleaned.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ProviderError(
            code="UNSUPPORTED",
            detail=f"Invalid GitHub repository full name: {repo_full_name!r}",
            provider="github",
        )
    return parts[0], parts[1]


class WorkflowHazardScanner:
    """Inspects `.github/workflows/*.yml|*.yaml` for privileged trigger & permission hazards."""

    @staticmethod
    def _extract_trigger_names(raw_on: Any) -> set[str]:
        if isinstance(raw_on, str):
            return {raw_on.strip()} if raw_on.strip() else set()
        if isinstance(raw_on, Sequence) and not isinstance(raw_on, (str, bytes)):
            return {str(item).strip() for item in raw_on if isinstance(item, str) and item.strip()}
        if isinstance(raw_on, Mapping):
            return {str(k).strip() for k in raw_on if str(k).strip()}
        return set()

    @staticmethod
    def _has_write_all_permissions(raw_perms: Any) -> bool:
        if isinstance(raw_perms, str):
            return raw_perms.strip().lower() == "write-all"
        if isinstance(raw_perms, Mapping):
            for scope_name, level in raw_perms.items():
                if (
                    str(scope_name).strip().lower() in {"id-token", "deployments", "packages"}
                    and str(level).strip().lower() == "write"
                ):
                    return True
        return False

    @classmethod
    def scan_workflow_yaml(
        cls,
        *,
        workflow_path: str,
        raw_yaml: str | bytes,
    ) -> list[WorkflowHazardFinding]:
        """Parse and inspect a single GitHub Actions workflow file for `SEC-031` hazards."""
        safe_path = workflow_path.strip()[:256] or ".github/workflows/unknown.yml"
        raw_bytes = raw_yaml.encode("utf-8") if isinstance(raw_yaml, str) else raw_yaml
        if len(raw_bytes) > MAX_WORKFLOW_YAML_BYTES:
            return [
                WorkflowHazardFinding(
                    code="workflow_parse_warning",
                    severity="low",
                    workflow_path=safe_path,
                    detail=(
                        "Workflow file exceeds 256 KiB inspection ceiling; manual review needed."
                    ),
                )
            ]

        try:
            parsed = yaml.safe_load(raw_bytes.decode("utf-8", errors="replace"))
        except yaml.YAMLError:
            return [
                WorkflowHazardFinding(
                    code="workflow_parse_warning",
                    severity="low",
                    workflow_path=safe_path,
                    detail="Workflow YAML could not be parsed cleanly during hazard inspection.",
                )
            ]

        if not isinstance(parsed, Mapping):
            return []

        # PyYAML YAML 1.1 parses unquoted `on:` as boolean True (`{True: ...}`).
        raw_on = parsed.get("on") if "on" in parsed else parsed.get(True)
        triggers = cls._extract_trigger_names(raw_on)
        findings: list[WorkflowHazardFinding] = []

        if "pull_request_target" in triggers:
            findings.append(
                WorkflowHazardFinding(
                    code="pull_request_target",
                    severity="high",
                    workflow_path=safe_path,
                    detail=(
                        "Workflow uses pull_request_target, executing with base-repository "
                        "privileges and secrets on untrusted PR events."
                    ),
                )
            )

        if "workflow_run" in triggers:
            findings.append(
                WorkflowHazardFinding(
                    code="privileged_workflow_run",
                    severity="high",
                    workflow_path=safe_path,
                    detail=(
                        "Workflow uses privileged downstream workflow_run trigger; "
                        "auto_repair requires explicit downstream policy approval."
                    ),
                )
            )

        write_all = cls._has_write_all_permissions(parsed.get("permissions"))
        raw_jobs = parsed.get("jobs")
        has_environment = False
        if isinstance(raw_jobs, Mapping):
            for _job_id, job_cfg in raw_jobs.items():
                if not isinstance(job_cfg, Mapping):
                    continue
                if cls._has_write_all_permissions(job_cfg.get("permissions")):
                    write_all = True
                if job_cfg.get("environment") is not None:
                    has_environment = True

        if write_all:
            findings.append(
                WorkflowHazardFinding(
                    code="write_all_permissions",
                    severity="high",
                    workflow_path=safe_path,
                    detail=(
                        "Workflow grants write-all or sensitive deployment/OIDC write permissions "
                        "to GITHUB_TOKEN."
                    ),
                )
            )

        deploy_triggers = triggers.intersection({"deployment", "deployment_status", "release"})
        if has_environment or deploy_triggers:
            findings.append(
                WorkflowHazardFinding(
                    code="deploy_trigger",
                    severity="medium",
                    workflow_path=safe_path,
                    detail=(
                        "Workflow references deployment environments or release/deployment "
                        "triggers that could cause side effects."
                    ),
                )
            )

        return findings

    @staticmethod
    def should_block_auto_repair(findings: Sequence[WorkflowHazardFinding]) -> bool:
        blocking_codes = {
            "pull_request_target",
            "privileged_workflow_run",
            "write_all_permissions",
            "deploy_trigger",
        }
        return any(item.code in blocking_codes for item in findings)

    @staticmethod
    def classify_pull_request_trust(
        *,
        base_repo_id: str,
        head_repo_id: str | None,
        head_repo_fork: bool,
    ) -> ForkPullRequestTrustVerdict:
        """Ensure untrusted fork PR heads never inherit base-repo execution grants (`SEC-031`)."""
        if head_repo_fork or not head_repo_id or head_repo_id != base_repo_id:
            return ForkPullRequestTrustVerdict(
                trusted_same_repo=False,
                untrusted_fork=True,
                allow_auto_repair=False,
                reason_code="untrusted_fork_head",
            )
        return ForkPullRequestTrustVerdict(
            trusted_same_repo=True,
            untrusted_fork=False,
            allow_auto_repair=True,
            reason_code="same_repository_head",
        )


class GitHubAppAdapter:
    """Unified `SourceProviderAdapter` for GitHub.com and GitHub Enterprise Server."""

    def __init__(
        self,
        *,
        vault: ProviderCredentialVaultProtocol,
        egress_policy: EgressPolicyEngine,
        ca_bundle_resolver: CaBundleResolverProtocol | None = None,
        transport_override: httpx.AsyncBaseTransport | None = None,
        redactor: Redactor | None = None,
        timeout_seconds: float = 15.0,
    ) -> None:
        self._vault = vault
        self._egress_policy = egress_policy
        self._ca_resolver = ca_bundle_resolver
        self._transport_override = transport_override
        self._redactor = redactor or DEFAULT_REDACTOR
        self._timeout_seconds = timeout_seconds

    def _build_url(self, base_url: str, path: str) -> str:
        clean_base = base_url.strip().rstrip("/")
        clean_path = path if path.startswith("/") else f"/{path}"
        return f"{clean_base}{clean_path}"

    def _default_headers(
        self,
        *,
        bearer_token: str | None = None,
        accept: str = "application/vnd.github+json",
    ) -> dict[str, str]:
        headers = {
            "Accept": accept,
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": "Red2PR-ControlPlane/0.1",
        }
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        return headers

    @staticmethod
    def _is_sensitive_header(header_name: str) -> bool:
        lower = header_name.strip().lower()
        if lower in {
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "x-gitlab-token",
            "private-token",
            "x-hub-signature",
            "x-hub-signature-256",
            "x-csrf-token",
        }:
            return True
        return lower.endswith(("-token", "-secret", "-key", "-signature"))

    @staticmethod
    def _origin_tuple(url: httpx.URL) -> tuple[str, str, int]:
        scheme = url.scheme.lower()
        port = url.port if url.port is not None else (443 if scheme == "https" else 80)
        return (scheme, url.host.lower(), port)

    async def _send_request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Any = None,
    ) -> httpx.Response:
        target_url = httpx.URL(url)

        try:
            if self._transport_override is not None:
                max_redirects = 3
                current_method = method.upper()
                current_url = target_url
                current_headers = dict(headers)
                current_json = json_body
                async with httpx.AsyncClient(
                    transport=self._transport_override,
                    follow_redirects=False,
                    trust_env=False,
                    timeout=httpx.Timeout(self._timeout_seconds),
                ) as client:
                    for hop in range(max_redirects + 1):
                        await self._egress_policy.evaluate_and_resolve(
                            adapter="github", url=current_url
                        )
                        resp = await client.request(
                            current_method,
                            current_url,
                            headers=current_headers,
                            json=current_json,
                        )
                        if resp.status_code not in {301, 302, 303, 307, 308}:
                            return resp
                        location = resp.headers.get("location")
                        if not location:
                            return resp
                        await resp.aclose()
                        if hop >= max_redirects:
                            raise EgressBlockedError(
                                code="egress_redirect_limit_exceeded",
                                detail=(
                                    "Outbound request exceeded max_redirects=3 "
                                    "for adapter 'github'."
                                ),
                                adapter="github",
                                target_url=str(current_url.copy_with(query=None, fragment=None)),
                            )
                        next_url = current_url.join(location.strip())
                        if self._origin_tuple(next_url) != self._origin_tuple(current_url):
                            current_headers = {
                                k: v
                                for k, v in current_headers.items()
                                if not self._is_sensitive_header(k)
                            }
                        if resp.status_code == 303 or (
                            resp.status_code in {301, 302} and current_method == "POST"
                        ):
                            current_method = "GET"
                            current_json = None
                            current_headers = {
                                k: v
                                for k, v in current_headers.items()
                                if k.lower() not in {"content-length", "content-type"}
                            }
                        current_url = next_url
                raise AssertionError("Unreachable redirect loop exit")

            async with EgressSafeHttpClient(
                adapter="github",
                policy_engine=self._egress_policy,
                ca_bundle_resolver=self._ca_resolver,
                timeout_seconds=self._timeout_seconds,
            ) as safe_client:
                return await safe_client.request(
                    method.upper(),
                    target_url,
                    headers=headers,
                    json=json_body,
                )
        except EgressBlockedError:
            raise
        except httpx.TimeoutException as exc:
            raise ProviderError(
                code="TRANSIENT",
                detail="GitHub API request timed out.",
                provider="github",
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(
                code="TRANSIENT",
                detail=self._redactor.redact_text(f"GitHub transport error: {exc}"),
                provider="github",
            ) from exc

    def _raise_for_github_status(
        self,
        response: httpx.Response,
        *,
        treat_404_as_revoked: bool = False,
        treat_409_422_as_stale_sha: bool = False,
    ) -> None:
        status_code = response.status_code
        if 200 <= status_code < 300:
            return

        retry_after: int | None = None
        raw_retry = response.headers.get("retry-after")
        if raw_retry and raw_retry.strip().isdigit():
            retry_after = int(raw_retry.strip())

        body_msg = ""
        try:
            parsed = response.json()
            if isinstance(parsed, Mapping) and isinstance(parsed.get("message"), str):
                body_msg = parsed["message"]
        except Exception:
            body_msg = response.text[:300]
        clean_msg = self._redactor.redact_text(body_msg or f"HTTP {status_code}")[:300]
        lower_msg = clean_msg.lower()

        if status_code == 429 or (
            status_code == 403
            and (
                response.headers.get("x-ratelimit-remaining") == "0"
                or "rate limit" in lower_msg
                or "secondary rate" in lower_msg
            )
        ):
            raise ProviderError(
                code="RATE_LIMIT",
                detail=f"GitHub API rate limit exceeded: {clean_msg}",
                provider="github",
                status_code=status_code,
                retry_after_seconds=retry_after or 60,
            )

        if status_code == 401:
            raise ProviderError(
                code="REVOKED",
                detail=f"GitHub credentials rejected or revoked: {clean_msg}",
                provider="github",
                status_code=status_code,
            )

        if status_code == 403:
            if any(
                marker in lower_msg
                for marker in ("suspended", "revoked", "installation has been", "bad credentials")
            ):
                raise ProviderError(
                    code="REVOKED",
                    detail=f"GitHub App installation suspended or revoked: {clean_msg}",
                    provider="github",
                    status_code=status_code,
                )
            raise ProviderError(
                code="FORBIDDEN",
                detail=f"GitHub permission denied: {clean_msg}",
                provider="github",
                status_code=status_code,
            )

        if status_code == 404:
            if treat_404_as_revoked:
                raise ProviderError(
                    code="REVOKED",
                    detail="GitHub App installation was uninstalled or is not accessible.",
                    provider="github",
                    status_code=404,
                )
            raise ProviderError(
                code="NOT_FOUND",
                detail=f"GitHub resource not found: {clean_msg}",
                provider="github",
                status_code=404,
            )

        if treat_409_422_as_stale_sha and status_code in (409, 422):
            raise ProviderError(
                code="STALE_SHA",
                detail=f"GitHub reference/SHA conflict: {clean_msg}",
                provider="github",
                status_code=status_code,
            )

        if status_code in (500, 502, 503, 504):
            raise ProviderError(
                code="TRANSIENT",
                detail=f"GitHub upstream transient error ({status_code}): {clean_msg}",
                provider="github",
                status_code=status_code,
                retry_after_seconds=retry_after,
            )

        raise ProviderError(
            code="UNSUPPORTED",
            detail=f"Unexpected GitHub response ({status_code}): {clean_msg}",
            provider="github",
            status_code=status_code,
        )

    async def _mint_app_jwt(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        now: datetime,
    ) -> str:
        issuer = ctx.app_id or ctx.client_id
        if not issuer or not ctx.credential_secret_ref:
            raise ProviderError(
                code="UNSUPPORTED",
                detail="GitHub App ID and private key secret reference are required.",
                provider="github",
            )
        return await self._vault.mint_github_app_jwt(
            session,
            workspace_id=ctx.workspace_id,
            secret_ref=ctx.credential_secret_ref,
            issuer=issuer,
            now=now,
        )

    async def _get_jit_installation_token(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        permissions: Mapping[str, str],
        repositories: Sequence[str] | None = None,
        installation_id_override: str | None = None,
        now: datetime,
    ) -> str:
        install_id = installation_id_override or ctx.installation_id
        if not install_id:
            raise ProviderError(
                code="UNSUPPORTED",
                detail="GitHub App connection has no confirmed installation_id.",
                provider="github",
            )

        # Never request discouraged excess scopes (e.g. workflows, org admin)
        minimal_perms = {
            k: v for k, v in sorted(permissions.items()) if k not in EXCESS_DISCOURAGED_PERMISSIONS
        }
        sorted_repos = sorted({r.strip() for r in (repositories or ()) if r.strip()})
        scope_key = sha256_canonical_json(
            {"permissions": minimal_perms, "repositories": sorted_repos}
        )

        cached = self._vault.get_cached_jit_installation_token(
            workspace_id=ctx.workspace_id,
            connection_id=ctx.connection_id,
            installation_id=install_id,
            scope_key=scope_key,
            now=now,
        )
        if cached is not None:
            return cached

        app_jwt = await self._mint_app_jwt(session, ctx, now=now)
        req_body: dict[str, Any] = {"permissions": minimal_perms}
        if sorted_repos:
            req_body["repositories"] = sorted_repos

        resp = await self._send_request(
            "POST",
            self._build_url(
                ctx.base_url,
                f"/app/installations/{quote(install_id, safe='')}/access_tokens",
            ),
            headers=self._default_headers(bearer_token=app_jwt),
            json_body=req_body,
        )
        self._raise_for_github_status(resp, treat_404_as_revoked=True)

        data = resp.json()
        raw_token = data.get("token") if isinstance(data, Mapping) else None
        expires_raw = data.get("expires_at") if isinstance(data, Mapping) else None
        expires_at = _parse_iso_dt(expires_raw)
        if not isinstance(raw_token, str) or not raw_token.strip() or expires_at is None:
            raise ProviderError(
                code="TRANSIENT",
                detail="GitHub access_tokens response omitted token or expires_at.",
                provider="github",
            )

        self._vault.cache_jit_installation_token(
            workspace_id=ctx.workspace_id,
            connection_id=ctx.connection_id,
            installation_id=install_id,
            scope_key=scope_key,
            token=raw_token,
            expires_at=expires_at,
            now=now,
        )
        return raw_token

    async def get_permissions(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        installation_id_override: str | None = None,
        now: datetime | None = None,
    ) -> ProviderPermissionSummary:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        app_jwt = await self._mint_app_jwt(session, ctx, now=ref_now)

        app_resp = await self._send_request(
            "GET",
            self._build_url(ctx.base_url, "/app"),
            headers=self._default_headers(bearer_token=app_jwt),
        )
        self._raise_for_github_status(app_resp)
        app_json = app_resp.json()
        if not isinstance(app_json, Mapping):
            raise ProviderError(
                code="TRANSIENT",
                detail="Malformed /app metadata payload from GitHub.",
                provider="github",
            )

        observed_app_id = str(app_json.get("id", ""))
        if ctx.app_id and observed_app_id and observed_app_id != ctx.app_id:
            raise ProviderError(
                code="FORBIDDEN",
                detail=(
                    f"Authenticated GitHub App ID {observed_app_id!r} does not match "
                    f"configured app_id {ctx.app_id!r}."
                ),
                provider="github",
                status_code=403,
            )

        vendor_ver = app_resp.headers.get("x-github-enterprise-version") or "github.com"
        install_id = installation_id_override or ctx.installation_id

        if not install_id:
            raw_app_perms = app_json.get("permissions")
            granted: dict[str, str] = (
                {str(k): str(v) for k, v in raw_app_perms.items() if isinstance(v, str)}
                if isinstance(raw_app_perms, Mapping)
                else {}
            )
            missing_req = tuple(
                perm
                for perm, level in REQUIRED_GITHUB_READ_PERMISSIONS.items()
                if not _permission_satisfies(granted.get(perm), level)
            )
            missing_opt = tuple(
                f"{perm}:{level}"
                for perm, level in OPTIONAL_GITHUB_REPAIR_PERMISSIONS.items()
                if not _permission_satisfies(granted.get(perm), level)
            )
            excess = tuple(sorted(k for k in granted if k in EXCESS_DISCOURAGED_PERMISSIONS))
            owner_obj = app_json.get("owner")
            owner_login = (
                str(owner_obj.get("login"))
                if isinstance(owner_obj, Mapping) and isinstance(owner_obj.get("login"), str)
                else None
            )
            return ProviderPermissionSummary(
                account_login=owner_login,
                vendor_version=vendor_ver[:120],
                api_version=GITHUB_API_VERSION,
                granted_permissions=granted,
                missing_required_permissions=missing_req,
                missing_optional_permissions=missing_opt,
                excess_unused_permissions=excess,
                capabilities={
                    "app_jwt_auth": "available",
                    "repo_discovery": "unavailable",
                    "actions_logs": "unavailable",
                    "draft_pr": "unavailable",
                    "webhook_hmac": (
                        "available" if ctx.webhook_secret_ref is not None else "unavailable"
                    ),
                },
                suspended=False,
                detail=(
                    "GitHub App JWT verified; confirm an installation to enable "
                    "repository discovery."
                ),
            )

        inst_resp = await self._send_request(
            "GET",
            self._build_url(
                ctx.base_url,
                f"/app/installations/{quote(install_id, safe='')}",
            ),
            headers=self._default_headers(bearer_token=app_jwt),
        )
        self._raise_for_github_status(inst_resp, treat_404_as_revoked=True)
        inst_json = inst_resp.json()
        if not isinstance(inst_json, Mapping):
            raise ProviderError(
                code="TRANSIENT",
                detail="Malformed installation payload from GitHub.",
                provider="github",
            )

        inst_app_id = str(inst_json.get("app_id", ""))
        if ctx.app_id and inst_app_id and inst_app_id != ctx.app_id:
            raise ProviderError(
                code="FORBIDDEN",
                detail="Installation does not belong to the configured GitHub App.",
                provider="github",
                status_code=403,
            )

        suspended_at = inst_json.get("suspended_at")
        if suspended_at is not None:
            raise ProviderError(
                code="REVOKED",
                detail="GitHub App installation is currently suspended.",
                provider="github",
                status_code=403,
            )

        raw_perms = inst_json.get("permissions")
        granted = (
            {str(k): str(v) for k, v in raw_perms.items() if isinstance(v, str)}
            if isinstance(raw_perms, Mapping)
            else {}
        )
        missing_req = tuple(
            perm
            for perm, level in REQUIRED_GITHUB_READ_PERMISSIONS.items()
            if not _permission_satisfies(granted.get(perm), level)
        )
        missing_opt = tuple(
            f"{perm}:{level}"
            for perm, level in OPTIONAL_GITHUB_REPAIR_PERMISSIONS.items()
            if not _permission_satisfies(granted.get(perm), level)
        )
        excess = tuple(sorted(k for k in granted if k in EXCESS_DISCOURAGED_PERMISSIONS))

        account_obj = inst_json.get("account")
        account_login = (
            str(account_obj.get("login"))
            if isinstance(account_obj, Mapping) and isinstance(account_obj.get("login"), str)
            else None
        )
        can_read_repos = len(missing_req) == 0
        can_draft_pr = _permission_satisfies(
            granted.get("pull_requests"), "write"
        ) and _permission_satisfies(granted.get("contents"), "write")
        can_checks = _permission_satisfies(granted.get("checks"), "read")

        capabilities: dict[str, CapabilityAvailability] = {
            "app_jwt_auth": "available",
            "repo_discovery": "available" if can_read_repos else "unavailable",
            "actions_logs": (
                "available"
                if _permission_satisfies(granted.get("actions"), "read")
                else "unavailable"
            ),
            "workflow_hazard_scan": (
                "available"
                if _permission_satisfies(granted.get("contents"), "read")
                else "unavailable"
            ),
            "draft_pr": "available" if can_draft_pr else "unavailable",
            "remote_checks": "available" if can_checks else "unavailable",
            "webhook_hmac": ("available" if ctx.webhook_secret_ref is not None else "unavailable"),
        }

        detail = "GitHub App installation permissions verified."
        if missing_req:
            detail = f"Missing required read permissions: {', '.join(missing_req)}."
        elif missing_opt:
            detail = (
                "Read/monitor permissions verified; draft PR publication permissions missing: "
                f"{', '.join(missing_opt)}."
            )

        return ProviderPermissionSummary(
            account_login=account_login,
            vendor_version=vendor_ver[:120],
            api_version=GITHUB_API_VERSION,
            granted_permissions=granted,
            missing_required_permissions=missing_req,
            missing_optional_permissions=missing_opt,
            excess_unused_permissions=excess,
            capabilities=capabilities,
            suspended=False,
            detail=detail,
        )

    async def _scan_repo_workflows(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        owner: str,
        repo_short_name: str,
        default_branch: str,
        now: datetime,
    ) -> tuple[WorkflowHazardStatus, tuple[WorkflowHazardFinding, ...], bool]:
        token = await self._get_jit_installation_token(
            session,
            ctx,
            permissions={"metadata": "read", "contents": "read"},
            repositories=[repo_short_name],
            now=now,
        )
        dir_url = self._build_url(
            ctx.base_url,
            f"/repos/{quote(owner, safe='')}/{quote(repo_short_name, safe='')}"
            f"/contents/.github/workflows?ref={quote(default_branch, safe='')}",
        )
        resp = await self._send_request(
            "GET",
            dir_url,
            headers=self._default_headers(bearer_token=token),
        )
        if resp.status_code == 404:
            return ("clean", (), False)
        self._raise_for_github_status(resp)

        entries = resp.json()
        if not isinstance(entries, list):
            return ("clean", (), False)

        findings: list[WorkflowHazardFinding] = []
        yaml_entries = [
            item
            for item in entries
            if isinstance(item, Mapping)
            and isinstance(item.get("path"), str)
            and str(item["path"]).lower().endswith((".yml", ".yaml"))
        ][:MAX_WORKFLOW_FILES_PER_REPO]

        for entry in yaml_entries:
            wf_path = str(entry["path"])
            file_url = self._build_url(
                ctx.base_url,
                f"/repos/{quote(owner, safe='')}/{quote(repo_short_name, safe='')}"
                f"/contents/{quote(wf_path, safe='/')}?ref={quote(default_branch, safe='')}",
            )
            file_resp = await self._send_request(
                "GET",
                file_url,
                headers=self._default_headers(bearer_token=token),
            )
            if file_resp.status_code == 404:
                continue
            self._raise_for_github_status(file_resp)
            file_obj = file_resp.json()
            if not isinstance(file_obj, Mapping):
                continue
            raw_b64 = file_obj.get("content")
            encoding = str(file_obj.get("encoding", "")).lower()
            if isinstance(raw_b64, str) and encoding == "base64":
                try:
                    decoded_bytes = base64.b64decode(raw_b64, validate=False)
                except ValueError:
                    findings.append(
                        WorkflowHazardFinding(
                            code="workflow_parse_warning",
                            severity="low",
                            workflow_path=wf_path,
                            detail="Workflow base64 blob could not be decoded cleanly.",
                        )
                    )
                    continue
                findings.extend(
                    WorkflowHazardScanner.scan_workflow_yaml(
                        workflow_path=wf_path,
                        raw_yaml=decoded_bytes,
                    )
                )

        if not findings:
            return ("clean", (), False)
        blocked = WorkflowHazardScanner.should_block_auto_repair(findings)
        return ("flagged", tuple(findings), blocked)

    async def list_repos(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        per_page: int = 50,
        scan_workflows: bool = True,
        now: datetime | None = None,
    ) -> PaginatedRepoDiscoveryResult:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        bounded_per_page = max(1, min(per_page, 100))
        token = await self._get_jit_installation_token(
            session,
            ctx,
            permissions={"metadata": "read", "contents": "read"},
            now=ref_now,
        )

        discovered: list[DiscoveredRepositoryRecord] = []
        total_reported = 0
        page = 1
        partial_sync = False
        warning_detail: str | None = None

        while page <= 100:
            url = self._build_url(
                ctx.base_url,
                f"/installation/repositories?per_page={bounded_per_page}&page={page}",
            )
            try:
                resp = await self._send_request(
                    "GET",
                    url,
                    headers=self._default_headers(bearer_token=token),
                )
                self._raise_for_github_status(resp)
            except ProviderError as exc:
                if page > 1 and exc.code in {"TRANSIENT", "RATE_LIMIT"}:
                    partial_sync = True
                    warning_detail = (
                        f"Paginated repository discovery stopped on page {page} ({exc.code}); "
                        "previously discovered repositories were preserved."
                    )
                    break
                raise

            payload = resp.json()
            if not isinstance(payload, Mapping):
                raise ProviderError(
                    code="TRANSIENT",
                    detail="Malformed /installation/repositories payload.",
                    provider="github",
                )
            total_reported = int(payload.get("total_count") or 0)
            raw_repos = payload.get("repositories")
            if not isinstance(raw_repos, list) or not raw_repos:
                break

            for item in raw_repos:
                if not isinstance(item, Mapping):
                    continue
                ext_id = str(item.get("id", "")).strip()
                short_name = str(item.get("name", "")).strip()
                full_name = str(item.get("full_name", "")).strip()
                if not ext_id or not short_name or not full_name:
                    continue
                default_branch = str(item.get("default_branch") or "main").strip()[:120]
                raw_vis = str(item.get("visibility") or "").strip().lower()
                if raw_vis in {"public", "private", "internal"}:
                    visibility = cast(RepositoryVisibility, raw_vis)
                elif item.get("private") is True:
                    visibility = "private"
                elif item.get("private") is False:
                    visibility = "public"
                else:
                    visibility = "unknown"

                archived = bool(item.get("archived", False))
                disabled = bool(item.get("disabled", False))
                is_fork = bool(item.get("fork", False))

                hazard_status: WorkflowHazardStatus = "unscanned"
                hazards: tuple[WorkflowHazardFinding, ...] = ()
                auto_blocked = False
                if scan_workflows and not disabled:
                    owner_part, _ = _split_repo_full_name(full_name)
                    try:
                        hazard_status, hazards, auto_blocked = await self._scan_repo_workflows(
                            session,
                            ctx,
                            owner=owner_part,
                            repo_short_name=short_name,
                            default_branch=default_branch,
                            now=ref_now,
                        )
                    except ProviderError as wf_exc:
                        if wf_exc.code in {"TRANSIENT", "RATE_LIMIT", "FORBIDDEN"}:
                            hazard_status = "unscanned"
                            partial_sync = True
                            warning_detail = (
                                f"Workflow hazard inspection incomplete for {full_name} "
                                f"({wf_exc.code})."
                            )
                        else:
                            raise

                discovered.append(
                    DiscoveredRepositoryRecord(
                        external_repo_id=ext_id,
                        short_name=short_name[:120],
                        full_name=full_name[:120],
                        default_branch=default_branch,
                        visibility=visibility,
                        archived=archived,
                        disabled=disabled,
                        is_fork=is_fork,
                        workflow_hazard_status=hazard_status,
                        workflow_hazards=hazards,
                        auto_repair_blocked=auto_blocked,
                    )
                )

            link_header = resp.headers.get("link", "")
            has_next_link = 'rel="next"' in link_header
            if not has_next_link and (
                len(raw_repos) < bounded_per_page
                or (total_reported > 0 and len(discovered) >= total_reported)
            ):
                break
            page += 1

        return PaginatedRepoDiscoveryResult(
            repositories=tuple(discovered),
            total_reported=max(total_reported, len(discovered)),
            partial_sync=partial_sync,
            warning_detail=warning_detail,
        )

    async def get_run(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        external_run_id: str,
        now: datetime | None = None,
    ) -> ProviderRunRecord:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        owner, repo = _split_repo_full_name(repo_full_name)
        token = await self._get_jit_installation_token(
            session,
            ctx,
            permissions={"metadata": "read", "actions": "read"},
            repositories=[repo],
            now=ref_now,
        )
        resp = await self._send_request(
            "GET",
            self._build_url(
                ctx.base_url,
                f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
                f"/actions/runs/{quote(external_run_id, safe='')}",
            ),
            headers=self._default_headers(bearer_token=token),
        )
        self._raise_for_github_status(resp)
        data = resp.json()
        if not isinstance(data, Mapping):
            raise ProviderError(
                code="TRANSIENT",
                detail="Malformed workflow run payload.",
                provider="github",
            )
        run_attempt = str(data.get("run_attempt") or "1")
        raw_status = str(data.get("status") or "unknown")
        head_repo = data.get("head_repository")
        base_repo = data.get("repository")
        head_repo_id = (
            str(head_repo["id"])
            if isinstance(head_repo, Mapping) and head_repo.get("id") is not None
            else None
        )
        base_repo_id = (
            str(base_repo["id"])
            if isinstance(base_repo, Mapping) and base_repo.get("id") is not None
            else None
        )
        head_fork = bool(head_repo.get("fork", False)) if isinstance(head_repo, Mapping) else False
        return ProviderRunRecord(
            external_run_id=str(data.get("id") or external_run_id),
            attempt_key=f"{data.get('id') or external_run_id}:{run_attempt}",
            head_sha=str(data.get("head_sha") or ""),
            ref=str(data.get("head_branch") or "HEAD"),
            event_type=str(data.get("event") or "unknown"),
            status=raw_status
            if raw_status in {"queued", "in_progress", "completed"}
            else "unknown",
            conclusion=str(data["conclusion"]) if data.get("conclusion") is not None else None,
            jobs_complete=raw_status == "completed",
            raw_vendor_status=raw_status,
            head_repo_id=head_repo_id,
            base_repo_id=base_repo_id,
            head_repo_fork=head_fork,
        )

    async def list_jobs(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        external_run_id: str,
        attempt_number: int | None = None,
        now: datetime | None = None,
    ) -> Sequence[ProviderJobRecord]:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        owner, repo = _split_repo_full_name(repo_full_name)
        token = await self._get_jit_installation_token(
            session,
            ctx,
            permissions={"metadata": "read", "actions": "read"},
            repositories=[repo],
            now=ref_now,
        )
        suffix = f"/attempts/{attempt_number}/jobs" if attempt_number is not None else "/jobs"
        resp = await self._send_request(
            "GET",
            self._build_url(
                ctx.base_url,
                f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
                f"/actions/runs/{quote(external_run_id, safe='')}{suffix}",
            ),
            headers=self._default_headers(bearer_token=token),
        )
        self._raise_for_github_status(resp)
        payload = resp.json()
        raw_jobs = payload.get("jobs", []) if isinstance(payload, Mapping) else []
        results: list[ProviderJobRecord] = []
        if isinstance(raw_jobs, list):
            for item in raw_jobs:
                if not isinstance(item, Mapping):
                    continue
                results.append(
                    ProviderJobRecord(
                        external_job_id=str(item.get("id", "")),
                        name=str(item.get("name") or "job")[:120],
                        status=str(item.get("status") or "unknown"),
                        conclusion=(
                            str(item["conclusion"]) if item.get("conclusion") is not None else None
                        ),
                        started_at=_parse_iso_dt(item.get("started_at")),
                        completed_at=_parse_iso_dt(item.get("completed_at")),
                    )
                )
        return tuple(results)

    async def get_job_log(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        external_job_id: str,
        max_bytes: int = 2_097_152,
        now: datetime | None = None,
    ) -> bytes:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        owner, repo = _split_repo_full_name(repo_full_name)
        token = await self._get_jit_installation_token(
            session,
            ctx,
            permissions={"metadata": "read", "actions": "read"},
            repositories=[repo],
            now=ref_now,
        )
        resp = await self._send_request(
            "GET",
            self._build_url(
                ctx.base_url,
                f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
                f"/actions/jobs/{quote(external_job_id, safe='')}/logs",
            ),
            headers=self._default_headers(bearer_token=token),
        )
        self._raise_for_github_status(resp)
        return bytes(resp.content[: max(1, max_bytes)])

    async def get_artifact_metadata(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        external_run_id: str,
        now: datetime | None = None,
    ) -> Sequence[ProviderArtifactRecord]:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        owner, repo = _split_repo_full_name(repo_full_name)
        token = await self._get_jit_installation_token(
            session,
            ctx,
            permissions={"metadata": "read", "actions": "read"},
            repositories=[repo],
            now=ref_now,
        )
        resp = await self._send_request(
            "GET",
            self._build_url(
                ctx.base_url,
                f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
                f"/actions/runs/{quote(external_run_id, safe='')}/artifacts",
            ),
            headers=self._default_headers(bearer_token=token),
        )
        self._raise_for_github_status(resp)
        payload = resp.json()
        raw_items = payload.get("artifacts", []) if isinstance(payload, Mapping) else []
        out: list[ProviderArtifactRecord] = []
        if isinstance(raw_items, list):
            for item in raw_items:
                if not isinstance(item, Mapping):
                    continue
                out.append(
                    ProviderArtifactRecord(
                        external_artifact_id=str(item.get("id", "")),
                        name=str(item.get("name") or "artifact")[:120],
                        size_bytes=max(0, int(item.get("size_in_bytes") or 0)),
                        expired=bool(item.get("expired", False)),
                        created_at=_parse_iso_dt(item.get("created_at")),
                        expires_at=_parse_iso_dt(item.get("expires_at")),
                    )
                )
        return tuple(out)

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
    ) -> str:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        owner, repo = _split_repo_full_name(repo_full_name)
        token = await self._get_jit_installation_token(
            session,
            ctx,
            permissions={"metadata": "read", "contents": "read"},
            repositories=[repo],
            now=ref_now,
        )
        resp = await self._send_request(
            "GET",
            self._build_url(
                ctx.base_url,
                f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
                f"/compare/{quote(base_sha, safe='')}...{quote(head_sha, safe='')}",
            ),
            headers=self._default_headers(
                bearer_token=token,
                accept="application/vnd.github.diff",
            ),
        )
        self._raise_for_github_status(resp)
        return resp.content[: max(1, max_bytes)].decode("utf-8", errors="replace")

    async def resolve_workflow_config(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        ref: str,
        now: datetime | None = None,
    ) -> Mapping[str, str]:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        owner, repo = _split_repo_full_name(repo_full_name)
        token = await self._get_jit_installation_token(
            session,
            ctx,
            permissions={"metadata": "read", "contents": "read"},
            repositories=[repo],
            now=ref_now,
        )
        dir_resp = await self._send_request(
            "GET",
            self._build_url(
                ctx.base_url,
                f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
                f"/contents/.github/workflows?ref={quote(ref, safe='')}",
            ),
            headers=self._default_headers(bearer_token=token),
        )
        if dir_resp.status_code == 404:
            return {}
        self._raise_for_github_status(dir_resp)
        entries = dir_resp.json()
        if not isinstance(entries, list):
            return {}
        configs: dict[str, str] = {}
        for item in entries[:MAX_WORKFLOW_FILES_PER_REPO]:
            if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
                continue
            wf_path = str(item["path"])
            if not wf_path.lower().endswith((".yml", ".yaml")):
                continue
            file_resp = await self._send_request(
                "GET",
                self._build_url(
                    ctx.base_url,
                    f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
                    f"/contents/{quote(wf_path, safe='/')}?ref={quote(ref, safe='')}",
                ),
                headers=self._default_headers(bearer_token=token),
            )
            if file_resp.status_code == 404:
                continue
            self._raise_for_github_status(file_resp)
            file_obj = file_resp.json()
            if isinstance(file_obj, Mapping) and isinstance(file_obj.get("content"), str):
                decoded = base64.b64decode(file_obj["content"], validate=False).decode(
                    "utf-8", errors="replace"
                )
                configs[wf_path] = decoded
        return configs

    async def create_branch(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        branch_name: str,
        from_sha: str,
        now: datetime | None = None,
    ) -> str:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        owner, repo = _split_repo_full_name(repo_full_name)
        token = await self._get_jit_installation_token(
            session,
            ctx,
            permissions={"metadata": "read", "contents": "write"},
            repositories=[repo],
            now=ref_now,
        )
        clean_branch = branch_name.removeprefix("refs/heads/")
        resp = await self._send_request(
            "POST",
            self._build_url(
                ctx.base_url,
                f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/git/refs",
            ),
            headers=self._default_headers(bearer_token=token),
            json_body={"ref": f"refs/heads/{clean_branch}", "sha": from_sha},
        )
        self._raise_for_github_status(resp, treat_409_422_as_stale_sha=True)
        return f"refs/heads/{clean_branch}"

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
    ) -> str:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        owner, repo = _split_repo_full_name(repo_full_name)
        token = await self._get_jit_installation_token(
            session,
            ctx,
            permissions={"metadata": "read", "contents": "write"},
            repositories=[repo],
            now=ref_now,
        )
        tree_entries = [
            {"path": path, "mode": "100644", "type": "blob", "content": content}
            for path, content in file_changes.items()
        ]
        tree_resp = await self._send_request(
            "POST",
            self._build_url(
                ctx.base_url,
                f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/git/trees",
            ),
            headers=self._default_headers(bearer_token=token),
            json_body={"base_tree": expected_parent_sha, "tree": tree_entries},
        )
        self._raise_for_github_status(tree_resp, treat_409_422_as_stale_sha=True)
        tree_sha = str(tree_resp.json().get("sha", ""))

        commit_resp = await self._send_request(
            "POST",
            self._build_url(
                ctx.base_url,
                f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/git/commits",
            ),
            headers=self._default_headers(bearer_token=token),
            json_body={
                "message": commit_message,
                "tree": tree_sha,
                "parents": [expected_parent_sha],
            },
        )
        self._raise_for_github_status(commit_resp, treat_409_422_as_stale_sha=True)
        new_sha = str(commit_resp.json().get("sha", ""))

        clean_branch = branch_name.removeprefix("refs/heads/")
        ref_resp = await self._send_request(
            "PATCH",
            self._build_url(
                ctx.base_url,
                f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
                f"/git/refs/heads/{quote(clean_branch, safe='/')}",
            ),
            headers=self._default_headers(bearer_token=token),
            json_body={"sha": new_sha, "force": False},
        )
        self._raise_for_github_status(ref_resp, treat_409_422_as_stale_sha=True)
        return new_sha

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
    ) -> ProviderDraftReviewRecord:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        owner, repo = _split_repo_full_name(repo_full_name)
        token = await self._get_jit_installation_token(
            session,
            ctx,
            permissions={"metadata": "read", "pull_requests": "write", "contents": "write"},
            repositories=[repo],
            now=ref_now,
        )
        resp = await self._send_request(
            "POST",
            self._build_url(
                ctx.base_url,
                f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/pulls",
            ),
            headers=self._default_headers(bearer_token=token),
            json_body={
                "title": title,
                "head": head_branch.removeprefix("refs/heads/"),
                "base": base_branch.removeprefix("refs/heads/"),
                "body": body,
                "draft": True,
            },
        )
        self._raise_for_github_status(resp, treat_409_422_as_stale_sha=True)
        pr_json = resp.json()
        head_obj = pr_json.get("head", {}) if isinstance(pr_json, Mapping) else {}
        return ProviderDraftReviewRecord(
            external_review_id=str(pr_json.get("id", "")),
            number=str(pr_json.get("number", "")),
            html_url=str(pr_json.get("html_url", "")),
            head_branch=head_branch,
            base_branch=base_branch,
            head_sha=str(head_obj.get("sha", "")) if isinstance(head_obj, Mapping) else "",
            draft=bool(pr_json.get("draft", True)),
            state=str(pr_json.get("state", "open")),
        )

    async def find_review_by_marker(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        head_branch: str,
        marker: str,
        now: datetime | None = None,
    ) -> ProviderDraftReviewRecord | None:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        owner, repo = _split_repo_full_name(repo_full_name)
        token = await self._get_jit_installation_token(
            session,
            ctx,
            permissions={"metadata": "read", "pull_requests": "read"},
            repositories=[repo],
            now=ref_now,
        )
        clean_head = head_branch.removeprefix("refs/heads/")
        resp = await self._send_request(
            "GET",
            self._build_url(
                ctx.base_url,
                f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
                f"/pulls?state=all&head={quote(f'{owner}:{clean_head}', safe=':')}",
            ),
            headers=self._default_headers(bearer_token=token),
        )
        self._raise_for_github_status(resp)
        items = resp.json()
        if not isinstance(items, list):
            return None
        for item in items:
            if not isinstance(item, Mapping):
                continue
            body_text = str(item.get("body") or "")
            if marker and marker not in body_text:
                continue
            head_obj = item.get("head", {})
            base_obj = item.get("base", {})
            return ProviderDraftReviewRecord(
                external_review_id=str(item.get("id", "")),
                number=str(item.get("number", "")),
                html_url=str(item.get("html_url", "")),
                head_branch=(
                    str(head_obj.get("ref", clean_head))
                    if isinstance(head_obj, Mapping)
                    else clean_head
                ),
                base_branch=(
                    str(base_obj.get("ref", "main")) if isinstance(base_obj, Mapping) else "main"
                ),
                head_sha=str(head_obj.get("sha", "")) if isinstance(head_obj, Mapping) else "",
                draft=bool(item.get("draft", False)),
                state=str(item.get("state", "open")),
            )
        return None

    async def get_remote_checks(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        head_sha: str,
        now: datetime | None = None,
    ) -> Sequence[ProviderRemoteCheckRecord]:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        owner, repo = _split_repo_full_name(repo_full_name)
        token = await self._get_jit_installation_token(
            session,
            ctx,
            permissions={"metadata": "read", "checks": "read"},
            repositories=[repo],
            now=ref_now,
        )
        resp = await self._send_request(
            "GET",
            self._build_url(
                ctx.base_url,
                f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
                f"/commits/{quote(head_sha, safe='')}/check-runs",
            ),
            headers=self._default_headers(bearer_token=token),
        )
        self._raise_for_github_status(resp)
        payload = resp.json()
        raw_checks = payload.get("check_runs", []) if isinstance(payload, Mapping) else []
        out: list[ProviderRemoteCheckRecord] = []
        if isinstance(raw_checks, list):
            for item in raw_checks:
                if not isinstance(item, Mapping):
                    continue
                out.append(
                    ProviderRemoteCheckRecord(
                        external_check_id=str(item.get("id", "")),
                        name=str(item.get("name") or "check")[:120],
                        head_sha=str(item.get("head_sha") or head_sha),
                        status=str(item.get("status") or "unknown"),
                        conclusion=(
                            str(item["conclusion"]) if item.get("conclusion") is not None else None
                        ),
                    )
                )
        return tuple(out)

    async def verify_webhook(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        headers: Mapping[str, str],
        raw_body: bytes,
    ) -> bool:
        if not ctx.webhook_secret_ref:
            return False
        sig_header: str | None = None
        for k, v in headers.items():
            if k.lower() == "x-hub-signature-256":
                sig_header = v
                break
        if not sig_header or not sig_header.startswith("sha256="):
            return False
        return await self._vault.verify_webhook_hmac(
            session,
            workspace_id=ctx.workspace_id,
            secret_ref=ctx.webhook_secret_ref,
            raw_body=raw_body,
            signature_header=sig_header,
        )

    async def sync_cursor(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        since_cursor: str | None = None,
        now: datetime | None = None,
    ) -> tuple[Sequence[ProviderRunRecord], str | None]:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        owner, repo = _split_repo_full_name(repo_full_name)
        token = await self._get_jit_installation_token(
            session,
            ctx,
            permissions={"metadata": "read", "actions": "read"},
            repositories=[repo],
            now=ref_now,
        )
        query = f"?created=%3E%3D{quote(since_cursor, safe='')}" if since_cursor else ""
        resp = await self._send_request(
            "GET",
            self._build_url(
                ctx.base_url,
                f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/actions/runs{query}",
            ),
            headers=self._default_headers(bearer_token=token),
        )
        self._raise_for_github_status(resp)
        payload = resp.json()
        raw_runs = payload.get("workflow_runs", []) if isinstance(payload, Mapping) else []
        runs: list[ProviderRunRecord] = []
        newest_ts = since_cursor
        if isinstance(raw_runs, list):
            for item in raw_runs:
                if not isinstance(item, Mapping):
                    continue
                created_str = str(item.get("created_at") or "")
                if created_str and (newest_ts is None or created_str > newest_ts):
                    newest_ts = created_str
                run_attempt = str(item.get("run_attempt") or "1")
                raw_status = str(item.get("status") or "unknown")
                runs.append(
                    ProviderRunRecord(
                        external_run_id=str(item.get("id", "")),
                        attempt_key=f"{item.get('id', '')}:{run_attempt}",
                        head_sha=str(item.get("head_sha") or ""),
                        ref=str(item.get("head_branch") or "HEAD"),
                        event_type=str(item.get("event") or "unknown"),
                        status=(
                            raw_status
                            if raw_status in {"queued", "in_progress", "completed"}
                            else "unknown"
                        ),
                        conclusion=(
                            str(item["conclusion"]) if item.get("conclusion") is not None else None
                        ),
                        jobs_complete=raw_status == "completed",
                        raw_vendor_status=raw_status,
                    )
                )
        return (tuple(runs), newest_ts)

    async def revoke_connection(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        now: datetime | None = None,
    ) -> None:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        self._vault.invalidate_cached_tokens(
            workspace_id=ctx.workspace_id,
            connection_id=ctx.connection_id,
        )
        if ctx.credential_secret_ref:
            await self._vault.revoke_provider_credential(
                session,
                workspace_id=ctx.workspace_id,
                secret_ref=ctx.credential_secret_ref,
                connection_id=ctx.connection_id,
                now=ref_now,
            )
        if ctx.webhook_secret_ref:
            await self._vault.revoke_provider_credential(
                session,
                workspace_id=ctx.workspace_id,
                secret_ref=ctx.webhook_secret_ref,
                connection_id=ctx.connection_id,
                now=ref_now,
            )


def _to_connection_context(row: ProviderConnectionModel) -> ProviderConnectionContext:
    return ProviderConnectionContext(
        workspace_id=row.workspace_id,
        connection_id=row.id,
        provider=cast(ProviderKind, row.provider),
        base_url=row.base_url,
        app_id=row.app_id,
        client_id=row.client_id,
        installation_id=row.external_installation_id,
        credential_secret_ref=row.credential_secret_ref,
        webhook_secret_ref=row.webhook_secret_ref,
        auth_mode=cast(ConnectionAuthMode, row.auth_mode),
        vendor_version=row.vendor_version,
    )


def _to_repository_dto(row: RepositoryModel) -> Repository:
    hazards = [
        WorkflowHazardFinding.model_validate(item) for item in (row.workflow_hazards_json or [])
    ]
    return Repository(
        id=row.id,
        workspace_id=row.workspace_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        external_id=row.external_repo_id,
        connection_id=row.provider_connection_id,
        name=row.name,
        default_branch=row.default_branch,
        visibility=cast(RepositoryVisibility, row.visibility),
        mode=cast(RepositoryMode, row.mode),
        paused=row.paused,
        policy_revision=row.policy_revision,
        tags=list(row.tags_json or []),
        archived=row.archived,
        is_fork=row.is_fork,
        workflow_hazard_status=cast(WorkflowHazardStatus, row.workflow_hazard_status),
        workflow_hazards=hazards,
        auto_repair_blocked=row.auto_repair_blocked,
    )


def _to_snapshot_dto(row: CapabilitySnapshotModel) -> CapabilitySnapshot:
    return CapabilitySnapshot(
        id=row.id,
        workspace_id=row.workspace_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        connection_id=row.connection_id,
        provider=cast(ProviderKind, row.provider),
        status=cast(ConnectionStatus, row.status),
        capabilities={
            k: cast(CapabilityAvailability, v) for k, v in (row.capabilities_json or {}).items()
        },
        granted_permissions=dict(row.granted_permissions_json or {}),
        missing_permissions=list(row.missing_permissions_json or []),
        vendor_version=row.vendor_version,
        api_version=row.api_version,
        checked_at=row.checked_at,
        detail=row.detail,
    )


async def _build_connection_dto(
    db: AsyncSession,
    row: ProviderConnectionModel,
) -> Connection:
    repo_count = int(
        (
            await db.scalar(
                select(func.count())
                .select_from(RepositoryModel)
                .where(
                    RepositoryModel.workspace_id == row.workspace_id,
                    RepositoryModel.provider_connection_id == row.id,
                    RepositoryModel.active.is_(True),
                )
            )
        )
        or 0
    )
    hazard_count = int(
        (
            await db.scalar(
                select(func.count())
                .select_from(RepositoryModel)
                .where(
                    RepositoryModel.workspace_id == row.workspace_id,
                    RepositoryModel.provider_connection_id == row.id,
                    RepositoryModel.active.is_(True),
                    RepositoryModel.workflow_hazard_status == "flagged",
                )
            )
        )
        or 0
    )
    return Connection(
        id=row.id,
        workspace_id=row.workspace_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        provider=cast(ProviderKind, row.provider),
        base_url=row.base_url,
        auth_mode=cast(ConnectionAuthMode, row.auth_mode),
        secret_presence=SecretPresence(
            configured=row.credential_secret_ref is not None and row.status != "revoked",
            secret_version=row.credential_secret_version,
        ),
        webhook_secret_presence=SecretPresence(
            configured=row.webhook_secret_ref is not None and row.status != "revoked",
            secret_version=row.webhook_secret_version,
        ),
        status=cast(ConnectionStatus, row.status),
        capabilities={
            k: cast(CapabilityAvailability, v) for k, v in (row.capabilities_json or {}).items()
        },
        checked_at=row.checked_at,
        vendor_version=row.vendor_version,
        api_version=row.api_version,
        display_name=row.display_name,
        app_id=row.app_id,
        client_id=row.client_id,
        installation_id=row.external_installation_id,
        account_login=row.account_login,
        granted_permissions=dict(row.granted_permissions_json or {}),
        missing_permissions=list(row.missing_permissions_json or []),
        repository_count=repo_count,
        flagged_hazard_repo_count=hazard_count,
        grant_review_required=row.grant_review_required,
        status_detail=row.status_detail,
        last_synced_at=row.last_synced_at,
    )


def _validate_uuid_or_404(raw_id: str, *, code: str, detail: str) -> str:
    try:
        return _UUID_ADAPTER.validate_python(raw_id.strip())
    except ValidationError as exc:
        raise NotFoundError(code=code, detail=detail) from exc


def _assert_not_permanently_forbidden_base_url(
    base_url: str,
    *,
    adapter: ProviderKind,
) -> None:
    parsed = urlparse(base_url.strip())
    if parsed.scheme.lower() not in {"https", "http"} or not parsed.hostname:
        raise UnprocessableEntityError(
            code="invalid_base_url",
            detail=f"base_url must be a valid http(s) {adapter} API endpoint.",
        )
    host_cand = parsed.hostname.strip().lower().rstrip(".")
    if host_cand == "localhost" or host_cand.endswith(".localhost"):
        raise EgressBlockedError(
            code="egress_forbidden_ip",
            detail="Loopback base_url targets are permanently forbidden (ADR-037).",
            adapter=adapter,
            target_url=base_url,
        )
    try:
        ip_obj = ipaddress.ip_address(host_cand)
    except ValueError:
        return
    if (
        ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
        or (isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None)
    ):
        raise EgressBlockedError(
            code="egress_forbidden_ip",
            detail=(
                "Loopback, link-local, and cloud metadata base_url targets are "
                "permanently forbidden (ADR-037)."
            ),
            adapter=adapter,
            target_url=base_url,
        )


class GitHubIntegrationService:
    """Workspace-scoped `A-06` & `A-23` provider integration lifecycle service (`U09`..`U10`)."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        signing_key: bytes,
        vault: ProviderCredentialVaultProtocol,
        github_adapter: GitHubAppAdapter,
        gitlab_adapter: GitLabAdapter | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._signing_key = signing_key
        self._vault = vault
        self._github = github_adapter
        self._redactor = redactor or DEFAULT_REDACTOR
        self._gitlab = gitlab_adapter or GitLabAdapter(
            vault=vault,
            egress_policy=github_adapter._egress_policy,
            ca_bundle_resolver=github_adapter._ca_resolver,
            redactor=self._redactor,
        )

    async def _suspend_connection_work_and_mark_revoked(
        self,
        db: AsyncSession,
        *,
        conn_row: ProviderConnectionModel,
        actor_type: Literal["user", "system"],
        actor_id: str,
        reason_code: str,
        detail: str,
        correlation_id: str,
        client_ip: str | None,
        revoke_stored_secrets: bool,
        now: datetime,
    ) -> int:
        """Transition connection to `revoked`, purge JIT tokens & suspend `task_jobs` (SEC-011)."""
        ws_id = conn_row.workspace_id
        self._vault.invalidate_cached_tokens(workspace_id=ws_id, connection_id=conn_row.id)

        if revoke_stored_secrets:
            if conn_row.credential_secret_ref:
                await self._vault.revoke_provider_credential(
                    db,
                    workspace_id=ws_id,
                    secret_ref=conn_row.credential_secret_ref,
                    connection_id=conn_row.id,
                    now=now,
                )
            if conn_row.webhook_secret_ref:
                await self._vault.revoke_provider_credential(
                    db,
                    workspace_id=ws_id,
                    secret_ref=conn_row.webhook_secret_ref,
                    connection_id=conn_row.id,
                    now=now,
                )

        repo_ids = list(
            (
                await db.scalars(
                    select(RepositoryModel.id).where(
                        RepositoryModel.workspace_id == ws_id,
                        RepositoryModel.provider_connection_id == conn_row.id,
                    )
                )
            ).all()
        )
        if repo_ids:
            # Force all repositories back to safe monitor/paused/inactive state (`W-02`)
            await db.execute(
                update(RepositoryModel)
                .where(
                    RepositoryModel.workspace_id == ws_id,
                    RepositoryModel.provider_connection_id == conn_row.id,
                )
                .values(
                    active=False,
                    paused=True,
                    mode="monitor",
                    version=RepositoryModel.version + 1,
                    updated_at=now,
                )
            )
            # Cancel queued jobs immediately and request cooperative cancellation on running jobs
            await db.execute(
                update(TaskJobModel)
                .where(
                    TaskJobModel.workspace_id == ws_id,
                    TaskJobModel.repository_id.in_(repo_ids),
                    TaskJobModel.state == "queued",
                )
                .values(
                    state="cancelled",
                    cancel_reason="provider_connection_revoked",
                    version=TaskJobModel.version + 1,
                    updated_at=now,
                )
            )
            await db.execute(
                update(TaskJobModel)
                .where(
                    TaskJobModel.workspace_id == ws_id,
                    TaskJobModel.repository_id.in_(repo_ids),
                    TaskJobModel.state.in_(("leased", "running")),
                )
                .values(
                    state="cancel_requested",
                    cancel_reason="provider_connection_revoked",
                    version=TaskJobModel.version + 1,
                    updated_at=now,
                )
            )

        was_already_revoked = conn_row.status == "revoked"
        conn_row.status = "revoked"
        conn_row.had_prior_revocation = True
        conn_row.grant_review_required = True
        conn_row.status_detail = self._redactor.redact_text(detail)[:950]
        conn_row.capabilities_json = {
            k: "unavailable"
            for k in (conn_row.capabilities_json or {"repo_discovery": "unavailable"})
        }
        conn_row.checked_at = now
        conn_row.version += 1
        conn_row.updated_at = now
        await db.flush()

        if not was_already_revoked:
            await enqueue_outbox_event(
                db,
                EventEnvelope(
                    event_id=new_uuid7(now=now),
                    type="integration.disconnected",
                    occurred_at=now,
                    workspace_id=ws_id,
                    aggregate_id=conn_row.id,
                    aggregate_version=conn_row.version,
                    correlation_id=correlation_id,
                    payload=ProviderConnectionEventPayload(
                        connection_id=conn_row.id,
                        status="revoked",
                    ),
                ),
                now=now,
            )

        await append_audit_entry(
            db,
            workspace_id=ws_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action="integration.connection_revoked",
            target=f"provider_connection:{conn_row.id}",
            decision="allow",
            reason_code=reason_code,
            correlation_id=correlation_id,
            client_ip=client_ip,
            metadata={
                "provider": conn_row.provider,
                "affected_repositories": len(repo_ids),
            },
            occurred_at=now,
        )
        return len(repo_ids)

    async def list_connections(
        self,
        ctx: WorkspaceAccessContext,
        *,
        provider: ProviderKind | None = None,
        cursor: str | None = None,
        limit: int = 25,
        now: datetime,
    ) -> ConnectionPage:
        ws_id = ctx.workspace_id
        bounded_limit = max(1, min(limit, 100))
        q_hash = compute_query_filter_hash({"provider": provider or "all"})
        decoded = (
            decode_signed_cursor(
                cursor,
                signing_key=self._signing_key,
                expected_workspace_scope=ws_id,
                expected_principal_id=ctx.auth.user.id,
                current_grant_epoch=ctx.auth.user.grant_epoch,
                expected_query_hash=q_hash,
                now=now,
            )
            if cursor is not None
            else None
        )

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            stmt = select(ProviderConnectionModel).where(
                ProviderConnectionModel.workspace_id == ws_id
            )
            if provider is not None:
                stmt = stmt.where(ProviderConnectionModel.provider == provider)
            if decoded is not None:
                stmt = stmt.where(
                    or_(
                        ProviderConnectionModel.created_at < decoded.created_at,
                        and_(
                            ProviderConnectionModel.created_at == decoded.created_at,
                            ProviderConnectionModel.id < decoded.item_id,
                        ),
                    )
                )
            stmt = stmt.order_by(
                ProviderConnectionModel.created_at.desc(),
                ProviderConnectionModel.id.desc(),
            ).limit(bounded_limit + 1)

            rows = list((await db.scalars(stmt)).all())
            has_more = len(rows) > bounded_limit
            page_rows = rows[:bounded_limit]
            items = [await _build_connection_dto(db, r) for r in page_rows]

            next_cursor: str | None = None
            if has_more and page_rows:
                tail = page_rows[-1]
                next_cursor = encode_signed_cursor(
                    signing_key=self._signing_key,
                    workspace_scope=ws_id,
                    principal_id=ctx.auth.user.id,
                    grant_epoch=ctx.auth.user.grant_epoch,
                    query_hash=q_hash,
                    created_at=tail.created_at,
                    item_id=tail.id,
                    now=now,
                )

            return ConnectionPage(
                items=items,
                next_cursor=next_cursor,
                snapshot_at=now.astimezone(UTC),
            )

    async def get_connection_detail(
        self,
        ctx: WorkspaceAccessContext,
        *,
        connection_id: str,
    ) -> ConnectionDetailResponse:
        ws_id = ctx.workspace_id
        clean_id = _validate_uuid_or_404(
            connection_id,
            code="connection_not_found",
            detail="Provider connection not found.",
        )
        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            row = await db.scalar(
                select(ProviderConnectionModel).where(
                    ProviderConnectionModel.workspace_id == ws_id,
                    ProviderConnectionModel.id == clean_id,
                )
            )
            if row is None:
                raise NotFoundError(
                    code="connection_not_found",
                    detail="Provider connection not found.",
                )
            conn_dto = await _build_connection_dto(db, row)
            snap_row = await db.scalar(
                select(CapabilitySnapshotModel)
                .where(
                    CapabilitySnapshotModel.workspace_id == ws_id,
                    CapabilitySnapshotModel.connection_id == row.id,
                )
                .order_by(
                    CapabilitySnapshotModel.checked_at.desc(),
                    CapabilitySnapshotModel.id.desc(),
                )
                .limit(1)
            )
            repo_rows = list(
                (
                    await db.scalars(
                        select(RepositoryModel)
                        .where(
                            RepositoryModel.workspace_id == ws_id,
                            RepositoryModel.provider_connection_id == row.id,
                            RepositoryModel.active.is_(True),
                        )
                        .order_by(RepositoryModel.name.asc())
                    )
                ).all()
            )
            # Enforce deny-by-default repository grant visibility (SEC-010)
            visible_repos = [
                _to_repository_dto(r) for r in repo_rows if ctx.can_read_repository(r.id)
            ]
            return ConnectionDetailResponse(
                connection=conn_dto,
                latest_snapshot=_to_snapshot_dto(snap_row) if snap_row is not None else None,
                repositories=visible_repos,
            )

    async def create_connection(
        self,
        ctx: WorkspaceAccessContext,
        payload: ConnectionWrite,
        *,
        idempotency_key: str,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> Connection:
        ws_id = ctx.workspace_id
        ref_now = now.astimezone(UTC)

        is_gitlab = payload.provider == "gitlab"
        if is_gitlab:
            if payload.auth_mode not in {"gitlab_signed_v19", "gitlab_legacy_token"}:
                raise UnprocessableEntityError(
                    code="invalid_gitlab_auth_mode",
                    detail=(
                        "GitLab connections require pinned auth_mode='gitlab_signed_v19' or "
                        "'gitlab_legacy_token'."
                    ),
                )
            if payload.private_key_pem is not None:
                raise UnprocessableEntityError(
                    code="invalid_gitlab_credential_type",
                    detail="GitLab connections accept access_token or secret_ref, not RSA PEMs.",
                )
            if payload.access_token is None and payload.secret_ref is None:
                raise UnprocessableEntityError(
                    code="gitlab_access_token_required",
                    detail="Provide a write-only GitLab project/group access_token or secret_ref.",
                )
            if payload.auth_mode == "gitlab_signed_v19" and payload.webhook_secret is not None:
                try:
                    decode_gitlab_signing_key(payload.webhook_secret)
                except CryptoVerificationError as exc:
                    raise UnprocessableEntityError(code=exc.code, detail=exc.detail) from exc
        else:
            if payload.auth_mode != "github_app":
                raise UnprocessableEntityError(
                    code="invalid_github_auth_mode",
                    detail="GitHub connections require auth_mode='github_app'.",
                )
            if payload.access_token is not None:
                raise UnprocessableEntityError(
                    code="invalid_github_credential_type",
                    detail="GitHub App connections accept private_key_pem or secret_ref.",
                )
            if not payload.app_id:
                raise UnprocessableEntityError(
                    code="github_app_id_required",
                    detail="app_id is required when creating a GitHub App connection.",
                )

        _assert_not_permanently_forbidden_base_url(payload.base_url, adapter=payload.provider)

        raw_secret_material = payload.private_key_pem or payload.access_token
        # Redact secret inputs before hashing idempotency request fingerprint
        fingerprint_payload = {
            "provider": payload.provider,
            "base_url": payload.base_url,
            "auth_mode": payload.auth_mode,
            "display_name": payload.display_name,
            "app_id": payload.app_id,
            "client_id": payload.client_id,
            "secret_fingerprint": (
                hashlib.sha256(raw_secret_material.encode("utf-8")).hexdigest()
                if raw_secret_material
                else payload.secret_ref
            ),
            "webhook_fingerprint": (
                hashlib.sha256(payload.webhook_secret.encode("utf-8")).hexdigest()
                if payload.webhook_secret
                else payload.webhook_secret_ref
            ),
        }

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            provisional_id = new_uuid7(now=ref_now)
            identity_segment = (
                payload.app_id
                if not is_gitlab
                else f"{payload.auth_mode}:{payload.display_name or 'default'}"
            )
            effect_key = (
                f"integration.create:{ws_id}:{payload.provider}:"
                f"{identity_segment}:{payload.base_url}"
            )
            claim = await claim_idempotent_operation(
                db,
                workspace_id=ws_id,
                principal_id=ctx.auth.user.id,
                operation="integrations.create",
                idempotency_key=idempotency_key,
                request_payload=fingerprint_payload,
                logical_effect_key=effect_key,
                resource_id=provisional_id,
                correlation_id=correlation_id,
                now=ref_now,
            )
            if not claim.is_new_claim and claim.cached_response is not None:
                return Connection.model_validate(claim.cached_response)

            cred_ref: str | None = None
            cred_ver: int | None = None
            if payload.private_key_pem is not None:
                cred_ref, cred_ver = await self._vault.store_provider_credential(
                    db,
                    workspace_id=ws_id,
                    plaintext=payload.private_key_pem.encode("utf-8"),
                    purpose="provider_read",
                    require_rsa_pem=True,
                    now=ref_now,
                )
            elif payload.access_token is not None:
                cred_ref, cred_ver = await self._vault.store_provider_credential(
                    db,
                    workspace_id=ws_id,
                    plaintext=payload.access_token.encode("utf-8"),
                    purpose="provider_read",
                    require_rsa_pem=False,
                    now=ref_now,
                )
            elif payload.secret_ref is not None:
                _, cred_ver = await self._vault.inspect_secret_presence(
                    db,
                    workspace_id=ws_id,
                    secret_ref=payload.secret_ref,
                    expected_purpose="provider_read",
                )
                cred_ref = payload.secret_ref

            wh_ref: str | None = None
            wh_ver: int | None = None
            if payload.webhook_secret is not None:
                wh_ref, wh_ver = await self._vault.store_provider_credential(
                    db,
                    workspace_id=ws_id,
                    plaintext=payload.webhook_secret.encode("utf-8"),
                    purpose="webhook_auth",
                    require_rsa_pem=False,
                    now=ref_now,
                )
            elif payload.webhook_secret_ref is not None:
                _, wh_ver = await self._vault.inspect_secret_presence(
                    db,
                    workspace_id=ws_id,
                    secret_ref=payload.webhook_secret_ref,
                    expected_purpose="webhook_auth",
                )
                wh_ref = payload.webhook_secret_ref

            default_label = (
                f"GitLab ({urlparse(payload.base_url).hostname or 'v4'})"
                if is_gitlab
                else f"GitHub App ({payload.app_id})"
            )
            display_name = (
                payload.display_name.strip() if payload.display_name else default_label
            )[:120]

            initial_caps = (
                {
                    "repo_discovery": "unknown" if cred_ref else "unavailable",
                    "ci_read": "unknown" if cred_ref else "unavailable",
                    "draft_review_create": "unknown" if cred_ref else "unavailable",
                    "webhook_hmac": (
                        "available"
                        if (payload.auth_mode == "gitlab_signed_v19" and wh_ref)
                        else "unavailable"
                    ),
                    "polling_fallback": "unknown" if cred_ref else "unavailable",
                    "idempotency_key_v17_4": "unknown",
                }
                if is_gitlab
                else {
                    "app_jwt_auth": "unknown" if cred_ref else "unavailable",
                    "repo_discovery": "unavailable",
                    "webhook_hmac": "available" if wh_ref else "unavailable",
                }
            )
            initial_detail = (
                "GitLab credentials sealed in Z2 vault with pinned webhook auth_mode; "
                "run Probe capabilities and Sync projects to verify scopes."
                if is_gitlab
                else "GitHub App credentials stored; mint an installation state and confirm "
                "installation to discover repositories."
            )

            conn_row = ProviderConnectionModel(
                id=provisional_id,
                workspace_id=ws_id,
                provider=payload.provider,
                display_name=display_name,
                base_url=payload.base_url.strip().rstrip("/"),
                auth_mode=payload.auth_mode,
                app_id=payload.app_id,
                client_id=payload.client_id,
                external_installation_id=None,
                account_login=None,
                credential_secret_ref=cred_ref,
                credential_secret_version=cred_ver,
                webhook_secret_ref=wh_ref,
                webhook_secret_version=wh_ver,
                status="not_configured",
                capabilities_json=initial_caps,
                granted_permissions_json=(
                    {"webhook_auth_mode": payload.auth_mode} if is_gitlab else {}
                ),
                missing_permissions_json=[],
                vendor_version=None,
                api_version=GITLAB_API_VERSION if is_gitlab else GITHUB_API_VERSION,
                status_detail=initial_detail,
                grant_review_required=False,
                had_prior_revocation=False,
                checked_at=None,
                last_synced_at=None,
                created_by_user_id=ctx.auth.user.id,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(conn_row)
            await db.flush()

            await enqueue_outbox_event(
                db,
                EventEnvelope(
                    event_id=new_uuid7(now=ref_now),
                    type="provider.connection.created",
                    occurred_at=ref_now,
                    workspace_id=ws_id,
                    aggregate_id=conn_row.id,
                    aggregate_version=conn_row.version,
                    correlation_id=correlation_id,
                    payload=ProviderConnectionEventPayload(
                        connection_id=conn_row.id,
                        status=conn_row.status,
                    ),
                ),
                now=ref_now,
            )
            await append_audit_entry(
                db,
                workspace_id=ws_id,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                action="integration.connection_created",
                target=f"provider_connection:{conn_row.id}",
                decision="allow",
                reason_code="created",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={
                    "provider": payload.provider,
                    "auth_mode": payload.auth_mode,
                    "app_id": payload.app_id,
                    "credential_configured": cred_ref is not None,
                    "webhook_secret_configured": wh_ref is not None,
                },
                occurred_at=ref_now,
            )

            dto = await _build_connection_dto(db, conn_row)
            await complete_idempotent_operation(
                db,
                workspace_id=ws_id,
                operation_id=claim.receipt.operation_id,
                state="succeeded",
                status_code=201,
                result_id=conn_row.id,
                response_payload=dto.model_dump(mode="json"),
                now=ref_now,
            )
            return dto

    async def update_connection(
        self,
        ctx: WorkspaceAccessContext,
        *,
        connection_id: str,
        payload: ConnectionPatchRequest,
        if_match_header: str | None,
        idempotency_key: str,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> Connection:
        ws_id = ctx.workspace_id
        ref_now = now.astimezone(UTC)
        clean_id = _validate_uuid_or_404(
            connection_id,
            code="connection_not_found",
            detail="Provider connection not found.",
        )

        patch_secret_material = payload.private_key_pem or payload.access_token
        fingerprint_payload = {
            "connection_id": clean_id,
            "expected_version": payload.expected_version,
            "display_name": payload.display_name,
            "base_url": payload.base_url,
            "auth_mode": payload.auth_mode,
            "app_id": payload.app_id,
            "client_id": payload.client_id,
            "secret_fingerprint": (
                hashlib.sha256(patch_secret_material.encode("utf-8")).hexdigest()
                if patch_secret_material
                else payload.secret_ref
            ),
            "webhook_fingerprint": (
                hashlib.sha256(payload.webhook_secret.encode("utf-8")).hexdigest()
                if payload.webhook_secret
                else payload.webhook_secret_ref
            ),
        }

        immutable_auth_err: UnprocessableEntityError | None = None

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            row = await db.scalar(
                select(ProviderConnectionModel)
                .where(
                    ProviderConnectionModel.workspace_id == ws_id,
                    ProviderConnectionModel.id == clean_id,
                )
                .with_for_update()
            )
            if row is None:
                raise NotFoundError(
                    code="connection_not_found",
                    detail="Provider connection not found.",
                )

            if payload.auth_mode is not None and payload.auth_mode != row.auth_mode:
                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    actor_type="user",
                    actor_id=ctx.auth.user.id,
                    action="integration.connection_auth_mode_change",
                    target=f"provider_connection:{row.id}",
                    decision="deny",
                    reason_code="auth_mode_downgrade_forbidden",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={
                        "provider": row.provider,
                        "current_auth_mode": row.auth_mode,
                        "attempted_auth_mode": payload.auth_mode,
                    },
                    occurred_at=ref_now,
                )
                immutable_auth_err = UnprocessableEntityError(
                    code="auth_mode_immutable",
                    detail=(
                        "Connection auth_mode is pinned at creation and cannot be downgraded "
                        "or modified (`SEC-027`)."
                    ),
                )

            if immutable_auth_err is None:
                if row.provider == "gitlab" and payload.private_key_pem is not None:
                    raise UnprocessableEntityError(
                        code="invalid_gitlab_credential_type",
                        detail="GitLab connections rotate access_token, not RSA private_key_pem.",
                    )
                if row.provider == "github" and payload.access_token is not None:
                    raise UnprocessableEntityError(
                        code="invalid_github_credential_type",
                        detail="GitHub App connections rotate private_key_pem, not access_token.",
                    )
                if payload.base_url is not None:
                    _assert_not_permanently_forbidden_base_url(
                        payload.base_url,
                        adapter=cast(ProviderKind, row.provider),
                    )
                if (
                    row.auth_mode in {"gitlab_signed_v19", "signed_webhook"}
                    and payload.webhook_secret is not None
                ):
                    try:
                        decode_gitlab_signing_key(payload.webhook_secret)
                    except CryptoVerificationError as exc:
                        raise UnprocessableEntityError(code=exc.code, detail=exc.detail) from exc

                claim = await claim_idempotent_operation(
                    db,
                    workspace_id=ws_id,
                    principal_id=ctx.auth.user.id,
                    operation="integrations.update",
                    idempotency_key=idempotency_key,
                    request_payload=fingerprint_payload,
                    logical_effect_key=f"integration.update:{ws_id}:{clean_id}:{idempotency_key}",
                    resource_id=clean_id,
                    correlation_id=correlation_id,
                    now=ref_now,
                )
                if not claim.is_new_claim and claim.cached_response is not None:
                    return Connection.model_validate(claim.cached_response)

                enforce_optimistic_version(
                    current_version=row.version,
                    if_match_header=if_match_header,
                    expected_version=payload.expected_version,
                )

                rotated_credentials = False
                if payload.display_name is not None:
                    row.display_name = payload.display_name.strip()[:120]
                if payload.base_url is not None:
                    row.base_url = payload.base_url.strip().rstrip("/")
                if payload.app_id is not None:
                    row.app_id = payload.app_id
                    rotated_credentials = True
                if payload.client_id is not None:
                    row.client_id = payload.client_id

                if payload.private_key_pem is not None:
                    old_ref = row.credential_secret_ref
                    new_ref, _ = await self._vault.store_provider_credential(
                        db,
                        workspace_id=ws_id,
                        plaintext=payload.private_key_pem.encode("utf-8"),
                        purpose="provider_read",
                        require_rsa_pem=True,
                        now=ref_now,
                    )
                    if old_ref:
                        await self._vault.revoke_provider_credential(
                            db,
                            workspace_id=ws_id,
                            secret_ref=old_ref,
                            connection_id=row.id,
                            now=ref_now,
                        )
                    row.credential_secret_ref = new_ref
                    row.credential_secret_version = (row.credential_secret_version or 0) + 1
                    rotated_credentials = True
                elif payload.access_token is not None:
                    if row.credential_secret_ref:
                        new_ref, new_ver = await self._vault.rotate_provider_credential(
                            db,
                            workspace_id=ws_id,
                            secret_ref=row.credential_secret_ref,
                            new_plaintext=payload.access_token.encode("utf-8"),
                            purpose="provider_read",
                            retain_previous_for_overlap=False,
                            now=ref_now,
                        )
                    else:
                        new_ref, new_ver = await self._vault.store_provider_credential(
                            db,
                            workspace_id=ws_id,
                            plaintext=payload.access_token.encode("utf-8"),
                            purpose="provider_read",
                            require_rsa_pem=False,
                            now=ref_now,
                        )
                    row.credential_secret_ref = new_ref
                    row.credential_secret_version = max(
                        (row.credential_secret_version or 0) + 1,
                        new_ver,
                    )
                    rotated_credentials = True
                elif payload.secret_ref is not None:
                    _, ver = await self._vault.inspect_secret_presence(
                        db,
                        workspace_id=ws_id,
                        secret_ref=payload.secret_ref,
                        expected_purpose="provider_read",
                    )
                    row.credential_secret_ref = payload.secret_ref
                    row.credential_secret_version = (row.credential_secret_version or 0) + (
                        ver or 1
                    )
                    rotated_credentials = True

                if payload.webhook_secret is not None:
                    if row.webhook_secret_ref:
                        new_wh, new_wh_ver = await self._vault.rotate_provider_credential(
                            db,
                            workspace_id=ws_id,
                            secret_ref=row.webhook_secret_ref,
                            new_plaintext=payload.webhook_secret.encode("utf-8"),
                            purpose="webhook_auth",
                            retain_previous_for_overlap=True,
                            now=ref_now,
                        )
                    else:
                        new_wh, new_wh_ver = await self._vault.store_provider_credential(
                            db,
                            workspace_id=ws_id,
                            plaintext=payload.webhook_secret.encode("utf-8"),
                            purpose="webhook_auth",
                            require_rsa_pem=False,
                            now=ref_now,
                        )
                    row.webhook_secret_ref = new_wh
                    row.webhook_secret_version = max(
                        (row.webhook_secret_version or 0) + 1,
                        new_wh_ver,
                    )
                    rotated_credentials = True
                elif payload.webhook_secret_ref is not None:
                    _, wh_ver = await self._vault.inspect_secret_presence(
                        db,
                        workspace_id=ws_id,
                        secret_ref=payload.webhook_secret_ref,
                        expected_purpose="webhook_auth",
                    )
                    row.webhook_secret_ref = payload.webhook_secret_ref
                    row.webhook_secret_version = (row.webhook_secret_version or 0) + (wh_ver or 1)
                    rotated_credentials = True

                if rotated_credentials:
                    self._vault.invalidate_cached_tokens(workspace_id=ws_id, connection_id=row.id)
                    if row.status == "revoked" and row.credential_secret_ref is not None:
                        # Rotating credentials on a previously revoked connection keeps
                        # grant_review_required=True and resets status until re-verified (`W-02`)
                        row.status = "not_configured"
                        if row.provider == "github":
                            row.external_installation_id = None
                            row.status_detail = (
                                "Credentials rotated after revocation; confirm installation and "
                                "explicitly review repository grants before resuming."
                            )
                        else:
                            row.status_detail = (
                                "GitLab token rotated after revocation; probe capabilities and "
                                "sync projects in Monitor mode before reviewing grants."
                            )
                        row.grant_review_required = True

                row.version += 1
                row.updated_at = ref_now
                await db.flush()

                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    actor_type="user",
                    actor_id=ctx.auth.user.id,
                    action="integration.connection_updated",
                    target=f"provider_connection:{row.id}",
                    decision="allow",
                    reason_code="rotated_credentials" if rotated_credentials else "updated",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={
                        "provider": row.provider,
                        "rotated_credentials": rotated_credentials,
                        "new_version": row.version,
                    },
                    occurred_at=ref_now,
                )

                dto = await _build_connection_dto(db, row)
                await complete_idempotent_operation(
                    db,
                    workspace_id=ws_id,
                    operation_id=claim.receipt.operation_id,
                    state="succeeded",
                    status_code=200,
                    result_id=row.id,
                    response_payload=dto.model_dump(mode="json"),
                    now=ref_now,
                )
                return dto

        assert immutable_auth_err is not None
        raise immutable_auth_err

    async def delete_connection(
        self,
        ctx: WorkspaceAccessContext,
        *,
        connection_id: str,
        idempotency_key: str,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> ActionReceipt:
        ws_id = ctx.workspace_id
        ref_now = now.astimezone(UTC)
        clean_id = _validate_uuid_or_404(
            connection_id,
            code="connection_not_found",
            detail="Provider connection not found.",
        )

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            row = await db.scalar(
                select(ProviderConnectionModel)
                .where(
                    ProviderConnectionModel.workspace_id == ws_id,
                    ProviderConnectionModel.id == clean_id,
                )
                .with_for_update()
            )
            if row is None:
                raise NotFoundError(
                    code="connection_not_found",
                    detail="Provider connection not found.",
                )

            effect_key = f"integration.delete:{ws_id}:{clean_id}"
            claim = await claim_idempotent_operation(
                db,
                workspace_id=ws_id,
                principal_id=ctx.auth.user.id,
                operation="integrations.delete",
                idempotency_key=idempotency_key,
                request_payload={"connection_id": clean_id},
                logical_effect_key=effect_key,
                resource_id=clean_id,
                correlation_id=correlation_id,
                now=ref_now,
            )
            if not claim.is_new_claim:
                return claim.receipt

            await self._suspend_connection_work_and_mark_revoked(
                db,
                conn_row=row,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                reason_code="admin_disconnected",
                detail=(
                    "Connection disconnected and credentials revoked by workspace administrator."
                ),
                correlation_id=correlation_id,
                client_ip=client_ip,
                revoke_stored_secrets=True,
                now=ref_now,
            )
            receipt = await complete_idempotent_operation(
                db,
                workspace_id=ws_id,
                operation_id=claim.receipt.operation_id,
                state="succeeded",
                status_code=200,
                result_id=row.id,
                now=ref_now,
            )
            await upsert_operation_receipt(
                db,
                operation_id=receipt.operation_id,
                scope="workspace",
                workspace_id=ws_id,
                repository_id=None,
                principal_id=ctx.auth.user.id,
                required_role="admin",
                operation_kind="integrations.delete",
                resource_id=row.id,
                state=receipt.state,
                correlation_id=receipt.correlation_id,
                status_url=receipt.status_url,
                logical_effect_key=effect_key,
                result_id=row.id,
                now=ref_now,
            )
            return receipt

    async def mint_install_state(
        self,
        ctx: WorkspaceAccessContext,
        *,
        connection_id: str,
        payload: GitHubInstallStateCreateRequest,
        idempotency_key: str,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> GitHubInstallStateResponse:
        ws_id = ctx.workspace_id
        ref_now = now.astimezone(UTC)
        clean_id = _validate_uuid_or_404(
            connection_id,
            code="connection_not_found",
            detail="Provider connection not found.",
        )
        expected_origin = _normalize_origin(payload.expected_origin)

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            conn_row = await db.scalar(
                select(ProviderConnectionModel).where(
                    ProviderConnectionModel.workspace_id == ws_id,
                    ProviderConnectionModel.id == clean_id,
                )
            )
            if conn_row is None:
                raise NotFoundError(
                    code="connection_not_found",
                    detail="Provider connection not found.",
                )
            if conn_row.provider != "github":
                raise UnprocessableEntityError(
                    code="github_only_operation",
                    detail="GitHub App installation state nonces apply only to GitHub connections.",
                )

            claim = await claim_idempotent_operation(
                db,
                workspace_id=ws_id,
                principal_id=ctx.auth.user.id,
                operation="integrations.mint_install_state",
                idempotency_key=idempotency_key,
                request_payload={
                    "connection_id": clean_id,
                    "expected_origin": expected_origin,
                },
                logical_effect_key=f"integration.install_state:{ws_id}:{clean_id}:{idempotency_key}",
                resource_id=clean_id,
                correlation_id=correlation_id,
                now=ref_now,
            )
            if not claim.is_new_claim and claim.cached_response is not None:
                return GitHubInstallStateResponse.model_validate(claim.cached_response)

            raw_state = f"st_{secrets.token_urlsafe(32)}"
            expires_at = ref_now + INSTALL_STATE_TTL
            state_row = ProviderInstallStateModel(
                id=new_uuid7(now=ref_now),
                workspace_id=ws_id,
                connection_id=conn_row.id,
                provider="github",
                initiated_by_user_id=ctx.auth.user.id,
                state_hash=_hash_install_state(raw_state),
                expected_origin=expected_origin,
                expires_at=expires_at,
                consumed_at=None,
                created_at=ref_now,
            )
            db.add(state_row)
            await db.flush()

            await append_audit_entry(
                db,
                workspace_id=ws_id,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                action="integration.github_state_minted",
                target=f"provider_connection:{conn_row.id}",
                decision="allow",
                reason_code="minted_10m_single_use_state",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={"state_id": state_row.id, "expires_at": expires_at.isoformat()},
                occurred_at=ref_now,
            )

            resp_dto = GitHubInstallStateResponse(
                connection_id=conn_row.id,
                workspace_id=ws_id,
                state=raw_state,
                expires_at=expires_at,
                install_url=f"https://github.com/settings/apps?state={quote(raw_state, safe='')}",
            )
            await complete_idempotent_operation(
                db,
                workspace_id=ws_id,
                operation_id=claim.receipt.operation_id,
                state="succeeded",
                status_code=201,
                result_id=state_row.id,
                response_payload=resp_dto.model_dump(mode="json"),
                now=ref_now,
            )
            return resp_dto

    async def validate_github_callback(
        self,
        auth: AuthenticatedContext,
        *,
        state: str | None,
        installation_id: str | None,
        setup_action: str | None,
        request_origin: str | None,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> GitHubCallbackResponse:
        """Validate `A-23` GitHub callback parameters without mutating state (`GET` safe).

        Rejects any callback missing a valid single-use `state` bound to the authenticated
        initiating user (`installation_id` query parameter alone proves nothing).
        """
        ref_now = now.astimezone(UTC)
        if not state or len(state.strip()) < 16 or len(state.strip()) > 256:
            raise BadRequestError(
                code="missing_or_invalid_install_state",
                detail=(
                    "A valid single-use state nonce is required on GitHub callbacks; "
                    "installation_id alone is never trusted."
                ),
            )

        state_hash = _hash_install_state(state.strip())
        invalid_state_err: BadRequestError | None = None
        ws_slug = ""
        ws_id = ""
        conn_id = ""
        initiated_by = ""
        consumed_at: datetime | None = None
        expires_at: datetime = ref_now
        expected_origin: str | None = None

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            state_row = await db.scalar(
                select(ProviderInstallStateModel).where(
                    ProviderInstallStateModel.state_hash == state_hash
                )
            )
            if state_row is None:
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="integration.github_callback",
                    target="provider_install_state:unknown",
                    decision="deny",
                    reason_code="invalid_install_state",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                invalid_state_err = BadRequestError(
                    code="invalid_install_state",
                    detail="Unrecognized GitHub installation callback state.",
                )
            else:
                ws_row = await db.scalar(
                    select(WorkspaceModel).where(WorkspaceModel.id == state_row.workspace_id)
                )
                ws_slug = ws_row.slug if ws_row is not None else state_row.workspace_id
                ws_id = state_row.workspace_id
                conn_id = state_row.connection_id
                initiated_by = state_row.initiated_by_user_id
                consumed_at = state_row.consumed_at
                expires_at = state_row.expires_at
                expected_origin = state_row.expected_origin

        if invalid_state_err is not None:
            raise invalid_state_err

        if initiated_by != auth.user.id:
            async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as ws_db:
                await append_audit_entry(
                    ws_db,
                    workspace_id=ws_id,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="integration.github_callback",
                    target=f"provider_connection:{conn_id}",
                    decision="deny",
                    reason_code="install_state_principal_mismatch",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
            raise ForbiddenError(
                code="install_state_principal_mismatch",
                detail="GitHub installation state belongs to a different user session.",
            )

        if consumed_at is not None:
            raise ConflictError(
                code="install_state_replayed",
                detail="GitHub installation callback state has already been consumed.",
            )
        if expires_at <= ref_now:
            raise GoneError(
                code="install_state_expired",
                detail="GitHub installation callback state expired after 10 minutes.",
            )
        normalized_req_origin = _normalize_origin(request_origin)
        if (
            expected_origin is not None
            and normalized_req_origin is not None
            and normalized_req_origin != expected_origin
        ):
            raise ForbiddenError(
                code="install_state_origin_mismatch",
                detail="Callback request origin does not match expected origin.",
            )

        clean_install_id = installation_id.strip()[:128] if installation_id else None
        clean_action = setup_action.strip()[:120] if setup_action else None
        return GitHubCallbackResponse(
            state_valid=True,
            workspace_id=ws_id,
            workspace_slug=ws_slug,
            connection_id=conn_id,
            installation_id=clean_install_id or None,
            setup_action=clean_action or None,
            expires_at=expires_at,
        )

    async def _upsert_discovered_repositories(
        self,
        db: AsyncSession,
        *,
        conn_row: ProviderConnectionModel,
        discovery: PaginatedRepoDiscoveryResult,
        selected_external_ids: set[str] | None,
        force_monitor_reset: bool,
        now: datetime,
    ) -> list[RepositoryModel]:
        ws_id = conn_row.workspace_id
        existing_rows = list(
            (
                await db.scalars(
                    select(RepositoryModel)
                    .where(
                        RepositoryModel.workspace_id == ws_id,
                        RepositoryModel.provider_connection_id == conn_row.id,
                    )
                    .with_for_update()
                )
            ).all()
        )
        by_ext_id = {r.external_repo_id: r for r in existing_rows}
        seen_ext_ids: set[str] = set()
        active_models: list[RepositoryModel] = []

        for rec in discovery.repositories:
            if (
                selected_external_ids is not None
                and rec.external_repo_id not in selected_external_ids
            ):
                continue
            seen_ext_ids.add(rec.external_repo_id)
            hazards_json = [h.model_dump(mode="json") for h in rec.workflow_hazards]
            existing = by_ext_id.get(rec.external_repo_id)
            if existing is None:
                new_repo = RepositoryModel(
                    id=new_uuid7(now=now),
                    workspace_id=ws_id,
                    provider_connection_id=conn_row.id,
                    external_repo_id=rec.external_repo_id,
                    name=rec.full_name,
                    default_branch=rec.default_branch,
                    visibility=rec.visibility,
                    mode="monitor",
                    paused=False,
                    active=not rec.disabled,
                    archived=rec.archived,
                    is_fork=rec.is_fork,
                    policy_revision=1,
                    tags_json=[],
                    workflow_hazard_status=rec.workflow_hazard_status,
                    workflow_hazards_json=hazards_json,
                    auto_repair_blocked=rec.auto_repair_blocked,
                    last_synced_at=now,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
                db.add(new_repo)
                active_models.append(new_repo)
            else:
                existing.name = rec.full_name
                existing.default_branch = rec.default_branch
                existing.visibility = rec.visibility
                existing.active = not rec.disabled
                existing.archived = rec.archived
                existing.is_fork = rec.is_fork
                if rec.workflow_hazard_status != "unscanned":
                    existing.workflow_hazard_status = rec.workflow_hazard_status
                    existing.workflow_hazards_json = hazards_json
                    existing.auto_repair_blocked = rec.auto_repair_blocked
                # SEC-031 + W-02: hazard-flagged or reconnected repos never stay in auto_repair
                if force_monitor_reset:
                    existing.mode = "monitor"
                    existing.paused = False
                elif existing.auto_repair_blocked and existing.mode == "auto_repair":
                    existing.mode = "monitor"
                existing.last_synced_at = now
                existing.version += 1
                existing.updated_at = now
                active_models.append(existing)

        # Only deactivate missing repositories when pagination completed WITHOUT partial errors!
        if not discovery.partial_sync:
            for ext_id, old_row in by_ext_id.items():
                if ext_id not in seen_ext_ids and old_row.active:
                    old_row.active = False
                    old_row.paused = True
                    old_row.mode = "monitor"
                    old_row.version += 1
                    old_row.updated_at = now

        await db.flush()
        return sorted(active_models, key=lambda r: r.name)

    async def confirm_github_installation(
        self,
        ctx: WorkspaceAccessContext,
        *,
        connection_id: str,
        payload: GitHubInstallationConfirmRequest,
        idempotency_key: str,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> GitHubInstallationConfirmResponse:
        ws_id = ctx.workspace_id
        ref_now = now.astimezone(UTC)
        clean_id = _validate_uuid_or_404(
            connection_id,
            code="connection_not_found",
            detail="Provider connection not found.",
        )
        expected_origin = _normalize_origin(payload.expected_origin)
        state_hash = _hash_install_state(payload.state.strip())

        fingerprint_payload = {
            "connection_id": clean_id,
            "installation_id": payload.installation_id,
            "state_hash": state_hash,
            "selected_external_repo_ids": sorted(payload.selected_external_repo_ids or []),
        }

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            conn_row = await db.scalar(
                select(ProviderConnectionModel)
                .where(
                    ProviderConnectionModel.workspace_id == ws_id,
                    ProviderConnectionModel.id == clean_id,
                )
                .with_for_update()
            )
            if conn_row is None:
                raise NotFoundError(
                    code="connection_not_found",
                    detail="Provider connection not found.",
                )
            if conn_row.provider != "github":
                raise UnprocessableEntityError(
                    code="github_only_operation",
                    detail=(
                        "GitHub App installation confirmation applies only to GitHub connections."
                    ),
                )

            effect_key = f"integration.confirm_install:{ws_id}:{clean_id}:{state_hash}"
            claim = await claim_idempotent_operation(
                db,
                workspace_id=ws_id,
                principal_id=ctx.auth.user.id,
                operation="integrations.confirm_github_installation",
                idempotency_key=idempotency_key,
                request_payload=fingerprint_payload,
                logical_effect_key=effect_key,
                resource_id=clean_id,
                correlation_id=correlation_id,
                now=ref_now,
            )
            if not claim.is_new_claim and claim.cached_response is not None:
                return GitHubInstallationConfirmResponse.model_validate(claim.cached_response)

            state_row = await db.scalar(
                select(ProviderInstallStateModel)
                .where(ProviderInstallStateModel.state_hash == state_hash)
                .with_for_update()
            )
            if state_row is None or state_row.connection_id != conn_row.id:
                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    actor_type="user",
                    actor_id=ctx.auth.user.id,
                    action="integration.github_confirm_failed",
                    target=f"provider_connection:{conn_row.id}",
                    decision="deny",
                    reason_code="invalid_install_state",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                raise BadRequestError(
                    code="invalid_install_state",
                    detail="Single-use installation state nonce is invalid for this connection.",
                )
            if state_row.initiated_by_user_id != ctx.auth.user.id:
                raise ForbiddenError(
                    code="install_state_principal_mismatch",
                    detail="Installation state nonce belongs to a different user.",
                )
            if state_row.consumed_at is not None:
                raise ConflictError(
                    code="install_state_replayed",
                    detail="Installation state nonce was already consumed.",
                )
            if state_row.expires_at <= ref_now:
                raise GoneError(
                    code="install_state_expired",
                    detail="Installation state nonce expired after 10 minutes.",
                )
            if (
                state_row.expected_origin is not None
                and expected_origin is not None
                and expected_origin != state_row.expected_origin
            ):
                raise ForbiddenError(
                    code="install_state_origin_mismatch",
                    detail="Origin mismatch while confirming GitHub installation.",
                )

            # Atomically consume the single-use state nonce
            state_row.consumed_at = ref_now

            # Verify installation permissions & ownership on GitHub via RS256 App JWT
            prov_ctx = ProviderConnectionContext(
                workspace_id=ws_id,
                connection_id=conn_row.id,
                provider="github",
                base_url=conn_row.base_url,
                app_id=conn_row.app_id,
                client_id=conn_row.client_id,
                installation_id=payload.installation_id,
                credential_secret_ref=conn_row.credential_secret_ref,
                webhook_secret_ref=conn_row.webhook_secret_ref,
            )
            try:
                perm_summary = await self._github.get_permissions(
                    db,
                    prov_ctx,
                    installation_id_override=payload.installation_id,
                    now=ref_now,
                )
                if perm_summary.missing_required_permissions:
                    discovery = PaginatedRepoDiscoveryResult(
                        repositories=(),
                        total_reported=0,
                        partial_sync=False,
                        warning_detail=perm_summary.detail,
                    )
                else:
                    discovery = await self._github.list_repos(
                        db,
                        prov_ctx,
                        scan_workflows=True,
                        now=ref_now,
                    )
            except ProviderError as exc:
                self._raise_http_for_provider_error(exc)

            selected_set = (
                set(payload.selected_external_repo_ids)
                if payload.selected_external_repo_ids is not None
                else None
            )
            reconnecting_after_revoke = (
                conn_row.had_prior_revocation or conn_row.status == "revoked"
            )
            repo_models = await self._upsert_discovered_repositories(
                db,
                conn_row=conn_row,
                discovery=discovery,
                selected_external_ids=selected_set,
                force_monitor_reset=reconnecting_after_revoke,
                now=ref_now,
            )

            all_missing = list(perm_summary.missing_required_permissions) + list(
                perm_summary.missing_optional_permissions
            )
            if perm_summary.missing_required_permissions or discovery.partial_sync:
                next_status: ConnectionStatus = "degraded"
            else:
                next_status = "ready"

            detail_text = discovery.warning_detail or perm_summary.detail or "Ready."
            if reconnecting_after_revoke:
                detail_text = (
                    f"{detail_text} Reconnected after revocation; repository grants and "
                    "automation modes require explicit review."
                )[:950]

            conn_row.external_installation_id = payload.installation_id
            conn_row.account_login = perm_summary.account_login
            conn_row.status = next_status
            conn_row.capabilities_json = dict(perm_summary.capabilities)
            conn_row.granted_permissions_json = dict(perm_summary.granted_permissions)
            conn_row.missing_permissions_json = all_missing
            conn_row.vendor_version = perm_summary.vendor_version
            conn_row.api_version = perm_summary.api_version
            conn_row.status_detail = self._redactor.redact_text(detail_text)[:950]
            conn_row.grant_review_required = reconnecting_after_revoke
            conn_row.checked_at = ref_now
            conn_row.last_synced_at = (
                ref_now if not perm_summary.missing_required_permissions else None
            )
            conn_row.version += 1
            conn_row.updated_at = ref_now

            snap_row = CapabilitySnapshotModel(
                id=new_uuid7(now=ref_now),
                workspace_id=ws_id,
                connection_id=conn_row.id,
                provider="github",
                status=next_status,
                capabilities_json=dict(perm_summary.capabilities),
                granted_permissions_json=dict(perm_summary.granted_permissions),
                missing_permissions_json=all_missing,
                vendor_version=perm_summary.vendor_version,
                api_version=perm_summary.api_version,
                detail=conn_row.status_detail,
                checked_at=ref_now,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(snap_row)
            await db.flush()

            await enqueue_outbox_event(
                db,
                EventEnvelope(
                    event_id=new_uuid7(now=ref_now),
                    type="provider.connection.created",
                    occurred_at=ref_now,
                    workspace_id=ws_id,
                    aggregate_id=conn_row.id,
                    aggregate_version=conn_row.version,
                    correlation_id=correlation_id,
                    payload=ProviderConnectionEventPayload(
                        connection_id=conn_row.id,
                        status=conn_row.status,
                    ),
                ),
                now=ref_now,
            )
            await append_audit_entry(
                db,
                workspace_id=ws_id,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                action="integration.github_installation_confirmed",
                target=f"provider_connection:{conn_row.id}",
                decision="allow",
                reason_code=next_status,
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={
                    "installation_id": payload.installation_id,
                    "discovered_repositories": len(repo_models),
                    "partial_sync": discovery.partial_sync,
                    "grant_review_required": reconnecting_after_revoke,
                },
                occurred_at=ref_now,
            )

            receipt = await complete_idempotent_operation(
                db,
                workspace_id=ws_id,
                operation_id=claim.receipt.operation_id,
                state="succeeded",
                status_code=200,
                result_id=conn_row.id,
                now=ref_now,
            )
            await upsert_operation_receipt(
                db,
                operation_id=receipt.operation_id,
                scope="workspace",
                workspace_id=ws_id,
                repository_id=None,
                principal_id=ctx.auth.user.id,
                required_role="admin",
                operation_kind="integrations.confirm_github_installation",
                resource_id=conn_row.id,
                state=receipt.state,
                correlation_id=receipt.correlation_id,
                status_url=receipt.status_url,
                logical_effect_key=effect_key,
                result_id=conn_row.id,
                now=ref_now,
            )

            resp_dto = GitHubInstallationConfirmResponse(
                receipt=receipt,
                connection=await _build_connection_dto(db, conn_row),
                snapshot=_to_snapshot_dto(snap_row),
                repositories=[_to_repository_dto(r) for r in repo_models],
                partial_sync=discovery.partial_sync,
                grant_review_required=reconnecting_after_revoke,
            )
            await complete_idempotent_operation(
                db,
                workspace_id=ws_id,
                operation_id=claim.receipt.operation_id,
                state="succeeded",
                status_code=200,
                result_id=conn_row.id,
                response_payload=resp_dto.model_dump(mode="json"),
                now=ref_now,
            )
            return resp_dto

    async def probe_connection(
        self,
        ctx: WorkspaceAccessContext,
        *,
        connection_id: str,
        idempotency_key: str,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> ConnectionProbeResponse:
        ws_id = ctx.workspace_id
        ref_now = now.astimezone(UTC)
        clean_id = _validate_uuid_or_404(
            connection_id,
            code="connection_not_found",
            detail="Provider connection not found.",
        )

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            conn_row = await db.scalar(
                select(ProviderConnectionModel)
                .where(
                    ProviderConnectionModel.workspace_id == ws_id,
                    ProviderConnectionModel.id == clean_id,
                )
                .with_for_update()
            )
            if conn_row is None:
                raise NotFoundError(
                    code="connection_not_found",
                    detail="Provider connection not found.",
                )

            effect_key = f"integration.probe:{ws_id}:{clean_id}:{idempotency_key}"
            claim = await claim_idempotent_operation(
                db,
                workspace_id=ws_id,
                principal_id=ctx.auth.user.id,
                operation="integrations.probe",
                idempotency_key=idempotency_key,
                request_payload={"connection_id": clean_id},
                logical_effect_key=effect_key,
                resource_id=clean_id,
                correlation_id=correlation_id,
                now=ref_now,
            )
            if not claim.is_new_claim and claim.cached_response is not None:
                return ConnectionProbeResponse.model_validate(claim.cached_response)

            prov_ctx = _to_connection_context(conn_row)
            is_gitlab = conn_row.provider == "gitlab"
            default_api_ver = GITLAB_API_VERSION if is_gitlab else GITHUB_API_VERSION
            try:
                perm_summary = (
                    await self._gitlab.get_permissions(db, prov_ctx, now=ref_now)
                    if is_gitlab
                    else await self._github.get_permissions(db, prov_ctx, now=ref_now)
                )
                all_missing = list(perm_summary.missing_required_permissions) + list(
                    perm_summary.missing_optional_permissions
                )
                if perm_summary.unsupported_auth_mode:
                    next_status: ConnectionStatus = "unsupported"
                elif (
                    not is_gitlab and conn_row.external_installation_id is None
                ) or perm_summary.missing_required_permissions:
                    next_status = "degraded"
                else:
                    next_status = "ready"

                conn_row.account_login = perm_summary.account_login or conn_row.account_login
                conn_row.status = next_status
                conn_row.capabilities_json = dict(perm_summary.capabilities)
                conn_row.granted_permissions_json = dict(perm_summary.granted_permissions)
                conn_row.missing_permissions_json = all_missing
                conn_row.vendor_version = perm_summary.vendor_version
                conn_row.api_version = perm_summary.api_version
                conn_row.status_detail = self._redactor.redact_text(
                    perm_summary.detail or "Probe succeeded."
                )[:950]
                conn_row.checked_at = ref_now
                conn_row.version += 1
                conn_row.updated_at = ref_now

                snap_row = CapabilitySnapshotModel(
                    id=new_uuid7(now=ref_now),
                    workspace_id=ws_id,
                    connection_id=conn_row.id,
                    provider=conn_row.provider,
                    status=next_status,
                    capabilities_json=dict(perm_summary.capabilities),
                    granted_permissions_json=dict(perm_summary.granted_permissions),
                    missing_permissions_json=all_missing,
                    vendor_version=perm_summary.vendor_version,
                    api_version=perm_summary.api_version,
                    detail=conn_row.status_detail,
                    checked_at=ref_now,
                    version=1,
                    created_at=ref_now,
                    updated_at=ref_now,
                )
                db.add(snap_row)
                await db.flush()
            except ProviderError as exc:
                if exc.code == "REVOKED":
                    await self._suspend_connection_work_and_mark_revoked(
                        db,
                        conn_row=conn_row,
                        actor_type="system",
                        actor_id=ctx.auth.user.id,
                        reason_code="provider_token_or_installation_revoked",
                        detail=exc.detail,
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        revoke_stored_secrets=False,
                        now=ref_now,
                    )
                    snap_row = CapabilitySnapshotModel(
                        id=new_uuid7(now=ref_now),
                        workspace_id=ws_id,
                        connection_id=conn_row.id,
                        provider=conn_row.provider,
                        status="revoked",
                        capabilities_json=dict(conn_row.capabilities_json),
                        granted_permissions_json={},
                        missing_permissions_json=[],
                        vendor_version=conn_row.vendor_version,
                        api_version=conn_row.api_version or default_api_ver,
                        detail=conn_row.status_detail,
                        checked_at=ref_now,
                        version=1,
                        created_at=ref_now,
                        updated_at=ref_now,
                    )
                    db.add(snap_row)
                    await db.flush()
                else:
                    self._raise_http_for_provider_error(exc)

            await append_audit_entry(
                db,
                workspace_id=ws_id,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                action="integration.connection_probed",
                target=f"provider_connection:{conn_row.id}",
                decision="allow",
                reason_code=conn_row.status,
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={"status": conn_row.status},
                occurred_at=ref_now,
            )

            receipt = await complete_idempotent_operation(
                db,
                workspace_id=ws_id,
                operation_id=claim.receipt.operation_id,
                state="succeeded",
                status_code=200,
                result_id=snap_row.id,
                now=ref_now,
            )
            await upsert_operation_receipt(
                db,
                operation_id=receipt.operation_id,
                scope="workspace",
                workspace_id=ws_id,
                repository_id=None,
                principal_id=ctx.auth.user.id,
                required_role="admin",
                operation_kind="integrations.probe",
                resource_id=conn_row.id,
                state=receipt.state,
                correlation_id=receipt.correlation_id,
                status_url=receipt.status_url,
                logical_effect_key=effect_key,
                result_id=snap_row.id,
                now=ref_now,
            )
            resp_dto = ConnectionProbeResponse(
                receipt=receipt,
                connection=await _build_connection_dto(db, conn_row),
                snapshot=_to_snapshot_dto(snap_row),
            )
            await complete_idempotent_operation(
                db,
                workspace_id=ws_id,
                operation_id=claim.receipt.operation_id,
                state="succeeded",
                status_code=200,
                result_id=snap_row.id,
                response_payload=resp_dto.model_dump(mode="json"),
                now=ref_now,
            )
            return resp_dto

    async def sync_connection(
        self,
        ctx: WorkspaceAccessContext,
        *,
        connection_id: str,
        idempotency_key: str,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> ConnectionSyncResponse:
        ws_id = ctx.workspace_id
        ref_now = now.astimezone(UTC)
        clean_id = _validate_uuid_or_404(
            connection_id,
            code="connection_not_found",
            detail="Provider connection not found.",
        )

        revoked_err: ForbiddenError | None = None
        result_dto: ConnectionSyncResponse | None = None

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            conn_row = await db.scalar(
                select(ProviderConnectionModel)
                .where(
                    ProviderConnectionModel.workspace_id == ws_id,
                    ProviderConnectionModel.id == clean_id,
                )
                .with_for_update()
            )
            if conn_row is None:
                raise NotFoundError(
                    code="connection_not_found",
                    detail="Provider connection not found.",
                )
            is_gitlab = conn_row.provider == "gitlab"
            if conn_row.status == "revoked":
                raise ForbiddenError(
                    code="provider_connection_revoked",
                    detail=(
                        "Provider connection is revoked; rotate credentials, verify scopes, "
                        "and review grants before syncing."
                    ),
                )
            if not is_gitlab and not conn_row.external_installation_id:
                raise ConflictError(
                    code="installation_not_confirmed",
                    detail="Confirm a GitHub App installation before syncing repositories.",
                )
            if is_gitlab and not conn_row.credential_secret_ref:
                raise ConflictError(
                    code="credentials_not_configured",
                    detail="Configure a GitLab access token before syncing projects.",
                )

            effect_key = f"integration.sync:{ws_id}:{clean_id}:{idempotency_key}"
            claim = await claim_idempotent_operation(
                db,
                workspace_id=ws_id,
                principal_id=ctx.auth.user.id,
                operation="integrations.sync",
                idempotency_key=idempotency_key,
                request_payload={"connection_id": clean_id},
                logical_effect_key=effect_key,
                resource_id=clean_id,
                correlation_id=correlation_id,
                now=ref_now,
            )
            if not claim.is_new_claim and claim.cached_response is not None:
                return ConnectionSyncResponse.model_validate(claim.cached_response)

            prov_ctx = _to_connection_context(conn_row)
            try:
                perm_summary = (
                    await self._gitlab.get_permissions(db, prov_ctx, now=ref_now)
                    if is_gitlab
                    else await self._github.get_permissions(db, prov_ctx, now=ref_now)
                )
                if perm_summary.unsupported_auth_mode:
                    conn_row.status = "unsupported"
                    conn_row.vendor_version = perm_summary.vendor_version
                    conn_row.capabilities_json = dict(perm_summary.capabilities)
                    conn_row.status_detail = self._redactor.redact_text(
                        perm_summary.detail
                        or "Pinned GitLab webhook auth_mode is unsupported by server version."
                    )[:950]
                    conn_row.checked_at = ref_now
                    conn_row.version += 1
                    conn_row.updated_at = ref_now
                    await db.flush()
                    raise ProviderError(
                        code="UNSUPPORTED",
                        detail=perm_summary.detail
                        or "Pinned GitLab webhook auth_mode is unsupported by server version.",
                        provider="gitlab",
                        status_code=422,
                    )
                if perm_summary.missing_required_permissions:
                    raise ProviderError(
                        code="FORBIDDEN",
                        detail=perm_summary.detail
                        or "Missing required repository read permissions.",
                        provider=cast(ProviderKind, conn_row.provider),
                        status_code=403,
                    )
                discovery = (
                    await self._gitlab.list_repos(
                        db,
                        prov_ctx,
                        scan_workflows=True,
                        now=ref_now,
                    )
                    if is_gitlab
                    else await self._github.list_repos(
                        db,
                        prov_ctx,
                        scan_workflows=True,
                        now=ref_now,
                    )
                )
            except ProviderError as exc:
                if exc.code == "REVOKED":
                    # Commit durable revocation + active task_jobs suspension (`SEC-011`)
                    await self._suspend_connection_work_and_mark_revoked(
                        db,
                        conn_row=conn_row,
                        actor_type="system",
                        actor_id=ctx.auth.user.id,
                        reason_code="provider_token_or_installation_revoked",
                        detail=exc.detail,
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        revoke_stored_secrets=False,
                        now=ref_now,
                    )
                    await complete_idempotent_operation(
                        db,
                        workspace_id=ws_id,
                        operation_id=claim.receipt.operation_id,
                        state="failed",
                        status_code=403,
                        now=ref_now,
                    )
                    revoked_err = ForbiddenError(
                        code="provider_connection_revoked",
                        detail=(
                            "Provider credentials or installation were revoked upstream; "
                            "active work suspended."
                        ),
                    )
                else:
                    self._raise_http_for_provider_error(exc)

            if revoked_err is None:
                reconnecting_after_revoke = bool(
                    conn_row.had_prior_revocation or conn_row.grant_review_required
                )
                await self._upsert_discovered_repositories(
                    db,
                    conn_row=conn_row,
                    discovery=discovery,
                    selected_external_ids=None,
                    force_monitor_reset=reconnecting_after_revoke,
                    now=ref_now,
                )
                all_active_repos = list(
                    (
                        await db.scalars(
                            select(RepositoryModel)
                            .where(
                                RepositoryModel.workspace_id == ws_id,
                                RepositoryModel.provider_connection_id == conn_row.id,
                                RepositoryModel.active.is_(True),
                            )
                            .order_by(RepositoryModel.name.asc())
                        )
                    ).all()
                )
                conn_row.account_login = perm_summary.account_login or conn_row.account_login
                conn_row.vendor_version = perm_summary.vendor_version or conn_row.vendor_version
                conn_row.api_version = perm_summary.api_version or conn_row.api_version
                conn_row.status = "degraded" if discovery.partial_sync else "ready"
                conn_row.capabilities_json = dict(perm_summary.capabilities)
                conn_row.granted_permissions_json = dict(perm_summary.granted_permissions)
                conn_row.missing_permissions_json = list(
                    perm_summary.missing_required_permissions
                ) + list(perm_summary.missing_optional_permissions)
                sync_msg = (
                    discovery.warning_detail
                    or perm_summary.detail
                    or "Repository catalog synchronized."
                )
                if reconnecting_after_revoke:
                    conn_row.grant_review_required = True
                    sync_msg = (
                        f"{sync_msg} Reconnected after revocation; repositories remain in "
                        "Monitor mode until grants are reviewed."
                    )[:950]
                conn_row.status_detail = self._redactor.redact_text(sync_msg)[:950]
                conn_row.checked_at = ref_now
                conn_row.last_synced_at = ref_now
                conn_row.version += 1
                conn_row.updated_at = ref_now
                await db.flush()

                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    actor_type="user",
                    actor_id=ctx.auth.user.id,
                    action="integration.connection_synced",
                    target=f"provider_connection:{conn_row.id}",
                    decision="allow",
                    reason_code="partial_sync" if discovery.partial_sync else "synced",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={
                        "active_repositories": len(all_active_repos),
                        "partial_sync": discovery.partial_sync,
                    },
                    occurred_at=ref_now,
                )

                receipt = await complete_idempotent_operation(
                    db,
                    workspace_id=ws_id,
                    operation_id=claim.receipt.operation_id,
                    state="succeeded",
                    status_code=200,
                    result_id=conn_row.id,
                    now=ref_now,
                )
                await upsert_operation_receipt(
                    db,
                    operation_id=receipt.operation_id,
                    scope="workspace",
                    workspace_id=ws_id,
                    repository_id=None,
                    principal_id=ctx.auth.user.id,
                    required_role="admin",
                    operation_kind="integrations.sync",
                    resource_id=conn_row.id,
                    state=receipt.state,
                    correlation_id=receipt.correlation_id,
                    status_url=receipt.status_url,
                    logical_effect_key=effect_key,
                    result_id=conn_row.id,
                    now=ref_now,
                )

                repo_dtos = [_to_repository_dto(r) for r in all_active_repos]
                flagged_cnt = sum(1 for r in repo_dtos if r.workflow_hazard_status == "flagged")
                result_dto = ConnectionSyncResponse(
                    receipt=receipt,
                    connection=await _build_connection_dto(db, conn_row),
                    discovered_count=len(repo_dtos),
                    partial_sync=discovery.partial_sync,
                    flagged_hazard_count=flagged_cnt,
                    repositories=repo_dtos,
                )
                await complete_idempotent_operation(
                    db,
                    workspace_id=ws_id,
                    operation_id=claim.receipt.operation_id,
                    state="succeeded",
                    status_code=200,
                    result_id=conn_row.id,
                    response_payload=result_dto.model_dump(mode="json"),
                    now=ref_now,
                )

        if revoked_err is not None:
            raise revoked_err
        assert result_dto is not None
        return result_dto

    def _raise_http_for_provider_error(self, exc: ProviderError) -> None:
        from red2pr_control.core.errors import RateLimitedError

        if exc.code == "RATE_LIMIT":
            raise RateLimitedError(
                code="provider_rate_limited",
                detail=exc.detail,
                retry_after_seconds=exc.retry_after_seconds or 60,
            ) from exc
        if exc.code in {"FORBIDDEN", "REVOKED"}:
            raise ForbiddenError(
                code=(
                    "provider_connection_revoked"
                    if exc.code == "REVOKED"
                    else "provider_permission_denied"
                ),
                detail=exc.detail,
            ) from exc
        if exc.code == "NOT_FOUND":
            raise NotFoundError(code="provider_resource_not_found", detail=exc.detail) from exc
        if exc.code == "STALE_SHA":
            raise ConflictError(code="provider_stale_sha", detail=exc.detail) from exc
        if exc.code == "TRANSIENT":
            transient_err = DependencyUnavailableError(
                code="provider_transient_unavailable",
                detail=exc.detail,
            )
            transient_err.retry_after_seconds = exc.retry_after_seconds
            raise transient_err from exc
        raise UnprocessableEntityError(code="provider_unsupported", detail=exc.detail) from exc

    def build_setup_probe(
        self,
        *,
        fallback_probe: SetupStepProbeCallable | None = None,
    ) -> SetupStepProbeCallable:
        """Build the concrete `provider_connect` probe for `SetupStepRegistry` (`U09`..`U10`)."""

        async def _probe(
            phase: SetupWizardPhase,
            draft: Mapping[str, Any],
        ) -> SetupStepProbeResult:
            provider = str(draft.get("provider") or "github").lower()
            if provider not in {"github", "gitlab"}:
                if fallback_probe is not None:
                    return await fallback_probe(phase, draft)
                return SetupStepProbeResult(
                    probe_status="not_configured",
                    detail=f"Provider '{provider}' live capability probe is not_configured.",
                    blocking_reasons=(f"{provider}_probe_unregistered",),
                )

            async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
                conn_rows = list(
                    (
                        await db.scalars(
                            select(ProviderConnectionModel)
                            .where(ProviderConnectionModel.provider == provider)
                            .order_by(ProviderConnectionModel.updated_at.desc())
                        )
                    ).all()
                )
                if not conn_rows:
                    label = "GitLab" if provider == "gitlab" else "GitHub App"
                    return SetupStepProbeResult(
                        probe_status="not_configured",
                        detail=(
                            f"No {label} connection recorded yet; create and verify a "
                            f"{label} connection in Workspace Integrations."
                        ),
                        blocking_reasons=(f"{provider}_connection_not_configured",),
                    )

                ready_conn = next((r for r in conn_rows if r.status == "ready"), None)
                if ready_conn is not None:
                    default_ver = GITLAB_API_VERSION if provider == "gitlab" else GITHUB_API_VERSION
                    return SetupStepProbeResult(
                        probe_status="passed",
                        detail=(
                            f"{provider.upper()} connection '{ready_conn.display_name}' verified "
                            f"(API {ready_conn.api_version or default_ver})."
                        ),
                    )

                target = conn_rows[0]
                if target.status == "revoked":
                    return SetupStepProbeResult(
                        probe_status="failed",
                        detail=(
                            f"{provider.upper()} connection '{target.display_name}' is revoked; "
                            "rotate credentials and review grants."
                        ),
                        blocking_reasons=(f"{provider}_connection_revoked",),
                    )
                if target.status == "unsupported":
                    return SetupStepProbeResult(
                        probe_status="unsupported",
                        detail=target.status_detail
                        or "Pinned webhook auth_mode is unsupported by the target GitLab server.",
                        blocking_reasons=(f"{provider}_auth_mode_unsupported",),
                    )

                if target.credential_secret_ref is not None:
                    try:
                        if provider == "gitlab":
                            summary = await self._gitlab.get_permissions(
                                db,
                                _to_connection_context(target),
                                now=datetime.now(tz=UTC),
                            )
                            if summary.unsupported_auth_mode:
                                target.status = "unsupported"
                                target.checked_at = datetime.now(tz=UTC)
                                target.updated_at = datetime.now(tz=UTC)
                                await db.flush()
                                return SetupStepProbeResult(
                                    probe_status="unsupported",
                                    detail=summary.detail
                                    or (
                                        "GitLab server version < 19.0 does not support "
                                        "signed webhooks."
                                    ),
                                    blocking_reasons=("gitlab_v19_webhook_signing_unsupported",),
                                )
                            if not summary.missing_required_permissions:
                                target.status = "ready"
                                target.vendor_version = summary.vendor_version
                                target.api_version = summary.api_version
                                target.checked_at = datetime.now(tz=UTC)
                                target.updated_at = datetime.now(tz=UTC)
                                await db.flush()
                                return SetupStepProbeResult(
                                    probe_status="passed",
                                    detail=(
                                        f"GitLab connection '{target.display_name}' verified "
                                        f"({summary.vendor_version or GITLAB_API_VERSION})."
                                    ),
                                )
                            return SetupStepProbeResult(
                                probe_status="needs_admin",
                                detail=summary.detail
                                or "Grant read_api or api scope on GitLab token.",
                                blocking_reasons=("gitlab_required_scope_missing",),
                            )

                        summary = await self._github.get_permissions(
                            db,
                            _to_connection_context(target),
                            now=datetime.now(tz=UTC),
                        )
                        if (
                            target.external_installation_id is not None
                            and not summary.missing_required_permissions
                        ):
                            target.status = "ready"
                            target.checked_at = datetime.now(tz=UTC)
                            target.updated_at = datetime.now(tz=UTC)
                            await db.flush()
                            return SetupStepProbeResult(
                                probe_status="passed",
                                detail=(
                                    f"GitHub App installation '{target.external_installation_id}' "
                                    "verified ready for repository monitoring."
                                ),
                            )
                        return SetupStepProbeResult(
                            probe_status="needs_admin",
                            detail=summary.detail
                            or "Confirm GitHub App installation to complete provider setup.",
                            blocking_reasons=("github_installation_confirmation_required",),
                        )
                    except ProviderError as exc:
                        return SetupStepProbeResult(
                            probe_status="failed",
                            detail=exc.detail,
                            blocking_reasons=(f"{provider}_{exc.code.lower()}",),
                        )

                return SetupStepProbeResult(
                    probe_status="needs_admin",
                    detail=(
                        f"{provider.upper()} connection '{target.display_name}' requires "
                        "credential configuration."
                    ),
                    blocking_reasons=(f"{provider}_credentials_missing",),
                )

        return _probe

    def register_setup_probe(self, registry: SetupStepRegistry) -> None:
        """Register the concrete `provider_connect` GitHub probe in `SetupStepRegistry`."""
        existing = registry.get_probe("provider_connect")
        registry.register_probe(
            "provider_connect",
            self.build_setup_probe(fallback_probe=existing),
        )
