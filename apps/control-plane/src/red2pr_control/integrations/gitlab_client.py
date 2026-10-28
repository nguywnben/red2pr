"""GitLab Cloud & Self-Managed REST v4 adapter, pinned webhook auth & `.gitlab-ci.yml` scanner.

Implements `docs/12_PROVIDER_INTEGRATIONS.md`, `docs/26_SECURITY_TEST_MATRIX.md`, and
`docs/40_EXECUTION_MASTER_PLAN.md` (`U10`, `SRC-02`, `A-06`, `S-08`, `W-02`,
`SEC-003`, `SEC-011`, `SEC-018`, `SEC-027`, `SEC-031`, `SEC-032`, `SEC-033`):
- GitLab.com and Self-Managed GitLab REST v4 client routed strictly through `ADR-037`
  DNS-pinning `EgressSafeHttpClient(adapter="gitlab", ...)` with custom `ca_ref` bundles
  and cross-origin redirect credential stripping (`PRIVATE-TOKEN`, `Authorization`).
- Capability negotiation via `/api/v4/version` and `/api/v4/personal_access_tokens/self`,
  recording exact major/minor version, CE/EE edition, and token scopes without ever
  claiming `read_api`-only tokens can create Merge Requests or manage webhooks.
- Pinned per-connection webhook authentication (`gitlab_signed_v19` vs `gitlab_legacy_token`)
  with zero silent downgrade (`SEC-027`) and redacted security rejection logging (`SEC-003`).
- Pipeline, child/downstream `/bridges`, and `/jobs?include_retried=true` normalization
  preserving exact GitLab pipeline/job IDs and retry lineage (`retry_of_id`) without
  inventing synthetic GitHub `run_attempt` integers.
- `Draft: ` Merge Request creation targeting explicit `target_project_id` and `target_branch`
  (never sending deprecated `wip`), attaching `Idempotency-Key` when server `>= 17.4`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx
import yaml
from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts.integrations import (
    CapabilityAvailability,
    RepositoryVisibility,
    WorkflowHazardFinding,
    WorkflowHazardStatus,
)
from py_contracts.primitives import new_uuid7
from red2pr_control.core.egress import (
    CaBundleResolverProtocol,
    EgressBlockedError,
    EgressPolicyEngine,
    EgressSafeHttpClient,
)
from red2pr_control.core.logging import get_structured_logger
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.integrations.base import (
    DiscoveredRepositoryRecord,
    PaginatedRepoDiscoveryResult,
    ProviderArtifactRecord,
    ProviderConnectionContext,
    ProviderCredentialVaultProtocol,
    ProviderDraftReviewRecord,
    ProviderError,
    ProviderJobRecord,
    ProviderPermissionSummary,
    ProviderPollItem,
    ProviderPollRunsResult,
    ProviderRemoteCheckRecord,
    ProviderRunRecord,
    parse_retry_after_seconds,
)

GITLAB_API_VERSION = "v4"
_MAX_WORKFLOW_YAML_BYTES = 262_144
_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)")
_MATRIX_BRACKET_RE = re.compile(r"^(?P<base>[^:\[]+?):?\s*\[(?P<dims>[^\]]+)\]\s*$")
_RESERVED_GITLAB_CI_KEYS: frozenset[str] = frozenset(
    {
        "stages",
        "variables",
        "default",
        "workflow",
        "include",
        "pages",
        "spec",
        "image",
        "services",
        "before_script",
        "after_script",
        "cache",
    }
)
_PROD_ENV_KEYWORDS: tuple[str, ...] = ("prod", "production", "live", "release")

_LOGGER = get_structured_logger("red2pr_control.integrations.gitlab")


@dataclass(frozen=True, slots=True)
class GitLabChildPipelineRecord:
    """Downstream / child pipeline relation discovered via `/pipelines/:id/bridges`."""

    bridge_job_id: str
    bridge_name: str
    bridge_status: str
    downstream_pipeline_id: str
    downstream_project_id: str | None
    downstream_status: str
    downstream_sha: str | None
    downstream_ref: str | None


def parse_gitlab_semver(version_text: str | None) -> tuple[int, int] | None:
    """Extract `(major, minor)` integer tuple from a GitLab version string (e.g. `19.1.2-ee`)."""
    if not version_text:
        return None
    match = _SEMVER_RE.match(version_text.strip())
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)))


def _parse_iso_dt(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    cleaned = raw.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _map_gitlab_pipeline_status(raw_status: str) -> tuple[str, str | None, bool]:
    lowered = raw_status.strip().lower()
    if lowered in {
        "created",
        "waiting_for_resource",
        "preparing",
        "pending",
        "scheduled",
    }:
        return ("queued", None, False)
    if lowered in {"running", "canceling"}:
        return ("in_progress", None, False)
    if lowered == "manual":
        return ("completed", "action_required", True)
    if lowered == "success":
        return ("completed", "success", True)
    if lowered == "failed":
        return ("completed", "failure", True)
    if lowered in {"canceled", "cancelled"}:
        return ("completed", "cancelled", True)
    if lowered == "skipped":
        return ("completed", "skipped", True)
    return ("unknown", "unknown", False)


def _map_gitlab_job_status(raw_status: str) -> tuple[str, str | None]:
    lowered = raw_status.strip().lower()
    if lowered in {"created", "waiting_for_resource", "preparing", "pending", "scheduled"}:
        return ("queued", None)
    if lowered in {"running", "canceling"}:
        return ("in_progress", None)
    if lowered == "success":
        return ("completed", "success")
    if lowered == "failed":
        return ("completed", "failure")
    if lowered in {"canceled", "cancelled"}:
        return ("completed", "cancelled")
    if lowered == "skipped":
        return ("completed", "skipped")
    if lowered == "manual":
        return ("completed", "action_required")
    return ("unknown", "unknown")


def _extract_matrix_dimensions(job_name: str, stage: str | None) -> dict[str, str]:
    dims: dict[str, str] = {}
    if stage and stage.strip():
        dims["stage"] = stage.strip()[:120]
    match = _MATRIX_BRACKET_RE.match(job_name.strip())
    if match is not None:
        raw_parts = [p.strip() for p in match.group("dims").split(",") if p.strip()]
        for idx, part in enumerate(raw_parts[:8]):
            dims[f"matrix_{idx}"] = part[:120]
    return dims


def scan_gitlab_ci_yaml(
    yaml_content: str,
    *,
    ci_path: str = ".gitlab-ci.yml",
) -> tuple[WorkflowHazardStatus, tuple[WorkflowHazardFinding, ...], bool]:
    """Inspect `.gitlab-ci.yml` for dangerous MR-triggered production deployments (`SEC-031`)."""
    encoded = yaml_content.encode("utf-8", errors="replace")
    safe_path = (ci_path.strip() or ".gitlab-ci.yml")[:240]
    if len(encoded) > _MAX_WORKFLOW_YAML_BYTES:
        finding = WorkflowHazardFinding(
            code="workflow_parse_warning",
            severity="medium",
            workflow_path=safe_path,
            detail="GitLab CI configuration exceeds 256 KiB static inspection ceiling.",
        )
        return ("flagged", (finding,), True)

    try:
        parsed = yaml.safe_load(yaml_content)
    except yaml.YAMLError:
        finding = WorkflowHazardFinding(
            code="workflow_parse_warning",
            severity="medium",
            workflow_path=safe_path,
            detail=(
                "Failed to parse .gitlab-ci.yml YAML safely; review before enabling auto-repair."
            ),
        )
        return ("flagged", (finding,), True)

    if not isinstance(parsed, Mapping):
        return ("clean", (), False)

    findings: list[WorkflowHazardFinding] = []
    for raw_key, job_cfg in parsed.items():
        job_name = str(raw_key).strip()
        if (
            not job_name
            or job_name.startswith(".")
            or job_name in _RESERVED_GITLAB_CI_KEYS
            or not isinstance(job_cfg, Mapping)
        ):
            continue

        env_spec = job_cfg.get("environment")
        env_name = ""
        env_action = "start"
        if isinstance(env_spec, str):
            env_name = env_spec.strip().lower()
        elif isinstance(env_spec, Mapping):
            env_name = str(env_spec.get("name") or "").strip().lower()
            env_action = str(env_spec.get("action") or "start").strip().lower()

        is_prod_env = env_action != "stop" and any(
            env_name == kw or env_name.startswith((f"{kw}/", f"{kw}-", f"{kw}_"))
            for kw in _PROD_ENV_KEYWORDS
        )
        if not is_prod_env:
            continue

        top_when = str(job_cfg.get("when") or "").strip().lower()
        rules_list = job_cfg.get("rules")
        mr_automatic_allowed = top_when != "manual"
        if isinstance(rules_list, list) and rules_list:
            mr_non_manual = False
            for rule in rules_list:
                if not isinstance(rule, Mapping):
                    continue
                if_expr = str(rule.get("if") or "")
                rule_when = str(rule.get("when") or "on_success").strip().lower()
                if "merge_request_event" in if_expr or "CI_MERGE_REQUEST" in if_expr:
                    if rule_when not in {"manual", "never"}:
                        mr_non_manual = True
                elif not if_expr and rule_when not in {"manual", "never"}:
                    mr_non_manual = True
            mr_automatic_allowed = mr_non_manual

        if mr_automatic_allowed:
            findings.append(
                WorkflowHazardFinding(
                    code="deploy_trigger",
                    severity="high",
                    workflow_path=safe_path,
                    detail=(
                        f"Job '{job_name[:60]}' deploys automatically to production environment "
                        f"'{env_name[:60]}' without manual gating; autonomous repair is blocked."
                    ),
                )
            )

    if not findings:
        return ("clean", (), False)
    auto_blocked = any(f.severity in {"high", "medium"} for f in findings)
    return ("flagged", tuple(findings), auto_blocked)


class GitLabAdapter:
    """GitLab Cloud & Self-Managed `SourceProviderAdapter` (`U10`, `SRC-02`)."""

    def __init__(
        self,
        *,
        vault: ProviderCredentialVaultProtocol,
        egress_policy: EgressPolicyEngine | None = None,
        ca_bundle_resolver: CaBundleResolverProtocol | None = None,
        redactor: Redactor | None = None,
        timeout_seconds: float = 15.0,
        transport_override: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._vault = vault
        self._egress_policy = egress_policy or EgressPolicyEngine()
        self._ca_resolver = ca_bundle_resolver
        self._redactor = redactor or DEFAULT_REDACTOR
        self._timeout_seconds = timeout_seconds
        self._transport_override = transport_override

    @staticmethod
    def _build_api_url(base_url: str, api_path: str) -> str:
        clean_base = base_url.strip().rstrip("/")
        clean_path = api_path if api_path.startswith("/") else f"/{api_path}"
        if clean_base.endswith("/api/v4"):
            return f"{clean_base}{clean_path}"
        return f"{clean_base}/api/v4{clean_path}"

    @staticmethod
    def _encode_project_ref(repo_full_name: str) -> str:
        cleaned = repo_full_name.strip().strip("/")
        if not cleaned or ".." in cleaned.split("/"):
            raise ProviderError(
                code="UNSUPPORTED",
                detail="Invalid GitLab project path or identifier.",
                provider="gitlab",
            )
        return quote(cleaned, safe="")

    @staticmethod
    def _default_headers(
        *,
        access_token: str,
        extra: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        headers: dict[str, str] = {
            "Accept": "application/json",
            "PRIVATE-TOKEN": access_token,
            "User-Agent": "Red2PR-ControlPlane/1.0",
        }
        if extra:
            headers.update(extra)
        return headers

    @staticmethod
    def _is_sensitive_header(name: str) -> bool:
        lower = name.strip().lower()
        if lower in {
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "x-gitlab-token",
            "private-token",
            "job-token",
            "x-csrf-token",
        }:
            return True
        return lower.endswith(("-token", "-secret", "-key", "-signature"))

    @staticmethod
    def _origin_tuple(url: httpx.URL) -> tuple[str, str, int]:
        scheme = url.scheme.lower()
        port = url.port if url.port is not None else (443 if scheme == "https" else 80)
        return (scheme, url.host.lower(), port)

    async def _resolve_token(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
    ) -> str:
        if not ctx.credential_secret_ref:
            raise ProviderError(
                code="UNSUPPORTED",
                detail="GitLab connection has no configured access token in the Z2 secret broker.",
                provider="gitlab",
            )
        try:
            token = await self._vault.resolve_provider_access_token(
                session,
                workspace_id=ctx.workspace_id,
                secret_ref=ctx.credential_secret_ref,
            )
        except Exception as exc:
            raise ProviderError(
                code="REVOKED",
                detail="GitLab credential secret in Z2 broker is revoked or unavailable.",
                provider="gitlab",
                status_code=401,
            ) from exc
        if not token:
            raise ProviderError(
                code="UNSUPPORTED",
                detail="GitLab access token is empty.",
                provider="gitlab",
            )
        return token

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
                            adapter="gitlab",
                            url=current_url,
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
                                    "for adapter 'gitlab'."
                                ),
                                adapter="gitlab",
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
                adapter="gitlab",
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
                detail="GitLab API request timed out.",
                provider="gitlab",
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(
                code="TRANSIENT",
                detail=self._redactor.redact_text(f"GitLab transport error: {exc}"),
                provider="gitlab",
            ) from exc

    def _raise_for_gitlab_status(
        self,
        response: httpx.Response,
        *,
        treat_400_409_422_as_stale_sha: bool = False,
    ) -> None:
        status_code = response.status_code
        if 200 <= status_code < 300:
            return

        ref_now = datetime.now(tz=UTC)
        raw_retry = response.headers.get("retry-after") or response.headers.get(
            "ratelimit-resettime"
        )
        retry_after = parse_retry_after_seconds(raw_retry, now=ref_now)
        if retry_after is None:
            raw_reset = response.headers.get("ratelimit-reset")
            if raw_reset and raw_reset.strip().isdigit():
                delta = int(raw_reset.strip()) - int(ref_now.timestamp())
                retry_after = max(1, min(delta, 3600))

        body_msg = ""
        try:
            parsed = response.json()
            if isinstance(parsed, Mapping):
                raw_m = (
                    parsed.get("message") or parsed.get("error_description") or parsed.get("error")
                )
                if isinstance(raw_m, str):
                    body_msg = raw_m
                elif raw_m is not None:
                    body_msg = str(raw_m)
        except Exception:
            body_msg = response.text[:300]
        clean_msg = self._redactor.redact_text(body_msg or f"HTTP {status_code}")[:300]
        lower_msg = clean_msg.lower()

        if status_code == 429:
            raise ProviderError(
                code="RATE_LIMIT",
                detail=f"GitLab API rate limit exceeded: {clean_msg}",
                provider="gitlab",
                status_code=429,
                retry_after_seconds=retry_after or 60,
            )

        if status_code == 401:
            raise ProviderError(
                code="REVOKED",
                detail=f"GitLab access token rejected or revoked: {clean_msg}",
                provider="gitlab",
                status_code=401,
            )

        if status_code == 403:
            if any(
                marker in lower_msg for marker in ("revoked", "expired", "blocked", "deactivated")
            ):
                raise ProviderError(
                    code="REVOKED",
                    detail=f"GitLab token or bot account revoked/blocked: {clean_msg}",
                    provider="gitlab",
                    status_code=403,
                )
            raise ProviderError(
                code="FORBIDDEN",
                detail=f"GitLab permission denied: {clean_msg}",
                provider="gitlab",
                status_code=403,
            )

        if status_code == 404:
            raise ProviderError(
                code="NOT_FOUND",
                detail=f"GitLab resource not found: {clean_msg}",
                provider="gitlab",
                status_code=404,
            )

        if treat_400_409_422_as_stale_sha and status_code in (400, 409, 422):
            raise ProviderError(
                code="STALE_SHA",
                detail=f"GitLab branch/commit conflict: {clean_msg}",
                provider="gitlab",
                status_code=status_code,
            )

        if status_code in (500, 502, 503, 504):
            raise ProviderError(
                code="TRANSIENT",
                detail=f"GitLab upstream transient error ({status_code}): {clean_msg}",
                provider="gitlab",
                status_code=status_code,
                retry_after_seconds=retry_after,
            )

        raise ProviderError(
            code="UNSUPPORTED",
            detail=f"Unexpected GitLab response ({status_code}): {clean_msg}",
            provider="gitlab",
            status_code=status_code,
        )

    async def get_permissions(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        installation_id_override: str | None = None,
        now: datetime | None = None,
    ) -> ProviderPermissionSummary:
        del installation_id_override, now
        token = await self._resolve_token(session, ctx)
        headers = self._default_headers(access_token=token)

        ver_resp = await self._send_request(
            "GET",
            self._build_api_url(ctx.base_url, "/version"),
            headers=headers,
        )
        self._raise_for_gitlab_status(ver_resp)
        ver_json = ver_resp.json()
        raw_version = (
            str(ver_json.get("version") or "").strip() if isinstance(ver_json, Mapping) else ""
        )
        enterprise = bool(ver_json.get("enterprise")) if isinstance(ver_json, Mapping) else False
        semver = parse_gitlab_semver(raw_version)

        pat_resp = await self._send_request(
            "GET",
            self._build_api_url(ctx.base_url, "/personal_access_tokens/self"),
            headers=headers,
        )
        self._raise_for_gitlab_status(pat_resp)
        pat_json = pat_resp.json()
        if not isinstance(pat_json, Mapping):
            raise ProviderError(
                code="TRANSIENT",
                detail="Malformed response from /api/v4/personal_access_tokens/self.",
                provider="gitlab",
            )

        if bool(pat_json.get("revoked")) or pat_json.get("active") is False:
            raise ProviderError(
                code="REVOKED",
                detail="GitLab access token is marked inactive or revoked.",
                provider="gitlab",
                status_code=401,
            )

        raw_scopes = pat_json.get("scopes")
        scopes: list[str] = (
            [str(s).strip() for s in raw_scopes if str(s).strip()]
            if isinstance(raw_scopes, list)
            else []
        )
        token_name = str(pat_json.get("name") or "").strip()[:120] or None

        has_full_api = "api" in scopes
        has_read_api = has_full_api or "read_api" in scopes
        has_write_repo = has_full_api or "write_repository" in scopes

        granted: dict[str, str] = {
            "edition": "enterprise" if enterprise else "community",
            "webhook_auth_mode": ctx.auth_mode,
        }
        for sc in scopes[:16]:
            granted[f"scope:{sc}"[:120]] = "granted"
        expires_at = pat_json.get("expires_at")
        if isinstance(expires_at, str) and expires_at.strip():
            granted["token_expires_at"] = expires_at.strip()[:120]

        missing_required: list[str] = []
        missing_optional: list[str] = []
        unsupported_auth_mode = False

        if not has_read_api:
            missing_required.append("read_api")

        if not has_full_api:
            # Never claim read_api-only tokens can create MRs or manage project webhooks!
            missing_optional.append("api")
            missing_optional.append("webhook_admin")

        is_signed_v19_mode = ctx.auth_mode in {"gitlab_signed_v19", "signed_webhook"}
        webhook_hmac_avail: CapabilityAvailability = "unavailable"
        if is_signed_v19_mode:
            if semver is not None and semver < (19, 0):
                unsupported_auth_mode = True
                missing_required.append("gitlab_v19_webhook_signing")
            elif ctx.webhook_secret_ref:
                webhook_hmac_avail = "available"
            else:
                missing_optional.append("webhook_signing_secret")
        else:
            granted["webhook_assurance"] = "legacy_token_tls"
            if not ctx.webhook_secret_ref:
                missing_optional.append("webhook_legacy_secret")

        capabilities: dict[str, CapabilityAvailability] = {
            "repo_discovery": "available" if has_read_api else "unavailable",
            "ci_read": "available" if has_read_api else "unavailable",
            "log_download": "available" if has_read_api else "unavailable",
            "artifact_download": "available" if has_read_api else "unavailable",
            "branch_write": "available" if (has_full_api or has_write_repo) else "unavailable",
            "draft_review_create": "available" if has_full_api else "unavailable",
            "checks_write": "available" if has_full_api else "unavailable",
            "webhook_hmac": webhook_hmac_avail,
            "webhook_admin": "available" if has_full_api else "unavailable",
            "polling_fallback": "available" if has_read_api else "unavailable",
            "idempotency_key_v17_4": (
                "available" if (semver is not None and semver >= (17, 4)) else "unavailable"
            ),
        }

        if unsupported_auth_mode:
            detail = (
                f"GitLab {raw_version or 'unknown'} (< 19.0) does not support Standard Webhooks "
                "signing tokens (`gitlab_signed_v19`). Connection stays unsupported; Red2PR never "
                "silently downgrades to legacy X-Gitlab-Token."
            )
        elif missing_required:
            detail = f"GitLab token is missing required scope(s): {', '.join(missing_required)}."
        elif not has_full_api:
            detail = (
                f"GitLab {raw_version or GITLAB_API_VERSION} verified in read-only Monitor scope "
                "(`read_api`): Draft MR creation and webhook admin are unavailable; polling "
                "fallback is available."
            )
        else:
            detail = (
                f"GitLab {raw_version or GITLAB_API_VERSION} "
                f"({'EE' if enterprise else 'CE'}) verified with full API capabilities."
            )

        return ProviderPermissionSummary(
            account_login=token_name,
            vendor_version=raw_version[:120] if raw_version else None,
            api_version=GITLAB_API_VERSION,
            granted_permissions=granted,
            missing_required_permissions=tuple(missing_required),
            missing_optional_permissions=tuple(missing_optional),
            excess_unused_permissions=(),
            capabilities=capabilities,
            suspended=False,
            unsupported_auth_mode=unsupported_auth_mode,
            detail=detail[:950],
        )

    async def _scan_project_ci_hazards(
        self,
        *,
        base_url: str,
        headers: Mapping[str, str],
        project_path: str,
        default_branch: str,
        ci_config_path: str,
    ) -> tuple[WorkflowHazardStatus, tuple[WorkflowHazardFinding, ...], bool]:
        clean_ci = (ci_config_path.strip() or ".gitlab-ci.yml").lstrip("/")
        if "@" in clean_ci or clean_ci.startswith(("http://", "https://")):
            return ("unscanned", (), False)
        encoded_proj = self._encode_project_ref(project_path)
        encoded_file = quote(clean_ci, safe="")
        encoded_ref = quote(default_branch, safe="")
        resp = await self._send_request(
            "GET",
            self._build_api_url(
                base_url,
                f"/projects/{encoded_proj}/repository/files/{encoded_file}/raw?ref={encoded_ref}",
            ),
            headers={**headers, "Accept": "text/plain"},
        )
        if resp.status_code == 404:
            return ("clean", (), False)
        if resp.status_code >= 400:
            return ("unscanned", (), False)
        return scan_gitlab_ci_yaml(resp.text, ci_path=clean_ci)

    async def list_repos(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        per_page: int = 50,
        scan_workflows: bool = True,
        now: datetime | None = None,
    ) -> PaginatedRepoDiscoveryResult:
        del now
        token = await self._resolve_token(session, ctx)
        headers = self._default_headers(access_token=token)
        bounded_per_page = max(1, min(per_page, 100))

        discovered: list[DiscoveredRepositoryRecord] = []
        seen_ids: set[str] = set()
        partial_sync = False
        warning_detail: str | None = None
        page = 1

        while page <= 50:
            path = (
                f"/projects?membership=true&simple=false"
                f"&per_page={bounded_per_page}&page={page}&order_by=id&sort=asc"
            )
            try:
                resp = await self._send_request(
                    "GET",
                    self._build_api_url(ctx.base_url, path),
                    headers=headers,
                )
                self._raise_for_gitlab_status(resp)
            except ProviderError as exc:
                if page > 1 and exc.code in {"RATE_LIMIT", "TRANSIENT"}:
                    partial_sync = True
                    warning_detail = (
                        f"GitLab project discovery stopped at page {page} ({exc.code}); "
                        "previously synchronized projects were preserved."
                    )
                    break
                raise

            items = resp.json()
            if not isinstance(items, list):
                raise ProviderError(
                    code="TRANSIENT",
                    detail="GitLab /projects endpoint did not return a JSON array.",
                    provider="gitlab",
                )

            for raw_proj in items:
                if not isinstance(raw_proj, Mapping):
                    continue
                ext_id = str(raw_proj.get("id") or "").strip()
                full_name = str(raw_proj.get("path_with_namespace") or "").strip()
                short_name = str(raw_proj.get("name") or "").strip()
                if not ext_id or not full_name or ext_id in seen_ids:
                    continue
                seen_ids.add(ext_id)

                default_branch = str(raw_proj.get("default_branch") or "main").strip()[:120]
                raw_vis = str(raw_proj.get("visibility") or "unknown").strip().lower()
                visibility: RepositoryVisibility = (
                    raw_vis  # type: ignore[assignment]
                    if raw_vis in {"public", "private", "internal"}
                    else "unknown"
                )
                archived = bool(raw_proj.get("archived", False))
                empty_repo = bool(raw_proj.get("empty_repo", False))
                jobs_enabled = bool(raw_proj.get("jobs_enabled", True))
                is_fork = raw_proj.get("forked_from_project") is not None
                ci_path = str(raw_proj.get("ci_config_path") or ".gitlab-ci.yml")

                hazard_status: WorkflowHazardStatus = "unscanned"
                hazards: tuple[WorkflowHazardFinding, ...] = ()
                auto_blocked = False
                if scan_workflows and not archived and not empty_repo:
                    try:
                        (
                            hazard_status,
                            hazards,
                            auto_blocked,
                        ) = await self._scan_project_ci_hazards(
                            base_url=ctx.base_url,
                            headers=headers,
                            project_path=full_name,
                            default_branch=default_branch,
                            ci_config_path=ci_path,
                        )
                    except ProviderError:
                        hazard_status = "unscanned"

                discovered.append(
                    DiscoveredRepositoryRecord(
                        external_repo_id=ext_id[:128],
                        short_name=(short_name or full_name.rsplit("/", 1)[-1])[:120],
                        full_name=full_name[:120],
                        default_branch=default_branch or "main",
                        visibility=visibility,
                        archived=archived,
                        disabled=not jobs_enabled,
                        is_fork=is_fork,
                        workflow_hazard_status=hazard_status,
                        workflow_hazards=hazards,
                        auto_repair_blocked=auto_blocked,
                    )
                )

            next_page_hdr = (resp.headers.get("x-next-page") or "").strip()
            if not next_page_hdr or not next_page_hdr.isdigit():
                break
            next_page = int(next_page_hdr)
            if next_page <= page:
                break
            page = next_page

        total_hdr = (resp.headers.get("x-total") or "").strip() if page >= 1 else ""
        total_reported = int(total_hdr) if total_hdr.isdigit() else len(discovered)
        return PaginatedRepoDiscoveryResult(
            repositories=tuple(discovered),
            total_reported=max(total_reported, len(discovered)),
            partial_sync=partial_sync,
            warning_detail=warning_detail,
        )

    async def list_child_pipelines(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        external_run_id: str,
    ) -> Sequence[GitLabChildPipelineRecord]:
        """Inspect `/pipelines/:id/bridges` to preserve parent/downstream child pipeline lineage."""
        token = await self._resolve_token(session, ctx)
        encoded_proj = self._encode_project_ref(repo_full_name)
        encoded_pipe = quote(external_run_id.strip(), safe="")
        resp = await self._send_request(
            "GET",
            self._build_api_url(
                ctx.base_url,
                f"/projects/{encoded_proj}/pipelines/{encoded_pipe}/bridges?per_page=100",
            ),
            headers=self._default_headers(access_token=token),
        )
        if resp.status_code == 404:
            return ()
        self._raise_for_gitlab_status(resp)
        raw_bridges = resp.json()
        if not isinstance(raw_bridges, list):
            return ()

        children: list[GitLabChildPipelineRecord] = []
        for bridge in raw_bridges:
            if not isinstance(bridge, Mapping):
                continue
            downstream = bridge.get("downstream_pipeline")
            if not isinstance(downstream, Mapping) or not downstream.get("id"):
                continue
            children.append(
                GitLabChildPipelineRecord(
                    bridge_job_id=str(bridge.get("id") or ""),
                    bridge_name=str(bridge.get("name") or "bridge")[:120],
                    bridge_status=str(bridge.get("status") or "unknown"),
                    downstream_pipeline_id=str(downstream["id"]),
                    downstream_project_id=(
                        str(downstream["project_id"])
                        if downstream.get("project_id") is not None
                        else None
                    ),
                    downstream_status=str(downstream.get("status") or "unknown"),
                    downstream_sha=(
                        str(downstream["sha"]) if downstream.get("sha") is not None else None
                    ),
                    downstream_ref=(
                        str(downstream["ref"]) if downstream.get("ref") is not None else None
                    ),
                )
            )
        return tuple(children)

    async def get_run(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        external_run_id: str,
        now: datetime | None = None,
    ) -> ProviderRunRecord:
        del now
        token = await self._resolve_token(session, ctx)
        encoded_proj = self._encode_project_ref(repo_full_name)
        encoded_pipe = quote(external_run_id.strip(), safe="")
        resp = await self._send_request(
            "GET",
            self._build_api_url(
                ctx.base_url,
                f"/projects/{encoded_proj}/pipelines/{encoded_pipe}",
            ),
            headers=self._default_headers(access_token=token),
        )
        self._raise_for_gitlab_status(resp)
        pipe = resp.json()
        if not isinstance(pipe, Mapping):
            raise ProviderError(
                code="TRANSIENT",
                detail="Malformed GitLab pipeline payload.",
                provider="gitlab",
            )

        raw_status = str(pipe.get("status") or "unknown")
        norm_status, conclusion, jobs_complete = _map_gitlab_pipeline_status(raw_status)

        children = await self.list_child_pipelines(
            session,
            ctx,
            repo_full_name=repo_full_name,
            external_run_id=external_run_id,
        )
        for child in children:
            child_status, child_conclusion, child_done = _map_gitlab_pipeline_status(
                child.downstream_status
            )
            if not child_done or child_status in {"queued", "in_progress"}:
                jobs_complete = False
                if norm_status == "completed":
                    norm_status = "in_progress"
                    conclusion = None
            elif child_conclusion == "failure" and conclusion == "success":
                conclusion = "failure"

        pipe_id = str(pipe.get("id") or external_run_id.strip())
        proj_id = str(pipe.get("project_id")) if pipe.get("project_id") is not None else None
        # Preserve exact GitLab pipeline ID in attempt_key without synthetic run_attempt ints
        return ProviderRunRecord(
            external_run_id=pipe_id,
            attempt_key=f"pipeline:{pipe_id}",
            head_sha=str(pipe.get("sha") or ""),
            ref=str(pipe.get("ref") or "HEAD")[:120],
            event_type=str(pipe.get("source") or "push")[:120],
            status=norm_status,
            conclusion=conclusion,
            jobs_complete=jobs_complete,
            raw_vendor_status=raw_status[:120],
            head_repo_id=proj_id,
            base_repo_id=proj_id,
            head_repo_fork=False,
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
        del attempt_number, now
        token = await self._resolve_token(session, ctx)
        headers = self._default_headers(access_token=token)
        encoded_proj = self._encode_project_ref(repo_full_name)
        encoded_pipe = quote(external_run_id.strip(), safe="")

        raw_jobs: list[Mapping[str, Any]] = []
        page = 1
        while page <= 20:
            resp = await self._send_request(
                "GET",
                self._build_api_url(
                    ctx.base_url,
                    f"/projects/{encoded_proj}/pipelines/{encoded_pipe}/jobs"
                    f"?include_retried=true&per_page=100&page={page}",
                ),
                headers=headers,
            )
            self._raise_for_gitlab_status(resp)
            batch = resp.json()
            if not isinstance(batch, list):
                break
            for item in batch:
                if isinstance(item, Mapping) and item.get("id") is not None:
                    raw_jobs.append(item)
            next_page_hdr = (resp.headers.get("x-next-page") or "").strip()
            if not next_page_hdr or not next_page_hdr.isdigit():
                break
            next_page = int(next_page_hdr)
            if next_page <= page:
                break
            page = next_page

        def _job_sort_key(entry: Mapping[str, Any]) -> tuple[int, str]:
            jid = str(entry.get("id") or "")
            return (int(jid), jid) if jid.isdigit() else (0, jid)

        sorted_raw = sorted(raw_jobs, key=_job_sort_key)
        prior_by_stage_name: dict[tuple[str, str], str] = {}
        records: list[ProviderJobRecord] = []

        for item in sorted_raw:
            ext_job_id = str(item["id"]).strip()
            name = str(item.get("name") or "job").strip()[:120]
            stage = str(item.get("stage") or "").strip()
            raw_status = str(item.get("status") or "unknown")
            norm_status, conclusion = _map_gitlab_job_status(raw_status)

            lineage_key = (stage, name)
            retry_of_id = prior_by_stage_name.get(lineage_key)
            prior_by_stage_name[lineage_key] = ext_job_id

            dims = _extract_matrix_dimensions(name, stage or None)
            records.append(
                ProviderJobRecord(
                    external_job_id=ext_job_id,
                    name=name,
                    status=norm_status,
                    conclusion=conclusion,
                    started_at=_parse_iso_dt(item.get("started_at")),
                    completed_at=_parse_iso_dt(item.get("finished_at")),
                    matrix_dimensions=dims,
                    retry_of_id=retry_of_id,
                )
            )
        return tuple(records)

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
        del now
        token = await self._resolve_token(session, ctx)
        encoded_proj = self._encode_project_ref(repo_full_name)
        encoded_job = quote(external_job_id.strip(), safe="")
        resp = await self._send_request(
            "GET",
            self._build_api_url(
                ctx.base_url,
                f"/projects/{encoded_proj}/jobs/{encoded_job}/trace",
            ),
            headers=self._default_headers(
                access_token=token,
                extra={"Accept": "text/plain"},
            ),
        )
        self._raise_for_gitlab_status(resp)
        raw = resp.content
        if len(raw) > max_bytes:
            return raw[-max_bytes:]
        return raw

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
        token = await self._resolve_token(session, ctx)
        encoded_proj = self._encode_project_ref(repo_full_name)
        encoded_pipe = quote(external_run_id.strip(), safe="")
        resp = await self._send_request(
            "GET",
            self._build_api_url(
                ctx.base_url,
                f"/projects/{encoded_proj}/pipelines/{encoded_pipe}/jobs"
                "?include_retried=true&per_page=100",
            ),
            headers=self._default_headers(access_token=token),
        )
        self._raise_for_gitlab_status(resp)
        jobs = resp.json()
        if not isinstance(jobs, list):
            return ()

        artifacts: list[ProviderArtifactRecord] = []
        for job in jobs:
            if not isinstance(job, Mapping):
                continue
            job_id = str(job.get("id") or "")
            created_at = _parse_iso_dt(job.get("finished_at") or job.get("created_at"))
            expires_at = _parse_iso_dt(job.get("artifacts_expire_at"))
            expired = expires_at is not None and expires_at <= ref_now
            raw_list = job.get("artifacts")
            if not isinstance(raw_list, list):
                continue
            for art in raw_list:
                if not isinstance(art, Mapping):
                    continue
                file_type = str(art.get("file_type") or "archive")
                if file_type == "trace":
                    continue
                filename = str(art.get("filename") or f"{file_type}.zip")[:120]
                size_val = art.get("size")
                size_bytes = int(size_val) if isinstance(size_val, int) and size_val >= 0 else 0
                artifacts.append(
                    ProviderArtifactRecord(
                        external_artifact_id=f"{job_id}:{file_type}",
                        name=filename,
                        size_bytes=size_bytes,
                        expired=expired,
                        created_at=created_at,
                        expires_at=expires_at,
                    )
                )
        return tuple(artifacts)

    async def download_artifact_archive(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        external_artifact_id: str,
        max_bytes: int = 104_857_601,
        now: datetime | None = None,
    ) -> bytes:
        del now
        token = await self._resolve_token(session, ctx)
        encoded_proj = self._encode_project_ref(repo_full_name)
        raw_job_id = external_artifact_id.split(":", 1)[0].strip()
        if not raw_job_id:
            raise ProviderError(
                code="NOT_FOUND",
                detail="Invalid GitLab artifact identifier.",
                provider="gitlab",
                status_code=404,
            )
        encoded_job = quote(raw_job_id, safe="")
        resp = await self._send_request(
            "GET",
            self._build_api_url(
                ctx.base_url,
                f"/projects/{encoded_proj}/jobs/{encoded_job}/artifacts",
            ),
            headers=self._default_headers(
                access_token=token,
                extra={"Accept": "application/octet-stream"},
            ),
        )
        self._raise_for_gitlab_status(resp)
        cap = max(1, max_bytes)
        return bytes(resp.content[:cap])

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
        del now
        token = await self._resolve_token(session, ctx)
        encoded_proj = self._encode_project_ref(repo_full_name)
        resp = await self._send_request(
            "GET",
            self._build_api_url(
                ctx.base_url,
                f"/projects/{encoded_proj}/repository/compare"
                f"?from={quote(base_sha, safe='')}&to={quote(head_sha, safe='')}&unidiff=true",
            ),
            headers=self._default_headers(access_token=token),
        )
        self._raise_for_gitlab_status(resp)
        payload = resp.json()
        diffs = payload.get("diffs", []) if isinstance(payload, Mapping) else []
        chunks: list[str] = []
        if isinstance(diffs, list):
            for entry in diffs:
                if isinstance(entry, Mapping) and isinstance(entry.get("diff"), str):
                    old_p = str(entry.get("old_path") or "")
                    new_p = str(entry.get("new_path") or "")
                    chunks.append(f"--- a/{old_p}\n+++ b/{new_p}\n{entry['diff']}")
        joined = "\n".join(chunks)
        encoded = joined.encode("utf-8", errors="replace")
        if len(encoded) > max_bytes:
            return encoded[:max_bytes].decode("utf-8", errors="ignore")
        return joined

    async def resolve_workflow_config(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        workflow_path: str,
        ref: str,
        now: datetime | None = None,
    ) -> str:
        del now
        clean_path = workflow_path.strip().lstrip("/")
        if not clean_path or ".." in clean_path.split("/"):
            raise ProviderError(
                code="UNSUPPORTED",
                detail="Workflow path must be a safe repository-relative path.",
                provider="gitlab",
            )
        token = await self._resolve_token(session, ctx)
        encoded_proj = self._encode_project_ref(repo_full_name)
        resp = await self._send_request(
            "GET",
            self._build_api_url(
                ctx.base_url,
                f"/projects/{encoded_proj}/repository/files/{quote(clean_path, safe='')}/raw"
                f"?ref={quote(ref, safe='')}",
            ),
            headers=self._default_headers(
                access_token=token,
                extra={"Accept": "text/plain"},
            ),
        )
        self._raise_for_gitlab_status(resp)
        return resp.text

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
        del now
        token = await self._resolve_token(session, ctx)
        encoded_proj = self._encode_project_ref(repo_full_name)
        clean_branch = branch_name.removeprefix("refs/heads/")
        resp = await self._send_request(
            "POST",
            self._build_api_url(
                ctx.base_url,
                f"/projects/{encoded_proj}/repository/branches",
            ),
            headers=self._default_headers(access_token=token),
            json_body={"branch": clean_branch, "ref": from_sha},
        )
        self._raise_for_gitlab_status(resp, treat_400_409_422_as_stale_sha=True)
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
        del now
        token = await self._resolve_token(session, ctx)
        encoded_proj = self._encode_project_ref(repo_full_name)
        clean_branch = branch_name.removeprefix("refs/heads/")

        branch_resp = await self._send_request(
            "GET",
            self._build_api_url(
                ctx.base_url,
                f"/projects/{encoded_proj}/repository/branches/{quote(clean_branch, safe='')}",
            ),
            headers=self._default_headers(access_token=token),
        )
        self._raise_for_gitlab_status(branch_resp)
        branch_json = branch_resp.json()
        commit_obj = branch_json.get("commit", {}) if isinstance(branch_json, Mapping) else {}
        current_tip = str(commit_obj.get("id") or "") if isinstance(commit_obj, Mapping) else ""
        if current_tip and current_tip != expected_parent_sha:
            raise ProviderError(
                code="STALE_SHA",
                detail=(
                    f"GitLab branch '{clean_branch}' moved from expected parent SHA "
                    f"{expected_parent_sha[:12]} to {current_tip[:12]}."
                ),
                provider="gitlab",
                status_code=409,
            )

        actions = [
            {"action": "update", "file_path": path, "content": content}
            for path, content in file_changes.items()
        ]
        commit_resp = await self._send_request(
            "POST",
            self._build_api_url(
                ctx.base_url,
                f"/projects/{encoded_proj}/repository/commits",
            ),
            headers=self._default_headers(access_token=token),
            json_body={
                "branch": clean_branch,
                "commit_message": commit_message,
                "actions": actions,
                "force": False,
            },
        )
        self._raise_for_gitlab_status(commit_resp, treat_400_409_422_as_stale_sha=True)
        created = commit_resp.json()
        return str(created.get("id") or "") if isinstance(created, Mapping) else ""

    async def _negotiate_server_semver(
        self,
        *,
        ctx: ProviderConnectionContext,
        headers: Mapping[str, str],
    ) -> tuple[int, int] | None:
        cached_semver = parse_gitlab_semver(ctx.vendor_version)
        if cached_semver is not None:
            return cached_semver
        ver_resp = await self._send_request(
            "GET",
            self._build_api_url(ctx.base_url, "/version"),
            headers=headers,
        )
        if ver_resp.status_code >= 400:
            return None
        ver_json = ver_resp.json()
        if isinstance(ver_json, Mapping):
            return parse_gitlab_semver(str(ver_json.get("version") or ""))
        return None

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
        target_project_id: int | str | None = None,
        idempotency_key: str | None = None,
        now: datetime | None = None,
    ) -> ProviderDraftReviewRecord:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        token = await self._resolve_token(session, ctx)
        base_headers = self._default_headers(access_token=token)
        encoded_proj = self._encode_project_ref(repo_full_name)

        # Bind target_project_id to this exact project (never upstream fork!)
        resolved_target_project_id: int | str | None = target_project_id
        if resolved_target_project_id is None:
            proj_resp = await self._send_request(
                "GET",
                self._build_api_url(ctx.base_url, f"/projects/{encoded_proj}"),
                headers=base_headers,
            )
            self._raise_for_gitlab_status(proj_resp)
            proj_json = proj_resp.json()
            if isinstance(proj_json, Mapping) and proj_json.get("id") is not None:
                resolved_target_project_id = proj_json["id"]

        semver = await self._negotiate_server_semver(ctx=ctx, headers=base_headers)
        extra_headers: dict[str, str] = {}
        if semver is not None and semver >= (17, 4):
            extra_headers["Idempotency-Key"] = (
                idempotency_key.strip() if idempotency_key else new_uuid7(now=ref_now)
            )

        clean_title = title.strip()
        if not clean_title.lower().startswith("draft:"):
            clean_title = f"Draft: {clean_title}"

        mr_payload: dict[str, Any] = {
            "source_branch": head_branch.removeprefix("refs/heads/"),
            "target_branch": base_branch.removeprefix("refs/heads/"),
            "title": clean_title,
            "description": body,
        }
        if resolved_target_project_id is not None:
            mr_payload["target_project_id"] = (
                int(resolved_target_project_id)
                if str(resolved_target_project_id).isdigit()
                else resolved_target_project_id
            )

        resp = await self._send_request(
            "POST",
            self._build_api_url(
                ctx.base_url,
                f"/projects/{encoded_proj}/merge_requests",
            ),
            headers=self._default_headers(access_token=token, extra=extra_headers),
            json_body=mr_payload,
        )
        self._raise_for_gitlab_status(resp, treat_400_409_422_as_stale_sha=True)
        mr_json = resp.json()
        if not isinstance(mr_json, Mapping):
            raise ProviderError(
                code="TRANSIENT",
                detail="Malformed GitLab merge_request creation response.",
                provider="gitlab",
            )
        return ProviderDraftReviewRecord(
            external_review_id=str(mr_json.get("id") or ""),
            number=str(mr_json.get("iid") or ""),
            html_url=str(mr_json.get("web_url") or ""),
            head_branch=str(mr_json.get("source_branch") or head_branch),
            base_branch=str(mr_json.get("target_branch") or base_branch),
            head_sha=str(mr_json.get("sha") or ""),
            draft=bool(mr_json.get("draft", True)),
            state=str(mr_json.get("state") or "opened"),
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
        del now
        token = await self._resolve_token(session, ctx)
        encoded_proj = self._encode_project_ref(repo_full_name)
        clean_head = head_branch.removeprefix("refs/heads/")
        resp = await self._send_request(
            "GET",
            self._build_api_url(
                ctx.base_url,
                f"/projects/{encoded_proj}/merge_requests"
                f"?state=all&source_branch={quote(clean_head, safe='')}",
            ),
            headers=self._default_headers(access_token=token),
        )
        self._raise_for_gitlab_status(resp)
        items = resp.json()
        if not isinstance(items, list):
            return None
        for item in items:
            if not isinstance(item, Mapping):
                continue
            desc = str(item.get("description") or "")
            if marker and marker not in desc:
                continue
            return ProviderDraftReviewRecord(
                external_review_id=str(item.get("id") or ""),
                number=str(item.get("iid") or ""),
                html_url=str(item.get("web_url") or ""),
                head_branch=str(item.get("source_branch") or clean_head),
                base_branch=str(item.get("target_branch") or "main"),
                head_sha=str(item.get("sha") or ""),
                draft=bool(item.get("draft", False)),
                state=str(item.get("state") or "opened"),
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
        del now
        token = await self._resolve_token(session, ctx)
        encoded_proj = self._encode_project_ref(repo_full_name)
        resp = await self._send_request(
            "GET",
            self._build_api_url(
                ctx.base_url,
                f"/projects/{encoded_proj}/repository/commits/{quote(head_sha, safe='')}/statuses",
            ),
            headers=self._default_headers(access_token=token),
        )
        self._raise_for_gitlab_status(resp)
        items = resp.json()
        if not isinstance(items, list):
            return ()

        checks: list[ProviderRemoteCheckRecord] = []
        for item in items:
            if not isinstance(item, Mapping):
                continue
            raw_status = str(item.get("status") or "unknown")
            norm_status, conclusion = _map_gitlab_job_status(raw_status)
            checks.append(
                ProviderRemoteCheckRecord(
                    external_check_id=str(item.get("id") or ""),
                    name=str(item.get("name") or "default")[:120],
                    head_sha=str(item.get("sha") or head_sha),
                    status=norm_status,
                    conclusion=conclusion,
                    required=not bool(item.get("allow_failure", False)),
                )
            )
        return tuple(checks)

    async def verify_webhook(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        headers: Mapping[str, str],
        raw_body: bytes,
        now: datetime | None = None,
    ) -> bool:
        """Verify GitLab webhook strictly under the connection's pinned `auth_mode` (`SEC-027`).

        Never falls back from `gitlab_signed_v19` to legacy `X-Gitlab-Token`, and emits
        redacted structured security telemetry on every rejected payload (`SEC-003`).
        """
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        lowered = {k.strip().lower(): v for k, v in headers.items()}
        has_v19_sig = "webhook-signature" in lowered
        has_legacy_hdr = "x-gitlab-token" in lowered

        if not ctx.webhook_secret_ref:
            _LOGGER.warning(
                "Rejected GitLab webhook: no webhook secret configured",
                extra={
                    "event": "security.gitlab_webhook.rejected",
                    "error_code": "webhook_secret_unconfigured",
                    "reason_code": "webhook_secret_unconfigured",
                    "attributes": {
                        "workspace_id": ctx.workspace_id,
                        "connection_id": ctx.connection_id,
                        "pinned_auth_mode": ctx.auth_mode,
                        "reason_code": "webhook_secret_unconfigured",
                    },
                },
            )
            return False

        verified = await self._vault.verify_gitlab_webhook_auth(
            session,
            workspace_id=ctx.workspace_id,
            secret_ref=ctx.webhook_secret_ref,
            pinned_auth_mode=ctx.auth_mode,
            headers=headers,
            raw_body=raw_body,
            now=ref_now,
        )
        if not verified:
            reason_code = (
                "downgrade_to_legacy_token_blocked"
                if ctx.auth_mode in {"gitlab_signed_v19", "signed_webhook"}
                and has_legacy_hdr
                and not has_v19_sig
                else "invalid_or_expired_webhook_auth"
            )
            _LOGGER.warning(
                "Rejected GitLab webhook authentication under pinned auth_mode",
                extra={
                    "event": "security.gitlab_webhook.rejected",
                    "error_code": reason_code,
                    "reason_code": reason_code,
                    "attributes": {
                        "workspace_id": ctx.workspace_id,
                        "connection_id": ctx.connection_id,
                        "pinned_auth_mode": ctx.auth_mode,
                        "has_webhook_signature_header": has_v19_sig,
                        "has_legacy_token_header": has_legacy_hdr,
                        "reason_code": reason_code,
                    },
                },
            )
        return verified

    async def sync_cursor(
        self,
        session: AsyncSession,
        ctx: ProviderConnectionContext,
        *,
        repo_full_name: str,
        since_cursor: str | None = None,
        now: datetime | None = None,
    ) -> tuple[Sequence[ProviderRunRecord], str | None]:
        del now
        token = await self._resolve_token(session, ctx)
        encoded_proj = self._encode_project_ref(repo_full_name)
        query = (
            f"?updated_after={quote(since_cursor, safe='')}"
            "&per_page=50&order_by=updated_at&sort=asc"
            if since_cursor
            else "?per_page=50&order_by=updated_at&sort=desc"
        )
        resp = await self._send_request(
            "GET",
            self._build_api_url(
                ctx.base_url,
                f"/projects/{encoded_proj}/pipelines{query}",
            ),
            headers=self._default_headers(access_token=token),
        )
        self._raise_for_gitlab_status(resp)
        items = resp.json()
        runs: list[ProviderRunRecord] = []
        newest_ts = since_cursor
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, Mapping):
                    continue
                updated_str = str(item.get("updated_at") or item.get("created_at") or "")
                if updated_str and (newest_ts is None or updated_str > newest_ts):
                    newest_ts = updated_str
                raw_status = str(item.get("status") or "unknown")
                norm_status, conclusion, jobs_complete = _map_gitlab_pipeline_status(raw_status)
                pipe_id = str(item.get("id") or "")
                runs.append(
                    ProviderRunRecord(
                        external_run_id=pipe_id,
                        attempt_key=f"pipeline:{pipe_id}",
                        head_sha=str(item.get("sha") or ""),
                        ref=str(item.get("ref") or "HEAD")[:120],
                        event_type=str(item.get("source") or "push")[:120],
                        status=norm_status,
                        conclusion=conclusion,
                        jobs_complete=jobs_complete,
                        raw_vendor_status=raw_status[:120],
                    )
                )
        return (tuple(runs), newest_ts)

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
    ) -> ProviderPollRunsResult:
        del now
        token = await self._resolve_token(session, ctx)
        encoded_proj = self._encode_project_ref(repo_full_name)
        bounded_page = max(1, page)
        bounded_per_page = max(1, min(per_page, 100))
        q_parts = [
            f"per_page={bounded_per_page}",
            f"page={bounded_page}",
            "order_by=updated_at",
            "sort=desc",
        ]
        if since_cursor:
            q_parts.append(f"updated_after={quote(since_cursor, safe='')}")
        query = f"?{'&'.join(q_parts)}"

        extra_hdrs: dict[str, str] = {}
        if etag and bounded_page == 1:
            extra_hdrs["If-None-Match"] = etag

        resp = await self._send_request(
            "GET",
            self._build_api_url(
                ctx.base_url,
                f"/projects/{encoded_proj}/pipelines{query}",
            ),
            headers=self._default_headers(access_token=token, extra=extra_hdrs),
        )

        rl_remaining: int | None = None
        raw_rem = resp.headers.get("ratelimit-remaining")
        if raw_rem and raw_rem.strip().isdigit():
            rl_remaining = int(raw_rem.strip())

        rl_reset: datetime | None = None
        raw_reset = resp.headers.get("ratelimit-reset")
        if raw_reset and raw_reset.strip().isdigit():
            rl_reset = datetime.fromtimestamp(int(raw_reset.strip()), tz=UTC)

        resp_etag = resp.headers.get("etag")
        clean_etag = resp_etag.strip()[:500] if resp_etag and resp_etag.strip() else None

        if resp.status_code == 304:
            return ProviderPollRunsResult(
                items=(),
                not_modified=True,
                etag=clean_etag or etag,
                rate_limit_remaining=rl_remaining,
                rate_limit_reset_at=rl_reset,
            )

        if resp.status_code == 410:
            return ProviderPollRunsResult(
                items=(),
                retention_expired=True,
                etag=clean_etag,
                rate_limit_remaining=rl_remaining,
                rate_limit_reset_at=rl_reset,
            )

        self._raise_for_gitlab_status(resp)
        raw_items = resp.json()
        items: list[ProviderPollItem] = []
        oldest_dt: datetime | None = None
        newest_dt: datetime | None = None
        if isinstance(raw_items, list):
            for item in raw_items:
                if not isinstance(item, Mapping):
                    continue
                obs_dt = _parse_iso_dt(item.get("updated_at")) or _parse_iso_dt(
                    item.get("created_at")
                )
                if obs_dt is not None:
                    if oldest_dt is None or obs_dt < oldest_dt:
                        oldest_dt = obs_dt
                    if newest_dt is None or obs_dt > newest_dt:
                        newest_dt = obs_dt

                raw_status = str(item.get("status") or "unknown")
                norm_status, conclusion, jobs_complete = _map_gitlab_pipeline_status(raw_status)
                pipe_id = str(item.get("id") or "")
                proj_id = (
                    str(item.get("project_id")) if item.get("project_id") is not None else None
                )
                items.append(
                    ProviderPollItem(
                        run=ProviderRunRecord(
                            external_run_id=pipe_id,
                            attempt_key=f"pipeline:{pipe_id}",
                            head_sha=str(item.get("sha") or ""),
                            ref=str(item.get("ref") or "HEAD")[:120],
                            event_type=str(item.get("source") or "push")[:120],
                            status=norm_status,
                            conclusion=conclusion,
                            jobs_complete=jobs_complete,
                            raw_vendor_status=raw_status[:120],
                            head_repo_id=proj_id,
                            base_repo_id=proj_id,
                            head_repo_fork=False,
                        ),
                        observed_at=obs_dt,
                    )
                )

        next_page_hdr = (resp.headers.get("x-next-page") or "").strip()
        has_next = next_page_hdr.isdigit() or (
            isinstance(raw_items, list) and len(raw_items) >= bounded_per_page
        )
        next_page = (
            int(next_page_hdr)
            if next_page_hdr.isdigit()
            else ((bounded_page + 1) if has_next else None)
        )
        return ProviderPollRunsResult(
            items=tuple(items),
            not_modified=False,
            etag=clean_etag,
            rate_limit_remaining=rl_remaining,
            rate_limit_reset_at=rl_reset,
            has_next_page=has_next,
            next_page=next_page,
            oldest_observed_at=oldest_dt,
            newest_observed_at=newest_dt,
        )

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
