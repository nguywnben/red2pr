"""PostgreSQL 16 + Hermetic GitLab REST `v4` integration & security suite (`U10`).

Verifies against a real disposable PostgreSQL 16 server (`pgserver` /
`RED2PR_TEST_ADMIN_DATABASE_URL`), `SecretBrokerProviderVault` (`Z2`), `EgressPolicyEngine`
+ `DbEndpointAllowlistProvider` (`ADR-037`), and hermetic ASGI mock GitLab REST `v4` servers:
- `T-SRC-02-P` (`SRC-02`, `A-06`, `S-08`, `SEC-018`, `SEC-031`, `SEC-033`, `ADR-037`):
  - GitLab.com (`https://gitlab.com`, `gitlab_signed_v19`, `whsec_...`) write-only token &
    signing-key sealing in `Z2`, capability negotiation (`/version` `19.1.2-ee` +
    `/personal_access_tokens/self`), paginated `x-next-page` discovery in `Monitor` mode,
    `.gitlab-ci.yml` production MR `deploy_trigger` hazard flagging (`auto_repair_blocked=True`),
    and concrete `SetupStepRegistry` `provider_connect` probe for `provider="gitlab"`.
  - Self-Managed GitLab (`https://gitlab.internal.acme.corp:8443` resolving to private IP
    `10.20.30.40`): blocked `403 egress_private_ip_unregistered` before registration, then
    authorized after Instance Owner 5-minute step-up + `POST /api/v1/setup/endpoints`
    (`adapter="gitlab"`, exact host/port/CIDR/`ca_ref`).
  - Unified `SourceProviderAdapter` + GitLab pipeline/bridge/job normalization
    (`attempt_key="pipeline:7701"`, `include_retried=true` `retry_of_id` lineage, matrix
    dimensions, zero synthetic `run_attempt` integer), cross-origin `/trace` redirect stripping
    `PRIVATE-TOKEN` (`SEC-033`), and `Draft: ` MR creation with explicit `target_project_id`
    (no deprecated `wip`, `Idempotency-Key` sent on `>= 17.4` and omitted on `< 17.4`).
- `T-SRC-02-N`, `SEC-003`, `SEC-018`, `SEC-027`, `SEC-032`:
  - Pinned `gitlab_signed_v19` never falls back to `X-Gitlab-Token` (even when `X-Gitlab-Token`
    matches!), rejects `>300s` replay skew, logs redacted `security.gitlab_webhook.rejected`,
    supports dual-key signing overlap on rotation, rejects `PATCH` `auth_mode` downgrade
    (`422 auth_mode_immutable` + `audit_log` `deny`), and marks `< 19.0` servers `unsupported`.
  - `read_api`-only PAT capability honesty (`draft_review_create="unavailable"`,
    `webhook_admin="unavailable"`, `polling_fallback="available"`).
  - Metadata/loopback/cleartext SSRF denials, cross-workspace `404`, `viewer` RBAC + `RepoGrant`
    filtering, and mid-pagination `502` preserving existing catalog (`partial_sync=True`).
- `SEC-011` & `W-02`:
  - Upstream `401` token revocation suspends `queued`/`leased` `task_jobs`, emits
    `integration.disconnected`, and upon token rotation + resync resets upgraded projects to
    `mode="monitor"` (`grant_review_required=True`) with intact `verify_audit_chain`.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import sys
import tempfile
from collections.abc import AsyncIterator, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse, urlunparse

import httpx
import pgserver
import pytest
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from py_contracts.crypto import KeyRing, MasterKeyRing, sign_gitlab_webhook_v19
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import (
    ExternalCheckpointStore,
    verify_audit_chain,
)
from red2pr_control.api.app import create_app
from red2pr_control.core.egress import EgressPolicyEngine, InMemoryCaBundleResolver
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.base import (
    AuditLogModel,
    CapabilitySnapshotModel,
    IdempotencyRecordModel,
    MembershipModel,
    OutboxEventModel,
    ProviderConnectionModel,
    RepoGrantModel,
    RepositoryModel,
    TaskJobModel,
)
from red2pr_control.db.engine import (
    create_app_engine,
    create_session_factory,
    ensure_compatible_event_loop,
    run_alembic_downgrade,
    run_alembic_upgrade,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.sessions import IamService
from red2pr_control.integrations import (
    GitHubAppAdapter,
    GitLabAdapter,
    ProviderConnectionContext,
    ProviderError,
    ProviderIntegrationService,
)
from red2pr_control.operations.setup_wizard import (
    DbEndpointAllowlistProvider,
    SetupStepRegistry,
    SetupWizardService,
)
from red2pr_control.orchestrator import DurableTaskQueueService, OperationReceiptService
from red2pr_control.secrets.broker import (
    SecretBroker,
    SecretBrokerProviderVault,
    SecretBrokerTotpVault,
)

APP_ROLE_NAME = "red2pr_app"
APP_ROLE_PASSWORD = "red2pr_app_local_test_pw_10"
PUBLIC_BASE_URL = "http://127.0.0.1:4280"
ORIGIN_HEADERS = {"Origin": PUBLIC_BASE_URL}
OWNER_CREDENTIAL = "OwnerSup3rStr0ng!Pass#30"
MEMBER_CREDENTIAL = "MemberSup3rStr0ng!Pass#30"
REPO_ROOT = Path(__file__).resolve().parents[4]
GL_FIXTURES_DIR = REPO_ROOT / "contracts" / "fixtures" / "gitlab"


class ManualClock:
    """Deterministic controllable UTC clock for webhook replay windows, step-up & audit."""

    def __init__(self, initial: datetime | None = None) -> None:
        self._current = (initial or datetime(2026, 10, 27, 15, 0, 0, tzinfo=UTC)).astimezone(UTC)

    def __call__(self) -> datetime:
        return self._current

    def advance(self, **delta_kwargs: float) -> datetime:
        self._current = self._current + timedelta(**delta_kwargs)
        return self._current


@dataclass(frozen=True)
class PgTestUrls:
    admin_url: str
    app_url: str


def _build_role_url(base_uri: str, *, username: str, password: str) -> str:
    parsed = urlparse(base_uri)
    host = parsed.hostname or "127.0.0.1"
    port_part = f":{parsed.port}" if parsed.port else ""
    netloc = f"{username}:{password}@{host}{port_part}"
    return urlunparse(
        (
            "postgresql+psycopg",
            netloc,
            parsed.path or "/postgres",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def _csrf_headers(
    token: str,
    *,
    idem_key: str | None = None,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    headers: dict[str, str] = {"X-CSRF-Token": token, **ORIGIN_HEADERS}
    if idem_key is not None:
        headers["Idempotency-Key"] = idem_key
    if extra:
        headers.update(extra)
    return headers


@dataclass
class MockGitLabState:
    """Mutable state & request telemetry for the hermetic GitLab REST `v4` mock server."""

    valid_tokens: set[str] = field(default_factory=set)
    server_mode: str = "19_1_ee"  # "19_1_ee" | "16_11_ce"
    pat_mode: str = "full_api"  # "full_api" | "read_api_only"
    revoked: bool = False
    fail_page_2_with_502: bool = False
    branch_tip_sha: str = "a" * 40
    trace_redirect_private_tokens: list[str | None] = field(default_factory=list)
    trace_redirect_auth_headers: list[str | None] = field(default_factory=list)
    seen_mr_requests: list[tuple[dict[str, str], dict[str, Any]]] = field(default_factory=list)


def _build_mock_gitlab_app(state: MockGitLabState) -> FastAPI:
    gl = FastAPI()
    ver_19 = json.loads((GL_FIXTURES_DIR / "version_19_1_ee.json").read_text(encoding="utf-8"))
    ver_16 = json.loads((GL_FIXTURES_DIR / "version_16_11_ce.json").read_text(encoding="utf-8"))
    pat_full = json.loads((GL_FIXTURES_DIR / "pat_self_full_api.json").read_text(encoding="utf-8"))
    pat_ro = json.loads(
        (GL_FIXTURES_DIR / "pat_self_read_api_only.json").read_text(encoding="utf-8")
    )
    proj_p1 = json.loads((GL_FIXTURES_DIR / "projects_page1.json").read_text(encoding="utf-8"))
    proj_p2 = json.loads((GL_FIXTURES_DIR / "projects_page2.json").read_text(encoding="utf-8"))
    pipe_7701 = json.loads(
        (GL_FIXTURES_DIR / "pipeline_7701_and_bridges.json").read_text(encoding="utf-8")
    )
    jobs_7701 = json.loads(
        (GL_FIXTURES_DIR / "pipeline_7701_jobs_with_retries.json").read_text(encoding="utf-8")
    )
    ci_safe = (GL_FIXTURES_DIR / "gitlab_ci_safe.yml").read_text(encoding="utf-8")
    ci_hazard = (GL_FIXTURES_DIR / "gitlab_ci_hazardous_deploy.yml").read_text(encoding="utf-8")

    def _verify_private_token(request: Request) -> Response | None:
        tok = request.headers.get("PRIVATE-TOKEN")
        if state.revoked or not tok or tok not in state.valid_tokens:
            return JSONResponse({"message": "401 Unauthorized"}, status_code=401)
        return None

    @gl.get("/api/v4/version")
    async def get_version(request: Request) -> Response:
        err = _verify_private_token(request)
        if err is not None:
            return err
        return JSONResponse(ver_19 if state.server_mode == "19_1_ee" else ver_16)

    @gl.get("/api/v4/personal_access_tokens/self")
    async def get_pat_self(request: Request) -> Response:
        err = _verify_private_token(request)
        if err is not None:
            return err
        return JSONResponse(pat_full if state.pat_mode == "full_api" else pat_ro)

    @gl.get("/api/v4/projects")
    async def list_projects(request: Request, page: int = 1) -> Response:
        err = _verify_private_token(request)
        if err is not None:
            return err
        if page == 1:
            return JSONResponse(proj_p1, headers={"x-next-page": "2"})
        if page == 2:
            if state.fail_page_2_with_502:
                return JSONResponse({"message": "502 Bad Gateway"}, status_code=502)
            return JSONResponse(proj_p2, headers={"x-next-page": ""})
        return JSONResponse([])

    @gl.get("/trace-object/910005")
    async def signed_object_storage_trace(request: Request) -> Response:
        state.trace_redirect_private_tokens.append(request.headers.get("PRIVATE-TOKEN"))
        state.trace_redirect_auth_headers.append(request.headers.get("Authorization"))
        return PlainTextResponse("E   AssertionError: expected billing total 100 == 99\n")

    @gl.api_route(
        "/api/v4/projects/{rest_of_path:path}",
        methods=["GET", "POST"],
    )
    async def project_subroutes(rest_of_path: str, request: Request) -> Response:
        err = _verify_private_token(request)
        if err is not None:
            return err

        # Split encoded project identifier from sub-resource suffix
        # Since GitLabAdapter URL-encodes `repo_full_name` (`acme-group%2Fbilling-engine`),
        # Starlette may decode `%2F` into `/` inside `{rest_of_path:path}` — match suffixes cleanly!
        raw_path = request.scope.get("raw_path", b"").decode("latin1")
        prefix = "/api/v4/projects/"
        after_projects = raw_path[len(prefix) :] if raw_path.startswith(prefix) else rest_of_path
        if "/" in after_projects:
            enc_proj, sub = after_projects.split("/", 1)
        else:
            enc_proj, sub = after_projects, ""
        proj_ref = unquote(enc_proj)
        method = request.method.upper()

        if sub == "" and method == "GET":
            for item in [*proj_p1, *proj_p2]:
                if item["path_with_namespace"] == proj_ref or str(item["id"]) == proj_ref:
                    return JSONResponse(item)
            return JSONResponse({"message": "404 Project Not Found"}, status_code=404)

        if sub.startswith("repository/files/") and sub.endswith("/raw") and method == "GET":
            file_enc = sub[len("repository/files/") : -len("/raw")]
            file_path = unquote(file_enc)
            if file_path == ".gitlab-ci.yml":
                if "deploy-infra" in proj_ref or proj_ref == "440102":
                    return PlainTextResponse(ci_hazard)
                return PlainTextResponse(ci_safe)
            return JSONResponse({"message": "404 File Not Found"}, status_code=404)

        if sub == "pipelines/7701" and method == "GET":
            return JSONResponse(pipe_7701["pipeline"])

        if sub == "pipelines/7701/bridges" and method == "GET":
            return JSONResponse(pipe_7701["bridges"])

        if sub == "pipelines/7701/jobs" and method == "GET":
            assert request.query_params.get("include_retried") == "true"
            return JSONResponse(jobs_7701)

        if sub == "pipelines" and method == "GET":
            return JSONResponse([pipe_7701["pipeline"]])

        if sub == "jobs/910005/trace" and method == "GET":
            return RedirectResponse(
                url="https://artifacts-cdn.gitlab-static.net/trace-object/910005?X-Amz-Signature=sig1",
                status_code=302,
            )

        if sub == "repository/compare" and method == "GET":
            return JSONResponse(
                {
                    "diffs": [
                        {
                            "old_path": "billing/calc.py",
                            "new_path": "billing/calc.py",
                            "diff": "@@ -10,1 +10,1 @@\n-return 99\n+return 100\n",
                        }
                    ]
                }
            )

        if sub == "repository/branches" and method == "POST":
            body = await request.json()
            return JSONResponse(
                {
                    "name": body["branch"],
                    "commit": {"id": body["ref"]},
                },
                status_code=201,
            )

        if sub.startswith("repository/branches/") and method == "GET":
            branch_name = unquote(sub[len("repository/branches/") :])
            return JSONResponse(
                {
                    "name": branch_name,
                    "commit": {"id": state.branch_tip_sha},
                }
            )

        if sub == "repository/commits" and method == "POST":
            body = await request.json()
            assert body.get("force") is False
            new_sha = "b" * 40
            state.branch_tip_sha = new_sha
            return JSONResponse({"id": new_sha, "title": body["commit_message"]}, status_code=201)

        if sub.startswith("repository/commits/") and sub.endswith("/statuses") and method == "GET":
            return JSONResponse(
                [
                    {
                        "id": 33001,
                        "name": "pytest: [py312, postgres16]",
                        "sha": state.branch_tip_sha,
                        "status": "success",
                        "allow_failure": False,
                    }
                ]
            )

        if sub == "merge_requests" and method == "POST":
            body = await request.json()
            hdrs = {k.lower(): v for k, v in request.headers.items()}
            state.seen_mr_requests.append((hdrs, dict(body)))
            return JSONResponse(
                {
                    "id": 880101,
                    "iid": 42,
                    "project_id": body.get("target_project_id", 440101),
                    "title": body["title"],
                    "description": body.get("description", ""),
                    "state": "opened",
                    "draft": str(body["title"]).startswith("Draft:"),
                    "source_branch": body["source_branch"],
                    "target_branch": body["target_branch"],
                    "sha": state.branch_tip_sha,
                    "web_url": "https://gitlab.com/acme-group/platform/billing-engine/-/merge_requests/42",
                },
                status_code=201,
            )

        if sub == "merge_requests" and method == "GET":
            src = request.query_params.get("source_branch", "")
            return JSONResponse(
                [
                    {
                        "id": 880101,
                        "iid": 42,
                        "title": "Draft: Fix billing rounding",
                        "description": "Automated repair\n<!-- red2pr:repair-marker-u10 -->",
                        "state": "opened",
                        "draft": True,
                        "source_branch": src,
                        "target_branch": "main",
                        "sha": state.branch_tip_sha,
                        "web_url": "https://gitlab.com/acme-group/platform/billing-engine/-/merge_requests/42",
                    }
                ]
            )

        return JSONResponse({"message": f"Unhandled mock route: {method} {sub}"}, status_code=404)

    return gl


class _HybridGitLabDnsResolver:
    """Deterministic DNS resolver for public GitLab hosts and internal RFC1918 corp host."""

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        _ = port
        normalized = host.strip().lower()
        if normalized in {"gitlab.com", "artifacts-cdn.gitlab-static.net", "api.github.com"}:
            return ("172.65.251.78",)
        if normalized == "gitlab.internal.acme.corp":
            return ("10.20.30.40",)
        return (normalized,)


@pytest.fixture(scope="module")
def pg_urls() -> Iterator[PgTestUrls]:
    """Provide a real disposable PostgreSQL 16 server (`pgserver` / env override)."""
    ensure_compatible_event_loop()
    external_admin = os.environ.get("RED2PR_TEST_ADMIN_DATABASE_URL")
    if external_admin:
        app_url = os.environ.get("RED2PR_TEST_APP_DATABASE_URL") or _build_role_url(
            external_admin,
            username=APP_ROLE_NAME,
            password=APP_ROLE_PASSWORD,
        )
        yield PgTestUrls(admin_url=external_admin, app_url=app_url)
        return

    with (
        tempfile.TemporaryDirectory(prefix="red2pr_u10_pg_") as tmp_dir,
        pgserver.get_server(tmp_dir, cleanup_mode="delete") as server,
    ):
        raw_uri = server.get_uri()
        parsed = urlparse(raw_uri)
        admin_url = urlunparse(
            (
                "postgresql+psycopg",
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
        app_url = _build_role_url(
            raw_uri,
            username=APP_ROLE_NAME,
            password=APP_ROLE_PASSWORD,
        )
        yield PgTestUrls(admin_url=admin_url, app_url=app_url)


@pytest.fixture
async def migrated_db(pg_urls: PgTestUrls) -> AsyncIterator[PgTestUrls]:
    """Reset schema cleanly to head (`0006`) before each test."""
    run_alembic_downgrade(pg_urls.admin_url, "base", app_role_name=APP_ROLE_NAME)
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
    yield pg_urls


def _build_u10_stack(
    app_url: str,
    *,
    clock: ManualClock,
    mock_gl_app: FastAPI,
) -> tuple[
    AsyncEngine,
    IamService,
    Redactor,
    SecretBrokerProviderVault,
    GitLabAdapter,
    ProviderIntegrationService,
    DurableTaskQueueService,
    SetupStepRegistry,
    FastAPI,
]:
    app_engine = create_app_engine(app_url, pool_size=6, max_overflow=6)
    app_factory = create_session_factory(app_engine)
    redactor = Redactor()
    kek_ring = MasterKeyRing(active_version=1, keys={1: b"\x5a" * 32})
    broker = SecretBroker(key_ring=kek_ring, redactor=redactor)
    totp_vault = SecretBrokerTotpVault(broker)
    provider_vault = SecretBrokerProviderVault(broker)

    iam = IamService(
        session_factory=app_factory,
        totp_vault=totp_vault,
        iam_seed_key=b"\x6b" * 32,
        public_base_url=PUBLIC_BASE_URL,
        clock=clock,
    )
    allowlist_provider = DbEndpointAllowlistProvider(app_factory)
    ca_resolver = InMemoryCaBundleResolver(
        {"sec_corp_ca_01": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"}
    )
    egress_engine = EgressPolicyEngine(
        allowlist_provider=allowlist_provider,
        dns_resolver=_HybridGitLabDnsResolver(),
    )
    gh_adapter = GitHubAppAdapter(
        vault=provider_vault,
        egress_policy=egress_engine,
        redactor=redactor,
    )
    gl_adapter = GitLabAdapter(
        vault=provider_vault,
        egress_policy=egress_engine,
        ca_bundle_resolver=ca_resolver,
        redactor=redactor,
        transport_override=httpx.ASGITransport(app=mock_gl_app),
    )
    integration_service = ProviderIntegrationService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        vault=provider_vault,
        github_adapter=gh_adapter,
        gitlab_adapter=gl_adapter,
        redactor=redactor,
    )
    queue_service = DurableTaskQueueService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        redactor=redactor,
    )
    op_service = OperationReceiptService(session_factory=app_factory)
    step_registry = SetupStepRegistry()
    setup_service = SetupWizardService(
        iam_service=iam,
        step_registry=step_registry,
        redactor=redactor,
    )
    api_app = create_app(
        iam_service=iam,
        setup_wizard_service=setup_service,
        setup_step_registry=step_registry,
        task_queue_service=queue_service,
        operation_receipt_service=op_service,
        github_integration_service=integration_service,
    )
    return (
        app_engine,
        iam,
        redactor,
        provider_vault,
        gl_adapter,
        integration_service,
        queue_service,
        step_registry,
        api_app,
    )


async def _claim_owner_and_create_workspace(
    transport: httpx.ASGITransport,
    iam: IamService,
    *,
    slug: str = "acme",
    name: str = "Acme Core",
) -> tuple[httpx.AsyncClient, str, str, str]:
    raw_boot, _ = await iam.issue_bootstrap_token()
    client = httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL)
    pre_csrf = (await client.get("/api/v1/auth/csrf")).json()["csrf_token"]

    claim_resp = await client.post(
        "/api/v1/setup/claim",
        headers=_csrf_headers(pre_csrf),
        json={
            "bootstrap_token": raw_boot,
            "display_name": "Owner U10",
            "email": "owner.u10@red2pr.local",
            "password": OWNER_CREDENTIAL,
        },
    )
    assert claim_resp.status_code == 201, claim_resp.text
    csrf_token = claim_resp.json()["csrf_token"]
    owner_id = claim_resp.json()["user"]["id"]

    ws_resp = await client.post(
        "/api/v1/workspaces",
        headers=_csrf_headers(csrf_token),
        json={"name": name, "slug": slug},
    )
    assert ws_resp.status_code == 201, ws_resp.text
    ws_id = ws_resp.json()["id"]
    return client, csrf_token, owner_id, ws_id


async def _provision_and_login_client(
    transport: httpx.ASGITransport,
    iam: IamService,
    *,
    email: str,
    display_name: str,
) -> tuple[httpx.AsyncClient, str, str]:
    user_dto = await iam.provision_local_user(
        display_name=display_name,
        email=email,
        password=MEMBER_CREDENTIAL,
    )
    client = httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL)
    pre_csrf = (await client.get("/api/v1/auth/csrf")).json()["csrf_token"]
    login_resp = await client.post(
        "/api/v1/auth/login",
        headers=_csrf_headers(pre_csrf),
        json={"identifier": email, "password": MEMBER_CREDENTIAL},
    )
    assert login_resp.status_code == 200, login_resp.text
    return client, login_resp.json()["csrf_token"], user_dto.id


@pytest.mark.asyncio
async def test_u10_src_02_gitlab_cloud_and_self_managed_private_endpoint_adapter_flow(
    migrated_db: PgTestUrls,
) -> None:
    """Verify `T-SRC-02-P`, `ADR-037` private endpoint step-up, `SEC-031` & `SEC-033`."""
    clock = ManualClock()
    cloud_token = "glpat-u10CloudBotWriteToken99887766"
    self_managed_token = "glpat-u10CorpSelfManagedToken554433"
    whsec_key = "whsec_" + base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii")
    legacy_secret = "gl_legacy_hook_secret_16chars_minimum"

    gl_state = MockGitLabState(valid_tokens={cloud_token, self_managed_token})
    mock_gl = _build_mock_gitlab_app(gl_state)

    (
        app_engine,
        iam,
        redactor,
        _vault,
        gl_adapter,
        _svc,
        _queue,
        _registry,
        api_app,
    ) = _build_u10_stack(migrated_db.app_url, clock=clock, mock_gl_app=mock_gl)

    transport = httpx.ASGITransport(app=api_app)
    try:
        owner_client, csrf, _owner_id, ws_id = await _claim_owner_and_create_workspace(
            transport, iam
        )
        try:
            # 1. Create GitLab Cloud connection (`gitlab_signed_v19`) with write-only credentials
            idem_create = new_uuid7(now=clock())
            create_payload = {
                "provider": "gitlab",
                "base_url": "https://gitlab.com",
                "auth_mode": "gitlab_signed_v19",
                "display_name": "Acme GitLab Cloud",
                "access_token": cloud_token,
                "webhook_secret": whsec_key,
            }
            create_resp = await owner_client.post(
                "/api/v1/workspaces/acme/integrations",
                headers=_csrf_headers(csrf, idem_key=idem_create),
                json=create_payload,
            )
            assert create_resp.status_code == 201, create_resp.text
            assert create_resp.headers.get("ETag") == '"v1"'
            conn_body = create_resp.json()
            cloud_conn_id = conn_body["id"]

            assert conn_body["provider"] == "gitlab"
            assert conn_body["auth_mode"] == "gitlab_signed_v19"
            assert conn_body["secret_presence"]["configured"] is True
            assert conn_body["webhook_secret_presence"]["configured"] is True
            assert cloud_token not in create_resp.text
            assert whsec_key not in create_resp.text
            assert "sec_" not in create_resp.text
            # Canary registration verified immediately
            assert cloud_token not in redactor.redact_text(f"token={cloud_token}")
            assert whsec_key not in redactor.redact_text(f"whsec={whsec_key}")

            # Exact idempotent replay on identical Idempotency-Key
            replay_resp = await owner_client.post(
                "/api/v1/workspaces/acme/integrations",
                headers=_csrf_headers(csrf, idem_key=idem_create),
                json=create_payload,
            )
            assert replay_resp.status_code == 201
            assert replay_resp.json()["id"] == cloud_conn_id

            # 2. Capability probe negotiates GitLab 19.1.2-ee + full bot token scopes
            probe_resp = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{cloud_conn_id}/probes",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert probe_resp.status_code == 200, probe_resp.text
            pr_json = probe_resp.json()
            assert pr_json["connection"]["status"] == "ready"
            assert pr_json["connection"]["vendor_version"] == "19.1.2-ee"
            assert pr_json["connection"]["api_version"] == "v4"
            assert pr_json["connection"]["account_login"] == "red2pr-bot-project-token"
            caps = pr_json["connection"]["capabilities"]
            assert caps["repo_discovery"] == "available"
            assert caps["ci_read"] == "available"
            assert caps["log_download"] == "available"
            assert caps["draft_review_create"] == "available"
            assert caps["branch_write"] == "available"
            assert caps["webhook_hmac"] == "available"
            assert caps["webhook_admin"] == "available"
            assert caps["idempotency_key_v17_4"] == "available"

            # 3. Paginated project discovery (`x-next-page` 1..2) + `.gitlab-ci.yml` hazard scan
            sync_resp = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{cloud_conn_id}/sync",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert sync_resp.status_code == 200, sync_resp.text
            sync_json = sync_resp.json()
            assert sync_json["discovered_count"] == 3
            assert sync_json["flagged_hazard_count"] == 1
            assert sync_json["partial_sync"] is False

            by_name = {r["name"]: r for r in sync_json["repositories"]}
            billing_proj = by_name["acme-group/platform/billing-engine"]
            deploy_proj = by_name["acme-group/platform/deploy-infra"]
            sdk_proj = by_name["acme-group/platform/sdk-docs"]
            assert billing_proj["mode"] == "monitor"
            assert billing_proj["workflow_hazard_status"] == "clean"
            assert deploy_proj["mode"] == "monitor"
            assert deploy_proj["workflow_hazard_status"] == "flagged"
            assert deploy_proj["workflow_hazards"][0]["code"] == "deploy_trigger"
            assert sdk_proj["mode"] == "monitor"
            assert sdk_proj["is_fork"] is True

            # Verify DB auto_repair_blocked=True on hazard-flagged GitLab project (`SEC-031`)
            async with workspace_rls_session(iam.session_factory, workspace_id=ws_id) as db:
                dep_row = await db.scalar(
                    select(RepositoryModel).where(RepositoryModel.id == deploy_proj["id"])
                )
                assert dep_row is not None and dep_row.auto_repair_blocked is True
                snap_rows = (
                    await db.scalars(
                        select(CapabilitySnapshotModel).where(
                            CapabilitySnapshotModel.connection_id == cloud_conn_id
                        )
                    )
                ).all()
                assert len(snap_rows) == 1

            # 4. Verify SetupStepRegistry `provider_connect` concrete probe for `provider="gitlab"`
            setup_state = (await owner_client.get("/api/v1/setup")).json()
            ckpt = setup_state["checkpoint"]
            for phase_name, step_fields in (
                (
                    "topology_tls",
                    {
                        "action": "save",
                        "deployment_mode": "local",
                        "public_base_url": PUBLIC_BASE_URL,
                        "tls_mode": "loopback_http",
                    },
                ),
                (
                    "storage_keys",
                    {
                        "action": "save",
                        "storage_backend": "local",
                        "backup_retention_days": 45,
                        "master_key_custody_confirmed": True,
                    },
                ),
                (
                    "workspace_admin",
                    {
                        "action": "save",
                        "workspace_slug": "acme",
                        "workspace_name": "Acme Core",
                    },
                ),
                (
                    "provider_connect",
                    {
                        "action": "save",
                        "provider": "gitlab",
                        "provider_base_url": "https://gitlab.com",
                        "auth_mode": "gitlab_signed_v19",
                        "secret_ref": "sec_gitlab_cloud_01",
                    },
                ),
                ("model_consent", {"action": "skip"}),
                ("worker_readiness", {"action": "skip"}),
                (
                    "repo_policy",
                    {
                        "action": "save",
                        "default_repo_mode": "monitor",
                        "require_baseline": True,
                        "auto_merge": False,
                    },
                ),
            ):
                step_resp = await owner_client.post(
                    f"/api/v1/setup/steps/{phase_name}",
                    headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                    json={"expected_checkpoint": ckpt, **step_fields},
                )
                assert step_resp.status_code == 200, step_resp.text
                setup_state = step_resp.json()
                ckpt = setup_state["checkpoint"]

            assert setup_state["ready_monitor"] is True
            prov_step = next(s for s in setup_state["steps"] if s["phase"] == "provider_connect")
            assert prov_step["status"] == "completed"
            assert prov_step["probe_status"] == "passed"

            # 5. Self-Managed GitLab (`https://gitlab.internal.acme.corp:8443` -> `10.20.30.40`)
            gl_state.server_mode = "16_11_ce"
            sm_create = await owner_client.post(
                "/api/v1/workspaces/acme/integrations",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                json={
                    "provider": "gitlab",
                    "base_url": "https://gitlab.internal.acme.corp:8443",
                    "auth_mode": "gitlab_legacy_token",
                    "display_name": "Acme Corp Self-Managed GitLab",
                    "access_token": self_managed_token,
                    "webhook_secret": legacy_secret,
                },
            )
            assert sm_create.status_code == 201, sm_create.text
            sm_conn_id = sm_create.json()["id"]

            # Before Owner private endpoint registration -> blocked 403 (`SEC-018`, `ADR-037`)
            sm_probe_blocked = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{sm_conn_id}/probes",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert sm_probe_blocked.status_code == 403, sm_probe_blocked.text
            assert sm_probe_blocked.json()["code"] == "egress_private_ip_denied"

            # Perform Instance Owner 5-minute step-up + register private endpoint
            clock.advance(minutes=6)
            step_up_resp = await owner_client.post(
                "/api/v1/auth/step-up",
                headers=_csrf_headers(csrf),
                json={"password": OWNER_CREDENTIAL},
            )
            assert step_up_resp.status_code == 200, step_up_resp.text
            csrf = step_up_resp.json()["csrf_token"]

            ep_resp = await owner_client.post(
                "/api/v1/setup/endpoints",
                headers=_csrf_headers(csrf),
                json={
                    "adapter": "gitlab",
                    "scheme": "https",
                    "host": "gitlab.internal.acme.corp",
                    "port": 8443,
                    "cidrs": ["10.20.30.0/24"],
                    "ca_ref": "sec_corp_ca_01",
                    "description": "Acme Corp internal Self-Managed GitLab",
                },
            )
            assert ep_resp.status_code == 201, ep_resp.text

            # Now `probeConnection` succeeds against Self-Managed 16.11.5-ce!
            sm_probe_ok = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{sm_conn_id}/probes",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert sm_probe_ok.status_code == 200, sm_probe_ok.text
            sm_conn_json = sm_probe_ok.json()["connection"]
            assert sm_conn_json["status"] == "ready"
            assert sm_conn_json["vendor_version"] == "16.11.5"
            assert sm_conn_json["capabilities"]["idempotency_key_v17_4"] == "unavailable"
            assert sm_conn_json["capabilities"]["webhook_hmac"] == "unavailable"

            # 6. Unified SourceProviderAdapter methods + GitLab pipeline/bridge/job/MR semantics
            async with workspace_rls_session(iam.session_factory, workspace_id=ws_id) as db:
                cloud_row = await db.scalar(
                    select(ProviderConnectionModel).where(
                        ProviderConnectionModel.id == cloud_conn_id
                    )
                )
                sm_row = await db.scalar(
                    select(ProviderConnectionModel).where(ProviderConnectionModel.id == sm_conn_id)
                )
                assert cloud_row is not None and sm_row is not None

                assert cloud_row.auth_mode == "gitlab_signed_v19"
                assert sm_row.auth_mode == "gitlab_legacy_token"
                cloud_ctx = ProviderConnectionContext(
                    workspace_id=ws_id,
                    connection_id=cloud_conn_id,
                    provider="gitlab",
                    base_url=cloud_row.base_url,
                    app_id=None,
                    client_id=None,
                    installation_id=None,
                    auth_mode="gitlab_signed_v19",
                    vendor_version=cloud_row.vendor_version,
                    credential_secret_ref=cloud_row.credential_secret_ref,
                    webhook_secret_ref=cloud_row.webhook_secret_ref,
                )
                sm_ctx = ProviderConnectionContext(
                    workspace_id=ws_id,
                    connection_id=sm_conn_id,
                    provider="gitlab",
                    base_url=sm_row.base_url,
                    app_id=None,
                    client_id=None,
                    installation_id=None,
                    auth_mode="gitlab_legacy_token",
                    vendor_version=sm_row.vendor_version,
                    credential_secret_ref=sm_row.credential_secret_ref,
                    webhook_secret_ref=sm_row.webhook_secret_ref,
                )

                run_rec = await gl_adapter.get_run(
                    db,
                    cloud_ctx,
                    repo_full_name="acme-group/platform/billing-engine",
                    external_run_id="7701",
                    now=clock(),
                )
                assert run_rec.external_run_id == "7701"
                assert run_rec.attempt_key == "pipeline:7701"
                assert run_rec.conclusion == "failure"
                assert run_rec.jobs_complete is True

                bridges = await gl_adapter.list_child_pipelines(
                    db,
                    cloud_ctx,
                    repo_full_name="acme-group/platform/billing-engine",
                    external_run_id="7701",
                )
                assert len(bridges) == 1
                assert bridges[0].downstream_pipeline_id == "7702"
                assert bridges[0].downstream_status == "failed"

                jobs = await gl_adapter.list_jobs(
                    db,
                    cloud_ctx,
                    repo_full_name="acme-group/platform/billing-engine",
                    external_run_id="7701",
                    now=clock(),
                )
                assert [j.external_job_id for j in jobs] == ["910001", "910002", "910005"]
                j_initial, j_lint, j_retry = jobs
                assert j_initial.retry_of_id is None
                assert j_lint.retry_of_id is None
                # Retry lineage preserved without inventing synthetic GitHub run_attempt integers!
                assert j_retry.retry_of_id == "910001"
                assert j_retry.matrix_dimensions == {
                    "stage": "test",
                    "matrix_0": "py312",
                    "matrix_1": "postgres16",
                }

                # SEC-033: Cross-origin object-storage 302 redirect strips PRIVATE-TOKEN!
                trace_bytes = await gl_adapter.get_job_log(
                    db,
                    cloud_ctx,
                    repo_full_name="acme-group/platform/billing-engine",
                    external_job_id="910005",
                    now=clock(),
                )
                assert b"AssertionError: expected billing total" in trace_bytes
                assert gl_state.trace_redirect_private_tokens == [None]
                assert gl_state.trace_redirect_auth_headers == [None]

                artifacts = await gl_adapter.get_artifact_metadata(
                    db,
                    cloud_ctx,
                    repo_full_name="acme-group/platform/billing-engine",
                    external_run_id="7701",
                    now=clock(),
                )
                assert len(artifacts) == 1
                assert artifacts[0].external_artifact_id == "910005:archive"
                assert artifacts[0].name == "junit-artifacts.zip"

                diff_text = await gl_adapter.get_commit_diff(
                    db,
                    cloud_ctx,
                    repo_full_name="acme-group/platform/billing-engine",
                    base_sha="1" * 40,
                    head_sha="a" * 40,
                    now=clock(),
                )
                assert "+return 100" in diff_text

                ci_yaml = await gl_adapter.resolve_workflow_config(
                    db,
                    cloud_ctx,
                    repo_full_name="acme-group/platform/billing-engine",
                    workflow_path=".gitlab-ci.yml",
                    ref="main",
                    now=clock(),
                )
                assert "stages:" in ci_yaml
                with pytest.raises(ProviderError) as path_exc:
                    await gl_adapter.resolve_workflow_config(
                        db,
                        cloud_ctx,
                        repo_full_name="acme-group/platform/billing-engine",
                        workflow_path="../etc/passwd",
                        ref="main",
                    )
                assert path_exc.value.code == "UNSUPPORTED"

                ref_created = await gl_adapter.create_branch(
                    db,
                    cloud_ctx,
                    repo_full_name="acme-group/platform/billing-engine",
                    branch_name="red2pr/fix-7701",
                    from_sha="a" * 40,
                )
                assert ref_created == "refs/heads/red2pr/fix-7701"

                # Stale parent SHA rejected with STALE_SHA before force-less commit push
                with pytest.raises(ProviderError) as stale_exc:
                    await gl_adapter.push_commit(
                        db,
                        cloud_ctx,
                        repo_full_name="acme-group/platform/billing-engine",
                        branch_name="red2pr/fix-7701",
                        expected_parent_sha="f" * 40,
                        commit_message="fix: rounding",
                        file_changes={"billing/calc.py": "return 100\n"},
                    )
                assert stale_exc.value.code == "STALE_SHA"

                pushed_sha = await gl_adapter.push_commit(
                    db,
                    cloud_ctx,
                    repo_full_name="acme-group/platform/billing-engine",
                    branch_name="red2pr/fix-7701",
                    expected_parent_sha="a" * 40,
                    commit_message="fix: rounding",
                    file_changes={"billing/calc.py": "return 100\n"},
                )
                assert pushed_sha == "b" * 40

                # Draft MR on GitLab 19.1.2-ee (>= 17.4): sends Idempotency-Key, Draft: prefix,
                # explicit target_project_id=440101, and zero deprecated `wip` fields!
                mr_cloud = await gl_adapter.create_draft_review(
                    db,
                    cloud_ctx,
                    repo_full_name="acme-group/platform/billing-engine",
                    head_branch="red2pr/fix-7701",
                    base_branch="main",
                    title="Fix billing rounding",
                    body="Automated repair\n<!-- red2pr:repair-marker-u10 -->",
                    idempotency_key="idem-mr-cloud-19",
                    now=clock(),
                )
                assert mr_cloud.number == "42"
                assert mr_cloud.draft is True
                cloud_mr_hdrs, cloud_mr_body = gl_state.seen_mr_requests[-1]
                assert cloud_mr_hdrs.get("idempotency-key") == "idem-mr-cloud-19"
                assert cloud_mr_body["title"] == "Draft: Fix billing rounding"
                assert cloud_mr_body["target_project_id"] == 440101
                assert "wip" not in cloud_mr_body

                # Draft MR on Self-Managed GitLab 16.11.5 (< 17.4): omits Idempotency-Key cleanly!
                await gl_adapter.create_draft_review(
                    db,
                    sm_ctx,
                    repo_full_name="acme-group/platform/billing-engine",
                    head_branch="red2pr/fix-7701",
                    base_branch="main",
                    title="Draft: Legacy server MR",
                    body="Automated repair",
                    idempotency_key="idem-mr-sm-16",
                    now=clock(),
                )
                sm_mr_hdrs, sm_mr_body = gl_state.seen_mr_requests[-1]
                assert "idempotency-key" not in sm_mr_hdrs
                assert sm_mr_body["target_project_id"] == 440101

                found_mr = await gl_adapter.find_review_by_marker(
                    db,
                    cloud_ctx,
                    repo_full_name="acme-group/platform/billing-engine",
                    head_branch="red2pr/fix-7701",
                    marker="<!-- red2pr:repair-marker-u10 -->",
                )
                assert found_mr is not None and found_mr.number == "42"

                checks = await gl_adapter.get_remote_checks(
                    db,
                    cloud_ctx,
                    repo_full_name="acme-group/platform/billing-engine",
                    head_sha=pushed_sha,
                )
                assert len(checks) == 1 and checks[0].conclusion == "success"

                polled_runs, next_cursor = await gl_adapter.sync_cursor(
                    db,
                    cloud_ctx,
                    repo_full_name="acme-group/platform/billing-engine",
                    since_cursor="2026-10-27T05:00:00Z",
                )
                assert len(polled_runs) == 1 and polled_runs[0].attempt_key == "pipeline:7701"
                assert next_cursor == "2026-10-27T05:58:00.000Z"

                # Zero plaintext secrets in audit_log, outbox_events, or idempotency_records
                for secret_val in (cloud_token, self_managed_token, whsec_key, legacy_secret):
                    for audit_row in (await db.scalars(select(AuditLogModel))).all():
                        assert secret_val not in json.dumps(audit_row.metadata_json)
                    for outbox_row in (await db.scalars(select(OutboxEventModel))).all():
                        assert secret_val not in json.dumps(outbox_row.payload)
                    for idem_row in (await db.scalars(select(IdempotencyRecordModel))).all():
                        assert secret_val not in json.dumps(idem_row.response_payload)
        finally:
            await owner_client.aclose()
    finally:
        await app_engine.dispose()


@pytest.mark.asyncio
async def test_u10_src_02_negative_pinned_auth_nondowngrade_scope_honesty_ssrf_and_partial_sync(
    migrated_db: PgTestUrls,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify `T-SRC-02-N`, `SEC-003`, `SEC-018`, `SEC-027`, `SEC-032` & mid-pagination `502`."""
    clock = ManualClock()
    bot_token = "glpat-u10NegSuiteBotToken11223344"
    whsec_key_1 = "whsec_" + base64.b64encode(b"key_one_0123456789abcdef01234567").decode("ascii")
    whsec_key_2 = "whsec_" + base64.b64encode(b"key_two_fedcba9876543210fedcba98").decode("ascii")
    whsec_unknown = "whsec_" + base64.b64encode(b"unknown_aaaaaaaaaaaaaaaaaaaaaaaa").decode("ascii")

    gl_state = MockGitLabState(valid_tokens={bot_token})
    mock_gl = _build_mock_gitlab_app(gl_state)

    (
        app_engine,
        iam,
        _redactor,
        _vault,
        gl_adapter,
        _svc,
        _queue,
        _registry,
        api_app,
    ) = _build_u10_stack(migrated_db.app_url, clock=clock, mock_gl_app=mock_gl)

    transport = httpx.ASGITransport(app=api_app)
    try:
        owner_client, csrf, owner_id, ws_id = await _claim_owner_and_create_workspace(
            transport, iam
        )
        viewer_client, viewer_csrf, viewer_id = await _provision_and_login_client(
            transport,
            iam,
            email="viewer.u10@red2pr.local",
            display_name="Viewer U10",
        )
        outsider_client, _outsider_csrf, _outsider_id = await _provision_and_login_client(
            transport,
            iam,
            email="outsider.u10@red2pr.local",
            display_name="Outsider U10",
        )

        viewer_mem_id = new_uuid7(now=clock())
        async with workspace_rls_session(iam.session_factory, workspace_id=ws_id) as db:
            db.add(
                MembershipModel(
                    id=viewer_mem_id,
                    workspace_id=ws_id,
                    user_id=viewer_id,
                    role="viewer",
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )

        try:
            # 1. Create `gitlab_signed_v19` connection
            conn_resp = await owner_client.post(
                "/api/v1/workspaces/acme/integrations",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                json={
                    "provider": "gitlab",
                    "base_url": "https://gitlab.com",
                    "auth_mode": "gitlab_signed_v19",
                    "display_name": "Acme Signed v19 GL",
                    "access_token": bot_token,
                    "webhook_secret": whsec_key_1,
                },
            )
            assert conn_resp.status_code == 201
            conn_id = conn_resp.json()["id"]

            # 2. Attempt PATCH downgrade `gitlab_signed_v19` -> `gitlab_legacy_token` (`SEC-027`)
            downgrade_resp = await owner_client.patch(
                f"/api/v1/workspaces/acme/integrations/{conn_id}",
                headers=_csrf_headers(
                    csrf,
                    idem_key=new_uuid7(now=clock()),
                    extra={"If-Match": '"v1"'},
                ),
                json={
                    "expected_version": 1,
                    "auth_mode": "gitlab_legacy_token",
                },
            )
            assert downgrade_resp.status_code == 422
            assert downgrade_resp.json()["code"] == "auth_mode_immutable"

            async with workspace_rls_session(iam.session_factory, workspace_id=ws_id) as db:
                deny_audit = await db.scalar(
                    select(AuditLogModel).where(
                        AuditLogModel.workspace_id == ws_id,
                        AuditLogModel.action == "integration.connection_auth_mode_change",
                        AuditLogModel.decision == "deny",
                    )
                )
                assert deny_audit is not None
                assert deny_audit.reason_code == "auth_mode_downgrade_forbidden"

            # 3. Verify `SEC-003` & `SEC-027` webhook verification + rotation overlap
            wh_body = b'{"object_kind":"pipeline","object_attributes":{"id":7701}}'
            now_unix = int(clock().timestamp())
            valid_sig_1 = sign_gitlab_webhook_v19(
                secret=whsec_key_1,
                webhook_id="msg_u10_001",
                timestamp_unix=now_unix,
                raw_body=wh_body,
            )

            gl_logger = logging.getLogger("red2pr_control.integrations.gitlab")
            gl_logger.addHandler(caplog.handler)
            caplog.set_level(logging.WARNING, logger="red2pr_control.integrations.gitlab")
            try:
                async with workspace_rls_session(iam.session_factory, workspace_id=ws_id) as db:
                    c_row = await db.scalar(
                        select(ProviderConnectionModel).where(ProviderConnectionModel.id == conn_id)
                    )
                    assert c_row is not None and c_row.auth_mode == "gitlab_signed_v19"
                    ctx = ProviderConnectionContext(
                        workspace_id=ws_id,
                        connection_id=conn_id,
                        provider="gitlab",
                        base_url=c_row.base_url,
                        app_id=None,
                        client_id=None,
                        installation_id=None,
                        auth_mode="gitlab_signed_v19",
                        credential_secret_ref=c_row.credential_secret_ref,
                        webhook_secret_ref=c_row.webhook_secret_ref,
                    )

                    # Valid Standard Webhooks v19 HMAC succeeds
                    assert (
                        await gl_adapter.verify_webhook(
                            db,
                            ctx,
                            headers={
                                "webhook-id": "msg_u10_001",
                                "webhook-timestamp": str(now_unix),
                                "webhook-signature": valid_sig_1,
                            },
                            raw_body=wh_body,
                            now=clock(),
                        )
                        is True
                    )

                    # SEC-027: Legacy `X-Gitlab-Token` WITHOUT `webhook-signature` on
                    # `gitlab_signed_v19` MUST be rejected and logged!
                    caplog.clear()
                    assert (
                        await gl_adapter.verify_webhook(
                            db,
                            ctx,
                            headers={"X-Gitlab-Token": whsec_key_1},
                            raw_body=wh_body,
                            now=clock(),
                        )
                        is False
                    )
                    assert any(
                        getattr(rec, "reason_code", None) == "downgrade_to_legacy_token_blocked"
                        for rec in caplog.records
                    )
                    for rec in caplog.records:
                        assert whsec_key_1 not in rec.getMessage()

                    # Replay timestamp >300s old -> rejected
                    stale_ts_int = now_unix - 360
                    stale_ts = str(stale_ts_int)
                    stale_sig = sign_gitlab_webhook_v19(
                        secret=whsec_key_1,
                        webhook_id="msg_u10_stale",
                        timestamp_unix=stale_ts_int,
                        raw_body=wh_body,
                    )
                    assert (
                        await gl_adapter.verify_webhook(
                            db,
                            ctx,
                            headers={
                                "webhook-id": "msg_u10_stale",
                                "webhook-timestamp": stale_ts,
                                "webhook-signature": stale_sig,
                            },
                            raw_body=wh_body,
                            now=clock(),
                        )
                        is False
                    )
            finally:
                gl_logger.removeHandler(caplog.handler)

            # Rotate webhook signing key (`whsec_key_1` -> `whsec_key_2`) -> overlap accepts BOTH!
            rot_resp = await owner_client.patch(
                f"/api/v1/workspaces/acme/integrations/{conn_id}",
                headers=_csrf_headers(
                    csrf,
                    idem_key=new_uuid7(now=clock()),
                    extra={"If-Match": '"v1"'},
                ),
                json={
                    "expected_version": 1,
                    "webhook_secret": whsec_key_2,
                },
            )
            assert rot_resp.status_code == 200, rot_resp.text
            assert rot_resp.json()["webhook_secret_presence"]["secret_version"] == 2

            valid_sig_2 = sign_gitlab_webhook_v19(
                secret=whsec_key_2,
                webhook_id="msg_u10_002",
                timestamp_unix=now_unix,
                raw_body=wh_body,
            )
            unknown_sig = sign_gitlab_webhook_v19(
                secret=whsec_unknown,
                webhook_id="msg_u10_003",
                timestamp_unix=now_unix,
                raw_body=wh_body,
            )
            async with workspace_rls_session(iam.session_factory, workspace_id=ws_id) as db:
                c_row = await db.scalar(
                    select(ProviderConnectionModel).where(ProviderConnectionModel.id == conn_id)
                )
                assert c_row is not None and c_row.auth_mode == "gitlab_signed_v19"
                ctx_rot = ProviderConnectionContext(
                    workspace_id=ws_id,
                    connection_id=conn_id,
                    provider="gitlab",
                    base_url=c_row.base_url,
                    app_id=None,
                    client_id=None,
                    installation_id=None,
                    auth_mode="gitlab_signed_v19",
                    credential_secret_ref=c_row.credential_secret_ref,
                    webhook_secret_ref=c_row.webhook_secret_ref,
                )
                assert (
                    await gl_adapter.verify_webhook(
                        db,
                        ctx_rot,
                        headers={
                            "webhook-id": "msg_u10_002",
                            "webhook-timestamp": str(now_unix),
                            "webhook-signature": valid_sig_2,
                        },
                        raw_body=wh_body,
                        now=clock(),
                    )
                    is True
                )
                assert (
                    await gl_adapter.verify_webhook(
                        db,
                        ctx_rot,
                        headers={
                            "webhook-id": "msg_u10_001",
                            "webhook-timestamp": str(now_unix),
                            "webhook-signature": valid_sig_1,
                        },
                        raw_body=wh_body,
                        now=clock(),
                    )
                    is True
                )
                assert (
                    await gl_adapter.verify_webhook(
                        db,
                        ctx_rot,
                        headers={
                            "webhook-id": "msg_u10_003",
                            "webhook-timestamp": str(now_unix),
                            "webhook-signature": unknown_sig,
                        },
                        raw_body=wh_body,
                        now=clock(),
                    )
                    is False
                )

            # 4. Probing `gitlab_signed_v19` on GitLab < 19.0 (`16.11.5`) -> `unsupported`
            gl_state.server_mode = "16_11_ce"
            gl_state.pat_mode = "read_api_only"
            unsup_probe = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/probes",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert unsup_probe.status_code == 200
            unsup_conn = unsup_probe.json()["connection"]
            assert unsup_conn["status"] == "unsupported"
            assert unsup_conn["auth_mode"] == "gitlab_signed_v19"
            # Verify `read_api`-only scope honesty simultaneously!
            assert unsup_conn["capabilities"]["repo_discovery"] == "available"
            assert unsup_conn["capabilities"]["ci_read"] == "available"
            assert unsup_conn["capabilities"]["log_download"] == "available"
            assert unsup_conn["capabilities"]["draft_review_create"] == "unavailable"
            assert unsup_conn["capabilities"]["branch_write"] == "unavailable"
            assert unsup_conn["capabilities"]["webhook_admin"] == "unavailable"
            assert unsup_conn["capabilities"]["polling_fallback"] == "available"
            assert "gitlab_v19_webhook_signing" in unsup_conn["missing_permissions"]
            assert "api" in unsup_conn["missing_permissions"]

            # Sync is blocked (`422`) while status == 'unsupported'
            unsup_sync = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/sync",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert unsup_sync.status_code == 422
            assert unsup_sync.json()["code"] == "provider_unsupported"

            # Restore server to 19.1.2-ee: Monitor-ready (`read_api_only`),
            # sync 3 projects, then test mid-pagination 502 preserving page-2 projects!
            gl_state.server_mode = "19_1_ee"
            ro_probe_conn = (
                await owner_client.post(
                    f"/api/v1/workspaces/acme/integrations/{conn_id}/probes",
                    headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                )
            ).json()["connection"]
            assert ro_probe_conn["status"] == "ready"
            assert ro_probe_conn["capabilities"]["draft_review_create"] == "unavailable"

            full_sync = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/sync",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert full_sync.status_code == 200
            assert full_sync.json()["discovered_count"] == 3

            # Mid-pagination `502` on page 2 preserves page-2 project (`sdk-docs`)!
            gl_state.fail_page_2_with_502 = True
            partial_sync = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/sync",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert partial_sync.status_code == 200
            assert partial_sync.json()["partial_sync"] is True
            assert len(partial_sync.json()["repositories"]) == 3

            # 5. RBAC & Cross-Workspace Isolation (`SEC-032`)
            assert (
                await outsider_client.get(f"/api/v1/workspaces/acme/integrations/{conn_id}")
            ).status_code == 404
            assert (
                await viewer_client.post(
                    f"/api/v1/workspaces/acme/integrations/{conn_id}/sync",
                    headers=_csrf_headers(viewer_csrf, idem_key=new_uuid7(now=clock())),
                )
            ).status_code == 403

            # Viewer sees 0 projects until explicitly granted via RepoGrantModel
            viewer_detail_0 = await viewer_client.get(
                f"/api/v1/workspaces/acme/integrations/{conn_id}"
            )
            assert viewer_detail_0.status_code == 200
            assert viewer_detail_0.json()["repositories"] == []

            billing_id = next(
                r["id"]
                for r in full_sync.json()["repositories"]
                if r["name"] == "acme-group/platform/billing-engine"
            )
            async with workspace_rls_session(iam.session_factory, workspace_id=ws_id) as db:
                db.add(
                    RepoGrantModel(
                        id=new_uuid7(now=clock()),
                        workspace_id=ws_id,
                        membership_id=viewer_mem_id,
                        repository_id=billing_id,
                        granted_by_user_id=owner_id,
                        created_at=clock(),
                    )
                )
            viewer_detail_1 = await viewer_client.get(
                f"/api/v1/workspaces/acme/integrations/{conn_id}"
            )
            assert [r["name"] for r in viewer_detail_1.json()["repositories"]] == [
                "acme-group/platform/billing-engine"
            ]

            # 6. SSRF & Cleartext Denials (`SEC-018`, `ADR-037`)
            for forbidden_url in (
                "https://169.254.169.254",
                "https://127.0.0.1:8443",
            ):
                ssrf_conn = await owner_client.post(
                    "/api/v1/workspaces/acme/integrations",
                    headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                    json={
                        "provider": "gitlab",
                        "base_url": forbidden_url,
                        "auth_mode": "gitlab_legacy_token",
                        "access_token": bot_token,
                    },
                )
                assert ssrf_conn.status_code == 403
                assert ssrf_conn.json()["code"] == "egress_forbidden_ip"

            cleartext_conn = await owner_client.post(
                "/api/v1/workspaces/acme/integrations",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                json={
                    "provider": "gitlab",
                    "base_url": "http://gitlab.com",
                    "auth_mode": "gitlab_legacy_token",
                    "access_token": bot_token,
                },
            )
            assert cleartext_conn.status_code == 201
            cleartext_probe = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{cleartext_conn.json()['id']}/probes",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert cleartext_probe.status_code == 403
            assert cleartext_probe.json()["code"].startswith("egress_")
        finally:
            await owner_client.aclose()
            await viewer_client.aclose()
            await outsider_client.aclose()
    finally:
        await app_engine.dispose()


@pytest.mark.asyncio
async def test_u10_sec_011_revocation_cascade_w02_reconnect_monitor_reset_and_audit_chain(
    migrated_db: PgTestUrls,
) -> None:
    """Verify `SEC-011` revocation cascade, `W-02` reconnect reset & `verify_audit_chain`."""
    clock = ManualClock()
    token_v1 = "glpat-u10RevocableTokenV1_000111222"
    token_v2 = "glpat-u10RotatedFreshTokenV2_333444"
    whsec = "whsec_" + base64.b64encode(b"revocation_test_key_0123456789ab").decode("ascii")

    gl_state = MockGitLabState(valid_tokens={token_v1, token_v2})
    mock_gl = _build_mock_gitlab_app(gl_state)

    (
        app_engine,
        iam,
        _redactor,
        _vault,
        _gl_adapter,
        _svc,
        queue_service,
        _registry,
        api_app,
    ) = _build_u10_stack(migrated_db.app_url, clock=clock, mock_gl_app=mock_gl)

    transport = httpx.ASGITransport(app=api_app)
    try:
        owner_client, csrf, _owner_id, ws_id = await _claim_owner_and_create_workspace(
            transport, iam
        )
        try:
            conn_resp = await owner_client.post(
                "/api/v1/workspaces/acme/integrations",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                json={
                    "provider": "gitlab",
                    "base_url": "https://gitlab.com",
                    "auth_mode": "gitlab_signed_v19",
                    "display_name": "Acme Revocable GL",
                    "access_token": token_v1,
                    "webhook_secret": whsec,
                },
            )
            assert conn_resp.status_code == 201
            conn_id = conn_resp.json()["id"]

            assert (
                await owner_client.post(
                    f"/api/v1/workspaces/acme/integrations/{conn_id}/probes",
                    headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                )
            ).status_code == 200

            sync_initial = (
                await owner_client.post(
                    f"/api/v1/workspaces/acme/integrations/{conn_id}/sync",
                    headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                )
            ).json()
            billing_repo_id = next(
                r["id"]
                for r in sync_initial["repositories"]
                if r["name"] == "acme-group/platform/billing-engine"
            )

            # Promote `billing-engine` to `auto_repair` before revocation (`W-02`)
            async with workspace_rls_session(iam.session_factory, workspace_id=ws_id) as db:
                r_row = await db.scalar(
                    select(RepositoryModel).where(RepositoryModel.id == billing_repo_id)
                )
                assert r_row is not None
                r_row.mode = "auto_repair"

            # Enqueue 1 leased job and 1 queued job
            job_leased = await queue_service.enqueue_job(
                workspace_id=ws_id,
                repository_id=billing_repo_id,
                resource_id=billing_repo_id,
                kind="repair.execute",
                dedup_key="gl-dedup-leased-1",
                logical_effect_key="gl-eff-leased-1",
                budget_key="gl-bud-1",
                correlation_id="corr-gl-leased",
                payload={"pipeline_id": "7701"},
                now=clock(),
            )
            claimed = await queue_service.acquire_next_lease(
                worker_id=new_uuid7(now=clock()),
                now=clock(),
            )
            assert claimed is not None and claimed.job.id == job_leased.id

            job_queued = await queue_service.enqueue_job(
                workspace_id=ws_id,
                repository_id=billing_repo_id,
                resource_id=billing_repo_id,
                kind="triage.ingest",
                dedup_key="gl-dedup-queued-2",
                logical_effect_key="gl-eff-queued-2",
                budget_key="gl-bud-2",
                correlation_id="corr-gl-queued",
                payload={"pipeline_id": "7702"},
                now=clock(),
            )

            # Upstream GitLab revokes `token_v1` -> `401 Unauthorized` on sync (`SEC-011`)
            gl_state.valid_tokens.discard(token_v1)
            revoked_sync = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/sync",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert revoked_sync.status_code == 403
            assert revoked_sync.json()["code"] == "provider_connection_revoked"

            async with workspace_rls_session(iam.session_factory, workspace_id=ws_id) as db:
                c_row = await db.scalar(
                    select(ProviderConnectionModel).where(ProviderConnectionModel.id == conn_id)
                )
                assert c_row is not None
                assert c_row.status == "revoked"
                assert c_row.grant_review_required is True

                jq = await db.scalar(select(TaskJobModel).where(TaskJobModel.id == job_queued.id))
                jl = await db.scalar(select(TaskJobModel).where(TaskJobModel.id == job_leased.id))
                assert jq is not None and jq.state == "cancelled"
                assert jq.cancel_reason == "provider_connection_revoked"
                assert jl is not None and jl.state == "cancel_requested"

                disc_ev = await db.scalar(
                    select(OutboxEventModel).where(
                        OutboxEventModel.workspace_id == ws_id,
                        OutboxEventModel.event_type == "integration.disconnected",
                    )
                )
                assert disc_ev is not None

            # Rotate fresh `token_v2` via PATCH (`W-02` reconnect recovery)
            detail_revoked = await owner_client.get(
                f"/api/v1/workspaces/acme/integrations/{conn_id}"
            )
            etag_revoked = detail_revoked.headers["ETag"]
            ver_revoked = detail_revoked.json()["connection"]["version"]

            rot_ok = await owner_client.patch(
                f"/api/v1/workspaces/acme/integrations/{conn_id}",
                headers=_csrf_headers(
                    csrf,
                    idem_key=new_uuid7(now=clock()),
                    extra={"If-Match": etag_revoked},
                ),
                json={
                    "expected_version": ver_revoked,
                    "access_token": token_v2,
                },
            )
            assert rot_ok.status_code == 200, rot_ok.text
            assert rot_ok.json()["status"] == "not_configured"
            assert rot_ok.json()["grant_review_required"] is True

            assert (
                await owner_client.post(
                    f"/api/v1/workspaces/acme/integrations/{conn_id}/probes",
                    headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                )
            ).json()["connection"]["status"] == "ready"

            resync_resp = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/sync",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert resync_resp.status_code == 200, resync_resp.text
            resync_body = resync_resp.json()
            assert resync_body["connection"]["grant_review_required"] is True
            # W-02: `billing-engine` MUST be forced back to `monitor` (never `auto_repair`)!
            resync_billing = next(
                r
                for r in resync_body["repositories"]
                if r["name"] == "acme-group/platform/billing-engine"
            )
            assert resync_billing["mode"] == "monitor"

            # Explicit disconnect & revoke (`DELETE`) revokes Z2 secrets
            del_resp = await owner_client.delete(
                f"/api/v1/workspaces/acme/integrations/{conn_id}",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert del_resp.status_code == 200
            assert del_resp.json()["state"] == "succeeded"
            after_del = (
                await owner_client.get(f"/api/v1/workspaces/acme/integrations/{conn_id}")
            ).json()["connection"]
            assert after_del["status"] == "revoked"
            assert after_del["secret_presence"]["configured"] is False
            assert after_del["webhook_secret_presence"]["configured"] is False

            # Verify hash-chained audit log integrity across all U10 operations
            with tempfile.TemporaryDirectory(prefix="red2pr_u10_ckpt_") as ckpt_dir:
                ckpt_store = ExternalCheckpointStore(Path(ckpt_dir) / "audit_ckpt.json")
                async with instance_rls_session(iam.session_factory, mode="audit_verifier") as db:
                    entries_checked = await verify_audit_chain(
                        db,
                        external_store=ckpt_store,
                        keyring=KeyRing(),
                    )
                    assert entries_checked >= 12
        finally:
            await owner_client.aclose()
    finally:
        await app_engine.dispose()
