"""PostgreSQL 16 + Hermetic GitHub REST `2026-03-10` integration & security suite (`U09`).

Verifies against a real disposable PostgreSQL 16 server (`pgserver` /
`RED2PR_TEST_ADMIN_DATABASE_URL`), `SecretBrokerProviderVault` (`Z2`), `EgressPolicyEngine`
(`ADR-037`), and a hermetic ASGI mock GitHub REST `2026-03-10` server:
- Migration `0006_provider_connections_repos` reversibility (`upgrade -> downgrade -> upgrade`),
  fail-closed `FORCE ROW LEVEL SECURITY` across all `32` tenant/instance tables, cross-workspace
  tenant isolation (`SEC-032`), `ck_repositories_hazard_blocks_auto_repair` check constraint
  (`SEC-031`), and `trg_repo_grants_forbid_cross_workspace_repo` trigger enforcement.
- `T-SRC-01-P` & `SEC-001`:
  - GitHub App connection creation sealing write-only RSA PEM & webhook secret in `Z2`
    `SecretBroker`, registering canaries in `Redactor`, returning `SecretPresence` metadata
    only (zero raw secrets or internal `sec_*` refs in responses/audit/outbox/idempotency).
  - Cryptographically verified RS256 App JWT (`<=10m` lifetime) vs encrypted cached JIT
    repository-scoped installation tokens (reused before expiry, refreshed `<60s` before
    expiry, never requesting excess `workflows`/`administration` scopes) and pinned
    `X-GitHub-Api-Version: 2026-03-10`.
  - Two-step `A-23` single-use `10m` state nonce minting, read-only `GET` callback validation,
    and CSRF-protected `POST .../installations/confirm` paginated repository discovery +
    `.github/workflows` hazard scan (`workflows_safe_ci.yml` vs
    `workflows_hazardous_pr_target.yml`).
  - Concrete `SetupStepRegistry` `provider_connect` probe advancing Setup Wizard Phase 5 to
    `completed` / `ready_monitor=True`.
  - Unified `SourceProviderAdapter` read & webhook HMAC methods (`get_run`, `list_jobs`,
    `get_job_log` stripping `Authorization` on cross-origin signed archive redirect per
    `SEC-033`, `get_artifact_metadata`, `get_commit_diff`, `resolve_workflow_config`,
    `verify_webhook`, and `WorkflowHazardScanner.classify_pull_request_head` blocking untrusted
    fork PR heads per `SEC-031`).
- `T-SRC-01-N`, `SEC-010`, `SEC-032` & `ADR-037`:
  - Forged `installation_id` callback without `state`, unrecognized `state`, wrong user session,
    mismatched `Origin`, expired `state` (`>10m` -> `410`), and replayed `state` (`409`).
  - `ADR-037` SSRF (`http://169.254.169.254`, `https://127.0.0.1`, cleartext `http://`) blocked
    before transport dispatch.
  - Cross-workspace `404` anti-enumeration, `viewer` `403` on mutations + `RepoGrantModel`
    filtering on `getConnection`, `409`/`412` optimistic version guards, and mid-pagination
    transient `502` on page 2 preserving previously discovered repositories (`partial_sync=True`).
- `SEC-011` & `W-02`:
  - Upstream installation/token revocation (`401` / suspended `403`) transitions connection to
    `revoked`, purges cached JIT installation tokens, cancels `queued` `task_jobs` and marks
    `leased`/`running` `task_jobs` `cancel_requested`, emits `integration.disconnected` outbox
    event, blocks subsequent syncs (`403`), and upon reconnecting forces `mode='monitor'` +
    `grant_review_required=True` with intact `verify_audit_chain`.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
from collections.abc import AsyncIterator, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx
import pgserver
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from py_contracts.crypto import KeyRing, MasterKeyRing, verify_rs256_jwt
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import (
    ExternalCheckpointStore,
    verify_audit_chain,
)
from red2pr_control.api.app import create_app
from red2pr_control.core.egress import EgressPolicyEngine
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.base import (
    AuditLogModel,
    CapabilitySnapshotModel,
    IdempotencyRecordModel,
    MembershipModel,
    OutboxEventModel,
    ProviderConnectionModel,
    ProviderInstallStateModel,
    RepoGrantModel,
    RepositoryModel,
    SchemaMigrationRecordModel,
    TaskJobModel,
    WorkspaceModel,
)
from red2pr_control.db.engine import (
    create_admin_engine,
    create_app_engine,
    create_session_factory,
    ensure_compatible_event_loop,
    run_alembic_downgrade,
    run_alembic_upgrade,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.sessions import IamService
from red2pr_control.integrations import (
    GITHUB_API_VERSION,
    GitHubAppAdapter,
    GitHubIntegrationService,
    ProviderConnectionContext,
    WorkflowHazardScanner,
)
from red2pr_control.operations.setup_wizard import (
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
APP_ROLE_PASSWORD = "red2pr_app_local_test_pw_09"
PUBLIC_BASE_URL = "http://127.0.0.1:4280"
ORIGIN_HEADERS = {"Origin": PUBLIC_BASE_URL}
OWNER_CREDENTIAL = "OwnerSup3rStr0ng!Pass#29"
MEMBER_CREDENTIAL = "MemberSup3rStr0ng!Pass#29"
REPO_ROOT = Path(__file__).resolve().parents[4]
FIXTURES_DIR = REPO_ROOT / "contracts" / "fixtures" / "github"


class ManualClock:
    """Deterministic controllable UTC clock for JWT/JIT TTL, callback `10m` state & idempotency."""

    def __init__(self, initial: datetime | None = None) -> None:
        self._current = (initial or datetime(2026, 10, 27, 14, 0, 0, tzinfo=UTC)).astimezone(UTC)

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


def _generate_rsa_keypair() -> tuple[str, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return pem, private_key.public_key()


@dataclass
class MockGitHubState:
    """Mutable state & telemetry counters for the hermetic GitHub REST `2026-03-10` server."""

    public_key: rsa.RSAPublicKey
    clock: ManualClock
    app_id: str = "340122"
    installation_id: str = "99001"
    revoked: bool = False
    suspended: bool = False
    fail_page_2_with_502: bool = False
    missing_required_perms: bool = False
    access_token_mint_count: int = 0
    seen_api_versions: list[str] = field(default_factory=list)
    seen_token_requests: list[dict[str, Any]] = field(default_factory=list)
    archive_redirect_auth_headers: list[str | None] = field(default_factory=list)
    issued_tokens: set[str] = field(default_factory=set)


def _build_mock_github_app(state: MockGitHubState) -> FastAPI:
    gh = FastAPI()
    app_meta = json.loads((FIXTURES_DIR / "app_metadata.json").read_text(encoding="utf-8"))
    inst_meta = json.loads((FIXTURES_DIR / "installation_99001.json").read_text(encoding="utf-8"))
    repos_p1 = json.loads(
        (FIXTURES_DIR / "installation_repositories_page1.json").read_text(encoding="utf-8")
    )
    repos_p2 = json.loads(
        (FIXTURES_DIR / "installation_repositories_page2.json").read_text(encoding="utf-8")
    )
    safe_wf = (FIXTURES_DIR / "workflows_safe_ci.yml").read_bytes()
    hazard_wf = (FIXTURES_DIR / "workflows_hazardous_pr_target.yml").read_bytes()

    def _check_common(request: Request) -> None:
        ver = request.headers.get("X-GitHub-Api-Version", "")
        state.seen_api_versions.append(ver)
        assert ver == GITHUB_API_VERSION, f"Expected {GITHUB_API_VERSION}, got {ver!r}"

    def _verify_app_bearer(request: Request) -> Response | None:
        _check_common(request)
        if state.revoked:
            return JSONResponse({"message": "Bad credentials"}, status_code=401)
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"message": "Missing App JWT"}, status_code=401)
        raw_jwt = auth.removeprefix("Bearer ").strip()
        pub_pem = state.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        claims = verify_rs256_jwt(
            raw_jwt,
            public_key_pem=pub_pem,
            now=state.clock(),
        )
        assert claims.get("iss") == state.app_id
        assert int(claims["exp"]) - int(claims["iat"]) <= 600
        return None

    def _verify_installation_bearer(request: Request) -> Response | None:
        _check_common(request)
        if state.revoked:
            return JSONResponse({"message": "Bad credentials"}, status_code=401)
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"message": "Missing installation token"}, status_code=401)
        tok = auth.removeprefix("Bearer ").strip()
        if tok not in state.issued_tokens:
            return JSONResponse({"message": "Unknown or expired token"}, status_code=401)
        return None

    @gh.get("/app")
    async def get_app(request: Request) -> Response:
        err = _verify_app_bearer(request)
        if err is not None:
            return err
        payload = dict(app_meta)
        payload["id"] = int(state.app_id)
        return JSONResponse(
            payload,
            headers={"X-GitHub-Enterprise-Version": "github.com"},
        )

    @gh.get("/app/installations/{install_id}")
    async def get_installation(install_id: str, request: Request) -> Response:
        err = _verify_app_bearer(request)
        if err is not None:
            return err
        if install_id != state.installation_id:
            return JSONResponse({"message": "Not Found"}, status_code=404)
        payload = dict(inst_meta)
        payload["app_id"] = int(state.app_id)
        if state.suspended:
            payload["suspended_at"] = "2026-10-27T14:05:00Z"
        if state.missing_required_perms:
            payload["permissions"] = {"metadata": "read"}
        return JSONResponse(payload)

    @gh.post("/app/installations/{install_id}/access_tokens")
    async def create_access_token(install_id: str, request: Request) -> Response:
        err = _verify_app_bearer(request)
        if err is not None:
            return err
        if install_id != state.installation_id:
            return JSONResponse({"message": "Not Found"}, status_code=404)
        if state.suspended:
            return JSONResponse(
                {"message": "This installation has been suspended"},
                status_code=403,
            )
        body = await request.json()
        state.seen_token_requests.append(body)
        state.access_token_mint_count += 1
        tok = f"ghs_scoped_token_{state.access_token_mint_count:04d}_secretvalue123456"
        state.issued_tokens.add(tok)
        exp = (state.clock() + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        return JSONResponse(
            {
                "token": tok,
                "expires_at": exp,
                "permissions": body.get("permissions", {}),
            },
            status_code=201,
        )

    @gh.get("/installation/repositories")
    async def list_installation_repos(
        request: Request, page: int = 1, per_page: int = 50
    ) -> Response:
        _ = per_page
        err = _verify_installation_bearer(request)
        if err is not None:
            return err
        if page == 1:
            next_link = (
                '<https://api.github.com/installation/repositories?per_page=1&page=2>; rel="next"'
            )
            return JSONResponse(
                repos_p1,
                headers={"Link": next_link},
            )
        if page == 2:
            if state.fail_page_2_with_502:
                return JSONResponse({"message": "Upstream Bad Gateway"}, status_code=502)
            return JSONResponse(repos_p2)
        return JSONResponse({"total_count": 2, "repositories": []})

    @gh.get("/repos/{owner}/{repo}/contents/.github/workflows")
    async def list_workflows(owner: str, repo: str, request: Request) -> Response:
        _ = owner
        err = _verify_installation_bearer(request)
        if err is not None:
            return err
        if repo == "payments-service":
            return JSONResponse(
                [{"name": "ci.yml", "path": ".github/workflows/ci.yml", "type": "file"}]
            )
        if repo == "docs-portal":
            return JSONResponse(
                [
                    {
                        "name": "pr-target.yml",
                        "path": ".github/workflows/pr-target.yml",
                        "type": "file",
                    }
                ]
            )
        return JSONResponse({"message": "Not Found"}, status_code=404)

    @gh.get("/repos/{owner}/{repo}/contents/.github/workflows/{filename}")
    async def get_workflow_blob(
        owner: str,
        repo: str,
        filename: str,
        request: Request,
    ) -> Response:
        _ = owner
        err = _verify_installation_bearer(request)
        if err is not None:
            return err
        raw = safe_wf if (repo == "payments-service" and filename == "ci.yml") else hazard_wf
        return JSONResponse(
            {
                "name": filename,
                "path": f".github/workflows/{filename}",
                "encoding": "base64",
                "size": len(raw),
                "content": base64.b64encode(raw).decode("ascii"),
            }
        )

    @gh.get("/repos/{owner}/{repo}/actions/runs/{run_id}")
    async def get_run(owner: str, repo: str, run_id: str, request: Request) -> Response:
        _ = (owner, repo)
        err = _verify_installation_bearer(request)
        if err is not None:
            return err
        return JSONResponse(
            {
                "id": int(run_id),
                "run_attempt": 2,
                "head_sha": "a" * 40,
                "head_branch": "main",
                "event": "push",
                "status": "completed",
                "conclusion": "failure",
                "head_repository": {"id": 501001, "fork": False},
                "repository": {"id": 501001},
            }
        )

    @gh.get("/repos/{owner}/{repo}/actions/runs/{run_id}/jobs")
    async def list_jobs(owner: str, repo: str, run_id: str, request: Request) -> Response:
        _ = (owner, repo, run_id)
        err = _verify_installation_bearer(request)
        if err is not None:
            return err
        return JSONResponse(
            {
                "total_count": 1,
                "jobs": [
                    {
                        "id": 77001,
                        "name": "pytest (py312)",
                        "status": "completed",
                        "conclusion": "failure",
                        "started_at": "2026-10-27T13:55:00Z",
                        "completed_at": "2026-10-27T13:56:00Z",
                    }
                ],
            }
        )

    @gh.get("/repos/{owner}/{repo}/actions/jobs/{job_id}/logs")
    async def get_job_logs(owner: str, repo: str, job_id: str, request: Request) -> Response:
        _ = (owner, repo, job_id)
        err = _verify_installation_bearer(request)
        if err is not None:
            return err
        return RedirectResponse(
            url="https://pipelines.actions.githubusercontent.com/signed-logs/77001?sig=abc",
            status_code=302,
        )

    @gh.get("/signed-logs/77001")
    async def signed_archive_logs(request: Request) -> Response:
        state.archive_redirect_auth_headers.append(request.headers.get("Authorization"))
        return PlainTextResponse("E   AssertionError: expected 200 == 500\n")

    @gh.get("/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts")
    async def list_artifacts(owner: str, repo: str, run_id: str, request: Request) -> Response:
        _ = (owner, repo, run_id)
        err = _verify_installation_bearer(request)
        if err is not None:
            return err
        return JSONResponse(
            {
                "total_count": 1,
                "artifacts": [
                    {
                        "id": 88001,
                        "name": "junit-report",
                        "size_in_bytes": 4096,
                        "expired": False,
                        "created_at": "2026-10-27T13:56:00Z",
                        "expires_at": "2026-11-27T13:56:00Z",
                    }
                ],
            }
        )

    @gh.get("/repos/{owner}/{repo}/compare/{compare_spec}")
    async def compare_commits(
        owner: str,
        repo: str,
        compare_spec: str,
        request: Request,
    ) -> Response:
        _ = (owner, repo, compare_spec)
        err = _verify_installation_bearer(request)
        if err is not None:
            return err
        return PlainTextResponse("diff --git a/app.py b/app.py\n+return 200\n")

    return gh


class _PublicDnsResolver:
    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        _ = port
        if host in {"api.github.com", "pipelines.actions.githubusercontent.com"}:
            return ("140.82.112.6",)
        return (host,)


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
        tempfile.TemporaryDirectory(prefix="red2pr_u09_pg_") as tmp_dir,
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


def _build_u09_stack(
    app_url: str,
    *,
    clock: ManualClock,
    mock_gh_app: FastAPI,
) -> tuple[
    AsyncEngine,
    IamService,
    Redactor,
    SecretBrokerProviderVault,
    GitHubAppAdapter,
    GitHubIntegrationService,
    DurableTaskQueueService,
    SetupStepRegistry,
    FastAPI,
]:
    app_engine = create_app_engine(app_url, pool_size=6, max_overflow=6)
    app_factory = create_session_factory(app_engine)
    redactor = Redactor()
    kek_ring = MasterKeyRing(active_version=1, keys={1: b"\x39" * 32})
    broker = SecretBroker(key_ring=kek_ring, redactor=redactor)
    totp_vault = SecretBrokerTotpVault(broker)
    provider_vault = SecretBrokerProviderVault(broker)

    iam = IamService(
        session_factory=app_factory,
        totp_vault=totp_vault,
        iam_seed_key=b"\x49" * 32,
        public_base_url=PUBLIC_BASE_URL,
        clock=clock,
    )
    egress_engine = EgressPolicyEngine(dns_resolver=_PublicDnsResolver())
    gh_adapter = GitHubAppAdapter(
        vault=provider_vault,
        egress_policy=egress_engine,
        redactor=redactor,
        transport_override=httpx.ASGITransport(app=mock_gh_app),
    )
    gh_service = GitHubIntegrationService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        vault=provider_vault,
        github_adapter=gh_adapter,
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
        github_integration_service=gh_service,
    )
    return (
        app_engine,
        iam,
        redactor,
        provider_vault,
        gh_adapter,
        gh_service,
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
    csrf_resp = await client.get("/api/v1/auth/csrf")
    assert csrf_resp.status_code == 200
    pre_csrf = csrf_resp.json()["csrf_token"]

    claim_resp = await client.post(
        "/api/v1/setup/claim",
        headers=_csrf_headers(pre_csrf),
        json={
            "bootstrap_token": raw_boot,
            "display_name": "Owner U09",
            "email": "owner.u09@red2pr.local",
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
async def test_u09_migration_0006_reversibility_rls_and_hazard_check_constraints(
    migrated_db: PgTestUrls,
) -> None:
    """Verify `0006` upgrade/downgrade/upgrade, `32` RLS tables & DB check/trigger guards."""
    run_alembic_downgrade(
        migrated_db.admin_url,
        "0005_task_jobs_leases_dlq",
        app_role_name=APP_ROLE_NAME,
    )
    run_alembic_upgrade(
        migrated_db.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )

    admin_engine = create_admin_engine(migrated_db.admin_url)
    app_engine = create_app_engine(migrated_db.app_url, pool_size=2, max_overflow=2)
    try:
        admin_factory = create_session_factory(admin_engine)
        app_factory = create_session_factory(app_engine)

        async with admin_factory() as admin_db, admin_db.begin():
            rows = (
                await admin_db.execute(
                    text(
                        """
                        SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
                        FROM pg_class c
                        JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'public'
                          AND c.relkind = 'r'
                          AND c.relname <> 'alembic_version'
                        ORDER BY c.relname
                        """
                    )
                )
            ).fetchall()
            assert len(rows) >= 32
            assert {
                "provider_connections",
                "capability_snapshots",
                "repositories",
                "provider_install_states",
            }.issubset({relname for relname, _, _ in rows})
            for relname, has_rls, force_rls in rows:
                assert has_rls is True, f"{relname} missing ENABLE ROW LEVEL SECURITY"
                assert force_rls is True, f"{relname} missing FORCE ROW LEVEL SECURITY"

            mig_row = await admin_db.scalar(
                select(SchemaMigrationRecordModel).where(
                    SchemaMigrationRecordModel.revision == "0006_provider_connections_repos"
                )
            )
            assert mig_row is not None

        now = datetime(2026, 10, 27, 14, 0, 0, tzinfo=UTC)
        ws_a = new_uuid7(now=now)
        ws_b = new_uuid7(now=now)
        conn_a = new_uuid7(now=now)
        repo_a = new_uuid7(now=now)

        async with instance_rls_session(app_factory, mode="instance_admin") as db:
            db.add(
                WorkspaceModel(
                    id=ws_a,
                    name="Alpha",
                    slug="alpha",
                    status="active",
                    paused=False,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            db.add(
                WorkspaceModel(
                    id=ws_b,
                    name="Beta",
                    slug="beta",
                    status="active",
                    paused=False,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )

        async with workspace_rls_session(app_factory, workspace_id=ws_a) as db:
            db.add(
                ProviderConnectionModel(
                    id=conn_a,
                    workspace_id=ws_a,
                    provider="github",
                    display_name="Alpha GH",
                    base_url="https://api.github.com",
                    auth_mode="github_app",
                    app_id="1001",
                    status="ready",
                    capabilities_json={},
                    granted_permissions_json={},
                    missing_permissions_json=[],
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            await db.flush()
            db.add(
                RepositoryModel(
                    id=repo_a,
                    workspace_id=ws_a,
                    provider_connection_id=conn_a,
                    external_repo_id="901",
                    name="alpha/svc",
                    default_branch="main",
                    visibility="private",
                    mode="monitor",
                    paused=False,
                    active=True,
                    archived=False,
                    is_fork=False,
                    policy_revision=1,
                    tags_json=[],
                    workflow_hazard_status="flagged",
                    workflow_hazards_json=[],
                    auto_repair_blocked=True,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )

        # Fail-closed when GUC is unset + cross-workspace isolation (`SEC-032`)
        async with app_factory() as unscoped_db, unscoped_db.begin():
            assert (await unscoped_db.scalars(select(ProviderConnectionModel))).all() == []
            assert (await unscoped_db.scalars(select(RepositoryModel))).all() == []
            assert (await unscoped_db.scalars(select(CapabilitySnapshotModel))).all() == []
            assert (await unscoped_db.scalars(select(ProviderInstallStateModel))).all() == []

        async with workspace_rls_session(app_factory, workspace_id=ws_b) as db_b:
            assert (await db_b.scalars(select(ProviderConnectionModel))).all() == []
            assert (await db_b.scalars(select(RepositoryModel))).all() == []

        # SEC-031 check constraint: auto_repair_blocked=True forbids mode='auto_repair' at DB level
        with pytest.raises(DBAPIError):
            async with workspace_rls_session(app_factory, workspace_id=ws_a) as db_err:
                row = await db_err.scalar(
                    select(RepositoryModel).where(RepositoryModel.id == repo_a)
                )
                assert row is not None
                row.mode = "auto_repair"
                await db_err.flush()
    finally:
        await app_engine.dispose()
        await admin_engine.dispose()


@pytest.mark.asyncio
async def test_u09_src_01_positive_jwt_jit_token_cache_pagination_and_setup_probe(
    migrated_db: PgTestUrls,
) -> None:
    """Verify `T-SRC-01-P`, `SEC-001`, `SEC-031`, `SEC-033`, and `SetupStepRegistry` probe."""
    clock = ManualClock()
    rsa_pem, rsa_pub = _generate_rsa_keypair()
    webhook_secret = "whsec_u09_super_secret_canary_value_998877"
    gh_state = MockGitHubState(public_key=rsa_pub, clock=clock)
    mock_gh = _build_mock_github_app(gh_state)

    (
        app_engine,
        iam,
        redactor,
        _vault,
        gh_adapter,
        _gh_service,
        _queue_service,
        _registry,
        api_app,
    ) = _build_u09_stack(migrated_db.app_url, clock=clock, mock_gh_app=mock_gh)

    transport = httpx.ASGITransport(app=api_app)
    try:
        owner_client, csrf, _owner_id, ws_id = await _claim_owner_and_create_workspace(
            transport, iam
        )
        try:
            # 1. Create GitHub App connection with write-only PEM & webhook secret (`A-06`)
            idem_create = new_uuid7(now=clock())
            create_payload = {
                "provider": "github",
                "base_url": "https://api.github.com",
                "auth_mode": "github_app",
                "display_name": "Acme GitHub App",
                "app_id": "340122",
                "client_id": "Iv1.acme340122",
                "private_key_pem": rsa_pem,
                "webhook_secret": webhook_secret,
            }
            create_resp = await owner_client.post(
                "/api/v1/workspaces/acme/integrations",
                headers=_csrf_headers(csrf, idem_key=idem_create),
                json=create_payload,
            )
            assert create_resp.status_code == 201, create_resp.text
            assert create_resp.headers.get("ETag") == '"v1"'
            conn_json = create_resp.json()
            conn_id = conn_json["id"]
            assert conn_json["secret_presence"] == {"configured": True, "secret_version": 1}
            assert conn_json["webhook_secret_presence"] == {
                "configured": True,
                "secret_version": 1,
            }
            assert rsa_pem[:30] not in create_resp.text
            assert webhook_secret not in create_resp.text
            assert "sec_" not in create_resp.text
            assert redactor.redact_text(f"leak={webhook_secret}") == "leak=[REDACTED:CANARY]"

            # S-05 idempotency replay returns identical Connection without creating a duplicate row
            replay_resp = await owner_client.post(
                "/api/v1/workspaces/acme/integrations",
                headers=_csrf_headers(csrf, idem_key=idem_create),
                json=create_payload,
            )
            assert replay_resp.status_code == 201
            assert replay_resp.json()["id"] == conn_id

            # 2. Mint single-use 10-minute state (`A-23`) & validate read-only GET callback
            state_resp = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/installations/state",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                json={"expected_origin": PUBLIC_BASE_URL},
            )
            assert state_resp.status_code == 201, state_resp.text
            raw_state = state_resp.json()["state"]

            cb_resp = await owner_client.get(
                "/api/v1/integrations/github/callback",
                params={
                    "state": raw_state,
                    "installation_id": "99001",
                    "setup_action": "install",
                },
                headers=ORIGIN_HEADERS,
            )
            assert cb_resp.status_code == 200, cb_resp.text
            assert cb_resp.json()["state_valid"] is True
            assert cb_resp.json()["workspace_slug"] == "acme"

            # Verify GET callback did NOT mutate connection status
            pre_detail = await owner_client.get(f"/api/v1/workspaces/acme/integrations/{conn_id}")
            assert pre_detail.json()["connection"]["status"] == "not_configured"

            # 3. Confirm installation (`POST .../installations/confirm`) -> 2 pages + YAML scan
            confirm_resp = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/installations/confirm",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                json={"installation_id": "99001", "state": raw_state},
            )
            assert confirm_resp.status_code == 200, confirm_resp.text
            confirm_body = confirm_resp.json()
            assert confirm_body["connection"]["status"] == "ready"
            assert confirm_body["connection"]["api_version"] == GITHUB_API_VERSION
            assert confirm_body["connection"]["account_login"] == "acme-platform"
            assert confirm_body["partial_sync"] is False
            assert confirm_body["grant_review_required"] is False

            repos = {r["name"]: r for r in confirm_body["repositories"]}
            assert set(repos.keys()) == {
                "acme-platform/payments-service",
                "acme-platform/docs-portal",
                "acme-platform/oss-sdk-mirror",
            }

            payments = repos["acme-platform/payments-service"]
            assert payments["mode"] == "monitor"
            assert payments["workflow_hazard_status"] == "clean"
            assert payments["auto_repair_blocked"] is False

            docs_site = repos["acme-platform/docs-portal"]
            assert docs_site["mode"] == "monitor"
            assert docs_site["workflow_hazard_status"] == "flagged"
            assert docs_site["auto_repair_blocked"] is True
            hazard_codes = {h["code"] for h in docs_site["workflow_hazards"]}
            assert "pull_request_target" in hazard_codes
            assert "privileged_workflow_run" in hazard_codes
            assert "write_all_permissions" in hazard_codes
            assert "deploy_trigger" in hazard_codes

            oss_fork = repos["acme-platform/oss-sdk-mirror"]
            assert oss_fork["is_fork"] is True
            assert oss_fork["mode"] == "monitor"

            # Verify excess scopes (`workflows`, `administration`) were NEVER requested on JIT
            for tok_req in gh_state.seen_token_requests:
                assert "workflows" not in tok_req.get("permissions", {})
                assert "administration" not in tok_req.get("permissions", {})

            # 4. Verify encrypted JIT token cache reuse before expiry vs refresh near expiry
            mints_after_confirm = gh_state.access_token_mint_count
            clock.advance(minutes=10)
            sync_1 = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/sync",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert sync_1.status_code == 200
            # Same scopes reused cached encrypted JIT installation tokens -> 0 new mints!
            assert gh_state.access_token_mint_count == mints_after_confirm

            # Advance within 30s of 1h token expiry (<60s margin), keeping session active (<30m)
            clock.advance(minutes=25)
            assert (await owner_client.get("/api/v1/me")).status_code == 200
            clock.advance(minutes=24, seconds=35)
            sync_2 = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/sync",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert sync_2.status_code == 200
            assert gh_state.access_token_mint_count > mints_after_confirm

            # 5. Verify SetupStepRegistry `provider_connect` probe (`U07` + `U09`)
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
                        "provider": "github",
                        "provider_base_url": "https://api.github.com",
                        "auth_mode": "github_app",
                        "secret_ref": "sec_github_app_01",
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
                    json={
                        "expected_checkpoint": ckpt,
                        **step_fields,
                    },
                )
                assert step_resp.status_code == 200, step_resp.text
                setup_state = step_resp.json()
                ckpt = setup_state["checkpoint"]

            assert setup_state["ready_monitor"] is True
            prov_step = next(s for s in setup_state["steps"] if s["phase"] == "provider_connect")
            assert prov_step["status"] == "completed"
            assert prov_step["probe_status"] == "passed"

            # 6. Verify unified SourceProviderAdapter methods, SEC-033 redirect & SEC-031 fork guard
            app_factory = iam.session_factory
            async with workspace_rls_session(app_factory, workspace_id=ws_id) as db:
                conn_row = await db.scalar(
                    select(ProviderConnectionModel).where(ProviderConnectionModel.id == conn_id)
                )
                assert conn_row is not None
                prov_ctx = ProviderConnectionContext(
                    workspace_id=ws_id,
                    connection_id=conn_id,
                    provider="github",
                    base_url=conn_row.base_url,
                    app_id=conn_row.app_id,
                    client_id=conn_row.client_id,
                    installation_id=conn_row.external_installation_id,
                    credential_secret_ref=conn_row.credential_secret_ref,
                    webhook_secret_ref=conn_row.webhook_secret_ref,
                )
                run_rec = await gh_adapter.get_run(
                    db,
                    prov_ctx,
                    repo_full_name="acme-platform/payments-service",
                    external_run_id="55001",
                    now=clock(),
                )
                assert run_rec.attempt_key == "55001:2"
                assert run_rec.conclusion == "failure"

                jobs = await gh_adapter.list_jobs(
                    db,
                    prov_ctx,
                    repo_full_name="acme-platform/payments-service",
                    external_run_id="55001",
                    now=clock(),
                )
                assert len(jobs) == 1 and jobs[0].name == "pytest (py312)"

                log_bytes = await gh_adapter.get_job_log(
                    db,
                    prov_ctx,
                    repo_full_name="acme-platform/payments-service",
                    external_job_id="77001",
                    now=clock(),
                )
                assert b"AssertionError" in log_bytes
                # SEC-033: Cross-origin redirect stripped Authorization header!
                assert gh_state.archive_redirect_auth_headers == [None]

                artifacts = await gh_adapter.get_artifact_metadata(
                    db,
                    prov_ctx,
                    repo_full_name="acme-platform/payments-service",
                    external_run_id="55001",
                    now=clock(),
                )
                assert len(artifacts) == 1 and artifacts[0].name == "junit-report"

                diff_text = await gh_adapter.get_commit_diff(
                    db,
                    prov_ctx,
                    repo_full_name="acme-platform/payments-service",
                    base_sha="1" * 40,
                    head_sha="2" * 40,
                    now=clock(),
                )
                assert "+return 200" in diff_text

                wf_map = await gh_adapter.resolve_workflow_config(
                    db,
                    prov_ctx,
                    repo_full_name="acme-platform/payments-service",
                    ref="main",
                    now=clock(),
                )
                assert ".github/workflows/ci.yml" in wf_map

                wh_body = b'{"action":"completed"}'
                good_sig = (
                    "sha256="
                    + hmac.new(webhook_secret.encode("utf-8"), wh_body, hashlib.sha256).hexdigest()
                )
                assert (
                    await gh_adapter.verify_webhook(
                        db,
                        prov_ctx,
                        headers={"X-Hub-Signature-256": good_sig},
                        raw_body=wh_body,
                    )
                    is True
                )
                assert (
                    await gh_adapter.verify_webhook(
                        db,
                        prov_ctx,
                        headers={"X-Hub-Signature-256": "sha256=" + "0" * 64},
                        raw_body=wh_body,
                    )
                    is False
                )

                # Verify zero plaintext secrets in DB rows
                for audit_row in (await db.scalars(select(AuditLogModel))).all():
                    dumped = json.dumps(audit_row.metadata_json)
                    assert webhook_secret not in dumped
                    assert "BEGIN PRIVATE KEY" not in dumped
                for idem_row in (await db.scalars(select(IdempotencyRecordModel))).all():
                    dumped = json.dumps(idem_row.response_payload)
                    assert webhook_secret not in dumped
                    assert "BEGIN PRIVATE KEY" not in dumped

            fork_verdict = WorkflowHazardScanner.classify_pull_request_trust(
                base_repo_id="501001",
                head_repo_id="999999",
                head_repo_fork=True,
            )
            assert fork_verdict.untrusted_fork is True
            assert fork_verdict.allow_auto_repair is False
        finally:
            await owner_client.aclose()
    finally:
        await app_engine.dispose()


@pytest.mark.asyncio
async def test_u09_src_01_negative_callback_forgery_rbac_ssrf_and_partial_pagination(
    migrated_db: PgTestUrls,
) -> None:
    """Verify `T-SRC-01-N`, `SEC-010`, `SEC-032`, `ADR-037` SSRF & mid-pagination resilience."""
    clock = ManualClock()
    rsa_pem, rsa_pub = _generate_rsa_keypair()
    gh_state = MockGitHubState(public_key=rsa_pub, clock=clock)
    mock_gh = _build_mock_github_app(gh_state)

    (
        app_engine,
        iam,
        _redactor,
        _vault,
        _gh_adapter,
        _gh_service,
        _queue_service,
        _registry,
        api_app,
    ) = _build_u09_stack(migrated_db.app_url, clock=clock, mock_gh_app=mock_gh)

    transport = httpx.ASGITransport(app=api_app)
    try:
        owner_client, csrf, owner_id, ws_id = await _claim_owner_and_create_workspace(
            transport, iam
        )
        viewer_client, viewer_csrf, viewer_id = await _provision_and_login_client(
            transport,
            iam,
            email="viewer.u09@red2pr.local",
            display_name="Viewer U09",
        )
        outsider_client, _outsider_csrf, _outsider_id = await _provision_and_login_client(
            transport,
            iam,
            email="outsider.u09@red2pr.local",
            display_name="Outsider U09",
        )

        # Grant viewer membership in workspace `acme` (zero repo grants initially)
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
            # GitLab slice requires pinned auth_mode ('gitlab_signed_v19' | 'gitlab_legacy_token')
            gl_resp = await owner_client.post(
                "/api/v1/workspaces/acme/integrations",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                json={
                    "provider": "gitlab",
                    "base_url": "https://gitlab.com",
                    "auth_mode": "secret_token",
                },
            )
            assert gl_resp.status_code == 422
            assert gl_resp.json()["code"] == "invalid_gitlab_auth_mode"

            # Create valid GitHub connection
            conn_resp = await owner_client.post(
                "/api/v1/workspaces/acme/integrations",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                json={
                    "provider": "github",
                    "base_url": "https://api.github.com",
                    "auth_mode": "github_app",
                    "display_name": "Acme Primary GH",
                    "app_id": "340122",
                    "private_key_pem": rsa_pem,
                },
            )
            assert conn_resp.status_code == 201
            conn_id = conn_resp.json()["id"]

            # Forged callback with installation_id alone (missing state) -> 400
            forged_cb = await owner_client.get(
                "/api/v1/integrations/github/callback",
                params={"installation_id": "99001"},
            )
            assert forged_cb.status_code == 400
            assert forged_cb.json()["code"] == "missing_or_invalid_install_state"

            # Unrecognized state -> 400
            unknown_cb = await owner_client.get(
                "/api/v1/integrations/github/callback",
                params={"state": "st_forged_unknown_state_1234567890", "installation_id": "99001"},
            )
            assert unknown_cb.status_code == 400
            assert unknown_cb.json()["code"] == "invalid_install_state"

            # Mint state1 -> let it expire after >10m -> 410 Gone
            st1 = (
                await owner_client.post(
                    f"/api/v1/workspaces/acme/integrations/{conn_id}/installations/state",
                    headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                    json={"expected_origin": PUBLIC_BASE_URL},
                )
            ).json()["state"]

            # Wrong user session (`outsider`) trying to validate `st1` -> 403
            wrong_user_cb = await outsider_client.get(
                "/api/v1/integrations/github/callback",
                params={"state": st1, "installation_id": "99001"},
                headers=ORIGIN_HEADERS,
            )
            assert wrong_user_cb.status_code == 403
            assert wrong_user_cb.json()["code"] == "install_state_principal_mismatch"

            # Origin mismatch on callback -> 403
            bad_origin_cb = await owner_client.get(
                "/api/v1/integrations/github/callback",
                params={"state": st1, "installation_id": "99001"},
                headers={"Origin": "https://evil.attacker.example"},
            )
            assert bad_origin_cb.status_code == 403
            assert bad_origin_cb.json()["code"] == "install_state_origin_mismatch"

            # Advance clock 11m -> expired state -> 410
            clock.advance(minutes=11)
            expired_confirm = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/installations/confirm",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                json={"installation_id": "99001", "state": st1},
            )
            assert expired_confirm.status_code == 410
            assert expired_confirm.json()["code"] == "install_state_expired"

            # Mint fresh state `st2`, confirm once (200), then replay `st2` under new key -> 409
            st2 = (
                await owner_client.post(
                    f"/api/v1/workspaces/acme/integrations/{conn_id}/installations/state",
                    headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                    json={"expected_origin": PUBLIC_BASE_URL},
                )
            ).json()["state"]

            ok_confirm = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/installations/confirm",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                json={"installation_id": "99001", "state": st2},
            )
            assert ok_confirm.status_code == 200
            discovered_ids = {r["name"]: r["id"] for r in ok_confirm.json()["repositories"]}
            assert len(discovered_ids) == 3

            replayed_confirm = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/installations/confirm",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                json={"installation_id": "99001", "state": st2},
            )
            assert replayed_confirm.status_code == 409
            assert replayed_confirm.json()["code"] in {
                "duplicate_logical_effect",
                "install_state_replayed",
            }

            # Mid-pagination transient failure (`502` on page 2) preserves existing Page 2 repo!
            gh_state.fail_page_2_with_502 = True
            partial_resp = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/sync",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert partial_resp.status_code == 200, partial_resp.text
            partial_body = partial_resp.json()
            assert partial_body["partial_sync"] is True
            assert partial_body["connection"]["status"] == "degraded"
            # All 3 repositories (including Page 2 `oss-sdk-mirror`) remain active in PostgreSQL!
            assert {r["name"] for r in partial_body["repositories"]} == {
                "acme-platform/payments-service",
                "acme-platform/docs-portal",
                "acme-platform/oss-sdk-mirror",
            }
            gh_state.fail_page_2_with_502 = False

            # RBAC & RepoGrant visibility (`SEC-010`, `SEC-032`)
            outsider_get = await outsider_client.get("/api/v1/workspaces/acme/integrations")
            assert outsider_get.status_code == 404
            assert outsider_get.json()["code"] == "workspace_not_found"

            viewer_mut = await viewer_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/probes",
                headers=_csrf_headers(viewer_csrf, idem_key=new_uuid7(now=clock())),
            )
            assert viewer_mut.status_code == 403
            assert viewer_mut.json()["code"] == "insufficient_role"

            viewer_detail_0 = await viewer_client.get(
                f"/api/v1/workspaces/acme/integrations/{conn_id}"
            )
            assert viewer_detail_0.status_code == 200
            assert viewer_detail_0.json()["repositories"] == []

            # Grant viewer access to `acme-platform/payments-service` only
            async with workspace_rls_session(iam.session_factory, workspace_id=ws_id) as db:
                db.add(
                    RepoGrantModel(
                        id=new_uuid7(now=clock()),
                        workspace_id=ws_id,
                        membership_id=viewer_mem_id,
                        repository_id=discovered_ids["acme-platform/payments-service"],
                        granted_by_user_id=owner_id,
                        created_at=clock(),
                    )
                )
            viewer_detail_1 = await viewer_client.get(
                f"/api/v1/workspaces/acme/integrations/{conn_id}"
            )
            assert [r["name"] for r in viewer_detail_1.json()["repositories"]] == [
                "acme-platform/payments-service"
            ]

            # Optimistic concurrency (`412` on stale If-Match, `409` on stale expected_version)
            stale_if_match = await owner_client.patch(
                f"/api/v1/workspaces/acme/integrations/{conn_id}",
                headers=_csrf_headers(
                    csrf,
                    idem_key=new_uuid7(now=clock()),
                    extra={"If-Match": '"v1"'},
                ),
                json={"display_name": "Stale Edit"},
            )
            assert stale_if_match.status_code == 412

            stale_ver = await owner_client.patch(
                f"/api/v1/workspaces/acme/integrations/{conn_id}",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                json={"expected_version": 1, "display_name": "Stale Edit"},
            )
            assert stale_ver.status_code == 409

            # ADR-037 SSRF block: metadata & loopback fail-fast at create (`403`), HTTP at probe
            for forbidden_url in (
                "https://169.254.169.254",
                "https://127.0.0.1",
            ):
                ssrf_conn = await owner_client.post(
                    "/api/v1/workspaces/acme/integrations",
                    headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                    json={
                        "provider": "github",
                        "base_url": forbidden_url,
                        "auth_mode": "github_app",
                        "app_id": "340122",
                        "private_key_pem": rsa_pem,
                    },
                )
                assert ssrf_conn.status_code == 403
                assert ssrf_conn.json()["code"] == "egress_forbidden_ip"

            cleartext_conn = await owner_client.post(
                "/api/v1/workspaces/acme/integrations",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                json={
                    "provider": "github",
                    "base_url": "http://api.github.com",
                    "auth_mode": "github_app",
                    "app_id": "340122",
                    "private_key_pem": rsa_pem,
                },
            )
            assert cleartext_conn.status_code == 201
            cleartext_id = cleartext_conn.json()["id"]
            cleartext_probe = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{cleartext_id}/probes",
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
async def test_u09_sec_011_w02_revocation_suspends_jobs_and_reconnect_requires_grant_review(
    migrated_db: PgTestUrls,
) -> None:
    """Verify `SEC-011` revocation cascade on `task_jobs` + `W-02` reconnect & audit chain."""
    clock = ManualClock()
    rsa_pem, rsa_pub = _generate_rsa_keypair()
    gh_state = MockGitHubState(public_key=rsa_pub, clock=clock)
    mock_gh = _build_mock_github_app(gh_state)

    (
        app_engine,
        iam,
        _redactor,
        _vault,
        _gh_adapter,
        _gh_service,
        queue_service,
        _registry,
        api_app,
    ) = _build_u09_stack(migrated_db.app_url, clock=clock, mock_gh_app=mock_gh)

    transport = httpx.ASGITransport(app=api_app)
    try:
        owner_client, csrf, _owner_id, ws_id = await _claim_owner_and_create_workspace(
            transport, iam
        )
        try:
            conn_id = (
                await owner_client.post(
                    "/api/v1/workspaces/acme/integrations",
                    headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                    json={
                        "provider": "github",
                        "base_url": "https://api.github.com",
                        "auth_mode": "github_app",
                        "display_name": "Acme Revocable GH",
                        "app_id": "340122",
                        "private_key_pem": rsa_pem,
                    },
                )
            ).json()["id"]

            st1 = (
                await owner_client.post(
                    f"/api/v1/workspaces/acme/integrations/{conn_id}/installations/state",
                    headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                )
            ).json()["state"]

            confirmed = (
                await owner_client.post(
                    f"/api/v1/workspaces/acme/integrations/{conn_id}/installations/confirm",
                    headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                    json={"installation_id": "99001", "state": st1},
                )
            ).json()
            payments_repo_id = next(
                r["id"]
                for r in confirmed["repositories"]
                if r["name"] == "acme-platform/payments-service"
            )

            # Promote `acme-platform/payments-service` to `auto_repair` before revocation (`W-02`)
            async with workspace_rls_session(iam.session_factory, workspace_id=ws_id) as db:
                repo_row = await db.scalar(
                    select(RepositoryModel).where(RepositoryModel.id == payments_repo_id)
                )
                assert repo_row is not None
                repo_row.mode = "auto_repair"

            # Enqueue 2 task_jobs on `acme-platform/payments-service`: one `leased`, one `queued`
            job_leased = await queue_service.enqueue_job(
                workspace_id=ws_id,
                repository_id=payments_repo_id,
                resource_id=payments_repo_id,
                kind="repair.execute",
                dedup_key="dedup-leased-1",
                logical_effect_key="eff-leased-1",
                budget_key="bud-1",
                correlation_id="corr-job-leased",
                payload={"run_id": "55001"},
                now=clock(),
            )
            leased_claim = await queue_service.acquire_next_lease(
                worker_id=new_uuid7(now=clock()),
                now=clock(),
            )
            assert leased_claim is not None and leased_claim.job.id == job_leased.id

            job_queued = await queue_service.enqueue_job(
                workspace_id=ws_id,
                repository_id=payments_repo_id,
                resource_id=payments_repo_id,
                kind="triage.ingest",
                dedup_key="dedup-queued-2",
                logical_effect_key="eff-queued-2",
                budget_key="bud-2",
                correlation_id="corr-job-queued",
                payload={"run_id": "55002"},
                now=clock(),
            )

            # Simulate upstream GitHub App revocation (`401 Bad credentials`)
            gh_state.revoked = True
            sync_revoked = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/sync",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert sync_revoked.status_code == 403
            assert sync_revoked.json()["code"] == "provider_connection_revoked"

            # Verify durable revocation side effects (`SEC-011`)
            async with workspace_rls_session(iam.session_factory, workspace_id=ws_id) as db:
                c_row = await db.scalar(
                    select(ProviderConnectionModel).where(ProviderConnectionModel.id == conn_id)
                )
                assert c_row is not None
                assert c_row.status == "revoked"
                assert c_row.grant_review_required is True

                j_queued_row = await db.scalar(
                    select(TaskJobModel).where(TaskJobModel.id == job_queued.id)
                )
                j_leased_row = await db.scalar(
                    select(TaskJobModel).where(TaskJobModel.id == job_leased.id)
                )
                assert j_queued_row is not None and j_queued_row.state == "cancelled"
                assert j_queued_row.cancel_reason == "provider_connection_revoked"
                assert j_leased_row is not None and j_leased_row.state == "cancel_requested"

                disc_ev = await db.scalar(
                    select(OutboxEventModel).where(
                        OutboxEventModel.workspace_id == ws_id,
                        OutboxEventModel.event_type == "integration.disconnected",
                    )
                )
                assert disc_ev is not None

            # Subsequent sync while revoked stays blocked (`403`)
            blocked_sync = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/sync",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            )
            assert blocked_sync.status_code == 403

            # Restore upstream GitHub App and reconnect via fresh `A-23` single-use state (`W-02`)
            gh_state.revoked = False
            st2 = (
                await owner_client.post(
                    f"/api/v1/workspaces/acme/integrations/{conn_id}/installations/state",
                    headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                )
            ).json()["state"]

            reconnected = await owner_client.post(
                f"/api/v1/workspaces/acme/integrations/{conn_id}/installations/confirm",
                headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
                json={"installation_id": "99001", "state": st2},
            )
            assert reconnected.status_code == 200, reconnected.text
            rec_body = reconnected.json()
            assert rec_body["connection"]["status"] == "ready"
            assert rec_body["grant_review_required"] is True
            assert rec_body["connection"]["grant_review_required"] is True
            # W-02: `payments-service` MUST be forced back to `monitor` (never `auto_repair`)!
            rec_payments = next(
                r for r in rec_body["repositories"] if r["name"] == "acme-platform/payments-service"
            )
            assert rec_payments["mode"] == "monitor"

            # Verify hash-chained audit log integrity across all U09 operations
            with tempfile.TemporaryDirectory(prefix="red2pr_u09_ckpt_") as ckpt_dir:
                ckpt_store = ExternalCheckpointStore(Path(ckpt_dir) / "audit_ckpt.json")
                async with instance_rls_session(iam.session_factory, mode="audit_verifier") as db:
                    entries_checked = await verify_audit_chain(
                        db,
                        external_store=ckpt_store,
                        keyring=KeyRing(),
                    )
                    assert entries_checked >= 10
        finally:
            await owner_client.aclose()
    finally:
        await app_engine.dispose()
