"""PostgreSQL 16 + Hermetic GitHub/GitLab Webhook Ingress & Resumable Polling Suite (`U11`).

Verifies against a real disposable PostgreSQL 16 instance (`pgserver` / `fsync=on`):
- `0007_webhook_inbox_sync_cursors` expand/contract reversibility (`downgrade -> upgrade`),
  `35` RLS-forced tables (`ci_run_triggers`, `webhook_inbox`, `provider_sync_cursors`), and
  strict cross-workspace tenant isolation (`SEC-032`).
- `T-SRC-03-P` & `SEC-002` (`SRC-03`, `A-22`, `S-10`, `S-19`, `W-03`, `NFR-01`, `NFR-03`):
  - Raw-body GitHub `X-Hub-Signature-256` (including rotated webhook secret overlap) and
    GitLab `gitlab_signed_v19` / `gitlab_legacy_token` verification committing `webhook_inbox`
    BEFORE `202 Accepted` (`<=1s` ack), `200 OK` on identical duplicate delivery, and
    `409 webhook_payload_digest_conflict` on mutated body with the same delivery ID.
  - Concurrent race (`asyncio.gather`) across out-of-order `workflow_job` + `workflow_run` +
    duplicate webhook + overlapping `LocalPollingService` producing AT MOST ONE
    `ci_run_triggers` row, ONE `provider.run.failed` outbox event, and ONE `ci_run.triage`
    `task_jobs` row, plus `hypothesis` permutation property checks.
  - Genuine rerun (`5001:2`) creating a distinct 2nd trigger (`provider.run.retried`), and
    bot-authored `refs/heads/red2pr/...` repair-branch loop suppression (`ignored_bot_loop`).
- `T-SRC-03-N`, `SEC-001`, `SEC-003`, `SEC-027`, `NFR-01`:
  - Forged signature on malformed non-JSON bytes rejected `401` BEFORE JSON parse (`0` inbox
    rows, redacted `deny` audit, `security.github_webhook.rejected`).
  - Browser `Cookie` header rejected `400 webhook_cookie_forbidden`.
  - GitLab `gitlab_signed_v19` missing `webhook-signature` + matching `X-Gitlab-Token` rejected
    `401` with zero silent downgrade (`SEC-027`).
  - Mismatched GitHub `installation.id` rejected `403 webhook_installation_mismatch` (`SEC-001`).
  - Stale `>6h` replay against live `success` run suppressed (`ignored_stale_replay`, `SEC-003`).
  - Simulated DB persistence failure returns `503 webhook_persistence_unavailable` (never `2xx`).
- `T-SRC-04-P`, `T-SRC-04-N`, `SEC-010`, `SEC-011`, `NFR-04`:
  - Resumable `5m`-overlap polling cursor + conditional `If-None-Match` (`ETag`) `304 Not Modified`.
  - Atomic cursor rollback when mid-transaction persistence fails (zero lost runs on retry).
  - `429 Retry-After` (delta-seconds & RFC 7231 HTTP-date) honored without storming provider or
    advancing cursor (`complete_recovery=False`).
  - Offline `>90d` TTL gap & pagination window gap marked `gap_detected` (`complete_recovery=False`)
    and surfaced in `getConnection` (`SEC-010` `repo_grants`-scoped) & `reconcileConnectionRuns`
    until explicitly acknowledged via `acknowledge_history_gap=True` (`S-05` idempotent replay).
  - `MissedEventReconciler` resolving `reconcile_pending` inbox entries via live `get_run`,
    `SEC-011` `401` revocation cascade during poll, and end-to-end `verify_audit_chain`.
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
import time
from collections.abc import AsyncIterator, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx
import pgserver
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy import func, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from py_contracts.crypto import (
    KeyRing,
    MasterKeyRing,
    sign_gitlab_webhook_v19,
    verify_rs256_jwt,
)
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
    CiRunTriggerModel,
    OutboxEventModel,
    ProviderConnectionModel,
    ProviderSyncCursorModel,
    RepositoryModel,
    SchemaMigrationRecordModel,
    TaskJobModel,
    WebhookInboxModel,
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
    GitLabAdapter,
    LocalPollingService,
    MissedEventReconciler,
    ProviderIntegrationService,
    WebhookIngestService,
    is_bot_authored_repair_loop,
    parse_retry_after_seconds,
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
APP_ROLE_PASSWORD = "red2pr_app_local_test_pw_11"
PUBLIC_BASE_URL = "http://127.0.0.1:4280"
ORIGIN_HEADERS = {"Origin": PUBLIC_BASE_URL}
OWNER_CREDENTIAL = "OwnerSup3rStr0ng!Pass#31"
MEMBER_CREDENTIAL = "MemberSup3rStr0ng!Pass#31"
REPO_ROOT = Path(__file__).resolve().parents[4]
GH_FIXTURES_DIR = REPO_ROOT / "contracts" / "fixtures" / "github"
GL_FIXTURES_DIR = REPO_ROOT / "contracts" / "fixtures" / "gitlab"


class ManualClock:
    """Deterministic controllable UTC clock for webhook replay windows & polling cursors."""

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


def _gh_hmac_header(secret: str, raw_body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


class _PublicDnsResolver:
    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        _ = port
        if host in {"api.github.com", "gitlab.com"}:
            return ("140.82.112.6",)
        return (host,)


@dataclass
class MockProviderState:
    """Hermetic state shared by mock GitHub & GitLab endpoints for U11 tests."""

    clock: ManualClock
    gh_app_id: str
    gh_installation_id: str
    gh_public_key: rsa.RSAPublicKey
    gh_issued_tokens: set[str] = field(default_factory=set)
    gh_token_seq: int = 0
    gh_revoked: bool = False
    gh_poll_mode: str = "ok"  # "ok" | "rate_limit" | "gone_410" | "pagination_flood"
    gh_poll_retry_after: str = "180"
    gh_poll_etag: str = 'W/"gh-poll-v1"'
    gh_poll_requests: list[dict[str, str | None]] = field(default_factory=list)
    gh_live_runs: dict[str, dict[str, Any]] = field(default_factory=dict)

    gl_valid_tokens: set[str] = field(default_factory=set)
    gl_revoked: bool = False
    gl_poll_mode: str = "ok"  # "ok" | "rate_limit"
    gl_poll_etag: str = 'W/"gl-poll-v1"'
    gl_poll_requests: list[dict[str, str | None]] = field(default_factory=list)
    gl_live_pipelines: dict[str, dict[str, Any]] = field(default_factory=dict)


def _create_mock_github_app(state: MockProviderState) -> FastAPI:
    gh = FastAPI()
    poll_fixture = json.loads(
        (GH_FIXTURES_DIR / "poll_workflow_runs.json").read_text(encoding="utf-8")
    )

    def _verify_app_jwt(request: Request) -> Response | None:
        assert request.headers.get("X-GitHub-Api-Version") == GITHUB_API_VERSION
        if state.gh_revoked:
            return JSONResponse({"message": "Bad credentials"}, status_code=401)
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return JSONResponse({"message": "Missing App JWT"}, status_code=401)
        pub_pem = state.gh_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        claims = verify_rs256_jwt(
            auth.removeprefix("Bearer ").strip(),
            public_key_pem=pub_pem,
            now=state.clock(),
        )
        assert claims.get("iss") == state.gh_app_id
        return None

    def _verify_inst_token(request: Request) -> Response | None:
        assert request.headers.get("X-GitHub-Api-Version") == GITHUB_API_VERSION
        if state.gh_revoked:
            return JSONResponse({"message": "Bad credentials"}, status_code=401)
        auth = request.headers.get("Authorization", "")
        tok = auth.removeprefix("Bearer ").strip()
        if tok not in state.gh_issued_tokens:
            return JSONResponse({"message": "Invalid installation token"}, status_code=401)
        return None

    @gh.post("/app/installations/{install_id}/access_tokens")
    async def mint_token(install_id: str, request: Request) -> Response:
        err = _verify_app_jwt(request)
        if err is not None:
            return err
        if install_id != state.gh_installation_id:
            return JSONResponse({"message": "Not Found"}, status_code=404)
        state.gh_token_seq += 1
        tok = f"ghs_u11_scoped_{state.gh_token_seq:04d}_secret998877"
        state.gh_issued_tokens.add(tok)
        exp = (state.clock() + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        return JSONResponse({"token": tok, "expires_at": exp}, status_code=201)

    @gh.get("/repos/{owner}/{repo}/actions/runs")
    async def list_workflow_runs(
        owner: str,
        repo: str,
        request: Request,
        page: int = 1,
        per_page: int = 50,
        created: str | None = None,
    ) -> Response:
        _ = (owner, repo, per_page)
        err = _verify_inst_token(request)
        if err is not None:
            return err
        if_none_match = request.headers.get("If-None-Match")
        state.gh_poll_requests.append(
            {
                "if_none_match": if_none_match,
                "created": created,
                "page": str(page),
            }
        )
        if state.gh_poll_mode == "rate_limit":
            return JSONResponse(
                {"message": "API rate limit exceeded"},
                status_code=429,
                headers={
                    "Retry-After": state.gh_poll_retry_after,
                    "X-RateLimit-Remaining": "0",
                },
            )
        if state.gh_poll_mode == "gone_410":
            return JSONResponse({"message": "History retention expired"}, status_code=410)
        if state.gh_poll_mode == "pagination_flood":
            # Simulate more pages than max_catchup_pages with timestamps newer than since_cursor
            ts_str = (
                (state.clock() - timedelta(seconds=page * 5)).isoformat().replace("+00:00", "Z")
            )
            next_link = (
                f"<https://api.github.com/repos/{owner}/{repo}/actions/runs"
                f'?page={page + 1}>; rel="next"'
            )
            return JSONResponse(
                {
                    "total_count": 500,
                    "workflow_runs": [
                        {
                            "id": 9000 + page,
                            "run_attempt": 1,
                            "head_branch": "main",
                            "head_sha": f"{page:040x}",
                            "event": "push",
                            "status": "completed",
                            "conclusion": "success",
                            "created_at": ts_str,
                            "updated_at": ts_str,
                            "head_repository": {"id": 700101, "fork": False},
                        }
                    ],
                },
                headers={"Link": next_link, "ETag": state.gh_poll_etag},
            )
        if if_none_match == state.gh_poll_etag:
            return Response(status_code=304, headers={"ETag": state.gh_poll_etag})
        return JSONResponse(
            poll_fixture,
            headers={
                "ETag": state.gh_poll_etag,
                "X-RateLimit-Remaining": "4950",
            },
        )

    @gh.get("/repos/{owner}/{repo}/actions/runs/{run_id}")
    async def get_workflow_run(
        owner: str,
        repo: str,
        run_id: str,
        request: Request,
    ) -> Response:
        _ = (owner, repo)
        err = _verify_inst_token(request)
        if err is not None:
            return err
        live = state.gh_live_runs.get(run_id)
        if live is None:
            return JSONResponse({"message": "Not Found"}, status_code=404)
        return JSONResponse(live)

    return gh


def _create_mock_gitlab_app(state: MockProviderState) -> FastAPI:
    gl = FastAPI()
    poll_fixture = json.loads((GL_FIXTURES_DIR / "poll_pipelines.json").read_text(encoding="utf-8"))

    def _verify_gl_token(request: Request) -> Response | None:
        if state.gl_revoked:
            return JSONResponse({"message": "401 Unauthorized"}, status_code=401)
        tok = request.headers.get("PRIVATE-TOKEN", "")
        if tok not in state.gl_valid_tokens:
            return JSONResponse({"message": "401 Unauthorized"}, status_code=401)
        return None

    @gl.get("/api/v4/projects/{project_path:path}/pipelines/{pipeline_id}")
    async def get_pipeline(
        project_path: str,
        pipeline_id: str,
        request: Request,
    ) -> Response:
        _ = project_path
        err = _verify_gl_token(request)
        if err is not None:
            return err
        live = state.gl_live_pipelines.get(pipeline_id)
        if live is None:
            return JSONResponse({"message": "404 Not Found"}, status_code=404)
        return JSONResponse(live)

    @gl.get("/api/v4/projects/{project_path:path}/pipelines")
    async def list_pipelines(
        project_path: str,
        request: Request,
        page: int = 1,
        per_page: int = 50,
        updated_after: str | None = None,
    ) -> Response:
        _ = (project_path, per_page)
        err = _verify_gl_token(request)
        if err is not None:
            return err
        if_none_match = request.headers.get("If-None-Match")
        state.gl_poll_requests.append(
            {
                "if_none_match": if_none_match,
                "updated_after": updated_after,
                "page": str(page),
            }
        )
        if state.gl_poll_mode == "rate_limit":
            return JSONResponse(
                {"message": "Retry later"},
                status_code=429,
                headers={"Retry-After": "120", "RateLimit-Remaining": "0"},
            )
        if if_none_match == state.gl_poll_etag:
            return Response(status_code=304, headers={"ETag": state.gl_poll_etag})
        return JSONResponse(
            poll_fixture,
            headers={
                "ETag": state.gl_poll_etag,
                "RateLimit-Remaining": "1990",
                "x-next-page": "",
            },
        )

    return gl


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
        tempfile.TemporaryDirectory(prefix="red2pr_u11_pg_") as tmp_dir,
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
    """Reset schema cleanly to head (`0007`) before each test."""
    run_alembic_downgrade(pg_urls.admin_url, "base", app_role_name=APP_ROLE_NAME)
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
    yield pg_urls


@dataclass
class U11Harness:
    app_engine: AsyncEngine
    app_factory: async_sessionmaker[AsyncSession]
    iam: IamService
    redactor: Redactor
    provider_vault: SecretBrokerProviderVault
    gh_adapter: GitHubAppAdapter
    gl_adapter: GitLabAdapter
    integration_service: ProviderIntegrationService
    webhook_service: WebhookIngestService
    poller: LocalPollingService
    reconciler: MissedEventReconciler
    api_app: FastAPI
    state: MockProviderState
    gh_private_pem: str


def _build_u11_harness(app_url: str, *, clock: ManualClock) -> U11Harness:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")

    state = MockProviderState(
        clock=clock,
        gh_app_id="340122",
        gh_installation_id="99001",
        gh_public_key=rsa_key.public_key(),
        gh_live_runs={
            "5001": {
                "id": 5001,
                "run_attempt": 1,
                "head_branch": "main",
                "head_sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f60001",
                "event": "push",
                "status": "completed",
                "conclusion": "failure",
                "head_repository": {"id": 700101, "fork": False},
            }
        },
        gl_valid_tokens={"glpat-u11CloudTokenSecret99887766"},
        gl_live_pipelines={
            "7701": {
                "id": 7701,
                "sha": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a17701",
                "ref": "main",
                "status": "failed",
                "source": "push",
            }
        },
    )
    mock_gh = _create_mock_github_app(state)
    mock_gl = _create_mock_gitlab_app(state)

    app_engine = create_app_engine(app_url, pool_size=8, max_overflow=8)
    app_factory = create_session_factory(app_engine)
    redactor = Redactor()
    kek_ring = MasterKeyRing(active_version=1, keys={1: b"\x7c" * 32})
    broker = SecretBroker(key_ring=kek_ring, redactor=redactor)
    totp_vault = SecretBrokerTotpVault(broker)
    provider_vault = SecretBrokerProviderVault(broker)

    iam = IamService(
        session_factory=app_factory,
        totp_vault=totp_vault,
        iam_seed_key=b"\x8d" * 32,
        public_base_url=PUBLIC_BASE_URL,
        clock=clock,
    )
    egress_engine = EgressPolicyEngine(
        allowlist_provider=DbEndpointAllowlistProvider(app_factory),
        dns_resolver=_PublicDnsResolver(),
    )
    gh_adapter = GitHubAppAdapter(
        vault=provider_vault,
        egress_policy=egress_engine,
        redactor=redactor,
        transport_override=httpx.ASGITransport(app=mock_gh),
    )
    gl_adapter = GitLabAdapter(
        vault=provider_vault,
        egress_policy=egress_engine,
        ca_bundle_resolver=InMemoryCaBundleResolver({}),
        redactor=redactor,
        transport_override=httpx.ASGITransport(app=mock_gl),
    )
    integration_service = ProviderIntegrationService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        vault=provider_vault,
        github_adapter=gh_adapter,
        gitlab_adapter=gl_adapter,
        redactor=redactor,
    )
    webhook_service = WebhookIngestService(
        session_factory=app_factory,
        github_adapter=gh_adapter,
        gitlab_adapter=gl_adapter,
        integration_service=integration_service,
        redactor=redactor,
        clock=clock,
    )
    poller = LocalPollingService(
        session_factory=app_factory,
        github_adapter=gh_adapter,
        gitlab_adapter=gl_adapter,
        integration_service=integration_service,
        redactor=redactor,
        clock=clock,
        max_catchup_pages=3,
    )
    reconciler = MissedEventReconciler(
        session_factory=app_factory,
        github_adapter=gh_adapter,
        gitlab_adapter=gl_adapter,
        poller=poller,
        integration_service=integration_service,
        redactor=redactor,
        clock=clock,
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
        webhook_ingest_service=webhook_service,
        polling_service=poller,
        reconciler_service=reconciler,
    )
    return U11Harness(
        app_engine=app_engine,
        app_factory=app_factory,
        iam=iam,
        redactor=redactor,
        provider_vault=provider_vault,
        gh_adapter=gh_adapter,
        gl_adapter=gl_adapter,
        integration_service=integration_service,
        webhook_service=webhook_service,
        poller=poller,
        reconciler=reconciler,
        api_app=api_app,
        state=state,
        gh_private_pem=private_pem,
    )


async def _claim_owner_and_workspace(
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
            "display_name": "Owner U11",
            "email": "owner.u11@red2pr.local",
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
    return client, csrf_token, owner_id, ws_resp.json()["id"]


async def _seed_ready_connection_and_repo(
    harness: U11Harness,
    *,
    admin_client: httpx.AsyncClient,
    csrf: str,
    ws_slug: str,
    ws_id: str,
    provider: str,
    auth_mode: str,
    webhook_secret: str,
    external_repo_id: str,
    repo_name: str,
    now: datetime,
) -> tuple[str, str]:
    body: dict[str, Any] = {
        "provider": provider,
        "auth_mode": auth_mode,
        "display_name": f"{provider.upper()} Primary",
        "base_url": "https://api.github.com" if provider == "github" else "https://gitlab.com",
        "webhook_secret": webhook_secret,
    }
    if provider == "github":
        body["app_id"] = harness.state.gh_app_id
        body["private_key_pem"] = harness.gh_private_pem
    else:
        body["access_token"] = "glpat-u11CloudTokenSecret99887766"

    create_resp = await admin_client.post(
        f"/api/v1/workspaces/{ws_slug}/integrations",
        headers=_csrf_headers(csrf, idem_key=new_uuid7(now=now)),
        json=body,
    )
    assert create_resp.status_code == 201, create_resp.text
    conn_id = str(create_resp.json()["id"])

    repo_id = new_uuid7(now=now)
    async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
        conn_row = await db.scalar(
            select(ProviderConnectionModel).where(
                ProviderConnectionModel.workspace_id == ws_id,
                ProviderConnectionModel.id == conn_id,
            )
        )
        assert conn_row is not None
        conn_row.status = "ready"
        if provider == "github":
            conn_row.external_installation_id = harness.state.gh_installation_id
            conn_row.account_login = "acme-red2pr-app"
        else:
            conn_row.account_login = "acme-gitlab-bot"
        conn_row.checked_at = now
        conn_row.updated_at = now

        db.add(
            RepositoryModel(
                id=repo_id,
                workspace_id=ws_id,
                provider_connection_id=conn_id,
                external_repo_id=external_repo_id,
                name=repo_name,
                default_branch="main",
                visibility="private",
                mode="monitor",
                paused=False,
                active=True,
                archived=False,
                is_fork=False,
                policy_revision=1,
                tags_json=[],
                workflow_hazard_status="clean",
                workflow_hazards_json=[],
                auto_repair_blocked=False,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
        await db.flush()
    return conn_id, repo_id


@pytest.mark.asyncio
async def test_0007_migration_reversibility_rls_and_tenant_isolation(
    migrated_db: PgTestUrls,
) -> None:
    """Verify `0007` downgrade/upgrade reversibility, `35` RLS tables & tenant isolation."""
    run_alembic_downgrade(
        migrated_db.admin_url,
        "0006_provider_connections_repos",
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
            assert len(rows) == 35
            relnames = {r[0] for r in rows}
            assert {"ci_run_triggers", "webhook_inbox", "provider_sync_cursors"}.issubset(relnames)
            for relname, has_rls, force_rls in rows:
                assert has_rls is True, f"{relname} missing ENABLE ROW LEVEL SECURITY"
                assert force_rls is True, f"{relname} missing FORCE ROW LEVEL SECURITY"

            mig_row = await admin_db.scalar(
                select(SchemaMigrationRecordModel).where(
                    SchemaMigrationRecordModel.revision == "0007_webhook_inbox_sync_cursors"
                )
            )
            assert mig_row is not None

        now = datetime(2026, 10, 27, 15, 0, 0, tzinfo=UTC)
        ws_a = new_uuid7(now=now)
        ws_b = new_uuid7(now=now)
        conn_a = new_uuid7(now=now)
        repo_a = new_uuid7(now=now)
        inbox_a = new_uuid7(now=now)
        cursor_a = new_uuid7(now=now)

        async with instance_rls_session(app_factory, mode="instance_admin") as db:
            for ws_id, slug in ((ws_a, "ws-alpha"), (ws_b, "ws-beta")):
                db.add(
                    WorkspaceModel(
                        id=ws_id,
                        name=slug,
                        slug=slug,
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
                    display_name="GitHub Alpha",
                    base_url="https://api.github.com",
                    auth_mode="github_app",
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
                    external_repo_id="700101",
                    name="acme/payments",
                    default_branch="main",
                    visibility="private",
                    mode="monitor",
                    paused=False,
                    active=True,
                    archived=False,
                    is_fork=False,
                    policy_revision=1,
                    tags_json=[],
                    workflow_hazard_status="clean",
                    workflow_hazards_json=[],
                    auto_repair_blocked=False,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            await db.flush()
            db.add(
                WebhookInboxModel(
                    id=inbox_a,
                    workspace_id=ws_a,
                    connection_id=conn_a,
                    repository_id=repo_a,
                    provider="github",
                    source="webhook",
                    event_type="workflow_run",
                    provider_delivery_id="deliv-rls-1",
                    payload_digest="a" * 64,
                    signature_valid=True,
                    status="normalized",
                    sanitized_headers_json={},
                    normalized_summary_json={},
                    correlation_id="corr-rls-1",
                    received_at=now,
                    retention_until=now + timedelta(days=90),
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            db.add(
                ProviderSyncCursorModel(
                    id=cursor_a,
                    workspace_id=ws_a,
                    connection_id=conn_a,
                    repository_id=repo_a,
                    provider="github",
                    last_stable_page=1,
                    overlap_seconds=300,
                    poll_interval_seconds=60,
                    consecutive_failures=0,
                    last_status="ok",
                    history_gap_detected=False,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )

        # Workspace B MUST see zero rows from Workspace A (`SEC-032`)
        async with workspace_rls_session(app_factory, workspace_id=ws_b) as db_b:
            assert (await db_b.scalar(select(func.count(WebhookInboxModel.id)))) == 0
            assert (await db_b.scalar(select(func.count(ProviderSyncCursorModel.id)))) == 0
            assert (await db_b.scalar(select(func.count(CiRunTriggerModel.id)))) == 0
    finally:
        await app_engine.dispose()
        await admin_engine.dispose()


@given(
    order=st.permutations(["workflow_job", "workflow_run", "duplicate_webhook", "poll"]),
    branch=st.sampled_from(["refs/heads/red2pr/fix-5001", "red2pr/repair-99"]),
)
@settings(max_examples=24, deadline=None)
def test_property_bot_loop_and_permutation_invariants(
    order: list[str],
    branch: str,
) -> None:
    """Property check: all 24 permutations preserve unique semantic key & suppress bot branches."""
    assert len(set(order)) == 4
    assert is_bot_authored_repair_loop(
        ref=branch,
        actor_login="octo-dev",
        connection_account_login="acme-red2pr-app",
    )
    assert is_bot_authored_repair_loop(
        ref="refs/heads/main",
        actor_login="red2pr[bot]",
        connection_account_login="acme-red2pr-app",
    )
    assert is_bot_authored_repair_loop(
        ref="refs/heads/main",
        commit_message="fix: patch flaky test <!-- red2pr:session-01 -->",
        actor_login="octo-dev",
        connection_account_login="acme-red2pr-app",
    )
    assert not is_bot_authored_repair_loop(
        ref="refs/heads/feature/red2pr-docs",
        actor_login="octo-dev",
        connection_account_login="acme-red2pr-app",
    )


def test_parse_retry_after_delta_and_rfc7231_http_date() -> None:
    now = datetime(2026, 10, 27, 15, 0, 0, tzinfo=UTC)
    assert parse_retry_after_seconds("45", now=now) == 45
    future_http_date = format_datetime(now + timedelta(seconds=135), usegmt=True)
    assert parse_retry_after_seconds(future_http_date, now=now) == 135
    assert parse_retry_after_seconds("999999", now=now, max_seconds=3600) == 3600
    assert parse_retry_after_seconds(None, now=now) is None


@pytest.mark.asyncio
async def test_t_src_03_p_raw_hmac_rotated_secrets_concurrent_dedup_and_rerun(
    migrated_db: PgTestUrls,
) -> None:
    """Verify `T-SRC-03-P`, `SEC-002`, `NFR-01`/`NFR-03` ack, rotated secrets, dedup & reruns."""
    clock = ManualClock()
    harness = _build_u11_harness(migrated_db.app_url, clock=clock)
    gh_secret_v1 = "ghwh_secret_v1_0123456789abcdef"
    gh_secret_v2 = "ghwh_secret_v2_fedcba9876543210"
    gl_whsec = "whsec_" + base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii")
    gl_legacy = "glwh_legacy_token_secret_99887766"

    transport = httpx.ASGITransport(app=harness.api_app)
    admin_client, csrf, _, ws_id = await _claim_owner_and_workspace(transport, harness.iam)
    try:
        gh_conn_id, gh_repo_id = await _seed_ready_connection_and_repo(
            harness,
            admin_client=admin_client,
            csrf=csrf,
            ws_slug="acme",
            ws_id=ws_id,
            provider="github",
            auth_mode="github_app",
            webhook_secret=gh_secret_v1,
            external_repo_id="700101",
            repo_name="acme-platform/payments-service",
            now=clock(),
        )
        gl_signed_conn_id, _ = await _seed_ready_connection_and_repo(
            harness,
            admin_client=admin_client,
            csrf=csrf,
            ws_slug="acme",
            ws_id=ws_id,
            provider="gitlab",
            auth_mode="gitlab_signed_v19",
            webhook_secret=gl_whsec,
            external_repo_id="4401",
            repo_name="acme-group/billing-api",
            now=clock(),
        )
        gl_legacy_conn_id, _ = await _seed_ready_connection_and_repo(
            harness,
            admin_client=admin_client,
            csrf=csrf,
            ws_slug="acme",
            ws_id=ws_id,
            provider="gitlab",
            auth_mode="gitlab_legacy_token",
            webhook_secret=gl_legacy,
            external_repo_id="4402",
            repo_name="acme-group/legacy-service",
            now=clock(),
        )

        # Rotate GitHub webhook secret -> BOTH v1 (previous) and v2 (active) MUST verify!
        rot_resp = await admin_client.patch(
            f"/api/v1/workspaces/acme/integrations/{gh_conn_id}",
            headers=_csrf_headers(
                csrf,
                idem_key=new_uuid7(now=clock()),
                extra={"If-Match": '"v1"'},
            ),
            json={"expected_version": 1, "webhook_secret": gh_secret_v2},
        )
        assert rot_resp.status_code == 200, rot_resp.text

        raw_wf_run = (GH_FIXTURES_DIR / "webhook_workflow_run_failed.json").read_bytes()
        raw_wf_job = (GH_FIXTURES_DIR / "webhook_workflow_job_failed.json").read_bytes()

        # Public unauthenticated hook client (no session cookies!)
        async with httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL) as hook_client:

            async def _timed_post(
                url: str,
                *,
                content: bytes,
                headers: dict[str, str],
            ) -> tuple[httpx.Response, float]:
                t_start = time.perf_counter()
                resp = await hook_client.post(url, content=content, headers=headers)
                return resp, (time.perf_counter() - t_start)

            # Concurrent race: out-of-order workflow_job (signed w/ rotated v1) + workflow_run
            # (signed w/ active v2) + duplicate workflow_run + overlapping LocalPollingService!
            (
                (res_job, _),
                (res_run_a, dur_run_a),
                (res_run_b, dur_run_b),
                poll_summary,
            ) = await asyncio.gather(
                _timed_post(
                    f"/api/v1/hooks/github/{gh_conn_id}",
                    content=raw_wf_job,
                    headers={
                        "Content-Type": "application/json",
                        "X-GitHub-Event": "workflow_job",
                        "X-GitHub-Delivery": "deliv-gh-job-88001",
                        "X-Hub-Signature-256": _gh_hmac_header(gh_secret_v1, raw_wf_job),
                    },
                ),
                _timed_post(
                    f"/api/v1/hooks/github/{gh_conn_id}",
                    content=raw_wf_run,
                    headers={
                        "Content-Type": "application/json",
                        "X-GitHub-Event": "workflow_run",
                        "X-GitHub-Delivery": "deliv-gh-run-5001-a",
                        "X-Hub-Signature-256": _gh_hmac_header(gh_secret_v2, raw_wf_run),
                    },
                ),
                _timed_post(
                    f"/api/v1/hooks/github/{gh_conn_id}",
                    content=raw_wf_run,
                    headers={
                        "Content-Type": "application/json",
                        "X-GitHub-Event": "workflow_run",
                        "X-GitHub-Delivery": "deliv-gh-run-5001-b",
                        "X-Hub-Signature-256": _gh_hmac_header(gh_secret_v2, raw_wf_run),
                    },
                ),
                harness.poller.poll_connection(
                    workspace_id=ws_id,
                    connection_id=gh_conn_id,
                    force_poll=True,
                ),
            )
            assert res_job.status_code == 202, res_job.text
            assert res_run_a.status_code == 202, res_run_a.text
            assert res_run_b.status_code == 202, res_run_b.text
            assert poll_summary.polled_repository_count == 1
            _ = (dur_run_a, dur_run_b)

            # Exact duplicate delivery ID returns 200 OK with identical inbox_id (<=1s NFR-03)
            t_ack = time.perf_counter()
            dup_resp = await hook_client.post(
                f"/api/v1/hooks/github/{gh_conn_id}",
                content=raw_wf_run,
                headers={
                    "Content-Type": "application/json",
                    "X-GitHub-Event": "workflow_run",
                    "X-GitHub-Delivery": "deliv-gh-run-5001-a",
                    "X-Hub-Signature-256": _gh_hmac_header(gh_secret_v2, raw_wf_run),
                },
            )
            ack_elapsed = time.perf_counter() - t_ack
            assert ack_elapsed <= 1.0, f"Webhook ack exceeded 1s NFR-03 budget: {ack_elapsed:.3f}s"
            assert dup_resp.status_code == 200, dup_resp.text
            assert dup_resp.json()["duplicate"] is True
            assert dup_resp.json()["disposition"] == "duplicate_delivery"
            assert dup_resp.json()["inbox_id"] == res_run_a.json()["inbox_id"]

            # Mutated payload under identical delivery ID -> 409 Conflict (`T-SRC-03-N`)
            mutated_bytes = raw_wf_run + b" "
            conflict_resp = await hook_client.post(
                f"/api/v1/hooks/github/{gh_conn_id}",
                content=mutated_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-GitHub-Event": "workflow_run",
                    "X-GitHub-Delivery": "deliv-gh-run-5001-a",
                    "X-Hub-Signature-256": _gh_hmac_header(gh_secret_v2, mutated_bytes),
                },
            )
            assert conflict_resp.status_code == 409, conflict_resp.text
            assert conflict_resp.json()["code"] == "webhook_delivery_digest_mismatch"

            # Verify EXACT-ONCE semantic trigger, outbox event & triage job for 5001:1 (`SEC-002`)
            async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
                triggers = list(
                    (
                        await db.scalars(
                            select(CiRunTriggerModel).where(
                                CiRunTriggerModel.workspace_id == ws_id,
                                CiRunTriggerModel.repository_id == gh_repo_id,
                            )
                        )
                    ).all()
                )
                assert len(triggers) == 1
                first_trigger = triggers[0]
                assert first_trigger.attempt_key == "5001:1"
                assert first_trigger.is_rerun is False

                failed_events = list(
                    (
                        await db.scalars(
                            select(OutboxEventModel).where(
                                OutboxEventModel.workspace_id == ws_id,
                                OutboxEventModel.event_type == "provider.run.failed",
                            )
                        )
                    ).all()
                )
                assert len(failed_events) == 1

                triage_jobs = list(
                    (
                        await db.scalars(
                            select(TaskJobModel).where(
                                TaskJobModel.workspace_id == ws_id,
                                TaskJobModel.kind == "ci_run.triage",
                            )
                        )
                    ).all()
                )
                assert len(triage_jobs) == 1
                assert triage_jobs[0].resource_id == first_trigger.id

            # Genuine rerun (`5001:2`) creates a distinct 2nd trigger (`provider.run.retried`)
            rerun_obj = json.loads(raw_wf_run.decode("utf-8"))
            rerun_obj["workflow_run"]["run_attempt"] = 2
            raw_rerun = json.dumps(rerun_obj).encode("utf-8")
            rerun_resp = await hook_client.post(
                f"/api/v1/hooks/github/{gh_conn_id}",
                content=raw_rerun,
                headers={
                    "Content-Type": "application/json",
                    "X-GitHub-Event": "workflow_run",
                    "X-GitHub-Delivery": "deliv-gh-run-5001-attempt2",
                    "X-Hub-Signature-256": _gh_hmac_header(gh_secret_v2, raw_rerun),
                },
            )
            assert rerun_resp.status_code == 202, rerun_resp.text
            assert rerun_resp.json()["disposition"] == "accepted_trigger"
            assert rerun_resp.json()["trigger_id"] != first_trigger.id

            # Bot-authored `red2pr/` repair branch failure is ignored (`W-03` loop prevention)
            bot_obj = json.loads(raw_wf_run.decode("utf-8"))
            bot_obj["workflow_run"]["id"] = 5099
            bot_obj["workflow_run"]["head_branch"] = "red2pr/fix-5001"
            raw_bot = json.dumps(bot_obj).encode("utf-8")
            bot_resp = await hook_client.post(
                f"/api/v1/hooks/github/{gh_conn_id}",
                content=raw_bot,
                headers={
                    "Content-Type": "application/json",
                    "X-GitHub-Event": "workflow_run",
                    "X-GitHub-Delivery": "deliv-gh-bot-loop-5099",
                    "X-Hub-Signature-256": _gh_hmac_header(gh_secret_v2, raw_bot),
                },
            )
            assert bot_resp.status_code == 202, bot_resp.text
            assert bot_resp.json()["disposition"] == "ignored_bot_loop"
            assert bot_resp.json()["trigger_id"] is None

            # GitLab signed v19 webhook (`webhook-signature`) & legacy token (`X-Gitlab-Token`)
            raw_gl_pipe = (GL_FIXTURES_DIR / "webhook_pipeline_failed.json").read_bytes()
            ts_unix = int(clock().timestamp())
            gl_sig = sign_gitlab_webhook_v19(
                secret=gl_whsec,
                webhook_id="msg_gl_7701_a",
                timestamp_unix=ts_unix,
                raw_body=raw_gl_pipe,
            )
            gl_signed_resp = await hook_client.post(
                f"/api/v1/hooks/gitlab/{gl_signed_conn_id}",
                content=raw_gl_pipe,
                headers={
                    "Content-Type": "application/json",
                    "X-Gitlab-Event": "Pipeline Hook",
                    "webhook-id": "msg_gl_7701_a",
                    "webhook-timestamp": str(ts_unix),
                    "webhook-signature": gl_sig,
                },
            )
            assert gl_signed_resp.status_code == 202, gl_signed_resp.text
            assert gl_signed_resp.json()["disposition"] == "accepted_trigger"

            gl_legacy_obj = json.loads(raw_gl_pipe.decode("utf-8"))
            gl_legacy_obj["project"]["id"] = 4402
            gl_legacy_obj["project"]["path_with_namespace"] = "acme-group/legacy-service"
            gl_legacy_obj["object_attributes"]["id"] = 8801
            raw_gl_legacy = json.dumps(gl_legacy_obj).encode("utf-8")
            gl_legacy_resp = await hook_client.post(
                f"/api/v1/hooks/gitlab/{gl_legacy_conn_id}",
                content=raw_gl_legacy,
                headers={
                    "Content-Type": "application/json",
                    "X-Gitlab-Event": "Pipeline Hook",
                    "X-Gitlab-Event-UUID": "uuid-gl-legacy-8801",
                    "X-Gitlab-Token": gl_legacy,
                },
            )
            assert gl_legacy_resp.status_code == 202, gl_legacy_resp.text
            assert gl_legacy_resp.json()["disposition"] == "accepted_trigger"

            async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
                retried_events = list(
                    (
                        await db.scalars(
                            select(OutboxEventModel).where(
                                OutboxEventModel.workspace_id == ws_id,
                                OutboxEventModel.event_type == "provider.run.retried",
                            )
                        )
                    ).all()
                )
                assert len(retried_events) == 1
                total_triggers = await db.scalar(
                    select(func.count(CiRunTriggerModel.id)).where(
                        CiRunTriggerModel.workspace_id == ws_id
                    )
                )
                # 5001:1 + 5001:2 + pipeline:7701 + pipeline:8801 = 4 triggers (0 bot loops)
                assert total_triggers == 4
    finally:
        await admin_client.aclose()
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_t_src_03_n_raw_body_rejection_no_downgrade_stale_replay_and_db_503(
    migrated_db: PgTestUrls,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify `T-SRC-03-N`, `SEC-001`, `SEC-003`, `SEC-027`, and `NFR-01` DB failure -> `503`."""
    clock = ManualClock()
    harness = _build_u11_harness(migrated_db.app_url, clock=clock)
    gh_secret = "ghwh_canary_secret_never_leak_999"
    gl_whsec = "whsec_" + base64.b64encode(b"abcdef0123456789abcdef0123456789").decode("ascii")
    harness.redactor.register_canary(gh_secret)
    harness.redactor.register_canary(gl_whsec)

    transport = httpx.ASGITransport(app=harness.api_app)
    admin_client, csrf, _, ws_id = await _claim_owner_and_workspace(transport, harness.iam)
    try:
        gh_conn_id, _ = await _seed_ready_connection_and_repo(
            harness,
            admin_client=admin_client,
            csrf=csrf,
            ws_slug="acme",
            ws_id=ws_id,
            provider="github",
            auth_mode="github_app",
            webhook_secret=gh_secret,
            external_repo_id="700101",
            repo_name="acme-platform/payments-service",
            now=clock(),
        )
        gl_conn_id, _ = await _seed_ready_connection_and_repo(
            harness,
            admin_client=admin_client,
            csrf=csrf,
            ws_slug="acme",
            ws_id=ws_id,
            provider="gitlab",
            auth_mode="gitlab_signed_v19",
            webhook_secret=gl_whsec,
            external_repo_id="4401",
            repo_name="acme-group/billing-api",
            now=clock(),
        )

        import logging as std_logging

        gh_logger = std_logging.getLogger("red2pr_control.integrations.github")
        gl_logger = std_logging.getLogger("red2pr_control.integrations.gitlab")
        gh_logger.addHandler(caplog.handler)
        gl_logger.addHandler(caplog.handler)
        caplog.set_level(std_logging.WARNING)
        try:
            async with httpx.AsyncClient(
                transport=transport, base_url=PUBLIC_BASE_URL
            ) as hook_client:
                # 1. Forged signature on malformed non-JSON bytes -> 401 BEFORE JSON parse!
                caplog.clear()
                forged_resp = await hook_client.post(
                    f"/api/v1/hooks/github/{gh_conn_id}",
                    content=b"{malformed-not-json-at-all!!!",
                    headers={
                        "Content-Type": "application/json",
                        "X-GitHub-Event": "workflow_run",
                        "X-GitHub-Delivery": "deliv-forged-01",
                        "X-Hub-Signature-256": "sha256=" + ("f" * 64),
                    },
                )
                assert forged_resp.status_code == 401, forged_resp.text
                assert forged_resp.json()["code"] == "invalid_webhook_auth"
                assert gh_secret not in forged_resp.text
                assert any(
                    getattr(rec, "event", None) == "security.github_webhook.rejected"
                    for rec in caplog.records
                )
                for rec in caplog.records:
                    assert gh_secret not in rec.getMessage()

                # 2. Browser Cookie header on /hooks/* -> 400 (`A-22`)
                raw_wf_run = (GH_FIXTURES_DIR / "webhook_workflow_run_failed.json").read_bytes()
                cookie_resp = await hook_client.post(
                    f"/api/v1/hooks/github/{gh_conn_id}",
                    content=raw_wf_run,
                    headers={
                        "Content-Type": "application/json",
                        "Cookie": "red2pr_session=forged-browser-cookie",
                        "X-GitHub-Event": "workflow_run",
                        "X-GitHub-Delivery": "deliv-cookie-01",
                        "X-Hub-Signature-256": _gh_hmac_header(gh_secret, raw_wf_run),
                    },
                )
                assert cookie_resp.status_code == 400, cookie_resp.text
                assert cookie_resp.json()["code"] == "cookie_auth_forbidden_on_webhook"

                # 3. Pinned `gitlab_signed_v19` missing `webhook-signature` -> 401 (`SEC-027`)
                caplog.clear()
                raw_gl_pipe = (GL_FIXTURES_DIR / "webhook_pipeline_failed.json").read_bytes()
                downgrade_resp = await hook_client.post(
                    f"/api/v1/hooks/gitlab/{gl_conn_id}",
                    content=raw_gl_pipe,
                    headers={
                        "Content-Type": "application/json",
                        "X-Gitlab-Event": "Pipeline Hook",
                        "X-Gitlab-Token": gl_whsec,
                    },
                )
                assert downgrade_resp.status_code == 401, downgrade_resp.text
                assert downgrade_resp.json()["code"] == "invalid_webhook_auth"
                assert gl_whsec not in downgrade_resp.text
                for rec in caplog.records:
                    assert gl_whsec not in rec.getMessage()

                # 4. Mismatched GitHub `installation.id` -> 403 (`SEC-001`)
                spoof_obj = json.loads(raw_wf_run.decode("utf-8"))
                spoof_obj["installation"]["id"] = 77777
                raw_spoof = json.dumps(spoof_obj).encode("utf-8")
                spoof_resp = await hook_client.post(
                    f"/api/v1/hooks/github/{gh_conn_id}",
                    content=raw_spoof,
                    headers={
                        "Content-Type": "application/json",
                        "X-GitHub-Event": "workflow_run",
                        "X-GitHub-Delivery": "deliv-spoof-install-01",
                        "X-Hub-Signature-256": _gh_hmac_header(gh_secret, raw_spoof),
                    },
                )
                assert spoof_resp.status_code == 403, spoof_resp.text
                assert spoof_resp.json()["code"] == "webhook_installation_mismatch"

                # Zero inbox rows persisted across all rejected deliveries!
                async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
                    assert (await db.scalar(select(func.count(WebhookInboxModel.id)))) == 0
                    deny_audits = list(
                        (
                            await db.scalars(
                                select(AuditLogModel).where(
                                    AuditLogModel.workspace_id == ws_id,
                                    AuditLogModel.decision == "deny",
                                )
                            )
                        ).all()
                    )
                    assert len(deny_audits) >= 3

                # 5. Stale >6h replay where live run is now `success` -> `ignored_stale_replay`
                harness.state.gh_live_runs["5088"] = {
                    "id": 5088,
                    "run_attempt": 1,
                    "head_branch": "main",
                    "head_sha": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b25088",
                    "event": "push",
                    "status": "completed",
                    "conclusion": "success",
                    "head_repository": {"id": 700101, "fork": False},
                }
                stale_obj = json.loads(raw_wf_run.decode("utf-8"))
                stale_obj["workflow_run"]["id"] = 5088
                stale_obj["workflow_run"]["updated_at"] = "2026-10-27T01:00:00Z"
                raw_stale = json.dumps(stale_obj).encode("utf-8")
                stale_resp = await hook_client.post(
                    f"/api/v1/hooks/github/{gh_conn_id}",
                    content=raw_stale,
                    headers={
                        "Content-Type": "application/json",
                        "X-GitHub-Event": "workflow_run",
                        "X-GitHub-Delivery": "deliv-stale-5088",
                        "X-Hub-Signature-256": _gh_hmac_header(gh_secret, raw_stale),
                    },
                )
                assert stale_resp.status_code == 202, stale_resp.text
                assert stale_resp.json()["disposition"] == "ignored_stale_replay"
                assert stale_resp.json()["trigger_id"] is None

                # 6. Simulated DB persistence outage -> MUST return 503 (NEVER false 2xx, `NFR-01`)
                def _broken_session_factory() -> Any:
                    raise OSError("Simulated PostgreSQL disk/socket outage")

                broken_webhook_svc = WebhookIngestService(
                    session_factory=_broken_session_factory,  # type: ignore[arg-type]
                    github_adapter=harness.gh_adapter,
                    gitlab_adapter=harness.gl_adapter,
                    integration_service=harness.integration_service,
                    redactor=harness.redactor,
                    clock=clock,
                )
                harness.api_app.state.webhook_ingest_service = broken_webhook_svc
                outage_resp = await hook_client.post(
                    f"/api/v1/hooks/github/{gh_conn_id}",
                    content=raw_wf_run,
                    headers={
                        "Content-Type": "application/json",
                        "X-GitHub-Event": "workflow_run",
                        "X-GitHub-Delivery": "deliv-outage-5001",
                        "X-Hub-Signature-256": _gh_hmac_header(gh_secret, raw_wf_run),
                    },
                )
                assert outage_resp.status_code == 503, outage_resp.text
                assert outage_resp.json()["code"] == "webhook_persistence_unavailable"
        finally:
            gh_logger.removeHandler(caplog.handler)
            gl_logger.removeHandler(caplog.handler)
    finally:
        await admin_client.aclose()
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_t_src_04_resumable_polling_etag_rollback_429_gap_reconciler_and_revocation(
    migrated_db: PgTestUrls,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify `T-SRC-04-P`, `T-SRC-04-N`, `SEC-010`, `SEC-011`, `NFR-04` & `verify_audit_chain`."""
    clock = ManualClock()
    harness = _build_u11_harness(migrated_db.app_url, clock=clock)
    gh_secret = "ghwh_poll_test_secret_1234567890"

    transport = httpx.ASGITransport(app=harness.api_app)
    admin_client, csrf, _, ws_id = await _claim_owner_and_workspace(transport, harness.iam)

    viewer_dto = await harness.iam.provision_local_user(
        display_name="Scoped Viewer",
        email="viewer.u11@red2pr.local",
        password=MEMBER_CREDENTIAL,
    )
    viewer_client = httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL)
    v_pre_csrf = (await viewer_client.get("/api/v1/auth/csrf")).json()["csrf_token"]
    v_login = await viewer_client.post(
        "/api/v1/auth/login",
        headers=_csrf_headers(v_pre_csrf),
        json={"identifier": "viewer.u11@red2pr.local", "password": MEMBER_CREDENTIAL},
    )
    assert v_login.status_code == 200, v_login.text

    try:
        gh_conn_id, gh_repo_1 = await _seed_ready_connection_and_repo(
            harness,
            admin_client=admin_client,
            csrf=csrf,
            ws_slug="acme",
            ws_id=ws_id,
            provider="github",
            auth_mode="github_app",
            webhook_secret=gh_secret,
            external_repo_id="700101",
            repo_name="acme-platform/payments-service",
            now=clock(),
        )
        # Add a second repository that the viewer does NOT have a RepoGrant for (`SEC-010`)
        gh_repo_2 = new_uuid7(now=clock())
        async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
            db.add(
                RepositoryModel(
                    id=gh_repo_2,
                    workspace_id=ws_id,
                    provider_connection_id=gh_conn_id,
                    external_repo_id="700102",
                    name="acme-platform/secret-treasury",
                    default_branch="main",
                    visibility="private",
                    mode="monitor",
                    paused=False,
                    active=True,
                    archived=False,
                    is_fork=False,
                    policy_revision=1,
                    tags_json=[],
                    workflow_hazard_status="clean",
                    workflow_hazards_json=[],
                    auto_repair_blocked=False,
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
            await db.flush()

        # Grant viewer role ONLY on gh_repo_1
        inv_resp = await admin_client.post(
            "/api/v1/workspaces/acme/invitations",
            headers=_csrf_headers(csrf),
            json={
                "email": "viewer.u11@red2pr.local",
                "role": "viewer",
                "repository_grants": [gh_repo_1],
            },
        )
        assert inv_resp.status_code == 201, inv_resp.text
        v_csrf = v_login.json()["csrf_token"]
        acc_resp = await viewer_client.post(
            "/api/v1/invitations/accept",
            headers=_csrf_headers(v_csrf),
            json={"token": inv_resp.json()["invite_token"]},
        )
        assert acc_resp.status_code == 200, acc_resp.text
        _ = viewer_dto

        # 1. Atomic rollback proof: if trigger persistence raises mid-poll, cursor MUST NOT advance!
        import red2pr_control.integrations.poller as poller_mod
        from red2pr_control.integrations import (
            record_normalized_run_failure_trigger as orig_record,
        )

        async def _exploding_record(*args: Any, **kwargs: Any) -> Any:
            raise OperationalError("SELECT 1", {}, Exception("simulated mid-poll commit crash"))

        monkeypatch.setattr(poller_mod, "record_normalized_run_failure_trigger", _exploding_record)
        with pytest.raises(OperationalError):
            await harness.poller.poll_repository(
                workspace_id=ws_id,
                connection_id=gh_conn_id,
                repository_id=gh_repo_1,
                correlation_id="corr-rollback-test",
                force_poll=True,
            )
        monkeypatch.setattr(poller_mod, "record_normalized_run_failure_trigger", orig_record)

        async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
            rolled_back_cursor = await db.scalar(
                select(ProviderSyncCursorModel).where(
                    ProviderSyncCursorModel.workspace_id == ws_id,
                    ProviderSyncCursorModel.repository_id == gh_repo_1,
                )
            )
            assert rolled_back_cursor is None  # Entire transaction rolled back cleanly!

        # 2. Healthy initial poll -> records failure trigger & caches ETag + high_water_mark_at
        poll_1 = await harness.poller.poll_connection(
            workspace_id=ws_id,
            connection_id=gh_conn_id,
            force_poll=False,
        )
        assert poll_1.polled_repository_count == 2
        assert poll_1.triggers_created_count == 2  # 5001:1 on repo 1 & repo 2

        # Advance clock 70s (>60s + jitter) -> sends If-None-Match + 5m overlap, gets 304!
        clock.advance(seconds=70)
        harness.state.gh_poll_requests.clear()
        poll_2 = await harness.poller.poll_connection(
            workspace_id=ws_id,
            connection_id=gh_conn_id,
            repository_ids=[gh_repo_1],
            force_poll=False,
        )
        assert poll_2.outcomes[0].cursor.last_status == "not_modified"
        assert poll_2.triggers_created_count == 0
        assert harness.state.gh_poll_requests[-1]["if_none_match"] == 'W/"gh-poll-v1"'
        # 5m overlap: fixture newest updated_at is 14:59:30Z -> 14:54:30Z
        assert harness.state.gh_poll_requests[-1]["created"] == ">=2026-10-27T14:54:30Z"

        # 3. `429 Retry-After` backoff (`T-SRC-04-N`): honors cooldown without storming upstream!
        clock.advance(seconds=70)
        harness.state.gh_poll_mode = "rate_limit"
        harness.state.gh_poll_retry_after = "180"
        poll_rl = await harness.poller.poll_repository(
            workspace_id=ws_id,
            connection_id=gh_conn_id,
            repository_id=gh_repo_1,
            correlation_id="corr-rl-1",
            force_poll=True,
        )
        assert poll_rl is not None
        assert poll_rl.rate_limited is True
        assert poll_rl.cursor.last_status == "rate_limited"

        # Reconcile BEFORE 180s cooldown makes ZERO upstream poll calls (`complete_recovery=False`)
        clock.advance(seconds=30)
        harness.state.gh_poll_requests.clear()
        rec_rl_resp = await admin_client.post(
            f"/api/v1/workspaces/acme/integrations/{gh_conn_id}/reconcile",
            headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            json={"repository_ids": [gh_repo_1], "force_poll": True},
        )
        assert rec_rl_resp.status_code == 200, rec_rl_resp.text
        assert rec_rl_resp.json()["rate_limited_count"] == 1
        assert rec_rl_resp.json()["complete_recovery"] is False
        assert len(harness.state.gh_poll_requests) == 0  # Zero upstream storming!

        # 4. Offline >90d TTL gap (`T-SRC-04-N`): 95d advance -> `gap_detected`
        clock.advance(days=95)
        harness.state.gh_poll_mode = "ok"

        # Refresh browser sessions after advancing clock 95 days past session TTL
        admin_pre_csrf = (await admin_client.get("/api/v1/auth/csrf")).json()["csrf_token"]
        admin_relogin = await admin_client.post(
            "/api/v1/auth/login",
            headers=_csrf_headers(admin_pre_csrf),
            json={"identifier": "owner.u11@red2pr.local", "password": OWNER_CREDENTIAL},
        )
        assert admin_relogin.status_code == 200, admin_relogin.text
        csrf = admin_relogin.json()["csrf_token"]

        v_pre_csrf_2 = (await viewer_client.get("/api/v1/auth/csrf")).json()["csrf_token"]
        v_relogin = await viewer_client.post(
            "/api/v1/auth/login",
            headers=_csrf_headers(v_pre_csrf_2),
            json={"identifier": "viewer.u11@red2pr.local", "password": MEMBER_CREDENTIAL},
        )
        assert v_relogin.status_code == 200, v_relogin.text
        v_csrf = v_relogin.json()["csrf_token"]

        rec_gap_resp = await admin_client.post(
            f"/api/v1/workspaces/acme/integrations/{gh_conn_id}/reconcile",
            headers=_csrf_headers(csrf, idem_key=new_uuid7(now=clock())),
            json={"repository_ids": [gh_repo_1], "force_poll": True},
        )
        assert rec_gap_resp.status_code == 200, rec_gap_resp.text
        assert rec_gap_resp.json()["history_gap_count"] == 1
        assert rec_gap_resp.json()["complete_recovery"] is False
        gap_cursor = next(
            c for c in rec_gap_resp.json()["sync_cursors"] if c["repository_id"] == gh_repo_1
        )
        assert gap_cursor["history_gap_detected"] is True

        # Viewer GET detail sees ONLY gh_repo_1 cursor (`SEC-010`); POST /reconcile is 403!
        v_detail = await viewer_client.get(f"/api/v1/workspaces/acme/integrations/{gh_conn_id}")
        assert v_detail.status_code == 200, v_detail.text
        assert [c["repository_id"] for c in v_detail.json()["sync_cursors"]] == [gh_repo_1]

        v_forbid = await viewer_client.post(
            f"/api/v1/workspaces/acme/integrations/{gh_conn_id}/reconcile",
            headers=_csrf_headers(v_csrf, idem_key=new_uuid7(now=clock())),
            json={"force_poll": True},
        )
        assert v_forbid.status_code == 403

        # Admin explicitly acknowledges gap (`acknowledge_history_gap=True`) + S-05 replay!
        ack_idem = new_uuid7(now=clock())
        ack_resp_1 = await admin_client.post(
            f"/api/v1/workspaces/acme/integrations/{gh_conn_id}/reconcile",
            headers=_csrf_headers(csrf, idem_key=ack_idem),
            json={
                "repository_ids": [gh_repo_1],
                "acknowledge_history_gap": True,
                "force_poll": True,
            },
        )
        assert ack_resp_1.status_code == 200, ack_resp_1.text
        assert ack_resp_1.json()["history_gap_count"] == 0

        ack_resp_2 = await admin_client.post(
            f"/api/v1/workspaces/acme/integrations/{gh_conn_id}/reconcile",
            headers=_csrf_headers(csrf, idem_key=ack_idem),
            json={
                "repository_ids": [gh_repo_1],
                "acknowledge_history_gap": True,
                "force_poll": True,
            },
        )
        assert ack_resp_2.status_code == 200
        assert (
            ack_resp_2.json()["receipt"]["operation_id"]
            == ack_resp_1.json()["receipt"]["operation_id"]
        )

        # 5. Pagination flood gap (`unbridged_pagination_gap`) -> honest `gap_detected`
        harness.state.gh_poll_mode = "pagination_flood"
        flood_outcome = await harness.poller.poll_repository(
            workspace_id=ws_id,
            connection_id=gh_conn_id,
            repository_id=gh_repo_1,
            correlation_id="corr-flood-gap",
            force_poll=True,
        )
        assert flood_outcome is not None
        assert flood_outcome.history_gap_detected is True
        assert flood_outcome.cursor.last_error_code == "catchup_pagination_window_exceeded"
        harness.state.gh_poll_mode = "ok"

        # 6. `MissedEventReconciler` resolves early `workflow_job` (`reconcile_pending`)
        now_iso = clock().isoformat().replace("+00:00", "Z")
        harness.state.gh_live_runs["5077"] = {
            "id": 5077,
            "run_attempt": 1,
            "head_branch": "main",
            "head_sha": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c35077",
            "event": "push",
            "status": "in_progress",
            "conclusion": None,
            "created_at": now_iso,
            "updated_at": now_iso,
            "head_repository": {"id": 700101, "fork": False},
        }
        job_obj = json.loads(
            (GH_FIXTURES_DIR / "webhook_workflow_job_failed.json").read_text(encoding="utf-8")
        )
        job_obj["workflow_job"]["run_id"] = 5077
        job_obj["workflow_job"]["started_at"] = now_iso
        job_obj["workflow_job"]["completed_at"] = now_iso
        raw_early_job = json.dumps(job_obj).encode("utf-8")

        async with httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL) as hook_client:
            early_resp = await hook_client.post(
                f"/api/v1/hooks/github/{gh_conn_id}",
                content=raw_early_job,
                headers={
                    "Content-Type": "application/json",
                    "X-GitHub-Event": "workflow_job",
                    "X-GitHub-Delivery": "deliv-early-job-5077",
                    "X-Hub-Signature-256": _gh_hmac_header(gh_secret, raw_early_job),
                },
            )
            assert early_resp.status_code == 202, early_resp.text
            assert early_resp.json()["disposition"] == "reconcile_scheduled"
            assert early_resp.json()["status"] == "reconcile_pending"

        harness.state.gh_live_runs["5077"] = {
            "id": 5077,
            "run_attempt": 1,
            "head_branch": "main",
            "head_sha": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c35077",
            "event": "push",
            "status": "completed",
            "conclusion": "failure",
            "created_at": now_iso,
            "updated_at": now_iso,
            "head_repository": {"id": 700101, "fork": False},
        }
        sweeps = await harness.reconciler.reconcile_all_connections()
        assert sum(s.resolved_count for s in sweeps) == 1
        assert sum(s.triggers_created_count for s in sweeps) == 1

        # 7. `SEC-011` upstream `401` revocation cascade during poll + intact audit hash chain
        harness.state.gh_revoked = True
        rev_outcome = await harness.poller.poll_repository(
            workspace_id=ws_id,
            connection_id=gh_conn_id,
            repository_id=gh_repo_1,
            correlation_id="corr-poll-revoke",
            force_poll=True,
        )
        assert rev_outcome is not None
        assert rev_outcome.cursor.last_status == "revoked"

        with tempfile.TemporaryDirectory(prefix="red2pr_u11_ckpt_") as ckpt_dir:
            ckpt_store = ExternalCheckpointStore(Path(ckpt_dir) / "audit_ckpt.json")
            async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as ws_db:
                conn_after = await ws_db.scalar(
                    select(ProviderConnectionModel).where(ProviderConnectionModel.id == gh_conn_id)
                )
                assert conn_after is not None and conn_after.status == "revoked"

            async with instance_rls_session(harness.app_factory, mode="audit_verifier") as audit_db:
                entries_checked = await verify_audit_chain(
                    audit_db,
                    external_store=ckpt_store,
                    keyring=KeyRing(),
                )
                assert entries_checked >= 8
    finally:
        await viewer_client.aclose()
        await admin_client.aclose()
        await harness.app_engine.dispose()
