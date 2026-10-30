"""PostgreSQL 16 + Hypothesis Repository Catalog & Versioned Policy Engine Suite (`U12`).

Verifies against a real disposable PostgreSQL 16 instance (`pgserver` / `fsync=on`):
- `0008_repository_policies` expand/contract reversibility (`downgrade -> upgrade`), `>= 36`
  `FORCE ROW LEVEL SECURITY` tables, PL/pgSQL immutability trigger (`SQLSTATE 55000` on
  `UPDATE` or standalone `DELETE`, cascade delete allowed on parent `repositories`), and
  cross-workspace RLS tenant isolation (`SEC-032`).
- Hypothesis property-based fuzzing for `glob_guard` (`SEC-007` traversal, null/control,
  backslash, root/drive, empty-segment rejection; `SEC-009` case-folded protected CI/lockfile/
  secret globs never bypassing `deny` / `requires_approval`) and `policy_engine`
  (`deny > allow`, `hard_invariant > instance > workspace > repository`).
- `T-REP-01-P` & `T-REP-01-N`: `S-04` cursor pagination, provider/mode/hazard/paused/tag/q
  filters, `partial_sync_connection_ids` visibility, and `UX-02` / `SEC-010` zero-leakage
  proof (ungranted repos, tags, orgs, and counts never leak in `listRepositories` or direct
  `GET`/`PATCH`/`POST .../previews`).
- `T-REP-02-P` & `T-REP-02-N`: immutable `v1 -> v2 -> v3` policy snapshots, `ETag`/`If-Match`
  `412` + `expected_revision` `409` guards, `5m` MFA `step_up` enforcement, `SEC-031` hazard
  & `worker_readiness` & private-repo `inference` consent & `W-02` `grant_review_required`
  safety gates, `SEC-022` live in-transaction role downgrade (`403` + `security.policy.denied`
  outbox & audit denial), `ADR-033` `monitor` mode & `paused=True` queue draining + webhook
  gating, zero-mutation dry-run simulator (`POST .../policy/previews`), atomic bulk update
  rollback (`POST /repositories/bulk-update`), `SetupWizardService` `repo_policy` probe, and
  `verify_audit_chain` integrity.
- `T-REP-03-P` & `T-REP-03-N`: branch/file `deny` overriding `allow`, `../` & `.env`/`.git`
  hard-denied, `.github/workflows/**` / `.gitlab-ci.yml` / `uv.lock` / `Dockerfile` /
  `alembic/**` escalating to `requires_approval`, and `tests/**` / `pyproject.toml` gated by
  `allow_test_edits` / `allow_config_edits` (never auto-publishing without human approval).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import sys
import tempfile
from collections.abc import AsyncIterator, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx
import pgserver
import pytest
from fastapi import FastAPI
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from py_contracts.crypto import KeyRing, MasterKeyRing
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import (
    ExternalCheckpointStore,
    verify_audit_chain,
)
from red2pr_control.api.app import create_app
from red2pr_control.core.config import load_config
from red2pr_control.core.egress import EgressPolicyEngine, InMemoryCaBundleResolver
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.base import (
    AuditLogModel,
    ConsentModel,
    InstanceModel,
    MembershipModel,
    OutboxEventModel,
    ProviderConnectionModel,
    ProviderSyncCursorModel,
    RepositoryModel,
    RepositoryPolicyModel,
    SetupCheckpointModel,
    TaskJobModel,
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
    GitHubAppAdapter,
    GitLabAdapter,
    ProviderIntegrationService,
    WebhookIngestService,
)
from red2pr_control.operations.setup_wizard import (
    DbEndpointAllowlistProvider,
    SetupStepRegistry,
    SetupWizardService,
)
from red2pr_control.orchestrator import DurableTaskQueueService, OperationReceiptService
from red2pr_control.repositories import (
    HARD_DENIED_PATH_GLOBS,
    PROTECTED_SENSITIVE_PATH_GLOBS,
    PathCanonicalizationError,
    PolicyHierarchyContext,
    RepositoryCatalogService,
    WorkspacePolicyLayer,
    build_default_repository_policy,
    canonicalize_glob_pattern,
    canonicalize_repo_path,
    evaluate_branch_policy,
    evaluate_patch_paths,
    evaluate_path_policy,
    resolve_effective_policy,
)
from red2pr_control.secrets.broker import (
    SecretBroker,
    SecretBrokerProviderVault,
    SecretBrokerTotpVault,
)

APP_ROLE_NAME = "red2pr_app"
APP_ROLE_PASSWORD = "red2pr_app_local_test_pw_12"
PUBLIC_BASE_URL = "http://127.0.0.1:4280"
ORIGIN_HEADERS = {"Origin": PUBLIC_BASE_URL}
OWNER_CREDENTIAL = "OwnerSup3rStr0ng!Pass#32"
MAINTAINER_CREDENTIAL = "MaintSup3rStr0ng!Pass#32"
VIEWER_CREDENTIAL = "ViewrSup3rStr0ng!Pass#32"


class ManualClock:
    """Deterministic controllable UTC clock for step-up windows & policy timestamps."""

    def __init__(self, initial: datetime | None = None) -> None:
        self._current = (initial or datetime(2026, 10, 28, 9, 0, 0, tzinfo=UTC)).astimezone(UTC)

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
    if_match: str | None = None,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    headers: dict[str, str] = {"X-CSRF-Token": token, **ORIGIN_HEADERS}
    if idem_key is not None:
        headers["Idempotency-Key"] = idem_key
    if if_match is not None:
        headers["If-Match"] = if_match
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


@pytest.fixture(scope="module")
def pg_urls() -> Iterator[PgTestUrls]:
    ensure_compatible_event_loop()
    with (
        tempfile.TemporaryDirectory(prefix="red2pr_u12_pg_") as tmp_dir,
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
    run_alembic_downgrade(pg_urls.admin_url, "base", app_role_name=APP_ROLE_NAME)
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
    yield pg_urls


@dataclass
class U12Harness:
    app_engine: AsyncEngine
    app_factory: async_sessionmaker[AsyncSession]
    iam: IamService
    redactor: Redactor
    provider_vault: SecretBrokerProviderVault
    setup_registry: SetupStepRegistry
    setup_service: SetupWizardService
    queue_service: DurableTaskQueueService
    catalog_service: RepositoryCatalogService
    webhook_service: WebhookIngestService
    api_app: FastAPI
    clock: ManualClock


def _build_u12_harness(app_url: str, *, clock: ManualClock) -> U12Harness:
    app_engine = create_app_engine(app_url, pool_size=8, max_overflow=8)
    app_factory = create_session_factory(app_engine)
    redactor = Redactor()
    kek_ring = MasterKeyRing(active_version=1, keys={1: b"\x6b" * 32})
    broker = SecretBroker(key_ring=kek_ring, redactor=redactor)
    totp_vault = SecretBrokerTotpVault(broker)
    provider_vault = SecretBrokerProviderVault(broker)

    iam = IamService(
        session_factory=app_factory,
        totp_vault=totp_vault,
        iam_seed_key=b"\x5a" * 32,
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
    )
    gl_adapter = GitLabAdapter(
        vault=provider_vault,
        egress_policy=egress_engine,
        ca_bundle_resolver=InMemoryCaBundleResolver({}),
        redactor=redactor,
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
    setup_registry = SetupStepRegistry()
    setup_service = SetupWizardService(
        iam_service=iam,
        step_registry=setup_registry,
        redactor=redactor,
    )
    receipt_service = OperationReceiptService(session_factory=app_factory)
    queue_service = DurableTaskQueueService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        redactor=redactor,
    )
    cfg = load_config()
    catalog_service = RepositoryCatalogService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        instance_config=cfg,
        redactor=redactor,
        clock=clock,
    )
    api_app = create_app(
        iam_service=iam,
        setup_wizard_service=setup_service,
        setup_step_registry=setup_registry,
        task_queue_service=queue_service,
        operation_receipt_service=receipt_service,
        github_integration_service=integration_service,
        webhook_ingest_service=webhook_service,
        repository_catalog_service=catalog_service,
    )
    return U12Harness(
        app_engine=app_engine,
        app_factory=app_factory,
        iam=iam,
        redactor=redactor,
        provider_vault=provider_vault,
        setup_registry=setup_registry,
        setup_service=setup_service,
        queue_service=queue_service,
        catalog_service=catalog_service,
        webhook_service=webhook_service,
        api_app=api_app,
        clock=clock,
    )


async def _claim_owner_and_workspace(
    harness: U12Harness,
    client: httpx.AsyncClient,
    *,
    slug: str = "acme",
    name: str = "Acme Platform",
) -> tuple[str, str, str]:
    """Claim bootstrap instance owner, return `(owner_user_id, ws_id, csrf_token)`."""
    raw_boot, _ = await harness.iam.issue_bootstrap_token()
    boot = await client.get("/api/v1/auth/csrf")
    assert boot.status_code == 200
    csrf = boot.json()["csrf_token"]

    claim = await client.post(
        "/api/v1/setup/claim",
        json={
            "bootstrap_token": raw_boot,
            "email": "owner@red2pr.local",
            "display_name": "Instance Owner",
            "password": OWNER_CREDENTIAL,
        },
        headers=_csrf_headers(csrf),
    )
    assert claim.status_code == 201, claim.text
    owner_id = claim.json()["user"]["id"]
    csrf = claim.json()["csrf_token"]

    ws_resp = await client.post(
        "/api/v1/workspaces",
        json={"name": name, "slug": slug},
        headers=_csrf_headers(csrf, idem_key=new_uuid7()),
    )
    assert ws_resp.status_code == 201, ws_resp.text
    ws_id = ws_resp.json()["id"]
    return owner_id, ws_id, csrf


async def _invite_and_accept_member(
    harness: U12Harness,
    owner_client: httpx.AsyncClient,
    owner_csrf: str,
    *,
    ws_slug: str,
    email: str,
    display_name: str,
    password: str,
    role: str,
    repo_grants: list[str],
) -> tuple[httpx.AsyncClient, str, str]:
    """Provision local user, create workspace invitation, and accept in a fresh client."""
    user_dto = await harness.iam.provision_local_user(
        display_name=display_name,
        email=email,
        password=password,
    )
    member_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=harness.api_app),
        base_url=PUBLIC_BASE_URL,
    )
    m_boot = await member_client.get("/api/v1/auth/csrf")
    m_pre_csrf = m_boot.json()["csrf_token"]

    login_resp = await member_client.post(
        "/api/v1/auth/login",
        json={"identifier": email, "password": password},
        headers=_csrf_headers(m_pre_csrf),
    )
    assert login_resp.status_code == 200, login_resp.text
    m_csrf = login_resp.json()["csrf_token"]

    inv_resp = await owner_client.post(
        f"/api/v1/workspaces/{ws_slug}/invitations",
        json={
            "email": email,
            "role": role,
            "repository_grants": repo_grants,
        },
        headers=_csrf_headers(owner_csrf, idem_key=new_uuid7()),
    )
    assert inv_resp.status_code == 201, inv_resp.text
    invite_token = inv_resp.json()["invite_token"]

    acc_resp = await member_client.post(
        "/api/v1/invitations/accept",
        json={"token": invite_token},
        headers=_csrf_headers(m_csrf, idem_key=new_uuid7()),
    )
    assert acc_resp.status_code == 200, acc_resp.text
    return member_client, user_dto.id, m_csrf


async def _seed_connection_and_repo(
    harness: U12Harness,
    *,
    ws_id: str,
    provider: str = "github",
    external_repo_id: str = "700101",
    name: str = "acme/payments-service",
    visibility: str = "private",
    mode: str = "monitor",
    paused: bool = False,
    tags: list[str] | None = None,
    hazard_status: str = "clean",
    auto_repair_blocked: bool = False,
    grant_review_required: bool = False,
    partial_sync: bool = False,
    webhook_secret: str | None = None,
) -> tuple[str, str]:
    """Insert a `ProviderConnectionModel`, `RepositoryModel`, and initial `revision=1` policy."""
    conn_id = new_uuid7()
    repo_id = new_uuid7()
    pol_id = new_uuid7()
    now = harness.clock()

    default_pol = build_default_repository_policy()

    async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
        wh_ref: str | None = None
        wh_ver: int | None = None
        if webhook_secret is not None:
            wh_ref, wh_ver = await harness.provider_vault.store_provider_credential(
                db,
                workspace_id=ws_id,
                plaintext=webhook_secret.encode("utf-8"),
                purpose="webhook_auth",
                now=now,
            )

        conn = ProviderConnectionModel(
            id=conn_id,
            workspace_id=ws_id,
            provider=provider,
            display_name=f"{provider}-{external_repo_id}",
            base_url="https://api.github.com" if provider == "github" else "https://gitlab.com",
            auth_mode="github_app" if provider == "github" else "gitlab_signed_v19",
            external_installation_id=f"99{external_repo_id}" if provider == "github" else None,
            webhook_secret_ref=wh_ref,
            webhook_secret_version=wh_ver,
            status="degraded" if partial_sync else "ready",
            grant_review_required=False,
        )
        db.add(conn)
        await db.flush()

        hazards_json: list[dict[str, Any]] = []
        if hazard_status == "flagged":
            hazards_json = [
                {
                    "code": "pull_request_target",
                    "severity": "high",
                    "workflow_path": ".github/workflows/pr-target.yml",
                    "detail": "pull_request_target checks out untrusted PR head SHA.",
                }
            ]

        repo = RepositoryModel(
            id=repo_id,
            workspace_id=ws_id,
            provider_connection_id=conn_id,
            external_repo_id=external_repo_id,
            name=name,
            default_branch="main",
            visibility=visibility,
            mode=mode,
            paused=paused,
            policy_revision=1,
            tags_json=list(tags or []),
            archived=False,
            is_fork=False,
            workflow_hazard_status=hazard_status,
            workflow_hazards_json=hazards_json,
            auto_repair_blocked=auto_repair_blocked,
            grant_review_required=grant_review_required,
            active=True,
            last_synced_at=now,
        )
        db.add(repo)
        await db.flush()

        pol = RepositoryPolicyModel(
            id=pol_id,
            workspace_id=ws_id,
            repository_id=repo_id,
            revision=1,
            mode=mode,
            paused=paused,
            branch_allowlist_json=list(default_pol.branch_allowlist),
            branch_denylist_json=list(default_pol.branch_denylist),
            file_allowlist_json=list(default_pol.file_allowlist),
            file_denylist_json=list(default_pol.file_denylist),
            sensitive_rules_json=list(default_pol.sensitive_rules),
            required_check_names_json=["build"],
            allow_test_edits=default_pol.allow_test_edits,
            allow_config_edits=default_pol.allow_config_edits,
            max_attempts=default_pol.max_attempts,
            max_diff_lines=default_pol.max_diff_lines,
            max_calls_per_session=default_pol.max_calls_per_session,
            max_tokens_per_session=default_pol.max_tokens_per_session,
            max_wall_seconds=default_pol.max_wall_seconds,
            max_cost_per_session_amount=None,
            max_cost_currency=None,
            require_baseline=True,
            inference_consent_id=None,
            runtime_profile_id=default_pol.runtime_profile_id,
            change_reason="Initial repository policy snapshot.",
            created_by_user_id=None,
        )
        db.add(pol)

        cursor = ProviderSyncCursorModel(
            id=new_uuid7(),
            workspace_id=ws_id,
            repository_id=repo_id,
            connection_id=conn_id,
            provider=provider,
            last_status="ok",
            last_polled_at=now,
            last_success_at=now,
        )
        db.add(cursor)
        await db.commit()

    return conn_id, repo_id


async def _enable_worker_and_inference_readiness(
    harness: U12Harness,
    *,
    owner_user_id: str,
    ws_id: str,
) -> str:
    """Seed verified `worker_readiness` checkpoint and workspace `inference` consent."""
    consent_id = new_uuid7()
    now = harness.clock()
    async with instance_rls_session(harness.app_factory, mode="instance_admin") as inst_db:
        inst_row = await inst_db.scalar(select(InstanceModel))
        assert inst_row is not None
        ckpt = await inst_db.scalar(
            select(SetupCheckpointModel).where(SetupCheckpointModel.phase == "worker_readiness")
        )
        if ckpt is None:
            inst_db.add(
                SetupCheckpointModel(
                    id=new_uuid7(),
                    instance_id=inst_row.id,
                    phase="worker_readiness",
                    phase_order=7,
                    status="completed",
                    is_current_phase=False,
                    checkpoint_token="ckpt_u12_worker",
                    draft_payload_json={"sandbox_backend": "docker_rootless"},
                    probe_status="passed",
                    probe_detail="Isolated rootless Docker sandbox verified.",
                    completed_by_user_id=owner_user_id,
                    completed_at=now,
                )
            )
        else:
            ckpt.status = "completed"
            ckpt.probe_status = "passed"
            ckpt.completed_by_user_id = owner_user_id
            ckpt.completed_at = now

        inst_db.add(
            ConsentModel(
                id=consent_id,
                purpose="inference",
                scope="workspace",
                workspace_id=ws_id,
                repository_id=None,
                destination="https://api.llama.com/v1",
                data_classes_json=["public", "workspace_internal", "restricted"],
                granted_by_user_id=owner_user_id,
                granted_at=now,
                policy_version=1,
            )
        )
        await inst_db.commit()
    return consent_id


async def test_u12_migration_0008_reversibility_rls_and_immutability_trigger(
    migrated_db: PgTestUrls,
) -> None:
    """Verify 0008 expand/contract downgrade->upgrade, 36 RLS tables, and SQLSTATE 55000 trigger."""
    # Reversibility: downgrade to 0007 and upgrade back to head cleanly
    run_alembic_downgrade(
        migrated_db.admin_url,
        "0007_webhook_inbox_sync_cursors",
        app_role_name=APP_ROLE_NAME,
    )
    run_alembic_upgrade(
        migrated_db.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )

    admin_engine = create_admin_engine(migrated_db.admin_url)
    try:
        async with admin_engine.connect() as conn:
            forced_rows = (
                (
                    await conn.execute(
                        text(
                            "SELECT relname FROM pg_class c "
                            "JOIN pg_namespace n ON n.oid = c.relnamespace "
                            "WHERE n.nspname = 'public' AND c.relkind = 'r' "
                            "AND c.relrowsecurity IS TRUE AND c.relforcerowsecurity IS TRUE"
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert len(forced_rows) >= 36
            assert "repository_policies" in set(forced_rows)
    finally:
        await admin_engine.dispose()

    clock = ManualClock()
    harness = _build_u12_harness(migrated_db.app_url, clock=clock)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=harness.api_app),
            base_url=PUBLIC_BASE_URL,
        ) as client:
            _, ws_a_id, csrf = await _claim_owner_and_workspace(
                harness, client, slug="ws-a", name="WS A"
            )
            ws_b_resp = await client.post(
                "/api/v1/workspaces",
                json={"name": "WS B", "slug": "ws-b"},
                headers=_csrf_headers(csrf, idem_key=new_uuid7()),
            )
            assert ws_b_resp.status_code == 201
            ws_b_id = ws_b_resp.json()["id"]

        _, repo_a_id = await _seed_connection_and_repo(
            harness,
            ws_id=ws_a_id,
            name="ws-a/core-api",
        )

        # Cross-workspace RLS isolation (SEC-032): WS B session sees 0 rows of WS A policies
        async with workspace_rls_session(harness.app_factory, workspace_id=ws_b_id) as db_b:
            leaked = (
                await db_b.scalars(
                    select(RepositoryPolicyModel).where(
                        RepositoryPolicyModel.repository_id == repo_a_id
                    )
                )
            ).all()
            assert leaked == []

        # Immutability trigger: UPDATE on repository_policies rejected with SQLSTATE 55000
        with pytest.raises(DBAPIError) as upd_exc:
            async with workspace_rls_session(harness.app_factory, workspace_id=ws_a_id) as db_a:
                await db_a.execute(
                    text(
                        "UPDATE repository_policies SET mode = 'auto_repair' "
                        "WHERE repository_id = :rid"
                    ),
                    {"rid": repo_a_id},
                )
                await db_a.commit()
        assert "append_only_table_violation" in str(upd_exc.value).lower()

        # Immutability trigger: standalone DELETE on repository_policies rejected
        with pytest.raises(DBAPIError) as del_exc:
            async with workspace_rls_session(harness.app_factory, workspace_id=ws_a_id) as db_a:
                await db_a.execute(
                    text("DELETE FROM repository_policies WHERE repository_id = :rid"),
                    {"rid": repo_a_id},
                )
                await db_a.commit()
        assert "append_only_table_violation" in str(del_exc.value).lower()

        # Parent repository DELETE cascades cleanly without trigger rejection
        async with workspace_rls_session(harness.app_factory, workspace_id=ws_a_id) as db_a:
            await db_a.execute(
                text("DELETE FROM repositories WHERE id = :rid"),
                {"rid": repo_a_id},
            )
            await db_a.flush()
            remaining = await db_a.scalar(
                select(func.count())
                .select_from(RepositoryPolicyModel)
                .where(RepositoryPolicyModel.repository_id == repo_a_id)
            )
            assert remaining == 0
    finally:
        await harness.app_engine.dispose()


@settings(max_examples=60, deadline=None)
@given(
    seg_a=st.from_regex(r"[A-Za-z0-9_-]{1,12}", fullmatch=True),
    seg_b=st.from_regex(r"[A-Za-z0-9_-]{1,12}", fullmatch=True),
    attack_kind=st.sampled_from(
        [
            "dotdot_prefix",
            "dotdot_mid",
            "dot_seg",
            "leading_slash",
            "win_drive",
            "backslash",
            "double_slash",
            "null_byte",
        ]
    ),
)
def test_u12_hypothesis_sec007_canonicalizers_reject_all_traversal_and_separator_tricks(
    seg_a: str,
    seg_b: str,
    attack_kind: str,
) -> None:
    """Property: unsafe traversal/root/drive/backslash/control inputs never canonicalize."""
    payload_map = {
        "dotdot_prefix": f"../{seg_a}/{seg_b}.py",
        "dotdot_mid": f"{seg_a}/../{seg_b}.py",
        "dot_seg": f"./{seg_a}/{seg_b}.py",
        "leading_slash": f"/{seg_a}/{seg_b}.py",
        "win_drive": f"C:/{seg_a}/{seg_b}.py",
        "backslash": f"{seg_a}\\{seg_b}.py",
        "double_slash": f"{seg_a}//{seg_b}.py",
        "null_byte": f"{seg_a}/\x00{seg_b}.py",
    }
    malicious = payload_map[attack_kind]
    with pytest.raises(PathCanonicalizationError):
        canonicalize_repo_path(malicious)
    with pytest.raises(PathCanonicalizationError):
        canonicalize_glob_pattern(malicious)


@settings(max_examples=50, deadline=None)
@given(
    protected_sample=st.sampled_from(
        [
            ".github/workflows/ci.yml",
            ".GitHub/Workflows/Deploy.YML",
            ".gitlab-ci.yml",
            ".GITLAB-CI.YML",
            "uv.lock",
            "packages/api/UV.LOCK",
            "pnpm-lock.yaml",
            "Dockerfile",
            "services/worker/Dockerfile.prod",
            "alembic/versions/0008.py",
            "migrations/V1__init.sql",
            "auth/jwt.py",
            "AGENTS.md",
        ]
    ),
    hard_denied_sample=st.sampled_from(
        [
            ".env",
            ".ENV",
            "config/.env.production",
            ".git/config",
            ".GIT/hooks/pre-commit",
            "certs/private.PEM",
            "keys/id_ed25519",
            "secrets/prod.json",
        ]
    ),
    flip_upper=st.booleans(),
)
def test_u12_hypothesis_sec009_and_deny_precedence_never_allow_auto_publish(
    protected_sample: str,
    hard_denied_sample: str,
    flip_upper: bool,
) -> None:
    """Property: SEC-007 hard-deny & SEC-009 protected paths never evaluate to 'allow'."""
    assert len(HARD_DENIED_PATH_GLOBS) >= 8
    assert len(PROTECTED_SENSITIVE_PATH_GLOBS) >= 20

    cfg = load_config()
    ctx = PolicyHierarchyContext(
        instance_config=cfg,
        worker_isolation_ready=True,
        inference_consent_ready=True,
        workflow_hazard_blocked=False,
        grant_review_required=False,
        workspace_layer=WorkspacePolicyLayer(
            file_denylist=("vendor/**",),
        ),
    )
    permissive_policy = build_default_repository_policy(instance_config=cfg).model_copy(
        update={
            "file_allowlist": ["**"],
            "allow_test_edits": True,
            "allow_config_edits": True,
        }
    )
    effective = resolve_effective_policy(
        repo_mode="auto_repair",
        repo_paused=False,
        repo_policy=permissive_policy,
        ctx=ctx,
    )
    assert effective.effective_mode == "auto_repair"
    assert effective.allow_auto_publication is True

    prot_probe = protected_sample.upper() if flip_upper else protected_sample
    prot_eval = evaluate_path_policy(
        prot_probe,
        repo_policy=permissive_policy,
        effective_policy=effective,
        ctx=ctx,
    )
    assert prot_eval.verdict in {"requires_approval", "deny"}
    assert prot_eval.verdict != "allow"

    hard_probe = hard_denied_sample.upper() if flip_upper else hard_denied_sample
    hard_eval = evaluate_path_policy(
        hard_probe,
        repo_policy=permissive_policy,
        effective_policy=effective,
        ctx=ctx,
    )
    assert hard_eval.verdict == "deny"
    assert hard_eval.source_layer == "hard_invariant"

    # Workspace denylist overrides repository allowlist=["**"]
    ws_denied_eval = evaluate_path_policy(
        "vendor/lib/pkg.py",
        repo_policy=permissive_policy,
        effective_policy=effective,
        ctx=ctx,
    )
    assert ws_denied_eval.verdict == "deny"
    assert ws_denied_eval.source_layer == "workspace"


async def test_t_rep_01_p_and_n_catalog_pagination_filters_and_ux02_zero_leakage(
    migrated_db: PgTestUrls,
) -> None:
    """Verify S-04 catalog pagination, filters, partial-sync banner, and UX-02 zero leakage."""
    clock = ManualClock()
    harness = _build_u12_harness(migrated_db.app_url, clock=clock)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=harness.api_app),
            base_url=PUBLIC_BASE_URL,
        ) as admin_client:
            _, ws_id, admin_csrf = await _claim_owner_and_workspace(harness, admin_client)

            conn_ok_id, repo_a_id = await _seed_connection_and_repo(
                harness,
                ws_id=ws_id,
                provider="github",
                external_repo_id="700101",
                name="acme/payments-service",
                tags=["tier-1", "payments"],
                mode="monitor",
                paused=False,
                hazard_status="clean",
                partial_sync=True,
            )
            _, repo_b_id = await _seed_connection_and_repo(
                harness,
                ws_id=ws_id,
                provider="gitlab",
                external_repo_id="800202",
                name="acme/Search-Engine",
                tags=["tier-2", "search"],
                mode="approval",
                paused=False,
                hazard_status="clean",
            )
            _, repo_secret_id = await _seed_connection_and_repo(
                harness,
                ws_id=ws_id,
                provider="github",
                external_repo_id="900999",
                name="stealth-org/secret-payroll",
                tags=["classified-payroll"],
                mode="monitor",
                paused=True,
                hazard_status="flagged",
                auto_repair_blocked=True,
            )

            # Admin sees all 3 repositories, paginated via S-04 cursor
            p1 = await admin_client.get(
                "/api/v1/workspaces/acme/repositories",
                params={"limit": 2},
            )
            assert p1.status_code == 200, p1.text
            p1_body = p1.json()
            assert len(p1_body["items"]) == 2
            assert p1_body["next_cursor"] is not None
            assert conn_ok_id in p1_body["facets"]["partial_sync_connection_ids"]
            assert p1_body["facets"]["paused_count"] == 1
            assert p1_body["facets"]["hazard_flagged_count"] == 1
            assert "classified-payroll" in p1_body["facets"]["tags"]

            p2 = await admin_client.get(
                "/api/v1/workspaces/acme/repositories",
                params={"limit": 2, "cursor": p1_body["next_cursor"]},
            )
            assert p2.status_code == 200
            p2_body = p2.json()
            assert len(p2_body["items"]) == 1
            assert p2_body["next_cursor"] is None
            seen_ids = {r["id"] for r in p1_body["items"] + p2_body["items"]}
            assert seen_ids == {repo_a_id, repo_b_id, repo_secret_id}

            # Filters: provider=gitlab, mode=approval, q=search, hazard_status=flagged, paused=true
            gl_only = await admin_client.get(
                "/api/v1/workspaces/acme/repositories",
                params={"provider": "gitlab", "mode": "approval", "q": "search"},
            )
            assert gl_only.status_code == 200
            assert [r["id"] for r in gl_only.json()["items"]] == [repo_b_id]

            haz_only = await admin_client.get(
                "/api/v1/workspaces/acme/repositories",
                params={"hazard_status": "flagged", "paused": "true"},
            )
            assert haz_only.status_code == 200
            assert [r["id"] for r in haz_only.json()["items"]] == [repo_secret_id]

            # Invite Maintainer granted ONLY repo_a_id (UX-02 & SEC-010 zero-leakage proof)
            maint_client, _, maint_csrf = await _invite_and_accept_member(
                harness,
                admin_client,
                admin_csrf,
                ws_slug="acme",
                email="maint@red2pr.local",
                display_name="Scoped Maintainer",
                password=MAINTAINER_CREDENTIAL,
                role="maintainer",
                repo_grants=[repo_a_id],
            )
            try:
                scoped_cat = await maint_client.get("/api/v1/workspaces/acme/repositories")
                assert scoped_cat.status_code == 200
                scoped_body = scoped_cat.json()
                assert [r["id"] for r in scoped_body["items"]] == [repo_a_id]
                # Facets MUST NOT leak ungranted tags, orgs, paused counts, or hazard counts
                assert scoped_body["facets"]["tags"] == ["payments", "tier-1"]
                assert "classified-payroll" not in scoped_body["facets"]["tags"]
                assert scoped_body["facets"]["organizations"] == ["acme"]
                assert "stealth-org" not in scoped_body["facets"]["organizations"]
                assert scoped_body["facets"]["paused_count"] == 0
                assert scoped_body["facets"]["hazard_flagged_count"] == 0

                # Searching for secret tag or secret repo name returns 0 items and 0 leaked facets
                probe_search = await maint_client.get(
                    "/api/v1/workspaces/acme/repositories",
                    params={"q": "payroll"},
                )
                assert probe_search.status_code == 200
                assert probe_search.json()["items"] == []
                assert "classified-payroll" not in probe_search.json()["facets"]["tags"]

                # Direct access to ungranted repo_secret_id returns 404 across all A-07 endpoints
                for resp in [
                    await maint_client.get(
                        f"/api/v1/workspaces/acme/repositories/{repo_secret_id}"
                    ),
                    await maint_client.get(
                        f"/api/v1/workspaces/acme/repositories/{repo_secret_id}/policy"
                    ),
                    await maint_client.patch(
                        f"/api/v1/workspaces/acme/repositories/{repo_secret_id}",
                        json={"paused": False, "acknowledge_grant_review": False},
                        headers=_csrf_headers(maint_csrf),
                    ),
                    await maint_client.post(
                        f"/api/v1/workspaces/acme/repositories/{repo_secret_id}/policy/previews",
                        json={"mode": "approval"},
                        headers=_csrf_headers(maint_csrf),
                    ),
                    await maint_client.post(
                        "/api/v1/workspaces/acme/repositories/policy-previews",
                        json={"repository_ids": [repo_a_id, repo_secret_id], "mode": "approval"},
                        headers=_csrf_headers(maint_csrf),
                    ),
                    await maint_client.post(
                        "/api/v1/workspaces/acme/repositories/bulk-update",
                        json={
                            "repository_ids": [repo_a_id, repo_secret_id],
                            "expected_versions": {repo_a_id: 1, repo_secret_id: 1},
                            "paused": True,
                        },
                        headers=_csrf_headers(maint_csrf),
                    ),
                ]:
                    assert resp.status_code == 404, resp.text
                    assert "secret-payroll" not in resp.text
            finally:
                await maint_client.aclose()
    finally:
        await harness.app_engine.dispose()


async def test_t_rep_02_p_and_n_immutable_revisions_concurrency_gates_sec022_and_dry_run(
    migrated_db: PgTestUrls,
) -> None:
    """Verify immutable revisions, ETag/409, step-up, W-02/SEC-031 gates, SEC-022, and dry-run."""
    clock = ManualClock()
    harness = _build_u12_harness(migrated_db.app_url, clock=clock)
    webhook_secret = "whsec_u12_live_hmac_secret_99112233"
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=harness.api_app),
            base_url=PUBLIC_BASE_URL,
        ) as admin_client:
            owner_id, ws_id, admin_csrf = await _claim_owner_and_workspace(harness, admin_client)

            conn_clean_id, repo_clean_id = await _seed_connection_and_repo(
                harness,
                ws_id=ws_id,
                external_repo_id="700101",
                name="acme/payments-service",
                visibility="private",
                mode="monitor",
                grant_review_required=True,
                webhook_secret=webhook_secret,
            )
            _, repo_hazard_id = await _seed_connection_and_repo(
                harness,
                ws_id=ws_id,
                external_repo_id="700202",
                name="acme/untrusted-ci-repo",
                visibility="public",
                mode="monitor",
                hazard_status="flagged",
                auto_repair_blocked=True,
            )

            # 0. SetupWizard repo_policy probe rejects unsafe glob & validates good config
            setup_state_resp = await admin_client.get("/api/v1/setup")
            assert setup_state_resp.status_code == 200, setup_state_resp.text
            ckpt_1 = setup_state_resp.json()["checkpoint"]

            bad_setup = await admin_client.post(
                "/api/v1/setup/steps/repo_policy",
                json={
                    "expected_checkpoint": ckpt_1,
                    "action": "save",
                    "protected_branches": ["../escape"],
                    "max_attempts": 2,
                },
                headers=_csrf_headers(admin_csrf, idem_key=new_uuid7()),
            )
            assert bad_setup.status_code == 422, bad_setup.text

            good_setup = await admin_client.post(
                "/api/v1/setup/steps/repo_policy",
                json={
                    "expected_checkpoint": ckpt_1,
                    "action": "save",
                    "protected_branches": ["main", "release/*"],
                    "max_attempts": 2,
                },
                headers=_csrf_headers(admin_csrf, idem_key=new_uuid7()),
            )
            assert good_setup.status_code == 200, good_setup.text
            repo_pol_step = next(
                s for s in good_setup.json()["steps"] if s["phase"] == "repo_policy"
            )
            assert repo_pol_step["status"] == "completed"
            assert repo_pol_step["probe_status"] == "passed"

            # 1. Initial GET /policy returns revision=1 and ETag "v1"
            pol_v1_resp = await admin_client.get(
                f"/api/v1/workspaces/acme/repositories/{repo_clean_id}/policy"
            )
            assert pol_v1_resp.status_code == 200
            assert pol_v1_resp.headers.get("ETag") == '"v1"'
            pol_v1 = pol_v1_resp.json()
            assert pol_v1["current_revision"] == 1
            assert pol_v1["readiness_gates"]["grant_review_required"] is True
            assert pol_v1["readiness_gates"]["worker_isolation_ready"] is False
            assert pol_v1["readiness_gates"]["inference_consent_ready"] is False

            # 2. ADR-033: Webhook failure in 'monitor' mode records trigger with
            # allow_sandbox_execution=False and pins policy_revision=1
            wh_payload = json.dumps(
                {
                    "action": "completed",
                    "installation": {"id": 99700101},
                    "repository": {
                        "id": 700101,
                        "full_name": "acme/payments-service",
                        "fork": False,
                    },
                    "workflow_run": {
                        "id": 8801,
                        "run_attempt": 1,
                        "head_branch": "main",
                        "head_sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f68801",
                        "event": "push",
                        "status": "completed",
                        "conclusion": "failure",
                        "head_repository": {"id": 700101, "fork": False},
                    },
                }
            ).encode("utf-8")
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=harness.api_app),
                base_url=PUBLIC_BASE_URL,
            ) as hook_client:
                wh_resp = await hook_client.post(
                    f"/api/v1/hooks/github/{conn_clean_id}",
                    content=wh_payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-GitHub-Event": "workflow_run",
                        "X-GitHub-Delivery": "11111111-2222-3333-4444-555555555555",
                        "X-Hub-Signature-256": _gh_hmac_header(webhook_secret, wh_payload),
                    },
                )
            assert wh_resp.status_code == 202, wh_resp.text

            async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
                triage_job = await db.scalar(
                    select(TaskJobModel).where(
                        TaskJobModel.repository_id == repo_clean_id,
                        TaskJobModel.kind == "ci_run.triage",
                    )
                )
                assert triage_job is not None
                assert triage_job.payload_json["policy_revision"] == 1
                assert triage_job.payload_json["repository_mode"] == "monitor"
                assert triage_job.payload_json["allow_sandbox_execution"] is False

            # 3. Invite Maintainer and verify non-admin CANNOT clear W-02 grant_review_required
            maint_client, maint_user_id, maint_csrf = await _invite_and_accept_member(
                harness,
                admin_client,
                admin_csrf,
                ws_slug="acme",
                email="maint2@red2pr.local",
                display_name="Repo Maintainer",
                password=MAINTAINER_CREDENTIAL,
                role="maintainer",
                repo_grants=[repo_clean_id, repo_hazard_id],
            )
            try:
                # Advance clock > 6m so step-up is expired; verify step-up gate on W-02 ack / mode
                clock.advance(minutes=10)
                non_admin_ack = await maint_client.patch(
                    f"/api/v1/workspaces/acme/repositories/{repo_clean_id}",
                    json={"expected_version": 1, "acknowledge_grant_review": True},
                    headers=_csrf_headers(maint_csrf, if_match='"v1"'),
                )
                assert non_admin_ack.status_code == 403

                # Leaving monitor mode while grant_review_required=True is blocked (409)
                step_admin = await admin_client.post(
                    "/api/v1/auth/step-up",
                    json={"password": OWNER_CREDENTIAL, "otp": None},
                    headers=_csrf_headers(admin_csrf),
                )
                assert step_admin.status_code == 200
                admin_csrf = step_admin.json()["csrf_token"]

                blocked_w02 = await admin_client.patch(
                    f"/api/v1/workspaces/acme/repositories/{repo_clean_id}/policy",
                    json={
                        "expected_revision": 1,
                        "mode": "approval",
                        "paused": False,
                        "policy": pol_v1["policy"],
                        "reason": "Attempt approval before W-02 review.",
                    },
                    headers=_csrf_headers(admin_csrf, if_match='"v1"'),
                )
                assert blocked_w02.status_code == 409, blocked_w02.text
                assert blocked_w02.json()["code"] == "grant_review_required"

                # Admin acknowledges W-02 grant review
                ack_resp = await admin_client.patch(
                    f"/api/v1/workspaces/acme/repositories/{repo_clean_id}",
                    json={
                        "expected_version": 1,
                        "acknowledge_grant_review": True,
                        "reason": "Admin verified installation repository grants.",
                    },
                    headers=_csrf_headers(admin_csrf, if_match='"v1"'),
                )
                assert ack_resp.status_code == 200, ack_resp.text
                assert ack_resp.json()["grant_review_required"] is False
                assert ack_resp.json()["version"] == 2

                # 4. auto_repair is STILL blocked before worker_readiness + inference consent
                blocked_prereq = await admin_client.patch(
                    f"/api/v1/workspaces/acme/repositories/{repo_clean_id}/policy",
                    json={
                        "expected_revision": 1,
                        "mode": "auto_repair",
                        "paused": False,
                        "policy": pol_v1["policy"],
                    },
                    headers=_csrf_headers(admin_csrf, if_match='"v1"'),
                )
                assert blocked_prereq.status_code == 409

                # Enable worker_readiness + private-repo inference consent
                consent_id = await _enable_worker_and_inference_readiness(
                    harness,
                    owner_user_id=owner_id,
                    ws_id=ws_id,
                )

                # SEC-031: Hazard-flagged repo STILL blocks auto_repair even with worker + consent!
                hazard_blocked = await admin_client.patch(
                    f"/api/v1/workspaces/acme/repositories/{repo_hazard_id}/policy",
                    json={
                        "expected_revision": 1,
                        "mode": "auto_repair",
                        "paused": False,
                        "policy": pol_v1["policy"],
                    },
                    headers=_csrf_headers(admin_csrf, if_match='"v1"'),
                )
                assert hazard_blocked.status_code == 409
                assert "hazard" in hazard_blocked.text.lower()

                # 5. Step-up enforcement on Maintainer enabling auto_repair on clean repo
                candidate_pol = {
                    **pol_v1["policy"],
                    "branch_allowlist": ["main", "release/*"],
                    "branch_denylist": ["release/legacy"],
                    "file_allowlist": ["src/**", "tests/**"],
                    "file_denylist": ["src/generated/**"],
                    "sensitive_rules": ["src/billing/**"],
                    "allow_test_edits": True,
                    "max_attempts": 1,
                    "max_diff_lines": 300,
                    "inference_consent_id": consent_id,
                }
                # Exceeding instance ceiling (max_attempts=3 > 2) is flagged in dry-run preview
                ceiling_prev = await maint_client.post(
                    f"/api/v1/workspaces/acme/repositories/{repo_clean_id}/policy/previews",
                    json={
                        "mode": "auto_repair",
                        "paused": False,
                        "policy": {**candidate_pol, "max_attempts": 3},
                    },
                    headers=_csrf_headers(maint_csrf),
                )
                assert ceiling_prev.status_code == 200
                assert ceiling_prev.json()["can_apply"] is False
                assert any(
                    d["code"] == "max_attempts_exceeds_ceiling"
                    for d in ceiling_prev.json()["denials"]
                )

                need_step_up = await maint_client.patch(
                    f"/api/v1/workspaces/acme/repositories/{repo_clean_id}/policy",
                    json={
                        "expected_revision": 1,
                        "mode": "auto_repair",
                        "paused": False,
                        "policy": candidate_pol,
                        "reason": "Enable guarded auto_repair.",
                    },
                    headers=_csrf_headers(maint_csrf, if_match='"v1"'),
                )
                assert need_step_up.status_code == 403
                assert need_step_up.json()["code"] == "step_up_required"

                # Zero-mutation Dry-Run Preview (POST .../policy/previews) mutates 0 DB rows!
                preview_resp = await maint_client.post(
                    f"/api/v1/workspaces/acme/repositories/{repo_clean_id}/policy/previews",
                    json={
                        "mode": "auto_repair",
                        "paused": False,
                        "policy": candidate_pol,
                        "sample_branches": ["main", "release/legacy", "feature/unlisted"],
                        "sample_paths": [
                            "src/app.py",
                            "src/generated/out.py",
                            "src/billing/charge.py",
                            ".github/workflows/ci.yml",
                            ".env",
                            "tests/test_app.py",
                        ],
                        "sample_diff_lines": 180,
                    },
                    headers=_csrf_headers(maint_csrf),
                )
                assert preview_resp.status_code == 200, preview_resp.text
                prev_data = preview_resp.json()
                assert prev_data["can_apply"] is True
                assert prev_data["current_revision"] == 1
                assert prev_data["next_revision"] == 2
                assert prev_data["requires_step_up"] is True
                assert len(prev_data["historical_run_simulations"]) == 1
                assert (
                    prev_data["historical_run_simulations"][0]["disposition"]
                    == "eligible_auto_repair"
                )
                assert len(prev_data["affected_in_flight"]) == 1
                assert prev_data["affected_in_flight"][0]["pinned_policy_revision"] == 1

                # Prove zero DB mutations occurred during preview
                async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
                    rev_count = await db.scalar(
                        select(func.count())
                        .select_from(RepositoryPolicyModel)
                        .where(RepositoryPolicyModel.repository_id == repo_clean_id)
                    )
                    assert rev_count == 1

                # Complete 5m step-up for Maintainer and save immutable revision v2
                m_step = await maint_client.post(
                    "/api/v1/auth/step-up",
                    json={"password": MAINTAINER_CREDENTIAL, "otp": None},
                    headers=_csrf_headers(maint_csrf),
                )
                assert m_step.status_code == 200
                maint_csrf = m_step.json()["csrf_token"]

                saved_v2 = await maint_client.patch(
                    f"/api/v1/workspaces/acme/repositories/{repo_clean_id}/policy",
                    json={
                        "expected_revision": 1,
                        "mode": "auto_repair",
                        "paused": False,
                        "policy": candidate_pol,
                        "reason": "Enable guarded auto_repair.",
                    },
                    headers=_csrf_headers(maint_csrf, if_match='"v1"'),
                )
                assert saved_v2.status_code == 200, saved_v2.text
                assert saved_v2.headers.get("ETag") == '"v2"'
                v2_body = saved_v2.json()
                assert v2_body["current_revision"] == 2
                assert v2_body["mode"] == "auto_repair"
                assert [r["revision"] for r in v2_body["revisions"]] == [2, 1]

                # 6. Stale ETag -> 412; stale expected_revision with current ETag -> 409
                stale_etag = await maint_client.patch(
                    f"/api/v1/workspaces/acme/repositories/{repo_clean_id}/policy",
                    json={
                        "expected_revision": 2,
                        "mode": "approval",
                        "paused": False,
                        "policy": candidate_pol,
                    },
                    headers=_csrf_headers(maint_csrf, if_match='"v1"'),
                )
                assert stale_etag.status_code == 412

                stale_rev = await maint_client.patch(
                    f"/api/v1/workspaces/acme/repositories/{repo_clean_id}/policy",
                    json={
                        "expected_revision": 1,
                        "mode": "approval",
                        "paused": False,
                        "policy": candidate_pol,
                    },
                    headers=_csrf_headers(maint_csrf, if_match='"v2"'),
                )
                assert stale_rev.status_code == 409
                assert stale_rev.json()["code"] == "version_conflict"

                # 7. Pausing drains queued jobs while requesting cancel on leased jobs pinned to v1
                leased_job_id = new_uuid7()
                queued_job_id = new_uuid7()
                async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
                    db.add(
                        TaskJobModel(
                            id=leased_job_id,
                            workspace_id=ws_id,
                            repository_id=repo_clean_id,
                            kind="sandbox.reproduce",
                            is_repair_job=True,
                            resource_id=new_uuid7(),
                            dedup_key=f"leased-{leased_job_id}",
                            logical_effect_key=f"eff-leased-{leased_job_id}",
                            correlation_id=f"corr-leased-{leased_job_id}",
                            state="leased",
                            payload_json={"policy_revision": 1},
                            not_before=clock(),
                            deadline=clock() + timedelta(minutes=20),
                        )
                    )
                    db.add(
                        TaskJobModel(
                            id=queued_job_id,
                            workspace_id=ws_id,
                            repository_id=repo_clean_id,
                            kind="sandbox.verify",
                            is_repair_job=True,
                            resource_id=new_uuid7(),
                            dedup_key=f"queued-{queued_job_id}",
                            logical_effect_key=f"eff-queued-{queued_job_id}",
                            correlation_id=f"corr-queued-{queued_job_id}",
                            state="queued",
                            payload_json={"policy_revision": 2},
                            not_before=clock(),
                            deadline=clock() + timedelta(minutes=20),
                        )
                    )
                    await db.commit()

                repo_detail_before = await maint_client.get(
                    f"/api/v1/workspaces/acme/repositories/{repo_clean_id}"
                )
                assert repo_detail_before.status_code == 200
                cur_repo_ver = repo_detail_before.json()["repository"]["version"]

                pause_resp = await maint_client.patch(
                    f"/api/v1/workspaces/acme/repositories/{repo_clean_id}",
                    json={
                        "expected_version": cur_repo_ver,
                        "paused": True,
                        "acknowledge_grant_review": False,
                        "reason": "Pause during upstream outage.",
                    },
                    headers=_csrf_headers(maint_csrf, if_match=f'"v{cur_repo_ver}"'),
                )
                assert pause_resp.status_code == 200, pause_resp.text
                assert pause_resp.json()["paused"] is True
                assert pause_resp.json()["policy_revision"] == 3

                async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
                    mode_only_snapshot = await db.scalar(
                        select(RepositoryPolicyModel).where(
                            RepositoryPolicyModel.repository_id == repo_clean_id,
                            RepositoryPolicyModel.revision == 3,
                        )
                    )
                    assert mode_only_snapshot is not None
                    assert mode_only_snapshot.required_check_names_json == ["build"]

                async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
                    q_row = await db.get(TaskJobModel, queued_job_id)
                    l_row = await db.get(TaskJobModel, leased_job_id)
                    assert q_row is not None and q_row.state == "cancelled"
                    assert l_row is not None and l_row.state == "cancel_requested"
                    assert l_row.payload_json["policy_revision"] == 1

                # 8. Bulk preview + atomic rollback when 1 repo has version conflict
                repo_clean_ver = pause_resp.json()["version"]
                bulk_prev = await admin_client.post(
                    "/api/v1/workspaces/acme/repositories/policy-previews",
                    json={
                        "repository_ids": [repo_clean_id, repo_hazard_id],
                        "paused": False,
                        "add_tags": ["fleet-managed"],
                    },
                    headers=_csrf_headers(admin_csrf),
                )
                assert bulk_prev.status_code == 200
                assert bulk_prev.json()["can_apply_all"] is True

                # Pass wrong expected_version (999) for 2nd repo -> atomic rollback of 1st repo too!
                bulk_conflict = await admin_client.post(
                    "/api/v1/workspaces/acme/repositories/bulk-update",
                    json={
                        "repository_ids": [repo_clean_id, repo_hazard_id],
                        "expected_versions": {repo_clean_id: repo_clean_ver, repo_hazard_id: 999},
                        "paused": False,
                        "add_tags": ["should-rollback"],
                    },
                    headers=_csrf_headers(admin_csrf, idem_key=new_uuid7()),
                )
                assert bulk_conflict.status_code == 409

                after_rollback = await admin_client.get(
                    f"/api/v1/workspaces/acme/repositories/{repo_clean_id}"
                )
                assert after_rollback.json()["repository"]["paused"] is True
                assert "should-rollback" not in after_rollback.json()["repository"]["tags"]

                # Valid atomic bulk update succeeds across both repositories
                bulk_ok = await admin_client.post(
                    "/api/v1/workspaces/acme/repositories/bulk-update",
                    json={
                        "repository_ids": [repo_clean_id, repo_hazard_id],
                        "expected_versions": {repo_clean_id: repo_clean_ver, repo_hazard_id: 1},
                        "paused": False,
                        "add_tags": ["fleet-managed"],
                        "reason": "Resume fleet and apply fleet tag.",
                    },
                    headers=_csrf_headers(admin_csrf, idem_key=new_uuid7()),
                )
                assert bulk_ok.status_code == 200, bulk_ok.text
                assert len(bulk_ok.json()["updated_repositories"]) == 2
                assert all(
                    "fleet-managed" in r["tags"] for r in bulk_ok.json()["updated_repositories"]
                )

                # 9. SEC-022: Live in-DB role downgrade (maintainer -> viewer) WITHOUT bump of
                # session grant_epoch immediately denies mutation inside write transaction AND
                # commits deny audit + security.policy.denied outbox event!
                async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
                    m_row = await db.scalar(
                        select(MembershipModel).where(
                            MembershipModel.workspace_id == ws_id,
                            MembershipModel.user_id == maint_user_id,
                        )
                    )
                    assert m_row is not None
                    m_row.role = "viewer"
                    await db.commit()

                latest_pol = (
                    await admin_client.get(
                        f"/api/v1/workspaces/acme/repositories/{repo_clean_id}/policy"
                    )
                ).json()
                sec022_resp = await maint_client.patch(
                    f"/api/v1/workspaces/acme/repositories/{repo_clean_id}/policy",
                    json={
                        "expected_revision": latest_pol["current_revision"],
                        "mode": "monitor",
                        "paused": True,
                        "policy": latest_pol["policy"],
                    },
                    headers=_csrf_headers(
                        maint_csrf,
                        if_match=f'"v{latest_pol["current_revision"]}"',
                    ),
                )
                assert sec022_resp.status_code == 403

                async with workspace_rls_session(harness.app_factory, workspace_id=ws_id) as db:
                    denied_events = (
                        await db.scalars(
                            select(OutboxEventModel).where(
                                OutboxEventModel.event_type == "security.policy.denied"
                            )
                        )
                    ).all()
                    assert len(denied_events) >= 1
                    deny_audits = (
                        await db.scalars(
                            select(AuditLogModel).where(
                                AuditLogModel.actor_id == maint_user_id,
                                AuditLogModel.decision == "deny",
                            )
                        )
                    ).all()
                    assert len(deny_audits) >= 1

                # Verify tamper-evident audit hash chain end-to-end
                with tempfile.TemporaryDirectory(prefix="red2pr_u12_ckpt_") as ckpt_dir:
                    ckpt_store = ExternalCheckpointStore(Path(ckpt_dir) / "audit_ckpt.json")
                    async with instance_rls_session(
                        harness.app_factory, mode="audit_verifier"
                    ) as audit_db:
                        verified_entries = await verify_audit_chain(
                            audit_db,
                            external_store=ckpt_store,
                            keyring=KeyRing(),
                        )
                        assert verified_entries >= 8
            finally:
                await maint_client.aclose()
    finally:
        await harness.app_engine.dispose()


def test_t_rep_03_p_and_n_branch_path_patch_guardrails() -> None:
    """Verify REP-03 branch/file deny > allow, SEC-007/SEC-009, and test/config edit gates."""
    cfg = load_config()
    ctx = PolicyHierarchyContext(
        instance_config=cfg,
        worker_isolation_ready=True,
        inference_consent_ready=True,
        workflow_hazard_blocked=False,
        grant_review_required=False,
    )
    strict_policy = build_default_repository_policy(instance_config=cfg).model_copy(
        update={
            "branch_allowlist": ["main", "release/*"],
            "branch_denylist": ["release/frozen"],
            "file_allowlist": ["src/**", "tests/**", "pyproject.toml", ".github/workflows/**"],
            "file_denylist": ["src/secret_adapter/**"],
            "allow_test_edits": False,
            "allow_config_edits": False,
            "max_diff_lines": 120,
        }
    )
    eff_auto = resolve_effective_policy(
        repo_mode="auto_repair",
        repo_paused=False,
        repo_policy=strict_policy,
        ctx=ctx,
    )

    # Branch evaluations: allow vs deny override vs bot loop vs non-branch tag ref
    assert (
        evaluate_branch_policy(
            "refs/heads/main",
            repo_policy=strict_policy,
            effective_policy=eff_auto,
            ctx=ctx,
        ).verdict
        == "allow"
    )
    assert (
        evaluate_branch_policy(
            "release/frozen",
            repo_policy=strict_policy,
            effective_policy=eff_auto,
            ctx=ctx,
        ).verdict
        == "deny"
    )
    assert (
        evaluate_branch_policy(
            "red2pr/fix-run-123",
            repo_policy=strict_policy,
            effective_policy=eff_auto,
            ctx=ctx,
        ).verdict
        == "deny"
    )
    assert (
        evaluate_branch_policy(
            "refs/tags/v1.0.0",
            repo_policy=strict_policy,
            effective_policy=eff_auto,
            ctx=ctx,
        ).verdict
        == "deny"
    )

    # Standard source file allowed in auto_repair; denied subdir blocked; test & config blocked
    overall_ok, _, diff_v_ok, _ = evaluate_patch_paths(
        ["src/payment/processor.py"],
        diff_lines=40,
        repo_policy=strict_policy,
        effective_policy=eff_auto,
        ctx=ctx,
    )
    assert overall_ok == "allow"
    assert diff_v_ok == "allow"

    for blocked_path in (
        "../outside.py",
        ".env",
        ".git/hooks/post-checkout",
        "src/secret_adapter/keys.py",
        "tests/test_processor.py",
        "pyproject.toml",
    ):
        ev = evaluate_path_policy(
            blocked_path,
            repo_policy=strict_policy,
            effective_policy=eff_auto,
            ctx=ctx,
        )
        assert ev.verdict == "deny", f"Expected deny for {blocked_path}, got {ev.verdict}"

    # SEC-009 workflow file ALWAYS escalates to requires_approval even in auto_repair
    wf_eval = evaluate_path_policy(
        ".github/workflows/ci.yml",
        repo_policy=strict_policy,
        effective_policy=eff_auto,
        ctx=ctx,
    )
    assert wf_eval.verdict == "requires_approval"
    assert wf_eval.source_layer == "hard_invariant"

    # Enabling allow_test_edits & allow_config_edits escalates tests/config to requires_approval
    # (NEVER autonomous 'allow' without human review per AGENTS.md Principle 3!)
    unlocked_policy = strict_policy.model_copy(
        update={"allow_test_edits": True, "allow_config_edits": True}
    )
    eff_unlocked = resolve_effective_policy(
        repo_mode="auto_repair",
        repo_paused=False,
        repo_policy=unlocked_policy,
        ctx=ctx,
    )
    test_ev = evaluate_path_policy(
        "tests/test_processor.py",
        repo_policy=unlocked_policy,
        effective_policy=eff_unlocked,
        ctx=ctx,
    )
    cfg_ev = evaluate_path_policy(
        "pyproject.toml",
        repo_policy=unlocked_policy,
        effective_policy=eff_unlocked,
        ctx=ctx,
    )
    assert test_ev.verdict == "requires_approval"
    assert cfg_ev.verdict == "requires_approval"

    # Diff lines exceeding max_diff_lines (120) flips patch verdict to 'deny'
    overall_big, _, diff_v_big, _ = evaluate_patch_paths(
        ["src/payment/processor.py"],
        diff_lines=250,
        repo_policy=unlocked_policy,
        effective_policy=eff_unlocked,
        ctx=ctx,
    )
    assert overall_big == "deny"
    assert diff_v_big == "deny"
