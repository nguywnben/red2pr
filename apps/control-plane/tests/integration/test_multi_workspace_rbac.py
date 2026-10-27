"""PostgreSQL 16 integration & adversarial security tests for U06 Multi-Workspace RBAC & SSE.

Verifies against a real disposable PostgreSQL 16 instance (never SQLite mocks):
- Migration `0003_workspaces_memberships_grants` reversibility (`upgrade -> downgrade -> upgrade`),
  fail-closed `FORCE ROW LEVEL SECURITY` across `memberships`, `invitations`, `repo_grants`, and
  `break_glass_grants`, composite tenant FK enforcement, cross-workspace `repository_id` trigger,
  and pooled connection GUC reset (`SEC-032`).
- `T-IAM-02-P`: Two independent workspaces, all 5 workspace roles (`admin`, `maintainer`,
  `reviewer`, `viewer`, `auditor` `ADR-038`), single-use email-bound invitations (`invite_token`
  returned once only, SHA-256 hashed at rest), `GET /me` grant hydration, `S-04` signed cursor
  pagination, and `If-Match` (`412`) / `expected_version` (`409`) concurrency guards.
- `T-IAM-02-N`, `ADR-034`, `SEC-010`, `SEC-022`, `SEC-032`, `SEC-038`, `W-01`:
  - `instance_owner` holds ZERO implicit read/write access to non-member workspaces (`404`);
    temporary step-up `break_glass_grants` grant audited read-only access and immediately revert
    to `404` on expiry or explicit revocation; idempotent `DELETE /workspaces/{ws}` (`202`).
  - Wrong-email invitation redemption (`403 invite_email_mismatch`), expired invitation (`410`),
    simultaneous `asyncio.gather` single-use invite redemption race (`1` `200` + `1` `409`),
    cross-workspace `repository_grants` (`404`), cross-workspace `S-04` cursor (`400`), stale
    `grant_epoch` cursor (`410`), `last_admin` demotion/removal (`409 last_admin`) including
    concurrent two-admin deletion race, and mandatory workspace `admin` MFA policy (`403`).
- `A-21` & `NFR-04` SSE Security & `<5s` Revocation Cutoff:
  - Rejects bearer tokens in query/header (`400`), enforces `repo_grants` per-event filtering,
    replays missed events via signed `Last-Event-ID` (`410` on foreign/expired cursor), and
    severs live open SSE streams within `<=5s` upon role downgrade or member removal while
    preserving sessions in unrelated workspaces.
"""

from __future__ import annotations

import asyncio
import base64
import os
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import httpx
import pgserver
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from py_contracts.crypto import KeyRing, MasterKeyRing, export_ed25519_public_key_record
from py_contracts.events import EventEnvelope, RunEventPayload
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import (
    ExternalCheckpointStore,
    verify_audit_chain,
)
from red2pr_control.api.app import create_app
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.base import (
    AuditLogModel,
    BreakGlassGrantModel,
    InvitationModel,
    MembershipModel,
    RepoGrantModel,
    SchemaMigrationRecordModel,
)
from red2pr_control.db.engine import (
    create_admin_engine,
    create_app_engine,
    create_session_factory,
    ensure_compatible_event_loop,
    run_alembic_downgrade,
    run_alembic_upgrade,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.mfa import generate_totp_code_at
from red2pr_control.iam.sessions import IamService
from red2pr_control.iam.sse import encode_sse_event_cursor
from red2pr_control.secrets.broker import SecretBroker, SecretBrokerTotpVault

APP_ROLE_NAME = "red2pr_app"
APP_ROLE_PASSWORD = "red2pr_app_local_test_pw_06"
PUBLIC_BASE_URL = "http://127.0.0.1:4280"
ORIGIN_HEADERS = {"Origin": PUBLIC_BASE_URL}


class ManualClock:
    """Deterministic controllable UTC clock for TTL, step-up, cursor & break-glass tests."""

    def __init__(self, initial: datetime | None = None) -> None:
        self._current = (initial or datetime(2026, 10, 27, 10, 0, 0, tzinfo=UTC)).astimezone(UTC)

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
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    headers = {"X-CSRF-Token": token, **ORIGIN_HEADERS}
    if extra:
        headers.update(extra)
    return headers


def _decode_base32_secret(secret_b32: str) -> bytes:
    pad_len = (-len(secret_b32)) % 8
    return base64.b32decode(secret_b32 + ("=" * pad_len), casefold=True)


@pytest.fixture(scope="module")
def pg_urls() -> Iterator[PgTestUrls]:
    """Provide a real PostgreSQL 16 test instance via env override or disposable pgserver."""
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
        tempfile.TemporaryDirectory(prefix="red2pr_u06_pg16_") as tmp_dir,
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
    """Reset schema cleanly to head before each test function."""
    run_alembic_downgrade(pg_urls.admin_url, "base", app_role_name=APP_ROLE_NAME)
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
    yield pg_urls


def _build_iam_stack(
    app_url: str,
    *,
    clock: ManualClock,
    pool_size: int = 4,
    max_overflow: int = 4,
    sse_poll_interval_seconds: float = 0.05,
    sse_heartbeat_interval_seconds: float = 0.50,
) -> tuple[AsyncEngine, IamService]:
    app_engine = create_app_engine(app_url, pool_size=pool_size, max_overflow=max_overflow)
    app_factory = create_session_factory(app_engine)
    kek_ring = MasterKeyRing(active_version=1, keys={1: b"\x33" * 32})
    broker = SecretBroker(key_ring=kek_ring, redactor=Redactor())
    totp_vault = SecretBrokerTotpVault(broker)
    iam = IamService(
        session_factory=app_factory,
        totp_vault=totp_vault,
        iam_seed_key=b"\x44" * 32,
        public_base_url=PUBLIC_BASE_URL,
        clock=clock,
        sse_poll_interval_seconds=sse_poll_interval_seconds,
        sse_heartbeat_interval_seconds=sse_heartbeat_interval_seconds,
    )
    return app_engine, iam


DEFAULT_OWNER_TEST_CREDENTIAL = "OwnerSup3rStr0ng!Pass#26"
DEFAULT_MEMBER_TEST_CREDENTIAL = "MemberSup3rStr0ng!Pass#26"


async def _claim_owner_client(
    transport: httpx.ASGITransport,
    iam: IamService,
    *,
    email: str = "owner.alice@red2pr.local",
    display_name: str = "Owner Alice",
    password: str | None = None,
) -> tuple[httpx.AsyncClient, str, str]:
    resolved_pwd = password if password is not None else DEFAULT_OWNER_TEST_CREDENTIAL
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
            "display_name": display_name,
            "email": email,
            "password": resolved_pwd,
        },
    )
    assert claim_resp.status_code == 201, claim_resp.text
    body = claim_resp.json()
    return client, body["csrf_token"], body["user"]["id"]


async def _provision_and_login_client(
    transport: httpx.ASGITransport,
    iam: IamService,
    *,
    email: str,
    display_name: str,
    password: str | None = None,
) -> tuple[httpx.AsyncClient, str, str]:
    resolved_pwd = password if password is not None else DEFAULT_MEMBER_TEST_CREDENTIAL
    user_dto = await iam.provision_local_user(
        display_name=display_name,
        email=email,
        password=resolved_pwd,
    )
    client = httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL)
    csrf_resp = await client.get("/api/v1/auth/csrf")
    assert csrf_resp.status_code == 200
    pre_csrf = csrf_resp.json()["csrf_token"]

    login_resp = await client.post(
        "/api/v1/auth/login",
        headers=_csrf_headers(pre_csrf),
        json={"identifier": email, "password": resolved_pwd},
    )
    assert login_resp.status_code == 200, login_resp.text
    body = login_resp.json()
    return client, body["csrf_token"], user_dto.id


async def test_migration_0003_reversibility_rls_composite_fk_and_pooled_guc_reset(
    pg_urls: PgTestUrls,
) -> None:
    """Verify 0003 downgrade/upgrade reversibility, fail-closed RLS, composite FK & GUC reset."""
    run_alembic_downgrade(pg_urls.admin_url, "base", app_role_name=APP_ROLE_NAME)
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
    # Step back cleanly from 0003 -> 0002 and re-upgrade -> head
    run_alembic_downgrade(
        pg_urls.admin_url,
        "0002_iam_users_sessions_mfa",
        app_role_name=APP_ROLE_NAME,
    )
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )

    clock = ManualClock()
    admin_engine = create_admin_engine(pg_urls.admin_url)
    # Single-connection pool proves GUC never leaks across pooled transactions (SEC-032)
    app_engine, iam = _build_iam_stack(
        pg_urls.app_url,
        clock=clock,
        pool_size=1,
        max_overflow=0,
    )
    try:
        admin_factory = create_session_factory(admin_engine)
        app_factory = create_session_factory(app_engine)

        async with admin_factory() as admin_sess, admin_sess.begin():
            mig0003 = await admin_sess.scalar(
                select(SchemaMigrationRecordModel).where(
                    SchemaMigrationRecordModel.revision == "0003_workspaces_rbac_grants"
                )
            )
            assert mig0003 is not None
            assert mig0003.phase == "expand"
            assert mig0003.reversible is True
            assert len(mig0003.checksum_sha256) == 64

        app = create_app(iam_service=iam)
        transport = httpx.ASGITransport(app=app)
        owner_client, owner_csrf, owner_id = await _claim_owner_client(transport, iam)
        try:
            ws_a_resp = await owner_client.post(
                "/api/v1/workspaces",
                headers=_csrf_headers(owner_csrf),
                json={"name": "Tenant Alpha", "slug": "tenant-alpha"},
            )
            ws_b_resp = await owner_client.post(
                "/api/v1/workspaces",
                headers=_csrf_headers(owner_csrf),
                json={"name": "Tenant Beta", "slug": "tenant-beta"},
            )
            assert ws_a_resp.status_code == 201
            assert ws_b_resp.status_code == 201
            ws_a_id = ws_a_resp.json()["id"]
            ws_b_id = ws_b_resp.json()["id"]

            repo_alpha = new_uuid7(now=clock())
            async with workspace_rls_session(app_factory, workspace_id=ws_a_id) as ws_a_db:
                mem_a = await ws_a_db.scalar(
                    select(MembershipModel).where(MembershipModel.workspace_id == ws_a_id)
                )
                assert mem_a is not None
                mem_a_id = mem_a.id
                ws_a_db.add(
                    RepoGrantModel(
                        id=new_uuid7(now=clock()),
                        workspace_id=ws_a_id,
                        membership_id=mem_a_id,
                        repository_id=repo_alpha,
                        granted_by_user_id=owner_id,
                        created_at=clock(),
                    )
                )

            async with workspace_rls_session(app_factory, workspace_id=ws_b_id) as ws_b_db:
                mem_b = await ws_b_db.scalar(
                    select(MembershipModel).where(MembershipModel.workspace_id == ws_b_id)
                )
                assert mem_b is not None
                mem_b_id = mem_b.id

                # Tenant B RLS must see ZERO Tenant A memberships or repo_grants
                leaked_mems = (
                    await ws_b_db.scalars(
                        select(MembershipModel).where(MembershipModel.workspace_id == ws_a_id)
                    )
                ).all()
                assert leaked_mems == []

                leaked_grants = (
                    await ws_b_db.scalars(
                        select(RepoGrantModel).where(RepoGrantModel.workspace_id == ws_a_id)
                    )
                ).all()
                assert leaked_grants == []

            # Composite FK rejects inserting repo_grant in ws_b referencing mem_a_id from ws_a
            with pytest.raises(DBAPIError):
                async with workspace_rls_session(app_factory, workspace_id=ws_b_id) as ws_b_db:
                    ws_b_db.add(
                        RepoGrantModel(
                            id=new_uuid7(now=clock()),
                            workspace_id=ws_b_id,
                            membership_id=mem_a_id,
                            repository_id=new_uuid7(now=clock()),
                            granted_by_user_id=owner_id,
                            created_at=clock(),
                        )
                    )

            # Trigger rejects reusing repo_alpha (bound to ws_a) inside ws_b
            with pytest.raises(DBAPIError):
                async with workspace_rls_session(app_factory, workspace_id=ws_b_id) as ws_b_db:
                    ws_b_db.add(
                        RepoGrantModel(
                            id=new_uuid7(now=clock()),
                            workspace_id=ws_b_id,
                            membership_id=mem_b_id,
                            repository_id=repo_alpha,
                            granted_by_user_id=owner_id,
                            created_at=clock(),
                        )
                    )

            # Bare pooled connection (reusing single pool slot after workspace_rls_session!)
            # MUST fail closed with 0 visible rows across all 4 U06 tables (SEC-032)
            async with app_factory() as bare_sess, bare_sess.begin():
                assert (await bare_sess.scalars(select(MembershipModel))).all() == []
                assert (await bare_sess.scalars(select(InvitationModel))).all() == []
                assert (await bare_sess.scalars(select(RepoGrantModel))).all() == []
                assert (await bare_sess.scalars(select(BreakGlassGrantModel))).all() == []
        finally:
            await owner_client.aclose()
    finally:
        await app_engine.dispose()
        await admin_engine.dispose()


async def test_t_iam_02_p_two_workspaces_five_roles_invitations_cursors_and_concurrency(
    migrated_db: PgTestUrls,
) -> None:
    """Verify full positive RBAC matrix, 5 roles, single-use invites, S-04 cursors & ETag."""
    clock = ManualClock()
    app_engine, iam = _build_iam_stack(migrated_db.app_url, clock=clock)
    app = create_app(iam_service=iam)
    transport = httpx.ASGITransport(app=app)

    clients_to_close: list[httpx.AsyncClient] = []
    try:
        owner_client, owner_csrf, _ = await _claim_owner_client(transport, iam)
        clients_to_close.append(owner_client)

        ws_a = (
            await owner_client.post(
                "/api/v1/workspaces",
                headers=_csrf_headers(owner_csrf),
                json={"name": "Acme Core", "slug": "acme-core"},
            )
        ).json()
        ws_b = (
            await owner_client.post(
                "/api/v1/workspaces",
                headers=_csrf_headers(owner_csrf),
                json={"name": "Beta Infra", "slug": "beta-infra"},
            )
        ).json()

        repo_a1 = new_uuid7(now=clock())
        repo_a2 = new_uuid7(now=clock())

        role_specs = [
            ("maintainer", "maint.bob@red2pr.local", "Maintainer Bob", [repo_a1, repo_a2]),
            ("reviewer", "rev.carol@red2pr.local", "Reviewer Carol", [repo_a1]),
            ("viewer", "view.dan@red2pr.local", "Viewer Dan", []),
            ("auditor", "audit.erin@red2pr.local", "Auditor Erin", [repo_a2]),
        ]

        role_clients: dict[str, tuple[httpx.AsyncClient, str, str]] = {}
        for role_name, email, disp, grants in role_specs:
            clock.advance(seconds=1)
            u_client, u_csrf, u_id = await _provision_and_login_client(
                transport,
                iam,
                email=email,
                display_name=disp,
            )
            clients_to_close.append(u_client)
            role_clients[role_name] = (u_client, u_csrf, u_id)

            # Before accepting invite, user gets 404 on ws_a (anti-enumeration SEC-010)
            pre_get = await u_client.get("/api/v1/workspaces/acme-core")
            assert pre_get.status_code == 404

            inv_create = await owner_client.post(
                "/api/v1/workspaces/acme-core/invitations",
                headers=_csrf_headers(owner_csrf),
                json={
                    "email": email.upper(),  # verifies case-insensitive normalization
                    "role": role_name,
                    "repository_grants": grants,
                },
            )
            assert inv_create.status_code == 201, inv_create.text
            created_payload = inv_create.json()
            raw_token = created_payload["invite_token"]
            assert raw_token.startswith("inv_")
            assert "invite_token" not in created_payload["invite"]

            # Invitation listing never exposes raw token
            inv_list = await owner_client.get("/api/v1/workspaces/acme-core/invitations")
            assert inv_list.status_code == 200
            assert raw_token not in inv_list.text

            # Accept single-use invitation
            accept_resp = await u_client.post(
                "/api/v1/invitations/accept",
                headers=_csrf_headers(u_csrf),
                json={"token": raw_token},
            )
            assert accept_resp.status_code == 200, accept_resp.text
            mem_dto = accept_resp.json()
            assert mem_dto["workspace_id"] == ws_a["id"]
            assert mem_dto["role"] == role_name
            assert sorted(mem_dto["repository_grants"]) == sorted(grants)

        # Verify GET /me hydration & role capabilities
        auditor_client, auditor_csrf, _ = role_clients["auditor"]
        auditor_me = (await auditor_client.get("/api/v1/me")).json()
        assert len(auditor_me["workspaces"]) == 1
        assert auditor_me["workspaces"][0]["slug"] == "acme-core"
        assert auditor_me["memberships"][0]["role"] == "auditor"
        assert auditor_me["mfa_required_for_privileged"] is False

        # Auditor CAN read invitations & members, CANNOT mutate
        assert (
            await auditor_client.get("/api/v1/workspaces/acme-core/invitations")
        ).status_code == 200
        assert (
            await auditor_client.post(
                "/api/v1/workspaces/acme-core/invitations",
                headers=_csrf_headers(auditor_csrf),
                json={"email": "extra@red2pr.local", "role": "viewer"},
            )
        ).status_code == 403

        # Viewer CAN read members, CANNOT read invitations or mutate settings
        viewer_client, viewer_csrf, _ = role_clients["viewer"]
        assert (await viewer_client.get("/api/v1/workspaces/acme-core/members")).status_code == 200
        viewer_inv_resp = await viewer_client.get("/api/v1/workspaces/acme-core/invitations")
        assert viewer_inv_resp.status_code == 403
        assert viewer_inv_resp.json()["code"] == "insufficient_role"

        viewer_patch = await viewer_client.patch(
            "/api/v1/workspaces/acme-core",
            headers=_csrf_headers(viewer_csrf),
            json={"paused": True},
        )
        assert viewer_patch.status_code == 403

        # None of ws_a's non-owner members can see ws_b -> 404
        assert (await auditor_client.get(f"/api/v1/workspaces/{ws_b['id']}")).status_code == 404

        # S-04 signed cursor pagination across all 5 members of ws_a
        seen_member_ids: list[str] = []
        cursor: str | None = None
        while True:
            params: dict[str, str | int] = {"limit": 2}
            if cursor is not None:
                params["cursor"] = cursor
            page_resp = await owner_client.get(
                "/api/v1/workspaces/acme-core/members",
                params=params,
            )
            assert page_resp.status_code == 200, page_resp.text
            page_data = page_resp.json()
            for item in page_data["items"]:
                seen_member_ids.append(item["id"])
            cursor = page_data["next_cursor"]
            if cursor is None:
                break
        assert len(seen_member_ids) == 5
        assert len(set(seen_member_ids)) == 5

        # Optimistic concurrency on PATCH /workspaces/{ws} (ETag / If-Match / expected_version)
        get_ws = await owner_client.get("/api/v1/workspaces/acme-core")
        assert get_ws.status_code == 200
        assert get_ws.headers["ETag"] == '"v1"'

        patch_ok = await owner_client.patch(
            "/api/v1/workspaces/acme-core",
            headers=_csrf_headers(owner_csrf, extra={"If-Match": '"v1"'}),
            json={"name": "Acme Core Updated", "paused": True},
        )
        assert patch_ok.status_code == 200
        assert patch_ok.headers["ETag"] == '"v2"'
        assert patch_ok.json()["version"] == 2
        assert patch_ok.json()["paused"] is True

        stale_if_match = await owner_client.patch(
            "/api/v1/workspaces/acme-core",
            headers=_csrf_headers(owner_csrf, extra={"If-Match": '"v1"'}),
            json={"paused": False},
        )
        assert stale_if_match.status_code == 412
        assert stale_if_match.json()["code"] == "version_precondition_failed"

        stale_expected_ver = await owner_client.patch(
            "/api/v1/workspaces/acme-core",
            headers=_csrf_headers(owner_csrf),
            json={"paused": False, "expected_version": 1},
        )
        assert stale_expected_ver.status_code == 409
        assert stale_expected_ver.json()["code"] == "version_conflict"
    finally:
        for c in clients_to_close:
            await c.aclose()
        await app_engine.dispose()


async def test_t_iam_02_n_owner_zero_implicit_access_break_glass_and_workspace_delete(
    migrated_db: PgTestUrls,
) -> None:
    """Verify ADR-034 owner non-member 404 isolation, audited break-glass & S-05 delete."""
    clock = ManualClock()
    app_engine, iam = _build_iam_stack(migrated_db.app_url, clock=clock)
    app = create_app(iam_service=iam)
    transport = httpx.ASGITransport(app=app)

    clients_to_close: list[httpx.AsyncClient] = []
    try:
        owner_pwd = "OwnerSup3rStr0ng!Pass#26"
        owner_client, owner_csrf, _ = await _claim_owner_client(
            transport,
            iam,
            password=owner_pwd,
        )
        clients_to_close.append(owner_client)

        clara_client, _, clara_id = await _provision_and_login_client(
            transport,
            iam,
            email="clara.admin@red2pr.local",
            display_name="Clara Admin",
        )
        clients_to_close.append(clara_client)

        # Owner creates ws_isolated delegated to Clara as initial admin (Owner has NO membership!)
        create_resp = await owner_client.post(
            "/api/v1/workspaces",
            headers=_csrf_headers(owner_csrf),
            json={
                "name": "Isolated Security Team",
                "slug": "isolated-sec",
                "initial_admin_user_id": clara_id,
            },
        )
        assert create_resp.status_code == 201, create_resp.text
        ws_iso = create_resp.json()

        # ADR-034: Instance Owner without membership MUST receive 404 across workspace routes!
        assert (await owner_client.get("/api/v1/workspaces/isolated-sec")).status_code == 404
        assert (
            await owner_client.get("/api/v1/workspaces/isolated-sec/members")
        ).status_code == 404
        assert (await owner_client.get("/api/v1/workspaces/isolated-sec/events")).status_code == 404

        owner_ws_list = (await owner_client.get("/api/v1/workspaces")).json()["items"]
        assert all(item["id"] != ws_iso["id"] for item in owner_ws_list)

        # Break-glass without fresh step-up -> 403 step_up_required
        # Advance >5m past initial claim session's step_up_at so step-up is stale
        clock.advance(minutes=6)
        bg_no_step = await owner_client.post(
            "/api/v1/workspaces/isolated-sec/break-glass",
            headers=_csrf_headers(owner_csrf),
            json={"reason": "Investigating webhook outage #901", "duration_minutes": 15},
        )
        assert bg_no_step.status_code == 403
        assert bg_no_step.json()["code"] == "step_up_required"

        # Step up session (rotates CSRF token) -> request break-glass -> 201
        step_resp = await owner_client.post(
            "/api/v1/auth/step-up",
            headers=_csrf_headers(owner_csrf),
            json={"password": owner_pwd},
        )
        assert step_resp.status_code == 200
        owner_csrf = step_resp.json()["csrf_token"]

        bg_ok = await owner_client.post(
            "/api/v1/workspaces/isolated-sec/break-glass",
            headers=_csrf_headers(owner_csrf),
            json={"reason": "Investigating webhook outage #901", "duration_minutes": 15},
        )
        assert bg_ok.status_code == 201, bg_ok.text
        bg_grant = bg_ok.json()
        assert bg_grant["active"] is True

        # Verify dual audit entries (instance + workspace) AND that instance_admin RLS
        # cannot read workspace audit rows directly without a workspace RLS session (ADR-034)
        app_factory = create_session_factory(app_engine)
        async with instance_rls_session(app_factory, mode="instance_admin") as db:
            inst_bg_audits = int(
                (
                    await db.scalar(
                        select(func.count())
                        .select_from(AuditLogModel)
                        .where(
                            AuditLogModel.workspace_id.is_(None),
                            AuditLogModel.action == "workspace.break_glass_granted",
                        )
                    )
                )
                or 0
            )
            leaked_ws_audits = int(
                (
                    await db.scalar(
                        select(func.count())
                        .select_from(AuditLogModel)
                        .where(
                            AuditLogModel.workspace_id == ws_iso["id"],
                            AuditLogModel.action == "workspace.break_glass_granted",
                        )
                    )
                )
                or 0
            )
            assert inst_bg_audits == 1
            assert leaked_ws_audits == 0

        async with workspace_rls_session(app_factory, workspace_id=ws_iso["id"]) as ws_db:
            ws_bg_audits = int(
                (
                    await ws_db.scalar(
                        select(func.count())
                        .select_from(AuditLogModel)
                        .where(
                            AuditLogModel.workspace_id == ws_iso["id"],
                            AuditLogModel.action == "workspace.break_glass_granted",
                        )
                    )
                )
                or 0
            )
            assert ws_bg_audits == 1

        # With active break-glass, read routes succeed, while mutations stay 403 read-only!
        assert (await owner_client.get("/api/v1/workspaces/isolated-sec")).status_code == 200
        assert (
            await owner_client.get("/api/v1/workspaces/isolated-sec/members")
        ).status_code == 200
        bg_write = await owner_client.patch(
            "/api/v1/workspaces/isolated-sec",
            headers=_csrf_headers(owner_csrf),
            json={"paused": True},
        )
        assert bg_write.status_code == 403
        assert bg_write.json()["code"] == "break_glass_read_only"

        # Advance +16m past break-glass TTL -> immediately reverts to 404!
        clock.advance(minutes=16)
        assert (await owner_client.get("/api/v1/workspaces/isolated-sec")).status_code == 404

        # Re-step-up, issue second break-glass, and test explicit early DELETE revocation
        step_resp2 = await owner_client.post(
            "/api/v1/auth/step-up",
            headers=_csrf_headers(owner_csrf),
            json={"password": owner_pwd},
        )
        owner_csrf = step_resp2.json()["csrf_token"]
        bg_ok2 = (
            await owner_client.post(
                "/api/v1/workspaces/isolated-sec/break-glass",
                headers=_csrf_headers(owner_csrf),
                json={"reason": "Follow-up audit verification #902", "duration_minutes": 30},
            )
        ).json()
        assert (await owner_client.get("/api/v1/workspaces/isolated-sec")).status_code == 200

        rev_bg = await owner_client.delete(
            f"/api/v1/workspaces/isolated-sec/break-glass/{bg_ok2['id']}",
            headers=_csrf_headers(owner_csrf),
        )
        assert rev_bg.status_code == 204
        assert (await owner_client.get("/api/v1/workspaces/isolated-sec")).status_code == 404

        # S-05 Idempotent Workspace Delete (requires step-up + confirm_name + Idempotency-Key)
        missing_idem = await owner_client.request(
            "DELETE",
            "/api/v1/workspaces/isolated-sec",
            headers=_csrf_headers(owner_csrf),
            json={"confirm_name": "Isolated Security Team"},
        )
        assert missing_idem.status_code == 400
        assert missing_idem.json()["code"] == "missing_idempotency_key"

        idem_key = new_uuid7(now=clock())
        wrong_confirm = await owner_client.request(
            "DELETE",
            "/api/v1/workspaces/isolated-sec",
            headers=_csrf_headers(owner_csrf, extra={"Idempotency-Key": idem_key}),
            json={"confirm_name": "Wrong Name"},
        )
        assert wrong_confirm.status_code == 400
        assert wrong_confirm.json()["code"] == "confirm_name_mismatch"

        del_resp = await owner_client.request(
            "DELETE",
            "/api/v1/workspaces/isolated-sec",
            headers=_csrf_headers(owner_csrf, extra={"Idempotency-Key": idem_key}),
            json={"confirm_name": "Isolated Security Team"},
        )
        assert del_resp.status_code == 202, del_resp.text
        receipt1 = del_resp.json()
        assert receipt1["state"] == "succeeded"

        # Replaying exact same Idempotency-Key returns identical 202 ActionReceipt
        del_replay = await owner_client.request(
            "DELETE",
            "/api/v1/workspaces/isolated-sec",
            headers=_csrf_headers(owner_csrf, extra={"Idempotency-Key": idem_key}),
            json={"confirm_name": "Isolated Security Team"},
        )
        assert del_replay.status_code == 202
        assert del_replay.json()["operation_id"] == receipt1["operation_id"]

        # Clara's access to deleted workspace is immediately 404
        assert (await clara_client.get("/api/v1/workspaces/isolated-sec")).status_code == 404
    finally:
        for c in clients_to_close:
            await c.aclose()
        await app_engine.dispose()


async def test_invite_single_use_race_wrong_email_expiry_last_admin_race_and_admin_mfa_policy(
    migrated_db: PgTestUrls,
) -> None:
    """Verify SEC-038 invite races/email/TTL, W-01 last_admin races & admin MFA policy."""
    clock = ManualClock()
    app_engine, iam = _build_iam_stack(migrated_db.app_url, clock=clock)
    app = create_app(iam_service=iam)
    transport = httpx.ASGITransport(app=app)

    clients_to_close: list[httpx.AsyncClient] = []
    try:
        owner_client, owner_csrf, _ = await _claim_owner_client(transport, iam)
        clients_to_close.append(owner_client)

        ws_a = (
            await owner_client.post(
                "/api/v1/workspaces",
                headers=_csrf_headers(owner_csrf),
                json={"name": "Race Guard A", "slug": "race-a"},
            )
        ).json()
        ws_b = (
            await owner_client.post(
                "/api/v1/workspaces",
                headers=_csrf_headers(owner_csrf),
                json={"name": "Race Guard B", "slug": "race-b"},
            )
        ).json()

        # 1. Wrong-email acceptance -> 403 invite_email_mismatch (SEC-038)
        inv_resp = await owner_client.post(
            "/api/v1/workspaces/race-a/invitations",
            headers=_csrf_headers(owner_csrf),
            json={"email": "intended@red2pr.local", "role": "reviewer"},
        )
        raw_tok = inv_resp.json()["invite_token"]

        attacker_client, attacker_csrf, _ = await _provision_and_login_client(
            transport,
            iam,
            email="attacker@red2pr.local",
            display_name="Attacker Mallory",
        )
        clients_to_close.append(attacker_client)

        mismatch_resp = await attacker_client.post(
            "/api/v1/invitations/accept",
            headers=_csrf_headers(attacker_csrf),
            json={"token": raw_tok},
        )
        assert mismatch_resp.status_code == 403
        assert mismatch_resp.json()["code"] == "invite_email_mismatch"

        # 2. Simultaneous single-use invite redemption race -> 1x 200 + 1x 409 (SEC-038)
        intended_client, intended_csrf, _ = await _provision_and_login_client(
            transport,
            iam,
            email="intended@red2pr.local",
            display_name="Intended User",
        )
        clients_to_close.append(intended_client)

        r1, r2 = await asyncio.gather(
            intended_client.post(
                "/api/v1/invitations/accept",
                headers=_csrf_headers(intended_csrf),
                json={"token": raw_tok},
            ),
            intended_client.post(
                "/api/v1/invitations/accept",
                headers=_csrf_headers(intended_csrf),
                json={"token": raw_tok},
            ),
        )
        race_statuses = sorted([r1.status_code, r2.status_code])
        assert race_statuses == [200, 409]

        # 3. Expired invitation -> 410 invite_expired
        exp_inv = (
            await owner_client.post(
                "/api/v1/workspaces/race-a/invitations",
                headers=_csrf_headers(owner_csrf),
                json={
                    "email": "late@red2pr.local",
                    "role": "viewer",
                    "expires_at": (clock() + timedelta(minutes=10)).isoformat(),
                },
            )
        ).json()
        late_client, late_csrf, _ = await _provision_and_login_client(
            transport,
            iam,
            email="late@red2pr.local",
            display_name="Late User",
        )
        clients_to_close.append(late_client)
        clock.advance(minutes=11)
        exp_accept = await late_client.post(
            "/api/v1/invitations/accept",
            headers=_csrf_headers(late_csrf),
            json={"token": exp_inv["invite_token"]},
        )
        assert exp_accept.status_code == 410
        assert exp_accept.json()["code"] == "invite_expired"

        # 4. Cross-workspace S-04 cursor & cross-workspace repository_grants isolation (SEC-032)
        ws_a_page1 = (
            await owner_client.get("/api/v1/workspaces/race-a/members", params={"limit": 1})
        ).json()
        assert ws_a_page1["next_cursor"] is not None
        foreign_cursor_resp = await owner_client.get(
            "/api/v1/workspaces/race-b/members",
            params={"cursor": ws_a_page1["next_cursor"]},
        )
        assert foreign_cursor_resp.status_code == 400
        assert foreign_cursor_resp.json()["code"] == "invalid_cursor"

        # Grant repo_only_a in ws_a, then attempt to grant repo_only_a inside ws_b -> 404
        repo_only_a = new_uuid7(now=clock())
        intended_mem_a = next(
            m
            for m in (await owner_client.get("/api/v1/workspaces/race-a/members")).json()["items"]
            if m["role"] == "reviewer"
        )
        grant_a_ok = await owner_client.patch(
            f"/api/v1/workspaces/race-a/members/{intended_mem_a['id']}",
            headers=_csrf_headers(owner_csrf),
            json={"repository_grants": [repo_only_a]},
        )
        assert grant_a_ok.status_code == 200

        # Intended user's prior S-04 cursor in ws_a becomes 410 cursor_expired on grant_epoch bump
        intended_page = (
            await intended_client.get("/api/v1/workspaces/race-a/members", params={"limit": 1})
        ).json()
        stale_cursor = intended_page["next_cursor"]
        assert stale_cursor is not None
        await owner_client.patch(
            f"/api/v1/workspaces/race-a/members/{intended_mem_a['id']}",
            headers=_csrf_headers(owner_csrf),
            json={"role": "maintainer"},
        )
        stale_cursor_resp = await intended_client.get(
            "/api/v1/workspaces/race-a/members",
            params={"cursor": stale_cursor, "limit": 1},
        )
        assert stale_cursor_resp.status_code == 410
        assert stale_cursor_resp.json()["code"] == "cursor_expired"

        cross_repo_inv = await owner_client.post(
            "/api/v1/workspaces/race-b/invitations",
            headers=_csrf_headers(owner_csrf),
            json={
                "email": "attacker@red2pr.local",
                "role": "viewer",
                "repository_grants": [repo_only_a],
            },
        )
        assert cross_repo_inv.status_code == 404
        assert cross_repo_inv.json()["code"] == "repository_not_found"

        # 5. Sole last_admin demotion & deletion -> 409 last_admin, plus concurrent 2-admin race!
        ws_b_members = (await owner_client.get("/api/v1/workspaces/race-b/members")).json()["items"]
        sole_admin_mem = ws_b_members[0]
        demote_sole = await owner_client.patch(
            f"/api/v1/workspaces/race-b/members/{sole_admin_mem['id']}",
            headers=_csrf_headers(owner_csrf),
            json={"role": "viewer"},
        )
        assert demote_sole.status_code == 409
        assert demote_sole.json()["code"] == "last_admin"

        delete_sole = await owner_client.delete(
            f"/api/v1/workspaces/race-b/members/{sole_admin_mem['id']}",
            headers=_csrf_headers(owner_csrf),
        )
        assert delete_sole.status_code == 409
        assert delete_sole.json()["code"] == "last_admin"

        # Promote a second admin in ws_a, then race two concurrent DELETEs against both admins!
        promote_second = await owner_client.patch(
            f"/api/v1/workspaces/race-a/members/{intended_mem_a['id']}",
            headers=_csrf_headers(owner_csrf),
            json={"role": "admin"},
        )
        assert promote_second.status_code == 200

        ws_a_admins = [
            m
            for m in (await owner_client.get("/api/v1/workspaces/race-a/members")).json()["items"]
            if m["role"] == "admin"
        ]
        assert len(ws_a_admins) == 2

        del_a1, del_a2 = await asyncio.gather(
            owner_client.delete(
                f"/api/v1/workspaces/race-a/members/{ws_a_admins[0]['id']}",
                headers=_csrf_headers(owner_csrf),
            ),
            intended_client.delete(
                f"/api/v1/workspaces/race-a/members/{ws_a_admins[1]['id']}",
                headers=_csrf_headers(intended_csrf),
            ),
        )
        assert sorted([del_a1.status_code, del_a2.status_code]) == [204, 409]

        # 6. Non-owner workspace admin CANNOT disable mandatory TOTP MFA (ADR-034)
        admin2_pwd = "AdminTwoSup3rStr0ng!Pass#26"
        admin2_client, admin2_csrf, _ = await _provision_and_login_client(
            transport,
            iam,
            email="ws.admin2@red2pr.local",
            display_name="Workspace Admin Two",
            password=admin2_pwd,
        )
        clients_to_close.append(admin2_client)

        inv_admin2 = (
            await owner_client.post(
                "/api/v1/workspaces/race-b/invitations",
                headers=_csrf_headers(owner_csrf),
                json={"email": "ws.admin2@red2pr.local", "role": "admin"},
            )
        ).json()
        await admin2_client.post(
            "/api/v1/invitations/accept",
            headers=_csrf_headers(admin2_csrf),
            json={"token": inv_admin2["invite_token"]},
        )

        # Enroll MFA on admin2, then attempt DELETE /me/mfa -> 403 mfa_policy_mandatory!
        step_a2 = await admin2_client.post(
            "/api/v1/auth/step-up",
            headers=_csrf_headers(admin2_csrf),
            json={"password": admin2_pwd},
        )
        admin2_csrf = step_a2.json()["csrf_token"]
        enroll_s1 = (
            await admin2_client.post(
                "/api/v1/me/mfa",
                headers=_csrf_headers(admin2_csrf),
                json={},
            )
        ).json()
        totp_raw = _decode_base32_secret(enroll_s1["secret_base32"])
        otp_code = generate_totp_code_at(totp_raw, at_time=clock())
        enroll_s2 = (
            await admin2_client.post(
                "/api/v1/me/mfa",
                headers=_csrf_headers(admin2_csrf),
                json={"challenge_id": enroll_s1["challenge_id"], "otp": otp_code},
            )
        ).json()
        admin2_csrf = enroll_s2["csrf_token"]
        rec_code = enroll_s2["recovery_codes"][0]

        disable_mfa_resp = await admin2_client.request(
            "DELETE",
            "/api/v1/me/mfa",
            headers=_csrf_headers(admin2_csrf),
            json={"recovery_authorization": rec_code},
        )
        assert disable_mfa_resp.status_code == 403
        assert disable_mfa_resp.json()["code"] == "mfa_policy_mandatory"
        assert ws_a["id"] != ws_b["id"]
    finally:
        for c in clients_to_close:
            await c.aclose()
        await app_engine.dispose()


async def test_a21_sse_auth_repo_grant_filtering_cursor_replay_and_nfr04_5s_revocation_cutoff(
    migrated_db: PgTestUrls,
) -> None:
    """Verify A-21 cookie-only SSE, repo_grants filtering, Last-Event-ID & <=5s cutoff."""
    clock = ManualClock()
    app_engine, iam = _build_iam_stack(
        migrated_db.app_url,
        clock=clock,
        sse_poll_interval_seconds=0.04,
        sse_heartbeat_interval_seconds=0.30,
    )
    app = create_app(iam_service=iam)
    transport = httpx.ASGITransport(app=app)

    clients_to_close: list[httpx.AsyncClient] = []
    try:
        owner_client, owner_csrf, _ = await _claim_owner_client(transport, iam)
        clients_to_close.append(owner_client)

        ws_a = (
            await owner_client.post(
                "/api/v1/workspaces",
                headers=_csrf_headers(owner_csrf),
                json={"name": "Stream Alpha", "slug": "stream-alpha"},
            )
        ).json()
        ws_b = (
            await owner_client.post(
                "/api/v1/workspaces",
                headers=_csrf_headers(owner_csrf),
                json={"name": "Stream Beta", "slug": "stream-beta"},
            )
        ).json()

        repo_allowed = new_uuid7(now=clock())
        repo_secret = new_uuid7(now=clock())

        # Provision Bob in BOTH ws_a (maintainer, granted ONLY repo_allowed) and ws_b (viewer)
        bob_client, bob_csrf, _ = await _provision_and_login_client(
            transport,
            iam,
            email="bob.stream@red2pr.local",
            display_name="Bob Stream",
        )
        clients_to_close.append(bob_client)

        inv_a = (
            await owner_client.post(
                "/api/v1/workspaces/stream-alpha/invitations",
                headers=_csrf_headers(owner_csrf),
                json={
                    "email": "bob.stream@red2pr.local",
                    "role": "maintainer",
                    "repository_grants": [repo_allowed],
                },
            )
        ).json()
        bob_mem_a = (
            await bob_client.post(
                "/api/v1/invitations/accept",
                headers=_csrf_headers(bob_csrf),
                json={"token": inv_a["invite_token"]},
            )
        ).json()

        inv_b = (
            await owner_client.post(
                "/api/v1/workspaces/stream-beta/invitations",
                headers=_csrf_headers(owner_csrf),
                json={"email": "bob.stream@red2pr.local", "role": "viewer"},
            )
        ).json()
        await bob_client.post(
            "/api/v1/invitations/accept",
            headers=_csrf_headers(bob_csrf),
            json={"token": inv_b["invite_token"]},
        )

        # 1. Bearer token in URL query param or Authorization header -> 400 (A-21)
        q_tok_resp = await bob_client.get(
            "/api/v1/workspaces/stream-alpha/events?token=forbidden-secret"
        )
        assert q_tok_resp.status_code == 400
        assert q_tok_resp.json()["code"] == "bearer_token_forbidden"

        hdr_tok_resp = await bob_client.get(
            "/api/v1/workspaces/stream-alpha/events",
            headers={"Authorization": "Bearer forbidden-secret"},
        )
        assert hdr_tok_resp.status_code == 400
        assert hdr_tok_resp.json()["code"] == "bearer_token_forbidden"

        # 2. Anonymous SSE -> 401
        anon_client = httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL)
        clients_to_close.append(anon_client)
        assert (await anon_client.get("/api/v1/workspaces/stream-alpha/events")).status_code == 401

        # 3. Subscribing with ungranted repository_id filter -> 404 repository_not_found (SEC-010)
        ungranted_filter = await bob_client.get(
            "/api/v1/workspaces/stream-alpha/events",
            params={"repository_id": repo_secret},
        )
        assert ungranted_filter.status_code == 404
        assert ungranted_filter.json()["code"] == "repository_not_found"

        # 4. Per-event repo_grants filtering + signed Last-Event-ID cursor replay (SEC-010, SEC-032)
        baseline_cursor = encode_sse_event_cursor(
            signing_key=iam.csrf_signing_key,
            workspace_id=ws_a["id"],
            workspace_seq=0,
            now=clock(),
        )

        app_factory = create_session_factory(app_engine)
        secret_run_id = new_uuid7(now=clock())
        allowed_run_id = new_uuid7(now=clock())
        async with workspace_rls_session(app_factory, workspace_id=ws_a["id"]) as ws_db:
            await enqueue_outbox_event(
                ws_db,
                EventEnvelope(
                    event_id=new_uuid7(now=clock()),
                    type="provider.run.failed",
                    occurred_at=clock(),
                    workspace_id=ws_a["id"],
                    repository_id=repo_secret,
                    aggregate_id=secret_run_id,
                    aggregate_version=1,
                    correlation_id="corr-sse-secret",
                    payload=RunEventPayload(
                        run_id=secret_run_id,
                        attempt_key="gh-run-90001-attempt-1",
                        head_sha="a" * 40,
                    ),
                ),
                now=clock(),
            )
            await enqueue_outbox_event(
                ws_db,
                EventEnvelope(
                    event_id=new_uuid7(now=clock()),
                    type="provider.run.failed",
                    occurred_at=clock(),
                    workspace_id=ws_a["id"],
                    repository_id=repo_allowed,
                    aggregate_id=allowed_run_id,
                    aggregate_version=1,
                    correlation_id="corr-sse-allowed",
                    payload=RunEventPayload(
                        run_id=allowed_run_id,
                        attempt_key="gh-run-90002-attempt-1",
                        head_sha="b" * 40,
                    ),
                ),
                now=clock(),
            )

        replay_resp = await bob_client.get(
            "/api/v1/workspaces/stream-alpha/events",
            headers={"Last-Event-ID": baseline_cursor},
            params={"max_events": 1, "max_duration_seconds": 1.0},
        )
        assert replay_resp.status_code == 200
        assert replay_resp.headers["content-type"].startswith("text/event-stream")
        assert allowed_run_id in replay_resp.text
        assert secret_run_id not in replay_resp.text

        # Cross-workspace Last-Event-ID cursor -> 410 cursor_expired
        foreign_sse_resp = await bob_client.get(
            "/api/v1/workspaces/stream-beta/events",
            headers={"Last-Event-ID": baseline_cursor},
        )
        assert foreign_sse_resp.status_code == 410
        assert foreign_sse_resp.json()["code"] == "cursor_expired"

        # Expired Last-Event-ID cursor (+25h) -> 410 cursor_expired
        stale_sse_cursor = encode_sse_event_cursor(
            signing_key=iam.csrf_signing_key,
            workspace_id=ws_a["id"],
            workspace_seq=0,
            now=clock() - timedelta(hours=25),
        )
        expired_sse_resp = await bob_client.get(
            "/api/v1/workspaces/stream-alpha/events",
            headers={"Last-Event-ID": stale_sse_cursor},
        )
        assert expired_sse_resp.status_code == 410
        assert expired_sse_resp.json()["code"] == "cursor_expired"

        # 5. Live open SSE stream revocation cutoff <= 5s (NFR-04, SEC-022)
        # Note: httpx.ASGITransport buffers full responses before returning, so we drive
        # the real ASGI scope directly to observe live incremental StreamingResponse chunks.
        stream_connected = asyncio.Event()
        disconnect_event = asyncio.Event()
        collected_chunks: list[str] = []
        bob_cookie_hdr = "; ".join(f"{k}={v}" for k, v in bob_client.cookies.items())

        asgi_scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/api/v1/workspaces/stream-alpha/events",
            "raw_path": b"/api/v1/workspaces/stream-alpha/events",
            "query_string": b"max_duration_seconds=8.0",
            "root_path": "",
            "headers": [
                (b"host", b"127.0.0.1:4280"),
                (b"accept", b"text/event-stream"),
                (b"cookie", bob_cookie_hdr.encode("latin-1")),
            ],
            "client": ("127.0.0.1", 50123),
            "server": ("127.0.0.1", 4280),
        }

        request_sent = False

        async def _asgi_receive() -> dict[str, object]:
            nonlocal request_sent
            if not request_sent:
                request_sent = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await disconnect_event.wait()
            return {"type": "http.disconnect"}

        async def _asgi_send(message: dict[str, object]) -> None:
            msg_type = message.get("type")
            if msg_type == "http.response.start":
                assert message.get("status") == 200
            elif msg_type == "http.response.body":
                raw_body = message.get("body", b"")
                if isinstance(raw_body, bytes) and raw_body:
                    text_chunk = raw_body.decode("utf-8")
                    collected_chunks.append(text_chunk)
                    if ": connected" in text_chunk:
                        stream_connected.set()

        consumer_task = asyncio.create_task(app(asgi_scope, _asgi_receive, _asgi_send))  # type: ignore[arg-type]
        await asyncio.wait_for(stream_connected.wait(), timeout=2.0)

        revoke_t0 = time.perf_counter()
        remove_bob = await owner_client.delete(
            f"/api/v1/workspaces/stream-alpha/members/{bob_mem_a['id']}",
            headers=_csrf_headers(owner_csrf),
        )
        assert remove_bob.status_code == 204

        await asyncio.wait_for(consumer_task, timeout=5.0)
        disconnect_event.set()
        cutoff_elapsed = time.perf_counter() - revoke_t0
        full_stream_text = "".join(collected_chunks)

        # NFR-04: stream MUST emit identity.permission_revoked and close well within <= 5.0s!
        assert cutoff_elapsed < 5.0
        assert "event: identity.permission_revoked" in full_stream_text

        # Bob is immediately denied in stream-alpha (404), while stream-beta STILL works (200)!
        assert (await bob_client.get("/api/v1/workspaces/stream-alpha")).status_code == 404
        assert (await bob_client.get("/api/v1/workspaces/stream-beta")).status_code == 200
        assert ws_b["slug"] == "stream-beta"

        # Verify cryptographic audit hash-chain integrity across instance & workspace logs
        with tempfile.TemporaryDirectory(prefix="red2pr_u06_ckpt_") as ckpt_dir:
            priv_key = Ed25519PrivateKey.generate()
            pub_rec = export_ed25519_public_key_record(
                private_key=priv_key,
                key_id="audit-key-u06",
                not_before=clock() - timedelta(days=1),
            )
            keyring = KeyRing([pub_rec])
            ext_store = ExternalCheckpointStore(Path(ckpt_dir))

            async with instance_rls_session(app_factory, mode="audit_verifier") as verify_db:
                audit_rows = (await verify_db.scalars(select(AuditLogModel))).all()
                assert any(row.action == "workspace.member_removed" for row in audit_rows)
                verified_count = await verify_audit_chain(
                    verify_db,
                    external_store=ext_store,
                    keyring=keyring,
                )
                assert verified_count == len(audit_rows)
                assert verified_count >= 5
    finally:
        for c in clients_to_close:
            await c.aclose()
        await app_engine.dispose()
