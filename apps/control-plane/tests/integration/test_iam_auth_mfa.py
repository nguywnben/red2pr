"""PostgreSQL 16 integration & security tests for U05 IAM, sessions, CSRF, MFA & recovery.

Verifies against a real disposable PostgreSQL 16 instance (never SQLite mocks):
- Migration `0002_iam_users_sessions_mfa` reversibility (`upgrade -> downgrade -> upgrade`),
  fail-closed RLS isolation across all 7 IAM tables, and `W-01` DB trigger protecting the
  last active `is_instance_owner` from deletion, demotion, or disabling.
- `T-IAM-01-P` end-to-end lifecycle: `GET /auth/csrf` -> `POST /setup/claim` -> `GET /me` ->
  two-stage `POST /me/mfa` (once-only TOTP secret encrypted in Z2 `SecretBroker`, 10 HMAC-hashed
  single-use recovery codes) -> `POST /auth/logout` -> two-step `POST /auth/login` (cookie-free
  `mfa_required` challenge followed by TOTP verification) -> multi-session listing & revocation ->
  `POST /auth/recovery` rotating password, revoking active sessions, resetting MFA, emitting
  high-severity audit + `identity.permission_revoked` outbox event, and verifying audit chain.
- `T-IAM-01-N`, `SEC-026`, `SEC-038`, `NFR-05`, `ADR-034` negative & adversarial matrix:
  bootstrap replay (`409`), bootstrap expiry (`410`), non-loopback plain-HTTP claim (`403`),
  strict `extra="forbid"` body rejection (`422`), cross-origin `Origin` CSRF (`403`),
  missing/mismatched `X-CSRF-Token` (`403`), stale `>5m` step-up (`403 step_up_required`),
  session cookie rotation on `POST /auth/step-up`, mandatory privileged MFA policy denial
  (`403 mfa_policy_mandatory` + `security.policy.denied` outbox event) vs optional standard-user
  MFA disable (`204`), 30s TOTP replay rejection (`totp_replayed`), recovery code replay (`401`),
  per-`account+IP` `5 failed / 15m` rate limiting (`429 Retry-After`) without global account DoS,
  anti-enumeration response parity, `30m` sliding idle vs `12h` absolute session lifetime,
  and HTTPS `__Host-red2pr_session` `Secure` cookie attributes.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
import sys
import tempfile
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import httpx
import pgserver
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from py_contracts.crypto import KeyRing, MasterKeyRing, export_ed25519_public_key_record
from py_contracts.iam import SetupClaimRequest
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import (
    ExternalCheckpointStore,
    verify_audit_chain,
)
from red2pr_control.api.app import create_app
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.base import (
    AuditLogModel,
    AuthChallengeModel,
    AuthRateLimitModel,
    BootstrapTokenModel,
    MfaCredentialModel,
    OutboxEventModel,
    RecoveryCodeModel,
    SchemaMigrationRecordModel,
    SecretEntryModel,
    SessionModel,
    UserModel,
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
from red2pr_control.iam.csrf import CSRF_COOKIE_NAME
from red2pr_control.iam.mfa import generate_totp_code_at
from red2pr_control.iam.passwords import hash_password
from red2pr_control.iam.sessions import (
    HTTP_LOOPBACK_SESSION_COOKIE_NAME,
    HTTPS_SESSION_COOKIE_NAME,
    IamService,
)
from red2pr_control.secrets.broker import SecretBroker, SecretBrokerTotpVault

APP_ROLE_NAME = "red2pr_app"
APP_ROLE_PASSWORD = "red2pr_app_local_test_pw_05"
PUBLIC_BASE_URL = "http://127.0.0.1:4280"
ORIGIN_HEADERS = {"Origin": PUBLIC_BASE_URL}


class ManualClock:
    """Deterministic controllable UTC clock for testing TTL, step-up, TOTP & session expiry."""

    def __init__(self, initial: datetime | None = None) -> None:
        self._current = (initial or datetime(2026, 10, 27, 9, 0, 0, tzinfo=UTC)).astimezone(UTC)

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


def _decode_base32_secret(secret_b32: str) -> bytes:
    pad_len = (-len(secret_b32)) % 8
    return base64.b32decode(secret_b32 + ("=" * pad_len), casefold=True)


def _csrf_headers(token: str, *, origin: str | None = PUBLIC_BASE_URL) -> dict[str, str]:
    headers = {"X-CSRF-Token": token}
    if origin is not None:
        headers["Origin"] = origin
    return headers


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
        tempfile.TemporaryDirectory(prefix="red2pr_u05_pg16_") as tmp_dir,
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
    public_base_url: str = PUBLIC_BASE_URL,
) -> tuple[AsyncEngine, IamService, SecretBroker]:
    app_engine = create_app_engine(app_url, pool_size=2, max_overflow=2)
    app_factory = create_session_factory(app_engine)
    kek_ring = MasterKeyRing(
        active_version=1,
        keys={1: b"\x11" * 32},
    )
    redactor = Redactor()
    broker = SecretBroker(key_ring=kek_ring, redactor=redactor)
    totp_vault = SecretBrokerTotpVault(broker)
    iam = IamService(
        session_factory=app_factory,
        totp_vault=totp_vault,
        iam_seed_key=b"\x22" * 32,
        public_base_url=public_base_url,
        clock=clock,
    )
    return app_engine, iam, broker


async def test_migration_0002_reversibility_rls_isolation_and_w01_last_owner_guard(
    pg_urls: PgTestUrls,
) -> None:
    """Verify 0002 downgrade/upgrade reversibility, fail-closed RLS, and W-01 last-owner trigger."""
    run_alembic_downgrade(pg_urls.admin_url, "base", app_role_name=APP_ROLE_NAME)
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
    # Verify clean step-back to 0001 and re-upgrade to 0002 head
    run_alembic_downgrade(pg_urls.admin_url, "0001_foundation_spine", app_role_name=APP_ROLE_NAME)
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )

    clock = ManualClock()
    admin_engine = create_admin_engine(pg_urls.admin_url)
    app_engine, iam, _ = _build_iam_stack(pg_urls.app_url, clock=clock)
    try:
        admin_factory = create_session_factory(admin_engine)
        app_factory = create_session_factory(app_engine)

        async with admin_factory() as admin_sess, admin_sess.begin():
            mig0002 = await admin_sess.scalar(
                select(SchemaMigrationRecordModel).where(
                    SchemaMigrationRecordModel.revision == "0002_iam_users_sessions_mfa"
                )
            )
            assert mig0002 is not None
            assert mig0002.phase == "expand"
            assert mig0002.reversible is True
            assert len(mig0002.checksum_sha256) == 64

        boot_token, _ = await iam.issue_bootstrap_token()
        claim_resp, _ = await iam.claim_bootstrap_owner(
            payload=iam_claim_payload(
                bootstrap_token=boot_token,
                display_name="Primary Owner",
                email="owner1@example.org",
                password="StrongOwnerPassphrase!123",
            ),
            client_ip="127.0.0.1",
            user_agent="pytest",
            request_scheme="http",
            correlation_id="corr-mig-01",
        )
        owner1_id = claim_resp.user.id

        # 1. Fail-closed RLS: bare session without scope_mode sees 0 rows across all IAM tables
        async with app_factory() as bare_sess, bare_sess.begin():
            for model in (
                UserModel,
                BootstrapTokenModel,
                SessionModel,
                MfaCredentialModel,
                RecoveryCodeModel,
                AuthChallengeModel,
                AuthRateLimitModel,
            ):
                rows = (await bare_sess.scalars(select(model))).all()
                assert rows == []

        # 2. Workspace-scoped RLS cannot read instance-private auth credentials/tokens
        ws_id = new_uuid7(now=clock())
        async with instance_rls_session(app_factory, mode="instance_admin") as db:
            db.add(
                WorkspaceModel(
                    id=ws_id,
                    slug="acme",
                    name="Acme",
                    status="active",
                    paused=False,
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )

        async with workspace_rls_session(app_factory, workspace_id=ws_id) as ws_db:
            assert (await ws_db.scalars(select(BootstrapTokenModel))).all() == []
            assert (await ws_db.scalars(select(MfaCredentialModel))).all() == []
            assert (await ws_db.scalars(select(RecoveryCodeModel))).all() == []
            assert (await ws_db.scalars(select(SessionModel))).all() == []

        # 3. W-01 trigger blocks disabling, demoting, or deleting the sole active instance_owner
        with pytest.raises(DBAPIError, match="active_owner_removal_forbidden"):
            async with instance_rls_session(app_factory, mode="instance_admin") as db:
                u1 = await db.scalar(select(UserModel).where(UserModel.id == owner1_id))
                assert u1 is not None
                u1.status = "disabled"

        with pytest.raises(DBAPIError, match="active_owner_removal_forbidden"):
            async with instance_rls_session(app_factory, mode="instance_admin") as db:
                u1 = await db.scalar(select(UserModel).where(UserModel.id == owner1_id))
                assert u1 is not None
                u1.is_instance_owner = False

        with pytest.raises(DBAPIError, match="active_owner_removal_forbidden"):
            async with instance_rls_session(app_factory, mode="instance_admin") as db:
                u1 = await db.scalar(select(UserModel).where(UserModel.id == owner1_id))
                assert u1 is not None
                await db.delete(u1)

        # Adding a second active owner allows demoting the first while protecting the remaining one
        owner2_id = new_uuid7(now=clock())
        async with instance_rls_session(app_factory, mode="instance_admin") as db:
            db.add(
                UserModel(
                    id=owner2_id,
                    username="owner2",
                    email="owner2@example.org",
                    display_name="Backup Owner",
                    password_hash=hash_password("BackupOwnerPassphrase!123"),
                    status="active",
                    is_instance_owner=True,
                    mfa_enabled=False,
                    grant_epoch=1,
                    disabled_at=None,
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )

        async with instance_rls_session(app_factory, mode="instance_admin") as db:
            u1 = await db.scalar(select(UserModel).where(UserModel.id == owner1_id))
            assert u1 is not None
            u1.is_instance_owner = False
    finally:
        await app_engine.dispose()
        await admin_engine.dispose()


def iam_claim_payload(
    *,
    bootstrap_token: str,
    display_name: str,
    email: str | None,
    password: str,
) -> SetupClaimRequest:
    return SetupClaimRequest(
        bootstrap_token=bootstrap_token,
        display_name=display_name,
        email=email,
        password=password,
    )


async def test_end_to_end_bootstrap_mfa_login_sessions_recovery_and_audit_chain(
    migrated_db: PgTestUrls,
) -> None:
    """Verify full T-IAM-01-P lifecycle, once-only secrets, session revocation, recovery & audit."""
    clock = ManualClock()
    app_engine, iam, _ = _build_iam_stack(migrated_db.app_url, clock=clock)
    app = create_app(iam_service=iam)

    try:
        boot_token, _ = await iam.issue_bootstrap_token()
        transport1 = httpx.ASGITransport(app=app, client=("127.0.0.1", 51001))
        transport2 = httpx.ASGITransport(app=app, client=("127.0.0.1", 51002))

        async with (
            httpx.AsyncClient(
                transport=transport1,
                base_url=PUBLIC_BASE_URL,
                headers={"User-Agent": "Firefox/132.0 TestClient1"},
            ) as client1,
            httpx.AsyncClient(
                transport=transport2,
                base_url=PUBLIC_BASE_URL,
                headers={"User-Agent": "Chrome/131.0 TestClient2"},
            ) as client2,
        ):
            # 1. GET /auth/csrf reports bootstrap_claim_required=True and sets red2pr_csrf cookie
            csrf_res = await client1.get("/api/v1/auth/csrf")
            assert csrf_res.status_code == 200
            assert csrf_res.headers.get("Cache-Control") == "no-store"
            csrf_body = csrf_res.json()
            assert csrf_body["bootstrap_claim_required"] is True
            anon_csrf = csrf_body["csrf_token"]
            assert client1.cookies.get(CSRF_COOKIE_NAME) == anon_csrf

            # 2. POST /setup/claim creates Instance Owner & sets HttpOnly session cookie
            claim_res = await client1.post(
                "/api/v1/setup/claim",
                headers=_csrf_headers(anon_csrf),
                json={
                    "bootstrap_token": boot_token,
                    "display_name": "Alice Security",
                    "email": "alice@example.org",
                    "password": "AliceInitialPassphrase!2026",
                },
            )
            assert claim_res.status_code == 201
            claim_data = claim_res.json()
            assert claim_data["is_instance_owner"] is True
            assert claim_data["user"]["email"] == "alice@example.org"
            assert claim_data["session"]["auth_strength"] == "password"
            sess_csrf = claim_data["csrf_token"]

            set_cookie_headers = claim_res.headers.get_list("set-cookie")
            cookie_prefix = f"{HTTP_LOOPBACK_SESSION_COOKIE_NAME}="
            session_cookie_header = next(
                h for h in set_cookie_headers if h.startswith(cookie_prefix)
            )
            assert "HttpOnly" in session_cookie_header
            assert "SameSite=lax" in session_cookie_header
            initial_raw_session_cookie = client1.cookies.get(HTTP_LOOPBACK_SESSION_COOKIE_NAME)
            assert initial_raw_session_cookie is not None

            # Subsequent /auth/csrf shows bootstrap_claim_required=False
            csrf_after = await client1.get("/api/v1/auth/csrf")
            assert csrf_after.json()["bootstrap_claim_required"] is False

            # 3. GET /me returns profile, step_up_valid_until, and not_configured telegram_link
            me_res = await client1.get("/api/v1/me")
            assert me_res.status_code == 200
            me_body = me_res.json()
            assert me_body["mfa_enabled"] is False
            assert me_body["mfa_required_for_privileged"] is True
            assert me_body["telegram_link"]["status"] == "not_configured"
            assert me_body["step_up_valid_until"] is not None

            # 4. Stage 1 POST /me/mfa ({}) generates Z2-encrypted TOTP secret shown ONCE
            enroll1_res = await client1.post(
                "/api/v1/me/mfa",
                headers=_csrf_headers(sess_csrf),
                json={},
            )
            assert enroll1_res.status_code == 200
            enroll1_data = enroll1_res.json()
            assert enroll1_data["status"] == "enrollment_pending"
            secret_b32: str = enroll1_data["secret_base32"]
            enroll_challenge_id: str = enroll1_data["challenge_id"]
            assert enroll1_data["otpauth_uri"].startswith("otpauth://totp/Red2PR:")

            # Verify DB stores zero plaintext TOTP secret in mfa_credentials / secret_entries
            app_factory = create_session_factory(app_engine)
            async with instance_rls_session(app_factory, mode="instance_only") as db:
                cred_row = await db.scalar(
                    select(MfaCredentialModel).where(MfaCredentialModel.id == enroll_challenge_id)
                )
                assert cred_row is not None
                assert secret_b32 not in cred_row.secret_ref
                sec_row = await db.scalar(
                    select(SecretEntryModel).where(
                        SecretEntryModel.secret_ref == cred_row.secret_ref
                    )
                )
                assert sec_row is not None
                assert sec_row.purpose == "mfa_totp"
                assert secret_b32 not in json.dumps(sec_row.envelope_json)

            # 5. Stage 2 POST /me/mfa activates MFA, rotates session & returns 10 recovery codes
            raw_totp_secret = _decode_base32_secret(secret_b32)
            totp_code_t0 = generate_totp_code_at(raw_totp_secret, at_time=clock())
            enroll2_res = await client1.post(
                "/api/v1/me/mfa",
                headers=_csrf_headers(sess_csrf),
                json={"challenge_id": enroll_challenge_id, "otp": totp_code_t0},
            )
            assert enroll2_res.status_code == 200
            enroll2_data = enroll2_res.json()
            assert enroll2_data["status"] == "active"
            assert enroll2_data["session"]["auth_strength"] == "mfa"
            assert enroll2_data.get("secret_base32") is None
            recovery_codes: list[str] = enroll2_data["recovery_codes"]
            assert len(recovery_codes) == 10
            assert all(code.startswith("R2PR-") for code in recovery_codes)
            sess_csrf = enroll2_data["csrf_token"]

            rotated_session_cookie = client1.cookies.get(HTTP_LOOPBACK_SESSION_COOKIE_NAME)
            assert rotated_session_cookie != initial_raw_session_cookie

            # Verify recovery_codes in PostgreSQL contain ONLY 64-hex HMAC digests
            async with instance_rls_session(app_factory, mode="instance_only") as db:
                stored_codes = (await db.scalars(select(RecoveryCodeModel))).all()
                assert len(stored_codes) == 10
                for row in stored_codes:
                    assert len(row.code_hash) == 64
                    assert row.code_hash not in recovery_codes

            # Subsequent GET /me never exposes TOTP secret or recovery codes
            me_mfa_res = await client1.get("/api/v1/me")
            assert me_mfa_res.status_code == 200
            me_mfa_text = me_mfa_res.text
            assert secret_b32 not in me_mfa_text
            assert recovery_codes[0] not in me_mfa_text
            assert me_mfa_res.json()["mfa_enabled"] is True

            # 6. POST /auth/logout revokes session; old cookie cannot access /me
            logout_res = await client1.post(
                "/api/v1/auth/logout",
                headers=_csrf_headers(sess_csrf),
                json={},
            )
            assert logout_res.status_code == 204
            assert (await client1.get("/api/v1/me")).status_code == 401

            # Even if attacker replays the captured cookie string manually, server revoked it in DB!
            replay_res = await client1.get(
                "/api/v1/me",
                headers={
                    "Cookie": f"{HTTP_LOOPBACK_SESSION_COOKIE_NAME}={rotated_session_cookie or ''}"
                },
            )
            assert replay_res.status_code == 401
            client1.cookies.clear()

            # 7. Two-step MFA login: step 1 issues NO session cookie!
            csrf1 = (await client1.get("/api/v1/auth/csrf")).json()["csrf_token"]
            login_step1 = await client1.post(
                "/api/v1/auth/login",
                headers=_csrf_headers(csrf1),
                json={
                    "identifier": "alice@example.org",
                    "password": "AliceInitialPassphrase!2026",
                },
            )
            assert login_step1.status_code == 200
            step1_body = login_step1.json()
            assert step1_body["status"] == "mfa_required"
            assert step1_body.get("session") is None
            assert HTTP_LOOPBACK_SESSION_COOKIE_NAME not in client1.cookies
            assert (await client1.get("/api/v1/me")).status_code == 401

            # Advance clock +30s to next TOTP window and complete login
            clock.advance(seconds=30)
            totp_code_t1 = generate_totp_code_at(raw_totp_secret, at_time=clock())
            login_step2 = await client1.post(
                "/api/v1/auth/login",
                headers=_csrf_headers(csrf1),
                json={
                    "identifier": "alice@example.org",
                    "password": "AliceInitialPassphrase!2026",
                    "mfa_challenge_id": step1_body["mfa_challenge_id"],
                    "otp": totp_code_t1,
                },
            )
            assert login_step2.status_code == 200
            step2_body = login_step2.json()
            assert step2_body["status"] == "authenticated"
            assert step2_body["session"]["auth_strength"] == "mfa"
            c1_csrf = step2_body["csrf_token"]

            # 8. Second client signs in (next 30s TOTP timestep) -> list & revoke secondary session
            clock.advance(seconds=30)
            csrf2 = (await client2.get("/api/v1/auth/csrf")).json()["csrf_token"]
            c2_chal = (
                await client2.post(
                    "/api/v1/auth/login",
                    headers=_csrf_headers(csrf2),
                    json={
                        "identifier": "alice@example.org",
                        "password": "AliceInitialPassphrase!2026",
                    },
                )
            ).json()["mfa_challenge_id"]
            totp_code_t2 = generate_totp_code_at(raw_totp_secret, at_time=clock())
            c2_login = await client2.post(
                "/api/v1/auth/login",
                headers=_csrf_headers(csrf2),
                json={
                    "identifier": "alice@example.org",
                    "password": "AliceInitialPassphrase!2026",
                    "mfa_challenge_id": c2_chal,
                    "otp": totp_code_t2,
                },
            )
            assert c2_login.status_code == 200
            c2_session_id = c2_login.json()["session"]["id"]

            sessions_res = await client1.get("/api/v1/me/sessions")
            assert sessions_res.status_code == 200
            session_items = sessions_res.json()["items"]
            assert len(session_items) == 2
            assert sum(1 for item in session_items if item["is_current"]) == 1

            revoke_res = await client1.delete(
                f"/api/v1/me/sessions/{c2_session_id}",
                headers=_csrf_headers(c1_csrf),
            )
            assert revoke_res.status_code == 204
            assert (await client2.get("/api/v1/me")).status_code == 401

            # 9. Single-use recovery revokes Client 1 session, bumps grant_epoch & resets MFA
            client2.cookies.clear()
            rec_csrf = (await client2.get("/api/v1/auth/csrf")).json()["csrf_token"]
            rec_res = await client2.post(
                "/api/v1/auth/recovery",
                headers=_csrf_headers(rec_csrf),
                json={
                    "identifier": "alice@example.org",
                    "single_use_code": recovery_codes[0],
                    "new_password": "AliceRecoveredPassphrase!2027",
                },
            )
            assert rec_res.status_code == 200
            rec_body = rec_res.json()
            assert rec_body["mfa_re_enrollment_required"] is True
            assert rec_body["session"]["grant_epoch"] == 2

            # Prior Client 1 MFA session is immediately invalidated
            assert (await client1.get("/api/v1/me")).status_code == 401
            # Client 2 new recovery session is active with mfa_enabled=False
            c2_me = await client2.get("/api/v1/me")
            assert c2_me.status_code == 200
            assert c2_me.json()["mfa_enabled"] is False

            # Verify outbox event + intact cryptographic audit hash chain
            with tempfile.TemporaryDirectory(prefix="red2pr_u05_ckpt_") as ckpt_dir:
                priv_key = Ed25519PrivateKey.generate()
                pub_rec = export_ed25519_public_key_record(
                    private_key=priv_key,
                    key_id="audit-key-1",
                    not_before=clock() - timedelta(days=1),
                )
                keyring = KeyRing([pub_rec])
                ext_store = ExternalCheckpointStore(Path(ckpt_dir))

                async with instance_rls_session(app_factory, mode="audit_verifier") as db:
                    audit_rows = (await db.scalars(select(AuditLogModel))).all()
                    assert any(
                        row.action == "auth.recovery_used"
                        and row.metadata_json.get("severity") == "high"
                        for row in audit_rows
                    )
                    verified_count = await verify_audit_chain(
                        db,
                        external_store=ext_store,
                        keyring=keyring,
                    )
                    assert verified_count == len(audit_rows)

                async with instance_rls_session(app_factory, mode="instance_only") as db:
                    outbox_events = (await db.scalars(select(OutboxEventModel))).all()
                    assert any(
                        ev.event_type == "identity.permission_revoked" for ev in outbox_events
                    )
    finally:
        await app_engine.dispose()


async def test_bootstrap_replay_expiry_loopback_and_strict_schema_negatives(
    migrated_db: PgTestUrls,
) -> None:
    """Verify bootstrap expiry (410), non-loopback HTTP block (403), replay (409) & 422 checks."""
    clock = ManualClock()
    app_engine, iam, _ = _build_iam_stack(migrated_db.app_url, clock=clock)
    app = create_app(iam_service=iam)

    try:
        expiring_token, _ = await iam.issue_bootstrap_token(ttl_seconds=600, loopback_only=True)
        loopback_transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 51010))
        remote_transport = httpx.ASGITransport(app=app, client=("198.51.100.25", 51011))

        async with (
            httpx.AsyncClient(
                transport=loopback_transport,
                base_url=PUBLIC_BASE_URL,
            ) as local_client,
            httpx.AsyncClient(
                transport=remote_transport,
                base_url=PUBLIC_BASE_URL,
            ) as remote_client,
        ):
            # 1. Non-loopback plain HTTP client rejected with 403 bootstrap_loopback_required
            remote_csrf = (await remote_client.get("/api/v1/auth/csrf")).json()["csrf_token"]
            non_loopback_res = await remote_client.post(
                "/api/v1/setup/claim",
                headers=_csrf_headers(remote_csrf),
                json={
                    "bootstrap_token": expiring_token,
                    "display_name": "Remote Attacker",
                    "password": "AttackerLongPassphrase!123",
                },
            )
            assert non_loopback_res.status_code == 403
            assert non_loopback_res.json()["code"] == "bootstrap_loopback_required"

            # 2. Extra undeclared role/privilege fields rejected with 422 validation_error
            local_csrf = (await local_client.get("/api/v1/auth/csrf")).json()["csrf_token"]
            extra_field_res = await local_client.post(
                "/api/v1/setup/claim",
                headers=_csrf_headers(local_csrf),
                json={
                    "bootstrap_token": expiring_token,
                    "display_name": "Extra Role",
                    "password": "ValidLongPassphrase!1234",
                    "role": "instance_owner",
                },
            )
            assert extra_field_res.status_code == 422
            assert extra_field_res.json()["code"] == "validation_error"

            # 2b. Identity-echo password rejected with 422 weak_password
            echo_pw_res = await local_client.post(
                "/api/v1/setup/claim",
                headers=_csrf_headers(local_csrf),
                json={
                    "bootstrap_token": expiring_token,
                    "display_name": "AdminEcho",
                    "password": "MyAdminEchoPassphrase!99",
                },
            )
            assert echo_pw_res.status_code == 422
            assert echo_pw_res.json()["code"] == "weak_password"

            # 3. Advance clock past 10m TTL -> 410 bootstrap_expired
            clock.advance(minutes=11)
            local_csrf = (await local_client.get("/api/v1/auth/csrf")).json()["csrf_token"]
            expired_res = await local_client.post(
                "/api/v1/setup/claim",
                headers=_csrf_headers(local_csrf),
                json={
                    "bootstrap_token": expiring_token,
                    "display_name": "Late Owner",
                    "password": "ValidLongPassphrase!1234",
                },
            )
            assert expired_res.status_code == 410
            assert expired_res.json()["code"] == "bootstrap_expired"

            # 4. Issue fresh token, claim once (201), then replay -> 409 already_claimed
            fresh_token, _ = await iam.issue_bootstrap_token(ttl_seconds=900)
            local_csrf = (await local_client.get("/api/v1/auth/csrf")).json()["csrf_token"]
            ok_claim = await local_client.post(
                "/api/v1/setup/claim",
                headers=_csrf_headers(local_csrf),
                json={
                    "bootstrap_token": fresh_token,
                    "display_name": "Real Owner",
                    "email": "owner@example.org",
                    "password": "ValidLongPassphrase!1234",
                },
            )
            assert ok_claim.status_code == 201

            local_client.cookies.clear()
            replay_csrf = (await local_client.get("/api/v1/auth/csrf")).json()["csrf_token"]
            replay_claim = await local_client.post(
                "/api/v1/setup/claim",
                headers=_csrf_headers(replay_csrf),
                json={
                    "bootstrap_token": fresh_token,
                    "display_name": "Replay Attacker",
                    "password": "ValidLongPassphrase!1234",
                },
            )
            assert replay_claim.status_code == 409
            assert replay_claim.json()["code"] == "already_claimed"

            # Extra fields on /auth/login also rejected 422
            extra_login = await local_client.post(
                "/api/v1/auth/login",
                headers=_csrf_headers(replay_csrf),
                json={
                    "identifier": "owner@example.org",
                    "password": "ValidLongPassphrase!1234",
                    "is_instance_owner": True,
                },
            )
            assert extra_login.status_code == 422
    finally:
        await app_engine.dispose()


async def test_csrf_origin_validation_step_up_staleness_and_mandatory_mfa_policy(
    migrated_db: PgTestUrls,
) -> None:
    """Verify SEC-026 CSRF/Origin checks, 5m step-up staleness & ADR-034 mandatory MFA policy."""
    clock = ManualClock()
    app_engine, iam, _ = _build_iam_stack(migrated_db.app_url, clock=clock)
    app = create_app(iam_service=iam)

    try:
        boot_token, _ = await iam.issue_bootstrap_token()
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 51020))

        async with httpx.AsyncClient(transport=transport, base_url=PUBLIC_BASE_URL) as client:
            anon_csrf = (await client.get("/api/v1/auth/csrf")).json()["csrf_token"]

            # 1. Cross-origin POST on pre-auth endpoint rejected even with valid CSRF token + cookie
            evil_claim = await client.post(
                "/api/v1/setup/claim",
                headers=_csrf_headers(anon_csrf, origin="https://evil.example"),
                json={
                    "bootstrap_token": boot_token,
                    "display_name": "Owner",
                    "password": "CobaltQuantum#7391$Vault",
                },
            )
            assert evil_claim.status_code == 403
            assert evil_claim.json()["code"] == "csrf_origin_denied"

            # Missing X-CSRF-Token rejected with 403 csrf_invalid
            missing_csrf_claim = await client.post(
                "/api/v1/setup/claim",
                headers=ORIGIN_HEADERS,
                json={
                    "bootstrap_token": boot_token,
                    "display_name": "Owner",
                    "password": "CobaltQuantum#7391$Vault",
                },
            )
            assert missing_csrf_claim.status_code == 403
            assert missing_csrf_claim.json()["code"] == "csrf_invalid"

            # Valid claim succeeds
            claim_ok = await client.post(
                "/api/v1/setup/claim",
                headers=_csrf_headers(anon_csrf),
                json={
                    "bootstrap_token": boot_token,
                    "display_name": "Owner",
                    "email": "owner@example.org",
                    "password": "CobaltQuantum#7391$Vault",
                },
            )
            assert claim_ok.status_code == 201
            sess_csrf = claim_ok.json()["csrf_token"]
            pre_stepup_cookie = client.cookies.get(HTTP_LOOPBACK_SESSION_COOKIE_NAME)

            # 2. Cross-origin POST on authenticated endpoint with valid session cookie rejected
            evil_mfa = await client.post(
                "/api/v1/me/mfa",
                headers=_csrf_headers(sess_csrf, origin="https://evil.example"),
                json={},
            )
            assert evil_mfa.status_code == 403
            assert evil_mfa.json()["code"] == "csrf_origin_denied"

            # 3. Advance clock +6m (> 5m step_up_at) -> POST /me/mfa denied 403 step_up_required
            clock.advance(minutes=6)
            stale_mfa = await client.post(
                "/api/v1/me/mfa",
                headers=_csrf_headers(sess_csrf),
                json={},
            )
            assert stale_mfa.status_code == 403
            assert stale_mfa.json()["code"] == "step_up_required"

            # Fresh POST /auth/step-up rotates session cookie and unlocks POST /me/mfa
            step_res = await client.post(
                "/api/v1/auth/step-up",
                headers=_csrf_headers(sess_csrf),
                json={"password": "CobaltQuantum#7391$Vault"},
            )
            assert step_res.status_code == 200
            sess_csrf = step_res.json()["csrf_token"]
            post_stepup_cookie = client.cookies.get(HTTP_LOOPBACK_SESSION_COOKIE_NAME)
            assert post_stepup_cookie != pre_stepup_cookie

            # Enroll MFA on Instance Owner
            e1 = (
                await client.post("/api/v1/me/mfa", headers=_csrf_headers(sess_csrf), json={})
            ).json()
            owner_totp_secret = _decode_base32_secret(e1["secret_base32"])
            e2 = await client.post(
                "/api/v1/me/mfa",
                headers=_csrf_headers(sess_csrf),
                json={
                    "challenge_id": e1["challenge_id"],
                    "otp": generate_totp_code_at(owner_totp_secret, at_time=clock()),
                },
            )
            assert e2.status_code == 200
            owner_codes: list[str] = e2.json()["recovery_codes"]
            sess_csrf = e2.json()["csrf_token"]

            # 4. ADR-034 mandatory privileged MFA: Instance Owner CANNOT disable MFA
            deny_disable = await client.request(
                "DELETE",
                "/api/v1/me/mfa",
                headers=_csrf_headers(sess_csrf),
                json={"recovery_authorization": owner_codes[0]},
            )
            assert deny_disable.status_code == 403
            assert deny_disable.json()["code"] == "mfa_policy_mandatory"

            app_factory = create_session_factory(app_engine)
            async with instance_rls_session(app_factory, mode="instance_only") as db:
                outbox_rows = (await db.scalars(select(OutboxEventModel))).all()
                assert any(ev.event_type == "security.policy.denied" for ev in outbox_rows)

            # 5. Standard non-owner user with optional MFA CAN disable MFA with step-up + code
            async with instance_rls_session(app_factory, mode="instance_admin") as db:
                db.add(
                    UserModel(
                        id=new_uuid7(now=clock()),
                        username="member1",
                        email="member1@example.org",
                        display_name="Standard Member",
                        password_hash=hash_password("NebulaTimber#8462$Forge"),
                        status="active",
                        is_instance_owner=False,
                        mfa_enabled=False,
                        grant_epoch=1,
                        disabled_at=None,
                        version=1,
                        created_at=clock(),
                        updated_at=clock(),
                    )
                )

            client.cookies.clear()
            m_csrf = (await client.get("/api/v1/auth/csrf")).json()["csrf_token"]
            m_login = await client.post(
                "/api/v1/auth/login",
                headers=_csrf_headers(m_csrf),
                json={
                    "identifier": "member1@example.org",
                    "password": "NebulaTimber#8462$Forge",
                },
            )
            assert m_login.status_code == 200
            m_csrf = m_login.json()["csrf_token"]

            # Standard user login does not pre-populate step_up_at -> step-up required first
            m_step = await client.post(
                "/api/v1/auth/step-up",
                headers=_csrf_headers(m_csrf),
                json={"password": "NebulaTimber#8462$Forge"},
            )
            assert m_step.status_code == 200
            m_csrf = m_step.json()["csrf_token"]

            me1 = (
                await client.post("/api/v1/me/mfa", headers=_csrf_headers(m_csrf), json={})
            ).json()
            member_secret = _decode_base32_secret(me1["secret_base32"])
            me2 = await client.post(
                "/api/v1/me/mfa",
                headers=_csrf_headers(m_csrf),
                json={
                    "challenge_id": me1["challenge_id"],
                    "otp": generate_totp_code_at(member_secret, at_time=clock()),
                },
            )
            assert me2.status_code == 200
            member_codes: list[str] = me2.json()["recovery_codes"]
            m_csrf = me2.json()["csrf_token"]

            del_ok = await client.request(
                "DELETE",
                "/api/v1/me/mfa",
                headers=_csrf_headers(m_csrf),
                json={"recovery_authorization": member_codes[0]},
            )
            assert del_ok.status_code == 204
            assert (await client.get("/api/v1/me")).json()["mfa_enabled"] is False
    finally:
        await app_engine.dispose()


async def test_totp_replay_recovery_code_replay_rate_limits_and_session_timeouts(
    migrated_db: PgTestUrls,
) -> None:
    """Verify TOTP/recovery replay block, NFR-05 per-account+IP rate limit & session timeouts."""
    clock = ManualClock()
    app_engine, iam, _ = _build_iam_stack(migrated_db.app_url, clock=clock)
    app = create_app(iam_service=iam)

    try:
        boot_token, _ = await iam.issue_bootstrap_token()
        ip1_transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 51030))
        ip2_transport = httpx.ASGITransport(app=app, client=("198.51.100.88", 51031))

        async with (
            httpx.AsyncClient(transport=ip1_transport, base_url=PUBLIC_BASE_URL) as client_ip1,
            httpx.AsyncClient(transport=ip2_transport, base_url=PUBLIC_BASE_URL) as client_ip2,
        ):
            csrf = (await client_ip1.get("/api/v1/auth/csrf")).json()["csrf_token"]
            claim = await client_ip1.post(
                "/api/v1/setup/claim",
                headers=_csrf_headers(csrf),
                json={
                    "bootstrap_token": boot_token,
                    "display_name": "Alice",
                    "email": "alice@example.org",
                    "password": "SolarHorizon#5927$Anchor",
                },
            )
            assert claim.status_code == 201
            csrf = claim.json()["csrf_token"]

            # Enroll MFA and capture secret + recovery codes
            e1 = (
                await client_ip1.post("/api/v1/me/mfa", headers=_csrf_headers(csrf), json={})
            ).json()
            secret_bytes = _decode_base32_secret(e1["secret_base32"])
            otp_used = generate_totp_code_at(secret_bytes, at_time=clock())
            e2 = await client_ip1.post(
                "/api/v1/me/mfa",
                headers=_csrf_headers(csrf),
                json={"challenge_id": e1["challenge_id"], "otp": otp_used},
            )
            assert e2.status_code == 200
            codes: list[str] = e2.json()["recovery_codes"]
            csrf = e2.json()["csrf_token"]

            # 1. TOTP replay within the exact same 30s timestep on /auth/step-up is rejected (401)
            totp_replay_res = await client_ip1.post(
                "/api/v1/auth/step-up",
                headers=_csrf_headers(csrf),
                json={"password": "SolarHorizon#5927$Anchor", "otp": otp_used},
            )
            assert totp_replay_res.status_code == 401
            assert totp_replay_res.json()["code"] == "invalid_totp"

            # 2. Session 30m sliding idle timeout vs 12h absolute lifetime
            clock.advance(minutes=20)
            assert (await client_ip1.get("/api/v1/me")).status_code == 200  # renews idle_expires_at
            clock.advance(minutes=20)
            assert (await client_ip1.get("/api/v1/me")).status_code == 200  # T+40m still alive!
            clock.advance(minutes=31)
            assert (await client_ip1.get("/api/v1/me")).status_code == 401  # >30m idle expired!

            # Re-login and verify 12h absolute ceiling even when kept active every 25m
            client_ip1.cookies.clear()
            csrf = (await client_ip1.get("/api/v1/auth/csrf")).json()["csrf_token"]
            chal = (
                await client_ip1.post(
                    "/api/v1/auth/login",
                    headers=_csrf_headers(csrf),
                    json={
                        "identifier": "alice@example.org",
                        "password": "SolarHorizon#5927$Anchor",
                    },
                )
            ).json()["mfa_challenge_id"]
            login_ok = await client_ip1.post(
                "/api/v1/auth/login",
                headers=_csrf_headers(csrf),
                json={
                    "identifier": "alice@example.org",
                    "password": "SolarHorizon#5927$Anchor",
                    "mfa_challenge_id": chal,
                    "otp": generate_totp_code_at(secret_bytes, at_time=clock()),
                },
            )
            assert login_ok.status_code == 200
            for _ in range(28):  # 28 * 25m = 700m (11h40m)
                clock.advance(minutes=25)
                assert (await client_ip1.get("/api/v1/me")).status_code == 200
            clock.advance(minutes=21)  # 721m > 720m (12h)
            assert (await client_ip1.get("/api/v1/me")).status_code == 401

            # 3. Anti-enumeration parity & NFR-05 per-(account, IP) rate limit (5 failed / 15m)
            client_ip1.cookies.clear()
            csrf_ip1 = (await client_ip1.get("/api/v1/auth/csrf")).json()["csrf_token"]
            unknown_res = await client_ip1.post(
                "/api/v1/auth/login",
                headers=_csrf_headers(csrf_ip1),
                json={
                    "identifier": "nonexistent@example.org",
                    "password": "WrongPassword!1234",
                },
            )
            wrong_pw_res = await client_ip1.post(
                "/api/v1/auth/login",
                headers=_csrf_headers(csrf_ip1),
                json={
                    "identifier": "alice@example.org",
                    "password": "WrongPassword!1234",
                },
            )
            assert unknown_res.status_code == wrong_pw_res.status_code == 401
            assert unknown_res.json()["code"] == "invalid_credentials"
            assert wrong_pw_res.json()["code"] == "invalid_credentials"
            assert unknown_res.json()["detail"] == wrong_pw_res.json()["detail"]

            # 4 more wrong attempts for alice@example.org on IP1 reaches 5 total failures
            for _ in range(4):
                r = await client_ip1.post(
                    "/api/v1/auth/login",
                    headers=_csrf_headers(csrf_ip1),
                    json={
                        "identifier": "alice@example.org",
                        "password": "WrongPassword!1234",
                    },
                )
                assert r.status_code == 401

            sixth_ip1 = await client_ip1.post(
                "/api/v1/auth/login",
                headers=_csrf_headers(csrf_ip1),
                json={
                    "identifier": "alice@example.org",
                    "password": "SolarHorizon#5927$Anchor",
                },
            )
            assert sixth_ip1.status_code == 429
            assert sixth_ip1.json()["code"] == "rate_limited"
            assert int(sixth_ip1.headers["Retry-After"]) > 0

            # Crucial NFR-05 invariant: IP2 is NOT locked out for alice@example.org!
            clock.advance(seconds=30)
            csrf_ip2 = (await client_ip2.get("/api/v1/auth/csrf")).json()["csrf_token"]
            chal_ip2 = await client_ip2.post(
                "/api/v1/auth/login",
                headers=_csrf_headers(csrf_ip2),
                json={
                    "identifier": "alice@example.org",
                    "password": "SolarHorizon#5927$Anchor",
                },
            )
            assert chal_ip2.status_code == 200
            assert chal_ip2.json()["status"] == "mfa_required"

            # 4. Single-use recovery code replay & 5-failure recovery rate limit (SEC-038)
            client_ip2.cookies.clear()
            rec_csrf = (await client_ip2.get("/api/v1/auth/csrf")).json()["csrf_token"]
            rec_first = await client_ip2.post(
                "/api/v1/auth/recovery",
                headers=_csrf_headers(rec_csrf),
                json={
                    "identifier": "alice@example.org",
                    "single_use_code": codes[1],
                    "new_password": "LunarGranite#4183$Prism",
                },
            )
            assert rec_first.status_code == 200

            client_ip2.cookies.clear()
            rec_csrf2 = (await client_ip2.get("/api/v1/auth/csrf")).json()["csrf_token"]
            # Replaying codes[1] fails 401, and 5 total bad recovery attempts trigger 429
            replay_rec = await client_ip2.post(
                "/api/v1/auth/recovery",
                headers=_csrf_headers(rec_csrf2),
                json={
                    "identifier": "alice@example.org",
                    "single_use_code": codes[1],
                    "new_password": "AnotherNewPassword!1234",
                },
            )
            assert replay_rec.status_code == 401
            assert replay_rec.json()["code"] == "invalid_recovery_code"

            for _ in range(4):
                bad_rec = await client_ip2.post(
                    "/api/v1/auth/recovery",
                    headers=_csrf_headers(rec_csrf2),
                    json={
                        "identifier": "alice@example.org",
                        "single_use_code": f"R2PR-DEAD-BEEF-{secrets.token_hex(2).upper()}",
                        "new_password": "AnotherNewPassword!1234",
                    },
                )
                assert bad_rec.status_code == 401

            limited_rec = await client_ip2.post(
                "/api/v1/auth/recovery",
                headers=_csrf_headers(rec_csrf2),
                json={
                    "identifier": "alice@example.org",
                    "single_use_code": "R2PR-DEAD-BEEF-9999",
                    "new_password": "AnotherNewPassword!1234",
                },
            )
            assert limited_rec.status_code == 429
            assert int(limited_rec.headers["Retry-After"]) > 0

        # 5. HTTPS public_base_url enforces __Host-red2pr_session + Secure cookie flags
        https_url = "https://red2pr.internal.example"
        https_engine, https_iam, _ = _build_iam_stack(
            migrated_db.app_url,
            clock=clock,
            public_base_url=https_url,
        )
        try:
            https_app = create_app(iam_service=https_iam)
            https_transport = httpx.ASGITransport(app=https_app, client=("198.51.100.99", 51040))
            async with httpx.AsyncClient(transport=https_transport, base_url=https_url) as hclient:
                h_csrf_res = await hclient.get("/api/v1/auth/csrf")
                h_csrf = h_csrf_res.json()["csrf_token"]
                h_login = await hclient.post(
                    "/api/v1/auth/login",
                    headers={"X-CSRF-Token": h_csrf, "Origin": https_url},
                    json={
                        "identifier": "alice@example.org",
                        "password": "LunarGranite#4183$Prism",
                    },
                )
                assert h_login.status_code == 200
                set_cookies = h_login.headers.get_list("set-cookie")
                host_cookie = next(
                    c for c in set_cookies if c.startswith(f"{HTTPS_SESSION_COOKIE_NAME}=")
                )
                assert "Secure" in host_cookie
                assert "HttpOnly" in host_cookie
                assert "Path=/" in host_cookie
        finally:
            await https_engine.dispose()
    finally:
        await app_engine.dispose()
