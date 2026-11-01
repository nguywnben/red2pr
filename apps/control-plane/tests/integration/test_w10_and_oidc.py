"""U28 W-10 capability and OIDC federation security integration tests."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import parse_qs, urlparse, urlunparse

import httpx
import pgserver
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from py_contracts.crypto import MasterKeyRing
from py_contracts.primitives import new_uuid7
from red2pr_control.api.app import create_app
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.base import (
    InstanceModel,
    MembershipModel,
    OidcGroupMappingModel,
    OidcIdentityModel,
    OidcMembershipGrantModel,
    UserModel,
    WorkspaceModel,
)
from red2pr_control.db.engine import (
    create_admin_engine,
    create_session_factory,
    install_rls_pool_guards,
    run_alembic_downgrade,
    run_alembic_upgrade,
)
from red2pr_control.db.rls import instance_rls_session
from red2pr_control.iam.csrf import CSRF_COOKIE_NAME
from red2pr_control.iam.passwords import hash_password
from red2pr_control.iam.sessions import IamService, session_cookie_name
from red2pr_control.operations.runtime import dispose_operation_lock_engine
from red2pr_control.secrets.broker import SecretBroker, SecretBrokerTotpVault

APP_ROLE = "red2pr_app"
PUBLIC_URL = "http://127.0.0.1:4280"
OIDC_ISSUER = "https://idp.example.test/tenant"
OIDC_CLIENT_ID = "red2pr-test-client"


@dataclass(frozen=True)
class LabDatabase:
    admin_url: str
    app_url: str
    app_role_password: str


@pytest.fixture(scope="module")
def lab_database(tmp_path_factory: pytest.TempPathFactory) -> Iterator[LabDatabase]:
    external_admin = os.environ.get("RED2PR_TEST_ADMIN_DATABASE_URL")
    if external_admin:
        parsed = urlparse(external_admin)
        admin_url = external_admin
    else:
        directory = str(tmp_path_factory.mktemp("red2pr_u28_pg16_"))
        with pgserver.get_server(directory, cleanup_mode="delete") as server:
            parsed = urlparse(server.get_uri())
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
            yield _lab_database_urls(parsed, admin_url)
        return
    yield _lab_database_urls(parsed, admin_url)


def _lab_database_urls(parsed: Any, admin_url: str) -> LabDatabase:
    role_password = secrets.token_urlsafe(32)
    host = parsed.hostname or "127.0.0.1"
    port = f":{parsed.port}" if parsed.port else ""
    app_url = urlunparse(
        (
            "postgresql+psycopg",
            f"{APP_ROLE}:{role_password}@{host}{port}",
            parsed.path or "/postgres",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )
    return LabDatabase(admin_url, app_url, role_password)


@pytest.fixture
def migrated_database(lab_database: LabDatabase) -> Iterator[LabDatabase]:
    run_alembic_downgrade(lab_database.admin_url, "base", app_role_name=APP_ROLE)
    run_alembic_upgrade(
        lab_database.admin_url,
        "head",
        app_role_name=APP_ROLE,
        app_role_password=lab_database.app_role_password,
    )
    yield lab_database


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign_id_token(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    nonce: str,
    now: int,
    subject: str = "person-123",
    email: str = "person@example.test",
    email_verified: bool = True,
    issuer: str = OIDC_ISSUER,
    audience: Any = OIDC_CLIENT_ID,
    groups: list[str] | None = None,
) -> str:
    claims = {
        "iss": issuer,
        "aud": audience,
        "exp": now + 300,
        "iat": now,
        "nonce": nonce,
        "sub": subject,
        "email": email,
        "email_verified": email_verified,
        "name": "OIDC Test User",
        "groups": groups or [],
    }
    header = _b64(json.dumps({"alg": "ES256", "kid": "test-key"}).encode())
    payload = _b64(json.dumps(claims).encode())
    signature_der = private_key.sign(
        f"{header}.{payload}".encode("ascii"), ec.ECDSA(hashes.SHA256())
    )
    r, s = decode_dss_signature(signature_der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{header}.{payload}.{_b64(signature)}"


def _jwks(private_key: ec.EllipticCurvePrivateKey) -> dict[str, object]:
    point = private_key.public_key().public_numbers()
    return {
        "keys": [
            {
                "kid": "test-key",
                "kty": "EC",
                "crv": "P-256",
                "x": _b64(point.x.to_bytes(32, "big")),
                "y": _b64(point.y.to_bytes(32, "big")),
                "use": "sig",
                "alg": "ES256",
            }
        ]
    }


def test_w10_defaults_are_explicit_and_closed() -> None:
    client = TestClient(create_app())
    response = client.get("/api/v1/system/capabilities")
    assert response.status_code == 200
    statuses = {item["id"]: item["status"] for item in response.json()["capabilities"]}
    assert statuses == {
        "iam-03-oidc": "not_configured",
        "src-05-relay": "disabled",
        "agt-04-model-fallback": "disabled",
        "san-04-fleet-sandbox": "unsupported",
        "ext-02-mcp": "disabled",
    }
    assert response.json()["oidc_providers"] == []


def test_u28_migration_is_reversible(lab_database: LabDatabase) -> None:
    run_alembic_upgrade(
        lab_database.admin_url,
        "head",
        app_role_name=APP_ROLE,
        app_role_password=lab_database.app_role_password,
    )
    run_alembic_downgrade(
        lab_database.admin_url, "0022_backups_migrations_ops", app_role_name=APP_ROLE
    )
    run_alembic_upgrade(
        lab_database.admin_url,
        "head",
        app_role_name=APP_ROLE,
        app_role_password=lab_database.app_role_password,
    )
    engine = create_admin_engine(lab_database.admin_url)

    async def verify() -> None:
        async with engine.connect() as connection:
            tables = await connection.run_sync(
                lambda sync: set(__import__("sqlalchemy").inspect(sync).get_table_names())
            )
            assert {
                "extension_capabilities",
                "oidc_providers",
                "oidc_auth_transactions",
                "oidc_identities",
                "oidc_group_mappings",
                "oidc_membership_grants",
            } <= tables

    try:
        asyncio.run(verify())
    finally:
        asyncio.run(engine.dispose())


def test_oidc_pkce_claim_validation_provisioning_and_deprovisioning(
    migrated_database: LabDatabase,
) -> None:
    engine: AsyncEngine = create_async_engine(
        migrated_database.app_url, poolclass=NullPool
    )
    install_rls_pool_guards(engine)
    factory = create_session_factory(engine)
    broker = SecretBroker(
        key_ring=MasterKeyRing(active_version=1, keys={1: b"\x41" * 32}),
        redactor=Redactor(),
    )
    iam = IamService(
        session_factory=factory,
        totp_vault=SecretBrokerTotpVault(broker),
        iam_seed_key=b"\x42" * 32,
        public_base_url=PUBLIC_URL,
    )
    private_key = ec.generate_private_key(ec.SECP256R1())
    jwks = _jwks(private_key)
    state_for_token: dict[str, str] = {}
    groups_for_token: dict[str, list[str]] = {"groups": ["red2pr-admins"]}
    claims_for_token: dict[str, object] = {}
    pkce_for_token: dict[str, str] = {}

    def fake_provider(request: httpx.Request) -> httpx.Response:
        if str(request.url) == f"{OIDC_ISSUER}/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={
                    "issuer": OIDC_ISSUER,
                    "authorization_endpoint": "https://idp.example.test/authorize",
                    "token_endpoint": "https://idp.example.test/token",
                    "jwks_uri": "https://idp.example.test/keys",
                    "response_modes_supported": ["query", "form_post"],
                    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                },
            )
        if str(request.url) == "https://idp.example.test/keys":
            return httpx.Response(200, json=jwks)
        if str(request.url) == "https://idp.example.test/token":
            form = parse_qs(request.content.decode("ascii"))
            verifier = form["code_verifier"][0]
            pkce_for_token["challenge"] = _b64(hashlib.sha256(verifier.encode()).digest())
            raw_claims = dict(claims_for_token)
            now = int(iam.now().timestamp())
            overrides = {
                "nonce": state_for_token["nonce"],
                "now": now,
                "groups": groups_for_token["groups"],
            }
            overrides.update(raw_claims)
            return httpx.Response(
                200,
                json={
                    "access_token": "discarded-test-access-token",
                    "id_token": _sign_id_token(private_key, **cast(Any, overrides)),
                },
            )
        return httpx.Response(404)

    app = create_app(iam_service=iam, oidc_secret_broker=broker)
    app.state.oidc_http_client_factory = lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(fake_provider), follow_redirects=False, trust_env=False
    )
    admin_engine = create_admin_engine(migrated_database.admin_url)
    client = TestClient(app, follow_redirects=False)
    client.__enter__()

    async def seed_owner() -> tuple[str, str, str]:
        async with instance_rls_session(factory, mode="instance_admin") as db:
            now = iam.now()
            owner = UserModel(
                id=new_uuid7(now=now),
                username="oidc-unit-owner",
                email="owner@example.test",
                display_name="OIDC Unit Owner",
                password_hash=hash_password("unused-owner-test-password"),
                is_instance_owner=True,
                status="active",
                mfa_enabled=True,
                grant_epoch=1,
                disabled_at=None,
                version=1,
                created_at=now,
                updated_at=now,
            )
            db.add(owner)
            await db.flush()
            db.add(
                InstanceModel(
                    id=new_uuid7(now=now),
                    singleton_guard=True,
                    deployment_mode="local",
                    public_base_url=PUBLIC_URL,
                    config_revision=1,
                    recovery_epoch=1,
                    maintenance_enabled=False,
                    maintenance_reason=None,
                    maintenance_started_at=None,
                    maintenance_started_by_user_id=None,
                    initialized_at=now,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            _session, raw_session, raw_csrf = await iam._mint_db_session(
                db,
                user=owner,
                recovery_epoch=1,
                auth_strength="mfa",
                step_up_at=now,
                client_ip="127.0.0.1",
                user_agent="u28-test",
                now=now,
            )
            return raw_session, raw_csrf, owner.id

    try:
        raw_session, raw_csrf, owner_id = asyncio.run(seed_owner())
        client.cookies.set(session_cookie_name(secure=False), raw_session)
        client.cookies.set(CSRF_COOKIE_NAME, raw_csrf)
        owner_headers = {"Origin": PUBLIC_URL, "X-CSRF-Token": raw_csrf}
        configure = client.put(
            "/api/v1/system/oidc/providers/corp",
            headers=owner_headers,
            json={
                "issuer": OIDC_ISSUER,
                "client_id": OIDC_CLIENT_ID,
                "client_secret": "not-a-real-secret",
            },
        )
        assert configure.status_code == 200, configure.text
        assert "client_secret" not in configure.text
        assert configure.json()["status"] == "not_configured"
        probe = client.post("/api/v1/system/oidc/providers/corp/probe", headers=owner_headers)
        assert probe.status_code == 200, probe.text
        assert probe.json()["status"] == "enabled"
        assert client.get("/api/v1/system/capabilities").json()["oidc_providers"] == ["corp"]

        async def seed_workspace_mapping() -> None:
            async with instance_rls_session(factory, mode="instance_admin") as db:
                now = iam.now()
                workspace = WorkspaceModel(
                    id=new_uuid7(now=now),
                    name="OIDC Test Workspace",
                    slug="oidc-test-workspace",
                    owner_user_id=None,
                    status="active",
                    paused=False,
                    retention_policy={},
                    last_event_seq=0,
                    version=1,
                    created_at=now,
                    updated_at=now,
                    deleted_at=None,
                )
                db.add(workspace)
                await db.flush()
                db.add(
                    MembershipModel(
                        id=new_uuid7(now=now),
                        workspace_id=workspace.id,
                        user_id=owner_id,
                        role="admin",
                        invited_by_user_id=None,
                        version=1,
                        created_at=now,
                        updated_at=now,
                    )
                )
                db.add(
                    OidcGroupMappingModel(
                        id=new_uuid7(now=now),
                        workspace_id=workspace.id,
                        provider_id="corp",
                        group_name="red2pr-admins",
                        role="admin",
                        enabled=True,
                        created_at=now,
                    )
                )
                anchorless_workspace = WorkspaceModel(
                    id=new_uuid7(now=now),
                    name="OIDC Workspace Without Local Admin",
                    slug="oidc-workspace-without-local-admin",
                    owner_user_id=None,
                    status="active",
                    paused=False,
                    retention_policy={},
                    last_event_seq=0,
                    version=1,
                    created_at=now,
                    updated_at=now,
                    deleted_at=None,
                )
                db.add(anchorless_workspace)
                await db.flush()
                db.add(
                    OidcGroupMappingModel(
                        id=new_uuid7(now=now),
                        workspace_id=anchorless_workspace.id,
                        provider_id="corp",
                        group_name="unanchored-admins",
                        role="admin",
                        enabled=True,
                        created_at=now,
                    )
                )

        asyncio.run(seed_workspace_mapping())

        def begin_login(
            *, email_verified: bool = True, groups: list[str] | None = None, **overrides: object
        ) -> tuple[str, str, httpx.Response]:
            groups_for_token["groups"] = ["red2pr-admins"] if groups is None else groups
            claims_for_token.clear()
            claims_for_token["email_verified"] = email_verified
            claims_for_token.update(overrides)
            authorize = client.get("/api/v1/auth/oidc/corp/authorize")
            assert authorize.status_code == 302
            params = parse_qs(urlparse(authorize.headers["location"]).query)
            assert params["code_challenge_method"] == ["S256"]
            assert params["response_mode"] == ["form_post"]
            state_for_token["nonce"] = params["nonce"][0]
            cookie_name = (
                f"red2pr_oidc_{hashlib.sha256(params['state'][0].encode()).hexdigest()[:24]}"
            )
            cookie_path = "/api/v1/auth/oidc/corp/callback"
            binding_value = client.cookies.get(
                cookie_name, domain="testserver.local", path=cookie_path
            )
            assert binding_value is not None
            client.cookies.delete(cookie_name, domain="testserver.local", path=cookie_path)
            unbound_browser = client.post(
                "/api/v1/auth/oidc/corp/callback",
                data={"code": "single-use-code", "state": params["state"][0]},
                headers={"Origin": "https://idp.example.test"},
            )
            assert unbound_browser.status_code == 401
            client.cookies.set(
                cookie_name,
                binding_value,
                domain="testserver.local",
                path=cookie_path,
            )
            callback = client.post(
                "/api/v1/auth/oidc/corp/callback",
                data={"code": "single-use-code", "state": params["state"][0]},
                headers={"Origin": "https://idp.example.test"},
            )
            return params["state"][0], params["code_challenge"][0], callback

        # Existing local accounts are never linked by a matching email address.
        _, _, email_collision = begin_login(email="owner@example.test")
        assert email_collision.status_code == 409

        # OIDC cannot become the workspace's only admin authority.
        _, _, missing_anchor = begin_login(groups=["unanchored-admins"])
        assert missing_anchor.status_code == 409, missing_anchor.text

        # Unverified email, issuer and audience cannot authenticate or provision an account.
        _, _, unverified = begin_login(email_verified=False)
        assert unverified.status_code == 401
        _, _, bad_issuer = begin_login(issuer="https://attacker.example.test")
        assert bad_issuer.status_code == 401
        _, _, bad_audience = begin_login(audience=[OIDC_CLIENT_ID, "attacker-client"])
        assert bad_audience.status_code == 401
        _, _, bad_nonce = begin_login(nonce="attacker-nonce")
        assert bad_nonce.status_code == 401

        state, challenge, success = begin_login()
        assert success.status_code == 303, success.text
        assert pkce_for_token["challenge"] == challenge
        assert "access_token" not in success.text and "id_token" not in success.text
        assert success.headers["cache-control"] == "no-store"
        replay = client.post(
            "/api/v1/auth/oidc/corp/callback",
            data={"code": "single-use-code", "state": state},
        )
        assert replay.status_code == 401

        async def assert_identity_and_membership() -> tuple[str, str]:
            async with instance_rls_session(factory, mode="instance_admin") as db:
                identity = await db.scalar(
                    select(OidcIdentityModel).where(OidcIdentityModel.provider_id == "corp")
                )
                assert identity is not None
                membership = await db.scalar(
                    select(MembershipModel).where(MembershipModel.user_id == identity.user_id)
                )
                assert membership is not None and membership.role == "admin"
                grant = await db.scalar(
                    select(OidcMembershipGrantModel).where(
                        OidcMembershipGrantModel.user_id == identity.user_id
                    )
                )
                assert grant is not None and grant.granted_role == "admin"
                return identity.user_id, membership.workspace_id

        user_id, workspace_id = asyncio.run(assert_identity_and_membership())

        async def assert_local_admin_anchor_is_protected() -> None:
            with pytest.raises(DBAPIError, match="last_admin"):
                async with instance_rls_session(factory, mode="instance_admin") as db:
                    local_admin = await db.scalar(
                        select(MembershipModel).where(
                            MembershipModel.workspace_id == workspace_id,
                            MembershipModel.user_id == owner_id,
                        )
                    )
                    assert local_admin is not None
                    await db.delete(local_admin)
                    await db.flush()

            async with instance_rls_session(factory, mode="instance_admin") as db:
                assert (
                    await db.scalar(
                        select(MembershipModel).where(
                            MembershipModel.workspace_id == workspace_id,
                            MembershipModel.user_id == owner_id,
                        )
                    )
                    is not None
                )

        asyncio.run(assert_local_admin_anchor_is_protected())
        assert client.get("/api/v1/me").status_code == 200
        original_session = client.cookies.get(
            session_cookie_name(secure=False), domain="testserver.local", path="/"
        )
        assert original_session is not None

        async def add_locally_managed_membership() -> str:
            async with instance_rls_session(factory, mode="instance_admin") as db:
                now = iam.now()
                local_workspace = WorkspaceModel(
                    id=new_uuid7(now=now),
                    name="Locally Managed Workspace",
                    slug="locally-managed-workspace",
                    owner_user_id=None,
                    status="active",
                    paused=False,
                    retention_policy={},
                    last_event_seq=0,
                    version=1,
                    created_at=now,
                    updated_at=now,
                    deleted_at=None,
                )
                db.add(local_workspace)
                await db.flush()
                db.add(
                    MembershipModel(
                        id=new_uuid7(now=now),
                        workspace_id=local_workspace.id,
                        user_id=user_id,
                        role="viewer",
                        invited_by_user_id=None,
                        version=1,
                        created_at=now,
                        updated_at=now,
                    )
                )
                return local_workspace.id

        local_workspace_id = asyncio.run(add_locally_managed_membership())

        # A group removal synchronously removes the OIDC-managed grant and invalidates old sessions.
        _, _, deprovisioned = begin_login(groups=[])
        assert deprovisioned.status_code == 303, deprovisioned.text

        async def assert_deprovisioned() -> None:
            async with instance_rls_session(factory, mode="instance_admin") as db:
                assert (
                    await db.scalar(
                        select(MembershipModel).where(
                            MembershipModel.user_id == user_id,
                            MembershipModel.workspace_id == workspace_id,
                        )
                    )
                    is None
                )
                user = await db.scalar(select(UserModel).where(UserModel.id == user_id))
                assert user is not None and user.grant_epoch > 1
                assert (
                    await db.scalar(
                        select(OidcMembershipGrantModel).where(
                            OidcMembershipGrantModel.user_id == user_id
                        )
                    )
                    is None
                )
                assert (
                    await db.scalar(
                        select(MembershipModel).where(
                            MembershipModel.user_id == user_id,
                            MembershipModel.workspace_id == local_workspace_id,
                        )
                    )
                    is not None
                )

        asyncio.run(assert_deprovisioned())
        assert client.get("/api/v1/me").status_code == 200
        revoked_client = TestClient(app, follow_redirects=False)
        revoked_client.cookies.set(session_cookie_name(secure=False), original_session)
        assert revoked_client.get("/api/v1/me").status_code == 401
    finally:
        client.__exit__(None, None, None)
        asyncio.run(dispose_operation_lock_engine(factory))
        asyncio.run(engine.dispose())
        asyncio.run(admin_engine.dispose())
