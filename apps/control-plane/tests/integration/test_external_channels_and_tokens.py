"""U23 API token, webhook key lifecycle, and external channel integration coverage."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import AsyncIterator, Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select

from py_contracts.primitives import new_uuid7
from red2pr_control.db.base import (
    ApiTokenModel,
    ConsentModel,
    NotificationDestinationModel,
    SecretEntryModel,
    WebhookSigningKeyModel,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.api_tokens import hash_api_token
from red2pr_control.secrets.broker import NOTIFICATIONS_SECRET_CAPABILITY

_SUPPORT_PATH = Path(__file__).with_name("test_agents_and_state_machine.py")
_SPEC = importlib.util.spec_from_file_location("red2pr_u23_test_support", _SUPPORT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_SUPPORT = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SUPPORT
_SPEC.loader.exec_module(_SUPPORT)
ManualClock = _SUPPORT.ManualClock
_build_harness = _SUPPORT._build_u17_harness
_bootstrap = _SUPPORT._bootstrap_workspace_and_repo
_csrf_headers = _SUPPORT._csrf_headers


@pytest.fixture(scope="module")
def pg_urls() -> Iterator[object]:
    yield from _SUPPORT.pg_urls.__wrapped__()


@pytest.fixture
async def migrated_db(pg_urls: object) -> AsyncIterator[object]:
    async for result in _SUPPORT.migrated_db.__wrapped__(pg_urls):
        yield result


@pytest.mark.asyncio
async def test_u23_migration_0019_downgrade_and_upgrade_is_reversible(migrated_db: object) -> None:
    _SUPPORT.run_alembic_downgrade(
        migrated_db.admin_url,
        "0018_telegram_links_and_challenges",
        app_role_name=_SUPPORT.APP_ROLE_NAME,
    )
    _SUPPORT.run_alembic_upgrade(
        migrated_db.admin_url,
        "head",
        app_role_name=_SUPPORT.APP_ROLE_NAME,
        app_role_password=_SUPPORT.APP_ROLE_PASSWORD,
    )


@pytest.mark.asyncio
async def test_api_token_is_scoped_revocable_and_never_a_session_or_approval_credential(
    migrated_db: object, tmp_path: Path
) -> None:
    clock = ManualClock()
    harness = _build_harness(migrated_db.app_url, clock=clock, store_dir=tmp_path / "artifacts")
    client, csrf, _owner_id, workspace_id, _repo_id = await _bootstrap(
        harness, clock=clock, ws_slug="u23-token-scope"
    )
    try:
        issued = await client.post(
            "/api/v1/workspaces/u23-token-scope/api-tokens",
            headers=_csrf_headers(csrf),
            json={
                "name": "read only automation",
                "scopes": ["notifications:read"],
                "repository_ids": [],
                "expires_at": (clock() + timedelta(days=1)).isoformat(),
            },
        )
        assert issued.status_code == 201, issued.text
        token_response = issued.json()
        raw_token = token_response["token"]
        assert raw_token.startswith("r2p_")
        assert "secret_hash" not in str(token_response)
        token_id = token_response["metadata"]["id"]
        async with instance_rls_session(harness.app_factory, mode="instance_only") as db:
            persisted = await db.scalar(select(ApiTokenModel).where(ApiTokenModel.id == token_id))
            assert persisted is not None
            assert persisted.secret_hash == hash_api_token(raw_token)
            assert persisted.revoked_at is None
            assert persisted.expires_at > clock()

        headers = {"Authorization": f"Bearer {raw_token}"}
        inbox = await client.get(
            "/api/v1/workspaces/u23-token-scope/notifications", headers=headers
        )
        assert inbox.status_code == 200, inbox.text
        session_route = await client.get("/api/v1/me", headers=headers)
        assert session_route.status_code == 403
        out_of_scope = await client.get(
            "/api/v1/workspaces/u23-token-scope/approvals", headers=headers
        )
        assert out_of_scope.status_code == 403

        revoked = await client.delete(
            f"/api/v1/workspaces/u23-token-scope/api-tokens/{token_id}",
            headers=_csrf_headers(csrf),
        )
        assert revoked.status_code == 204
        after_revoke = await client.get(
            "/api/v1/workspaces/u23-token-scope/notifications", headers=headers
        )
        assert after_revoke.status_code == 401

        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            assert (
                await db.scalar(
                    select(func.count())
                    .select_from(ApiTokenModel)
                    .where(ApiTokenModel.id == token_id)
                )
                == 1
            )
    finally:
        await client.aclose()
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_webhook_key_rotation_is_encrypted_one_time_and_overlaps_for_48_hours(
    migrated_db: object, tmp_path: Path
) -> None:
    clock = ManualClock()
    harness = _build_harness(migrated_db.app_url, clock=clock, store_dir=tmp_path / "artifacts")
    client, csrf, owner_id, workspace_id, _repo_id = await _bootstrap(
        harness, clock=clock, ws_slug="u23-webhook-keys"
    )
    harness.api_app.state.notification_secret_broker = harness.secret_broker
    destination_id = new_uuid7(now=clock())
    consent_id = new_uuid7(now=clock())
    try:
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            db.add(
                ConsentModel(
                    id=consent_id,
                    purpose="notification",
                    scope="workspace",
                    workspace_id=workspace_id,
                    repository_id=None,
                    destination="https://hooks.example.invalid/u23",
                    data_classes_json=["workspace_internal"],
                    granted_by_user_id=owner_id,
                    granted_at=clock(),
                    revoked_by_user_id=None,
                    revoked_at=None,
                    revoke_reason=None,
                    policy_version=1,
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
            db.add(
                NotificationDestinationModel(
                    id=destination_id,
                    workspace_id=workspace_id,
                    user_id=None,
                    channel="webhook",
                    scope="workspace",
                    address="https://hooks.example.invalid/u23",
                    secret_ref=None,
                    consent_id=consent_id,
                    status="not_configured",
                    verified_at=None,
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )

        url = (
            "/api/v1/workspaces/u23-webhook-keys/notification-destinations/"
            f"{destination_id}/webhook-key/rotate"
        )
        first = await client.post(url, headers=_csrf_headers(csrf))
        assert first.status_code == 201, first.text
        first_value = first.json()
        assert first_value["secret"]
        assert first_value["overlap_hours"] == 48
        second = await client.post(url, headers=_csrf_headers(csrf))
        assert second.status_code == 201, second.text
        second_value = second.json()
        assert second_value["key_id"] != first_value["key_id"]
        assert second_value["secret"] != first_value["secret"]
        destinations = await client.get(
            "/api/v1/workspaces/u23-webhook-keys/notification-destinations"
        )
        assert destinations.status_code == 200, destinations.text
        assert second_value["secret"] not in destinations.text

        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            keys = list(
                await db.scalars(
                    select(WebhookSigningKeyModel)
                    .where(
                        WebhookSigningKeyModel.workspace_id == workspace_id,
                        WebhookSigningKeyModel.destination_id == destination_id,
                    )
                    .order_by(WebhookSigningKeyModel.created_at)
                )
            )
            assert sorted(key.status for key in keys) == ["active", "overlap"]
            previous = next(key for key in keys if key.status == "overlap")
            current = next(key for key in keys if key.status == "active")
            assert previous.expires_at == clock() + timedelta(hours=48)
            assert previous.secret_ref != current.secret_ref
            resolved = await harness.secret_broker.resolve_secret_bytes(
                db,
                secret_ref=current.secret_ref,
                capability=NOTIFICATIONS_SECRET_CAPABILITY,
                workspace_id=workspace_id,
            )
            assert resolved.decode() == second_value["secret"]
    finally:
        await client.aclose()
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_channel_credential_replacement_is_write_only_and_encrypted(
    migrated_db: object, tmp_path: Path
) -> None:
    clock = ManualClock()
    harness = _build_harness(migrated_db.app_url, clock=clock, store_dir=tmp_path / "artifacts")
    client, csrf, _owner_id, workspace_id, _repo_id = await _bootstrap(
        harness, clock=clock, ws_slug="u23-channel-credentials"
    )
    harness.api_app.state.notification_secret_broker = harness.secret_broker
    destination_id = new_uuid7(now=clock())
    credential = "U23-test-secret-value"
    try:
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            db.add(
                NotificationDestinationModel(
                    id=destination_id,
                    workspace_id=workspace_id,
                    user_id=None,
                    channel="slack",
                    scope="workspace",
                    address="red2pr-alerts",
                    secret_ref=None,
                    consent_id=None,
                    status="ready",
                    verified_at=clock(),
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )

        response = await client.put(
            f"/api/v1/workspaces/u23-channel-credentials/notification-destinations/"
            f"{destination_id}/credentials",
            headers=_csrf_headers(csrf),
            json={"secret_value": credential},
        )
        assert response.status_code == 204
        assert credential not in response.text

        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            destination = await db.get(NotificationDestinationModel, destination_id)
            assert destination is not None and destination.secret_ref is not None
            assert destination.status == "not_configured"
            assert destination.verified_at is None
            secret = await db.scalar(
                select(SecretEntryModel).where(
                    SecretEntryModel.workspace_id == workspace_id,
                    SecretEntryModel.secret_ref == destination.secret_ref,
                )
            )
            assert secret is not None
            assert credential not in str(secret.envelope_json)
            resolved = await harness.secret_broker.resolve_secret_bytes(
                db,
                secret_ref=destination.secret_ref,
                capability=NOTIFICATIONS_SECRET_CAPABILITY,
                workspace_id=workspace_id,
            )
            assert resolved.decode() == credential
    finally:
        await client.aclose()
        await harness.app_engine.dispose()
