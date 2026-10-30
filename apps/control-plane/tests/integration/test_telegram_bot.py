"""U22 Telegram polling, webhook, account-link and web-confirm integration tests."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import AsyncIterator, Iterator
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from sqlalchemy import select

from py_contracts.primitives import new_uuid7
from red2pr_control.db.base import (
    MembershipModel,
    RepositoryModel,
    TelegramLinkChallengeModel,
    TelegramLinkModel,
    TelegramUpdateModel,
    TelegramUpdateOffsetModel,
    UserModel,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.passwords import hash_password
from red2pr_control.notifications.telegram.adapter import TelegramApiResult
from red2pr_control.notifications.telegram.commands import TelegramBotSettings
from red2pr_control.notifications.telegram.poller import TelegramBotService

_SUPPORT_PATH = Path(__file__).with_name("test_agents_and_state_machine.py")
_SPEC = importlib.util.spec_from_file_location("red2pr_u22_test_support", _SUPPORT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_SUPPORT = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SUPPORT
_SPEC.loader.exec_module(_SUPPORT)
PUBLIC_BASE_URL = _SUPPORT.PUBLIC_BASE_URL
ManualClock = _SUPPORT.ManualClock
_build_harness = _SUPPORT._build_u17_harness
_bootstrap = _SUPPORT._bootstrap_workspace_and_repo
_csrf_headers = _SUPPORT._csrf_headers
_seed_ci_run = _SUPPORT._seed_ci_run_job_and_log_artifact
_create_repair = _SUPPORT._create_repair_session_with_budget


class _BotApi:
    def __init__(self, updates: list[dict[str, object]] | None = None) -> None:
        self.updates = updates or []
        self.webhook_url = ""
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def call(
        self, method: str, payload: dict[str, object], **_kwargs: object
    ) -> TelegramApiResult:
        self.calls.append((method, payload))
        if method == "getWebhookInfo":
            return TelegramApiResult(ok=True, result={"url": self.webhook_url})
        if method == "getUpdates":
            result, self.updates = self.updates, []
            return TelegramApiResult(ok=True, result=result)
        if method == "sendMessage":
            return TelegramApiResult(ok=True, result={"message_id": 7})
        return TelegramApiResult(ok=True, result=True)

    async def aclose(self) -> None:
        return None


def _settings(mode: str) -> TelegramBotSettings:
    return TelegramBotSettings(
        bot_id="primary",
        username="red2pr_test_bot",
        mode=mode,
        public_base_url="https://red2pr.example.invalid",
        token="12345:" + "A" * 32,
        webhook_secret="B" * 40,
    )


@pytest.fixture(scope="module")
def pg_urls() -> Iterator[object]:
    yield from _SUPPORT.pg_urls.__wrapped__()


@pytest.fixture
async def migrated_db(pg_urls: object) -> AsyncIterator[object]:
    async for result in _SUPPORT.migrated_db.__wrapped__(pg_urls):
        yield result


@pytest.mark.asyncio
async def test_u22_polling_offset_and_webhook_auth_deduplicate(
    migrated_db: object, tmp_path: Path
) -> None:
    clock = ManualClock()
    harness = _build_harness(migrated_db.app_url, clock=clock, store_dir=tmp_path / "u22-poll")
    poll_api = _BotApi(
        [
            {
                "update_id": 410,
                "message": {
                    "message_id": 1,
                    "from": {"id": 9, "is_bot": False},
                    "chat": {"id": 9, "type": "private"},
                    "text": "/help",
                },
            }
        ]
    )
    poller = TelegramBotService(
        settings=_settings("polling"),
        session_factory=harness.app_factory,
        api=poll_api,
        clock=clock,
    )
    harness.api_app.state.telegram_bot_service = poller
    client, _csrf, _owner_id, _workspace_id, _repo_id = await _bootstrap(
        harness, clock=clock, ws_slug="u22-poll"
    )
    try:
        poll_api.webhook_url = "https://red2pr.example.invalid/api/v1/hooks/telegram/old"
        assert await poller.reconcile_mode() is True
        delete_webhook = next(
            payload for method, payload in poll_api.calls if method == "deleteWebhook"
        )
        assert delete_webhook["drop_pending_updates"] is False
        assert await poller.poll_once() == 1
        assert (
            next(
                payload.get("offset")
                for method, payload in poll_api.calls
                if method == "getUpdates"
            )
            is None
        )
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            offset = await db.scalar(
                select(TelegramUpdateOffsetModel).where(
                    TelegramUpdateOffsetModel.bot_id == "primary"
                )
            )
            assert offset is not None and offset.mode == "polling" and offset.next_update_id == 411
        await poller.poll_once()
        assert [
            payload.get("offset") for method, payload in poll_api.calls if method == "getUpdates"
        ] == [None, 411]

        webhook_api = _BotApi()
        webhook = TelegramBotService(
            settings=_settings("webhook"),
            session_factory=harness.app_factory,
            api=webhook_api,
            clock=clock,
        )
        assert await webhook.reconcile_mode() is True
        set_webhook = next(
            payload for method, payload in webhook_api.calls if method == "setWebhook"
        )
        assert set_webhook["drop_pending_updates"] is False
        assert set_webhook["secret_token"] == "B" * 40
        harness.api_app.state.telegram_bot_service = webhook
        assert await poller.poll_once() == 0
        update = {
            "update_id": 411,
            "message": {
                "message_id": 2,
                "from": {"id": 9, "is_bot": False},
                "chat": {"id": 9, "type": "private"},
                "text": "/help",
            },
        }
        route = "/api/v1/hooks/telegram/primary"
        async with httpx.AsyncClient(
            transport=harness.transport, base_url=PUBLIC_BASE_URL
        ) as webhook_client:
            rejected = await webhook_client.post(
                route, headers={"X-Telegram-Bot-Api-Secret-Token": "C" * 40}, json=update
            )
            assert rejected.status_code == 401
            cookie_rejected = await webhook_client.post(
                route,
                headers={
                    "X-Telegram-Bot-Api-Secret-Token": "B" * 40,
                    "Cookie": "session=bad",
                },
                json=update,
            )
            assert cookie_rejected.status_code == 400
            malformed = await webhook_client.post(
                route,
                headers={"X-Telegram-Bot-Api-Secret-Token": "B" * 40},
                content=b"not-json",
            )
            assert malformed.status_code == 400
            boolean_id = await webhook_client.post(
                route,
                headers={"X-Telegram-Bot-Api-Secret-Token": "B" * 40},
                json={"update_id": True},
            )
            assert boolean_id.status_code == 400
            oversized = await webhook_client.post(
                route,
                headers={"X-Telegram-Bot-Api-Secret-Token": "B" * 40},
                content=b" " * (256 * 1024 + 1),
            )
            assert oversized.status_code == 413
            accepted = await webhook_client.post(
                route, headers={"X-Telegram-Bot-Api-Secret-Token": "B" * 40}, json=update
            )
            duplicate = await webhook_client.post(
                route, headers={"X-Telegram-Bot-Api-Secret-Token": "B" * 40}, json=update
            )
            assert accepted.status_code == 202 and accepted.json() == {"accepted": True}
            assert duplicate.status_code == 200 and duplicate.json() == {"accepted": False}
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            persisted = await db.scalar(
                select(TelegramUpdateModel).where(
                    TelegramUpdateModel.bot_id == "primary",
                    TelegramUpdateModel.update_id == 411,
                )
            )
            assert persisted is not None
            persisted.state = "processing"
            persisted.processing_started_at = clock() - timedelta(minutes=3)
        sends_before_recovery = len([c for c in webhook_api.calls if c[0] == "sendMessage"])
        assert await webhook.commands.process_pending() == 0
        assert len([c for c in webhook_api.calls if c[0] == "sendMessage"]) == sends_before_recovery
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            recovered = await db.scalar(
                select(TelegramUpdateModel).where(
                    TelegramUpdateModel.bot_id == "primary",
                    TelegramUpdateModel.update_id == 411,
                )
            )
            assert recovered is not None and recovered.state == "unknown"
    finally:
        await client.aclose()
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_u22_migration_0018_downgrade_and_upgrade_is_reversible(migrated_db: object) -> None:
    _SUPPORT.run_alembic_downgrade(
        migrated_db.admin_url,
        "0017_notifications_inbox_deliveries",
        app_role_name=_SUPPORT.APP_ROLE_NAME,
    )
    _SUPPORT.run_alembic_upgrade(
        migrated_db.admin_url,
        "head",
        app_role_name=_SUPPORT.APP_ROLE_NAME,
        app_role_password=_SUPPORT.APP_ROLE_PASSWORD,
    )


@pytest.mark.asyncio
async def test_u22_private_link_and_web_confirm_are_one_use_and_idempotent(
    migrated_db: object, tmp_path: Path
) -> None:
    clock = ManualClock()
    harness = _build_harness(migrated_db.app_url, clock=clock, store_dir=tmp_path / "u22-link")
    bot_api = _BotApi()
    service = TelegramBotService(
        settings=_settings("webhook"), session_factory=harness.app_factory, api=bot_api, clock=clock
    )
    harness.api_app.state.telegram_bot_service = service
    client, csrf, owner_id, workspace_id, repo_id = await _bootstrap(
        harness, clock=clock, ws_slug="u22-link"
    )
    try:
        created = await client.post(
            "/api/v1/me/telegram-link-challenges", headers=_csrf_headers(csrf)
        )
        assert created.status_code == 201
        assert created.headers["cache-control"] == "no-store"
        start_token = parse_qs(urlparse(created.json()["deep_link"]).query)["start"][0]
        now = clock()
        await service._activate_mode("webhook")
        rotated_settings = replace(_settings("webhook"), token="12345:" + "C" * 32)
        rotated_service = TelegramBotService(
            settings=rotated_settings,
            session_factory=harness.app_factory,
            api=bot_api,
            clock=clock,
        )
        await rotated_service._activate_mode("webhook")
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            old_challenge = await db.scalar(
                select(TelegramLinkChallengeModel).where(
                    TelegramLinkChallengeModel.scope == "account_link"
                )
            )
            assert old_challenge is not None and old_challenge.used_at == now
        assert await rotated_service.persist_webhook_update(
            {
                "update_id": 500,
                "message": {
                    "message_id": 2,
                    "from": {"id": 90210, "is_bot": False},
                    "chat": {"id": 90210, "type": "private"},
                    "text": f"/start {start_token}",
                },
            },
            correlation_id="u22-rotated-link",
        )
        await rotated_service.commands.process_pending()
        assert (await client.get("/api/v1/me")).json()["telegram_link"][
            "status"
        ] == "not_configured"
        created = await client.post(
            "/api/v1/me/telegram-link-challenges", headers=_csrf_headers(csrf)
        )
        start_token = parse_qs(urlparse(created.json()["deep_link"]).query)["start"][0]
        service = rotated_service
        harness.api_app.state.telegram_bot_service = service
        update = {
            "update_id": 501,
            "message": {
                "message_id": 3,
                "from": {"id": 90210, "is_bot": False},
                "chat": {"id": 90210, "type": "private"},
                "text": f"/start {start_token}",
            },
        }
        assert await service.persist_webhook_update(update, correlation_id="u22-link-1") is True
        assert await service.commands.process_pending() == 1
        me = (await client.get("/api/v1/me")).json()
        assert me["telegram_link"]["status"] == "linked"
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            persisted_start = await db.scalar(
                select(TelegramUpdateModel).where(TelegramUpdateModel.update_id == 501)
            )
            assert persisted_start is not None
            stored_start_hash = persisted_start.normalized_json["arguments"][0]
            assert stored_start_hash != start_token and len(stored_start_hash) == 64
        ci_run_id, _ci_job_id, _artifact_id, _fingerprint = await _seed_ci_run(
            harness,
            workspace_id=workspace_id,
            repository_id=repo_id,
            head_sha="a" * 40,
            job_name="pytest",
            ci_failure_log="FAILED tests/test_example.py::test_case - AssertionError",
            now=clock(),
        )
        repair_id, _budget_id = await _create_repair(
            harness,
            workspace_id=workspace_id,
            repository_id=repo_id,
            ci_run_id=ci_run_id,
            base_sha="a" * 40,
            semantic_key="u22-telegram-repair-read",
            now=clock(),
        )
        read_commands = [
            "/help",
            "/status",
            "/settings",
            "/repos",
            "/repairs",
            f"/repair {repair_id}",
            "/approvals",
        ]
        first_read_update_id = 508
        for index, command_text in enumerate(read_commands):
            assert await service.persist_webhook_update(
                {
                    "update_id": first_read_update_id + index,
                    "message": {
                        "message_id": 20 + index,
                        "from": {"id": 90210, "is_bot": False},
                        "chat": {"id": 90210, "type": "private"},
                        "text": command_text,
                    },
                },
                correlation_id="u22-read-command",
            )
        assert await service.commands.process_pending() == len(read_commands)
        read_replies = [
            str(payload.get("text")) for method, payload in bot_api.calls if method == "sendMessage"
        ][-len(read_commands) :]
        assert any("u22-link/calculator" in reply for reply in read_replies)
        repair_replies = [reply for reply in read_replies if "local=" in reply]
        assert repair_replies
        assert "remote=" in repair_replies[0]
        assert any(repair_id[:8] in reply for reply in repair_replies)
        assert any("No pending approvals" in reply for reply in read_replies)
        forbidden_updates = [
            {
                "update_id": 504,
                "message": {
                    "message_id": 6,
                    "from": {"id": 90210, "is_bot": False},
                    "chat": {"id": -100902100, "type": "supergroup"},
                    "text": "/pause " + repo_id,
                },
            },
            {
                "update_id": 505,
                "message": {
                    "message_id": 7,
                    "from": {"id": 90210, "is_bot": False},
                    "chat": {"id": 90210, "type": "private"},
                    "forward_origin": {"type": "user", "date": 1793354400},
                    "text": "/pause " + repo_id,
                },
            },
        ]
        sent_before_forbidden = len(bot_api.calls)
        for forbidden_update in forbidden_updates:
            assert await service.persist_webhook_update(
                forbidden_update, correlation_id="u22-no-action"
            )
        assert await service.commands.process_pending() == 0
        assert len(bot_api.calls) == sent_before_forbidden
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            assert (
                await db.scalar(
                    select(TelegramLinkChallengeModel.id).where(
                        TelegramLinkChallengeModel.scope == "action"
                    )
                )
                is None
            )

        pause_update = {
            "update_id": 506,
            "message": {
                "message_id": 8,
                "from": {"id": 90210, "is_bot": False},
                "chat": {"id": 90210, "type": "private"},
                "text": f"/pause {repo_id}",
            },
        }
        assert await service.persist_webhook_update(pause_update, correlation_id="u22-pause")
        await service.commands.process_pending()
        pause_text = str(
            next(
                payload["text"]
                for method, payload in reversed(bot_api.calls)
                if method == "sendMessage" and "Confirm /pause" in str(payload.get("text"))
            )
        )
        pause_token = pause_text.split("#", maxsplit=1)[1]
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            repo = await db.scalar(select(RepositoryModel).where(RepositoryModel.id == repo_id))
            assert repo is not None and repo.paused is False
        no_csrf = await client.post(
            "/api/v1/me/telegram-intents/confirm",
            headers={"Idempotency-Key": str(new_uuid7(now=clock()))},
            json={"token": pause_token, "confirmed": True},
        )
        assert no_csrf.status_code == 403
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            repo = await db.scalar(select(RepositoryModel).where(RepositoryModel.id == repo_id))
            assert repo is not None and repo.paused is False
        pause_confirmation = await client.post(
            "/api/v1/me/telegram-intents/confirm",
            headers=_csrf_headers(csrf, extra={"Idempotency-Key": str(new_uuid7(now=clock()))}),
            json={"token": pause_token, "confirmed": True},
        )
        assert pause_confirmation.status_code == 200
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            repo = await db.scalar(select(RepositoryModel).where(RepositoryModel.id == repo_id))
            assert repo is not None and repo.paused is True

        resume_update = {
            "update_id": 507,
            "message": {
                "message_id": 9,
                "from": {"id": 90210, "is_bot": False},
                "chat": {"id": 90210, "type": "private"},
                "text": f"/resume {repo_id}",
            },
        }
        assert await service.persist_webhook_update(resume_update, correlation_id="u22-resume")
        await service.commands.process_pending()
        resume_text = str(
            next(
                payload["text"]
                for method, payload in reversed(bot_api.calls)
                if method == "sendMessage" and "Confirm /resume" in str(payload.get("text"))
            )
        )
        resume_token = resume_text.split("#", maxsplit=1)[1]
        second_admin_id = new_uuid7(now=clock())
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            db.add(
                UserModel(
                    id=second_admin_id,
                    username=f"u22-admin-{second_admin_id[-8:]}",
                    email=None,
                    display_name="U22 spare administrator",
                    password_hash=hash_password("test-only-password-not-used"),
                    is_instance_owner=False,
                    status="active",
                    mfa_enabled=False,
                    grant_epoch=1,
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            db.add(
                MembershipModel(
                    id=new_uuid7(now=clock()),
                    workspace_id=workspace_id,
                    user_id=second_admin_id,
                    role="admin",
                    invited_by_user_id=owner_id,
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            membership = await db.scalar(
                select(MembershipModel).where(
                    MembershipModel.workspace_id == workspace_id,
                    MembershipModel.user_id == owner_id,
                )
            )
            assert membership is not None
            membership.role = "viewer"
        denied_resume = await client.post(
            "/api/v1/me/telegram-intents/confirm",
            headers=_csrf_headers(csrf, extra={"Idempotency-Key": str(new_uuid7(now=clock()))}),
            json={"token": resume_token, "confirmed": True},
        )
        assert denied_resume.status_code in {403, 404}
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            repo = await db.scalar(select(RepositoryModel).where(RepositoryModel.id == repo_id))
            membership = await db.scalar(
                select(MembershipModel).where(
                    MembershipModel.workspace_id == workspace_id,
                    MembershipModel.user_id == owner_id,
                )
            )
            assert repo is not None and repo.paused is True
            assert membership is not None
            membership.role = "admin"

        replayed_link = {
            **update,
            "update_id": 503,
            "message": {**update["message"], "message_id": 5},
        }
        assert await service.persist_webhook_update(replayed_link, correlation_id="u22-link-replay")
        await service.commands.process_pending()
        assert (await client.get("/api/v1/me")).json()["telegram_link"]["status"] == "linked"
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            link = await db.scalar(
                select(TelegramLinkModel).where(TelegramLinkModel.user_id == owner_id)
            )
            assert (
                link is not None
                and link.telegram_user_id == "90210"
                and link.private_chat_id == "90210"
            )
            challenge = await db.scalar(
                select(TelegramLinkChallengeModel).where(
                    TelegramLinkChallengeModel.scope == "account_link"
                )
            )
            assert challenge is not None and challenge.used_at == now

        action_update = {
            "update_id": 502,
            "message": {
                "message_id": 4,
                "from": {"id": 90210, "is_bot": False},
                "chat": {"id": 90210, "type": "private"},
                "text": "/unlink",
            },
        }
        assert (
            await service.persist_webhook_update(action_update, correlation_id="u22-link-2") is True
        )
        await service.commands.process_pending()
        action_text = str(
            next(
                payload["text"]
                for method, payload in bot_api.calls
                if method == "sendMessage" and "Confirm /unlink" in str(payload.get("text"))
            )
        )
        assert "/telegram/confirm/" not in action_text
        intent_token = action_text.split("#", maxsplit=1)[1]
        preview = await client.post(
            "/api/v1/me/telegram-intents/preview", json={"token": intent_token}
        )
        assert preview.status_code == 200 and preview.json()["action"] == "unlink"
        legacy_get = await client.get(
            "/api/v1/me/telegram-intents/confirm", params={"token": intent_token}
        )
        assert legacy_get.status_code == 405
        assert (await client.get("/api/v1/me")).json()["telegram_link"]["status"] == "linked"
        headers = _csrf_headers(csrf, extra={"Idempotency-Key": str(new_uuid7(now=clock()))})
        confirmed = await client.post(
            "/api/v1/me/telegram-intents/confirm",
            headers=headers,
            json={"token": intent_token, "confirmed": True},
        )
        assert confirmed.status_code == 200
        replay = await client.post(
            "/api/v1/me/telegram-intents/confirm",
            headers=headers,
            json={"token": intent_token, "confirmed": True},
        )
        assert replay.status_code == 200 and replay.json() == confirmed.json()
        assert (await client.get("/api/v1/me")).json()["telegram_link"][
            "status"
        ] == "not_configured"
        wrong_replay_key = await client.post(
            "/api/v1/me/telegram-intents/confirm",
            headers=_csrf_headers(csrf, extra={"Idempotency-Key": str(new_uuid7(now=clock()))}),
            json={"token": intent_token, "confirmed": True},
        )
        assert wrong_replay_key.status_code == 409
    finally:
        await client.aclose()
        await harness.app_engine.dispose()
