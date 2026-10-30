from __future__ import annotations

import json
from pathlib import Path

import anyio
import httpx
import pytest

from red2pr_control.notifications.telegram.adapter import (
    TelegramApiClient,
    TelegramUpdate,
    normalize_update,
    validate_webhook_secret,
)
from red2pr_control.notifications.telegram.commands import normalize_for_storage

_REPO_ROOT = Path(__file__).resolve().parents[4]


def test_normalizes_only_supported_private_message_fields() -> None:
    update = normalize_update(
        {
            "update_id": 42,
            "message": {
                "message_id": 9,
                "date": 1_800_000_000,
                "chat": {"id": 1234, "type": "private"},
                "from": {"id": 1234, "is_bot": False},
                "text": "/status@red2pr_bot",
            },
        },
        bot_username="red2pr_bot",
    )

    assert update == TelegramUpdate(
        update_id=42,
        chat_id="1234",
        telegram_user_id="1234",
        chat_type="private",
        command="status",
        arguments=(),
        forwarded=False,
    )


@pytest.mark.parametrize(
    "body",
    [
        {"update_id": 1, "message": {"chat": {"id": 1, "type": "group"}, "text": "/repos"}},
        {"update_id": 1, "message": {"chat": {"id": 1, "type": "private"}, "text": "/repos"}},
        {
            "update_id": 1,
            "message": {
                "chat": {"id": 1, "type": "private"},
                "from": {"id": 1, "is_bot": True},
                "text": "/repos",
            },
        },
    ],
)
def test_rejects_non_private_or_unattributed_updates(body: dict[str, object]) -> None:
    assert normalize_update(body, bot_username="red2pr_bot") is None


def test_rejects_boolean_identifiers_instead_of_treating_them_as_integers() -> None:
    body = {
        "update_id": True,
        "message": {
            "chat": {"id": 1, "type": "private"},
            "from": {"id": 1, "is_bot": False},
            "text": "/status",
        },
    }
    assert normalize_update(body, bot_username="red2pr_bot") is None


def test_webhook_secret_comparison_is_exact_and_rejects_bad_values() -> None:
    configured = "A" + ("b" * 31)
    assert validate_webhook_secret(configured, configured)
    assert not validate_webhook_secret(configured, configured[:-1] + "c")
    assert not validate_webhook_secret("short", "short")
    assert not validate_webhook_secret("bad chars" * 3, "bad chars" * 3)


def test_provider_contract_fixtures_reject_forwarded_and_group_commands() -> None:
    fixtures = _REPO_ROOT / "contracts" / "fixtures" / "telegram"
    forwarded = json.loads((fixtures / "forwarded_command.json").read_text(encoding="utf-8"))
    group = json.loads((fixtures / "group_command.json").read_text(encoding="utf-8"))
    private = json.loads((fixtures / "private_command.json").read_text(encoding="utf-8"))

    forwarded_data = normalize_for_storage(forwarded, bot_username="red2pr_test_bot").data
    group_data = normalize_for_storage(group, bot_username="red2pr_test_bot").data
    private_data = normalize_for_storage(private, bot_username="red2pr_test_bot").data
    assert forwarded_data["forwarded"] is True
    assert group_data == {"ignored": True}
    assert private_data["command"] == "repair"
    assert "message" not in private_data


def test_bot_api_bounds_redirects_and_maps_retry_after_without_leaking_token() -> None:
    observed: list[httpx.Request] = []

    async def run() -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            observed.append(request)
            return httpx.Response(
                429,
                json={
                    "ok": False,
                    "error_code": 429,
                    "description": "Too Many Requests",
                    "parameters": {"retry_after": 17},
                },
            )

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, follow_redirects=False)
        api = TelegramApiClient(
            token="12345:" + "A" * 32,
            client=client,
            api_base_url="http://127.0.0.1:8099",
        )
        try:
            result = await api.call("sendMessage", {"chat_id": "1234", "text": "hello"})
            assert not result.ok and result.error_code == 429
            assert result.retry_after_seconds == 17
            assert len(observed) == 1
            assert "/sendMessage" in str(observed[0].url)
        finally:
            await client.aclose()

    anyio.run(run)


def test_bot_api_rejects_non_telegram_non_loopback_origins() -> None:
    with pytest.raises(ValueError, match=r"api.telegram.org or an HTTP loopback"):
        TelegramApiClient(
            token="12345:" + "A" * 32,
            api_base_url="https://attacker.example",
        )
