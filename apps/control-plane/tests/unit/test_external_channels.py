"""U23 channel, signing, and API token negative-case tests."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import time

import httpx
import pytest

from red2pr_control.iam.api_tokens import hash_api_token, token_scope_is_allowed
from red2pr_control.notifications.channels import smtp_adapter
from red2pr_control.notifications.channels.discord_adapter import (
    DiscordNotificationAdapter,
    build_discord_payload,
)
from red2pr_control.notifications.channels.slack_adapter import (
    SlackNotificationAdapter,
    neutralize_slack_mentions,
)
from red2pr_control.notifications.channels.smtp_adapter import (
    SmtpNotificationAdapter,
    build_email_message,
)
from red2pr_control.notifications.channels.webhook_signer import (
    SignedWebhookNotificationAdapter,
    sign_webhook_delivery,
    verify_webhook_delivery,
)
from red2pr_control.notifications.dispatcher import NotificationSendRequest


def test_api_token_hash_is_one_way_and_rights_are_scoped() -> None:
    secret = "r2p_" + "a" * 43
    assert hash_api_token(secret) == hashlib.sha256(secret.encode()).hexdigest()
    assert hash_api_token(secret) != secret
    assert token_scope_is_allowed(
        requested_scopes={"notifications:read"},
        issuer_scopes={"notifications:read", "repairs:read"},
    )
    assert not token_scope_is_allowed(
        requested_scopes={"notifications:admin"},
        issuer_scopes={"notifications:read"},
    )


def test_slack_and_discord_do_not_allow_untrusted_mentions() -> None:
    source = "@everyone @channel <!here> <!channel> <@12345> <https://example.test|link>"
    neutralized = neutralize_slack_mentions(source)
    assert "@\u200beveryone" in neutralized
    assert "@\u200bchannel" in neutralized
    assert "<!\u200bhere>" in neutralized
    assert "<!\u200bchannel>" in neutralized
    discord = build_discord_payload("Title", source, None)
    assert discord["allowed_mentions"] == {"parse": []}
    # Discord preserves visible text, while allowed_mentions prevents parsing it as a ping.
    assert "@everyone" in discord["content"]


def test_email_rejects_header_injection_and_escapes_html() -> None:
    with pytest.raises(ValueError, match="header"):
        build_email_message(
            sender="alerts@example.test\r\nBcc: attacker@example.test",
            recipient="owner@example.test",
            title="Alert",
            body="safe",
            correlation_id="corr-1",
            deep_link=None,
        )

    message = build_email_message(
        sender="alerts@example.test",
        recipient="owner@example.test",
        title="<script>alert(1)</script>",
        body="<img src=x onerror=alert(1)>",
        correlation_id="corr-1",
        deep_link="https://app.example.test/repairs/1",
    )
    html_part = next(part for part in message.walk() if part.get_content_type() == "text/html")
    html = html_part.get_content()
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "<img src=x onerror=alert(1)>" not in html


def test_smtp_timeout_after_submission_begins_is_ambiguous(monkeypatch: pytest.MonkeyPatch) -> None:
    class SmtpStub:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def ehlo(self) -> None:
            return None

        def has_extn(self, _name: str) -> bool:
            return True

        def starttls(self, *, context: object) -> None:
            return None

        def send_message(self, *_args: object, **_kwargs: object) -> object:
            raise TimeoutError("local SMTP sink timed out after DATA")

        def close(self) -> None:
            return None

    monkeypatch.setattr(smtp_adapter, "_PinnedSMTP", SmtpStub)
    adapter = SmtpNotificationAdapter(resolve_secret=_unused_secret, egress_policy=object())
    outcome = adapter._send_sync(
        host="smtp.example.test",
        port=587,
        pinned_ip="192.0.2.10",
        tls_mode="starttls",
        username=None,
        password=None,
        sender="alerts@example.test",
        recipient="owner@example.test",
        message=build_email_message(
            sender="alerts@example.test",
            recipient="owner@example.test",
            title="Test",
            body="Body",
            correlation_id="corr-u23",
            deep_link=None,
        ),
    )
    assert outcome == (503, "smtp_transport_unknown", True)

    class SmtpConnectTimeout(SmtpStub):
        def ehlo(self) -> None:
            raise TimeoutError("local SMTP sink timed out before submission")

    monkeypatch.setattr(smtp_adapter, "_PinnedSMTP", SmtpConnectTimeout)
    before_submission = adapter._send_sync(
        host="smtp.example.test",
        port=587,
        pinned_ip="192.0.2.10",
        tls_mode="starttls",
        username=None,
        password=None,
        sender="alerts@example.test",
        recipient="owner@example.test",
        message=build_email_message(
            sender="alerts@example.test",
            recipient="owner@example.test",
            title="Test",
            body="Body",
            correlation_id="corr-u23",
            deep_link=None,
        ),
    )
    assert before_submission == (503, "smtp_transport_unknown", False)


async def _unused_secret(_request: NotificationSendRequest) -> bytes:
    raise AssertionError("The synchronous SMTP protocol test does not resolve secrets.")


def test_signed_webhook_uses_exact_bytes_and_replay_window() -> None:
    body = b'{"event_id":"e1","payload":{"text":"caf\xc3\xa9"}}'
    secret = b"test-signing-secret" * 2
    now = int(time.time())
    headers = sign_webhook_delivery(
        secret=secret,
        event_id="e1",
        delivery_id="d1",
        key_id="key-1",
        timestamp=now,
        body=body,
    )
    signed = f"{now}.d1.".encode() + body
    expected = base64.b64encode(hmac.new(secret, signed, hashlib.sha256).digest()).decode()
    assert headers["Red2PR-Signature"] == f"v1,{expected}"
    assert verify_webhook_delivery(
        secret=secret,
        headers=headers,
        body=body,
        now=now,
        consumed_delivery_ids=set(),
    )
    assert not verify_webhook_delivery(
        secret=secret,
        headers=headers,
        body=body + b" ",
        now=now,
        consumed_delivery_ids=set(),
    )
    assert not verify_webhook_delivery(
        secret=secret,
        headers=headers,
        body=body,
        now=now + 301,
        consumed_delivery_ids=set(),
    )
    assert not verify_webhook_delivery(
        secret=secret,
        headers=headers,
        body=body,
        now=now,
        consumed_delivery_ids={"d1"},
    )


def _send_request(
    *,
    channel: str,
    address: str,
    is_test: bool = False,
    webhook_key_id: str | None = None,
) -> NotificationSendRequest:
    return NotificationSendRequest(
        workspace_id="019a4b4c-7d00-7000-8000-000000000002",
        delivery_id="019a4b4c-7d00-7000-8000-000000000003",
        event_id="019a4b4c-7d00-7000-8000-000000000001",
        correlation_id="corr-u23",
        channel=channel,
        address=address,
        secret_ref="secret-ref",
        title="Build failed",
        body="The build failed for @everyone",
        severity="error",
        deep_link=None,
        request_digest="d" * 64,
        is_test=is_test,
        event_payload={"payload": {"reason": "redacted"}},
        event_type="provider.run.failed",
        repository_id="019a4b4c-7d00-7000-8000-000000000004",
        webhook_key_id=webhook_key_id,
    )


class _StubHttpClient:
    def __init__(
        self,
        status: int,
        *,
        headers: dict[str, str] | None = None,
        payload: object = None,
    ) -> None:
        self.status = status
        self.headers = headers or {}
        self.payload = payload
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    async def request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        self.calls.append((method, str(url), kwargs))
        return httpx.Response(
            self.status,
            headers=self.headers,
            json=self.payload,
            request=httpx.Request(method, str(url)),
        )


@pytest.mark.asyncio
async def test_slack_429_preserves_bounded_retry_after_and_neutralizes_mentions() -> None:
    client = _StubHttpClient(429, headers={"Retry-After": "17"})
    adapter = SlackNotificationAdapter(
        http_client=client,
        resolve_secret=lambda _request: _async_bytes(
            b"https://hooks.slack.com/services/ABCDEF/GHIJKL/12345678901234567890"
        ),
    )
    result = await asyncio.wait_for(
        adapter.deliver(_send_request(channel="slack", address="ignored")), timeout=2
    )
    assert result.http_status == 429
    assert result.retry_after_seconds == 17
    text = str(client.calls[0][2]["json"]["text"])
    assert "@\u200beveryone" in text
    assert "@everyone" not in text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tls_mode", "port", "transport_name"),
    [("starttls", 587, "_PinnedSMTP"), ("ssl", 465, "_PinnedSMTPSSL")],
)
async def test_smtp_adapter_uses_pinned_tls_submission_transport(
    monkeypatch: pytest.MonkeyPatch, tls_mode: str, port: int, transport_name: str
) -> None:
    calls: list[tuple[str, object]] = []

    class EgressStub:
        async def evaluate_and_resolve(self, *, adapter: str, url: httpx.URL) -> object:
            assert adapter == "smtp"
            assert url.host == "mail.example.test"
            assert url.port == port
            calls.append(("egress", url.host))
            return type("Endpoint", (), {"pinned_ips": [ipaddress.ip_address("192.0.2.10")]})()

    class SmtpStub:
        def __init__(self, host: str, actual_port: int, **kwargs: object) -> None:
            calls.append(("connect", (host, actual_port, kwargs.get("pinned_ip"))))

        def ehlo(self) -> None:
            calls.append(("ehlo", None))

        def has_extn(self, name: str) -> bool:
            assert name == "starttls"
            return True

        def starttls(self, *, context: object) -> None:
            calls.append(("starttls", context))

        def login(self, username: str, password: str) -> None:
            calls.append(("login", (username, password)))

        def send_message(self, _message: object, *, from_addr: str, to_addrs: list[str]) -> dict:
            calls.append(("send", (from_addr, to_addrs)))
            return {}

        def close(self) -> None:
            calls.append(("close", None))

    monkeypatch.setattr(smtp_adapter, transport_name, SmtpStub)

    async def resolve(_request: NotificationSendRequest) -> bytes:
        return json.dumps(
            {
                "host": "mail.example.test",
                "port": port,
                "sender": "alerts@example.test",
                "username": "smtp-user",
                "password": "smtp-pass",
                "tls_mode": tls_mode,
            }
        ).encode()

    adapter = SmtpNotificationAdapter(
        resolve_secret=resolve,
        egress_policy=EgressStub(),
    )
    result = await adapter.deliver(_send_request(channel="email", address="owner@example.test"))
    assert result.http_status == 250
    assert result.error_code is None
    assert ("connect", ("mail.example.test", port, "192.0.2.10")) in calls
    assert ("login", ("smtp-user", "smtp-pass")) in calls
    assert any(name == "send" for name, _ in calls)
    if tls_mode == "starttls":
        assert next(index for index, (name, _) in enumerate(calls) if name == "starttls") < next(
            index for index, (name, _) in enumerate(calls) if name == "send"
        )


@pytest.mark.asyncio
async def test_discord_requires_receipt_and_sends_mentions_disabled() -> None:
    client = _StubHttpClient(200, payload={"id": "discord-message-42"})
    url = b"https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz"
    adapter = DiscordNotificationAdapter(
        http_client=client, resolve_secret=lambda _request: _async_bytes(url)
    )
    result = await adapter.deliver(_send_request(channel="discord", address="ignored"))
    assert result.provider_id == "discord-message-42"
    assert client.calls[0][1].endswith("?wait=true")
    payload = client.calls[0][2]["json"]
    assert payload["allowed_mentions"] == {"parse": []}


@pytest.mark.asyncio
async def test_signed_webhook_refuses_to_send_without_active_key_identity() -> None:
    client = _StubHttpClient(204)
    adapter = SignedWebhookNotificationAdapter(
        http_client=client,
        resolve_secret=lambda _request: _async_bytes(b"s" * 32),
        clock=lambda: 1_900_000_000,
    )
    result = await adapter.deliver(
        _send_request(channel="webhook", address="https://hooks.example.invalid/notify")
    )
    assert result.http_status == 400
    assert result.error_code == "webhook_signing_key_unconfigured"
    assert client.calls == []


@pytest.mark.asyncio
async def test_signed_webhook_test_requires_echo_and_rejects_redirect() -> None:
    secret = b"s" * 32
    client = _StubHttpClient(204)
    adapter = SignedWebhookNotificationAdapter(
        http_client=client,
        resolve_secret=lambda _request: _async_bytes(secret),
        clock=lambda: 1_900_000_000,
    )
    result = await adapter.send_test(
        _send_request(
            channel="webhook",
            address="https://hooks.example.invalid/notify",
            is_test=True,
            webhook_key_id="whk_test",
        )
    )
    assert result.http_status == 409
    assert result.error_code == "proof_of_control_failed"

    client.status = 302
    redirect = await adapter.deliver(
        _send_request(
            channel="webhook",
            address="https://hooks.example.invalid/notify",
            webhook_key_id="whk_test",
        )
    )
    assert redirect.http_status == 400
    assert redirect.error_code == "webhook_redirect_rejected"

    invalid = await adapter.deliver(
        _send_request(
            channel="webhook",
            address="http://127.0.0.1/notify",
            webhook_key_id="whk_test",
        )
    )
    assert invalid.error_code == "invalid_destination"


async def _async_bytes(value: bytes) -> bytes:
    return value
