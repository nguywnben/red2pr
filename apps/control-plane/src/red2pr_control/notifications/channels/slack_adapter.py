"""Outbound Slack incoming-webhook adapter (no bot token or interactive actions)."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

import httpx

from red2pr_control.notifications.channels.common import (
    OutboundHttpClient,
    owns_client,
    safe_http_result,
)
from red2pr_control.notifications.dispatcher import (
    NotificationAdapterResult,
    NotificationSendRequest,
)

_ALLOWED_HOSTS = frozenset({"hooks.slack.com", "hooks.slack-gov.com"})
_SLACK_SECRET_PATH = re.compile(r"^/services/[A-Z0-9]{6,}/[A-Z0-9]{6,}/[A-Za-z0-9]{20,}$")
_MENTION_RE = re.compile(
    r"@(everyone|channel)|<!(here|channel|everyone)>|<@[A-Z0-9]+>", re.IGNORECASE
)


def neutralize_slack_mentions(value: str) -> str:
    """Break Slack broadcast/user mention syntax in untrusted notification content."""

    def replace(match: re.Match[str]) -> str:
        return match.group(0).replace("@", "@\u200b", 1).replace("<!", "<!\u200b", 1)

    return _MENTION_RE.sub(replace, value)


def validate_slack_webhook_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme == "https"
            and parsed.hostname in _ALLOWED_HOSTS
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and parsed.query == ""
            and parsed.fragment == ""
            and _SLACK_SECRET_PATH.fullmatch(parsed.path) is not None
        )
    except ValueError:
        return False


class SlackNotificationAdapter:
    def __init__(
        self,
        *,
        http_client: OutboundHttpClient,
        resolve_secret: Callable[[NotificationSendRequest], Awaitable[bytes]],
    ) -> None:
        self._client = http_client
        self._resolve_secret = resolve_secret

    async def deliver(self, request: NotificationSendRequest) -> NotificationAdapterResult:
        return await self._send(request, test=False)

    async def send_test(self, request: NotificationSendRequest) -> NotificationAdapterResult:
        return await self._send(request, test=True)

    async def _send(
        self, request: NotificationSendRequest, *, test: bool
    ) -> NotificationAdapterResult:
        try:
            url = (await self._resolve_secret(request)).decode("utf-8", errors="strict")
            if not validate_slack_webhook_url(url):
                return NotificationAdapterResult(http_status=400, error_code="invalid_destination")
            body = "\n".join(
                neutralize_slack_mentions(item)
                for item in (request.title, request.body, request.deep_link or "")
                if item
            )[:3500]
            response = await self._client.request(
                "POST", url, json={"text": body}, headers={"Content-Type": "application/json"}
            )
            return safe_http_result(response, provider="slack")
        except asyncio.CancelledError:
            raise
        except (TimeoutError, httpx.TimeoutException):
            return NotificationAdapterResult(
                timed_out_after_send=True, error_code="timeout_after_send"
            )
        except (UnicodeDecodeError, ValueError):
            return NotificationAdapterResult(http_status=400, error_code="invalid_secret")
        except httpx.TransportError:
            return NotificationAdapterResult(error_code="transport_error")
        except Exception:
            return NotificationAdapterResult(error_code="adapter_error")

    async def aclose(self) -> None:
        if owns_client(self._client):
            await self._client.aclose()
