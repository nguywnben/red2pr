"""Discord incoming-webhook adapter with explicit receipt and disabled mentions."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit, urlunsplit

import httpx

from red2pr_control.notifications.channels.common import OutboundHttpClient, owns_client
from red2pr_control.notifications.dispatcher import (
    NotificationAdapterResult,
    NotificationSendRequest,
)

_ALLOWED_HOSTS = frozenset({"discord.com", "discordapp.com"})


def validate_discord_webhook_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        pieces = parsed.path.split("/")
        return (
            parsed.scheme == "https"
            and parsed.hostname in _ALLOWED_HOSTS
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and parsed.fragment == ""
            and len(pieces) == 5
            and pieces[1:3] == ["api", "webhooks"]
            and pieces[3].isdigit()
            and len(pieces[4]) >= 24
            and not parsed.query
        )
    except ValueError:
        return False


def build_discord_payload(title: str, body: str, deep_link: str | None) -> dict[str, object]:
    text = f"**{title[:180]}**\n{body[:1600]}"
    if deep_link:
        text += f"\n{deep_link[:512]}"
    return {"content": text[:1900], "allowed_mentions": {"parse": []}}


class DiscordNotificationAdapter:
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
            parsed = urlsplit(url)
            if not validate_discord_webhook_url(url):
                return NotificationAdapterResult(http_status=400, error_code="invalid_destination")
            query = "wait=true"
            if parsed.query:
                query = f"{parsed.query}&wait=true"
            response = await self._client.request(
                "POST",
                urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, "")),
                json=build_discord_payload(request.title, request.body, request.deep_link),
                headers={"Content-Type": "application/json"},
            )
            retry_after = None
            if response.status_code == 429:
                raw_retry_after = response.headers.get("Retry-After")
                try:
                    if raw_retry_after is not None:
                        retry_after = max(0, min(86_400, int(float(raw_retry_after) + 0.999)))
                    else:
                        payload = response.json()
                        raw_retry_after = (
                            payload.get("retry_after") if isinstance(payload, dict) else None
                        )
                        if raw_retry_after is not None:
                            retry_after = max(0, min(86_400, int(float(raw_retry_after) + 0.999)))
                except (ValueError, TypeError, OverflowError):
                    retry_after = None
            provider_id = None
            if 200 <= response.status_code < 300:
                try:
                    payload = response.json()
                    raw_id = payload.get("id") if isinstance(payload, dict) else None
                    if isinstance(raw_id, (str, int)) and not isinstance(raw_id, bool):
                        candidate = str(raw_id)
                        if candidate.isprintable() and len(candidate) <= 128:
                            provider_id = candidate
                except (ValueError, json.JSONDecodeError):
                    pass
                if provider_id is None:
                    return NotificationAdapterResult(
                        http_status=503, error_code="missing_message_receipt"
                    )
            return NotificationAdapterResult(
                http_status=response.status_code,
                provider_id=provider_id,
                retry_after_seconds=retry_after,
                error_code=None if 200 <= response.status_code < 300 else "discord_delivery_failed",
            )
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
