"""Bounded Telegram Bot API transport and allowlisted update normalization."""

from __future__ import annotations

import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

_BOT_API_ORIGIN = "https://api.telegram.org"
_BOT_TOKEN_RE = re.compile(r"[0-9]{5,}:[A-Za-z0-9_-]{20,}")
_WEBHOOK_SECRET_RE = re.compile(r"[A-Za-z0-9_-]{32,256}")
_COMMAND_RE = re.compile(r"^/([A-Za-z][A-Za-z0-9_]{0,31})(?:@([A-Za-z0-9_]{5,32}))?(?:\s+(.*))?$")
_MAX_ARGUMENTS_BYTES = 2048


@dataclass(frozen=True, slots=True)
class TelegramApiResult:
    ok: bool
    result: Any = None
    error_code: int | None = None
    retry_after_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class TelegramUpdate:
    update_id: int
    chat_id: str
    telegram_user_id: str
    chat_type: str
    command: str
    arguments: tuple[str, ...]
    forwarded: bool


class TelegramNotificationChannelAdapter:
    """U21 channel adapter using the configured per-instance bot, with no parse mode."""

    def __init__(self, api: TelegramApiClient) -> None:
        self._api = api

    async def deliver(self, request: Any) -> Any:
        return await self._send(request)

    async def send_test(self, request: Any) -> Any:
        return await self._send(request)

    async def _send(self, request: Any) -> Any:
        from red2pr_control.notifications.dispatcher import NotificationAdapterResult

        if not re.fullmatch(r"-?[0-9]{1,32}", request.address):
            return NotificationAdapterResult(http_status=400, error_code="invalid_chat_id")
        text = f"{request.title}\n{request.body}"
        if request.deep_link:
            text += f"\n{request.deep_link}"
        result = await self._api.call(
            "sendMessage",
            {"chat_id": request.address, "text": text[:4000], "disable_web_page_preview": True},
        )
        if result.ok:
            message = result.result if isinstance(result.result, dict) else {}
            message_id = message.get("message_id")
            return NotificationAdapterResult(
                http_status=200,
                provider_id=str(message_id)[:128] if message_id is not None else None,
            )
        return NotificationAdapterResult(
            http_status=result.error_code
            if result.error_code in {400, 401, 403, 404, 429}
            else 503,
            retry_after_seconds=result.retry_after_seconds,
            timed_out_after_send=result.error_code == 0,
            error_code=f"telegram_{result.error_code or 'transport'}",
        )


class TelegramApiClient:
    """Telegram HTTP client. Error values intentionally omit request URLs and text."""

    def __init__(
        self,
        *,
        token: str,
        client: httpx.AsyncClient | None = None,
        api_base_url: str = _BOT_API_ORIGIN,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not _BOT_TOKEN_RE.fullmatch(token):
            raise ValueError("Telegram bot token is malformed.")
        parsed_base = urlsplit(api_base_url)
        loopback_test_origin = (
            parsed_base.scheme == "http"
            and parsed_base.hostname in {"127.0.0.1", "localhost", "::1"}
            and parsed_base.port is not None
            and parsed_base.username is None
            and parsed_base.password is None
            and not parsed_base.path
            and not parsed_base.query
            and not parsed_base.fragment
        )
        if api_base_url != _BOT_API_ORIGIN and not loopback_test_origin:
            raise ValueError(
                "Telegram API calls must use api.telegram.org or an HTTP loopback test server."
            )
        self._token = token
        self._base_url = api_base_url.rstrip("/")
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 3.0)),
            follow_redirects=False,
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        )
        self._owns_client = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def call(
        self,
        method: str,
        payload: Mapping[str, Any],
        *,
        timeout_seconds: float | None = None,
    ) -> TelegramApiResult:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{1,63}", method):
            raise ValueError("Telegram method name is invalid.")
        try:
            request_options: dict[str, Any] = {}
            if timeout_seconds is not None:
                request_options["timeout"] = httpx.Timeout(
                    timeout_seconds, connect=min(timeout_seconds, 3.0)
                )
            response = await self._client.post(
                f"{self._base_url}/bot{self._token}/{method}",
                json=dict(payload),
                headers={"Accept": "application/json"},
                **request_options,
            )
        except (httpx.TimeoutException, httpx.NetworkError, httpx.ProtocolError):
            return TelegramApiResult(ok=False, error_code=0)
        try:
            data = response.json()
        except ValueError:
            return TelegramApiResult(ok=False, error_code=response.status_code)
        if not isinstance(data, dict):
            return TelegramApiResult(ok=False, error_code=response.status_code)
        ok = data.get("ok") is True and response.is_success
        result = data.get("result") if ok else None
        error_code = data.get("error_code")
        if not isinstance(error_code, int):
            error_code = None if ok else response.status_code
        retry_after: int | None = None
        parameters = data.get("parameters")
        if isinstance(parameters, dict):
            value = parameters.get("retry_after")
            if isinstance(value, int) and 0 < value <= 86_400:
                retry_after = value
        if response.status_code == 429 and retry_after is None:
            header = response.headers.get("Retry-After")
            if header and header.isdecimal() and 0 < int(header) <= 86_400:
                retry_after = int(header)
        return TelegramApiResult(
            ok=ok,
            result=result,
            error_code=error_code,
            retry_after_seconds=retry_after,
        )


def validate_webhook_secret(received: str | None, configured: str) -> bool:
    if not isinstance(received, str) or not _WEBHOOK_SECRET_RE.fullmatch(configured):
        return False
    if not _WEBHOOK_SECRET_RE.fullmatch(received):
        return False
    return hmac.compare_digest(received.encode("ascii"), configured.encode("ascii"))


def normalize_update(raw: Mapping[str, Any], *, bot_username: str) -> TelegramUpdate | None:
    update_id = raw.get("update_id")
    message = raw.get("message")
    if type(update_id) is not int or update_id < 0 or not isinstance(message, dict):
        return None
    chat = message.get("chat")
    sender = message.get("from")
    text = message.get("text")
    if not isinstance(chat, dict) or not isinstance(sender, dict) or not isinstance(text, str):
        return None
    chat_id = chat.get("id")
    user_id = sender.get("id")
    if (
        chat.get("type") != "private"
        or type(chat_id) is not int
        or type(user_id) is not int
        or chat_id <= 0
        or user_id <= 0
        or chat_id != user_id
        or sender.get("is_bot") is True
        or len(text.encode("utf-8")) > _MAX_ARGUMENTS_BYTES
    ):
        return None
    match = _COMMAND_RE.fullmatch(text.strip())
    if match is None:
        return None
    mentioned_bot = match.group(2)
    if mentioned_bot and mentioned_bot.casefold() != bot_username.casefold():
        return None
    raw_args = match.group(3) or ""
    args = tuple(raw_args.split())
    if len(args) > 8 or any(len(arg) > 256 for arg in args):
        return None
    forwarded = any(
        key in message
        for key in ("forward_origin", "forward_from", "forward_from_chat", "forward_sender_name")
    )
    return TelegramUpdate(
        update_id=update_id,
        chat_id=str(chat_id),
        telegram_user_id=str(user_id),
        chat_type="private",
        command=match.group(1).casefold(),
        arguments=args,
        forwarded=forwarded,
    )
