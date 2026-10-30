"""Shared notification adapter contracts, secret resolution, and safe result helpers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Protocol

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from red2pr_control.core.egress import EgressSafeHttpClient
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.notifications.dispatcher import (
    NotificationAdapterResult,
    NotificationSendRequest,
)
from red2pr_control.secrets.broker import NOTIFICATIONS_SECRET_CAPABILITY, SecretBroker


class OutboundHttpClient(Protocol):
    async def request(
        self,
        method: str,
        url: str | httpx.URL,
        *,
        headers: Mapping[str, str] | None = None,
        content: bytes | str | None = None,
        json: Any = None,
    ) -> httpx.Response: ...

    async def aclose(self) -> None: ...


SecretResolver = Callable[[NotificationSendRequest], Awaitable[bytes]]


class NotificationSecretResolver:
    """Resolve notification secrets only for Z2 notification-channel adapters."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        secret_broker: SecretBroker,
    ) -> None:
        self._session_factory = session_factory
        self._secret_broker = secret_broker

    async def __call__(self, request: NotificationSendRequest) -> bytes:
        if not request.secret_ref:
            raise ValueError("notification_secret_not_configured")
        async with workspace_rls_session(
            self._session_factory, workspace_id=request.workspace_id
        ) as db:
            return await self._secret_broker.resolve_secret_bytes(
                db,
                secret_ref=request.secret_ref,
                capability=NOTIFICATIONS_SECRET_CAPABILITY,
                workspace_id=request.workspace_id,
            )


def response_retry_after(response: httpx.Response) -> int | None:
    raw = response.headers.get("Retry-After")
    if raw is None:
        return None
    try:
        return max(0, min(int(float(raw)), 86_400))
    except (ValueError, OverflowError):
        return None


def safe_http_result(response: httpx.Response, *, provider: str) -> NotificationAdapterResult:
    status = response.status_code
    provider_id: str | None = None
    try:
        payload = response.json()
    except (ValueError, UnicodeDecodeError):
        payload = None
    if isinstance(payload, Mapping):
        raw_id = payload.get("id")
        if isinstance(raw_id, (str, int)) and not isinstance(raw_id, bool):
            candidate = str(raw_id)
            if 0 < len(candidate) <= 128 and candidate.isprintable():
                provider_id = candidate
    return NotificationAdapterResult(
        http_status=status,
        provider_id=provider_id,
        retry_after_seconds=response_retry_after(response),
        timed_out_after_send=False,
        error_code=None if 200 <= status < 300 else f"{provider}_http_{status}",
    )


def owns_client(client: OutboundHttpClient) -> bool:
    return isinstance(client, EgressSafeHttpClient)
