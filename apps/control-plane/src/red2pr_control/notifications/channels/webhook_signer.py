"""Red2PR-Signature v1 signing, reference verification, and generic HTTPS adapter."""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping, MutableSet
from urllib.parse import urlsplit

import httpx

from py_contracts.crypto import (
    CryptoVerificationError,
    canonical_json_bytes,
    sign_red2pr_webhook_v1,
    verify_red2pr_webhook_v1,
)
from red2pr_control.notifications.channels.common import OutboundHttpClient, owns_client
from red2pr_control.notifications.dispatcher import (
    NotificationAdapterResult,
    NotificationSendRequest,
)

_MAX_RESPONSE_BYTES = 16 * 1024


def sign_webhook_delivery(
    *,
    secret: bytes,
    event_id: str,
    delivery_id: str,
    key_id: str,
    timestamp: int,
    body: bytes,
) -> dict[str, str]:
    if not secret or len(secret) < 32:
        raise ValueError("Webhook signing key must contain at least 256 bits.")
    signature = sign_red2pr_webhook_v1(
        secret=secret,
        timestamp_unix=timestamp,
        delivery_id=delivery_id,
        raw_body=body,
    )
    return {
        "Content-Type": "application/json",
        "Red2PR-Event-Id": event_id,
        "Red2PR-Delivery-Id": delivery_id,
        "Red2PR-Timestamp": str(timestamp),
        "Red2PR-Key-Id": key_id,
        "Red2PR-Signature": signature,
    }


def verify_webhook_delivery(
    *,
    secret: bytes,
    headers: Mapping[str, str],
    body: bytes,
    now: int,
    consumed_delivery_ids: MutableSet[str],
) -> bool:
    normalized = {key.lower(): value for key, value in headers.items()}
    try:
        delivery_id = normalized["red2pr-delivery-id"]
        event_id = normalized["red2pr-event-id"]
        key_id = normalized["red2pr-key-id"]
        timestamp = int(normalized["red2pr-timestamp"])
        signature = normalized["red2pr-signature"]
        if (
            not event_id
            or len(event_id) > 128
            or not key_id
            or len(key_id) > 120
            or not delivery_id
            or len(delivery_id) > 128
            or delivery_id in consumed_delivery_ids
        ):
            return False
        verify_red2pr_webhook_v1(
            secret=secret,
            signature_header=signature,
            timestamp_unix=timestamp,
            now_unix=now,
            delivery_id=delivery_id,
            raw_body=body,
            max_skew_seconds=300,
        )
    except (KeyError, ValueError, CryptoVerificationError):
        return False
    consumed_delivery_ids.add(delivery_id)
    return True


def _raw_webhook_body(request: NotificationSendRequest, *, challenge: str | None = None) -> bytes:
    if request.is_test:
        payload = {
            "schema_version": 1,
            "type": "red2pr.webhook.test",
            "event_id": request.event_id,
            "correlation_id": request.correlation_id,
            "title": request.title,
            "body": request.body,
            "challenge": challenge,
        }
    else:
        payload = request.event_payload or {
            "schema_version": 1,
            "type": request.event_type or "notification.unknown",
            "event_id": request.event_id,
            "correlation_id": request.correlation_id,
            "workspace_id": request.workspace_id,
            "repository_id": request.repository_id,
            "occurred_at": request.occurred_at,
            "payload": {"title": request.title, "body": request.body},
        }
    return canonical_json_bytes(payload)


def _valid_webhook_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https"
            and parsed.hostname is not None
            and parsed.username is None
            and parsed.password is None
            and parsed.fragment == ""
        )
    except ValueError:
        return False


class SignedWebhookNotificationAdapter:
    def __init__(
        self,
        *,
        http_client: OutboundHttpClient,
        resolve_secret: Callable[[NotificationSendRequest], Awaitable[bytes]],
        clock: Callable[[], int] | None = None,
        test_challenge_echo_header: str = "Red2PR-Challenge",
    ) -> None:
        self._client = http_client
        self._resolve_secret = resolve_secret
        self._clock = clock or (lambda: int(time.time()))
        self._challenge_header = test_challenge_echo_header

    async def deliver(self, request: NotificationSendRequest) -> NotificationAdapterResult:
        return await self._send(request, test=False)

    async def send_test(self, request: NotificationSendRequest) -> NotificationAdapterResult:
        return await self._send(request, test=True)

    async def _send(
        self, request: NotificationSendRequest, *, test: bool
    ) -> NotificationAdapterResult:
        challenge = secrets.token_urlsafe(32) if test else None
        try:
            if not _valid_webhook_url(request.address):
                return NotificationAdapterResult(http_status=400, error_code="invalid_destination")
            if not request.secret_ref or not request.webhook_key_id:
                return NotificationAdapterResult(
                    http_status=400, error_code="webhook_signing_key_unconfigured"
                )
            secret = await self._resolve_secret(request)
            if len(secret) < 32:
                return NotificationAdapterResult(http_status=400, error_code="invalid_signing_key")
            body = _raw_webhook_body(request, challenge=challenge)
            headers = sign_webhook_delivery(
                secret=secret,
                event_id=request.event_id or "test",
                delivery_id=request.delivery_id or request.correlation_id,
                key_id=request.webhook_key_id or "active",
                timestamp=self._clock(),
                body=body,
            )
            response = await self._client.request(
                "POST",
                request.address,
                content=body,
                headers=headers,
            )
            if response.status_code in {301, 302, 303, 307, 308}:
                return NotificationAdapterResult(
                    http_status=400, error_code="webhook_redirect_rejected"
                )
            if len(response.content) > _MAX_RESPONSE_BYTES:
                return NotificationAdapterResult(http_status=502, error_code="response_too_large")
            if test and response.headers.get(self._challenge_header) != challenge:
                return NotificationAdapterResult(
                    http_status=409, error_code="proof_of_control_failed"
                )
            provider_id = response.headers.get("Red2PR-Receipt-Id")
            if provider_id is not None and (
                len(provider_id) > 128 or not provider_id.isprintable()
            ):
                provider_id = None
            return NotificationAdapterResult(
                http_status=response.status_code,
                provider_id=provider_id,
                error_code=None if 200 <= response.status_code < 300 else "webhook_delivery_failed",
            )
        except asyncio.CancelledError:
            raise
        except (TimeoutError, httpx.TimeoutException):
            return NotificationAdapterResult(
                timed_out_after_send=True, error_code="timeout_after_send"
            )
        except httpx.TransportError:
            return NotificationAdapterResult(error_code="transport_error")
        except Exception:
            return NotificationAdapterResult(error_code="adapter_error")

    async def aclose(self) -> None:
        if owns_client(self._client):
            await self._client.aclose()
