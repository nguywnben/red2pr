"""Opt-in customer-operated WSS relay client and fail-closed frame validation (`U29`)."""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import hmac
import json
import os
import ssl
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlparse

import httpx
from pydantic import ValidationError
from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from websockets.asyncio.client import connect

from py_contracts.extensions import RelayFrameV1, RelayPullResponse
from py_contracts.primitives import new_uuid7
from red2pr_control.core.egress import CaBundleResolverProtocol, EgressPolicyEngine
from red2pr_control.core.errors import ConflictError, ForbiddenError, NotFoundError
from red2pr_control.core.logging import get_structured_logger
from red2pr_control.db.base import (
    ConsentModel,
    EndpointRegistrationModel,
    ProviderConnectionModel,
    RelaySubscriptionModel,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.secrets.broker import SecretBroker, SecretCallerCapability

if TYPE_CHECKING:
    from red2pr_control.integrations.webhooks import WebhookIngestService

MAX_RELAY_BODY_BYTES = 1_000_000
MAX_RELAY_FRAME_BYTES = 1_500_000
_logger = get_structured_logger("red2pr_control.extensions.webhook_relay")
RELAY_SECRET_CAPABILITY = SecretCallerCapability(
    caller_id="z2.webhook_relay", allowed_purposes=frozenset({"webhook_auth"})
)


class RelayFrameRejected(ValueError):
    """A relay frame failed integrity, tenant binding, or monotonic cursor validation."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


@dataclass(frozen=True, slots=True)
class VerifiedRelayFrame:
    frame: RelayFrameV1
    raw_headers: tuple[tuple[str, str], ...]
    raw_body: bytes


def _canonical_unsigned_frame(frame: RelayFrameV1) -> bytes:
    value = frame.model_dump(mode="json", exclude={"signature_sha256"})
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sign_relay_frame(payload: dict[str, Any], *, secret: bytes) -> RelayFrameV1:
    """Build a deterministic HMAC-SHA256-signed frame for customer relay implementations/tests."""
    if len(secret) < 32:
        raise ValueError("Relay frame HMAC key must contain at least 256 bits.")
    unsigned = RelayFrameV1.model_validate({**payload, "signature_sha256": "0" * 64})
    signature = hmac.new(secret, _canonical_unsigned_frame(unsigned), hashlib.sha256).hexdigest()
    return unsigned.model_copy(update={"signature_sha256": signature})


def verify_relay_frame(
    raw_message: str | bytes,
    *,
    secret: bytes,
    expected_workspace_id: str,
    expected_connection_id: str,
    expected_provider: str,
    last_relay_seq: int,
) -> VerifiedRelayFrame:
    """Verify frame HMAC and tenant/provider/cursor before any inbox write."""
    if len(secret) < 32:
        raise RelayFrameRejected("relay_secret_invalid", "Relay HMAC key is invalid.")
    if isinstance(raw_message, bytes):
        if len(raw_message) > MAX_RELAY_FRAME_BYTES:
            raise RelayFrameRejected("relay_frame_too_large", "Relay frame exceeds its size limit.")
        try:
            raw_message = raw_message.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise RelayFrameRejected(
                "relay_frame_invalid", "Relay frame is not UTF-8 JSON."
            ) from exc
    if len(raw_message.encode("utf-8")) > MAX_RELAY_FRAME_BYTES:
        raise RelayFrameRejected("relay_frame_too_large", "Relay frame exceeds its size limit.")
    try:
        frame = RelayFrameV1.model_validate_json(raw_message)
    except ValidationError as exc:
        raise RelayFrameRejected("relay_frame_invalid", "Relay frame schema is invalid.") from exc

    expected_sig = hmac.new(secret, _canonical_unsigned_frame(frame), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, frame.signature_sha256):
        raise RelayFrameRejected(
            "relay_frame_signature_invalid", "Relay frame signature is invalid."
        )
    if (
        frame.workspace_id != expected_workspace_id
        or frame.provider_connection_id != expected_connection_id
        or frame.provider != expected_provider
    ):
        raise RelayFrameRejected(
            "relay_tenant_binding_invalid",
            "Relay frame does not match its bound tenant connection.",
        )
    if frame.relay_seq <= last_relay_seq:
        raise RelayFrameRejected("relay_frame_replayed", "Relay sequence was already consumed.")
    if frame.relay_seq != last_relay_seq + 1:
        raise RelayFrameRejected(
            "relay_cursor_gap", "Relay sequence gap requires polling recovery."
        )

    try:
        body = base64.b64decode(frame.raw_body_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RelayFrameRejected("relay_body_invalid", "Relay body encoding is invalid.") from exc
    if not body or len(body) > MAX_RELAY_BODY_BYTES:
        raise RelayFrameRejected(
            "relay_body_invalid", "Relay body is empty or exceeds its size limit."
        )

    seen_headers: set[str] = set()
    for name, value in frame.raw_headers:
        normalized = name.strip().lower()
        if (
            not normalized
            or "\r" in name
            or "\n" in name
            or "\r" in value
            or "\n" in value
            or normalized in seen_headers
        ):
            raise RelayFrameRejected(
                "relay_headers_invalid", "Relay frame contains invalid or duplicate headers."
            )
        seen_headers.add(normalized)
    return VerifiedRelayFrame(frame=frame, raw_headers=tuple(frame.raw_headers), raw_body=body)


def raw_headers_mapping(frame: VerifiedRelayFrame) -> dict[str, str]:
    """Convert verified unique raw headers to the existing webhook verifier's mapping contract."""
    return {name: value for name, value in frame.raw_headers}


def validate_client_certificate_pair(certificate_pem: str, private_key_pem: str) -> None:
    """Validate the uploaded mTLS identity pair without returning or logging key material."""
    paths: list[Path] = []
    try:
        for pem, suffix in ((certificate_pem, ".crt"), (private_key_pem, ".key")):
            fd, file_path = tempfile.mkstemp(
                prefix="red2pr-relay-validate-",
                suffix=suffix,
                dir=_private_tempdir(),
            )
            os.chmod(file_path, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as cert_file:
                cert_file.write(pem)
            paths.append(Path(file_path))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_cert_chain(certfile=str(paths[0]), keyfile=str(paths[1]))
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise RelayFrameRejected(
            "relay_client_certificate_invalid",
            "Client certificate and private key are invalid or do not match.",
        ) from exc
    finally:
        for path in paths:
            with contextlib.suppress(OSError):
                path.unlink(missing_ok=True)


async def ingest_relay_frame(
    raw_message: str | bytes,
    *,
    secret: bytes,
    expected_workspace_id: str,
    expected_connection_id: str,
    expected_provider: str,
    last_relay_seq: int,
    webhook_ingest_service: WebhookIngestService,
    correlation_id: str,
) -> tuple[int, object, int]:
    """Verify relay integrity first, then delegate original provider auth and durable inbox.

    The returned cursor is only a proposed value. The subscription transaction must compare
    and persist it after the ingress service commits its authenticated inbox receipt.
    """
    verified = verify_relay_frame(
        raw_message,
        secret=secret,
        expected_workspace_id=expected_workspace_id,
        expected_connection_id=expected_connection_id,
        expected_provider=expected_provider,
        last_relay_seq=last_relay_seq,
    )
    status_code, receipt = await webhook_ingest_service.ingest_webhook(
        provider=verified.frame.provider,
        connection_id=verified.frame.provider_connection_id,
        headers=raw_headers_mapping(verified),
        raw_body=verified.raw_body,
        client_ip=None,
        correlation_id=correlation_id,
    )
    return status_code, receipt, verified.frame.relay_seq


def canonical_websocket_uri(host: str, port: int, connection_id: str, cursor: int) -> str:
    """Build the fixed WSS stream URI without accepting a caller-controlled path or query."""
    clean_host = host.strip().lower().rstrip(".")
    if not clean_host or any(ch in clean_host for ch in "/?#@") or not 1 <= port <= 65535:
        raise ValueError("Invalid registered relay endpoint.")
    if cursor < 0:
        raise ValueError("Relay cursor must be non-negative.")
    host_literal = f"[{clean_host}]" if ":" in clean_host else clean_host
    port_suffix = "" if port == 443 else f":{port}"
    return (
        f"wss://{host_literal}{port_suffix}/api/v1/relay/v1/stream"
        f"?provider_connection_id={connection_id}&after_seq={cursor}"
    )


def relay_subscribe_message(*, workspace_id: str, connection_id: str, after_seq: int) -> str:
    """Serialize a canonical cursor request; the relay must replay strictly after this sequence."""
    if after_seq < 0:
        raise ValueError("Relay cursor must be non-negative.")
    return json.dumps(
        {
            "type": "subscribe",
            "workspace_id": workspace_id,
            "provider_connection_id": connection_id,
            "after_seq": after_seq,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


async def receive_customer_relay_frame(
    *,
    uri: str,
    workspace_id: str,
    connection_id: str,
    after_seq: int,
    client_certificate_pem: str,
    client_private_key_pem: str,
    egress_policy: EgressPolicyEngine,
    ca_bundle_resolver: CaBundleResolverProtocol | None,
) -> str | None:
    """Receive one frame through ADR-037 DNS-pinned WSS/mTLS to a customer endpoint.

    Certificate material is written only to mode-0600 temporary files and removed before
    returning. The server hostname remains the registered DNS name for SNI/certificate checks.
    """
    parsed = urlparse(uri)
    if (
        parsed.scheme != "wss"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path != "/api/v1/relay/v1/stream"
        or parsed.fragment
    ):
        raise RelayFrameRejected("relay_endpoint_invalid", "Registered relay endpoint is invalid.")
    target = await egress_policy.evaluate_and_resolve(
        adapter="webhook", url=httpx.URL(uri)
    )
    if target.scheme != "wss" or target.host != parsed.hostname.lower().rstrip("."):
        raise RelayFrameRejected("relay_endpoint_invalid", "Registered relay endpoint is invalid.")
    if not target.pinned_ips:
        raise RelayFrameRejected("relay_dns_unavailable", "Relay endpoint did not resolve safely.")

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if target.ca_ref is not None:
        if ca_bundle_resolver is None:
            raise RelayFrameRejected("relay_ca_unavailable", "Relay CA bundle is unavailable.")
        ca_pem = await ca_bundle_resolver.resolve_ca_pem(target.ca_ref)
        if not ca_pem:
            raise RelayFrameRejected("relay_ca_unavailable", "Relay CA bundle is unavailable.")
        context.load_verify_locations(cadata=ca_pem)

    cert_path: Path | None = None
    key_path: Path | None = None
    try:
        for pem, suffix in ((client_certificate_pem, ".crt"), (client_private_key_pem, ".key")):
            fd, file_path = tempfile.mkstemp(
                prefix="red2pr-relay-", suffix=suffix, dir=_private_tempdir()
            )
            os.chmod(file_path, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as cert_file:
                cert_file.write(pem)
            if suffix == ".crt":
                cert_path = Path(file_path)
            else:
                key_path = Path(file_path)
        assert cert_path is not None and key_path is not None
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        ip_address = target.pinned_ips[0]
        async with connect(
            uri,
            host=str(ip_address),
            port=target.port,
            server_hostname=parsed.hostname,
            ssl=context,
            proxy=None,
            open_timeout=10,
            close_timeout=3,
            max_size=MAX_RELAY_FRAME_BYTES,
            max_queue=1,
            ping_interval=20,
            ping_timeout=20,
        ) as websocket:
            await websocket.send(
                relay_subscribe_message(
                    workspace_id=workspace_id,
                    connection_id=connection_id,
                    after_seq=after_seq,
                )
            )
            try:
                message = await asyncio.wait_for(websocket.recv(), timeout=30)
            except TimeoutError:
                return None
            return message if isinstance(message, str) else bytes(message).decode("utf-8", "strict")
    finally:
        for path in (cert_path, key_path):
            if path is not None:
                with contextlib.suppress(OSError):
                    path.unlink(missing_ok=True)


class CustomerWebhookRelayRunner:
    """Single-frame pull runner; cursor advances only after provider-authenticated ingress."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        secret_broker: SecretBroker,
        egress_policy: EgressPolicyEngine,
        webhook_ingest_service: WebhookIngestService,
        ca_bundle_resolver: CaBundleResolverProtocol | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._secrets = secret_broker
        self._egress = egress_policy
        self._webhooks = webhook_ingest_service
        self._ca_resolver = ca_bundle_resolver

    async def run_forever(self) -> None:
        """Poll enabled subscriptions over outbound WSS with bounded concurrency."""
        semaphore = asyncio.Semaphore(4)

        async def _pull(workspace_id: str, connection_id: str) -> None:
            async with semaphore:
                try:
                    await self.receive_once(
                        workspace_id=workspace_id,
                        connection_id=connection_id,
                        correlation_id=f"relay:{new_uuid7()}",
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    code = getattr(exc, "code", "relay_pull_failed")
                    _logger.warning(
                        "Customer-operated webhook relay pull failed",
                        extra={
                            "workspace_id": workspace_id,
                            "provider_connection_id": connection_id,
                            "reason_code": str(code)[:64],
                        },
                    )

        while True:
            async with instance_rls_session(
                self._session_factory, mode="instance_admin"
            ) as db:
                subscriptions = (
                    await db.execute(
                        select(
                            RelaySubscriptionModel.workspace_id,
                            RelaySubscriptionModel.provider_connection_id,
                        )
                        .where(
                            RelaySubscriptionModel.enabled.is_(True),
                            RelaySubscriptionModel.status.in_(("ready", "degraded")),
                        )
                        .order_by(
                            RelaySubscriptionModel.updated_at,
                            RelaySubscriptionModel.id,
                        )
                        .limit(100)
                    )
                ).all()
            if subscriptions:
                await asyncio.gather(
                    *(_pull(ws_id, conn_id) for ws_id, conn_id in subscriptions)
                )
            await asyncio.sleep(2)

    async def receive_once(
        self,
        *,
        workspace_id: str,
        connection_id: str,
        correlation_id: str,
    ) -> RelayPullResponse:
        async with workspace_rls_session(
            self._session_factory, workspace_id=workspace_id
        ) as db:
            subscription = await db.scalar(
                select(RelaySubscriptionModel).where(
                    RelaySubscriptionModel.workspace_id == workspace_id,
                    RelaySubscriptionModel.provider_connection_id == connection_id,
                )
            )
            if subscription is None:
                raise NotFoundError(
                    code="relay_subscription_not_found", detail="Relay subscription was not found."
                )
            if not subscription.enabled:
                return RelayPullResponse(subscription_id=subscription.id, status="disabled")
            connection = await db.scalar(
                select(ProviderConnectionModel).where(
                    ProviderConnectionModel.workspace_id == workspace_id,
                    ProviderConnectionModel.id == connection_id,
                    ProviderConnectionModel.status == "ready",
                )
            )
            endpoint = await db.scalar(
                select(EndpointRegistrationModel).where(
                    EndpointRegistrationModel.id == subscription.endpoint_registration_id,
                    EndpointRegistrationModel.adapter == "webhook",
                    EndpointRegistrationModel.scheme == "wss",
                    EndpointRegistrationModel.revoked_at.is_(None),
                )
            )
            consent = await db.scalar(
                select(ConsentModel).where(
                    ConsentModel.workspace_id == workspace_id,
                    ConsentModel.id == subscription.consent_id,
                    ConsentModel.purpose == "provider",
                    ConsentModel.scope == "workspace",
                    ConsentModel.revoked_at.is_(None),
                    ConsentModel.data_classes_json.contains(["webhook_payload"]),
                )
            )
            if connection is None or endpoint is None or consent is None:
                subscription.enabled = False
                subscription.status = "degraded"
                subscription.status_detail = "relay_prerequisite_revoked"
                subscription.version += 1
                return RelayPullResponse(subscription_id=subscription.id, status="disabled")
            cursor = subscription.last_relay_seq
            secret_ref = subscription.relay_secret_ref
            provider = connection.provider
            host = endpoint.host
            port = endpoint.port
            secret_bytes = await self._secrets.resolve_secret_bytes(
                db,
                secret_ref=secret_ref,
                capability=RELAY_SECRET_CAPABILITY,
                workspace_id=workspace_id,
            )
            subscription_id = subscription.id
        try:
            secret_data = json.loads(secret_bytes.decode("utf-8"))
            frame_secret = str(secret_data["relay_hmac_secret"]).encode("utf-8")
            client_cert = str(secret_data["client_certificate_pem"])
            client_key = str(secret_data["client_private_key_pem"])
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ForbiddenError(
                code="relay_secret_invalid", detail="Stored relay credentials are invalid."
            ) from exc
        uri = canonical_websocket_uri(host, port, connection_id, cursor)
        try:
            raw_frame = await receive_customer_relay_frame(
                uri=uri,
                workspace_id=workspace_id,
                connection_id=connection_id,
                after_seq=cursor,
                client_certificate_pem=client_cert,
                client_private_key_pem=client_key,
                egress_policy=self._egress,
                ca_bundle_resolver=self._ca_resolver,
            )
            if raw_frame is None:
                return RelayPullResponse(subscription_id=subscription_id, status="idle")
            verified = verify_relay_frame(
                raw_frame,
                secret=frame_secret,
                expected_workspace_id=workspace_id,
                expected_connection_id=connection_id,
                expected_provider=provider,
                last_relay_seq=cursor,
            )
            status_code, _receipt = await self._webhooks.ingest_webhook(
                provider=verified.frame.provider,
                connection_id=verified.frame.provider_connection_id,
                headers={name: value for name, value in verified.raw_headers},
                raw_body=verified.raw_body,
                client_ip=None,
                correlation_id=correlation_id,
            )
            if status_code >= 400:
                raise RelayFrameRejected(
                    "relay_provider_auth_rejected",
                    "Original provider authentication rejected the relayed event.",
                )
        except RelayFrameRejected as exc:
            async with workspace_rls_session(
                self._session_factory, workspace_id=workspace_id
            ) as db:
                row = await db.scalar(
                    select(RelaySubscriptionModel)
                    .where(RelaySubscriptionModel.id == subscription_id)
                    .with_for_update()
                )
                if row is not None and row.last_relay_seq == cursor:
                    row.status = "gap_detected" if exc.code == "relay_cursor_gap" else "degraded"
                    row.status_detail = exc.code
                    row.enabled = False
                    row.version += 1
            if exc.code == "relay_cursor_gap":
                return RelayPullResponse(
                    subscription_id=subscription_id,
                    status="gap_detected",
                    polling_required=True,
                )
            raise

        async with workspace_rls_session(
            self._session_factory, workspace_id=workspace_id
        ) as db:
            result = cast(
                CursorResult[Any],
                await db.execute(
                    update(RelaySubscriptionModel)
                    .where(
                        RelaySubscriptionModel.id == subscription_id,
                        RelaySubscriptionModel.workspace_id == workspace_id,
                        RelaySubscriptionModel.enabled.is_(True),
                        RelaySubscriptionModel.last_relay_seq == cursor,
                    )
                    .values(
                        last_relay_seq=verified.frame.relay_seq,
                        last_received_at=datetime.now(UTC),
                        status="ready",
                        status_detail=None,
                        version=RelaySubscriptionModel.version + 1,
                        updated_at=datetime.now(UTC),
                    )
                ),
            )
            if result.rowcount != 1:
                raise ConflictError(
                    code="relay_cursor_conflict", detail="Relay cursor changed during ingest."
                )
        return RelayPullResponse(
            subscription_id=subscription_id,
            status="received",
            relay_seq=verified.frame.relay_seq,
        )


def _private_tempdir() -> str:
    """Use the operating system's private temp directory for short-lived TLS key files."""
    return tempfile.gettempdir()
