from __future__ import annotations

import base64
import ipaddress
import json
import ssl
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from websockets.asyncio.server import serve

from red2pr_control.extensions.webhook_relay import (
    RelayFrameRejected,
    canonical_websocket_uri,
    ingest_relay_frame,
    receive_customer_relay_frame,
    sign_relay_frame,
    verify_relay_frame,
)

WS = "0196ed16-0000-7000-8000-000000000301"
CONN = "0196ed16-0000-7000-8000-000000000401"
SECRET = b"relay-frame-test-secret-32-bytes-long"


def _payload(seq: int = 1) -> dict[str, object]:
    return {
        "relay_seq": seq,
        "workspace_id": WS,
        "provider_connection_id": CONN,
        "provider": "github",
        "raw_headers": [
            ["X-Hub-Signature-256", "sha256=" + "a" * 64],
            ["X-GitHub-Event", "push"],
            ["X-GitHub-Delivery", "delivery-1"],
        ],
        "raw_body_b64": base64.b64encode(b'{"repository":{"full_name":"org/repo"}}').decode(),
    }


def test_verified_frame_preserves_exact_provider_bytes_and_headers() -> None:
    frame = sign_relay_frame(_payload(), secret=SECRET)
    verified = verify_relay_frame(
        frame.model_dump_json(),
        secret=SECRET,
        expected_workspace_id=WS,
        expected_connection_id=CONN,
        expected_provider="github",
        last_relay_seq=0,
    )

    assert verified.raw_body == b'{"repository":{"full_name":"org/repo"}}'
    assert verified.raw_headers[0] == ("X-Hub-Signature-256", "sha256=" + "a" * 64)


@pytest.mark.parametrize(
    ("payload_change", "last_seq", "expected_code"),
    [
        (
            {"raw_body_b64": base64.b64encode(b"tampered").decode()},
            0,
            "relay_frame_signature_invalid",
        ),
        (
            {"workspace_id": "0196ed16-0000-7000-8000-000000000302"},
            0,
            "relay_tenant_binding_invalid",
        ),
        ({}, 1, "relay_frame_replayed"),
        ({"relay_seq": 3}, 0, "relay_cursor_gap"),
        ({"raw_headers": [["X-Test", "a"], ["x-test", "b"]]}, 0, "relay_headers_invalid"),
    ],
)
def test_invalid_integrity_scope_replay_gap_or_ambiguous_headers_rejected(
    payload_change: dict[str, object], last_seq: int, expected_code: str
) -> None:
    if expected_code == "relay_frame_signature_invalid":
        frame = sign_relay_frame(_payload(), secret=SECRET)
        wire = json.loads(frame.model_dump_json())
        wire.update(payload_change)
        raw_message = json.dumps(wire)
    else:
        payload = _payload()
        payload.update(payload_change)
        raw_message = sign_relay_frame(payload, secret=SECRET).model_dump_json()

    with pytest.raises(RelayFrameRejected) as exc_info:
        verify_relay_frame(
            raw_message,
            secret=SECRET,
            expected_workspace_id=WS,
            expected_connection_id=CONN,
            expected_provider="github",
            last_relay_seq=last_seq,
        )

    assert exc_info.value.code == expected_code


def test_registered_websocket_uri_has_fixed_path_and_encoded_cursor() -> None:
    uri = canonical_websocket_uri("relay.customer.example", 443, CONN, 8)
    assert uri == (
        "wss://relay.customer.example/api/v1/relay/v1/stream"
        f"?provider_connection_id={CONN}&after_seq=8"
    )


def test_websocket_uri_rejects_path_in_host_and_negative_cursor() -> None:
    with pytest.raises(ValueError):
        canonical_websocket_uri("relay.example/path", 443, CONN, 0)
    with pytest.raises(ValueError):
        canonical_websocket_uri("relay.example", 443, CONN, -1)


def _certificate_pair(*, common_name: str, ca_key, ca_cert, san: str | None = None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


@pytest.mark.asyncio
async def test_customer_relay_client_uses_pinned_wss_and_mutual_tls() -> None:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "U29 test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_cert, server_key = _certificate_pair(
        common_name="localhost", ca_key=ca_key, ca_cert=ca_cert, san="localhost"
    )
    client_cert, client_key = _certificate_pair(
        common_name="red2pr-u29-test-client", ca_key=ca_key, ca_cert=ca_cert
    )
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    with tempfile.TemporaryDirectory(prefix="red2pr-u29-test-") as directory:
        server_cert_path = Path(directory) / "server.crt"
        server_key_path = Path(directory) / "server.key"
        ca_path = Path(directory) / "ca.crt"
        server_cert_path.write_text(server_cert)
        server_key_path.write_text(server_key)
        ca_path.write_text(ca_pem)
        server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_context.load_cert_chain(server_cert_path, server_key_path)
        server_context.load_verify_locations(ca_path)
        server_context.verify_mode = ssl.CERT_REQUIRED
        received_subscribe: list[dict[str, object]] = []

        async def relay_handler(socket) -> None:
            received_subscribe.append(json.loads(await socket.recv()))
            await socket.send("{\"signed\":true}")

        async with serve(relay_handler, "127.0.0.1", 0, ssl=server_context) as server:
            port = server.sockets[0].getsockname()[1]
            policy = SimpleNamespace(
                evaluate_and_resolve=AsyncMock(
                    return_value=SimpleNamespace(
                        scheme="wss",
                        host="localhost",
                        port=port,
                        pinned_ips=(ipaddress.ip_address("127.0.0.1"),),
                        ca_ref="u29-test-ca",
                    )
                )
            )
            ca_resolver = SimpleNamespace(resolve_ca_pem=AsyncMock(return_value=ca_pem))
            uri = f"wss://localhost:{port}/api/v1/relay/v1/stream?provider_connection_id={CONN}&after_seq=7"
            secure_tmp = Path(tempfile.gettempdir())
            existing_files = set(secure_tmp.glob("red2pr-relay-*"))
            received = await receive_customer_relay_frame(
                uri=uri,
                workspace_id=WS,
                connection_id=CONN,
                after_seq=7,
                client_certificate_pem=client_cert,
                client_private_key_pem=client_key,
                egress_policy=policy,  # type: ignore[arg-type]
                ca_bundle_resolver=ca_resolver,  # type: ignore[arg-type]
            )
            assert received == '{"signed":true}'
            assert received_subscribe == [
                {
                    "type": "subscribe",
                    "workspace_id": WS,
                    "provider_connection_id": CONN,
                    "after_seq": 7,
                }
            ]
            assert policy.evaluate_and_resolve.await_args.kwargs["adapter"] == "webhook"
            assert not (set(secure_tmp.glob("red2pr-relay-*")) - existing_files)


@pytest.mark.asyncio
async def test_verified_frame_is_delegated_to_provider_webhook_verifier() -> None:
    webhook = SimpleNamespace(
        ingest_webhook=AsyncMock(return_value=(202, {"status": "accepted"}))
    )
    frame = sign_relay_frame(_payload(), secret=SECRET)
    status, receipt, next_seq = await ingest_relay_frame(
        frame.model_dump_json(),
        secret=SECRET,
        expected_workspace_id=WS,
        expected_connection_id=CONN,
        expected_provider="github",
        last_relay_seq=0,
        webhook_ingest_service=webhook,  # type: ignore[arg-type]
        correlation_id="corr-u29-test",
    )

    assert status == 202
    assert receipt == {"status": "accepted"}
    assert next_seq == 1
    call = webhook.ingest_webhook.await_args.kwargs
    assert call["provider"] == "github"
    assert call["connection_id"] == CONN
    assert call["raw_body"] == base64.b64decode(frame.raw_body_b64)
    assert call["client_ip"] is None


@pytest.mark.asyncio
async def test_invalid_frame_is_rejected_before_provider_inbox_write() -> None:
    webhook = SimpleNamespace(ingest_webhook=AsyncMock())
    frame = sign_relay_frame(_payload(), secret=SECRET)
    wire = json.loads(frame.model_dump_json())
    wire["workspace_id"] = "0196ed16-0000-7000-8000-000000000302"

    with pytest.raises(RelayFrameRejected):
        await ingest_relay_frame(
            json.dumps(wire),
            secret=SECRET,
            expected_workspace_id=WS,
            expected_connection_id=CONN,
            expected_provider="github",
            last_relay_seq=0,
            webhook_ingest_service=webhook,  # type: ignore[arg-type]
            correlation_id="corr-u29-test",
        )

    webhook.ingest_webhook.assert_not_awaited()
