"""Canonical cryptographic primitives for Red2PR contracts (S-21, S-22, OPS-03, SEC-030).

Provides:
- Deterministic RFC-8785-compatible sorted-key UTF-8 canonical JSON serialization
  (forbidding NaN/Infinity).
- Domain-separated Ed25519 manifest & worker-result signing and verification with
  KeyRing enrollment, algorithm checks, trust-domain binding, and revoked-at-signing
  enforcement (SEC-030).
- Versioned AES-256-GCM envelope encryption (256-bit KEK wrapping random 256-bit DEK
  with canonical AAD binding) supporting live key rotation (OPS-03).
- Constant-time HMAC-SHA256 verification and Red2PR v1 webhook signing/verification
  (docs/32_NOTIFICATION_EVENT_MATRIX.md).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from py_contracts.primitives import (
    BoundedName,
    BoundedText,
    PositiveVersion,
    Sha256Digest,
    StrictContractModel,
    UtcTimestamp,
)

DOMAIN_RESULT_V1: str = "red2pr.worker.result.v1"
DOMAIN_EVIDENCE_MANIFEST_V1: str = "red2pr.evidence.manifest.v1"
DOMAIN_RELEASE_MANIFEST_V1: str = "red2pr.release.manifest.v1"
DOMAIN_AUDIT_CHECKPOINT_V1: str = "red2pr.audit.checkpoint.v1"

_ED25519_SIG_PREFIX = "ed25519:"
_AES256_KEY_BYTES = 32
_AESGCM_NONCE_BYTES = 12


class CryptoVerificationError(ValueError):
    """Deterministic cryptographic verification or decryption failure."""

    def __init__(self, *, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(encoded: str) -> bytes:
    padding = "=" * ((4 - (len(encoded) % 4)) % 4)
    try:
        return base64.urlsafe_b64decode((encoded + padding).encode("ascii"))
    except Exception as exc:
        raise CryptoVerificationError(
            code="malformed_encoding",
            detail="Invalid base64url cryptographic field",
        ) from exc


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize a JSON-compatible object to deterministic UTF-8 bytes without whitespace."""
    try:
        serialized = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Non-canonicalizable JSON value: {exc}") from exc
    return serialized.encode("utf-8")


def sha256_canonical_json(value: Any) -> str:
    """Compute lowercase 64-char SHA-256 hex digest over canonical_json_bytes(value)."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


# ---------------------------------------------------------------------------
# Domain-Separated Ed25519 Signing & Verification (S-21, S-22, SEC-030)
# ---------------------------------------------------------------------------


class PublicKeyRecord(StrictContractModel):
    """Enrolled verification public key metadata retained across rotations (S-22)."""

    key_id: BoundedName
    algorithm: Literal["ed25519"] = "ed25519"
    public_key_b64: BoundedText
    not_before: UtcTimestamp
    revoked_at: UtcTimestamp | None = None
    trust_domain: BoundedName | None = None


def export_ed25519_public_key_record(
    *,
    private_key: Ed25519PrivateKey,
    key_id: str,
    not_before: datetime,
    revoked_at: datetime | None = None,
    trust_domain: str | None = None,
) -> PublicKeyRecord:
    """Export raw 32-byte Ed25519 public key into an immutable PublicKeyRecord."""
    raw_pub = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return PublicKeyRecord(
        key_id=key_id,
        algorithm="ed25519",
        public_key_b64=_b64url_encode(raw_pub),
        not_before=not_before,
        revoked_at=revoked_at,
        trust_domain=trust_domain,
    )


class KeyRing:
    """In-memory verification key ring supporting rotated historical keys and revocations."""

    def __init__(self, records: Iterable[PublicKeyRecord] = ()) -> None:
        self._records: dict[str, PublicKeyRecord] = {rec.key_id: rec for rec in records}

    def get(self, key_id: str) -> PublicKeyRecord | None:
        return self._records.get(key_id)


def _domain_separated_message(domain: str, payload: Mapping[str, Any]) -> bytes:
    if not domain or "\x00" in domain:
        raise ValueError("Signing domain must be non-empty ASCII without null bytes")
    return domain.encode("ascii") + b"\x00" + canonical_json_bytes(dict(payload))


def _signable_model_dict(model: StrictContractModel) -> dict[str, Any]:
    dumped: dict[str, Any] = model.model_dump(mode="json", by_alias=True)
    dumped.pop("signature", None)
    return dumped


def sign_domain_separated_ed25519(
    payload: Mapping[str, Any],
    *,
    private_key: Ed25519PrivateKey,
    domain: str,
) -> str:
    """Sign a canonical JSON payload under an explicit domain separator."""
    clean_payload = {k: v for k, v in payload.items() if k != "signature"}
    msg = _domain_separated_message(domain, clean_payload)
    sig_bytes = private_key.sign(msg)
    return f"{_ED25519_SIG_PREFIX}{_b64url_encode(sig_bytes)}"


def sign_model_ed25519[TSignedModel: StrictContractModel](
    model: TSignedModel,
    *,
    private_key: Ed25519PrivateKey,
    key_id: str,
    domain: str,
) -> TSignedModel:
    """Return a copy of a signed contract model (ResultV1 / EvidenceManifestV1) with signature."""
    with_key_id = model.model_copy(update={"signer_key_id": key_id})
    sig = sign_domain_separated_ed25519(
        _signable_model_dict(with_key_id),
        private_key=private_key,
        domain=domain,
    )
    return with_key_id.model_copy(update={"signature": sig})


def verify_model_ed25519(
    model: StrictContractModel,
    *,
    keyring: KeyRing,
    domain: str,
    signed_at: datetime,
    expected_trust_domain: str | None = None,
) -> PublicKeyRecord:
    """Verify domain-separated Ed25519 signature, key validity window, and trust domain."""
    key_id = getattr(model, "signer_key_id", None)
    signature_field = getattr(model, "signature", None)
    if not isinstance(key_id, str) or not isinstance(signature_field, str):
        raise CryptoVerificationError(
            code="missing_signature_fields",
            detail="Model does not expose signer_key_id and signature strings",
        )

    record = keyring.get(key_id)
    if record is None:
        raise CryptoVerificationError(
            code="unknown_signer_key",
            detail=f"Signer key {key_id!r} is not enrolled in trust keyring",
        )

    if not signature_field.startswith(_ED25519_SIG_PREFIX) or record.algorithm != "ed25519":
        raise CryptoVerificationError(
            code="unsupported_signature_algorithm",
            detail="Only domain-separated ed25519 signatures are accepted",
        )

    if expected_trust_domain is not None and record.trust_domain != expected_trust_domain:
        raise CryptoVerificationError(
            code="trust_domain_mismatch",
            detail="Signer key trust_domain does not match expected worker trust domain",
        )

    if signed_at < record.not_before:
        raise CryptoVerificationError(
            code="key_not_yet_valid",
            detail="Signature timestamp precedes key enrollment not_before",
        )

    if record.revoked_at is not None and signed_at >= record.revoked_at:
        raise CryptoVerificationError(
            code="signer_key_revoked",
            detail="Signer key was already revoked at or before signing timestamp",
        )

    raw_pub = _b64url_decode(record.public_key_b64)
    if len(raw_pub) != 32:
        raise CryptoVerificationError(
            code="invalid_public_key",
            detail="Ed25519 public key must be exactly 32 bytes",
        )
    raw_sig = _b64url_decode(signature_field[len(_ED25519_SIG_PREFIX) :])
    if len(raw_sig) != 64:
        raise CryptoVerificationError(
            code="invalid_signature",
            detail="Ed25519 signature must be exactly 64 bytes",
        )

    pub_key = Ed25519PublicKey.from_public_bytes(raw_pub)
    msg = _domain_separated_message(domain, _signable_model_dict(model))
    try:
        pub_key.verify(raw_sig, msg)
    except InvalidSignature as exc:
        raise CryptoVerificationError(
            code="invalid_signature",
            detail="Ed25519 signature verification failed (payload or domain mismatch)",
        ) from exc

    return record


# ---------------------------------------------------------------------------
# Versioned AES-256-GCM Envelope Encryption (OPS-03)
# ---------------------------------------------------------------------------


class EnvelopeCiphertext(StrictContractModel):
    """Version-tagged AES-256-GCM envelope ciphertext (KEK-wrapped DEK + AAD binding)."""

    envelope_version: Literal[1] = 1
    kek_version: PositiveVersion
    wrapped_dek_nonce_b64: BoundedText
    wrapped_dek_b64: BoundedText
    payload_nonce_b64: BoundedText
    ciphertext_b64: BoundedText
    aad_digest: Sha256Digest


class MasterKeyRing:
    """Versioned 256-bit Master Key-Encryption-Key (KEK) ring supporting live rotation."""

    def __init__(self, *, active_version: int, keys: Mapping[int, bytes]) -> None:
        if active_version < 1 or active_version not in keys:
            raise ValueError("active_version must be >= 1 and present in keys mapping")
        validated: dict[int, bytes] = {}
        for ver, material in keys.items():
            if ver < 1 or len(material) != _AES256_KEY_BYTES:
                raise ValueError("Every KEK version must be >= 1 with 32-byte key material")
            validated[ver] = bytes(material)
        self.active_version = active_version
        self._keys = validated

    def get(self, version: int) -> bytes | None:
        return self._keys.get(version)


def encrypt_envelope(
    plaintext: bytes,
    *,
    key_ring: MasterKeyRing,
    aad_context: Mapping[str, Any],
) -> EnvelopeCiphertext:
    """Encrypt bytes with a fresh 256-bit DEK wrapped by the active KEK version."""
    kek_version = key_ring.active_version
    kek = key_ring.get(kek_version)
    if kek is None:
        raise CryptoVerificationError(code="missing_kek", detail="Active KEK missing")

    bound_aad = canonical_json_bytes({"kek_version": kek_version, "context": dict(aad_context)})
    aad_digest = hashlib.sha256(bound_aad).hexdigest()

    dek = os.urandom(_AES256_KEY_BYTES)
    dek_nonce = os.urandom(_AESGCM_NONCE_BYTES)
    payload_nonce = os.urandom(_AESGCM_NONCE_BYTES)

    wrapped_dek = AESGCM(kek).encrypt(dek_nonce, dek, bound_aad)
    ciphertext = AESGCM(dek).encrypt(payload_nonce, plaintext, bound_aad)

    return EnvelopeCiphertext(
        kek_version=kek_version,
        wrapped_dek_nonce_b64=_b64url_encode(dek_nonce),
        wrapped_dek_b64=_b64url_encode(wrapped_dek),
        payload_nonce_b64=_b64url_encode(payload_nonce),
        ciphertext_b64=_b64url_encode(ciphertext),
        aad_digest=aad_digest,
    )


def decrypt_envelope(
    envelope: EnvelopeCiphertext,
    *,
    key_ring: MasterKeyRing,
    aad_context: Mapping[str, Any],
) -> bytes:
    """Unwrap DEK using envelope.kek_version and authenticate/decrypt payload with AAD."""
    kek = key_ring.get(envelope.kek_version)
    if kek is None:
        raise CryptoVerificationError(
            code="unknown_kek_version",
            detail=f"KEK version {envelope.kek_version} is not available in key ring",
        )

    bound_aad = canonical_json_bytes(
        {"kek_version": envelope.kek_version, "context": dict(aad_context)}
    )
    expected_aad_digest = hashlib.sha256(bound_aad).hexdigest()
    if not hmac.compare_digest(expected_aad_digest, envelope.aad_digest):
        raise CryptoVerificationError(
            code="aad_mismatch",
            detail="Authenticated context does not match envelope AAD binding",
        )

    dek_nonce = _b64url_decode(envelope.wrapped_dek_nonce_b64)
    wrapped_dek = _b64url_decode(envelope.wrapped_dek_b64)
    payload_nonce = _b64url_decode(envelope.payload_nonce_b64)
    ciphertext = _b64url_decode(envelope.ciphertext_b64)

    if len(dek_nonce) != _AESGCM_NONCE_BYTES or len(payload_nonce) != _AESGCM_NONCE_BYTES:
        raise CryptoVerificationError(
            code="invalid_nonce",
            detail="AES-GCM nonce must be 12 bytes",
        )

    try:
        dek = AESGCM(kek).decrypt(dek_nonce, wrapped_dek, bound_aad)
        return AESGCM(dek).decrypt(payload_nonce, ciphertext, bound_aad)
    except InvalidTag as exc:
        raise CryptoVerificationError(
            code="envelope_auth_failed",
            detail="AES-256-GCM authentication tag verification failed",
        ) from exc


# ---------------------------------------------------------------------------
# Constant-Time HMAC-SHA256 & Red2PR Outgoing Webhook Signature v1 (docs/32)
# ---------------------------------------------------------------------------


def compute_hmac_sha256_hex(secret: bytes, message: bytes) -> str:
    """Compute lowercase HMAC-SHA256 hex digest over raw bytes."""
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def verify_hmac_sha256_hex(secret: bytes, message: bytes, signature_header: str) -> bool:
    """Constant-time verification of 'sha256=<hex>' or raw '<hex>' HMAC-SHA256 header."""
    candidate = signature_header.strip()
    if candidate.startswith("sha256="):
        candidate = candidate[len("sha256=") :]
    expected = compute_hmac_sha256_hex(secret, message)
    return hmac.compare_digest(expected.encode("ascii"), candidate.lower().encode("ascii"))


def sign_red2pr_webhook_v1(
    *,
    secret: bytes,
    timestamp_unix: int,
    delivery_id: str,
    raw_body: bytes,
) -> str:
    """Compute Red2PR-Signature = 'v1,<base64 HMAC-SHA256>' over timestamp.delivery_id.body."""
    prefix = f"{timestamp_unix}.{delivery_id}.".encode("ascii")
    mac = hmac.new(secret, prefix + raw_body, hashlib.sha256).digest()
    encoded = base64.b64encode(mac).decode("ascii")
    return f"v1,{encoded}"


def verify_red2pr_webhook_v1(
    *,
    secret: bytes,
    signature_header: str,
    timestamp_unix: int,
    now_unix: int,
    delivery_id: str,
    raw_body: bytes,
    max_skew_seconds: int = 300,
) -> None:
    """Constant-time verification of Red2PR v1 outgoing webhook signature and replay window."""
    if abs(now_unix - timestamp_unix) > max_skew_seconds:
        raise CryptoVerificationError(
            code="webhook_timestamp_skew",
            detail=f"Webhook timestamp skew exceeds {max_skew_seconds}s tolerance",
        )
    expected = sign_red2pr_webhook_v1(
        secret=secret,
        timestamp_unix=timestamp_unix,
        delivery_id=delivery_id,
        raw_body=raw_body,
    )
    if not hmac.compare_digest(expected.encode("ascii"), signature_header.strip().encode("ascii")):
        raise CryptoVerificationError(
            code="invalid_webhook_signature",
            detail="Red2PR v1 webhook HMAC verification failed",
        )
