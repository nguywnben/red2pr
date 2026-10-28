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
- RFC 7515 / RFC 7519 RS256 GitHub App JWT signing and verification (`SRC-01`, `U09`).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

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


# ---------------------------------------------------------------------------
# RFC 7515 / RFC 7519 RS256 GitHub App JWT Signing & Verification (SRC-01)
# ---------------------------------------------------------------------------


def _load_rsa_private_key(pem_bytes: bytes, *, min_key_size: int = 2048) -> RSAPrivateKey:
    try:
        loaded = load_pem_private_key(pem_bytes, password=None)
    except Exception as exc:
        raise CryptoVerificationError(
            code="invalid_rsa_private_key",
            detail="Failed to parse unencrypted PEM private key.",
        ) from exc
    if not isinstance(loaded, RSAPrivateKey):
        raise CryptoVerificationError(
            code="unsupported_private_key_type",
            detail="GitHub App JWT signing requires an RSA private key.",
        )
    if loaded.key_size < min_key_size:
        raise CryptoVerificationError(
            code="weak_rsa_key",
            detail=f"RSA private key size must be >= {min_key_size} bits.",
        )
    return loaded


def validate_rsa_private_key_pem(pem_bytes: bytes, *, min_key_size: int = 2048) -> None:
    """Validate that `pem_bytes` is an unencrypted RSA private key of at least `min_key_size`."""
    _load_rsa_private_key(pem_bytes, min_key_size=min_key_size)


def sign_github_app_jwt_rs256(
    *,
    private_key_pem: bytes,
    issuer: str,
    now: datetime,
    ttl_seconds: int = 540,
    clock_drift_seconds: int = 60,
) -> str:
    """Mint an RS256 GitHub App JWT (`iat = now - 60s`, `exp <= now + 540s`, total `<= 10m`)."""
    clean_issuer = issuer.strip()
    if not clean_issuer or len(clean_issuer) > 128:
        raise CryptoVerificationError(
            code="invalid_jwt_issuer",
            detail="GitHub App issuer (app_id or client_id) must be 1..128 characters.",
        )
    if ttl_seconds < 1 or clock_drift_seconds < 0 or (ttl_seconds + clock_drift_seconds) > 600:
        raise CryptoVerificationError(
            code="invalid_jwt_lifetime",
            detail="GitHub App JWT lifetime (exp - iat) must not exceed 600 seconds.",
        )

    rsa_key = _load_rsa_private_key(private_key_pem)
    now_unix = int(now.astimezone(UTC).timestamp())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iat": now_unix - clock_drift_seconds,
        "exp": now_unix + ttl_seconds,
        "iss": clean_issuer,
    }
    signing_input = (
        f"{_b64url_encode(canonical_json_bytes(header))}."
        f"{_b64url_encode(canonical_json_bytes(payload))}"
    ).encode("ascii")
    signature = rsa_key.sign(signing_input, asym_padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input.decode('ascii')}.{_b64url_encode(signature)}"


def verify_rs256_jwt(
    token: str,
    *,
    public_key_pem: bytes,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify an RS256 JWT signature, algorithm header, and `iat`/`exp` window."""
    parts = token.strip().split(".")
    if len(parts) != 3 or not all(parts):
        raise CryptoVerificationError(
            code="malformed_jwt",
            detail="JWT must consist of three non-empty base64url segments.",
        )
    header_b64, payload_b64, sig_b64 = parts
    try:
        header_obj = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        payload_obj = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CryptoVerificationError(
            code="malformed_jwt",
            detail="JWT header or payload is not valid UTF-8 JSON.",
        ) from exc

    if (
        not isinstance(header_obj, dict)
        or header_obj.get("alg") != "RS256"
        or not isinstance(payload_obj, dict)
    ):
        raise CryptoVerificationError(
            code="unsupported_jwt_algorithm",
            detail="Only RS256 JWT headers are accepted.",
        )

    try:
        loaded_pub = load_pem_public_key(public_key_pem)
    except Exception as exc:
        raise CryptoVerificationError(
            code="invalid_rsa_public_key",
            detail="Failed to parse PEM RSA public key.",
        ) from exc
    if not isinstance(loaded_pub, RSAPublicKey):
        raise CryptoVerificationError(
            code="invalid_rsa_public_key",
            detail="Public key is not an RSA key.",
        )

    sig_bytes = _b64url_decode(sig_b64)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        loaded_pub.verify(sig_bytes, signing_input, asym_padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise CryptoVerificationError(
            code="invalid_jwt_signature",
            detail="RS256 JWT signature verification failed.",
        ) from exc

    iat = payload_obj.get("iat")
    exp = payload_obj.get("exp")
    if not isinstance(iat, int) or not isinstance(exp, int) or exp <= iat or (exp - iat) > 600:
        raise CryptoVerificationError(
            code="invalid_jwt_claims",
            detail="JWT iat/exp claims are missing or exceed 600s lifetime.",
        )
    if now is not None:
        now_unix = int(now.astimezone(UTC).timestamp())
        if now_unix >= exp:
            raise CryptoVerificationError(
                code="jwt_expired",
                detail="RS256 JWT has expired.",
            )
    return dict(payload_obj)


# ---------------------------------------------------------------------------
# GitLab 19.0+/19.1 Standard Webhooks Signing & Legacy Token Auth (SRC-02)
# ---------------------------------------------------------------------------

_GITLAB_WHSEC_PREFIX = "whsec_"


def decode_gitlab_signing_key(secret: bytes | str) -> bytes:
    """Decode a GitLab 19.0+/19.1 `whsec_<base64>` signing token or raw secret bytes."""
    raw_text = secret.decode("utf-8", errors="strict") if isinstance(secret, bytes) else secret
    cleaned = raw_text.strip()
    if not cleaned:
        raise CryptoVerificationError(
            code="invalid_gitlab_signing_key",
            detail="GitLab webhook signing key must be non-empty.",
        )
    if cleaned.startswith(_GITLAB_WHSEC_PREFIX):
        b64_part = cleaned.removeprefix(_GITLAB_WHSEC_PREFIX)
        if not b64_part:
            raise CryptoVerificationError(
                code="invalid_gitlab_signing_key",
                detail="GitLab whsec_ signing key has an empty base64 payload.",
            )
        padding = "=" * ((4 - (len(b64_part) % 4)) % 4)
        try:
            decoded = base64.b64decode((b64_part + padding).encode("ascii"), validate=True)
        except Exception as exc:
            raise CryptoVerificationError(
                code="invalid_gitlab_signing_key",
                detail="GitLab whsec_ signing key is not valid Base64.",
            ) from exc
        if len(decoded) < 16:
            raise CryptoVerificationError(
                code="weak_gitlab_signing_key",
                detail="Decoded GitLab whsec_ signing key must be at least 16 bytes.",
            )
        return decoded
    raw_bytes = cleaned.encode("utf-8")
    if len(raw_bytes) < 16:
        raise CryptoVerificationError(
            code="weak_gitlab_signing_key",
            detail="GitLab webhook signing key must be at least 16 bytes.",
        )
    return raw_bytes


def sign_gitlab_webhook_v19(
    *,
    secret: bytes | str,
    webhook_id: str,
    timestamp_unix: int,
    raw_body: bytes,
) -> str:
    """Compute GitLab 19.0+/19.1 `webhook-signature` (`v1,<base64>`) over `{id}.{ts}.{body}`."""
    clean_id = webhook_id.strip()
    if not clean_id or "." in clean_id or any(ch in clean_id for ch in ("\r", "\n", "\x00")):
        raise CryptoVerificationError(
            code="invalid_webhook_id",
            detail="GitLab webhook-id header must be non-empty without '.' or control bytes.",
        )
    key_bytes = decode_gitlab_signing_key(secret)
    prefix = f"{clean_id}.{timestamp_unix}.".encode("ascii")
    mac = hmac.new(key_bytes, prefix + raw_body, hashlib.sha256).digest()
    return f"v1,{base64.b64encode(mac).decode('ascii')}"


def verify_gitlab_webhook_v19(
    *,
    secrets: Sequence[bytes | str],
    webhook_id: str | None,
    webhook_timestamp: str | None,
    webhook_signature: str | None,
    raw_body: bytes,
    now_unix: int,
    max_skew_seconds: int = 300,
) -> bool:
    """Constant-time verification of GitLab 19.0+/19.1 signed webhooks (`SEC-003`, `SEC-027`).

    Strictly validates `webhook-id`, `webhook-timestamp` (`<= 300s` replay window), and
    space-delimited `v1,<base64>` signatures against active + rotated signing keys.
    Never inspects or falls back to `X-Gitlab-Token`.
    """
    if not secrets or not webhook_id or not webhook_timestamp or not webhook_signature:
        return False
    clean_id = webhook_id.strip()
    if not clean_id or "." in clean_id or any(ch in clean_id for ch in ("\r", "\n", "\x00")):
        return False

    try:
        ts_int = int(webhook_timestamp.strip())
    except ValueError:
        return False
    if abs(now_unix - ts_int) > max_skew_seconds:
        return False

    candidate_sigs: list[bytes] = []
    for token in webhook_signature.strip().split():
        if token.startswith("v1,") and len(token) > 3:
            candidate_sigs.append(token.encode("ascii"))
    if not candidate_sigs:
        return False

    matched = False
    for raw_secret in secrets:
        try:
            expected_str = sign_gitlab_webhook_v19(
                secret=raw_secret,
                webhook_id=clean_id,
                timestamp_unix=ts_int,
                raw_body=raw_body,
            )
        except CryptoVerificationError:
            continue
        expected_bytes = expected_str.encode("ascii")
        for cand in candidate_sigs:
            if hmac.compare_digest(expected_bytes, cand):
                matched = True
    return matched


def verify_gitlab_legacy_token(
    *,
    secrets: Sequence[bytes | str],
    header_token: str | None,
) -> bool:
    """Constant-time verification of legacy GitLab `X-Gitlab-Token` over TLS (`SRC-02`)."""
    if not secrets or header_token is None:
        return False
    provided = header_token.encode("utf-8")
    if not provided:
        return False

    matched = False
    for raw_secret in secrets:
        secret_bytes = raw_secret if isinstance(raw_secret, bytes) else raw_secret.encode("utf-8")
        if secret_bytes and hmac.compare_digest(secret_bytes, provided):
            matched = True
    return matched


# ---------------------------------------------------------------------------
# Worker mTLS X.509 PKI & Scoped Upload Capability Tickets (SAN-01, A-13, S-21)
# ---------------------------------------------------------------------------

WORKER_SPIFFE_PREFIX = "spiffe://red2pr.internal/ns/workers/td/"
DOMAIN_UPLOAD_CAPABILITY_V1 = "red2pr.worker.upload_ticket.v1"
_SAFE_TRUST_DOMAIN_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
_UUID_LIKE_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


@dataclass(frozen=True, slots=True)
class VerifiedWorkerCertIdentity:
    """Cryptographically verified X.509 mTLS leaf certificate identity for a Z3 worker."""

    worker_id: str
    trust_domain: str
    serial_hex: str
    fingerprint_sha256: str
    not_valid_before: datetime
    not_valid_after: datetime


@dataclass(frozen=True, slots=True)
class VerifiedUploadCapability:
    """Verified write-only per-job artifact upload capability claims (`S-21`)."""

    job_id: str
    workspace_id: str
    repository_id: str
    lease_epoch: int
    capability_nonce: str
    allowed_slots: tuple[str, ...]
    max_output_bytes: int
    expires_at_unix: int


def build_worker_spiffe_uri(*, trust_domain: str, worker_id: str) -> str:
    """Build canonical SPIFFE URI binding `trust_domain` and `worker_id` in X.509 SAN."""
    td = trust_domain.strip()
    wid = worker_id.strip().lower()
    if not _SAFE_TRUST_DOMAIN_RE.fullmatch(td):
        raise ValueError(f"Invalid worker trust_domain for SPIFFE URI: {trust_domain!r}")
    if not _UUID_LIKE_RE.fullmatch(wid):
        raise ValueError(f"Invalid UUID worker_id for SPIFFE URI: {worker_id!r}")
    return f"{WORKER_SPIFFE_PREFIX}{td}/id/{wid}"


def parse_worker_spiffe_uri(uri: str) -> tuple[str, str]:
    """Parse `(trust_domain, worker_id)` from canonical worker SPIFFE URI."""
    cleaned = uri.strip()
    if not cleaned.startswith(WORKER_SPIFFE_PREFIX):
        raise CryptoVerificationError(
            code="invalid_worker_spiffe_uri",
            detail="X.509 SAN URI does not match canonical Red2PR worker SPIFFE namespace.",
        )
    rest = cleaned[len(WORKER_SPIFFE_PREFIX) :]
    parts = rest.split("/id/")
    if len(parts) != 2:
        raise CryptoVerificationError(
            code="invalid_worker_spiffe_uri",
            detail="X.509 SAN URI is missing '/id/' worker segment.",
        )
    td, wid = parts[0], parts[1].lower()
    if not _SAFE_TRUST_DOMAIN_RE.fullmatch(td) or not _UUID_LIKE_RE.fullmatch(wid):
        raise CryptoVerificationError(
            code="invalid_worker_spiffe_uri",
            detail="X.509 SAN URI contains malformed trust_domain or worker_id.",
        )
    return td, wid


def generate_worker_ca_keypair(
    *,
    common_name: str = "Red2PR Internal Worker Root CA",
    valid_days: int = 3650,
    now: datetime | None = None,
) -> tuple[str, str]:
    """Generate an internal ECDSA P-256 X.509 v3 Root CA for worker mTLS authentication."""
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Red2PR Self-Hosted Control Plane"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name[:64]),
        ]
    )
    ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ref_now - timedelta(minutes=5))
        .not_valid_after(ref_now + timedelta(days=max(1, valid_days)))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    cert_pem = cert.public_bytes(Encoding.PEM).decode("ascii")
    key_pem = ca_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption(),
    ).decode("ascii")
    return cert_pem, key_pem


def issue_worker_server_certificate(
    *,
    ca_cert_pem: str,
    ca_private_key_pem: str,
    hostnames: Sequence[str] = ("localhost",),
    ip_addresses: Sequence[str] = ("127.0.0.1",),
    valid_days: int = 365,
    now: datetime | None = None,
) -> tuple[str, str]:
    """Issue a TLS 1.3 server certificate signed by the Worker CA for internal mTLS ingress."""
    import ipaddress

    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("ascii"))
    ca_key = load_pem_private_key(ca_private_key_pem.encode("ascii"), password=None)
    if not isinstance(ca_key, ec.EllipticCurvePrivateKey):
        raise CryptoVerificationError(
            code="invalid_ca_private_key",
            detail="Worker CA private key must be an ECDSA private key.",
        )

    srv_key = ec.generate_private_key(ec.SECP256R1())
    san_entries: list[x509.GeneralName] = [x509.DNSName(h) for h in hostnames]
    for raw_ip in ip_addresses:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(raw_ip)))

    cn_value = (hostnames[0] if hostnames else "localhost")[:64]
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Red2PR Control Plane Internal mTLS"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn_value),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ref_now - timedelta(minutes=5))
        .not_valid_after(ref_now + timedelta(days=max(1, valid_days)))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=True,
        )
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(srv_key.public_key()),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    cert_pem = cert.public_bytes(Encoding.PEM).decode("ascii")
    key_pem = srv_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption(),
    ).decode("ascii")
    return cert_pem, key_pem


def generate_worker_csr(*, host_id: str, trust_domain: str) -> tuple[str, str]:
    """Generate a fresh ECDSA P-256 private key and PKCS#10 CSR for Z3 worker enrollment."""
    td = trust_domain.strip()
    hid = host_id.strip()
    if not _SAFE_TRUST_DOMAIN_RE.fullmatch(td) or not hid:
        raise ValueError("host_id and trust_domain must be non-empty safe identifiers.")
    priv_key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Red2PR Isolated Worker"),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, td[:64]),
                    x509.NameAttribute(NameOID.COMMON_NAME, hid[:64]),
                ]
            )
        )
        .sign(priv_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(Encoding.PEM).decode("ascii")
    key_pem = priv_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption(),
    ).decode("ascii")
    return csr_pem, key_pem


def issue_worker_client_certificate(
    *,
    ca_cert_pem: str,
    ca_private_key_pem: str,
    csr_pem: str,
    worker_id: str,
    trust_domain: str,
    valid_hours: int = 24 * 7,
    now: datetime | None = None,
) -> tuple[str, str, str, datetime]:
    """Validate worker PKCS#10 CSR and sign a short-lived mTLS client certificate (`A-13`)."""
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    except Exception as exc:
        raise CryptoVerificationError(
            code="malformed_worker_csr",
            detail="Failed to parse PEM PKCS#10 certificate signing request.",
        ) from exc

    if not csr.is_signature_valid:
        raise CryptoVerificationError(
            code="invalid_csr_signature",
            detail="PKCS#10 CSR proof-of-possession signature is invalid.",
        )

    pub_key = csr.public_key()
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        if pub_key.curve.name not in {"secp256r1", "secp384r1"}:
            raise CryptoVerificationError(
                code="unsupported_csr_key",
                detail="ECDSA CSR public key must use P-256 (secp256r1) or P-384 (secp384r1).",
            )
    elif isinstance(pub_key, RSAPublicKey):
        if pub_key.key_size < 2048:
            raise CryptoVerificationError(
                code="weak_csr_key",
                detail="RSA CSR public key must be at least 2048 bits.",
            )
    elif not isinstance(pub_key, Ed25519PublicKey):
        raise CryptoVerificationError(
            code="unsupported_csr_key",
            detail="CSR public key must be ECDSA P-256/P-384, Ed25519, or RSA >= 2048.",
        )

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("ascii"))
    ca_key = load_pem_private_key(ca_private_key_pem.encode("ascii"), password=None)
    if not isinstance(ca_key, ec.EllipticCurvePrivateKey):
        raise CryptoVerificationError(
            code="invalid_ca_private_key",
            detail="Worker CA private key must be an ECDSA private key.",
        )

    spiffe_uri = build_worker_spiffe_uri(trust_domain=trust_domain, worker_id=worker_id)
    not_before = ref_now - timedelta(minutes=2)
    not_after = ref_now + timedelta(hours=max(1, valid_hours))
    serial = x509.random_serial_number()

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Red2PR Isolated Worker"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, trust_domain.strip()[:64]),
            x509.NameAttribute(NameOID.COMMON_NAME, worker_id.strip().lower()[:64]),
        ]
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(pub_key)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=isinstance(pub_key, ec.EllipticCurvePublicKey),
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_uri)]),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(pub_key),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    leaf_pem = leaf.public_bytes(Encoding.PEM).decode("ascii")
    leaf_der = leaf.public_bytes(Encoding.DER)
    fingerprint_sha256 = hashlib.sha256(leaf_der).hexdigest()
    serial_hex = format(serial, "x")
    return leaf_pem, serial_hex, fingerprint_sha256, not_after


def verify_worker_client_certificate(
    *,
    cert_der_or_pem: bytes | str,
    ca_cert_pem: str,
    now: datetime | None = None,
) -> VerifiedWorkerCertIdentity:
    """Verify worker mTLS leaf certificate against Worker CA, validity window, EKU, and SAN."""
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    try:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("ascii"))
    except Exception as exc:
        raise CryptoVerificationError(
            code="invalid_worker_ca",
            detail="Failed to parse internal Worker CA certificate.",
        ) from exc

    try:
        if isinstance(cert_der_or_pem, str):
            leaf = x509.load_pem_x509_certificate(cert_der_or_pem.encode("ascii"))
        elif cert_der_or_pem.lstrip().startswith(b"-----BEGIN"):
            leaf = x509.load_pem_x509_certificate(cert_der_or_pem)
        else:
            leaf = x509.load_der_x509_certificate(cert_der_or_pem)
    except Exception as exc:
        raise CryptoVerificationError(
            code="malformed_client_certificate",
            detail="Failed to parse worker mTLS client certificate.",
        ) from exc

    try:
        leaf.verify_directly_issued_by(ca_cert)
    except Exception as exc:
        raise CryptoVerificationError(
            code="untrusted_client_certificate",
            detail="Worker client certificate was not issued by the active Red2PR Worker CA.",
        ) from exc

    try:
        bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise CryptoVerificationError(
            code="missing_basic_constraints",
            detail="Worker client certificate is missing BasicConstraints.",
        ) from exc
    if bc.ca:
        raise CryptoVerificationError(
            code="ca_certificate_forbidden_as_leaf",
            detail="CA certificate cannot authenticate as a worker leaf identity.",
        )

    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CryptoVerificationError(
            code="missing_client_auth_eku",
            detail="Worker client certificate is missing ExtendedKeyUsage.",
        ) from exc
    if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
        raise CryptoVerificationError(
            code="missing_client_auth_eku",
            detail="Worker client certificate does not carry id-kp-clientAuth EKU.",
        )

    not_before = leaf.not_valid_before_utc
    not_after = leaf.not_valid_after_utc
    if ref_now < not_before:
        raise CryptoVerificationError(
            code="client_certificate_not_yet_valid",
            detail="Worker client certificate is not yet valid.",
        )
    if ref_now >= not_after:
        raise CryptoVerificationError(
            code="client_certificate_expired",
            detail="Worker client certificate has expired.",
        )

    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise CryptoVerificationError(
            code="missing_worker_san",
            detail="Worker client certificate is missing SubjectAlternativeName.",
        ) from exc

    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1:
        raise CryptoVerificationError(
            code="invalid_worker_san",
            detail="Worker client certificate must carry exactly one SPIFFE URI SAN.",
        )
    trust_domain, worker_id = parse_worker_spiffe_uri(uris[0])
    leaf_der = leaf.public_bytes(Encoding.DER)
    return VerifiedWorkerCertIdentity(
        worker_id=worker_id,
        trust_domain=trust_domain,
        serial_hex=format(leaf.serial_number, "x"),
        fingerprint_sha256=hashlib.sha256(leaf_der).hexdigest(),
        not_valid_before=not_before,
        not_valid_after=not_after,
    )


def mint_upload_capability_ticket(
    *,
    signing_key: bytes,
    job_id: str,
    workspace_id: str,
    repository_id: str,
    lease_epoch: int,
    capability_nonce: str,
    allowed_slots: Sequence[str],
    max_output_bytes: int,
    expires_at: datetime,
) -> str:
    """Mint a short-lived HMAC-signed write-only per-job artifact upload ticket (`S-21`)."""
    if len(signing_key) < 32:
        raise ValueError("Upload capability signing_key must be at least 32 bytes.")
    slots = sorted({s.strip() for s in allowed_slots if s.strip()})
    if not slots:
        raise ValueError("allowed_slots must contain at least one artifact slot.")
    claims = {
        "v": 1,
        "job_id": job_id,
        "workspace_id": workspace_id,
        "repository_id": repository_id,
        "lease_epoch": int(lease_epoch),
        "nonce": capability_nonce,
        "slots": slots,
        "max_bytes": int(max_output_bytes),
        "exp": int(expires_at.astimezone(UTC).timestamp()),
    }
    body_bytes = canonical_json_bytes(claims)
    msg = DOMAIN_UPLOAD_CAPABILITY_V1.encode("ascii") + b"\x00" + body_bytes
    mac = hmac.new(signing_key, msg, hashlib.sha256).digest()
    return f"upltkt_v1.{_b64url_encode(body_bytes)}.{_b64url_encode(mac)}"


def verify_upload_capability_ticket(
    *,
    signing_key: bytes,
    ticket: str,
    expected_job_id: str,
    now: datetime | None = None,
) -> VerifiedUploadCapability:
    """Verify HMAC signature, job binding, and expiry of an `S-21` upload capability ticket."""
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    parts = ticket.strip().split(".")
    if len(parts) != 3 or parts[0] != "upltkt_v1":
        raise CryptoVerificationError(
            code="malformed_upload_capability",
            detail="Malformed S-21 artifact upload capability ticket.",
        )
    body_bytes = _b64url_decode(parts[1])
    sig_bytes = _b64url_decode(parts[2])
    expected_mac = hmac.new(
        signing_key,
        DOMAIN_UPLOAD_CAPABILITY_V1.encode("ascii") + b"\x00" + body_bytes,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(expected_mac, sig_bytes):
        raise CryptoVerificationError(
            code="invalid_upload_capability_signature",
            detail="Artifact upload capability signature verification failed.",
        )
    try:
        claims = json.loads(body_bytes.decode("utf-8"))
    except Exception as exc:
        raise CryptoVerificationError(
            code="malformed_upload_capability",
            detail="Upload capability payload is not valid UTF-8 JSON.",
        ) from exc
    if not isinstance(claims, dict) or claims.get("v") != 1:
        raise CryptoVerificationError(
            code="malformed_upload_capability",
            detail="Unsupported upload capability version.",
        )
    job_id = claims.get("job_id")
    workspace_id = claims.get("workspace_id")
    repository_id = claims.get("repository_id")
    lease_epoch = claims.get("lease_epoch")
    nonce = claims.get("nonce")
    slots = claims.get("slots")
    max_bytes = claims.get("max_bytes")
    exp = claims.get("exp")
    if (
        not isinstance(job_id, str)
        or not isinstance(workspace_id, str)
        or not isinstance(repository_id, str)
        or not isinstance(lease_epoch, int)
        or not isinstance(nonce, str)
        or not isinstance(slots, list)
        or not all(isinstance(s, str) and s for s in slots)
        or not isinstance(max_bytes, int)
        or not isinstance(exp, int)
    ):
        raise CryptoVerificationError(
            code="malformed_upload_capability",
            detail="Upload capability claims failed structural validation.",
        )
    if job_id != expected_job_id:
        raise CryptoVerificationError(
            code="upload_capability_job_mismatch",
            detail="Upload capability ticket is bound to a different job_id.",
        )
    if int(ref_now.timestamp()) >= exp:
        raise CryptoVerificationError(
            code="upload_capability_expired",
            detail="Artifact upload capability ticket has expired.",
        )
    return VerifiedUploadCapability(
        job_id=job_id,
        workspace_id=workspace_id,
        repository_id=repository_id,
        lease_epoch=lease_epoch,
        capability_nonce=nonce,
        allowed_slots=tuple(slots),
        max_output_bytes=max_bytes,
        expires_at_unix=exp,
    )
