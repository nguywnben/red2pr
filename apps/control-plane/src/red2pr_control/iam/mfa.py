"""RFC 6238 TOTP MFA enrollment/verification & single-use recovery codes (SEC-026, SEC-038).

Implements docs/14_SECURITY_IDENTITY.md, ADR-034, A-02, A-03:
- RFC 6238 TOTP (`SHA-1`, 6 digits, 30-second time step, `[-1, 0, +1]` clock-skew tolerance)
  backed by `cryptography.hazmat.primitives.twofactor.totp.TOTP`.
- Strict monotonic `last_used_timestep` enforcement so a 6-digit TOTP code can NEVER be
  replayed within its acceptance window.
- Narrow `TotpSecretVaultProtocol` boundary so `red2pr_control.iam` never holds raw Z2
  encryption keys; TOTP secrets live encrypted in Z2 `SecretBroker` (`purpose='mfa_totp'`).
- 10 single-use recovery codes (`R2PR-XXXX-XXXX-XXXX`, ~80 bits entropy each) stored
  strictly as HMAC-SHA256 digests (`SEC-038`).
"""

from __future__ import annotations

import base64
import hmac
import secrets
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import quote

from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts.crypto import compute_hmac_sha256_hex

TOTP_DIGITS: int = 6
TOTP_TIME_STEP_SECONDS: int = 30
TOTP_KEY_BYTES: int = 20  # 160-bit RFC 6238 SHA-1 secret
TOTP_SKEW_STEPS: tuple[int, ...] = (-1, 0, 1)
RECOVERY_CODE_BATCH_SIZE: int = 10
_RECOVERY_ALPHABET: str = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class TotpSecretVaultProtocol(Protocol):
    """Port interface for Z2 encrypted storage of TOTP shared secrets (`mfa_totp`)."""

    async def store_totp_secret(
        self,
        session: AsyncSession,
        *,
        plaintext: bytes,
        now: datetime | None = None,
    ) -> str: ...

    async def resolve_totp_secret(
        self,
        session: AsyncSession,
        *,
        secret_ref: str,
    ) -> bytes: ...

    async def revoke_totp_secret(
        self,
        session: AsyncSession,
        *,
        secret_ref: str,
        now: datetime | None = None,
    ) -> None: ...


def derive_iam_subkey(seed_key: bytes, *, context: bytes) -> bytes:
    """Derive a domain-separated 256-bit HMAC key via HKDF-SHA256."""
    if len(seed_key) < 32:
        raise ValueError("IAM seed key material must be at least 32 bytes")
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=b"red2pr-iam-hkdf-salt-v1",
        info=context,
    )
    return hkdf.derive(seed_key)


def generate_totp_secret() -> tuple[bytes, str]:
    """Generate a 160-bit random TOTP key and its unpadded uppercase RFC 4648 Base32 form."""
    raw_secret = secrets.token_bytes(TOTP_KEY_BYTES)
    secret_b32 = base64.b32encode(raw_secret).decode("ascii").rstrip("=")
    return raw_secret, secret_b32


def build_otpauth_uri(
    *,
    secret_base32: str,
    account_label: str,
    issuer: str = "Red2PR",
) -> str:
    """Build standard RFC 6238 / KeyUriFormat `otpauth://totp/...` provisioning URI."""
    safe_issuer = issuer.strip() or "Red2PR"
    safe_account = account_label.strip() or "user"
    label = quote(f"{safe_issuer}:{safe_account}", safe=":@._-")
    issuer_param = quote(safe_issuer, safe="")
    return (
        f"otpauth://totp/{label}"
        f"?secret={secret_base32}&issuer={issuer_param}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_TIME_STEP_SECONDS}"
    )


def generate_totp_code_at(raw_secret: bytes, *, at_time: datetime) -> str:
    """Generate the 6-digit RFC 6238 TOTP code at `at_time` (used by verifier & tests)."""
    totp = TOTP(
        raw_secret,
        TOTP_DIGITS,
        SHA1(),  # noqa: S303 - RFC 6238 standard HMAC-SHA1 TOTP PRF
        TOTP_TIME_STEP_SECONDS,
        enforce_key_length=True,
    )
    unix_ts = int(at_time.astimezone(UTC).timestamp())
    return totp.generate(unix_ts).decode("ascii")


def verify_totp_code(
    raw_secret: bytes,
    *,
    otp: str,
    at_time: datetime,
    last_used_timestep: int | None,
) -> tuple[bool, int | None, bool]:
    """Verify a 6-digit TOTP code with `[-1, 0, +1]` skew and monotonic replay rejection.

    Returns `(accepted, matched_timestep, was_replayed)`.
    """
    cleaned = otp.strip()
    if len(cleaned) != TOTP_DIGITS or not cleaned.isdigit():
        return False, None, False

    totp = TOTP(
        raw_secret,
        TOTP_DIGITS,
        SHA1(),  # noqa: S303 - RFC 6238 standard HMAC-SHA1 TOTP PRF
        TOTP_TIME_STEP_SECONDS,
        enforce_key_length=True,
    )
    base_step = int(at_time.astimezone(UTC).timestamp()) // TOTP_TIME_STEP_SECONDS
    candidate_bytes = cleaned.encode("ascii")

    matched_step: int | None = None
    for delta in TOTP_SKEW_STEPS:
        step = base_step + delta
        if step < 0:
            continue
        expected = totp.generate(step * TOTP_TIME_STEP_SECONDS)
        if hmac.compare_digest(expected, candidate_bytes):
            matched_step = step
            break

    if matched_step is None:
        return False, None, False

    if last_used_timestep is not None and matched_step <= last_used_timestep:
        return False, matched_step, True

    return True, matched_step, False


def normalize_recovery_code(raw_code: str) -> str:
    """Normalize a user-entered single-use recovery code for constant-time HMAC lookup."""
    compact = "".join(ch for ch in raw_code.strip().upper() if ch.isalnum())
    if compact.startswith("R2PR"):
        compact = compact[4:]
    return compact


def hash_recovery_code(hmac_key: bytes, raw_code: str) -> str:
    """Compute HMAC-SHA256 hex digest of a normalized recovery code."""
    normalized = normalize_recovery_code(raw_code)
    if len(normalized) < 8:
        # Hash deterministic invalid domain string so caller still runs constant-time path
        return compute_hmac_sha256_hex(hmac_key, b"red2pr:recovery:invalid")
    return compute_hmac_sha256_hex(
        hmac_key,
        f"red2pr:recovery:v1:{normalized}".encode("ascii"),
    )


def generate_recovery_code_batch(
    hmac_key: bytes,
    *,
    count: int = RECOVERY_CODE_BATCH_SIZE,
) -> list[tuple[str, str]]:
    """Generate `count` unique single-use recovery codes returning `(display_code, code_hash)`."""
    seen_hashes: set[str] = set()
    results: list[tuple[str, str]] = []
    while len(results) < count:
        groups = [
            "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(4)) for _ in range(4)
        ]
        display = f"R2PR-{'-'.join(groups)}"
        digest = hash_recovery_code(hmac_key, display)
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)
        results.append((display, digest))
    return results
