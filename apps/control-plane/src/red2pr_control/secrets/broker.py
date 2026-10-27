"""Z2 Encrypted Secret Broker with external MasterKeyRing, AAD & capability isolation.

Implements docs/14_SECURITY_IDENTITY.md and docs/40_EXECUTION_MASTER_PLAN.md (U03, OPS-03):
- Master Key-Encryption-Keys (KEKs) are loaded strictly from an external file pointer
  (`RED2PR_MASTER_KEY_FILE`), never stored in PostgreSQL or YAML settings.
- Secrets are encrypted via versioned AES-256-GCM envelope encryption (`py_contracts.crypto`)
  with AAD bound to `(secret_ref, workspace_id, purpose)` preventing cross-tenant or
  cross-purpose ciphertext transplant attacks.
- Raw decrypted bytes are returned ONLY to callers holding an explicit Z2
  `SecretCallerCapability` permitting the entry's `purpose`; public/internal metadata
  DTOs (`SecretMetadata`) expose presence and key versions only.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast, get_args

from pydantic import StrictBool
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts.crypto import (
    EnvelopeCiphertext,
    MasterKeyRing,
    decrypt_envelope,
    encrypt_envelope,
)
from py_contracts.primitives import (
    BoundedName,
    InternalId,
    PositiveVersion,
    StrictContractModel,
    UtcTimestamp,
    new_uuid7,
)
from red2pr_control.core.errors import DependencyUnavailableError, ForbiddenError, NotFoundError
from red2pr_control.core.redaction import DEFAULT_REDACTOR, MIN_CANARY_LENGTH, Redactor
from red2pr_control.db.base import SecretEntryModel

SecretPurpose = Literal[
    "provider_read",
    "provider_write",
    "webhook_auth",
    "meta_inference",
    "notification_channel",
    "mfa_totp",
    "oidc_client",
    "storage_encryption",
]

ALL_SECRET_PURPOSES: frozenset[SecretPurpose] = frozenset(get_args(SecretPurpose))


@dataclass(frozen=True)
class SecretCallerCapability:
    """Internal Z2 capability token restricting which secret purposes a subsystem may unwrap."""

    caller_id: str
    allowed_purposes: frozenset[SecretPurpose]


INFERENCE_SECRET_CAPABILITY = SecretCallerCapability(
    caller_id="z2.inference",
    allowed_purposes=frozenset({"meta_inference"}),
)
PUBLISHER_SECRET_CAPABILITY = SecretCallerCapability(
    caller_id="z2.publisher",
    allowed_purposes=frozenset({"provider_write"}),
)
INTEGRATIONS_READ_SECRET_CAPABILITY = SecretCallerCapability(
    caller_id="z2.integrations_read",
    allowed_purposes=frozenset({"provider_read", "webhook_auth"}),
)
NOTIFICATIONS_SECRET_CAPABILITY = SecretCallerCapability(
    caller_id="z2.notifications",
    allowed_purposes=frozenset({"notification_channel"}),
)
IAM_SECRET_CAPABILITY = SecretCallerCapability(
    caller_id="z2.iam",
    allowed_purposes=frozenset({"mfa_totp", "oidc_client"}),
)
STORAGE_SECRET_CAPABILITY = SecretCallerCapability(
    caller_id="z2.storage",
    allowed_purposes=frozenset({"storage_encryption"}),
)
OPS_ROTATION_SECRET_CAPABILITY = SecretCallerCapability(
    caller_id="z2.ops_rotation",
    allowed_purposes=ALL_SECRET_PURPOSES,
)


class SecretMetadata(StrictContractModel):
    """Write-only safe metadata DTO for stored secrets (never contains raw secret bytes)."""

    id: InternalId
    secret_ref: BoundedName
    workspace_id: InternalId | None = None
    purpose: SecretPurpose
    active_key_version: PositiveVersion
    kek_version: PositiveVersion
    configured: StrictBool = True
    rotated_at: UtcTimestamp | None = None
    revoked_at: UtcTimestamp | None = None
    created_at: UtcTimestamp
    updated_at: UtcTimestamp


def _decode_32byte_key_material(raw: str | bytes) -> bytes:
    if isinstance(raw, bytes):
        if len(raw) == 32:
            return raw
        text_val = raw.decode("ascii", errors="strict").strip()
    else:
        text_val = raw.strip()

    if len(text_val) == 64:
        try:
            decoded_hex = bytes.fromhex(text_val)
            if len(decoded_hex) == 32:
                return decoded_hex
        except ValueError:
            pass

    try:
        padded = text_val + "=" * ((4 - (len(text_val) % 4)) % 4)
        decoded_b64 = base64.b64decode(padded.encode("ascii"), validate=False)
        if len(decoded_b64) == 32:
            return decoded_b64
    except (ValueError, binascii.Error):
        pass

    raise ValueError("Master key material must decode to exactly 32 bytes (256 bits)")


def load_master_key_ring_from_file(
    path: Path | str | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> MasterKeyRing:
    """Load versioned 256-bit MasterKeyRing from external file or RED2PR_MASTER_KEY_FILE."""
    effective_env = env if env is not None else os.environ
    resolved_target = (
        Path(path)
        if path is not None
        else (
            Path(effective_env["RED2PR_MASTER_KEY_FILE"])
            if effective_env.get("RED2PR_MASTER_KEY_FILE")
            else None
        )
    )
    if resolved_target is None or not resolved_target.is_file():
        raise DependencyUnavailableError(
            code="master_key_unavailable",
            detail=(
                "External master encryption key file is missing or unconfigured; "
                "cannot unwrap or seal secrets."
            ),
        )

    try:
        raw_bytes = resolved_target.read_bytes()
    except OSError as exc:
        raise DependencyUnavailableError(
            code="master_key_unavailable",
            detail="External master encryption key file could not be read.",
        ) from exc

    if len(raw_bytes) == 32:
        return MasterKeyRing(active_version=1, keys={1: raw_bytes})

    try:
        text_content = raw_bytes.decode("utf-8").strip()
        if text_content.startswith("{"):
            parsed = json.loads(text_content)
            active_ver = int(parsed["active_version"])
            raw_keys = parsed["keys"]
            if not isinstance(raw_keys, Mapping) or not raw_keys:
                raise ValueError("Empty keys mapping")
            keys_map = {
                int(ver_str): _decode_32byte_key_material(str(mat))
                for ver_str, mat in raw_keys.items()
            }
            return MasterKeyRing(active_version=active_ver, keys=keys_map)
        single_key = _decode_32byte_key_material(text_content)
        return MasterKeyRing(active_version=1, keys={1: single_key})
    except Exception as exc:
        raise DependencyUnavailableError(
            code="master_key_unavailable",
            detail="External master encryption key file has invalid format or key length.",
        ) from exc


def _build_aad_context(
    *,
    secret_ref: str,
    workspace_id: str | None,
    purpose: str,
) -> dict[str, Any]:
    return {
        "secret_ref": secret_ref,
        "workspace_id": workspace_id,
        "purpose": purpose,
    }


def _row_to_metadata(row: SecretEntryModel) -> SecretMetadata:
    return SecretMetadata(
        id=row.id,
        secret_ref=row.secret_ref,
        workspace_id=row.workspace_id,
        purpose=cast(SecretPurpose, row.purpose),
        active_key_version=row.active_key_version,
        kek_version=row.kek_version,
        configured=row.revoked_at is None,
        rotated_at=row.rotated_at,
        revoked_at=row.revoked_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


class SecretBroker:
    """Z2 envelope-encrypted secret store enforcing purpose capabilities & canary scrubbing."""

    def __init__(
        self,
        *,
        key_ring: MasterKeyRing,
        redactor: Redactor | None = None,
    ) -> None:
        self._key_ring = key_ring
        self._redactor = redactor if redactor is not None else DEFAULT_REDACTOR

    def _register_canary_if_textual(self, secret_bytes: bytes) -> None:
        try:
            as_text = secret_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return
        if len(as_text) >= MIN_CANARY_LENGTH:
            self._redactor.register_canary(as_text)

    async def store_secret(
        self,
        session: AsyncSession,
        *,
        plaintext: bytes,
        purpose: SecretPurpose,
        workspace_id: str | None = None,
        secret_ref: str | None = None,
        now: datetime | None = None,
    ) -> SecretMetadata:
        """Encrypt and persist a secret entry, returning safe metadata only."""
        if not plaintext:
            raise ValueError("Secret plaintext must be non-empty bytes")
        if purpose not in ALL_SECRET_PURPOSES:
            raise ValueError(f"Unsupported secret purpose: {purpose!r}")

        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        assigned_ref = secret_ref or f"sec_{secrets.token_urlsafe(18)}"
        aad_ctx = _build_aad_context(
            secret_ref=assigned_ref,
            workspace_id=workspace_id,
            purpose=purpose,
        )
        envelope = encrypt_envelope(
            plaintext,
            key_ring=self._key_ring,
            aad_context=aad_ctx,
        )
        self._register_canary_if_textual(plaintext)

        entry = SecretEntryModel(
            id=new_uuid7(now=ref_now),
            secret_ref=assigned_ref,
            workspace_id=workspace_id,
            purpose=purpose,
            active_key_version=1,
            kek_version=envelope.kek_version,
            envelope_json=envelope.model_dump(mode="json"),
            previous_envelope_json=None,
            aad_digest=envelope.aad_digest,
            rotated_at=None,
            revoked_at=None,
            version=1,
            created_at=ref_now,
            updated_at=ref_now,
        )
        session.add(entry)
        await session.flush()
        return _row_to_metadata(entry)

    async def resolve_secret_bytes(
        self,
        session: AsyncSession,
        *,
        secret_ref: str,
        capability: SecretCallerCapability,
        workspace_id: str | None = None,
    ) -> bytes:
        """Unwrap and return raw secret bytes strictly to authorized Z2 capability callers."""
        scope_clause = (
            SecretEntryModel.workspace_id == workspace_id
            if workspace_id is not None
            else SecretEntryModel.workspace_id.is_(None)
        )
        row = await session.scalar(
            select(SecretEntryModel).where(
                SecretEntryModel.secret_ref == secret_ref,
                scope_clause,
            )
        )
        if row is None:
            raise NotFoundError(
                code="secret_not_found",
                detail="Referenced secret was not found in the active scope.",
            )
        if row.revoked_at is not None:
            raise ForbiddenError(
                code="secret_revoked",
                detail="Referenced secret has been revoked and cannot be unwrapped.",
            )
        entry_purpose = cast(SecretPurpose, row.purpose)
        if entry_purpose not in capability.allowed_purposes:
            raise ForbiddenError(
                code="secret_purpose_denied",
                detail=(
                    f"Caller {capability.caller_id!r} is not permitted to unwrap "
                    f"secrets of purpose {row.purpose!r}."
                ),
            )

        envelope = EnvelopeCiphertext.model_validate(row.envelope_json)
        aad_ctx = _build_aad_context(
            secret_ref=row.secret_ref,
            workspace_id=row.workspace_id,
            purpose=row.purpose,
        )
        plaintext = decrypt_envelope(
            envelope,
            key_ring=self._key_ring,
            aad_context=aad_ctx,
        )
        self._register_canary_if_textual(plaintext)
        return plaintext

    async def rotate_secret_kek(
        self,
        session: AsyncSession,
        *,
        secret_ref: str,
        capability: SecretCallerCapability,
        new_key_ring: MasterKeyRing,
        workspace_id: str | None = None,
        now: datetime | None = None,
    ) -> SecretMetadata:
        """Re-encrypt an existing secret entry under `new_key_ring.active_version` (OPS-03)."""
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        scope_clause = (
            SecretEntryModel.workspace_id == workspace_id
            if workspace_id is not None
            else SecretEntryModel.workspace_id.is_(None)
        )
        row = await session.scalar(
            select(SecretEntryModel)
            .where(SecretEntryModel.secret_ref == secret_ref, scope_clause)
            .with_for_update()
        )
        if row is None:
            raise NotFoundError(
                code="secret_not_found",
                detail="Referenced secret was not found in the active scope.",
            )
        if row.revoked_at is not None:
            raise ForbiddenError(
                code="secret_revoked",
                detail="Revoked secrets cannot be rotated.",
            )
        entry_purpose = cast(SecretPurpose, row.purpose)
        if entry_purpose not in capability.allowed_purposes:
            raise ForbiddenError(
                code="secret_purpose_denied",
                detail=(
                    f"Caller {capability.caller_id!r} is not permitted to rotate "
                    f"secrets of purpose {row.purpose!r}."
                ),
            )

        aad_ctx = _build_aad_context(
            secret_ref=row.secret_ref,
            workspace_id=row.workspace_id,
            purpose=row.purpose,
        )
        old_envelope = EnvelopeCiphertext.model_validate(row.envelope_json)
        plaintext = decrypt_envelope(
            old_envelope,
            key_ring=new_key_ring,
            aad_context=aad_ctx,
        )
        new_envelope = encrypt_envelope(
            plaintext,
            key_ring=new_key_ring,
            aad_context=aad_ctx,
        )

        row.previous_envelope_json = dict(row.envelope_json)
        row.envelope_json = new_envelope.model_dump(mode="json")
        row.kek_version = new_envelope.kek_version
        row.aad_digest = new_envelope.aad_digest
        row.rotated_at = ref_now
        row.updated_at = ref_now
        row.version += 1
        self._key_ring = new_key_ring
        await session.flush()
        return _row_to_metadata(row)

    async def revoke_secret(
        self,
        session: AsyncSession,
        *,
        secret_ref: str,
        workspace_id: str | None = None,
        now: datetime | None = None,
    ) -> SecretMetadata:
        """Immediately revoke a secret entry so subsequent resolution attempts fail."""
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        scope_clause = (
            SecretEntryModel.workspace_id == workspace_id
            if workspace_id is not None
            else SecretEntryModel.workspace_id.is_(None)
        )
        row = await session.scalar(
            select(SecretEntryModel)
            .where(SecretEntryModel.secret_ref == secret_ref, scope_clause)
            .with_for_update()
        )
        if row is None:
            raise NotFoundError(
                code="secret_not_found",
                detail="Referenced secret was not found in the active scope.",
            )
        if row.revoked_at is None:
            row.revoked_at = ref_now
            row.updated_at = ref_now
            row.version += 1
            await session.flush()
        return _row_to_metadata(row)


class SecretBrokerTotpVault:
    """Z2 capability-scoped adapter storing & unwrapping RFC 6238 TOTP keys (`mfa_totp`)."""

    def __init__(self, broker: SecretBroker) -> None:
        self._broker = broker

    async def store_totp_secret(
        self,
        session: AsyncSession,
        *,
        plaintext: bytes,
        now: datetime | None = None,
    ) -> str:
        meta = await self._broker.store_secret(
            session,
            plaintext=plaintext,
            purpose="mfa_totp",
            workspace_id=None,
            now=now,
        )
        return meta.secret_ref

    async def resolve_totp_secret(
        self,
        session: AsyncSession,
        *,
        secret_ref: str,
    ) -> bytes:
        return await self._broker.resolve_secret_bytes(
            session,
            secret_ref=secret_ref,
            capability=IAM_SECRET_CAPABILITY,
            workspace_id=None,
        )

    async def revoke_totp_secret(
        self,
        session: AsyncSession,
        *,
        secret_ref: str,
        now: datetime | None = None,
    ) -> None:
        await self._broker.revoke_secret(
            session,
            secret_ref=secret_ref,
            workspace_id=None,
            now=now,
        )
