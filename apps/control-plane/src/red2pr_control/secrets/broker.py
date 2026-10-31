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
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts.crypto import (
    EnvelopeCiphertext,
    MasterKeyRing,
    decrypt_envelope,
    encrypt_envelope,
)
from py_contracts.integrations import ConnectionAuthMode
from py_contracts.primitives import (
    BoundedName,
    InternalId,
    PositiveVersion,
    StrictContractModel,
    UtcTimestamp,
    new_uuid7,
)
from py_contracts.secrets import SecretKeyRotationResult
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    NotFoundError,
)
from red2pr_control.core.redaction import DEFAULT_REDACTOR, MIN_CANARY_LENGTH, Redactor
from red2pr_control.db.base import SecretEntryModel, SecretKeyringStateModel, WorkspaceModel
from red2pr_control.db.rls import instance_rls_session
from red2pr_control.secrets.rotation import RotationDrain

_KEY_ROTATION_LOCK = "red2pr:secret-keyring-rotation:v1"

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
        self.rotation_drain = RotationDrain()

    def _refresh_key_ring(self) -> None:
        """Reload the shared external key file so every process observes rotations."""
        key_path = os.environ.get("RED2PR_MASTER_KEY_FILE")
        if key_path:
            self._key_ring = load_master_key_ring_from_file(key_path)

    async def _acquire_keyring_read_lock(self, session: AsyncSession) -> int:
        await session.execute(
            text("SELECT pg_advisory_xact_lock_shared(hashtextextended(:key, 0))"),
            {"key": _KEY_ROTATION_LOCK},
        )
        state = await session.get(SecretKeyringStateModel, "global")
        if state is None:
            raise DependencyUnavailableError(
                code="secret_keyring_state_missing",
                detail="The global secret key rotation state is not initialized.",
            )
        if self._key_ring.get(state.active_kek_version) is None:
            raise DependencyUnavailableError(
                code="master_key_rotation_reload_required",
                detail=(
                    "This process must reload the active external key ring before secret access."
                ),
            )
        return state.active_kek_version

    async def rotate_all_secret_keks(
        self,
        *,
        session_factory: Any,
        actor_id: str,
        correlation_id: str,
        now: datetime | None = None,
    ) -> SecretKeyRotationResult:
        """Atomically re-encrypt all entries while every process's broker leases drain."""
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        async with self.rotation_drain.rotation():
            self._refresh_key_ring()
            async with instance_rls_session(session_factory, mode="instance_admin") as db:
                await db.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                    {"key": _KEY_ROTATION_LOCK},
                )
                state = await db.scalar(
                    select(SecretKeyringStateModel)
                    .where(SecretKeyringStateModel.singleton_id == "global")
                    .with_for_update()
                )
                if state is None:
                    raise DependencyUnavailableError(
                        code="secret_keyring_state_missing",
                        detail="The global secret key rotation state is not initialized.",
                    )
                target_version = self._key_ring.active_version
                if target_version < state.active_kek_version:
                    raise ConflictError(
                        code="master_key_version_regression",
                        detail="The configured active master key version cannot move backwards.",
                    )
                workspace_ids = list(
                    await db.scalars(select(WorkspaceModel.id).order_by(WorkspaceModel.id))
                )
                rotated = 0
                for workspace_id in workspace_ids:
                    await db.execute(
                        text(
                            "SELECT set_config('red2pr.scope_mode', 'workspace', true), "
                            "set_config('red2pr.workspace_id', :workspace_id, true)"
                        ),
                        {"workspace_id": workspace_id},
                    )
                    rows = list(
                        (
                            await db.scalars(
                                select(SecretEntryModel)
                                .where(SecretEntryModel.workspace_id == workspace_id)
                                .order_by(SecretEntryModel.id)
                                .with_for_update()
                            )
                        ).all()
                    )
                    rotated += self._reencrypt_secret_rows(
                        rows, target_version=target_version, now=ref_now
                    )
                    await db.flush()
                await db.execute(
                    text(
                        "SELECT set_config('red2pr.scope_mode', 'instance_admin', true), "
                        "set_config('red2pr.workspace_id', '', true)"
                    )
                )
                instance_rows = list(
                    (
                        await db.scalars(
                            select(SecretEntryModel)
                            .where(SecretEntryModel.workspace_id.is_(None))
                            .order_by(SecretEntryModel.id)
                            .with_for_update()
                        )
                    ).all()
                )
                rotated += self._reencrypt_secret_rows(
                    instance_rows, target_version=target_version, now=ref_now
                )
                await db.flush()
                state.active_kek_version = target_version
                state.version += 1
                state.updated_at = ref_now
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=actor_id,
                    action="security.secret_keyring.rotated",
                    target="instance:secret-keyring",
                    decision="allow",
                    reason_code="all_secret_entries_reencrypted",
                    correlation_id=correlation_id,
                    metadata={
                        "rotated_count": rotated,
                        "active_kek_version": target_version,
                    },
                    occurred_at=ref_now,
                )
            return SecretKeyRotationResult(
                active_kek_version=target_version,
                rotated_count=rotated,
                completed_at=ref_now,
            )

    def _register_canary_if_textual(self, secret_bytes: bytes) -> None:
        try:
            as_text = secret_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return
        if len(as_text) >= MIN_CANARY_LENGTH:
            self._redactor.register_canary(as_text)

    def _reencrypt_secret_rows(
        self, rows: list[SecretEntryModel], *, target_version: int, now: datetime
    ) -> int:
        rotated = 0
        for row in rows:
            aad_ctx = _build_aad_context(
                secret_ref=row.secret_ref,
                workspace_id=row.workspace_id,
                purpose=row.purpose,
            )
            old_envelope = EnvelopeCiphertext.model_validate(row.envelope_json)
            plaintext = decrypt_envelope(old_envelope, key_ring=self._key_ring, aad_context=aad_ctx)
            if row.kek_version != target_version:
                envelope = encrypt_envelope(plaintext, key_ring=self._key_ring, aad_context=aad_ctx)
                row.envelope_json = envelope.model_dump(mode="json")
                row.kek_version = envelope.kek_version
                row.aad_digest = envelope.aad_digest
                row.rotated_at = now
                row.updated_at = now
                row.version += 1
                rotated += 1
            row.previous_envelope_json = None
            self._register_canary_if_textual(plaintext)
        return rotated

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
        async with self.rotation_drain.operation():
            self._refresh_key_ring()
            return await self._store_secret_unlocked(
                session,
                plaintext=plaintext,
                purpose=purpose,
                workspace_id=workspace_id,
                secret_ref=secret_ref,
                now=now,
            )

    async def _store_secret_unlocked(
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

        active_version = await self._acquire_keyring_read_lock(session)
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        assigned_ref = secret_ref or f"sec_{secrets.token_urlsafe(18)}"
        aad_ctx = _build_aad_context(
            secret_ref=assigned_ref,
            workspace_id=workspace_id,
            purpose=purpose,
        )
        envelope = encrypt_envelope(
            plaintext,
            key_ring=MasterKeyRing(
                active_version=active_version,
                keys={active_version: self._key_ring.get(active_version) or b""},
            ),
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
        async with self.rotation_drain.operation():
            self._refresh_key_ring()
            return await self._resolve_secret_bytes_unlocked(
                session,
                secret_ref=secret_ref,
                capability=capability,
                workspace_id=workspace_id,
            )

    async def _resolve_secret_bytes_unlocked(
        self,
        session: AsyncSession,
        *,
        secret_ref: str,
        capability: SecretCallerCapability,
        workspace_id: str | None = None,
    ) -> bytes:
        """Unwrap and return raw secret bytes strictly to authorized Z2 capability callers."""
        await self._acquire_keyring_read_lock(session)
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
        async with self.rotation_drain.rotation():
            return await self._rotate_secret_kek_unlocked(
                session,
                secret_ref=secret_ref,
                capability=capability,
                new_key_ring=new_key_ring,
                workspace_id=workspace_id,
                now=now,
            )

    async def _rotate_secret_kek_unlocked(
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
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": _KEY_ROTATION_LOCK},
        )
        state = await session.get(SecretKeyringStateModel, "global")
        if state is None or new_key_ring.active_version != state.active_kek_version:
            raise ConflictError(
                code="global_key_rotation_required",
                detail="KEK version changes must use the audited all-secret rotation operation.",
            )
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
        self._refresh_key_ring()
        await self._acquire_keyring_read_lock(session)
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


class SecretBrokerProviderVault:
    """Z2 capability-scoped provider vault for GitHub/GitLab credentials & encrypted JIT tokens.

    Enforces `Z1`/`Z2` least privilege (`U09`, `SRC-01`, `SEC-011`, `SEC-017`):
    - Raw RSA private key PEMs and webhook secrets never cross from `Z2` into `Z1` adapters.
    - RS256 GitHub App JWTs and webhook HMAC verifications execute strictly inside `Z2`.
    - Short-lived JIT scoped installation tokens are cached envelope-encrypted in broker memory
      with AAD bound to `(workspace_id, connection_id, installation_id, scope_key)` and
      honoring `expires_at` minus a 60-second safety margin.
    """

    _JIT_EXPIRY_SAFETY_MARGIN_SECONDS = 60

    def __init__(self, broker: SecretBroker) -> None:
        import threading

        self._broker = broker
        self._lock = threading.RLock()
        self._jit_cache: dict[tuple[str, str, str, str], tuple[EnvelopeCiphertext, datetime]] = {}

    async def store_provider_credential(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        plaintext: bytes,
        purpose: Literal["provider_read", "webhook_auth"],
        require_rsa_pem: bool = False,
        now: datetime | None = None,
    ) -> tuple[str, int]:
        if require_rsa_pem:
            from py_contracts.crypto import CryptoVerificationError, validate_rsa_private_key_pem
            from red2pr_control.core.errors import UnprocessableEntityError

            try:
                validate_rsa_private_key_pem(plaintext)
            except CryptoVerificationError as exc:
                raise UnprocessableEntityError(
                    code=exc.code,
                    detail=exc.detail,
                ) from exc

        meta = await self._broker.store_secret(
            session,
            plaintext=plaintext,
            purpose=purpose,
            workspace_id=workspace_id,
            now=now,
        )
        return (meta.secret_ref, meta.active_key_version)

    async def inspect_secret_presence(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        secret_ref: str,
        expected_purpose: Literal["provider_read", "webhook_auth"],
    ) -> tuple[bool, int | None]:
        row = await session.scalar(
            select(SecretEntryModel).where(
                SecretEntryModel.secret_ref == secret_ref,
                SecretEntryModel.workspace_id == workspace_id,
            )
        )
        if row is None:
            raise NotFoundError(
                code="secret_not_found",
                detail="Referenced secret was not found in this workspace.",
            )
        if row.revoked_at is not None:
            raise ForbiddenError(
                code="secret_revoked",
                detail="Referenced secret has been revoked.",
            )
        if row.purpose != expected_purpose:
            raise ForbiddenError(
                code="secret_purpose_denied",
                detail=f"Referenced secret does not have purpose '{expected_purpose}'.",
            )
        return (True, int(row.active_key_version))

    async def revoke_provider_credential(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        secret_ref: str,
        connection_id: str | None = None,
        now: datetime | None = None,
    ) -> None:
        self.invalidate_cached_tokens(workspace_id=workspace_id, connection_id=connection_id)
        try:
            await self._broker.revoke_secret(
                session,
                secret_ref=secret_ref,
                workspace_id=workspace_id,
                now=now,
            )
        except NotFoundError:
            return

    async def mint_github_app_jwt(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        secret_ref: str,
        issuer: str,
        now: datetime,
    ) -> str:
        from py_contracts.crypto import CryptoVerificationError, sign_github_app_jwt_rs256
        from red2pr_control.core.errors import UnprocessableEntityError

        pem_bytes = await self._broker.resolve_secret_bytes(
            session,
            secret_ref=secret_ref,
            capability=INTEGRATIONS_READ_SECRET_CAPABILITY,
            workspace_id=workspace_id,
        )
        try:
            jwt_token = sign_github_app_jwt_rs256(
                private_key_pem=pem_bytes,
                issuer=issuer,
                now=now,
            )
        except CryptoVerificationError as exc:
            raise UnprocessableEntityError(code=exc.code, detail=exc.detail) from exc
        self._broker._redactor.register_canary(jwt_token)
        return jwt_token

    async def verify_webhook_hmac(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        secret_ref: str,
        raw_body: bytes,
        signature_header: str,
    ) -> bool:
        from py_contracts.crypto import verify_hmac_sha256_hex

        row = await session.scalar(
            select(SecretEntryModel).where(
                SecretEntryModel.secret_ref == secret_ref,
                SecretEntryModel.workspace_id == workspace_id,
            )
        )
        if row is None or row.revoked_at is not None or row.purpose != "webhook_auth":
            verify_hmac_sha256_hex(
                b"__red2pr_dummy_webhook_hmac_secret__",
                raw_body,
                signature_header,
            )
            return False

        aad_ctx = _build_aad_context(
            secret_ref=row.secret_ref,
            workspace_id=row.workspace_id,
            purpose=row.purpose,
        )
        enrolled_secrets: list[bytes] = []
        active_env = EnvelopeCiphertext.model_validate(row.envelope_json)
        active_plain = decrypt_envelope(
            active_env,
            key_ring=self._broker._key_ring,
            aad_context=aad_ctx,
        )
        self._broker._register_canary_if_textual(active_plain)
        enrolled_secrets.append(active_plain)

        if row.previous_envelope_json is not None:
            try:
                prev_env = EnvelopeCiphertext.model_validate(row.previous_envelope_json)
                prev_plain = decrypt_envelope(
                    prev_env,
                    key_ring=self._broker._key_ring,
                    aad_context=aad_ctx,
                )
            except (ValueError, KeyError):
                prev_plain = b""
            if prev_plain:
                self._broker._register_canary_if_textual(prev_plain)
                enrolled_secrets.append(prev_plain)

        matched = False
        for secret_bytes in enrolled_secrets:
            sig_ok = verify_hmac_sha256_hex(secret_bytes, raw_body, signature_header)
            matched = sig_ok or matched
        return matched

    async def rotate_provider_credential(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        secret_ref: str,
        new_plaintext: bytes,
        purpose: Literal["provider_read", "webhook_auth"],
        retain_previous_for_overlap: bool = False,
        now: datetime | None = None,
    ) -> tuple[str, int]:
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        self.invalidate_cached_tokens(workspace_id=workspace_id)
        row = await session.scalar(
            select(SecretEntryModel)
            .where(
                SecretEntryModel.secret_ref == secret_ref,
                SecretEntryModel.workspace_id == workspace_id,
            )
            .with_for_update()
        )
        if row is None or row.revoked_at is not None or row.purpose != purpose:
            return await self.store_provider_credential(
                session,
                workspace_id=workspace_id,
                plaintext=new_plaintext,
                purpose=purpose,
                require_rsa_pem=False,
                now=ref_now,
            )

        aad_ctx = _build_aad_context(
            secret_ref=row.secret_ref,
            workspace_id=row.workspace_id,
            purpose=row.purpose,
        )
        new_envelope = encrypt_envelope(
            new_plaintext,
            key_ring=self._broker._key_ring,
            aad_context=aad_ctx,
        )
        self._broker._register_canary_if_textual(new_plaintext)
        row.previous_envelope_json = (
            dict(row.envelope_json) if retain_previous_for_overlap else None
        )
        row.envelope_json = new_envelope.model_dump(mode="json")
        row.kek_version = new_envelope.kek_version
        row.aad_digest = new_envelope.aad_digest
        row.active_key_version = int(row.active_key_version) + 1
        row.rotated_at = ref_now
        row.updated_at = ref_now
        row.version += 1
        await session.flush()
        return (row.secret_ref, int(row.active_key_version))

    async def resolve_provider_access_token(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        secret_ref: str,
    ) -> str:
        raw = await self._broker.resolve_secret_bytes(
            session,
            secret_ref=secret_ref,
            capability=INTEGRATIONS_READ_SECRET_CAPABILITY,
            workspace_id=workspace_id,
        )
        token = raw.decode("utf-8", errors="strict").strip()
        if token:
            self._broker._redactor.register_canary(token)
        return token

    async def verify_gitlab_webhook_auth(
        self,
        session: AsyncSession,
        *,
        workspace_id: str,
        secret_ref: str,
        pinned_auth_mode: ConnectionAuthMode,
        headers: Mapping[str, str],
        raw_body: bytes,
        now: datetime,
    ) -> bool:
        from py_contracts.crypto import verify_gitlab_legacy_token, verify_gitlab_webhook_v19

        row = await session.scalar(
            select(SecretEntryModel).where(
                SecretEntryModel.secret_ref == secret_ref,
                SecretEntryModel.workspace_id == workspace_id,
            )
        )
        if row is None or row.revoked_at is not None or row.purpose != "webhook_auth":
            return False

        aad_ctx = _build_aad_context(
            secret_ref=row.secret_ref,
            workspace_id=row.workspace_id,
            purpose=row.purpose,
        )
        enrolled_secrets: list[bytes] = []
        active_env = EnvelopeCiphertext.model_validate(row.envelope_json)
        active_plain = decrypt_envelope(
            active_env,
            key_ring=self._broker._key_ring,
            aad_context=aad_ctx,
        )
        self._broker._register_canary_if_textual(active_plain)
        enrolled_secrets.append(active_plain)

        if row.previous_envelope_json is not None:
            try:
                prev_env = EnvelopeCiphertext.model_validate(row.previous_envelope_json)
                prev_plain = decrypt_envelope(
                    prev_env,
                    key_ring=self._broker._key_ring,
                    aad_context=aad_ctx,
                )
            except (ValueError, KeyError):
                prev_plain = b""
            if prev_plain:
                self._broker._register_canary_if_textual(prev_plain)
                enrolled_secrets.append(prev_plain)

        lowered_headers = {k.strip().lower(): v for k, v in headers.items()}
        if pinned_auth_mode in {"gitlab_signed_v19", "signed_webhook"}:
            return verify_gitlab_webhook_v19(
                secrets=enrolled_secrets,
                webhook_id=lowered_headers.get("webhook-id"),
                webhook_timestamp=lowered_headers.get("webhook-timestamp"),
                webhook_signature=lowered_headers.get("webhook-signature"),
                raw_body=raw_body,
                now_unix=int(now.astimezone(UTC).timestamp()),
            )
        if pinned_auth_mode in {"gitlab_legacy_token", "secret_token"}:
            return verify_gitlab_legacy_token(
                secrets=enrolled_secrets,
                header_token=lowered_headers.get("x-gitlab-token"),
            )
        return False

    def get_cached_jit_installation_token(
        self,
        *,
        workspace_id: str,
        connection_id: str,
        installation_id: str,
        scope_key: str,
        now: datetime,
    ) -> str | None:
        from datetime import timedelta

        ref_now = now.astimezone(UTC)
        cache_key = (workspace_id, connection_id, installation_id, scope_key)
        with self._lock:
            cached = self._jit_cache.get(cache_key)
            if cached is None:
                return None
            envelope, expires_at = cached
            if ref_now + timedelta(
                seconds=self._JIT_EXPIRY_SAFETY_MARGIN_SECONDS
            ) >= expires_at.astimezone(UTC):
                self._jit_cache.pop(cache_key, None)
                return None

        aad_ctx = {
            "cache_kind": "github_jit_installation_token",
            "workspace_id": workspace_id,
            "connection_id": connection_id,
            "installation_id": installation_id,
            "scope_key": scope_key,
        }
        try:
            raw = decrypt_envelope(
                envelope,
                key_ring=self._broker._key_ring,
                aad_context=aad_ctx,
            )
            return raw.decode("utf-8")
        except Exception:
            with self._lock:
                self._jit_cache.pop(cache_key, None)
            return None

    def cache_jit_installation_token(
        self,
        *,
        workspace_id: str,
        connection_id: str,
        installation_id: str,
        scope_key: str,
        token: str,
        expires_at: datetime,
        now: datetime,
    ) -> None:
        from datetime import timedelta

        ref_now = now.astimezone(UTC)
        exp_utc = expires_at.astimezone(UTC)
        if (
            not token
            or ref_now + timedelta(seconds=self._JIT_EXPIRY_SAFETY_MARGIN_SECONDS) >= exp_utc
        ):
            return

        self._broker._redactor.register_canary(token)
        aad_ctx = {
            "cache_kind": "github_jit_installation_token",
            "workspace_id": workspace_id,
            "connection_id": connection_id,
            "installation_id": installation_id,
            "scope_key": scope_key,
        }
        envelope = encrypt_envelope(
            token.encode("utf-8"),
            key_ring=self._broker._key_ring,
            aad_context=aad_ctx,
        )
        cache_key = (workspace_id, connection_id, installation_id, scope_key)
        with self._lock:
            self._jit_cache[cache_key] = (envelope, exp_utc)

    def invalidate_cached_tokens(
        self,
        *,
        workspace_id: str,
        connection_id: str | None = None,
    ) -> int:
        with self._lock:
            keys_to_remove = [
                k
                for k in self._jit_cache
                if k[0] == workspace_id and (connection_id is None or k[1] == connection_id)
            ]
            for key in keys_to_remove:
                self._jit_cache.pop(key, None)
            return len(keys_to_remove)

    def cached_token_count(self, *, workspace_id: str | None = None) -> int:
        with self._lock:
            if workspace_id is None:
                return len(self._jit_cache)
            return sum(1 for k in self._jit_cache if k[0] == workspace_id)
