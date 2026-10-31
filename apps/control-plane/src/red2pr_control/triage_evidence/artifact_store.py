"""Encrypted local & S3-compatible ArtifactStore with staged SHA-256 verification (`U13`).

Implements `S-14`, `A-10`, `OPS-03`, `SEC-025`, and `SEC-032`:
- Client-side versioned AES-256-GCM envelope encryption (`py_contracts.crypto.encrypt_envelope`)
  with canonical AAD binding `{"purpose": "artifact_blob", "sha256": digest, "workspace_id": ws}`
  so neither disk nor S3 object storage ever receives plaintext bytes or cross-tenant key reuse.
- Deterministic 4-phase blob lifecycle:
  `stage_upload -> verify_staged (AEAD + SHA-256 verify) -> DB commit -> finalize_staged`.
- Any corrupted blob, tampered ciphertext, or SHA-256 mismatch is moved to `quarantine/` and
  marked `quarantined` (`SEC-025` — NEVER marked verified or finalized).
- Deduplication is strictly tenant-scoped (`UNIQUE (workspace_id, digest)`); cross-tenant
  storage references are rejected fail-closed (`SEC-032`).
- Orphan staged blob sweeper and retention expiry sweeper (`410` after `retention_until`).
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts.crypto import (
    CryptoVerificationError,
    EnvelopeCiphertext,
    MasterKeyRing,
    decrypt_envelope,
    encrypt_envelope,
)
from py_contracts.evidence import Artifact, ArtifactAccessClass
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.egress import EgressPolicyEngine
from red2pr_control.core.errors import (
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    GoneError,
    NotFoundError,
)
from red2pr_control.db.base import ArtifactBlobModel, ArtifactDeletionJobModel, ArtifactModel
from red2pr_control.triage_evidence.s3_sigv4 import S3Credentials, sign_s3_v4_headers

StorageBackendKind = Literal["local_encrypted", "s3_encrypted"]

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^[0-9A-Za-z_-]{8,64}$")
_S3_CONTENTS_BLOCK_RE = re.compile(r"<Contents\b[^>]*>(.*?)</Contents>", re.DOTALL)
_S3_KEY_TAG_RE = re.compile(r"<Key>([^<]+)</Key>")
_S3_LAST_MOD_TAG_RE = re.compile(r"<LastModified>([^<]+)</LastModified>")
_LOCAL_REF_PREFIX = "local://v1/"
_S3_REF_PREFIX = "s3://v1/"


class ArtifactIntegrityError(ConflictError):
    """Raised when staged or stored artifact bytes fail AEAD or SHA-256 verification (`SEC-025`)."""

    def __init__(self, *, code: str = "artifact_integrity_failed", detail: str) -> None:
        super().__init__(code=code, detail=detail)


@dataclass(frozen=True, slots=True)
class StagedBlobHandle:
    """Opaque handle produced by `stage_upload` prior to SHA-256 verification & DB commit."""

    stage_id: str
    workspace_id: str
    expected_digest: str
    expected_size_bytes: int
    staged_ref: str
    final_ref: str
    storage_backend: StorageBackendKind
    kek_version: int
    aad_digest: str
    staged_at: datetime


def _validate_workspace_and_digest(workspace_id: str, expected_digest: str) -> tuple[str, str]:
    ws = workspace_id.strip()
    digest = expected_digest.strip().lower()
    if not _SAFE_ID_RE.fullmatch(ws):
        raise ValueError("Invalid workspace_id for artifact storage")
    if not _HEX64_RE.fullmatch(digest):
        raise ArtifactIntegrityError(
            code="invalid_artifact_digest",
            detail="Expected artifact SHA-256 digest must be 64 lowercase hex characters.",
        )
    return ws, digest


def _build_aad_context(workspace_id: str, sha256_digest: str) -> dict[str, str]:
    return {
        "purpose": "artifact_blob",
        "sha256": sha256_digest,
        "workspace_id": workspace_id,
    }


def _serialize_envelope(envelope: EnvelopeCiphertext, *, staged_at: datetime) -> bytes:
    payload = {
        "envelope": envelope.model_dump(mode="json"),
        "staged_at": staged_at.astimezone(UTC).isoformat(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _deserialize_envelope(raw: bytes) -> tuple[EnvelopeCiphertext, datetime | None]:
    try:
        parsed = json.loads(raw.decode("utf-8"))
        if not isinstance(parsed, dict) or "envelope" not in parsed:
            raise ValueError("Missing envelope root")
        env = EnvelopeCiphertext.model_validate(parsed["envelope"])
        staged_at: datetime | None = None
        if isinstance(parsed.get("staged_at"), str):
            dt_str = parsed["staged_at"]
            if dt_str.endswith("Z"):
                dt_str = dt_str[:-1] + "+00:00"
            staged_at = datetime.fromisoformat(dt_str).astimezone(UTC)
        return env, staged_at
    except Exception as exc:
        raise ArtifactIntegrityError(
            code="artifact_corrupt_envelope",
            detail="Stored artifact envelope is corrupted or malformed (SEC-025).",
        ) from exc


class ArtifactStoreProtocol(Protocol):
    """Unified encrypted object store interface (`LocalEncryptedArtifactStore` & S3)."""

    @property
    def backend_kind(self) -> StorageBackendKind: ...

    async def stage_upload(
        self,
        *,
        workspace_id: str,
        plaintext: bytes,
        expected_digest: str,
        now: datetime | None = None,
    ) -> StagedBlobHandle: ...

    async def verify_staged(
        self,
        handle: StagedBlobHandle,
    ) -> int: ...

    async def finalize_staged(
        self,
        handle: StagedBlobHandle,
    ) -> str: ...

    async def read_verified(
        self,
        *,
        workspace_id: str,
        storage_ref: str,
        expected_digest: str,
    ) -> bytes: ...

    async def export_encrypted_blob(
        self, *, workspace_id: str, storage_ref: str, expected_digest: str
    ) -> bytes: ...

    async def restore_encrypted_blob(
        self, *, workspace_id: str, storage_ref: str, expected_digest: str, ciphertext: bytes
    ) -> None: ...

    async def verify_encrypted_blob(
        self, *, workspace_id: str, expected_digest: str, ciphertext: bytes
    ) -> int: ...

    async def delete_blob(
        self,
        *,
        workspace_id: str,
        storage_ref: str,
    ) -> bool: ...

    async def sweep_orphan_staged(
        self,
        *,
        older_than: datetime,
        workspace_id: str | None = None,
    ) -> int: ...


class LocalEncryptedArtifactStore:
    """Filesystem-backed AES-256-GCM envelope-encrypted `ArtifactStore` (`U13`)."""

    def __init__(
        self,
        *,
        root_dir: Path,
        key_ring: MasterKeyRing,
    ) -> None:
        self._root_dir = root_dir.resolve()
        self._root_dir.mkdir(parents=True, exist_ok=True)
        self._key_ring = key_ring

    @property
    def backend_kind(self) -> StorageBackendKind:
        return "local_encrypted"

    @property
    def root_dir(self) -> Path:
        return self._root_dir

    def _ref_to_confined_path(self, *, workspace_id: str, storage_ref: str) -> Path:
        ws = workspace_id.strip()
        if not storage_ref.startswith(_LOCAL_REF_PREFIX):
            raise ForbiddenError(
                code="invalid_storage_ref_scheme",
                detail="Artifact storage reference does not match local encrypted store.",
            )
        rel = storage_ref[len(_LOCAL_REF_PREFIX) :]
        parts = [p for p in rel.split("/") if p]
        if len(parts) < 3 or any(p in (".", "..") for p in parts):
            raise ForbiddenError(
                code="invalid_storage_ref_path",
                detail="Malformed local artifact storage reference.",
            )
        # Format: local://v1/{workspace_id}/{bucket_section}/...
        if parts[0] != ws:
            raise ForbiddenError(
                code="cross_tenant_artifact_ref",
                detail="Cross-tenant artifact storage reference denied (SEC-032).",
            )
        resolved = (self._root_dir / Path(*parts)).resolve()
        if not resolved.is_relative_to(self._root_dir):
            raise ForbiddenError(
                code="invalid_storage_ref_path",
                detail="Artifact path escaped local store root.",
            )
        return resolved

    async def stage_upload(
        self,
        *,
        workspace_id: str,
        plaintext: bytes,
        expected_digest: str,
        now: datetime | None = None,
    ) -> StagedBlobHandle:
        ws, digest = _validate_workspace_and_digest(workspace_id, expected_digest)
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        stage_id = new_uuid7(now=ref_now)
        aad = _build_aad_context(ws, digest)
        envelope = encrypt_envelope(plaintext, key_ring=self._key_ring, aad_context=aad)

        staged_ref = f"{_LOCAL_REF_PREFIX}{ws}/staged/{stage_id}.enc"
        final_ref = f"{_LOCAL_REF_PREFIX}{ws}/blobs/{digest[:2]}/{digest}.enc"
        staged_path = self._ref_to_confined_path(workspace_id=ws, storage_ref=staged_ref)
        staged_path.parent.mkdir(parents=True, exist_ok=True)

        tmp_path = staged_path.with_suffix(f".tmp.{os.urandom(4).hex()}")
        serialized = _serialize_envelope(envelope, staged_at=ref_now)
        tmp_path.write_bytes(serialized)
        os.replace(tmp_path, staged_path)

        return StagedBlobHandle(
            stage_id=stage_id,
            workspace_id=ws,
            expected_digest=digest,
            expected_size_bytes=len(plaintext),
            staged_ref=staged_ref,
            final_ref=final_ref,
            storage_backend="local_encrypted",
            kek_version=envelope.kek_version,
            aad_digest=envelope.aad_digest,
            staged_at=ref_now,
        )

    def _quarantine_staged_file(self, handle: StagedBlobHandle) -> None:
        staged_path = self._ref_to_confined_path(
            workspace_id=handle.workspace_id,
            storage_ref=handle.staged_ref,
        )
        if not staged_path.exists():
            return
        quarantine_ref = (
            f"{_LOCAL_REF_PREFIX}{handle.workspace_id}/quarantine/{handle.stage_id}.corrupt"
        )
        q_path = self._ref_to_confined_path(
            workspace_id=handle.workspace_id,
            storage_ref=quarantine_ref,
        )
        q_path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staged_path, q_path)

    async def verify_staged(self, handle: StagedBlobHandle) -> int:
        staged_path = self._ref_to_confined_path(
            workspace_id=handle.workspace_id,
            storage_ref=handle.staged_ref,
        )
        if not staged_path.exists():
            raise ArtifactIntegrityError(
                code="staged_blob_missing",
                detail="Staged artifact blob is missing prior to verification (SEC-025).",
            )
        try:
            raw = staged_path.read_bytes()
            envelope, _ = _deserialize_envelope(raw)
            plaintext = decrypt_envelope(
                envelope,
                key_ring=self._key_ring,
                aad_context=_build_aad_context(handle.workspace_id, handle.expected_digest),
            )
        except (ArtifactIntegrityError, CryptoVerificationError, OSError) as exc:
            self._quarantine_staged_file(handle)
            raise ArtifactIntegrityError(
                code="artifact_verification_failed",
                detail="Staged artifact failed AEAD decryption or envelope check; quarantined.",
            ) from exc

        actual_digest = hashlib.sha256(plaintext).hexdigest()
        if (
            not hmac.compare_digest(actual_digest, handle.expected_digest)
            or len(plaintext) != handle.expected_size_bytes
        ):
            self._quarantine_staged_file(handle)
            raise ArtifactIntegrityError(
                code="artifact_sha256_mismatch",
                detail=(
                    "Staged artifact plaintext SHA-256 or byte length mismatched expected "
                    "digest; quarantined (SEC-025)."
                ),
            )
        return len(plaintext)

    async def finalize_staged(self, handle: StagedBlobHandle) -> str:
        staged_path = self._ref_to_confined_path(
            workspace_id=handle.workspace_id,
            storage_ref=handle.staged_ref,
        )
        final_path = self._ref_to_confined_path(
            workspace_id=handle.workspace_id,
            storage_ref=handle.final_ref,
        )
        if not staged_path.exists():
            if final_path.exists():
                return handle.final_ref
            raise ArtifactIntegrityError(
                code="staged_blob_missing",
                detail="Cannot finalize missing staged artifact blob.",
            )
        final_path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staged_path, final_path)
        return handle.final_ref

    async def read_verified(
        self,
        *,
        workspace_id: str,
        storage_ref: str,
        expected_digest: str,
    ) -> bytes:
        ws, digest = _validate_workspace_and_digest(workspace_id, expected_digest)
        blob_path = self._ref_to_confined_path(workspace_id=ws, storage_ref=storage_ref)
        if not blob_path.exists():
            raise NotFoundError(
                code="artifact_blob_missing",
                detail="Encrypted artifact blob is not present in storage.",
            )
        raw = blob_path.read_bytes()
        envelope, _ = _deserialize_envelope(raw)
        try:
            plaintext = decrypt_envelope(
                envelope,
                key_ring=self._key_ring,
                aad_context=_build_aad_context(ws, digest),
            )
        except CryptoVerificationError as exc:
            raise ArtifactIntegrityError(
                code="artifact_tampered",
                detail="Stored artifact failed AES-256-GCM authentication (SEC-025).",
            ) from exc

        actual_digest = hashlib.sha256(plaintext).hexdigest()
        if not hmac.compare_digest(actual_digest, digest):
            raise ArtifactIntegrityError(
                code="artifact_sha256_mismatch",
                detail="Stored artifact SHA-256 digest mismatch on read (SEC-025).",
            )
        return plaintext

    async def export_encrypted_blob(
        self, *, workspace_id: str, storage_ref: str, expected_digest: str
    ) -> bytes:
        """Verify plaintext integrity before exporting the original ciphertext unchanged."""
        await self.read_verified(
            workspace_id=workspace_id, storage_ref=storage_ref, expected_digest=expected_digest
        )
        return self._ref_to_confined_path(
            workspace_id=workspace_id, storage_ref=storage_ref
        ).read_bytes()

    async def restore_encrypted_blob(
        self, *, workspace_id: str, storage_ref: str, expected_digest: str, ciphertext: bytes
    ) -> None:
        """Validate AEAD + digest before atomically restoring opaque encrypted bytes."""
        ws, digest = _validate_workspace_and_digest(workspace_id, expected_digest)
        envelope, _ = _deserialize_envelope(ciphertext)
        try:
            plaintext = decrypt_envelope(
                envelope, key_ring=self._key_ring, aad_context=_build_aad_context(ws, digest)
            )
        except CryptoVerificationError as exc:
            raise ArtifactIntegrityError(
                code="artifact_missing_key_or_tampered",
                detail="Encrypted backup object cannot be authenticated with configured keys.",
            ) from exc
        if not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), digest):
            raise ArtifactIntegrityError(
                code="artifact_sha256_mismatch",
                detail="Restored object digest does not match inventory.",
            )
        path = self._ref_to_confined_path(workspace_id=ws, storage_ref=storage_ref)
        if path.exists():
            await self.read_verified(
                workspace_id=ws, storage_ref=storage_ref, expected_digest=digest
            )
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(f".restore.{os.urandom(6).hex()}")
        temp.write_bytes(ciphertext)
        os.replace(temp, path)

    async def verify_encrypted_blob(
        self, *, workspace_id: str, expected_digest: str, ciphertext: bytes
    ) -> int:
        ws, digest = _validate_workspace_and_digest(workspace_id, expected_digest)
        envelope, _ = _deserialize_envelope(ciphertext)
        try:
            plaintext = decrypt_envelope(
                envelope, key_ring=self._key_ring, aad_context=_build_aad_context(ws, digest)
            )
        except CryptoVerificationError as exc:
            raise ArtifactIntegrityError(
                code="artifact_missing_key_or_tampered",
                detail="Encrypted backup object cannot be authenticated with configured keys.",
            ) from exc
        if not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), digest):
            raise ArtifactIntegrityError(
                code="artifact_sha256_mismatch",
                detail="Backup object plaintext digest does not match manifest.",
            )
        return len(plaintext)

    async def delete_blob(self, *, workspace_id: str, storage_ref: str) -> bool:
        blob_path = self._ref_to_confined_path(
            workspace_id=workspace_id.strip(),
            storage_ref=storage_ref,
        )
        if not blob_path.exists():
            return False
        blob_path.unlink()
        return True

    async def sweep_orphan_staged(
        self,
        *,
        older_than: datetime,
        workspace_id: str | None = None,
    ) -> int:
        cutoff = older_than.astimezone(UTC)
        removed = 0
        ws_dirs: list[Path] = []
        if workspace_id is not None:
            candidate = (self._root_dir / workspace_id.strip()).resolve()
            if candidate.is_relative_to(self._root_dir) and candidate.is_dir():
                ws_dirs.append(candidate)
        elif self._root_dir.exists():
            ws_dirs = [p for p in self._root_dir.iterdir() if p.is_dir()]

        for ws_dir in ws_dirs:
            staged_dir = ws_dir / "staged"
            if not staged_dir.is_dir():
                continue
            for entry in list(staged_dir.glob("*.enc")):
                should_delete = False
                try:
                    _, staged_at = _deserialize_envelope(entry.read_bytes())
                    if staged_at is not None and staged_at <= cutoff:
                        should_delete = True
                except ArtifactIntegrityError:
                    mtime = datetime.fromtimestamp(entry.stat().st_mtime, tz=UTC)
                    if mtime <= cutoff:
                        should_delete = True
                if should_delete:
                    entry.unlink(missing_ok=True)
                    removed += 1
        return removed


class S3CompatibleArtifactStore:
    """S3 / MinIO `AWS4-HMAC-SHA256` + AES-256-GCM envelope-encrypted `ArtifactStore` (`U13`)."""

    def __init__(
        self,
        *,
        endpoint_url: str,
        bucket: str,
        credentials: S3Credentials,
        key_ring: MasterKeyRing,
        egress_policy: EgressPolicyEngine | None = None,
        transport_override: httpx.AsyncBaseTransport | None = None,
        timeout_seconds: float = 20.0,
    ) -> None:
        clean_ep = endpoint_url.strip().rstrip("/")
        clean_bucket = bucket.strip().strip("/")
        if not clean_ep or not clean_bucket or "/" in clean_bucket:
            raise ValueError("Valid S3 endpoint_url and bucket name are required")
        self._endpoint_url = clean_ep
        self._bucket = clean_bucket
        self._credentials = credentials
        self._key_ring = key_ring
        self._egress_policy = egress_policy
        self._transport_override = transport_override
        self._timeout_seconds = timeout_seconds

    @property
    def backend_kind(self) -> StorageBackendKind:
        return "s3_encrypted"

    @property
    def bucket(self) -> str:
        return self._bucket

    def _ref_to_object_key(self, *, workspace_id: str, storage_ref: str) -> str:
        ws = workspace_id.strip()
        expected_prefix = f"{_S3_REF_PREFIX}{self._bucket}/"
        if not storage_ref.startswith(expected_prefix):
            raise ForbiddenError(
                code="invalid_storage_ref_scheme",
                detail="Artifact storage reference does not match configured S3 bucket.",
            )
        obj_key = storage_ref[len(expected_prefix) :]
        parts = [p for p in obj_key.split("/") if p]
        if len(parts) < 3 or any(p in (".", "..") for p in parts):
            raise ForbiddenError(
                code="invalid_storage_ref_path",
                detail="Malformed S3 artifact object key.",
            )
        if parts[0] != ws:
            raise ForbiddenError(
                code="cross_tenant_artifact_ref",
                detail="Cross-tenant S3 artifact reference denied (SEC-032).",
            )
        return "/".join(parts)

    def _build_object_url(self, object_key: str) -> str:
        encoded_key = "/".join(quote(seg, safe="-_.~") for seg in object_key.split("/"))
        return f"{self._endpoint_url}/{quote(self._bucket, safe='-_.~')}/{encoded_key}"

    async def _s3_request(
        self,
        method: str,
        url: str,
        *,
        body: bytes = b"",
        extra_headers: dict[str, str] | None = None,
        now: datetime | None = None,
    ) -> httpx.Response:
        if self._egress_policy is not None:
            await self._egress_policy.evaluate_and_resolve(
                adapter="s3_artifacts",
                url=httpx.URL(url),
            )
        signed_headers = sign_s3_v4_headers(
            method=method,
            url=url,
            credentials=self._credentials,
            body=body,
            extra_headers=extra_headers,
            now=now,
        )
        try:
            async with httpx.AsyncClient(
                transport=self._transport_override,
                follow_redirects=False,
                trust_env=False,
                timeout=httpx.Timeout(self._timeout_seconds),
            ) as client:
                return await client.request(
                    method.upper(),
                    url,
                    content=body if body else None,
                    headers=signed_headers,
                )
        except httpx.HTTPError as exc:
            raise DependencyUnavailableError(
                code="s3_storage_unavailable",
                detail="S3-compatible artifact store transport failed.",
            ) from exc

    async def ensure_bucket_exists(self, *, now: datetime | None = None) -> None:
        """Idempotently verify or create the target S3 bucket (`HEAD` -> `PUT`)."""
        bucket_url = f"{self._endpoint_url}/{quote(self._bucket, safe='-_.~')}"
        head_resp = await self._s3_request("HEAD", bucket_url, now=now)
        if head_resp.status_code == 200:
            return
        if head_resp.status_code == 404:
            put_resp = await self._s3_request("PUT", bucket_url, now=now)
            if put_resp.status_code in (200, 201, 409):
                return
        raise DependencyUnavailableError(
            code="s3_bucket_unavailable",
            detail=f"S3 bucket '{self._bucket}' returned HTTP {head_resp.status_code}.",
        )

    async def stage_upload(
        self,
        *,
        workspace_id: str,
        plaintext: bytes,
        expected_digest: str,
        now: datetime | None = None,
    ) -> StagedBlobHandle:
        ws, digest = _validate_workspace_and_digest(workspace_id, expected_digest)
        ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        stage_id = new_uuid7(now=ref_now)
        aad = _build_aad_context(ws, digest)
        envelope = encrypt_envelope(plaintext, key_ring=self._key_ring, aad_context=aad)
        serialized = _serialize_envelope(envelope, staged_at=ref_now)

        staged_key = f"{ws}/staged/{stage_id}.enc"
        final_key = f"{ws}/blobs/{digest[:2]}/{digest}.enc"
        staged_ref = f"{_S3_REF_PREFIX}{self._bucket}/{staged_key}"
        final_ref = f"{_S3_REF_PREFIX}{self._bucket}/{final_key}"

        resp = await self._s3_request(
            "PUT",
            self._build_object_url(staged_key),
            body=serialized,
            extra_headers={"Content-Type": "application/octet-stream"},
            now=ref_now,
        )
        if resp.status_code not in (200, 201):
            raise DependencyUnavailableError(
                code="s3_stage_upload_failed",
                detail=f"S3 PUT staged upload failed with HTTP {resp.status_code}.",
            )

        return StagedBlobHandle(
            stage_id=stage_id,
            workspace_id=ws,
            expected_digest=digest,
            expected_size_bytes=len(plaintext),
            staged_ref=staged_ref,
            final_ref=final_ref,
            storage_backend="s3_encrypted",
            kek_version=envelope.kek_version,
            aad_digest=envelope.aad_digest,
            staged_at=ref_now,
        )

    async def _quarantine_staged_s3(
        self,
        handle: StagedBlobHandle,
        raw_bytes: bytes | None,
    ) -> None:
        staged_key = self._ref_to_object_key(
            workspace_id=handle.workspace_id,
            storage_ref=handle.staged_ref,
        )
        quarantine_key = f"{handle.workspace_id}/quarantine/{handle.stage_id}.corrupt"
        payload = raw_bytes if raw_bytes is not None else b"CORRUPT_MISSING"
        await self._s3_request(
            "PUT",
            self._build_object_url(quarantine_key),
            body=payload,
            extra_headers={"Content-Type": "application/octet-stream"},
        )
        await self._s3_request("DELETE", self._build_object_url(staged_key))

    async def verify_staged(self, handle: StagedBlobHandle) -> int:
        staged_key = self._ref_to_object_key(
            workspace_id=handle.workspace_id,
            storage_ref=handle.staged_ref,
        )
        resp = await self._s3_request("GET", self._build_object_url(staged_key))
        if resp.status_code == 404:
            raise ArtifactIntegrityError(
                code="staged_blob_missing",
                detail="Staged S3 artifact object is missing prior to verification (SEC-025).",
            )
        if resp.status_code != 200:
            raise DependencyUnavailableError(
                code="s3_verify_read_failed",
                detail=f"S3 GET staged object returned HTTP {resp.status_code}.",
            )

        raw = resp.content
        try:
            envelope, _ = _deserialize_envelope(raw)
            plaintext = decrypt_envelope(
                envelope,
                key_ring=self._key_ring,
                aad_context=_build_aad_context(handle.workspace_id, handle.expected_digest),
            )
        except (ArtifactIntegrityError, CryptoVerificationError) as exc:
            await self._quarantine_staged_s3(handle, raw)
            raise ArtifactIntegrityError(
                code="artifact_verification_failed",
                detail="Staged S3 artifact failed AEAD decryption; moved to quarantine (SEC-025).",
            ) from exc

        actual_digest = hashlib.sha256(plaintext).hexdigest()
        if (
            not hmac.compare_digest(actual_digest, handle.expected_digest)
            or len(plaintext) != handle.expected_size_bytes
        ):
            await self._quarantine_staged_s3(handle, raw)
            raise ArtifactIntegrityError(
                code="artifact_sha256_mismatch",
                detail="Staged S3 artifact SHA-256 mismatched expected digest; quarantined.",
            )
        return len(plaintext)

    async def finalize_staged(self, handle: StagedBlobHandle) -> str:
        staged_key = self._ref_to_object_key(
            workspace_id=handle.workspace_id,
            storage_ref=handle.staged_ref,
        )
        final_key = self._ref_to_object_key(
            workspace_id=handle.workspace_id,
            storage_ref=handle.final_ref,
        )
        get_resp = await self._s3_request("GET", self._build_object_url(staged_key))
        if get_resp.status_code == 404:
            head_final = await self._s3_request("HEAD", self._build_object_url(final_key))
            if head_final.status_code == 200:
                return handle.final_ref
            raise ArtifactIntegrityError(
                code="staged_blob_missing",
                detail="Cannot finalize missing staged S3 object.",
            )
        if get_resp.status_code != 200:
            raise DependencyUnavailableError(
                code="s3_finalize_failed",
                detail=f"S3 GET during finalize failed with HTTP {get_resp.status_code}.",
            )

        put_resp = await self._s3_request(
            "PUT",
            self._build_object_url(final_key),
            body=get_resp.content,
            extra_headers={"Content-Type": "application/octet-stream"},
        )
        if put_resp.status_code not in (200, 201):
            raise DependencyUnavailableError(
                code="s3_finalize_failed",
                detail=f"S3 PUT finalized object failed with HTTP {put_resp.status_code}.",
            )
        await self._s3_request("DELETE", self._build_object_url(staged_key))
        return handle.final_ref

    async def read_verified(
        self,
        *,
        workspace_id: str,
        storage_ref: str,
        expected_digest: str,
    ) -> bytes:
        ws, digest = _validate_workspace_and_digest(workspace_id, expected_digest)
        obj_key = self._ref_to_object_key(workspace_id=ws, storage_ref=storage_ref)
        resp = await self._s3_request("GET", self._build_object_url(obj_key))
        if resp.status_code == 404:
            raise NotFoundError(
                code="artifact_blob_missing",
                detail="Encrypted artifact object is not present in S3 bucket.",
            )
        if resp.status_code != 200:
            raise DependencyUnavailableError(
                code="s3_read_failed",
                detail=f"S3 GET object returned HTTP {resp.status_code}.",
            )

        envelope, _ = _deserialize_envelope(resp.content)
        try:
            plaintext = decrypt_envelope(
                envelope,
                key_ring=self._key_ring,
                aad_context=_build_aad_context(ws, digest),
            )
        except CryptoVerificationError as exc:
            raise ArtifactIntegrityError(
                code="artifact_tampered",
                detail="Stored S3 artifact failed AES-256-GCM authentication (SEC-025).",
            ) from exc

        actual_digest = hashlib.sha256(plaintext).hexdigest()
        if not hmac.compare_digest(actual_digest, digest):
            raise ArtifactIntegrityError(
                code="artifact_sha256_mismatch",
                detail="Stored S3 artifact SHA-256 digest mismatch on read (SEC-025).",
            )
        return plaintext

    async def export_encrypted_blob(
        self, *, workspace_id: str, storage_ref: str, expected_digest: str
    ) -> bytes:
        await self.read_verified(
            workspace_id=workspace_id, storage_ref=storage_ref, expected_digest=expected_digest
        )
        key = self._ref_to_object_key(workspace_id=workspace_id, storage_ref=storage_ref)
        response = await self._s3_request("GET", self._build_object_url(key))
        if response.status_code != 200:
            raise NotFoundError(
                code="artifact_blob_missing",
                detail="Encrypted artifact is missing from object storage.",
            )
        return response.content

    async def restore_encrypted_blob(
        self, *, workspace_id: str, storage_ref: str, expected_digest: str, ciphertext: bytes
    ) -> None:
        ws, digest = _validate_workspace_and_digest(workspace_id, expected_digest)
        envelope, _ = _deserialize_envelope(ciphertext)
        try:
            plaintext = decrypt_envelope(
                envelope, key_ring=self._key_ring, aad_context=_build_aad_context(ws, digest)
            )
        except CryptoVerificationError as exc:
            raise ArtifactIntegrityError(
                code="artifact_missing_key_or_tampered",
                detail="Encrypted backup object cannot be authenticated with configured keys.",
            ) from exc
        if not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), digest):
            raise ArtifactIntegrityError(
                code="artifact_sha256_mismatch",
                detail="Restored object digest does not match inventory.",
            )
        key = self._ref_to_object_key(workspace_id=ws, storage_ref=storage_ref)
        existing = await self._s3_request("GET", self._build_object_url(key))
        if existing.status_code == 200:
            await self.read_verified(
                workspace_id=ws, storage_ref=storage_ref, expected_digest=digest
            )
            return
        response = await self._s3_request(
            "PUT",
            self._build_object_url(key),
            body=ciphertext,
            extra_headers={"Content-Type": "application/octet-stream"},
        )
        if response.status_code not in (200, 201):
            raise DependencyUnavailableError(
                code="s3_restore_write_failed", detail="Encrypted artifact restore write failed."
            )

    async def verify_encrypted_blob(
        self, *, workspace_id: str, expected_digest: str, ciphertext: bytes
    ) -> int:
        ws, digest = _validate_workspace_and_digest(workspace_id, expected_digest)
        envelope, _ = _deserialize_envelope(ciphertext)
        try:
            plaintext = decrypt_envelope(
                envelope, key_ring=self._key_ring, aad_context=_build_aad_context(ws, digest)
            )
        except CryptoVerificationError as exc:
            raise ArtifactIntegrityError(
                code="artifact_missing_key_or_tampered",
                detail="Encrypted backup object cannot be authenticated with configured keys.",
            ) from exc
        if not hmac.compare_digest(hashlib.sha256(plaintext).hexdigest(), digest):
            raise ArtifactIntegrityError(
                code="artifact_sha256_mismatch",
                detail="Backup object plaintext digest does not match manifest.",
            )
        return len(plaintext)

    async def delete_blob(self, *, workspace_id: str, storage_ref: str) -> bool:
        obj_key = self._ref_to_object_key(
            workspace_id=workspace_id.strip(),
            storage_ref=storage_ref,
        )
        head_resp = await self._s3_request("HEAD", self._build_object_url(obj_key))
        if head_resp.status_code == 404:
            return False
        del_resp = await self._s3_request("DELETE", self._build_object_url(obj_key))
        return del_resp.status_code in (200, 204)

    async def sweep_orphan_staged(
        self,
        *,
        older_than: datetime,
        workspace_id: str | None = None,
    ) -> int:
        cutoff = older_than.astimezone(UTC)
        prefix = f"{workspace_id.strip()}/staged/" if workspace_id else ""
        list_url = (
            f"{self._endpoint_url}/{quote(self._bucket, safe='-_.~')}"
            f"?list-type=2&prefix={quote(prefix, safe='-_.~/')}"
        )
        resp = await self._s3_request("GET", list_url)
        if resp.status_code != 200:
            return 0
        body_xml = resp.text[:262_144]
        if "<!" in body_xml:
            return 0

        removed = 0
        for block_match in _S3_CONTENTS_BLOCK_RE.finditer(body_xml):
            block = block_match.group(1)
            key_m = _S3_KEY_TAG_RE.search(block)
            last_mod_m = _S3_LAST_MOD_TAG_RE.search(block)
            key_text = html.unescape(key_m.group(1)).strip() if key_m is not None else None
            last_mod_text = (
                html.unescape(last_mod_m.group(1)).strip() if last_mod_m is not None else None
            )
            if not key_text or "/staged/" not in key_text or not key_text.endswith(".enc"):
                continue

            should_delete = False
            get_obj = await self._s3_request("GET", self._build_object_url(key_text))
            if get_obj.status_code == 200:
                try:
                    _, staged_at = _deserialize_envelope(get_obj.content)
                    if staged_at is not None and staged_at <= cutoff:
                        should_delete = True
                except ArtifactIntegrityError:
                    should_delete = True
            elif last_mod_text:
                dt_raw = (
                    last_mod_text[:-1] + "+00:00" if last_mod_text.endswith("Z") else last_mod_text
                )
                try:
                    if datetime.fromisoformat(dt_raw).astimezone(UTC) <= cutoff:
                        should_delete = True
                except ValueError:
                    pass

            if should_delete:
                await self._s3_request("DELETE", self._build_object_url(key_text))
                removed += 1
        return removed


def artifact_model_to_public_dto(row: ArtifactModel, *, now: datetime) -> Artifact:
    """Project `ArtifactModel` to `S-14` `Artifact` DTO (never exposing `storage_ref`)."""
    ref_now = now.astimezone(UTC)
    expired = row.retention_until <= ref_now
    available = row.lifecycle_state == "finalized" and not expired
    purge_reason = row.purge_reason
    if purge_reason is None and expired:
        purge_reason = "retention_expired"
    elif purge_reason is None and row.lifecycle_state == "quarantined":
        purge_reason = "integrity_quarantined"

    return Artifact(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        name=row.name,
        run_id=row.run_id,
        job_id=row.job_id,
        kind=row.kind,
        mime=row.mime,
        size_bytes=row.size_bytes,
        digest=row.digest,
        redaction_version=row.redaction_version,
        retention_until=row.retention_until,
        access_class=row.access_class,  # type: ignore[arg-type]
        manifest_id=row.manifest_id,
        extracted_file_count=row.extracted_file_count,
        available=available,
        purge_reason=purge_reason,
    )


async def persist_encrypted_artifact(
    db: AsyncSession,
    *,
    store: ArtifactStoreProtocol,
    workspace_id: str,
    repository_id: str,
    name: str,
    kind: str,
    mime: str,
    plaintext: bytes,
    expected_digest: str | None = None,
    redaction_version: str = "v1",
    access_class: ArtifactAccessClass = "workspace_internal",
    retention_delta: timedelta = timedelta(days=30),
    run_id: str | None = None,
    job_id: str | None = None,
    external_artifact_id: str | None = None,
    extracted_file_count: int | None = None,
    now: datetime | None = None,
) -> ArtifactModel:
    """Execute `staged upload -> SHA-256 verify -> DB row commit -> finalize` (`SEC-025`).

    Deduplicates physical encrypted blobs strictly within `workspace_id` (`SEC-032`).
    If `expected_digest` is supplied and differs from `sha256(plaintext)` or staged
    verification fails, records a `quarantined` `ArtifactBlobModel` and raises
    `ArtifactIntegrityError`.
    """
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    computed_digest = hashlib.sha256(plaintext).hexdigest()
    target_digest = (
        expected_digest.strip().lower() if expected_digest is not None else computed_digest
    )

    # Tenant-scoped deduplication check (NEVER cross-tenant: SEC-032)
    existing_blob = await db.scalar(
        select(ArtifactBlobModel).where(
            ArtifactBlobModel.workspace_id == workspace_id,
            ArtifactBlobModel.digest == target_digest,
        )
    )
    if (
        existing_blob is not None
        and existing_blob.blob_state == "finalized"
        and hmac.compare_digest(computed_digest, target_digest)
    ):
        # Verify existing tenant blob is still readable & intact before linking
        await store.read_verified(
            workspace_id=workspace_id,
            storage_ref=existing_blob.storage_ref,
            expected_digest=target_digest,
        )
        art_row = ArtifactModel(
            id=new_uuid7(now=ref_now),
            workspace_id=workspace_id,
            repository_id=repository_id,
            run_id=run_id,
            job_id=job_id,
            blob_id=existing_blob.id,
            manifest_id=None,
            external_artifact_id=external_artifact_id,
            name=name[:120],
            kind=kind[:120],
            mime=mime[:120],
            size_bytes=len(plaintext),
            digest=target_digest,
            storage_ref=existing_blob.storage_ref,
            redaction_version=redaction_version[:64],
            retention_until=ref_now + retention_delta,
            access_class=access_class,
            lifecycle_state="finalized",
            extracted_file_count=extracted_file_count,
            purge_reason=None,
            version=1,
            created_at=ref_now,
            updated_at=ref_now,
        )
        db.add(art_row)
        await db.flush()
        return art_row

    # Phase 1: Stage encrypted upload
    handle = await store.stage_upload(
        workspace_id=workspace_id,
        plaintext=plaintext,
        expected_digest=target_digest,
        now=ref_now,
    )
    if existing_blob is None:
        blob_row = ArtifactBlobModel(
            id=new_uuid7(now=ref_now),
            workspace_id=workspace_id,
            digest=target_digest,
            size_bytes=len(plaintext),
            storage_backend=store.backend_kind,
            storage_ref=handle.final_ref,
            staged_ref=handle.staged_ref,
            blob_state="staged",
            kek_version=handle.kek_version,
            aad_digest=handle.aad_digest,
            quarantine_reason=None,
            verified_at=None,
            finalized_at=None,
            version=1,
            created_at=ref_now,
            updated_at=ref_now,
        )
        db.add(blob_row)
    else:
        blob_row = existing_blob
        blob_row.storage_backend = store.backend_kind
        blob_row.storage_ref = handle.final_ref
        blob_row.staged_ref = handle.staged_ref
        blob_row.blob_state = "staged"
        blob_row.kek_version = handle.kek_version
        blob_row.aad_digest = handle.aad_digest
        blob_row.quarantine_reason = None
        blob_row.version += 1
        blob_row.updated_at = ref_now
    await db.flush()

    # Phase 2: Read back & verify AEAD + SHA-256 before marking verified (SEC-025)
    try:
        await store.verify_staged(handle)
    except ArtifactIntegrityError as exc:
        blob_row.blob_state = "quarantined"
        blob_row.quarantine_reason = exc.code[:256]
        blob_row.updated_at = ref_now
        await db.flush()
        raise

    # Phase 3: Commit verified DB metadata before promoting staged object
    blob_row.blob_state = "verified"
    blob_row.verified_at = ref_now
    blob_row.updated_at = ref_now

    art_row = ArtifactModel(
        id=new_uuid7(now=ref_now),
        workspace_id=workspace_id,
        repository_id=repository_id,
        run_id=run_id,
        job_id=job_id,
        blob_id=blob_row.id,
        manifest_id=None,
        external_artifact_id=external_artifact_id,
        name=name[:120],
        kind=kind[:120],
        mime=mime[:120],
        size_bytes=len(plaintext),
        digest=target_digest,
        storage_ref=handle.final_ref,
        redaction_version=redaction_version[:64],
        retention_until=ref_now + retention_delta,
        access_class=access_class,
        lifecycle_state="staged",
        extracted_file_count=extracted_file_count,
        purge_reason=None,
        version=1,
        created_at=ref_now,
        updated_at=ref_now,
    )
    db.add(art_row)
    await db.flush()

    # Phase 4: Finalize staged object into canonical tenant blob path
    final_ref = await store.finalize_staged(handle)
    blob_row.storage_ref = final_ref
    blob_row.staged_ref = None
    blob_row.blob_state = "finalized"
    blob_row.finalized_at = ref_now
    blob_row.updated_at = ref_now
    art_row.storage_ref = final_ref
    art_row.lifecycle_state = "finalized"
    art_row.updated_at = ref_now
    await db.flush()
    return art_row


async def read_artifact_for_authorized_caller(
    db: AsyncSession,
    *,
    store: ArtifactStoreProtocol,
    artifact_row: ArtifactModel,
    now: datetime,
) -> bytes:
    """Verify retention & lifecycle state (`410` if expired) and return verified plaintext."""
    ref_now = now.astimezone(UTC)
    if artifact_row.retention_until <= ref_now or artifact_row.lifecycle_state in (
        "expired",
        "purged",
    ):
        raise GoneError(
            code="artifact_expired",
            detail="Artifact retention window has expired and content is no longer available.",
        )
    if artifact_row.lifecycle_state == "quarantined":
        raise ArtifactIntegrityError(
            code="artifact_quarantined",
            detail="Artifact failed integrity verification and is quarantined (SEC-025).",
        )
    if artifact_row.lifecycle_state != "finalized":
        raise ConflictError(
            code="artifact_not_finalized",
            detail="Artifact upload is still staged and not yet finalized.",
        )
    return await store.read_verified(
        workspace_id=artifact_row.workspace_id,
        storage_ref=artifact_row.storage_ref,
        expected_digest=artifact_row.digest,
    )


async def purge_expired_artifacts_in_tx(
    db: AsyncSession,
    *,
    store: ArtifactStoreProtocol,
    workspace_id: str,
    now: datetime,
) -> int:
    """Mark expired artifacts and enqueue durable, retryable physical blob deletion."""
    ref_now = now.astimezone(UTC)
    expired_rows = list(
        (
            await db.scalars(
                select(ArtifactModel).where(
                    ArtifactModel.workspace_id == workspace_id,
                    ArtifactModel.retention_until <= ref_now,
                    ArtifactModel.lifecycle_state.in_(("finalized", "expired")),
                )
            )
        ).all()
    )
    purged_count = 0
    candidate_blob_ids: set[str] = set()
    for row in expired_rows:
        row.lifecycle_state = "purged"
        row.purge_reason = "retention_expired"
        row.version += 1
        row.updated_at = ref_now
        if row.blob_id is not None:
            candidate_blob_ids.add(row.blob_id)
        purged_count += 1
    await db.flush()

    for blob_id in candidate_blob_ids:
        still_live = await db.scalar(
            select(ArtifactModel.id)
            .where(
                ArtifactModel.workspace_id == workspace_id,
                ArtifactModel.blob_id == blob_id,
                ArtifactModel.lifecycle_state.in_(("staged", "finalized")),
            )
            .limit(1)
        )
        if still_live is not None:
            continue
        blob_row = await db.scalar(
            select(ArtifactBlobModel).where(
                ArtifactBlobModel.workspace_id == workspace_id,
                ArtifactBlobModel.id == blob_id,
            )
        )
        if blob_row is not None and blob_row.blob_state == "finalized":
            await db.execute(
                pg_insert(ArtifactDeletionJobModel)
                .values(
                    id=new_uuid7(now=ref_now),
                    workspace_id=workspace_id,
                    blob_id=blob_row.id,
                    correlation_id=f"retention:{blob_row.id}",
                    state="pending",
                    attempts=0,
                    available_at=ref_now,
                    created_at=ref_now,
                )
                .on_conflict_do_nothing(index_elements=["workspace_id", "blob_id"])
            )
    for row in expired_rows:
        await append_audit_entry(
            db,
            actor_type="system",
            actor_id="retention-worker",
            action="artifact.retention.purged",
            target=f"artifact:{row.id}",
            decision="allow",
            reason_code="retention_expired",
            correlation_id=f"retention:{row.id}",
            workspace_id=workspace_id,
            occurred_at=ref_now,
            metadata={"lifecycle_state": "purged"},
        )
    await db.flush()
    return purged_count
