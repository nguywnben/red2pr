"""Tamper-evident append-only audit hash chain & external signed checkpoints (SEC-037).

Implements docs/06_DATA_MODEL.md, docs/36_CANONICAL_CONTRACTS.md (S-17, S-22), and SEC-037:
- `append_audit_entry` serializes writers via `red2pr_next_audit_chain_head()` (backed by
  PostgreSQL transaction-level advisory lock), scrubs `target` and `metadata` via
  `Redactor`, links `prev_hash -> entry_hash` over canonical JSON, and persists an
  immutable `audit_log` row.
- `create_audit_checkpoint` signs an `AuditCheckpointV1` under `DOMAIN_AUDIT_CHECKPOINT_V1`
  (Ed25519) and replicates it atomically to `ExternalCheckpointStore` (separately
  permissioned storage outside DB writer control).
- `verify_audit_chain` validates Ed25519 checkpoint signatures, DB/external checkpoint
  parity, contiguous `seq = 1..N`, unbroken `prev_hash -> entry_hash`, per-row canonical
  SHA-256 integrity, and absence of tail truncation (`SEC-037`).
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field, StrictInt
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts.crypto import (
    DOMAIN_AUDIT_CHECKPOINT_V1,
    CryptoVerificationError,
    KeyRing,
    canonical_json_bytes,
    sha256_canonical_json,
    sign_model_ed25519,
    verify_model_ed25519,
)
from py_contracts.evidence import AuditDecision, AuditRecord
from py_contracts.primitives import (
    BoundedName,
    BoundedText,
    InternalId,
    Sha256Digest,
    StrictContractModel,
    UtcTimestamp,
    new_uuid7,
)
from red2pr_control.core.errors import ConflictError, Red2PrError
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.db.base import AuditCheckpointModel, AuditLogModel

GENESIS_PREV_HASH: str = "0" * 64
AuditActorType = Literal["user", "system", "service", "anonymous"]


class AuditIntegrityError(Red2PrError):
    """Deterministic audit hash-chain or checkpoint tamper detection failure (SEC-037)."""

    def __init__(self, *, code: str, detail: str) -> None:
        super().__init__(
            code=code,
            title="Audit integrity verification failed",
            detail=detail,
            status=409,
        )


class AuditCheckpointV1(StrictContractModel):
    """Domain-separated Ed25519-signed audit chain checkpoint replicated externally."""

    schema_version: Literal[1] = 1
    checkpoint_id: InternalId
    start_seq: Annotated[StrictInt, Field(ge=1)]
    end_seq: Annotated[StrictInt, Field(ge=1)]
    entry_count: Annotated[StrictInt, Field(ge=1)]
    first_entry_hash: Sha256Digest
    last_entry_hash: Sha256Digest
    chain_digest: Sha256Digest
    created_at: UtcTimestamp
    signer_key_id: BoundedName
    signature: BoundedText


class ExternalCheckpointStore:
    """Append-only file-backed external checkpoint store with fsync atomic writes."""

    def __init__(self, root_dir: Path | str) -> None:
        self._root = Path(root_dir)
        self._root.mkdir(parents=True, exist_ok=True)

    @property
    def root_dir(self) -> Path:
        return self._root

    def write_checkpoint(self, checkpoint: AuditCheckpointV1) -> Path:
        """Persist signed checkpoint atomically without overwriting existing checkpoints."""
        filename = f"ckpt_{checkpoint.end_seq:012d}_{checkpoint.checkpoint_id}.json"
        dest = self._root / filename
        if dest.exists():
            raise AuditIntegrityError(
                code="audit_checkpoint_overwrite_denied",
                detail=f"External checkpoint {filename} already exists and is immutable.",
            )
        payload_bytes = canonical_json_bytes(checkpoint.model_dump(mode="json"))
        fd, tmp_name = tempfile.mkstemp(prefix=".tmp_ckpt_", dir=str(self._root))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, dest)
        except Exception:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise
        return dest

    def list_checkpoints(self) -> list[AuditCheckpointV1]:
        """Load all externally stored audit checkpoints ordered by `end_seq`."""
        if not self._root.exists():
            return []
        checkpoints: list[AuditCheckpointV1] = []
        for path in sorted(self._root.glob("ckpt_*.json")):
            try:
                raw_text = path.read_text(encoding="utf-8")
                checkpoints.append(AuditCheckpointV1.model_validate_json(raw_text))
            except Exception as exc:
                raise AuditIntegrityError(
                    code="audit_checkpoint_corrupted",
                    detail=f"External checkpoint {path.name} failed schema validation.",
                ) from exc
        checkpoints.sort(key=lambda item: (item.start_seq, item.end_seq, item.checkpoint_id))
        return checkpoints


def _canonical_ts_micros(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _compute_audit_entry_hash(
    *,
    seq: int,
    entry_id: str,
    workspace_id: str | None,
    repository_id: str | None,
    actor_type: str,
    actor_id: str,
    action: str,
    target: str,
    decision: str,
    reason_code: str,
    correlation_id: str,
    client_ip: str | None,
    metadata_json: Mapping[str, Any],
    occurred_at: datetime,
    prev_hash: str,
) -> str:
    return sha256_canonical_json(
        {
            "schema_version": 1,
            "seq": seq,
            "id": entry_id,
            "workspace_id": workspace_id,
            "repository_id": repository_id,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "action": action,
            "target": target,
            "decision": decision,
            "reason_code": reason_code,
            "correlation_id": correlation_id,
            "client_ip": client_ip,
            "metadata": dict(metadata_json),
            "occurred_at": _canonical_ts_micros(occurred_at),
            "prev_hash": prev_hash,
        }
    )


async def append_audit_entry(
    session: AsyncSession,
    *,
    actor_type: AuditActorType,
    actor_id: str,
    action: str,
    target: str,
    decision: AuditDecision,
    reason_code: str,
    correlation_id: str,
    workspace_id: str | None = None,
    repository_id: str | None = None,
    client_ip: str | None = None,
    metadata: Mapping[str, Any] | None = None,
    occurred_at: datetime | None = None,
    redactor: Redactor | None = None,
) -> AuditRecord:
    """Append a redacted, hash-chained S-17 audit record inside the active DB transaction."""
    active_redactor = redactor if redactor is not None else DEFAULT_REDACTOR
    ref_at = occurred_at.astimezone(UTC) if occurred_at is not None else datetime.now(tz=UTC)
    entry_id = new_uuid7(now=ref_at)

    safe_actor_id = active_redactor.redact_text(actor_id.strip())[:120]
    safe_action = active_redactor.redact_text(action.strip())[:120]
    safe_target = active_redactor.redact_text(target.strip())[:4096]
    safe_reason = active_redactor.redact_text(reason_code.strip())[:120]
    safe_corr = active_redactor.redact_text(correlation_id.strip())[:120]
    raw_meta = dict(metadata) if metadata is not None else {}
    safe_meta = cast(dict[str, Any], active_redactor.redact_value(raw_meta))

    head_row = (
        await session.execute(
            text("SELECT last_seq, last_entry_hash FROM red2pr_next_audit_chain_head()")
        )
    ).one()
    last_seq = int(head_row[0])
    last_hash = str(head_row[1]) if head_row[1] is not None else None

    next_seq = last_seq + 1
    prev_hash = last_hash if last_hash is not None else GENESIS_PREV_HASH
    entry_hash = _compute_audit_entry_hash(
        seq=next_seq,
        entry_id=entry_id,
        workspace_id=workspace_id,
        repository_id=repository_id,
        actor_type=actor_type,
        actor_id=safe_actor_id,
        action=safe_action,
        target=safe_target,
        decision=decision,
        reason_code=safe_reason,
        correlation_id=safe_corr,
        client_ip=client_ip,
        metadata_json=safe_meta,
        occurred_at=ref_at,
        prev_hash=prev_hash,
    )

    row = AuditLogModel(
        seq=next_seq,
        id=entry_id,
        workspace_id=workspace_id,
        repository_id=repository_id,
        actor_type=actor_type,
        actor_id=safe_actor_id,
        action=safe_action,
        target=safe_target,
        decision=decision,
        reason_code=safe_reason,
        correlation_id=safe_corr,
        client_ip=client_ip,
        metadata_json=safe_meta,
        occurred_at=ref_at,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        version=1,
        created_at=ref_at,
    )
    session.add(row)
    await session.flush()

    actor_label = f"{actor_type}:{safe_actor_id}"[:120]
    return AuditRecord(
        id=entry_id,
        version=1,
        created_at=ref_at,
        updated_at=ref_at,
        workspace_id=workspace_id,
        actor=actor_label,
        action=safe_action,
        target=safe_target,
        decision=decision,
        reason_code=safe_reason,
        correlation_id=safe_corr,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        checkpoint_id=None,
    )


async def create_audit_checkpoint(
    session: AsyncSession,
    *,
    external_store: ExternalCheckpointStore,
    private_key: Ed25519PrivateKey,
    signer_key_id: str,
    now: datetime | None = None,
) -> AuditCheckpointV1:
    """Create an Ed25519-signed checkpoint over uncheckpointed audit entries & replicate."""
    ref_now = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
    last_ckpt = await session.scalar(
        select(AuditCheckpointModel).order_by(AuditCheckpointModel.end_seq.desc()).limit(1)
    )
    start_seq = int(last_ckpt.end_seq) + 1 if last_ckpt is not None else 1

    entries = (
        await session.scalars(
            select(AuditLogModel)
            .where(AuditLogModel.seq >= start_seq)
            .order_by(AuditLogModel.seq.asc())
        )
    ).all()
    if not entries:
        raise ConflictError(
            code="audit_checkpoint_empty",
            detail="No new uncheckpointed audit_log entries exist to checkpoint.",
        )

    end_seq = int(entries[-1].seq)
    entry_hashes = [row.entry_hash for row in entries]
    chain_digest = sha256_canonical_json(entry_hashes)
    ckpt_id = new_uuid7(now=ref_now)

    unsigned = AuditCheckpointV1(
        checkpoint_id=ckpt_id,
        start_seq=int(entries[0].seq),
        end_seq=end_seq,
        entry_count=len(entries),
        first_entry_hash=entries[0].entry_hash,
        last_entry_hash=entries[-1].entry_hash,
        chain_digest=chain_digest,
        created_at=ref_now,
        signer_key_id=signer_key_id,
        signature="ed25519:unsigned",
    )
    signed = sign_model_ed25519(
        unsigned,
        private_key=private_key,
        key_id=signer_key_id,
        domain=DOMAIN_AUDIT_CHECKPOINT_V1,
    )

    db_ckpt = AuditCheckpointModel(
        id=signed.checkpoint_id,
        start_seq=signed.start_seq,
        end_seq=signed.end_seq,
        entry_count=signed.entry_count,
        first_entry_hash=signed.first_entry_hash,
        last_entry_hash=signed.last_entry_hash,
        chain_digest=signed.chain_digest,
        created_at=signed.created_at,
        signer_key_id=signed.signer_key_id,
        signature=signed.signature,
    )
    session.add(db_ckpt)
    await session.flush()
    external_store.write_checkpoint(signed)
    return signed


async def verify_audit_chain(
    session: AsyncSession,
    *,
    external_store: ExternalCheckpointStore,
    keyring: KeyRing,
) -> int:
    """Verify full audit hash chain and cross-check signed external checkpoints (SEC-037)."""
    ext_checkpoints = external_store.list_checkpoints()
    for ext_ckpt in ext_checkpoints:
        try:
            verify_model_ed25519(
                ext_ckpt,
                keyring=keyring,
                domain=DOMAIN_AUDIT_CHECKPOINT_V1,
                signed_at=ext_ckpt.created_at,
            )
        except CryptoVerificationError as exc:
            raise AuditIntegrityError(
                code="audit_checkpoint_signature_invalid",
                detail=f"External checkpoint {ext_ckpt.checkpoint_id} failed signature check.",
            ) from exc

    db_checkpoints = (
        await session.scalars(
            select(AuditCheckpointModel).order_by(
                AuditCheckpointModel.start_seq.asc(),
                AuditCheckpointModel.end_seq.asc(),
            )
        )
    ).all()

    db_ckpt_by_id = {row.id: row for row in db_checkpoints}
    for ext_ckpt in ext_checkpoints:
        db_row = db_ckpt_by_id.get(ext_ckpt.checkpoint_id)
        if db_row is None:
            raise AuditIntegrityError(
                code="audit_checkpoint_tampered",
                detail=(
                    f"Signed external checkpoint {ext_ckpt.checkpoint_id} is missing from "
                    "database audit_checkpoints."
                ),
            )
        if (
            int(db_row.start_seq) != ext_ckpt.start_seq
            or int(db_row.end_seq) != ext_ckpt.end_seq
            or db_row.last_entry_hash != ext_ckpt.last_entry_hash
            or db_row.chain_digest != ext_ckpt.chain_digest
            or db_row.signature != ext_ckpt.signature
        ):
            raise AuditIntegrityError(
                code="audit_checkpoint_tampered",
                detail=(
                    f"Database checkpoint {ext_ckpt.checkpoint_id} diverges from "
                    "externally signed checkpoint."
                ),
            )

    for db_row in db_checkpoints:
        db_model = AuditCheckpointV1(
            checkpoint_id=db_row.id,
            start_seq=int(db_row.start_seq),
            end_seq=int(db_row.end_seq),
            entry_count=int(db_row.entry_count),
            first_entry_hash=db_row.first_entry_hash,
            last_entry_hash=db_row.last_entry_hash,
            chain_digest=db_row.chain_digest,
            created_at=db_row.created_at,
            signer_key_id=db_row.signer_key_id,
            signature=db_row.signature,
        )
        try:
            verify_model_ed25519(
                db_model,
                keyring=keyring,
                domain=DOMAIN_AUDIT_CHECKPOINT_V1,
                signed_at=db_model.created_at,
            )
        except CryptoVerificationError as exc:
            raise AuditIntegrityError(
                code="audit_checkpoint_signature_invalid",
                detail=f"Database checkpoint {db_row.id} failed Ed25519 verification.",
            ) from exc

    entries = (await session.scalars(select(AuditLogModel).order_by(AuditLogModel.seq.asc()))).all()

    expected_seq = 1
    expected_prev_hash = GENESIS_PREV_HASH
    hash_by_seq: dict[int, str] = {}

    for row in entries:
        actual_seq = int(row.seq)
        if actual_seq != expected_seq:
            raise AuditIntegrityError(
                code="audit_sequence_gap",
                detail=f"Expected audit seq {expected_seq}, observed {actual_seq}.",
            )
        if row.prev_hash != expected_prev_hash:
            raise AuditIntegrityError(
                code="audit_prev_hash_mismatch",
                detail=f"Audit entry seq={actual_seq} has broken prev_hash link.",
            )
        recomputed = _compute_audit_entry_hash(
            seq=actual_seq,
            entry_id=row.id,
            workspace_id=row.workspace_id,
            repository_id=row.repository_id,
            actor_type=row.actor_type,
            actor_id=row.actor_id,
            action=row.action,
            target=row.target,
            decision=row.decision,
            reason_code=row.reason_code,
            correlation_id=row.correlation_id,
            client_ip=row.client_ip,
            metadata_json=row.metadata_json,
            occurred_at=row.occurred_at,
            prev_hash=row.prev_hash,
        )
        if recomputed != row.entry_hash:
            raise AuditIntegrityError(
                code="audit_hash_mismatch",
                detail=f"Audit entry seq={actual_seq} failed canonical SHA-256 verification.",
            )
        hash_by_seq[actual_seq] = row.entry_hash
        expected_prev_hash = row.entry_hash
        expected_seq += 1

    max_seq = len(entries)
    for ext_ckpt in ext_checkpoints:
        if max_seq < ext_ckpt.end_seq:
            raise AuditIntegrityError(
                code="audit_tail_truncated",
                detail=(
                    f"Audit log ends at seq={max_seq}, behind signed external checkpoint "
                    f"end_seq={ext_ckpt.end_seq}."
                ),
            )
        span_hashes = [hash_by_seq[s] for s in range(ext_ckpt.start_seq, ext_ckpt.end_seq + 1)]
        if (
            span_hashes[0] != ext_ckpt.first_entry_hash
            or span_hashes[-1] != ext_ckpt.last_entry_hash
            or sha256_canonical_json(span_hashes) != ext_ckpt.chain_digest
        ):
            raise AuditIntegrityError(
                code="audit_hash_mismatch",
                detail=(
                    f"Audit entries in seq={ext_ckpt.start_seq}..{ext_ckpt.end_seq} "
                    f"do not match signed checkpoint {ext_ckpt.checkpoint_id}."
                ),
            )

    return max_seq
