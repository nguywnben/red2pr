"""SQLAlchemy 2.0 declarative base and U03 foundation spine ORM models (docs/06_DATA_MODEL.md).

Defines the authoritative relational persistence models for Migration 0001_foundation_spine:
- instances (singleton install metadata & recovery_epoch)
- workspaces (multi-workspace tenant root + monotonic SSE last_event_seq)
- secret_entries (Z2 AES-256-GCM envelope-encrypted secrets; zero plaintext columns)
- idempotency_records (S-05 atomic Idempotency-Key receipts & 7-day response cache)
- effect_tombstones (NFR-07 >=90-day logical side-effect anti-replay tombstones)
- outbox_events (S-19 transactional domain event outbox)
- outbox_claims (fenced consumer-group outbox delivery leases with composite tenant FK)
- audit_log (S-17 append-only SHA-256 hash-chained audit ledger)
- audit_checkpoints (Ed25519-signed chain checkpoints replicated to external storage)
- schema_migrations (expand/backfill/validate/contract migration ledger)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def utc_now() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(tz=UTC)


class Base(DeclarativeBase):
    """Declarative base with deterministic constraint naming conventions."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class InstanceModel(Base):
    """Singleton installation state and recovery epoch fence."""

    __tablename__ = "instances"
    __table_args__ = (
        UniqueConstraint("singleton_guard", name="uq_instances_singleton_guard"),
        CheckConstraint("singleton_guard IS TRUE", name="singleton_guard_true"),
        CheckConstraint(
            "deployment_mode IN ('local', 'server', 'distributed')",
            name="deployment_mode_valid",
        ),
        CheckConstraint("config_revision >= 1", name="config_revision_pos"),
        CheckConstraint("recovery_epoch >= 1", name="recovery_epoch_pos"),
        CheckConstraint("version >= 1", name="version_pos"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    singleton_guard: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    deployment_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    public_base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    config_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    recovery_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    initialized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class WorkspaceModel(Base):
    """Multi-workspace tenant boundary (ADR-030) and per-workspace SSE sequence counter."""

    __tablename__ = "workspaces"
    __table_args__ = (
        UniqueConstraint("slug", name="uq_workspaces_slug"),
        CheckConstraint(
            "status IN ('active', 'suspended', 'deleting')",
            name="workspace_status_valid",
        ),
        CheckConstraint("last_event_seq >= 0", name="last_event_seq_nonneg"),
        CheckConstraint("version >= 1", name="version_pos"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False)
    owner_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    paused: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    retention_policy: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    last_event_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SecretEntryModel(Base):
    """Z2 envelope-encrypted secret entry (OPS-03; zero plaintext credentials in DB)."""

    __tablename__ = "secret_entries"
    __table_args__ = (
        UniqueConstraint("secret_ref", name="uq_secret_entries_secret_ref"),
        UniqueConstraint("workspace_id", "id", name="uq_secret_entries_workspace_id_id"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_secret_entries_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "purpose IN ("
            "'provider_read', 'provider_write', 'webhook_auth', 'meta_inference', "
            "'notification_channel', 'mfa_totp', 'oidc_client', 'storage_encryption'"
            ")",
            name="secret_purpose_valid",
        ),
        CheckConstraint("active_key_version >= 1", name="active_key_version_pos"),
        CheckConstraint("kek_version >= 1", name="kek_version_pos"),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_secret_entries_workspace_purpose", "workspace_id", "purpose"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    secret_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    workspace_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    purpose: Mapped[str] = mapped_column(String(64), nullable=False)
    active_key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    kek_version: Mapped[int] = mapped_column(Integer, nullable=False)
    envelope_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    previous_envelope_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    aad_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class IdempotencyRecordModel(Base):
    """S-05 atomic Idempotency-Key claim record and 7-day response cache."""

    __tablename__ = "idempotency_records"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_idempotency_records_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "principal_id",
            "operation",
            "idempotency_key",
            name="uq_idempotency_records_claim_scope",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_idempotency_records_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "state IN ('accepted', 'running', 'succeeded', 'failed', 'unknown')",
            name="idempotency_state_valid",
        ),
        CheckConstraint(
            "status_code >= 200 AND status_code <= 599",
            name="idempotency_status_code_valid",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_idempotency_records_workspace_expires", "workspace_id", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    principal_id: Mapped[str] = mapped_column(String(128), nullable=False)
    operation: Mapped[str] = mapped_column(String(120), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(36), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    logical_effect_key: Mapped[str] = mapped_column(String(256), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(36), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    status_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(120), nullable=False)
    result_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    response_payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    problem_payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    claimed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class EffectTombstoneModel(Base):
    """NFR-07 logical-effect anti-replay tombstone retained across >=90d horizon."""

    __tablename__ = "effect_tombstones"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_effect_tombstones_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "operation",
            "logical_effect_key",
            name="uq_effect_tombstones_logical_effect",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_effect_tombstones_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        Index("ix_effect_tombstones_workspace_retained", "workspace_id", "retained_until"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    logical_effect_key: Mapped[str] = mapped_column(String(256), nullable=False)
    operation: Mapped[str] = mapped_column(String(120), nullable=False)
    origin_operation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(36), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(36), nullable=False)
    retained_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class OutboxEventModel(Base):
    """S-19 transactional domain outbox event committed atomically with state mutations."""

    __tablename__ = "outbox_events"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_outbox_events_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "workspace_seq",
            name="uq_outbox_events_workspace_seq",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_outbox_events_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "status IN ('pending', 'claimed', 'published', 'dead_letter')",
            name="outbox_status_valid",
        ),
        CheckConstraint(
            "(workspace_id IS NULL AND workspace_seq IS NULL) OR "
            "(workspace_id IS NOT NULL AND workspace_seq IS NOT NULL AND workspace_seq >= 1)",
            name="outbox_workspace_seq_consistency",
        ),
        CheckConstraint("schema_version >= 1", name="schema_version_pos"),
        CheckConstraint("aggregate_version >= 1", name="aggregate_version_pos"),
        CheckConstraint("attempts >= 0", name="attempts_nonneg"),
        Index("ix_outbox_events_dispatch", "status", "next_attempt_at", "id"),
        Index("ix_outbox_events_workspace_seq", "workspace_id", "workspace_seq"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    workspace_seq: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    schema_version: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)
    repository_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    aggregate_id: Mapped[str] = mapped_column(String(36), nullable=False)
    aggregate_version: Mapped[int] = mapped_column(Integer, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(120), nullable=False)
    causation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class OutboxClaimModel(Base):
    """Per-consumer-group outbox lease with composite tenant FK and lease_epoch fencing."""

    __tablename__ = "outbox_claims"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_outbox_claims_workspace_id_id"),
        UniqueConstraint("event_id", "consumer_group", name="uq_outbox_claims_event_group"),
        ForeignKeyConstraint(
            ["event_id"],
            ["outbox_events.id"],
            name="fk_outbox_claims_event_id_outbox_events",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "event_id"],
            ["outbox_events.workspace_id", "outbox_events.id"],
            name="fk_outbox_claims_tenant_event_outbox_events",
            ondelete="CASCADE",
        ),
        CheckConstraint("lease_epoch >= 1", name="lease_epoch_pos"),
        Index("ix_outbox_claims_lease_expires", "consumer_group", "lease_expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    consumer_group: Mapped[str] = mapped_column(String(120), nullable=False)
    worker_id: Mapped[str] = mapped_column(String(120), nullable=False)
    lease_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    claimed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLogModel(Base):
    """S-17 append-only SHA-256 hash-chained audit entry (protected against UPDATE/DELETE)."""

    __tablename__ = "audit_log"
    __table_args__ = (
        UniqueConstraint("id", name="uq_audit_log_id"),
        UniqueConstraint("workspace_id", "id", name="uq_audit_log_workspace_id_id"),
        UniqueConstraint("entry_hash", name="uq_audit_log_entry_hash"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_audit_log_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "actor_type IN ('user', 'system', 'service', 'anonymous')",
            name="audit_actor_type_valid",
        ),
        CheckConstraint(
            "decision IN ('allow', 'deny', 'error', 'reconcile')",
            name="audit_decision_valid",
        ),
        CheckConstraint("version = 1", name="audit_version_immutable"),
        Index("ix_audit_log_workspace_occurred", "workspace_id", "occurred_at", "id"),
        Index("ix_audit_log_correlation_id", "correlation_id"),
    )

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    id: Mapped[str] = mapped_column(String(36), nullable=False)
    workspace_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    repository_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(120), nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(120), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(120), nullable=False)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class AuditCheckpointModel(Base):
    """Signed append-only audit chain checkpoint record (SEC-037)."""

    __tablename__ = "audit_checkpoints"
    __table_args__ = (
        CheckConstraint("start_seq >= 1", name="ckpt_start_seq_pos"),
        CheckConstraint("end_seq >= start_seq", name="ckpt_end_seq_ge_start"),
        CheckConstraint("entry_count = (end_seq - start_seq + 1)", name="ckpt_count_consistent"),
        Index("ix_audit_checkpoints_end_seq", "end_seq"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    start_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    end_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    entry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    first_entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    last_entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signer_key_id: Mapped[str] = mapped_column(String(120), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)


class SchemaMigrationRecordModel(Base):
    """Expand/backfill/validate/contract schema migration metadata ledger (docs/06)."""

    __tablename__ = "schema_migrations"
    __table_args__ = (
        CheckConstraint(
            "phase IN ('expand', 'backfill', 'validate', 'contract')",
            name="migration_phase_valid",
        ),
    )

    revision: Mapped[str] = mapped_column(String(120), primary_key=True)
    parent_revision: Mapped[str | None] = mapped_column(String(120), nullable=True)
    phase: Mapped[str] = mapped_column(String(32), nullable=False)
    checksum_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    compatible_min_app_version: Mapped[str] = mapped_column(String(32), nullable=False)
    reversible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class UserModel(Base):
    """S-06 instance-scoped user account with Argon2id password digest & grant_epoch."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("username", name="uq_users_username"),
        UniqueConstraint("email", name="uq_users_email"),
        CheckConstraint("status IN ('active', 'disabled')", name="user_status_valid"),
        CheckConstraint("grant_epoch >= 1", name="user_grant_epoch_pos"),
        CheckConstraint("version >= 1", name="version_pos"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    is_instance_owner: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    grant_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class BootstrapTokenModel(Base):
    """A-01 one-time expiring instance-owner bootstrap claim token (hashed at rest)."""

    __tablename__ = "bootstrap_tokens"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_bootstrap_tokens_token_hash"),
        ForeignKeyConstraint(
            ["claimed_by_user_id"],
            ["users.id"],
            name="fk_bootstrap_tokens_claimed_by_user_id_users",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    loopback_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claimed_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class SessionModel(Base):
    """S-06 authenticated browser/CLI session (opaque 256-bit token SHA-256 hashed at rest)."""

    __tablename__ = "sessions"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_sessions_token_hash"),
        ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_sessions_user_id_users",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "auth_strength IN ('password', 'mfa')",
            name="session_auth_strength_valid",
        ),
        CheckConstraint("grant_epoch >= 1", name="session_grant_epoch_pos"),
        CheckConstraint("recovery_epoch >= 1", name="session_recovery_epoch_pos"),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_sessions_user_active", "user_id", "revoked_at", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    csrf_secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    auth_strength: Mapped[str] = mapped_column(String(32), nullable=False)
    step_up_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    grant_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    recovery_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(String(120), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class MfaCredentialModel(Base):
    """RFC 6238 TOTP MFA credential referencing Z2 SecretBroker (purpose='mfa_totp')."""

    __tablename__ = "mfa_credentials"
    __table_args__ = (
        UniqueConstraint("secret_ref", name="uq_mfa_credentials_secret_ref"),
        ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_mfa_credentials_user_id_users",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "status IN ('pending', 'active', 'revoked')",
            name="mfa_credential_status_valid",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_mfa_credentials_user_status", "user_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    secret_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    last_used_timestep: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    challenge_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class RecoveryCodeModel(Base):
    """Single-use HMAC-SHA256 hashed account recovery codes (SEC-038)."""

    __tablename__ = "recovery_codes"
    __table_args__ = (
        UniqueConstraint("code_hash", name="uq_recovery_codes_code_hash"),
        ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_recovery_codes_user_id_users",
            ondelete="RESTRICT",
        ),
        Index("ix_recovery_codes_user_unused", "user_id", "used_at", "revoked_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    batch_id: Mapped[str] = mapped_column(String(36), nullable=False)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class AuthChallengeModel(Base):
    """Short-lived cookie-free MFA login challenge ticket (never issues full session cookie)."""

    __tablename__ = "auth_challenges"
    __table_args__ = (
        ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_auth_challenges_user_id_users",
            ondelete="RESTRICT",
        ),
        CheckConstraint("purpose IN ('login_mfa')", name="auth_challenge_purpose_valid"),
        CheckConstraint("failed_attempts >= 0", name="auth_challenge_attempts_nonneg"),
        Index("ix_auth_challenges_user_expires", "user_id", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False, default="login_mfa")
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class AuthRateLimitModel(Base):
    """Multi-process PostgreSQL sliding-window failure attempts for NFR-05 & SEC-038."""

    __tablename__ = "auth_rate_limits"
    __table_args__ = (
        CheckConstraint(
            "action IN ('login', 'step_up', 'recovery', 'bootstrap_claim', 'mfa_verify')",
            name="auth_rate_action_valid",
        ),
        Index("ix_auth_rate_limits_lookup", "action", "bucket_key", "attempted_at"),
        Index("ix_auth_rate_limits_expires", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    bucket_key: Mapped[str] = mapped_column(String(256), nullable=False)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
