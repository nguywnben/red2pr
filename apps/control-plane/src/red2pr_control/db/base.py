"""SQLAlchemy 2.0 declarative base and U03..U08 persistence ORM models (docs/06_DATA_MODEL.md).

Defines the authoritative relational persistence models for Migrations 0001..0005:
- instances, workspaces, secret_entries, idempotency_records, effect_tombstones,
  outbox_events, outbox_claims, audit_log, audit_checkpoints, schema_migrations (0001)
- users, bootstrap_tokens, sessions, mfa_credentials, recovery_codes, auth_challenges,
  auth_rate_limits (0002)
- memberships, invitations, repo_grants, break_glass_grants (0003)
- setup_checkpoints, consents, endpoint_registrations (0004)
- task_jobs, task_attempts, dead_letter_jobs, operation_receipts (0005)
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
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
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
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
    retention_policy: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
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
            "action IN ("
            "'login', 'step_up', 'recovery', 'bootstrap_claim', 'mfa_verify', "
            "'invite_create', 'invite_accept'"
            ")",
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


class MembershipModel(Base):
    """S-07 workspace-scoped RBAC role assignment (ADR-030, ADR-038, SEC-032)."""

    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_memberships_workspace_id_id"),
        UniqueConstraint("workspace_id", "user_id", name="uq_memberships_workspace_user"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_memberships_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_memberships_user_id_users",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["invited_by_user_id"],
            ["users.id"],
            name="fk_memberships_invited_by_user_id_users",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "role IN ('admin', 'maintainer', 'reviewer', 'viewer', 'auditor')",
            name="membership_role_valid",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_memberships_user_workspace", "user_id", "workspace_id"),
        Index("ix_memberships_workspace_created", "workspace_id", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    invited_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class InvitationModel(Base):
    """S-07 email-bound single-use workspace invitation (SHA-256 hashed token, SEC-038)."""

    __tablename__ = "invitations"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_invitations_workspace_id_id"),
        UniqueConstraint("token_hash", name="uq_invitations_token_hash"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_invitations_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["invited_by_user_id"],
            ["users.id"],
            name="fk_invitations_invited_by_user_id_users",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["accepted_by_user_id"],
            ["users.id"],
            name="fk_invitations_accepted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "role IN ('admin', 'maintainer', 'reviewer', 'viewer', 'auditor')",
            name="invitation_role_valid",
        ),
        CheckConstraint(
            "status IN ('pending', 'accepted', 'expired', 'revoked')",
            name="invitation_status_valid",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_invitations_workspace_status", "workspace_id", "status", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    repository_grants_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    invited_by_user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    accepted_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class RepoGrantModel(Base):
    """Deny-by-default per-repository grant with composite tenant FK (SEC-010, SEC-032)."""

    __tablename__ = "repo_grants"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_repo_grants_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "membership_id",
            "repository_id",
            name="uq_repo_grants_ws_member_repo",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_repo_grants_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "membership_id"],
            ["memberships.workspace_id", "memberships.id"],
            name="fk_repo_grants_tenant_membership_memberships",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["granted_by_user_id"],
            ["users.id"],
            name="fk_repo_grants_granted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        Index("ix_repo_grants_ws_repo", "workspace_id", "repository_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    membership_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    granted_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class BreakGlassGrantModel(Base):
    """ADR-034 time-bounded audited instance-owner break-glass read grant."""

    __tablename__ = "break_glass_grants"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_break_glass_grants_workspace_id_id"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_break_glass_grants_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_break_glass_grants_user_id_users",
            ondelete="RESTRICT",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_break_glass_grants_ws_user_expires", "workspace_id", "user_id", "expires_at"),
        Index("ix_break_glass_grants_user_expires", "user_id", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class SetupCheckpointModel(Base):
    """INS-02 durable 10-phase setup wizard checkpoint (redacted non-secret draft payload)."""

    __tablename__ = "setup_checkpoints"
    __table_args__ = (
        UniqueConstraint("instance_id", "phase", name="uq_setup_checkpoints_instance_phase"),
        ForeignKeyConstraint(
            ["instance_id"],
            ["instances.id"],
            name="fk_setup_checkpoints_instance_id_instances",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["completed_by_user_id"],
            ["users.id"],
            name="fk_setup_checkpoints_completed_by_user_id_users",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "phase IN ("
            "'owner_claim', 'topology_tls', 'storage_keys', 'workspace_admin', "
            "'provider_connect', 'model_consent', 'worker_readiness', 'repo_policy', "
            "'notifications', 'readiness_review'"
            ")",
            name="setup_phase_valid",
        ),
        CheckConstraint("phase_order >= 1 AND phase_order <= 10", name="setup_phase_order_valid"),
        CheckConstraint(
            "status IN ('pending', 'completed', 'not_configured', 'degraded', 'blocked')",
            name="setup_status_valid",
        ),
        CheckConstraint(
            "probe_status IS NULL OR probe_status IN ("
            "'passed', 'failed', 'needs_admin', 'needs_restart', "
            "'not_configured', 'blocked', 'unsupported'"
            ")",
            name="setup_probe_status_valid",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_setup_checkpoints_instance_order", "instance_id", "phase_order"),
        Index(
            "uq_setup_checkpoints_one_current",
            "instance_id",
            unique=True,
            postgresql_where=text("is_current_phase IS TRUE"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    instance_id: Mapped[str] = mapped_column(String(36), nullable=False)
    phase: Mapped[str] = mapped_column(String(64), nullable=False)
    phase_order: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    is_current_phase: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    checkpoint_token: Mapped[str] = mapped_column(String(120), nullable=False)
    draft_payload_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    probe_status: Mapped[str | None] = mapped_column(String(32), nullable=True, default=None)
    probe_detail: Mapped[str | None] = mapped_column(String(512), nullable=True)
    blocking_reasons_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    completed_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class ConsentModel(Base):
    """S-18 & SEC-018 explicit data-sharing consent ledger separated by purpose and scope."""

    __tablename__ = "consents"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_consents_workspace_id_id"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_consents_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["granted_by_user_id"],
            ["users.id"],
            name="fk_consents_granted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["revoked_by_user_id"],
            ["users.id"],
            name="fk_consents_revoked_by_user_id_users",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "purpose IN ('inference', 'notification', 'telemetry', 'provider')",
            name="consent_purpose_valid",
        ),
        CheckConstraint(
            "scope IN ('instance', 'workspace', 'repository')",
            name="consent_scope_valid",
        ),
        CheckConstraint(
            "(scope = 'instance' AND workspace_id IS NULL AND repository_id IS NULL) OR "
            "(scope = 'workspace' AND workspace_id IS NOT NULL AND repository_id IS NULL) OR "
            "(scope = 'repository' AND workspace_id IS NOT NULL AND repository_id IS NOT NULL)",
            name="consent_scope_binding_valid",
        ),
        CheckConstraint(
            "NOT jsonb_exists(data_classes_json, 'secret')",
            name="consent_forbid_secret_class",
        ),
        CheckConstraint("policy_version >= 1", name="consent_policy_version_pos"),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_consents_purpose_active", "purpose", "revoked_at", "created_at", "id"),
        Index("ix_consents_workspace_purpose", "workspace_id", "purpose", "revoked_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    scope: Mapped[str] = mapped_column(String(32), nullable=False)
    workspace_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    repository_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    destination: Mapped[str] = mapped_column(String(512), nullable=False)
    data_classes_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    granted_by_user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    revoked_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class EndpointRegistrationModel(Base):
    """ADR-037 owner-registered private adapter endpoint allowlist entry."""

    __tablename__ = "endpoint_registrations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_endpoint_registrations_created_by_user_id_users",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["revoked_by_user_id"],
            ["users.id"],
            name="fk_endpoint_registrations_revoked_by_user_id_users",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "adapter IN ("
            "'github', 'gitlab', 'meta_inference', 'oidc', 's3_artifacts', "
            "'telegram', 'slack', 'discord', 'webhook', 'smtp'"
            ")",
            name="endpoint_adapter_valid",
        ),
        CheckConstraint(
            "scheme IN ('https', 'http')",
            name="endpoint_scheme_valid",
        ),
        CheckConstraint("port >= 1 AND port <= 65535", name="endpoint_port_valid"),
        CheckConstraint(
            "jsonb_typeof(cidrs_json) = 'array' AND jsonb_array_length(cidrs_json) >= 1",
            name="endpoint_cidrs_nonempty",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_endpoint_registrations_adapter_host", "adapter", "host", "port", "revoked_at"),
        Index(
            "uq_endpoint_registrations_active_target",
            "adapter",
            "scheme",
            "host",
            "port",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    adapter: Mapped[str] = mapped_column(String(32), nullable=False)
    scheme: Mapped[str] = mapped_column(String(16), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    cidrs_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    ca_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_by_user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    revoked_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class TaskJobModel(Base):
    """S-15 / JOB-01 authoritative PostgreSQL durable task queue job with lease_epoch fencing."""

    __tablename__ = "task_jobs"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_task_jobs_workspace_id_id"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_task_jobs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["cancelled_by_user_id"],
            ["users.id"],
            name="fk_task_jobs_cancelled_by_user_id_users",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "state IN ("
            "'queued', 'leased', 'running', 'succeeded', 'failed', "
            "'cancel_requested', 'cancelled', 'dead_letter'"
            ")",
            name="task_job_state_valid",
        ),
        CheckConstraint("priority >= 0 AND priority <= 1000", name="task_job_priority_bounds"),
        CheckConstraint("attempt >= 1", name="task_job_attempt_pos"),
        CheckConstraint("max_attempts >= 1", name="task_job_max_attempts_pos"),
        CheckConstraint("lease_epoch >= 0", name="task_job_lease_epoch_nonneg"),
        CheckConstraint("deadline >= not_before", name="task_job_deadline_after_not_before"),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_task_jobs_ready_queue",
            "state",
            "not_before",
            "priority",
            "created_at",
            "id",
        ),
        Index("ix_task_jobs_workspace_state", "workspace_id", "state", "created_at", "id"),
        Index("ix_task_jobs_lease_sweeper", "state", "lease_expires_at"),
        Index("ix_task_jobs_workspace_dispatch_seq", "workspace_id", "last_dispatch_seq"),
        Index(
            "uq_task_jobs_active_dedup",
            "workspace_id",
            "dedup_key",
            unique=True,
            postgresql_where=text(
                "dedup_key IS NOT NULL AND state IN "
                "('queued', 'leased', 'running', 'cancel_requested')"
            ),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    repair_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    kind: Mapped[str] = mapped_column(String(120), nullable=False)
    is_repair_job: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    resource_id: Mapped[str] = mapped_column(String(36), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    dedup_key: Mapped[str | None] = mapped_column(String(256), nullable=True)
    logical_effect_key: Mapped[str] = mapped_column(String(256), nullable=False)
    budget_key: Mapped[str | None] = mapped_column(String(256), nullable=True)
    correlation_id: Mapped[str] = mapped_column(String(120), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    lease_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_dispatch_seq: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    leased_by_worker_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_error_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_error_detail: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    cancel_reason: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    cancelled_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    recoverable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    reconcile_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class TaskAttemptModel(Base):
    """S-15 / NFR-02 per-attempt lease execution history bound to (workspace_id, job_id)."""

    __tablename__ = "task_attempts"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_task_attempts_workspace_id_id"),
        UniqueConstraint("job_id", "lease_epoch", name="uq_task_attempts_job_lease_epoch"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_task_attempts_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "job_id"],
            ["task_jobs.workspace_id", "task_jobs.id"],
            name="fk_task_attempts_workspace_job_task_jobs",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "state IN ('leased', 'running', 'succeeded', 'failed', 'cancelled', 'orphaned')",
            name="task_attempt_state_valid",
        ),
        CheckConstraint("attempt_number >= 1", name="task_attempt_number_pos"),
        CheckConstraint("lease_epoch >= 1", name="task_attempt_lease_epoch_pos"),
        Index("ix_task_attempts_job_epoch", "workspace_id", "job_id", "lease_epoch"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    job_id: Mapped[str] = mapped_column(String(36), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    lease_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    worker_id: Mapped[str] = mapped_column(String(36), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="leased")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    error_detail: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class DeadLetterJobModel(Base):
    """JOB-02 / W-08 dead-letter queue entry preserving logical_effect_key and budget_key."""

    __tablename__ = "dead_letter_jobs"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_dead_letter_jobs_workspace_id_id"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_dead_letter_jobs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "original_job_id"],
            ["task_jobs.workspace_id", "task_jobs.id"],
            name="fk_dead_letter_jobs_workspace_job_task_jobs",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["requeued_by_user_id"],
            ["users.id"],
            name="fk_dead_letter_jobs_requeued_by_user_id_users",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "status IN ('open', 'requeued', 'reconciled', 'discarded')",
            name="dlq_status_valid",
        ),
        CheckConstraint("attempts >= 1", name="dlq_attempts_pos"),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_dead_letter_jobs_workspace_status", "workspace_id", "status", "created_at", "id"),
        Index(
            "uq_dead_letter_jobs_open_per_job",
            "workspace_id",
            "original_job_id",
            unique=True,
            postgresql_where=text("status = 'open'"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    original_job_id: Mapped[str] = mapped_column(String(36), nullable=False)
    kind: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(36), nullable=False)
    logical_effect_key: Mapped[str] = mapped_column(String(256), nullable=False)
    budget_key: Mapped[str | None] = mapped_column(String(256), nullable=True)
    error_code: Mapped[str] = mapped_column(String(120), nullable=False)
    error_detail: Mapped[str] = mapped_column(String(4096), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    recoverable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    reconcile_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    requeued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    requeued_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class OperationReceiptModel(Base):
    """A-24 / S-05 durable asynchronous operation receipt enforcing originating scope."""

    __tablename__ = "operation_receipts"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_operation_receipts_workspace_id_id"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_operation_receipts_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "scope IN ('workspace', 'instance')",
            name="operation_receipt_scope_valid",
        ),
        CheckConstraint(
            "(scope = 'instance' AND workspace_id IS NULL AND repository_id IS NULL) OR "
            "(scope = 'workspace' AND workspace_id IS NOT NULL)",
            name="operation_receipt_scope_binding_valid",
        ),
        CheckConstraint(
            "required_role IN ("
            "'instance_owner', 'admin', 'maintainer', 'reviewer', 'viewer', 'auditor', 'self'"
            ")",
            name="operation_receipt_required_role_valid",
        ),
        CheckConstraint(
            "state IN ('accepted', 'running', 'succeeded', 'failed', 'unknown')",
            name="operation_receipt_state_valid",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_operation_receipts_workspace_created", "workspace_id", "created_at", "id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scope: Mapped[str] = mapped_column(String(32), nullable=False, default="workspace")
    workspace_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    repository_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    principal_id: Mapped[str] = mapped_column(String(128), nullable=False)
    required_role: Mapped[str] = mapped_column(String(32), nullable=False)
    operation_kind: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(36), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    correlation_id: Mapped[str] = mapped_column(String(120), nullable=False)
    status_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    result_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    problem_payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    logical_effect_key: Mapped[str] = mapped_column(String(256), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class ProviderConnectionModel(Base):
    """S-08 / SRC-01 workspace-scoped source provider connection (secrets stored in Z2 broker)."""

    __tablename__ = "provider_connections"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_provider_connections_workspace_id_id"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_provider_connections_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_provider_connections_created_by_user_id_users",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "provider IN ('github', 'gitlab')",
            name="provider_connection_provider_valid",
        ),
        CheckConstraint(
            "auth_mode IN ('github_app', 'gitlab_signed_v19', 'gitlab_legacy_token', "
            "'signed_webhook', 'secret_token')",
            name="provider_connection_auth_mode_valid",
        ),
        CheckConstraint(
            "status IN ("
            "'not_configured', 'checking', 'ready', 'degraded', 'revoked', 'unsupported'"
            ")",
            name="provider_connection_status_valid",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_provider_connections_workspace_created",
            "workspace_id",
            "created_at",
            "id",
        ),
        Index(
            "uq_provider_connections_active_install",
            "workspace_id",
            "provider",
            "external_installation_id",
            unique=True,
            postgresql_where=text("external_installation_id IS NOT NULL AND status <> 'revoked'"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    auth_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    app_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    client_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    external_installation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    account_login: Mapped[str | None] = mapped_column(String(120), nullable=True)
    credential_secret_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    credential_secret_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    webhook_secret_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    webhook_secret_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="not_configured")
    capabilities_json: Mapped[dict[str, str]] = mapped_column(JSONB, nullable=False, default=dict)
    granted_permissions_json: Mapped[dict[str, str]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    missing_permissions_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    vendor_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    api_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    status_detail: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    grant_review_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    had_prior_revocation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class CapabilitySnapshotModel(Base):
    """S-08 immutable observed provider capability & permission snapshot."""

    __tablename__ = "capability_snapshots"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_capability_snapshots_workspace_id_id"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_capability_snapshots_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["provider_connections.workspace_id", "provider_connections.id"],
            name="fk_capability_snapshots_tenant_conn_provider_connections",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "provider IN ('github', 'gitlab')",
            name="capability_snapshot_provider_valid",
        ),
        CheckConstraint(
            "status IN ("
            "'not_configured', 'checking', 'ready', 'degraded', 'revoked', 'unsupported'"
            ")",
            name="capability_snapshot_status_valid",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_capability_snapshots_conn_checked",
            "workspace_id",
            "connection_id",
            "checked_at",
            "id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    connection_id: Mapped[str] = mapped_column(String(36), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    capabilities_json: Mapped[dict[str, str]] = mapped_column(JSONB, nullable=False, default=dict)
    granted_permissions_json: Mapped[dict[str, str]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    missing_permissions_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    vendor_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    api_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    detail: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class ProviderInstallStateModel(Base):
    """A-23 single-use 10-minute SHA-256 hashed GitHub App installation callback state nonce."""

    __tablename__ = "provider_install_states"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_provider_install_states_workspace_id_id"),
        UniqueConstraint("state_hash", name="uq_provider_install_states_state_hash"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_provider_install_states_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["provider_connections.workspace_id", "provider_connections.id"],
            name="fk_provider_install_states_tenant_conn_provider_connections",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["initiated_by_user_id"],
            ["users.id"],
            name="fk_provider_install_states_initiated_by_user_id_users",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "provider IN ('github', 'gitlab')",
            name="provider_install_state_provider_valid",
        ),
        Index(
            "ix_provider_install_states_conn_expires",
            "workspace_id",
            "connection_id",
            "expires_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    connection_id: Mapped[str] = mapped_column(String(36), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="github")
    initiated_by_user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expected_origin: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class RepositoryModel(Base):
    """S-09 / SRC-01 workspace-scoped repository catalog entry with SEC-031 hazard metadata."""

    __tablename__ = "repositories"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_repositories_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "provider_connection_id",
            "external_repo_id",
            name="uq_repositories_ws_conn_ext_id",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_repositories_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "provider_connection_id"],
            ["provider_connections.workspace_id", "provider_connections.id"],
            name="fk_repositories_tenant_conn_provider_connections",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "visibility IN ('public', 'private', 'internal', 'unknown')",
            name="repository_visibility_valid",
        ),
        CheckConstraint(
            "mode IN ('monitor', 'approval', 'auto_repair')",
            name="repository_mode_valid",
        ),
        CheckConstraint(
            "workflow_hazard_status IN ('clean', 'flagged', 'unscanned')",
            name="repository_hazard_status_valid",
        ),
        CheckConstraint(
            "NOT (mode = 'auto_repair' AND auto_repair_blocked IS TRUE)",
            name="repository_hazard_blocks_auto_repair",
        ),
        CheckConstraint("policy_revision >= 1", name="repository_policy_revision_pos"),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_repositories_ws_name", "workspace_id", "name"),
        Index(
            "ix_repositories_ws_conn_active",
            "workspace_id",
            "provider_connection_id",
            "active",
            "created_at",
            "id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    provider_connection_id: Mapped[str] = mapped_column(String(36), nullable=False)
    external_repo_id: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    default_branch: Mapped[str] = mapped_column(String(120), nullable=False, default="main")
    visibility: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="monitor")
    paused: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    archived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_fork: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    policy_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    tags_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    workflow_hazard_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unscanned"
    )
    workflow_hazards_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    auto_repair_blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    grant_review_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class CiRunTriggerModel(Base):
    """SRC-03 / W-03 / SEC-002 normalized semantic CI run-attempt failure trigger."""

    __tablename__ = "ci_run_triggers"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_ci_run_triggers_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "repository_id",
            "provider_run_id",
            "attempt_key",
            name="uq_ci_run_triggers_semantic",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_ci_run_triggers_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["provider_connections.workspace_id", "provider_connections.id"],
            name="fk_ci_run_triggers_tenant_conn_provider_connections",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_ci_run_triggers_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "provider IN ('github', 'gitlab')",
            name="ci_run_trigger_provider_valid",
        ),
        CheckConstraint(
            "status IN ('queued', 'in_progress', 'completed', 'unknown')",
            name="ci_run_trigger_status_valid",
        ),
        CheckConstraint(
            "conclusion IN ("
            "'failure', 'timed_out', 'action_required', 'cancelled', "
            "'success', 'skipped', 'neutral', 'unknown'"
            ")",
            name="ci_run_trigger_conclusion_valid",
        ),
        CheckConstraint(
            "first_source IN ('webhook', 'poll', 'reconcile')",
            name="ci_run_trigger_source_valid",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_ci_run_triggers_ws_repo_run",
            "workspace_id",
            "repository_id",
            "provider_run_id",
            "triggered_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    connection_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_run_id: Mapped[str] = mapped_column(String(128), nullable=False)
    attempt_key: Mapped[str] = mapped_column(String(128), nullable=False)
    head_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    ref: Mapped[str] = mapped_column(String(120), nullable=False)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    conclusion: Mapped[str] = mapped_column(String(32), nullable=False, default="failure")
    jobs_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    raw_vendor_status: Mapped[str | None] = mapped_column(String(120), nullable=True)
    is_rerun: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    untrusted_fork: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    first_source: Mapped[str] = mapped_column(String(32), nullable=False)
    first_inbox_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    correlation_id: Mapped[str] = mapped_column(String(120), nullable=False)
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class WebhookInboxModel(Base):
    """SRC-03 / A-22 / NFR-01 durable verified webhook & poll delivery inbox."""

    __tablename__ = "webhook_inbox"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_webhook_inbox_workspace_id_id"),
        UniqueConstraint(
            "connection_id",
            "provider_delivery_id",
            name="uq_webhook_inbox_conn_delivery",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_webhook_inbox_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["provider_connections.workspace_id", "provider_connections.id"],
            name="fk_webhook_inbox_tenant_conn_provider_connections",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_webhook_inbox_tenant_repo_repositories",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "provider IN ('github', 'gitlab')",
            name="webhook_inbox_provider_valid",
        ),
        CheckConstraint(
            "source IN ('webhook', 'poll', 'reconcile')",
            name="webhook_inbox_source_valid",
        ),
        CheckConstraint(
            "signature_valid IS TRUE",
            name="webhook_inbox_signature_verified",
        ),
        CheckConstraint(
            "status IN ("
            "'received', 'normalized', 'duplicate_semantic', "
            "'ignored', 'reconcile_pending', 'quarantined'"
            ")",
            name="webhook_inbox_status_valid",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_webhook_inbox_ws_status_received",
            "workspace_id",
            "status",
            "received_at",
            "id",
        ),
        Index(
            "ix_webhook_inbox_conn_received",
            "workspace_id",
            "connection_id",
            "received_at",
        ),
        Index(
            "ix_webhook_inbox_retention",
            "workspace_id",
            "retention_until",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    connection_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="webhook")
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    provider_delivery_id: Mapped[str] = mapped_column(String(256), nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    provider_run_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    attempt_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    head_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="received")
    disposition_reason: Mapped[str | None] = mapped_column(String(120), nullable=True)
    sanitized_headers_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    normalized_summary_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    trigger_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    correlation_id: Mapped[str] = mapped_column(String(120), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retention_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class ProviderSyncCursorModel(Base):
    """SRC-04 / NFR-04 resumable per-repository polling checkpoint, rate-limit & gap tracker."""

    __tablename__ = "provider_sync_cursors"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_provider_sync_cursors_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "connection_id",
            "repository_id",
            name="uq_provider_sync_cursors_ws_conn_repo",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_provider_sync_cursors_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["provider_connections.workspace_id", "provider_connections.id"],
            name="fk_provider_sync_cursors_tenant_conn_provider_connections",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_provider_sync_cursors_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "provider IN ('github', 'gitlab')",
            name="provider_sync_cursor_provider_valid",
        ),
        CheckConstraint("last_stable_page >= 1", name="provider_sync_cursor_page_pos"),
        CheckConstraint(
            "overlap_seconds >= 0 AND overlap_seconds <= 3600",
            name="provider_sync_cursor_overlap_bounds",
        ),
        CheckConstraint(
            "poll_interval_seconds >= 10 AND poll_interval_seconds <= 3600",
            name="provider_sync_cursor_interval_bounds",
        ),
        CheckConstraint(
            "consecutive_failures >= 0",
            name="provider_sync_cursor_failures_nonneg",
        ),
        CheckConstraint(
            "last_status IN ("
            "'idle', 'ok', 'not_modified', 'rate_limited', 'gap_detected', 'error', 'revoked'"
            ")",
            name="provider_sync_cursor_status_valid",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_provider_sync_cursors_due",
            "workspace_id",
            "connection_id",
            "next_poll_after",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    connection_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    etag: Mapped[str | None] = mapped_column(String(512), nullable=True)
    high_water_mark_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen_run_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_stable_page: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    overlap_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    poll_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_poll_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rate_limit_remaining: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rate_limit_reset_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_status: Mapped[str] = mapped_column(String(32), nullable=False, default="idle")
    last_error_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_error_detail: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    history_gap_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    history_gap_since: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    history_gap_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    history_gap_detail: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class RepositoryPolicyModel(Base):
    """REP-02 / S-09 immutable versioned repository policy snapshot (`ADR-031`, `SEC-032`)."""

    __tablename__ = "repository_policies"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_repository_policies_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "repository_id",
            "revision",
            name="uq_repository_policies_ws_repo_rev",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_repository_policies_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_repository_policies_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_repository_policies_created_by_user_id_users",
            ondelete="RESTRICT",
        ),
        CheckConstraint("revision >= 1", name="repository_policy_revision_pos"),
        CheckConstraint(
            "mode IN ('monitor', 'approval', 'auto_repair')",
            name="repository_policy_mode_valid",
        ),
        CheckConstraint(
            "max_attempts >= 1 AND max_attempts <= 5",
            name="repository_policy_max_attempts_bounds",
        ),
        CheckConstraint(
            "max_diff_lines >= 1 AND max_diff_lines <= 2000",
            name="repository_policy_max_diff_lines_bounds",
        ),
        CheckConstraint(
            "max_calls_per_session IS NULL "
            "OR (max_calls_per_session >= 1 AND max_calls_per_session <= 100)",
            name="repository_policy_max_calls_bounds",
        ),
        CheckConstraint(
            "max_tokens_per_session IS NULL "
            "OR (max_tokens_per_session >= 1 AND max_tokens_per_session <= 1000000)",
            name="repository_policy_max_tokens_bounds",
        ),
        CheckConstraint(
            "max_wall_seconds IS NULL OR (max_wall_seconds >= 60 AND max_wall_seconds <= 7200)",
            name="repository_policy_max_wall_bounds",
        ),
        CheckConstraint(
            "max_cost_per_session_amount IS NULL OR max_cost_per_session_amount >= 0",
            name="repository_policy_max_cost_nonneg",
        ),
        CheckConstraint(
            "require_baseline IS TRUE",
            name="repository_policy_require_baseline_true",
        ),
        CheckConstraint("version = 1", name="repository_policy_immutable_version"),
        Index(
            "ix_repository_policies_ws_repo_rev_desc",
            "workspace_id",
            "repository_id",
            "revision",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="monitor")
    paused: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    branch_allowlist_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    branch_denylist_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    file_allowlist_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    file_denylist_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    sensitive_rules_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    allow_test_edits: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allow_config_edits: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    max_diff_lines: Mapped[int] = mapped_column(Integer, nullable=False, default=500)
    max_calls_per_session: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_tokens_per_session: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_wall_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_cost_per_session_amount: Mapped[Decimal | None] = mapped_column(
        Numeric(12, 4), nullable=True
    )
    max_cost_currency: Mapped[str | None] = mapped_column(String(3), nullable=True)
    require_baseline: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    inference_consent_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    runtime_profile_id: Mapped[str] = mapped_column(
        String(120), nullable=False, default="default-isolated"
    )
    change_reason: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
