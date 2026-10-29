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


class ArtifactBlobModel(Base):
    """U13 / S-14 / SEC-025 / SEC-032 tenant-scoped physical encrypted blob lifecycle record."""

    __tablename__ = "artifact_blobs"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_artifact_blobs_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "digest",
            name="uq_artifact_blobs_workspace_digest",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_artifact_blobs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "storage_backend IN ('local_encrypted', 's3_encrypted')",
            name="artifact_blob_backend_valid",
        ),
        CheckConstraint(
            "blob_state IN ('staged', 'verified', 'finalized', 'quarantined', 'purged')",
            name="artifact_blob_state_valid",
        ),
        CheckConstraint("size_bytes >= 0", name="artifact_blob_size_nonneg"),
        CheckConstraint("kek_version >= 1", name="artifact_blob_kek_version_pos"),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_artifact_blobs_ws_state_created",
            "workspace_id",
            "blob_state",
            "created_at",
            "id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    storage_backend: Mapped[str] = mapped_column(String(32), nullable=False)
    storage_ref: Mapped[str] = mapped_column(String(1024), nullable=False)
    staged_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    blob_state: Mapped[str] = mapped_column(String(32), nullable=False, default="staged")
    kek_version: Mapped[int] = mapped_column(Integer, nullable=False)
    aad_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    quarantine_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class FailureFingerprintModel(Base):
    """TRI-03 / U13 historical failure signature & bounded flaky-test observation tracker."""

    __tablename__ = "failure_fingerprints"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_failure_fingerprints_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "repository_id",
            "fingerprint_hash",
            name="uq_failure_fingerprints_ws_repo_hash",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_failure_fingerprints_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_failure_fingerprints_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "classification IN ("
            "'flaky', 'persistent_failure', 'single_pass_unproven', "
            "'insufficient_history', 'unknown'"
            ")",
            name="failure_fingerprint_classification_valid",
        ),
        CheckConstraint("failure_count >= 0", name="failure_fingerprint_failures_nonneg"),
        CheckConstraint(
            "pass_on_same_sha_count >= 0",
            name="failure_fingerprint_same_sha_passes_nonneg",
        ),
        CheckConstraint(
            "distinct_sha_count >= 0",
            name="failure_fingerprint_distinct_shas_nonneg",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_failure_fingerprints_ws_repo_last_seen",
            "workspace_id",
            "repository_id",
            "last_seen_at",
            "id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    fingerprint_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_label: Mapped[str] = mapped_column(String(1000), nullable=False)
    test_identifier: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    error_kind: Mapped[str | None] = mapped_column(String(120), nullable=True)
    classification: Mapped[str] = mapped_column(
        String(32), nullable=False, default="insufficient_history"
    )
    confidence_reason: Mapped[str] = mapped_column(String(1000), nullable=False)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    pass_on_same_sha_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    distinct_sha_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    recent_observations_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class CiRunModel(Base):
    """S-10 / TRI-01 / U13 normalized attempt-pinned CI run/pipeline record."""

    __tablename__ = "ci_runs"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_ci_runs_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "repository_id",
            "external_id",
            "attempt_key",
            name="uq_ci_runs_ws_repo_ext_attempt",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_ci_runs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_ci_runs_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["provider_connections.workspace_id", "provider_connections.id"],
            name="fk_ci_runs_tenant_conn_provider_connections",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "trigger_id"],
            ["ci_run_triggers.workspace_id", "ci_run_triggers.id"],
            name="fk_ci_runs_tenant_trigger_ci_run_triggers",
            ondelete="RESTRICT",
        ),
        CheckConstraint("provider IN ('github', 'gitlab')", name="ci_run_provider_valid"),
        CheckConstraint(
            "status IN ('queued', 'in_progress', 'completed', 'unknown')",
            name="ci_run_status_valid",
        ),
        CheckConstraint(
            "conclusion IS NULL OR conclusion IN ("
            "'failure', 'timed_out', 'action_required', 'cancelled', "
            "'success', 'skipped', 'neutral', 'unknown'"
            ")",
            name="ci_run_conclusion_valid",
        ),
        CheckConstraint(
            "ingestion_state IN ("
            "'pending', 'collecting', 'ingested', 'incomplete', 'stale_sha', 'failed'"
            ")",
            name="ci_run_ingestion_state_valid",
        ),
        CheckConstraint(
            "flaky_classification IN ("
            "'flaky', 'persistent_failure', 'single_pass_unproven', "
            "'insufficient_history', 'unknown'"
            ")",
            name="ci_run_flaky_class_valid",
        ),
        CheckConstraint("attempt_number >= 1", name="ci_run_attempt_number_pos"),
        CheckConstraint("failed_job_count >= 0", name="ci_run_failed_jobs_nonneg"),
        CheckConstraint("total_job_count >= 0", name="ci_run_total_jobs_nonneg"),
        CheckConstraint("artifact_count >= 0", name="ci_run_artifacts_nonneg"),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_ci_runs_ws_repo_created",
            "workspace_id",
            "repository_id",
            "created_at",
            "id",
        ),
        Index(
            "ix_ci_runs_ws_sha",
            "workspace_id",
            "head_sha",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    connection_id: Mapped[str] = mapped_column(String(36), nullable=False)
    trigger_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    external_id: Mapped[str] = mapped_column(String(128), nullable=False)
    attempt_key: Mapped[str] = mapped_column(String(128), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    head_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_head_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    head_sha_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    ref: Mapped[str] = mapped_column(String(120), nullable=False)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    conclusion: Mapped[str | None] = mapped_column(String(32), nullable=True)
    jobs_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    raw_vendor_status: Mapped[str | None] = mapped_column(String(120), nullable=True)
    is_rerun: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    untrusted_fork: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ingestion_state: Mapped[str] = mapped_column(String(32), nullable=False, default="ingested")
    incomplete_reason: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    failed_job_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_job_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    artifact_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    flaky_classification: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    child_pipeline_ids_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class ArtifactModel(Base):
    """S-14 / A-10 / U13 workspace-scoped artifact metadata record (storage_ref internal only)."""

    __tablename__ = "artifacts"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_artifacts_workspace_id_id"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_artifacts_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_artifacts_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "run_id"],
            ["ci_runs.workspace_id", "ci_runs.id"],
            name="fk_artifacts_tenant_run_ci_runs",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "blob_id"],
            ["artifact_blobs.workspace_id", "artifact_blobs.id"],
            name="fk_artifacts_tenant_blob_artifact_blobs",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "access_class IN ('public', 'workspace_internal', 'restricted')",
            name="artifact_access_class_valid",
        ),
        CheckConstraint(
            "lifecycle_state IN ('staged', 'finalized', 'quarantined', 'expired', 'purged')",
            name="artifact_lifecycle_state_valid",
        ),
        CheckConstraint("size_bytes >= 0", name="artifact_size_nonneg"),
        CheckConstraint(
            "extracted_file_count IS NULL OR extracted_file_count >= 0",
            name="artifact_extracted_files_nonneg",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_artifacts_ws_run_created",
            "workspace_id",
            "run_id",
            "created_at",
            "id",
        ),
        Index(
            "ix_artifacts_ws_retention",
            "workspace_id",
            "retention_until",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    blob_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    manifest_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    external_artifact_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[str] = mapped_column(String(120), nullable=False)
    mime: Mapped[str] = mapped_column(String(120), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_ref: Mapped[str] = mapped_column(String(1024), nullable=False)
    redaction_version: Mapped[str] = mapped_column(String(64), nullable=False, default="v1")
    retention_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    access_class: Mapped[str] = mapped_column(
        String(32), nullable=False, default="workspace_internal"
    )
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False, default="finalized")
    extracted_file_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    purge_reason: Mapped[str | None] = mapped_column(String(120), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class CiJobModel(Base):
    """S-10 / TRI-01 / U13 normalized CI job with matrix dimensions, log ref & flaky summary."""

    __tablename__ = "ci_jobs"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_ci_jobs_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "run_id",
            "external_id",
            name="uq_ci_jobs_ws_run_ext_id",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_ci_jobs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_ci_jobs_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "run_id"],
            ["ci_runs.workspace_id", "ci_runs.id"],
            name="fk_ci_jobs_tenant_run_ci_runs",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "log_artifact_id"],
            ["artifacts.workspace_id", "artifacts.id"],
            name="fk_ci_jobs_tenant_log_artifact_artifacts",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "failure_fingerprint_id"],
            ["failure_fingerprints.workspace_id", "failure_fingerprints.id"],
            name="fk_ci_jobs_tenant_fp_failure_fingerprints",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "status IN ('queued', 'in_progress', 'completed', 'unknown')",
            name="ci_job_status_valid",
        ),
        CheckConstraint(
            "conclusion IS NULL OR conclusion IN ("
            "'failure', 'timed_out', 'action_required', 'cancelled', "
            "'success', 'skipped', 'neutral', 'unknown'"
            ")",
            name="ci_job_conclusion_valid",
        ),
        CheckConstraint(
            "log_status IN ('pending', 'available', 'truncated', 'expired', 'unavailable')",
            name="ci_job_log_status_valid",
        ),
        CheckConstraint(
            "flaky_classification IN ("
            "'flaky', 'persistent_failure', 'single_pass_unproven', "
            "'insufficient_history', 'unknown'"
            ")",
            name="ci_job_flaky_class_valid",
        ),
        CheckConstraint("log_size_bytes >= 0", name="ci_job_log_size_nonneg"),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_ci_jobs_ws_run_created",
            "workspace_id",
            "run_id",
            "created_at",
            "id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    external_id: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    stage: Mapped[str | None] = mapped_column(String(120), nullable=True)
    matrix_dimensions_json: Mapped[dict[str, str]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    retry_of_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_child_pipeline_job: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    child_pipeline_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    conclusion: Mapped[str | None] = mapped_column(String(32), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    log_artifact_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    log_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unavailable")
    log_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    log_truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    failure_excerpt: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    failure_fingerprint_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    failure_fingerprint_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    flaky_classification: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class WorkerModel(Base):
    """S-15 / SAN-01 / U14 enrolled isolated worker supervisor node (instance-scoped)."""

    __tablename__ = "workers"
    __table_args__ = (
        UniqueConstraint(
            "mtls_cert_fingerprint_sha256",
            name="uq_workers_mtls_cert_fingerprint",
        ),
        CheckConstraint(
            "status IN ('online', 'offline', 'draining', 'quarantined')",
            name="worker_status_valid",
        ),
        CheckConstraint(
            "isolation_mode IN ('oci_rootless', 'vm_isolated', 'oci_trusted_local')",
            name="worker_isolation_mode_valid",
        ),
        CheckConstraint("cpu_limit >= 1 AND cpu_limit <= 256", name="worker_cpu_bounds"),
        CheckConstraint("memory_limit_bytes >= 1", name="worker_memory_pos"),
        CheckConstraint("disk_limit_bytes >= 1", name="worker_disk_pos"),
        CheckConstraint("pids_limit >= 1 AND pids_limit <= 65536", name="worker_pids_bounds"),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_workers_status_heartbeat", "status", "heartbeat_at", "id"),
        Index("ix_workers_trust_domain", "trust_domain", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    host_id: Mapped[str] = mapped_column(String(120), nullable=False)
    trust_domain: Mapped[str] = mapped_column(String(120), nullable=False)
    isolation_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="oci_rootless")
    runtime_name: Mapped[str] = mapped_column(String(120), nullable=False)
    profile_ids_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    capabilities_json: Mapped[dict[str, bool]] = mapped_column(JSONB, nullable=False, default=dict)
    cpu_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    memory_limit_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=8_589_934_592
    )
    disk_limit_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=42_949_672_960
    )
    pids_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=512)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="online")
    heartbeat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    mtls_cert_serial: Mapped[str] = mapped_column(String(64), nullable=False)
    mtls_cert_fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    mtls_cert_pem: Mapped[str] = mapped_column(Text, nullable=False)
    mtls_cert_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    mtls_cert_revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    active_signer_key_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_workspace_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    host_escape_risk_acknowledged: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    quarantine_reason: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    drain_reason: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class WorkerEnrollmentModel(Base):
    """A-13 / U14 one-time mTLS worker enrollment token ledger (raw token never stored)."""

    __tablename__ = "worker_enrollments"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_worker_enrollments_token_hash"),
        ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_worker_enrollments_created_by_user_id_users",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["enrolled_worker_id"],
            ["workers.id"],
            name="fk_worker_enrollments_enrolled_worker_id_workers",
            ondelete="SET NULL",
        ),
        CheckConstraint(
            "isolation_mode IN ('oci_rootless', 'vm_isolated', 'oci_trusted_local')",
            name="worker_enrollment_isolation_mode_valid",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_worker_enrollments_expires_at", "expires_at", "used_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    trust_domain: Mapped[str] = mapped_column(String(120), nullable=False)
    profile_ids_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    isolation_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="oci_rootless")
    host_escape_risk_acknowledged: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    created_by_user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    enrolled_worker_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class SigningKeyModel(Base):
    """S-21 / S-22 / SEC-030 / U14 Ed25519 verification public key registry."""

    __tablename__ = "signing_keys"
    __table_args__ = (
        UniqueConstraint("key_id", name="uq_signing_keys_key_id"),
        ForeignKeyConstraint(
            ["worker_id"],
            ["workers.id"],
            name="fk_signing_keys_worker_id_workers",
            ondelete="RESTRICT",
        ),
        CheckConstraint("algorithm = 'ed25519'", name="signing_key_algorithm_ed25519"),
        CheckConstraint(
            "purpose IN ("
            "'worker_result', 'evidence_manifest', 'audit_checkpoint', 'release_manifest'"
            ")",
            name="signing_key_purpose_valid",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_signing_keys_worker_purpose", "worker_id", "purpose", "revoked_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    key_id: Mapped[str] = mapped_column(String(120), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="ed25519")
    purpose: Mapped[str] = mapped_column(String(32), nullable=False, default="worker_result")
    public_key_b64: Mapped[str] = mapped_column(String(256), nullable=False)
    worker_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    trust_domain: Mapped[str | None] = mapped_column(String(120), nullable=True)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class SandboxLeaseModel(Base):
    """S-21 / SAN-01 / U14 workspace-scoped fenced sandbox execution lease."""

    __tablename__ = "sandbox_leases"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_sandbox_leases_workspace_id_id"),
        UniqueConstraint("job_id", "lease_epoch", name="uq_sandbox_leases_job_lease_epoch"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_sandbox_leases_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_sandbox_leases_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "job_id"],
            ["task_jobs.workspace_id", "task_jobs.id"],
            name="fk_sandbox_leases_tenant_job_task_jobs",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["worker_id"],
            ["workers.id"],
            name="fk_sandbox_leases_worker_id_workers",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "status IN ("
            "'leased', 'running', 'completed', 'cancel_requested', "
            "'cancelled', 'expired', 'quarantined'"
            ")",
            name="sandbox_lease_status_valid",
        ),
        CheckConstraint("lease_epoch >= 1", name="sandbox_lease_epoch_pos"),
        CheckConstraint("profile_revision >= 1", name="sandbox_lease_profile_rev_pos"),
        CheckConstraint("output_bytes_uploaded >= 0", name="sandbox_lease_output_nonneg"),
        CheckConstraint("lease_expires_at > issued_at", name="sandbox_lease_expiry_after_issue"),
        CheckConstraint("version >= 1", name="version_pos"),
        Index("ix_sandbox_leases_ws_status_exp", "workspace_id", "status", "lease_expires_at"),
        Index("ix_sandbox_leases_worker_status", "worker_id", "status", "lease_expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repair_id: Mapped[str] = mapped_column(String(36), nullable=False)
    job_id: Mapped[str] = mapped_column(String(36), nullable=False)
    worker_id: Mapped[str] = mapped_column(String(36), nullable=False)
    lease_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    capability_nonce: Mapped[str] = mapped_column(String(120), nullable=False)
    expected_worker_trust_domain: Mapped[str] = mapped_column(String(120), nullable=False)
    profile_id: Mapped[str] = mapped_column(String(120), nullable=False)
    profile_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    image_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    base_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    source_archive_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    patch_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    network_policy_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    supervisor_policy_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    sandbox_job_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    upload_slots_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    uploaded_artifacts_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    output_bytes_uploaded: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="leased")
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    cleanup_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class ProfileRevisionModel(Base):
    """SAN-03 / U15 immutable SHA-256 pinned runner profile manifest revision."""

    __tablename__ = "profile_revisions"
    __table_args__ = (
        UniqueConstraint(
            "profile_id",
            "revision",
            name="uq_profile_revisions_profile_id_revision",
        ),
        UniqueConstraint(
            "manifest_digest",
            name="uq_profile_revisions_manifest_digest",
        ),
        CheckConstraint("revision >= 1", name="profile_revision_pos"),
        CheckConstraint(
            "ecosystem IN ('python', 'node', 'custom')",
            name="profile_ecosystem_valid",
        ),
        CheckConstraint(
            "platform IN ('linux/amd64', 'linux/arm64')",
            name="profile_platform_valid",
        ),
        CheckConstraint("version = 1", name="profile_immutable_version"),
        Index("ix_profile_revisions_profile_rev", "profile_id", "revision"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    profile_id: Mapped[str] = mapped_column(String(120), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    manifest_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False)
    platform: Mapped[str] = mapped_column(String(32), nullable=False, default="linux/amd64")
    base_image: Mapped[str] = mapped_column(String(512), nullable=False)
    image_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    requires_isolated_vm_tier: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requires_admin_opt_in: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    manifest_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class ReproductionRunModel(Base):
    """SAN-02 / ADR-031 / U15 workspace-scoped immutable Sandbox A / Sandbox B reproduction run."""

    __tablename__ = "reproduction_runs"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_reproduction_runs_workspace_id_id"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_reproduction_runs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_reproduction_runs_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "ci_run_id"],
            ["ci_runs.workspace_id", "ci_runs.id"],
            name="fk_reproduction_runs_tenant_ci_run_ci_runs",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "ci_job_id"],
            ["ci_jobs.workspace_id", "ci_jobs.id"],
            name="fk_reproduction_runs_tenant_ci_job_ci_jobs",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "baseline_reproduction_id"],
            ["reproduction_runs.workspace_id", "reproduction_runs.id"],
            name="fk_reproduction_runs_tenant_baseline_reproduction_runs",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "sandbox_job_id"],
            ["task_jobs.workspace_id", "task_jobs.id"],
            name="fk_reproduction_runs_tenant_sandbox_job_task_jobs",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "sandbox_lease_id"],
            ["sandbox_leases.workspace_id", "sandbox_leases.id"],
            name="fk_reproduction_runs_tenant_sandbox_lease_sandbox_leases",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["profile_revision_id"],
            ["profile_revisions.id"],
            name="fk_reproduction_runs_profile_revision_id_profile_revisions",
            ondelete="RESTRICT",
        ),
        CheckConstraint("phase IN ('baseline_a', 'patched_b')", name="repro_phase_valid"),
        CheckConstraint(
            "status IN ("
            "'running', 'repro_confirmed', 'repro_unconfirmed', "
            "'patched_passed', 'patched_failed', 'unsupported', 'blocked', 'cancelled'"
            ")",
            name="repro_status_valid",
        ),
        CheckConstraint(
            "fidelity_grade IN ('F1_TARGETED', 'F2_APPROX', 'F3_VALIDATED', 'FX_UNSUPPORTED')",
            name="repro_fidelity_valid",
        ),
        CheckConstraint(
            "handoff_outcome IN ("
            "'pending', 'proceed_to_patch', 'diagnosis_and_human_handoff', "
            "'unsupported_abstain', 'verified_red_to_green', 'patch_still_failing'"
            ")",
            name="repro_handoff_valid",
        ),
        CheckConstraint(
            "termination IS NULL OR termination IN ("
            "'exited', 'timeout', 'oom', 'cancelled', 'infrastructure_error'"
            ")",
            name="repro_termination_valid",
        ),
        CheckConstraint("profile_revision >= 1", name="repro_profile_rev_pos"),
        CheckConstraint(
            "executed_tests_count >= 0 AND passed_tests_count >= 0 "
            "AND failed_tests_count >= 0 AND skipped_tests_count >= 0",
            name="repro_test_counts_nonneg",
        ),
        CheckConstraint(
            "(phase = 'baseline_a' AND patch_digest IS NULL AND baseline_reproduction_id IS NULL) "
            "OR (phase = 'patched_b' AND patch_digest IS NOT NULL "
            "AND baseline_reproduction_id IS NOT NULL)",
            name="repro_phase_parity",
        ),
        CheckConstraint(
            "(NOT allow_patching) OR ("
            "phase = 'baseline_a' AND status = 'repro_confirmed' "
            "AND fidelity_grade <> 'FX_UNSUPPORTED' "
            "AND executed_tests_count > 0 AND failed_tests_count > 0 "
            "AND fingerprint_matched IS TRUE"
            ")",
            name="adr031_patching_gate",
        ),
        CheckConstraint(
            "(NOT allow_publication) OR ("
            "phase = 'patched_b' AND status = 'patched_passed' "
            "AND fidelity_grade <> 'FX_UNSUPPORTED' "
            "AND executed_tests_count > 0 AND failed_tests_count = 0 "
            "AND termination = 'exited' AND exit_code = 0"
            ")",
            name="adr031_publication_gate",
        ),
        CheckConstraint(
            "(status = 'running' AND immutable_sealed IS FALSE) "
            "OR (status <> 'running' AND immutable_sealed IS TRUE AND finished_at IS NOT NULL)",
            name="repro_sealed_when_terminal",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_reproduction_runs_ws_repair_phase",
            "workspace_id",
            "repair_id",
            "phase",
            "created_at",
        ),
        Index("ix_reproduction_runs_ws_ci_job", "workspace_id", "ci_job_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repair_id: Mapped[str] = mapped_column(String(36), nullable=False)
    ci_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    ci_job_id: Mapped[str] = mapped_column(String(36), nullable=False)
    phase: Mapped[str] = mapped_column(String(32), nullable=False)
    baseline_reproduction_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    sandbox_job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    sandbox_lease_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    profile_revision_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    profile_id: Mapped[str] = mapped_column(String(120), nullable=False)
    profile_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    profile_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    image_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    base_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    source_archive_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dependency_lock_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cache_key: Mapped[str | None] = mapped_column(String(256), nullable=True)
    patch_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    command_ids_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    command_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    environment_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expected_fingerprint_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    observed_fingerprint_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fingerprint_matched: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    executed_tests_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    passed_tests_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_tests_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    skipped_tests_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    termination: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    fidelity_grade: Mapped[str] = mapped_column(String(32), nullable=False)
    fidelity_differences_json: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    handoff_outcome: Mapped[str] = mapped_column(String(64), nullable=False)
    allow_patching: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allow_publication: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    failure_reason_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    failure_detail: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    result_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    artifact_refs_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    immutable_sealed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class WorkspaceModelConfigModel(Base):
    """U16 / A-20 workspace Meta Muse inference configuration, pricing, budgets & escalation."""

    __tablename__ = "workspace_model_configs"
    __table_args__ = (
        UniqueConstraint("workspace_id", name="uq_workspace_model_configs_workspace_id"),
        UniqueConstraint("workspace_id", "id", name="uq_workspace_model_configs_workspace_id_id"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_workspace_model_configs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["endpoint_registration_id"],
            ["endpoint_registrations.id"],
            name="fk_workspace_model_configs_endpoint_reg_endpoint_registrations",
            ondelete="SET NULL",
        ),
        ForeignKeyConstraint(
            ["active_inference_consent_id"],
            ["consents.id"],
            name="fk_workspace_model_configs_consent_id_consents",
            ondelete="SET NULL",
        ),
        ForeignKeyConstraint(
            ["updated_by_user_id"],
            ["users.id"],
            name="fk_workspace_model_configs_updated_by_user_id_users",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "suspension_reason IS NULL OR suspension_reason IN ("
            "'maintenance', 'model_unavailable', 'quota', "
            "'worker_unavailable', 'operator_pause'"
            ")",
            name="model_cfg_suspension_valid",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    endpoint_base_url: Mapped[str] = mapped_column(
        String(2048), nullable=False, default="https://api.meta.ai/v1"
    )
    endpoint_registration_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    credential_secret_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    credential_secret_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    active_inference_consent_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    pricing_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    budget_policy_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    escalation_policy_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    suspension_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status_detail: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    retry_after_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    updated_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class ModelCapabilitySnapshotModel(Base):
    """U16 / AGT-01 immutable observed capability probe snapshot for Meta Muse models."""

    __tablename__ = "model_capability_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "workspace_id", "id", name="uq_model_capability_snapshots_workspace_id_id"
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_model_capability_snapshots_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["consent_id"],
            ["consents.id"],
            name="fk_model_capability_snapshots_consent_id_consents",
            ondelete="SET NULL",
        ),
        CheckConstraint(
            "model_id IN ('muse-spark-1.3', 'muse-wonder-1.0')",
            name="model_snapshot_model_id_valid",
        ),
        CheckConstraint(
            "tier_role IN ('primary', 'escalation')",
            name="model_snapshot_tier_role_valid",
        ),
        CheckConstraint(
            "status IN ('available', 'unavailable', 'not_probed', 'degraded', 'disabled')",
            name="model_snapshot_status_valid",
        ),
        CheckConstraint(
            "suspension_reason IS NULL OR suspension_reason IN ("
            "'maintenance', 'model_unavailable', 'quota', "
            "'worker_unavailable', 'operator_pause'"
            ")",
            name="model_snapshot_suspension_valid",
        ),
        CheckConstraint(
            "retry_after_seconds IS NULL OR retry_after_seconds >= 0",
            name="model_snapshot_retry_nonneg",
        ),
        CheckConstraint("version = 1", name="model_snapshot_immutable_version"),
        Index(
            "ix_model_capability_snapshots_ws_model_probed",
            "workspace_id",
            "model_id",
            "probed_at",
            "id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    model_id: Mapped[str] = mapped_column(String(120), nullable=False)
    tier_role: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    capabilities_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    provider_request_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    consent_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    probed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status_detail: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    suspension_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    retry_after_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class BudgetAccountModel(Base):
    """U16 / AGT-03 / SEC-033 row-locked NUMERIC(18, 6) token, call, attempt & cost ledger."""

    __tablename__ = "budget_accounts"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_budget_accounts_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "scope_kind",
            "scope_key",
            name="uq_budget_accounts_ws_scope_kind_key",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_budget_accounts_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "scope_kind IN ('workspace_daily', 'workspace_total', 'repair_session', 'model_probe')",
            name="budget_scope_kind_valid",
        ),
        CheckConstraint("currency ~ '^[A-Z]{3}$'", name="budget_currency_iso"),
        CheckConstraint(
            "cost_cap >= 0 AND reserved_cost >= 0 AND settled_cost >= 0 AND unknown_cost >= 0",
            name="budget_costs_nonneg",
        ),
        CheckConstraint(
            "token_cap >= 0 AND reserved_tokens >= 0 "
            "AND settled_tokens >= 0 AND unknown_tokens >= 0",
            name="budget_tokens_nonneg",
        ),
        CheckConstraint(
            "call_cap >= 0 AND reserved_calls >= 0 AND settled_calls >= 0 AND unknown_calls >= 0",
            name="budget_calls_nonneg",
        ),
        CheckConstraint(
            "max_patch_attempts >= 0 AND patch_attempts_used >= 0 "
            "AND patch_attempts_used <= max_patch_attempts",
            name="budget_patch_attempts_bounds",
        ),
        CheckConstraint("max_wall_seconds >= 0", name="budget_wall_seconds_nonneg"),
        CheckConstraint(
            "reserved_calls = 0 OR ("
            "(reserved_cost + settled_cost + unknown_cost) <= cost_cap "
            "AND (reserved_tokens + settled_tokens + unknown_tokens) <= token_cap "
            "AND (reserved_calls + settled_calls + unknown_calls) <= call_cap"
            ")",
            name="budget_active_reservation_within_caps",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_budget_accounts_ws_scope_window",
            "workspace_id",
            "scope_kind",
            "window_started_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    repair_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    scope_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    scope_key: Mapped[str] = mapped_column(String(120), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="USD")
    cost_cap: Mapped[Decimal] = mapped_column(Numeric(18, 6), nullable=False)
    reserved_cost: Mapped[Decimal] = mapped_column(
        Numeric(18, 6), nullable=False, default=Decimal("0.000000")
    )
    settled_cost: Mapped[Decimal] = mapped_column(
        Numeric(18, 6), nullable=False, default=Decimal("0.000000")
    )
    unknown_cost: Mapped[Decimal] = mapped_column(
        Numeric(18, 6), nullable=False, default=Decimal("0.000000")
    )
    token_cap: Mapped[int] = mapped_column(Integer, nullable=False)
    reserved_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    settled_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unknown_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    call_cap: Mapped[int] = mapped_column(Integer, nullable=False)
    reserved_calls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    settled_calls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unknown_calls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_patch_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    patch_attempts_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_wall_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=1800)
    threshold_alert_emitted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class BudgetReservationModel(Base):
    """U16 / AGT-03 / SEC-033 worst-case pre-call budget reservation & settlement row."""

    __tablename__ = "budget_reservations"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_budget_reservations_workspace_id_id"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_budget_reservations_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "budget_account_id"],
            ["budget_accounts.workspace_id", "budget_accounts.id"],
            name="fk_budget_reservations_tenant_account_budget_accounts",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["consent_id"],
            ["consents.id"],
            name="fk_budget_reservations_consent_id_consents",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "model_id IN ('muse-spark-1.3', 'muse-wonder-1.0')",
            name="reservation_model_id_valid",
        ),
        CheckConstraint(
            "status IN ('reserved', 'settled', 'released', 'unknown_outcome')",
            name="reservation_status_valid",
        ),
        CheckConstraint(
            "estimated_input_tokens >= 0 AND max_output_tokens >= 0",
            name="reservation_estimated_tokens_nonneg",
        ),
        CheckConstraint(
            "(actual_input_tokens IS NULL OR actual_input_tokens >= 0) "
            "AND (actual_output_tokens IS NULL OR actual_output_tokens >= 0)",
            name="reservation_actual_tokens_nonneg",
        ),
        CheckConstraint(
            "reserved_cost >= 0 AND (settled_cost IS NULL OR settled_cost >= 0)",
            name="reservation_costs_nonneg",
        ),
        CheckConstraint(
            "status <> 'unknown_outcome' OR settled_cost IS NULL",
            name="reservation_unknown_never_settled",
        ),
        CheckConstraint("currency ~ '^[A-Z]{3}$'", name="reservation_currency_iso"),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_budget_reservations_ws_account_status",
            "workspace_id",
            "budget_account_id",
            "status",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    repair_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    budget_account_id: Mapped[str] = mapped_column(String(36), nullable=False)
    secondary_budget_account_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    consent_id: Mapped[str] = mapped_column(String(36), nullable=False)
    model_id: Mapped[str] = mapped_column(String(120), nullable=False)
    pricing_revision: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="reserved")
    estimated_input_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    max_output_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    actual_input_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actual_output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reserved_cost: Mapped[Decimal] = mapped_column(Numeric(18, 6), nullable=False)
    settled_cost: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="USD")
    provider_request_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    prompt_redacted_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    response_redacted_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tool_call_digests_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    late_after_cancel: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    correlation_id: Mapped[str] = mapped_column(String(120), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class UsageLedgerModel(Base):
    """S-17 / U16 append-only ModelUsageRecord ledger (`unknown` != `0`, zero CoT stored)."""

    __tablename__ = "usage_ledger"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_usage_ledger_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "reservation_id",
            name="uq_usage_ledger_ws_reservation_id",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_usage_ledger_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "reservation_id"],
            ["budget_reservations.workspace_id", "budget_reservations.id"],
            name="fk_usage_ledger_tenant_reservation_budget_reservations",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "model_id IN ('muse-spark-1.3', 'muse-wonder-1.0')",
            name="usage_model_id_valid",
        ),
        CheckConstraint(
            "status IN ('reserved', 'settled', 'released', 'failed', 'unknown')",
            name="usage_status_valid",
        ),
        CheckConstraint(
            "(input_tokens IS NULL OR input_tokens >= 0) "
            "AND (output_tokens IS NULL OR output_tokens >= 0)",
            name="usage_tokens_nonneg",
        ),
        CheckConstraint(
            "estimated_cost >= 0 AND (settled_cost IS NULL OR settled_cost >= 0)",
            name="usage_costs_nonneg",
        ),
        CheckConstraint(
            "status <> 'unknown' OR ("
            "settled_cost IS NULL AND input_tokens IS NULL AND output_tokens IS NULL"
            ")",
            name="usage_unknown_never_zero",
        ),
        CheckConstraint(
            "status <> 'settled' OR ("
            "settled_cost IS NOT NULL AND input_tokens IS NOT NULL AND output_tokens IS NOT NULL"
            ")",
            name="usage_settled_complete",
        ),
        CheckConstraint("currency ~ '^[A-Z]{3}$'", name="usage_currency_iso"),
        CheckConstraint("version = 1", name="usage_immutable_version"),
        Index(
            "ix_usage_ledger_ws_created",
            "workspace_id",
            "created_at",
            "id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    repair_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reservation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    provider_request_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    model_id: Mapped[str] = mapped_column(String(120), nullable=False)
    input_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    estimated_cost: Mapped[Decimal] = mapped_column(Numeric(18, 6), nullable=False)
    settled_cost: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="USD")
    pricing_revision: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(120), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class WorkspaceAgentProfileModel(Base):
    """A-20 / UI-S11 / U17 bounded workspace agent profile (no arbitrary prompt override)."""

    __tablename__ = "workspace_agent_profiles"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_workspace_agent_profiles_workspace_id_id"),
        UniqueConstraint(
            "workspace_id", "role_key", name="uq_workspace_agent_profiles_ws_role_key"
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_workspace_agent_profiles_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["updated_by_user_id"],
            ["users.id"],
            name="fk_workspace_agent_profiles_updated_by_user_id_users",
            ondelete="SET NULL",
        ),
        CheckConstraint(
            "role_key IN ('triage_diagnosis', 'bounded_patch')",
            name="agent_profile_role_key_valid",
        ),
        CheckConstraint(
            "model_id IN ('muse-spark-1.3', 'muse-wonder-1.0')",
            name="agent_profile_model_id_valid",
        ),
        CheckConstraint(
            "escalation_model_id IS NULL OR escalation_model_id = 'muse-wonder-1.0'",
            name="agent_profile_escalation_model_id_valid",
        ),
        CheckConstraint(
            "reasoning_effort IN ('low', 'medium', 'high')",
            name="agent_profile_reasoning_effort_valid",
        ),
        CheckConstraint(
            "max_steps >= 1 AND max_steps <= 16",
            name="agent_profile_max_steps_bounds",
        ),
        CheckConstraint(
            "max_tool_calls_per_step >= 1 AND max_tool_calls_per_step <= 8",
            name="agent_profile_max_tool_calls_bounds",
        ),
        CheckConstraint(
            "max_schema_repair_retries >= 0 AND max_schema_repair_retries <= 2",
            name="agent_profile_schema_retries_bounds",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    role_key: Mapped[str] = mapped_column(String(32), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False)
    model_id: Mapped[str] = mapped_column(String(120), nullable=False, default="muse-spark-1.3")
    escalation_model_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    reasoning_effort: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    allowed_tools_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    max_steps: Mapped[int] = mapped_column(Integer, nullable=False, default=8)
    max_tool_calls_per_step: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    max_schema_repair_retries: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class RepairSessionModel(Base):
    """S-11 / W-04 / W-05 / ADR-038 autonomous CI repair session aggregate."""

    __tablename__ = "repair_sessions"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_repair_sessions_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "repository_id",
            "semantic_trigger_key",
            name="uq_repair_sessions_ws_repo_trigger_key",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_repair_sessions_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_repair_sessions_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "ci_run_id"],
            ["ci_runs.workspace_id", "ci_runs.id"],
            name="fk_repair_sessions_tenant_run_ci_runs",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "budget_account_id"],
            ["budget_accounts.workspace_id", "budget_accounts.id"],
            name="fk_repair_sessions_tenant_budget_budget_accounts",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "parent_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_repair_sessions_tenant_parent_repair_sessions",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "supersedes_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_repair_sessions_tenant_supersedes_repair_sessions",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "active_reproduction_id"],
            ["reproduction_runs.workspace_id", "reproduction_runs.id"],
            name="fk_repair_sessions_tenant_repro_reproduction_runs",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "state IN ("
            "'received', 'authorized', 'collecting', 'triaging', 'diagnosed_only', "
            "'unsupported', 'reproducing', 'repro_confirmed', 'repro_unconfirmed', "
            "'blocked', 'patching', 'verifying', 'rejected', 'policy_gate', "
            "'awaiting_approval', 'expired', 'publishing', 'publish_reconcile', "
            "'needs_human', 'remote_validating', 'remote_verified', 'remote_failed', "
            "'remote_unknown', 'cancel_requested', 'cancelled'"
            ")",
            name="repair_session_state_valid",
        ),
        CheckConstraint(
            "proof_grade IN ("
            "'none', 'baseline_confirmed', 'locally_verified', 'remotely_verified'"
            ")",
            name="repair_session_proof_grade_valid",
        ),
        CheckConstraint(
            "remote_status IN ('not_published', 'pending', 'passed', 'failed', 'unknown')",
            name="repair_session_remote_status_valid",
        ),
        CheckConstraint(
            "state NOT IN ("
            "'repro_confirmed', 'patching', 'verifying', 'policy_gate', "
            "'awaiting_approval', 'publishing', 'publish_reconcile', "
            "'remote_validating', 'remote_verified', 'remote_failed', 'remote_unknown'"
            ") OR proof_grade <> 'none'",
            name="repair_session_adr031_proof_grade_gate",
        ),
        CheckConstraint("policy_revision >= 1", name="repair_session_policy_revision_pos"),
        CheckConstraint(
            "patch_attempts_count >= 0 AND patch_attempts_count <= 5",
            name="repair_session_patch_attempts_bounds",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_repair_sessions_ws_repo_created",
            "workspace_id",
            "repository_id",
            "created_at",
            "id",
        ),
        Index(
            "ix_repair_sessions_ws_state_updated",
            "workspace_id",
            "state",
            "updated_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    ci_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    parent_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    supersedes_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    semantic_trigger_key: Mapped[str] = mapped_column(String(256), nullable=False)
    base_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    target_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    policy_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="received")
    proof_grade: Mapped[str] = mapped_column(String(32), nullable=False, default="none")
    remote_status: Mapped[str] = mapped_column(String(32), nullable=False, default="not_published")
    suspension_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    budget_account_id: Mapped[str] = mapped_column(String(36), nullable=False)
    active_reproduction_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    latest_diagnosis_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    patch_attempts_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reason_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    status_detail: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    correlation_id: Mapped[str] = mapped_column(String(120), nullable=False)
    causation_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class ContextManifestModel(Base):
    """Append-only redacted context manifest isolated by tenant/repo/SHA/policy/redaction."""

    __tablename__ = "context_manifests"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_context_manifests_workspace_id_id"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_context_manifests_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_context_manifests_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repair_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_context_manifests_tenant_repair_repair_sessions",
            ondelete="CASCADE",
        ),
        CheckConstraint("policy_revision >= 1", name="context_manifest_policy_rev_pos"),
        CheckConstraint("version = 1", name="context_manifest_immutable_version"),
        Index(
            "ix_context_manifests_ws_cache_key",
            "workspace_id",
            "repository_id",
            "cache_key",
        ),
        Index(
            "ix_context_manifests_ws_repair",
            "workspace_id",
            "repair_id",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repair_id: Mapped[str] = mapped_column(String(36), nullable=False)
    base_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    redaction_version: Mapped[str] = mapped_column(String(120), nullable=False)
    cache_key: Mapped[str] = mapped_column(String(64), nullable=False)
    context_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    entries_json: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class DiagnosticModel(Base):
    """S-11 / TRI-02 / AGT-02 append-only evidence-backed failure classification & diagnosis."""

    __tablename__ = "diagnostics"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_diagnostics_workspace_id_id"),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_diagnostics_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_diagnostics_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repair_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_diagnostics_tenant_repair_repair_sessions",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "failure_class IN ("
            "'code_regression', 'test_defect', 'config', 'dependency', "
            "'flaky', 'infra', 'network', 'auth', 'unsupported', 'unknown'"
            ")",
            name="diagnostic_failure_class_valid",
        ),
        CheckConstraint(
            "decision IN ('continue', 'abstain', 'human')",
            name="diagnostic_decision_valid",
        ),
        CheckConstraint(
            "model_id IS NULL OR model_id IN ('muse-spark-1.3', 'muse-wonder-1.0')",
            name="diagnostic_model_id_valid",
        ),
        CheckConstraint(
            "schema_repair_retries_used >= 0 AND schema_repair_retries_used <= 2",
            name="diagnostic_schema_retries_bounds",
        ),
        CheckConstraint("version = 1", name="diagnostic_immutable_version"),
        Index(
            "ix_diagnostics_ws_repair_created",
            "workspace_id",
            "repair_id",
            "created_at",
            "id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repair_id: Mapped[str] = mapped_column(String(36), nullable=False)
    failure_class: Mapped[str] = mapped_column(String(32), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    summary: Mapped[str] = mapped_column(String(4000), nullable=False)
    evidence_refs_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    evidence_citations_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    hypotheses_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    uncertainties_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    proposed_profile: Mapped[str | None] = mapped_column(String(120), nullable=True)
    proposed_command_ids_json: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    fingerprint_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    provider_request_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    schema_repair_retries_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    deterministic_rule_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class AgentStepModel(Base):
    """Append-only audit trail of bounded agent steps, S-20 tool calls, and denials."""

    __tablename__ = "agent_steps"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_agent_steps_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "repair_id",
            "step_number",
            name="uq_agent_steps_ws_repair_step_number",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_agent_steps_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_agent_steps_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repair_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_agent_steps_tenant_repair_repair_sessions",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "usage_record_id"],
            ["usage_ledger.workspace_id", "usage_ledger.id"],
            name="fk_agent_steps_tenant_usage_usage_ledger",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "agent_role IN ('diagnosis', 'patch')",
            name="agent_step_role_valid",
        ),
        CheckConstraint(
            "attempt_number >= 0 AND attempt_number <= 10",
            name="agent_step_attempt_bounds",
        ),
        CheckConstraint(
            "step_number >= 1 AND step_number <= 500",
            name="agent_step_number_bounds",
        ),
        CheckConstraint(
            "step_kind IN ("
            "'model_call', 'tool_call', 'schema_repair', 'abstention', 'policy_denial'"
            ")",
            name="agent_step_kind_valid",
        ),
        CheckConstraint(
            "status IN ('ok', 'denied', 'failed', 'pending')",
            name="agent_step_status_valid",
        ),
        CheckConstraint("version = 1", name="agent_step_immutable_version"),
        Index(
            "ix_agent_steps_ws_created",
            "workspace_id",
            "created_at",
            "id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repair_id: Mapped[str] = mapped_column(String(36), nullable=False)
    agent_role: Mapped[str] = mapped_column(String(32), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    step_number: Mapped[int] = mapped_column(Integer, nullable=False)
    step_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    tool_call_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    tool_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    args_redacted_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_redacted_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    context_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    deny_reason_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    deny_explanation: Mapped[str | None] = mapped_column(String(4000), nullable=True)
    model_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    provider_request_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    usage_record_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class PatchAttemptModel(Base):
    """S-12 / AGT-02 bounded candidate patch attempt record with S-22 provenance."""

    __tablename__ = "patch_attempts"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_patch_attempts_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "repair_id",
            "attempt_number",
            name="uq_patch_attempts_ws_repair_attempt",
        ),
        ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_patch_attempts_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_patch_attempts_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repair_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_patch_attempts_tenant_repair_repair_sessions",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "diff_artifact_id"],
            ["artifacts.workspace_id", "artifacts.id"],
            name="fk_patch_attempts_tenant_artifact_artifacts",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "sandbox_reproduction_id"],
            ["reproduction_runs.workspace_id", "reproduction_runs.id"],
            name="fk_patch_attempts_tenant_repro_reproduction_runs",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "attempt_number >= 1 AND attempt_number <= 5",
            name="patch_attempt_number_bounds",
        ),
        CheckConstraint(
            "diff_lines_added >= 0 AND diff_lines_removed >= 0",
            name="patch_attempt_diff_lines_nonneg",
        ),
        CheckConstraint(
            "integrity_outcome IN ('accepted', 'rejected_policy', 'rejected_integrity')",
            name="patch_attempt_integrity_outcome_valid",
        ),
        CheckConstraint("version >= 1", name="version_pos"),
        Index(
            "ix_patch_attempts_ws_repair_created",
            "workspace_id",
            "repair_id",
            "created_at",
            "id",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repair_id: Mapped[str] = mapped_column(String(36), nullable=False)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    base_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    patch_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    diff_artifact_id: Mapped[str] = mapped_column(String(36), nullable=False)
    changed_paths_json: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    diff_lines_added: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    diff_lines_removed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    claimed_root_cause: Mapped[str] = mapped_column(String(4000), nullable=False)
    target_test_selection_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    integrity_outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    sandbox_reproduction_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    provenance_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class VerificationRunModel(Base):
    """S-12 append-only deterministic V-01..V-07 evaluation record (U18)."""

    __tablename__ = "verification_runs"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_verification_runs_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "idempotency_key",
            name="uq_verification_runs_ws_idempotency_key",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_verification_runs_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repair_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_verification_runs_tenant_repair_repair_sessions",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "status IN ('verified', 'failed', 'human_review', 'blocked', 'cancelled')",
            name="verification_run_status_valid",
        ),
        CheckConstraint(
            "proof_grade IN ('baseline_confirmed', 'locally_verified')",
            name="verification_run_proof_grade_valid",
        ),
        Index("ix_verification_runs_ws_repair_created", "workspace_id", "repair_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repair_id: Mapped[str] = mapped_column(String(36), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(120), nullable=False)
    patch_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    proof_grade: Mapped[str] = mapped_column(String(32), nullable=False)
    gates_json: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    baseline_result_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    patched_result_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class EvidenceManifestModel(Base):
    """Immutable signed S-22 manifest, tenant-bound to its verification run (U18)."""

    __tablename__ = "evidence_manifests"
    __table_args__ = (
        UniqueConstraint("workspace_id", "id", name="uq_evidence_manifests_workspace_id_id"),
        UniqueConstraint(
            "workspace_id",
            "verification_run_id",
            name="uq_evidence_manifests_ws_verification_run",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_evidence_manifests_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "repair_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_evidence_manifests_tenant_repair_repair_sessions",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["workspace_id", "verification_run_id"],
            ["verification_runs.workspace_id", "verification_runs.id"],
            name="fk_evidence_manifests_tenant_verification_run",
            ondelete="RESTRICT",
        ),
        CheckConstraint("schema_version = 1", name="evidence_manifest_version_valid"),
        Index("ix_evidence_manifests_ws_repair_created", "workspace_id", "repair_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repair_id: Mapped[str] = mapped_column(String(36), nullable=False)
    verification_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    manifest_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    signer_key_id: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
