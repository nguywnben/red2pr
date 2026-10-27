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
