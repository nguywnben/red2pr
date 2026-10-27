"""Foundation persistence spine, RLS policies, outbox, idempotency & audit chain.

Revision ID: 0001_foundation_spine
Revises: None
Create Date: 2026-10-27T00:00:00Z

Implements Unit U03 (`docs/06_DATA_MODEL.md`, `SEC-032`, `SEC-037`, `NFR-01`, `NFR-07`,
`OPS-01`, `OPS-03`, `JOB-01`):
- 10 foundation tables: `instances`, `workspaces`, `secret_entries`, `idempotency_records`,
  `effect_tombstones`, `outbox_events`, `outbox_claims`, `audit_log`, `audit_checkpoints`,
  `schema_migrations`.
- Non-superuser, non-BYPASSRLS runtime role (`red2pr_app` by default) with least-privilege
  table/function grants.
- Append-only triggers & privilege restrictions forbidding `UPDATE`/`DELETE` on `audit_log`
  and `audit_checkpoints`.
- `SECURITY DEFINER` helper `red2pr_next_audit_chain_head()` serialized via transaction
  advisory lock to compute contiguous global `seq` and `prev_hash` across tenants safely.
- `ENABLE` + `FORCE ROW LEVEL SECURITY` and fail-closed tenant/scope policies on every table.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Sequence
from pathlib import Path

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision: str = "0001_foundation_spine"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

_ALL_TABLES: tuple[str, ...] = (
    "instances",
    "workspaces",
    "secret_entries",
    "idempotency_records",
    "effect_tombstones",
    "outbox_events",
    "outbox_claims",
    "audit_log",
    "audit_checkpoints",
    "schema_migrations",
)


def _resolve_app_role() -> tuple[str, str | None]:
    cfg = context.config
    raw_role = cfg.attributes.get("red2pr_app_role_name") or os.environ.get(
        "RED2PR_APP_DB_ROLE", "red2pr_app"
    )
    role_name = str(raw_role).strip()
    if not _ROLE_RE.fullmatch(role_name):
        raise ValueError(f"Unsafe PostgreSQL role identifier: {role_name!r}")

    raw_pw = cfg.attributes.get("red2pr_app_role_password")
    if raw_pw is None:
        raw_pw = os.environ.get("RED2PR_APP_DB_PASSWORD")
    password = str(raw_pw) if raw_pw is not None else None
    return role_name, password


def _migration_checksum_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def upgrade() -> None:
    app_role, app_password = _resolve_app_role()

    # 1. instances (singleton install metadata & recovery_epoch)
    op.create_table(
        "instances",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column(
            "singleton_guard",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("deployment_mode", sa.String(length=32), nullable=False),
        sa.Column("public_base_url", sa.String(length=2048), nullable=False),
        sa.Column(
            "config_revision",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "recovery_epoch",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column("initialized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "version",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_instances"),
        sa.UniqueConstraint("singleton_guard", name="uq_instances_singleton_guard"),
        sa.CheckConstraint("singleton_guard IS TRUE", name="ck_instances_singleton_guard_true"),
        sa.CheckConstraint(
            "deployment_mode IN ('local', 'server', 'distributed')",
            name="ck_instances_deployment_mode_valid",
        ),
        sa.CheckConstraint("config_revision >= 1", name="ck_instances_config_revision_pos"),
        sa.CheckConstraint("recovery_epoch >= 1", name="ck_instances_recovery_epoch_pos"),
        sa.CheckConstraint("version >= 1", name="ck_instances_version_pos"),
    )

    # 2. workspaces (multi-workspace tenant root + monotonic SSE sequence)
    op.create_table(
        "workspaces",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("slug", sa.String(length=120), nullable=False),
        sa.Column("owner_user_id", sa.String(length=36), nullable=True),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'active'"),
        ),
        sa.Column(
            "paused",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "retention_policy",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "last_event_seq",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "version",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_workspaces"),
        sa.UniqueConstraint("slug", name="uq_workspaces_slug"),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'deleting')",
            name="ck_workspaces_workspace_status_valid",
        ),
        sa.CheckConstraint("last_event_seq >= 0", name="ck_workspaces_last_event_seq_nonneg"),
        sa.CheckConstraint("version >= 1", name="ck_workspaces_version_pos"),
    )

    # 3. secret_entries (Z2 AES-256-GCM envelope-encrypted secrets)
    op.create_table(
        "secret_entries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("secret_ref", sa.String(length=128), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=True),
        sa.Column("purpose", sa.String(length=64), nullable=False),
        sa.Column(
            "active_key_version",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column("kek_version", sa.Integer(), nullable=False),
        sa.Column(
            "envelope_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "previous_envelope_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("aad_digest", sa.String(length=64), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "version",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_secret_entries"),
        sa.UniqueConstraint("secret_ref", name="uq_secret_entries_secret_ref"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_secret_entries_workspace_id_id"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_secret_entries_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "purpose IN ("
            "'provider_read', 'provider_write', 'webhook_auth', 'meta_inference', "
            "'notification_channel', 'mfa_totp', 'oidc_client', 'storage_encryption'"
            ")",
            name="ck_secret_entries_secret_purpose_valid",
        ),
        sa.CheckConstraint(
            "active_key_version >= 1",
            name="ck_secret_entries_active_key_version_pos",
        ),
        sa.CheckConstraint("kek_version >= 1", name="ck_secret_entries_kek_version_pos"),
        sa.CheckConstraint("version >= 1", name="ck_secret_entries_version_pos"),
    )
    op.create_index(
        "ix_secret_entries_workspace_purpose",
        "secret_entries",
        ["workspace_id", "purpose"],
    )

    # 4. idempotency_records (S-05 7-day response cache & atomic operation claims)
    op.create_table(
        "idempotency_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("principal_id", sa.String(length=128), nullable=False),
        sa.Column("operation", sa.String(length=120), nullable=False),
        sa.Column("idempotency_key", sa.String(length=36), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("logical_effect_key", sa.String(length=256), nullable=False),
        sa.Column("resource_id", sa.String(length=36), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("status_url", sa.String(length=2048), nullable=False),
        sa.Column("correlation_id", sa.String(length=120), nullable=False),
        sa.Column("result_id", sa.String(length=36), nullable=True),
        sa.Column(
            "response_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "problem_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "version",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_idempotency_records"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_idempotency_records_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "principal_id",
            "operation",
            "idempotency_key",
            name="uq_idempotency_records_claim_scope",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_idempotency_records_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "state IN ('accepted', 'running', 'succeeded', 'failed', 'unknown')",
            name="ck_idempotency_records_idempotency_state_valid",
        ),
        sa.CheckConstraint(
            "status_code >= 200 AND status_code <= 599",
            name="ck_idempotency_records_idempotency_status_code_valid",
        ),
        sa.CheckConstraint("version >= 1", name="ck_idempotency_records_version_pos"),
    )
    op.create_index(
        "ix_idempotency_records_workspace_expires",
        "idempotency_records",
        ["workspace_id", "expires_at"],
    )

    # 5. effect_tombstones (NFR-07 >=90d logical side-effect anti-replay ledger)
    op.create_table(
        "effect_tombstones",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("logical_effect_key", sa.String(length=256), nullable=False),
        sa.Column("operation", sa.String(length=120), nullable=False),
        sa.Column("origin_operation_id", sa.String(length=36), nullable=False),
        sa.Column("idempotency_key", sa.String(length=36), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=36), nullable=False),
        sa.Column("retained_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_effect_tombstones"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_effect_tombstones_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "operation",
            "logical_effect_key",
            name="uq_effect_tombstones_logical_effect",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_effect_tombstones_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_effect_tombstones_workspace_retained",
        "effect_tombstones",
        ["workspace_id", "retained_until"],
    )

    # 6. outbox_events (S-19 transactional domain outbox)
    op.create_table(
        "outbox_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=True),
        sa.Column("workspace_seq", sa.BigInteger(), nullable=True),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column(
            "schema_version",
            sa.SmallInteger(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column("repository_id", sa.String(length=36), nullable=True),
        sa.Column("session_id", sa.String(length=36), nullable=True),
        sa.Column("aggregate_id", sa.String(length=36), nullable=False),
        sa.Column("aggregate_version", sa.Integer(), nullable=False),
        sa.Column("correlation_id", sa.String(length=120), nullable=False),
        sa.Column("causation_id", sa.String(length=36), nullable=True),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column(
            "attempts",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=120), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_outbox_events"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_outbox_events_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "workspace_seq",
            name="uq_outbox_events_workspace_seq",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_outbox_events_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'claimed', 'published', 'dead_letter')",
            name="ck_outbox_events_outbox_status_valid",
        ),
        sa.CheckConstraint(
            "(workspace_id IS NULL AND workspace_seq IS NULL) OR "
            "(workspace_id IS NOT NULL AND workspace_seq IS NOT NULL AND workspace_seq >= 1)",
            name="ck_outbox_events_outbox_workspace_seq_consistency",
        ),
        sa.CheckConstraint("schema_version >= 1", name="ck_outbox_events_schema_version_pos"),
        sa.CheckConstraint(
            "aggregate_version >= 1",
            name="ck_outbox_events_aggregate_version_pos",
        ),
        sa.CheckConstraint("attempts >= 0", name="ck_outbox_events_attempts_nonneg"),
    )
    op.create_index(
        "ix_outbox_events_dispatch",
        "outbox_events",
        ["status", "next_attempt_at", "id"],
    )
    op.create_index(
        "ix_outbox_events_workspace_seq",
        "outbox_events",
        ["workspace_id", "workspace_seq"],
    )

    # 7. outbox_claims (fenced consumer-group claims with composite tenant FK)
    op.create_table(
        "outbox_claims",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=True),
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("consumer_group", sa.String(length=120), nullable=False),
        sa.Column("worker_id", sa.String(length=120), nullable=False),
        sa.Column(
            "lease_epoch",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_outbox_claims"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_outbox_claims_workspace_id_id"),
        sa.UniqueConstraint("event_id", "consumer_group", name="uq_outbox_claims_event_group"),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["outbox_events.id"],
            name="fk_outbox_claims_event_id_outbox_events",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "event_id"],
            ["outbox_events.workspace_id", "outbox_events.id"],
            name="fk_outbox_claims_tenant_event_outbox_events",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint("lease_epoch >= 1", name="ck_outbox_claims_lease_epoch_pos"),
    )
    op.create_index(
        "ix_outbox_claims_lease_expires",
        "outbox_claims",
        ["consumer_group", "lease_expires_at"],
    )

    # 8. audit_log (S-17 append-only SHA-256 hash-chained audit ledger)
    op.create_table(
        "audit_log",
        sa.Column("seq", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=True),
        sa.Column("repository_id", sa.String(length=36), nullable=True),
        sa.Column("actor_type", sa.String(length=32), nullable=False),
        sa.Column("actor_id", sa.String(length=120), nullable=False),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("reason_code", sa.String(length=120), nullable=False),
        sa.Column("correlation_id", sa.String(length=120), nullable=False),
        sa.Column("client_ip", sa.String(length=64), nullable=True),
        sa.Column(
            "metadata_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "version",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("seq", name="pk_audit_log"),
        sa.UniqueConstraint("id", name="uq_audit_log_id"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_audit_log_workspace_id_id"),
        sa.UniqueConstraint("entry_hash", name="uq_audit_log_entry_hash"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_audit_log_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "actor_type IN ('user', 'system', 'service', 'anonymous')",
            name="ck_audit_log_audit_actor_type_valid",
        ),
        sa.CheckConstraint(
            "decision IN ('allow', 'deny', 'error', 'reconcile')",
            name="ck_audit_log_audit_decision_valid",
        ),
        sa.CheckConstraint("version = 1", name="ck_audit_log_audit_version_immutable"),
    )
    op.create_index(
        "ix_audit_log_workspace_occurred",
        "audit_log",
        ["workspace_id", "occurred_at", "id"],
    )
    op.create_index(
        "ix_audit_log_correlation_id",
        "audit_log",
        ["correlation_id"],
    )

    # 9. audit_checkpoints (Ed25519-signed chain checkpoints)
    op.create_table(
        "audit_checkpoints",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("start_seq", sa.BigInteger(), nullable=False),
        sa.Column("end_seq", sa.BigInteger(), nullable=False),
        sa.Column("entry_count", sa.Integer(), nullable=False),
        sa.Column("first_entry_hash", sa.String(length=64), nullable=False),
        sa.Column("last_entry_hash", sa.String(length=64), nullable=False),
        sa.Column("chain_digest", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signer_key_id", sa.String(length=120), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_audit_checkpoints"),
        sa.CheckConstraint("start_seq >= 1", name="ck_audit_checkpoints_ckpt_start_seq_pos"),
        sa.CheckConstraint(
            "end_seq >= start_seq",
            name="ck_audit_checkpoints_ckpt_end_seq_ge_start",
        ),
        sa.CheckConstraint(
            "entry_count = (end_seq - start_seq + 1)",
            name="ck_audit_checkpoints_ckpt_count_consistent",
        ),
    )
    op.create_index("ix_audit_checkpoints_end_seq", "audit_checkpoints", ["end_seq"])

    # 10. schema_migrations (expand/backfill/validate/contract metadata ledger)
    op.create_table(
        "schema_migrations",
        sa.Column("revision", sa.String(length=120), nullable=False),
        sa.Column("parent_revision", sa.String(length=120), nullable=True),
        sa.Column("phase", sa.String(length=32), nullable=False),
        sa.Column("checksum_sha256", sa.String(length=64), nullable=False),
        sa.Column("compatible_min_app_version", sa.String(length=32), nullable=False),
        sa.Column(
            "reversible",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "applied_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("revision", name="pk_schema_migrations"),
        sa.CheckConstraint(
            "phase IN ('expand', 'backfill', 'validate', 'contract')",
            name="ck_schema_migrations_migration_phase_valid",
        ),
    )

    # 11. Provision non-superuser, non-BYPASSRLS runtime role
    conn = op.get_bind()
    conn.execute(
        sa.text(
            "SELECT "
            "set_config('red2pr.migration_role', CAST(:role_name AS text), true), "
            "set_config('red2pr.migration_pw', COALESCE(CAST(:role_password AS text), ''), true), "
            "set_config("
            "  'red2pr.migration_has_pw', "
            "  CASE WHEN CAST(:role_password AS text) IS NULL THEN 'false' ELSE 'true' END, "
            "  true"
            ")"
        ),
        {"role_name": app_role, "role_password": app_password},
    )
    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE
                v_role text := current_setting('red2pr.migration_role', true);
                v_has_pw boolean := current_setting('red2pr.migration_has_pw', true) = 'true';
                v_pw text := current_setting('red2pr.migration_pw', true);
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_role) THEN
                    IF v_has_pw THEN
                        EXECUTE format(
                            'CREATE ROLE %I NOSUPERUSER NOCREATEDB NOCREATEROLE '
                            'NOREPLICATION NOBYPASSRLS LOGIN PASSWORD %L',
                            v_role,
                            v_pw
                        );
                    ELSE
                        EXECUTE format(
                            'CREATE ROLE %I NOSUPERUSER NOCREATEDB NOCREATEROLE '
                            'NOREPLICATION NOBYPASSRLS NOLOGIN',
                            v_role
                        );
                    END IF;
                ELSE
                    IF v_has_pw THEN
                        EXECUTE format(
                            'ALTER ROLE %I NOSUPERUSER NOCREATEDB NOCREATEROLE '
                            'NOREPLICATION NOBYPASSRLS LOGIN PASSWORD %L',
                            v_role,
                            v_pw
                        );
                    ELSE
                        EXECUTE format(
                            'ALTER ROLE %I NOSUPERUSER NOCREATEDB NOCREATEROLE '
                            'NOREPLICATION NOBYPASSRLS',
                            v_role
                        );
                    END IF;
                END IF;
            END
            $$;
            """
        )
    )

    # 12. Append-only mutation prevention trigger for audit_log & audit_checkpoints (SEC-037)
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.red2pr_forbid_mutation_trigger()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            RAISE EXCEPTION 'append_only_table_violation: % on % is forbidden', TG_OP, TG_TABLE_NAME
                USING ERRCODE = '55000';
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_log_forbid_mutation
        BEFORE UPDATE OR DELETE ON public.audit_log
        FOR EACH ROW EXECUTE FUNCTION public.red2pr_forbid_mutation_trigger();
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_checkpoints_forbid_mutation
        BEFORE UPDATE OR DELETE ON public.audit_checkpoints
        FOR EACH ROW EXECUTE FUNCTION public.red2pr_forbid_mutation_trigger();
        """
    )

    # 13. Advisory-locked global audit chain head helper (safe across multi-tenant RLS)
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.red2pr_next_audit_chain_head()
        RETURNS TABLE(last_seq BIGINT, last_entry_hash VARCHAR(64))
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET red2pr.scope_mode = 'audit_verifier'
        AS $$
        BEGIN
            PERFORM pg_advisory_xact_lock(72940031);
            RETURN QUERY
            SELECT
                COALESCE(MAX(a.seq), 0::BIGINT),
                (SELECT b.entry_hash FROM public.audit_log b ORDER BY b.seq DESC LIMIT 1)
            FROM public.audit_log a;
        END;
        $$;
        """
    )

    # 14. Enable & FORCE Row-Level Security on ALL 10 foundation tables (SEC-032)
    for tbl in _ALL_TABLES:
        op.execute(f"ALTER TABLE public.{tbl} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE public.{tbl} FORCE ROW LEVEL SECURITY;")

    # instances RLS policies
    op.execute(
        """
        CREATE POLICY rls_instances_select ON public.instances
        FOR SELECT
        USING (
            current_setting('red2pr.scope_mode', true)
            IN ('instance_only', 'instance_admin', 'workspace', 'audit_verifier')
        );
        """
    )
    op.execute(
        """
        CREATE POLICY rls_instances_write ON public.instances
        FOR ALL
        USING (current_setting('red2pr.scope_mode', true) = 'instance_admin')
        WITH CHECK (current_setting('red2pr.scope_mode', true) = 'instance_admin');
        """
    )

    # workspaces RLS policies
    op.execute(
        """
        CREATE POLICY rls_workspaces_select ON public.workspaces
        FOR SELECT
        USING (
            current_setting('red2pr.scope_mode', true) = 'instance_admin'
            OR (
                current_setting('red2pr.scope_mode', true) = 'workspace'
                AND id = NULLIF(current_setting('red2pr.workspace_id', true), '')
            )
        );
        """
    )
    op.execute(
        """
        CREATE POLICY rls_workspaces_update ON public.workspaces
        FOR UPDATE
        USING (
            current_setting('red2pr.scope_mode', true) = 'instance_admin'
            OR (
                current_setting('red2pr.scope_mode', true) = 'workspace'
                AND id = NULLIF(current_setting('red2pr.workspace_id', true), '')
            )
        )
        WITH CHECK (
            current_setting('red2pr.scope_mode', true) = 'instance_admin'
            OR (
                current_setting('red2pr.scope_mode', true) = 'workspace'
                AND id = NULLIF(current_setting('red2pr.workspace_id', true), '')
            )
        );
        """
    )
    op.execute(
        """
        CREATE POLICY rls_workspaces_insert ON public.workspaces
        FOR INSERT
        WITH CHECK (current_setting('red2pr.scope_mode', true) = 'instance_admin');
        """
    )
    op.execute(
        """
        CREATE POLICY rls_workspaces_delete ON public.workspaces
        FOR DELETE
        USING (current_setting('red2pr.scope_mode', true) = 'instance_admin');
        """
    )

    # Strict workspace-only tables: idempotency_records, effect_tombstones
    for ws_only_tbl in ("idempotency_records", "effect_tombstones"):
        op.execute(
            f"""
            CREATE POLICY rls_{ws_only_tbl}_tenant_isolation ON public.{ws_only_tbl}
            FOR ALL
            USING (
                current_setting('red2pr.scope_mode', true) = 'workspace'
                AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
            )
            WITH CHECK (
                current_setting('red2pr.scope_mode', true) = 'workspace'
                AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
            );
            """
        )

    # Dual workspace-or-instance-null tables: secret_entries, outbox_events, outbox_claims
    for dual_tbl in ("secret_entries", "outbox_events", "outbox_claims"):
        op.execute(
            f"""
            CREATE POLICY rls_{dual_tbl}_tenant_isolation ON public.{dual_tbl}
            FOR ALL
            USING (
                (
                    current_setting('red2pr.scope_mode', true) = 'workspace'
                    AND workspace_id IS NOT NULL
                    AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
                )
                OR (
                    current_setting('red2pr.scope_mode', true)
                    IN ('instance_only', 'instance_admin')
                    AND workspace_id IS NULL
                )
            )
            WITH CHECK (
                (
                    current_setting('red2pr.scope_mode', true) = 'workspace'
                    AND workspace_id IS NOT NULL
                    AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
                )
                OR (
                    current_setting('red2pr.scope_mode', true)
                    IN ('instance_only', 'instance_admin')
                    AND workspace_id IS NULL
                )
            );
            """
        )

    # audit_log append-only RLS policies
    op.execute(
        """
        CREATE POLICY rls_audit_log_select ON public.audit_log
        FOR SELECT
        USING (
            (
                current_setting('red2pr.scope_mode', true) = 'workspace'
                AND workspace_id IS NOT NULL
                AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
            )
            OR (
                current_setting('red2pr.scope_mode', true) IN ('instance_only', 'instance_admin')
                AND workspace_id IS NULL
            )
            OR current_setting('red2pr.scope_mode', true) = 'audit_verifier'
        );
        """
    )
    op.execute(
        """
        CREATE POLICY rls_audit_log_insert ON public.audit_log
        FOR INSERT
        WITH CHECK (
            (
                current_setting('red2pr.scope_mode', true) = 'workspace'
                AND workspace_id IS NOT NULL
                AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
            )
            OR (
                current_setting('red2pr.scope_mode', true)
                IN ('instance_only', 'instance_admin', 'audit_verifier')
                AND workspace_id IS NULL
            )
        );
        """
    )

    # audit_checkpoints append-only RLS policies
    op.execute(
        """
        CREATE POLICY rls_audit_checkpoints_select ON public.audit_checkpoints
        FOR SELECT
        USING (
            current_setting('red2pr.scope_mode', true)
            IN ('audit_verifier', 'instance_admin', 'instance_only')
        );
        """
    )
    op.execute(
        """
        CREATE POLICY rls_audit_checkpoints_insert ON public.audit_checkpoints
        FOR INSERT
        WITH CHECK (current_setting('red2pr.scope_mode', true) = 'audit_verifier');
        """
    )

    # schema_migrations read-only RLS policy for runtime status/doctor checks
    op.execute(
        """
        CREATE POLICY rls_schema_migrations_select ON public.schema_migrations
        FOR SELECT
        USING (
            current_setting('red2pr.scope_mode', true)
            IN ('instance_only', 'instance_admin', 'audit_verifier')
        );
        """
    )

    # 15. Least-privilege table & function grants for runtime app role
    op.execute(f'GRANT USAGE ON SCHEMA public TO "{app_role}";')
    op.execute(
        f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE '
        f'public.instances, public.workspaces, public.secret_entries, '
        f'public.idempotency_records, public.effect_tombstones, '
        f'public.outbox_events, public.outbox_claims '
        f'TO "{app_role}";'
    )
    op.execute(f'REVOKE ALL ON TABLE public.audit_log, public.audit_checkpoints FROM "{app_role}";')
    op.execute(
        f'GRANT SELECT, INSERT ON TABLE public.audit_log, public.audit_checkpoints '
        f'TO "{app_role}";'
    )
    op.execute(f'REVOKE ALL ON TABLE public.schema_migrations FROM "{app_role}";')
    op.execute(f'GRANT SELECT ON TABLE public.schema_migrations TO "{app_role}";')
    op.execute("REVOKE ALL ON FUNCTION public.red2pr_next_audit_chain_head() FROM PUBLIC;")
    op.execute(
        f'GRANT EXECUTE ON FUNCTION public.red2pr_next_audit_chain_head() TO "{app_role}";'
    )

    # 16. Record expand-phase metadata in schema_migrations
    conn.execute(
        sa.text(
            """
            INSERT INTO public.schema_migrations (
                revision,
                parent_revision,
                phase,
                checksum_sha256,
                compatible_min_app_version,
                reversible
            ) VALUES (
                :revision,
                NULL,
                'expand',
                :checksum,
                '0.1.0',
                true
            )
            """
        ),
        {
            "revision": revision,
            "checksum": _migration_checksum_sha256(),
        },
    )


def downgrade() -> None:
    app_role, _ = _resolve_app_role()

    op.execute("DROP FUNCTION IF EXISTS public.red2pr_next_audit_chain_head() CASCADE;")
    op.execute("DROP FUNCTION IF EXISTS public.red2pr_forbid_mutation_trigger() CASCADE;")

    for tbl in reversed(_ALL_TABLES):
        op.drop_table(tbl)

    conn = op.get_bind()
    conn.execute(
        sa.text("SELECT set_config('red2pr.migration_role', CAST(:role_name AS text), true)"),
        {"role_name": app_role},
    )
    conn.execute(
        sa.text(
            """
            DO $$
            DECLARE
                v_role text := current_setting('red2pr.migration_role', true);
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_role) THEN
                    EXECUTE format('REVOKE USAGE ON SCHEMA public FROM %I', v_role);
                END IF;
            END
            $$;
            """
        )
    )
