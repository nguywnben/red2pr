"""U25 retryable retention deletion jobs and ADR-032 release exceptions.

Revision ID: 0021_retention_jobs_and_exceptions
Revises: 0020_reporting_projections_and_exports
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Sequence
from pathlib import Path

import sqlalchemy as sa
from alembic import context, op

revision: str = "0021_retention_jobs_and_exceptions"
down_revision: str | Sequence[str] | None = "0020_reporting_projections_and_exports"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def _role() -> str:
    role = str(
        context.config.attributes.get("red2pr_app_role_name")
        or os.environ.get("RED2PR_APP_DB_ROLE", "red2pr_app")
    ).strip()
    if not _ROLE_RE.fullmatch(role):
        raise ValueError("Unsafe PostgreSQL role identifier.")
    return role


def _checksum() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _secure_workspace_table(table: str, role: str) -> None:
    scope = (
        "(current_setting('red2pr.scope_mode', true) = 'workspace' "
        "AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), ''))"
    )
    op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY rls_{table}_select ON public.{table} FOR SELECT USING ({scope})")
    op.execute(
        f"CREATE POLICY rls_{table}_write ON public.{table} FOR ALL "
        f"USING ({scope}) WITH CHECK ({scope})"
    )
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.{table} TO "{role}"')


def upgrade() -> None:
    role = _role()
    op.create_table(
        "artifact_deletion_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("blob_id", sa.String(36), nullable=False),
        sa.Column("correlation_id", sa.String(120), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("error_code", sa.String(64)),
        sa.UniqueConstraint("workspace_id", "blob_id", name="uq_artifact_deletion_blob"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "blob_id"],
            ["artifact_blobs.workspace_id", "artifact_blobs.id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("state IN ('pending','claimed','deleted','failed')", name="state_valid"),
        sa.CheckConstraint("attempts >= 0", name="attempts_nonnegative"),
    )
    op.create_index(
        "ix_artifact_deletion_ready",
        "artifact_deletion_jobs",
        ["state", "available_at", "created_at"],
    )
    op.create_table(
        "effect_replay_guards",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("operation", sa.String(120), nullable=False),
        sa.Column("logical_effect_key_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "workspace_id",
            "operation",
            "logical_effect_key_digest",
            name="uq_effect_replay_guard_digest",
        ),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "length(logical_effect_key_digest) = 64 "
            "AND logical_effect_key_digest ~ '^[0-9a-f]{64}$'",
            name="logical_effect_digest_valid",
        ),
    )
    op.create_index(
        "ix_effect_replay_guards_workspace_operation",
        "effect_replay_guards",
        ["workspace_id", "operation"],
    )
    op.create_table(
        "release_exceptions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("finding_ref", sa.String(128), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("artifact_digest", sa.String(64), nullable=False),
        sa.Column("owner_user_id", sa.String(36), nullable=False),
        sa.Column("security_reviewer_user_id", sa.String(36), nullable=False),
        sa.Column("mitigation", sa.String(2000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["security_reviewer_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.CheckConstraint("severity = 'high'", name="severity_high_only"),
        sa.CheckConstraint(
            "length(artifact_digest) = 64 AND artifact_digest ~ '^[0-9a-f]{64}$'",
            name="artifact_digest_valid",
        ),
        sa.CheckConstraint(
            "expires_at > created_at AND expires_at <= created_at + interval '30 days'",
            name="expiry_max_30_days",
        ),
        sa.CheckConstraint(
            "owner_user_id <> security_reviewer_user_id", name="reviewer_independent"
        ),
    )
    op.create_index(
        "ix_release_exceptions_active",
        "release_exceptions",
        ["workspace_id", "finding_ref", "expires_at"],
    )
    _secure_workspace_table("artifact_deletion_jobs", role)
    _secure_workspace_table("effect_replay_guards", role)
    _secure_workspace_table("release_exceptions", role)
    op.create_table(
        "operational_alarms",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("alarm_code", sa.String(64), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("correlation_id", sa.String(120), nullable=False),
        sa.UniqueConstraint(
            "workspace_id", "alarm_code", name="uq_operational_alarms_workspace_code"
        ),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "alarm_code IN ('queue_lag','backup_failed','worker_quarantined',"
            "'storage_soft_limit','storage_hard_limit','audit_chain_mismatch')",
            name="operational_alarm_code_valid",
        ),
        sa.CheckConstraint("state IN ('firing','resolved')", name="operational_alarm_state_valid"),
        sa.CheckConstraint("version >= 1", name="version_pos"),
    )
    op.create_index(
        "ix_operational_alarms_workspace_state",
        "operational_alarms",
        ["workspace_id", "state", "alarm_code"],
    )
    _secure_workspace_table("operational_alarms", role)
    op.create_table(
        "secret_keyring_state",
        sa.Column("singleton_id", sa.String(16), primary_key=True),
        sa.Column("active_kek_version", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("singleton_id = 'global'", name="secret_keyring_singleton"),
        sa.CheckConstraint("active_kek_version >= 1", name="active_kek_version_pos"),
        sa.CheckConstraint("version >= 1", name="version_pos"),
    )
    op.execute(
        "INSERT INTO public.secret_keyring_state "
        "(singleton_id,active_kek_version,version,updated_at) "
        "SELECT 'global',COALESCE(MAX(kek_version),1),1,now() FROM public.secret_entries"
    )
    op.execute("ALTER TABLE public.secret_keyring_state ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE public.secret_keyring_state FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY rls_secret_keyring_state_read ON public.secret_keyring_state "
        "FOR SELECT USING (current_setting('red2pr.scope_mode', true) IN "
        "('workspace','instance_admin'))"
    )
    op.execute(
        "CREATE POLICY rls_secret_keyring_state_admin_write ON public.secret_keyring_state "
        "FOR ALL USING (current_setting('red2pr.scope_mode', true) = 'instance_admin') "
        "WITH CHECK (current_setting('red2pr.scope_mode', true) = 'instance_admin')"
    )
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON TABLE public.secret_keyring_state TO "{role}"')
    op.get_bind().execute(
        sa.text(
            "INSERT INTO public.schema_migrations "
            "(revision,parent_revision,phase,checksum_sha256,"
            "compatible_min_app_version,reversible) "
            "VALUES (:revision,:parent,'expand',:checksum,'0.1.0',true)"
        ),
        {"revision": revision, "parent": down_revision, "checksum": _checksum()},
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    op.drop_table("release_exceptions")
    op.drop_table("operational_alarms")
    op.drop_table("secret_keyring_state")
    op.drop_table("effect_replay_guards")
    op.drop_table("artifact_deletion_jobs")
