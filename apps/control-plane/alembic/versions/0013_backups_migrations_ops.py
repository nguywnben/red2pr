"""U26 instance backups, migration operations and support bundles.

The approved plan reserves this artifact filename as ``0013``. Prior completed
units have already advanced the live Alembic graph to ``0021``; the graph
revision therefore advances to ``0022`` without rewriting migration history.
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

revision: str = "0022_backups_migrations_ops"
down_revision: str | Sequence[str] | None = "0021_retention_jobs_and_exceptions"
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


def _secure_instance_table(table: str, role: str) -> None:
    op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY rls_{table}_read ON public.{table} FOR SELECT USING "
        "(current_setting('red2pr.scope_mode', true) IN ('instance_admin','audit_verifier'))"
    )
    op.execute(
        f"CREATE POLICY rls_{table}_write ON public.{table} FOR ALL USING "
        "(current_setting('red2pr.scope_mode', true) = 'instance_admin') "
        "WITH CHECK (current_setting('red2pr.scope_mode', true) = 'instance_admin')"
    )
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.{table} TO "{role}"')


def upgrade() -> None:
    role = _role()
    op.execute(f'GRANT SELECT ON TABLE public.alembic_version TO "{role}"')
    # Instance-scoped MFA uses the broker and must see the singleton metadata.
    # This does not grant instance-scoped writes to the keyring state.
    op.execute(
        "ALTER POLICY rls_secret_keyring_state_read ON public.secret_keyring_state "
        "USING (current_setting('red2pr.scope_mode', true) IN "
        "('workspace','instance_only','instance_admin'))"
    )
    op.add_column(
        "workers",
        sa.Column(
            "protocol_versions_json",
            postgresql.JSONB(),
            nullable=False,
            server_default="[]",
        ),
    )
    op.add_column(
        "instances",
        sa.Column("maintenance_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("instances", sa.Column("maintenance_reason", sa.String(500), nullable=True))
    op.add_column("instances", sa.Column("maintenance_started_at", sa.DateTime(timezone=True)))
    op.add_column("instances", sa.Column("maintenance_started_by_user_id", sa.String(36)))
    op.create_foreign_key(
        "fk_instances_maintenance_started_by_user_id_users",
        "instances",
        "users",
        ["maintenance_started_by_user_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        "maintenance_state_valid",
        "instances",
        "(maintenance_enabled IS TRUE AND maintenance_reason IS NOT NULL) OR "
        "(maintenance_enabled IS FALSE AND maintenance_reason IS NULL)",
    )

    op.create_table(
        "backup_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("created_by_user_id", sa.String(36), nullable=False),
        sa.Column("correlation_id", sa.String(120), nullable=False),
        sa.Column("label", sa.String(120)),
        sa.Column("bundle_key", sa.String(64)),
        sa.Column("manifest_json", postgresql.JSONB()),
        sa.Column("manifest_digest", sa.String(64)),
        sa.Column("snapshot_lsn", sa.String(64)),
        sa.Column("schema_revision", sa.String(120)),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("object_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("error_code", sa.String(64)),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "state IN ('creating','succeeded','failed','expired','restoring')",
            name="backup_state_valid",
        ),
        sa.CheckConstraint(
            "size_bytes >= 0 AND object_count >= 0", name="backup_sizes_nonnegative"
        ),
        sa.CheckConstraint("version >= 1", name="version_pos"),
    )
    op.create_index("ix_backup_records_created", "backup_records", ["created_at", "id"])
    _secure_instance_table("backup_records", role)

    op.create_table(
        "migration_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("actor_user_id", sa.String(36), nullable=False),
        sa.Column("correlation_id", sa.String(120), nullable=False),
        sa.Column("current_revision", sa.String(120), nullable=False),
        sa.Column("target_revision", sa.String(120), nullable=False),
        sa.Column("target_version", sa.String(64), nullable=False),
        sa.Column("result_json", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("error_code", sa.String(64)),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "state IN ('preflight','running','succeeded','failed','blocked','rolled_back')",
            name="migration_run_state_valid",
        ),
        sa.CheckConstraint("version >= 1", name="version_pos"),
    )
    op.create_index("ix_migration_runs_created", "migration_runs", ["created_at", "id"])
    _secure_instance_table("migration_runs", role)

    op.create_table(
        "support_bundles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("actor_user_id", sa.String(36), nullable=False),
        sa.Column("correlation_id", sa.String(120), nullable=False),
        sa.Column("manifest_digest", sa.String(64), nullable=False),
        sa.Column("file_ids_json", postgresql.JSONB(), nullable=False),
        sa.Column("bundle_key", sa.String(64), nullable=False),
        sa.Column("file_count", sa.Integer(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.CheckConstraint("file_count > 0 AND size_bytes >= 0", name="support_bundle_sizes_valid"),
        sa.CheckConstraint("version >= 1", name="version_pos"),
    )
    op.create_index("ix_support_bundles_expiry", "support_bundles", ["expires_at", "id"])
    _secure_instance_table("support_bundles", role)

    schema_migrations = sa.table(
        "schema_migrations",
        sa.column("revision", sa.String()),
        sa.column("parent_revision", sa.String()),
        sa.column("phase", sa.String()),
        sa.column("checksum_sha256", sa.String()),
        sa.column("compatible_min_app_version", sa.String()),
        sa.column("reversible", sa.Boolean()),
        schema="public",
    )
    op.execute(
        schema_migrations.insert().values(
            revision=op.inline_literal(revision, type_=sa.String()),
            parent_revision=op.inline_literal(str(down_revision), type_=sa.String()),
            phase=op.inline_literal("expand", type_=sa.String()),
            checksum_sha256=op.inline_literal(_checksum(), type_=sa.String()),
            compatible_min_app_version=op.inline_literal("0.1.0", type_=sa.String()),
            reversible=op.inline_literal(True, type_=sa.Boolean()),
        )
    )


def downgrade() -> None:
    role = _role()
    op.execute(
        sa.DDL(
            'REVOKE SELECT ON TABLE public.alembic_version FROM "%(role)s"',
            context={"role": role},
        )
    )
    op.execute(
        "ALTER POLICY rls_secret_keyring_state_read ON public.secret_keyring_state "
        "USING (current_setting('red2pr.scope_mode', true) IN "
        "('workspace','instance_admin'))"
    )
    schema_migrations = sa.table(
        "schema_migrations", sa.column("revision", sa.String()), schema="public"
    )
    op.execute(
        schema_migrations.delete().where(
            schema_migrations.c.revision == op.inline_literal(revision, type_=sa.String())
        )
    )
    op.drop_table("support_bundles")
    op.drop_table("migration_runs")
    op.drop_table("backup_records")
    op.drop_column("workers", "protocol_versions_json")
    op.drop_constraint("maintenance_state_valid", "instances", type_="check")
    op.drop_constraint(
        "fk_instances_maintenance_started_by_user_id_users", "instances", type_="foreignkey"
    )
    op.drop_column("instances", "maintenance_started_by_user_id")
    op.drop_column("instances", "maintenance_started_at")
    op.drop_column("instances", "maintenance_reason")
    op.drop_column("instances", "maintenance_enabled")
