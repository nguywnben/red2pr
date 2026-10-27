"""Provider connections, capability snapshots, install states, repositories & RLS.

Revision ID: 0006_provider_connections_repos
Revises: 0005_task_jobs_leases_dlq
Create Date: 2026-10-27T08:00:00Z

Implements Unit U09 (`SRC-01`, `A-06`, `A-23`, `S-08`, `S-09`, `UI-S15`, `W-02`,
`SEC-001`, `SEC-011`, `SEC-031`, `SEC-032`):
- `provider_connections`: workspace-scoped provider integration registry storing only
  opaque `Z2` `SecretBroker` secret references (`credential_secret_ref`, `webhook_secret_ref`),
  installation bindings, permission diff summaries, and revocation history.
- `capability_snapshots`: immutable observed provider capability & permission snapshots
  bound via composite tenant FK `(workspace_id, connection_id)`.
- `provider_install_states`: single-use 10-minute SHA-256 hashed OAuth / GitHub App
  installation callback state nonces bound to `(workspace_id, connection_id,
  initiated_by_user_id, expected_origin)`.
- `repositories`: workspace-scoped discovered repository catalog defaulting to
  `mode='monitor'` with `SEC-031` workflow hazard metadata and DB-enforced
  `NOT (mode = 'auto_repair' AND auto_repair_blocked IS TRUE)` invariant.
- `ENABLE` + `FORCE ROW LEVEL SECURITY` on all 4 U09 tables (`SEC-032`).
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

revision: str = "0006_provider_connections_repos"
down_revision: str | Sequence[str] | None = "0005_task_jobs_leases_dlq"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

_U09_TABLES: tuple[str, ...] = (
    "provider_connections",
    "capability_snapshots",
    "provider_install_states",
    "repositories",
)


def _resolve_app_role() -> str:
    cfg = context.config
    raw_role = cfg.attributes.get("red2pr_app_role_name") or os.environ.get(
        "RED2PR_APP_DB_ROLE", "red2pr_app"
    )
    role_name = str(raw_role).strip()
    if not _ROLE_RE.fullmatch(role_name):
        raise ValueError(f"Unsafe PostgreSQL role identifier: {role_name!r}")
    return role_name


def _migration_checksum_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def upgrade() -> None:
    app_role = _resolve_app_role()

    # 1. provider_connections (S-08 / SRC-01)
    op.create_table(
        "provider_connections",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("base_url", sa.String(length=2048), nullable=False),
        sa.Column("auth_mode", sa.String(length=32), nullable=False),
        sa.Column("app_id", sa.String(length=128), nullable=True),
        sa.Column("client_id", sa.String(length=120), nullable=True),
        sa.Column("external_installation_id", sa.String(length=128), nullable=True),
        sa.Column("account_login", sa.String(length=120), nullable=True),
        sa.Column("credential_secret_ref", sa.String(length=128), nullable=True),
        sa.Column("credential_secret_version", sa.Integer(), nullable=True),
        sa.Column("webhook_secret_ref", sa.String(length=128), nullable=True),
        sa.Column("webhook_secret_version", sa.Integer(), nullable=True),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'not_configured'"),
        ),
        sa.Column(
            "capabilities_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "granted_permissions_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "missing_permissions_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("vendor_version", sa.String(length=120), nullable=True),
        sa.Column("api_version", sa.String(length=120), nullable=True),
        sa.Column("status_detail", sa.String(length=1000), nullable=True),
        sa.Column(
            "grant_review_required",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "had_prior_revocation",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_provider_connections"),
        sa.UniqueConstraint(
            "workspace_id",
            "id",
            name="uq_provider_connections_workspace_id_id",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_provider_connections_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_provider_connections_created_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "provider IN ('github', 'gitlab')",
            name="ck_provider_connections_provider_connection_provider_valid",
        ),
        sa.CheckConstraint(
            "auth_mode IN ("
            "'github_app', 'gitlab_signed_v19', 'gitlab_legacy_token', "
            "'signed_webhook', 'secret_token'"
            ")",
            name="ck_provider_connections_provider_connection_auth_mode_valid",
        ),
        sa.CheckConstraint(
            "status IN ("
            "'not_configured', 'checking', 'ready', 'degraded', 'revoked', 'unsupported'"
            ")",
            name="ck_provider_connections_provider_connection_status_valid",
        ),
        sa.CheckConstraint("version >= 1", name="ck_provider_connections_version_pos"),
    )
    op.create_index(
        "ix_provider_connections_workspace_created",
        "provider_connections",
        ["workspace_id", "created_at", "id"],
    )
    op.create_index(
        "uq_provider_connections_active_install",
        "provider_connections",
        ["workspace_id", "provider", "external_installation_id"],
        unique=True,
        postgresql_where=sa.text("external_installation_id IS NOT NULL AND status <> 'revoked'"),
    )

    # 2. capability_snapshots (S-08)
    op.create_table(
        "capability_snapshots",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("connection_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column(
            "capabilities_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "granted_permissions_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "missing_permissions_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("vendor_version", sa.String(length=120), nullable=True),
        sa.Column("api_version", sa.String(length=120), nullable=True),
        sa.Column("detail", sa.String(length=1000), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name="pk_capability_snapshots"),
        sa.UniqueConstraint(
            "workspace_id",
            "id",
            name="uq_capability_snapshots_workspace_id_id",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_capability_snapshots_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["provider_connections.workspace_id", "provider_connections.id"],
            name="fk_capability_snapshots_tenant_conn_provider_connections",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "provider IN ('github', 'gitlab')",
            name="ck_capability_snapshots_capability_snapshot_provider_valid",
        ),
        sa.CheckConstraint(
            "status IN ("
            "'not_configured', 'checking', 'ready', 'degraded', 'revoked', 'unsupported'"
            ")",
            name="ck_capability_snapshots_capability_snapshot_status_valid",
        ),
        sa.CheckConstraint("version >= 1", name="ck_capability_snapshots_version_pos"),
    )
    op.create_index(
        "ix_capability_snapshots_conn_checked",
        "capability_snapshots",
        ["workspace_id", "connection_id", "checked_at", "id"],
    )

    # 3. provider_install_states (A-23 single-use 10m callback state nonces)
    op.create_table(
        "provider_install_states",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("connection_id", sa.String(length=36), nullable=False),
        sa.Column(
            "provider",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'github'"),
        ),
        sa.Column("initiated_by_user_id", sa.String(length=36), nullable=False),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("expected_origin", sa.String(length=2048), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_provider_install_states"),
        sa.UniqueConstraint(
            "workspace_id",
            "id",
            name="uq_provider_install_states_workspace_id_id",
        ),
        sa.UniqueConstraint("state_hash", name="uq_provider_install_states_state_hash"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_provider_install_states_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["provider_connections.workspace_id", "provider_connections.id"],
            name="fk_provider_install_states_tenant_conn_provider_connections",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["initiated_by_user_id"],
            ["users.id"],
            name="fk_provider_install_states_initiated_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "provider IN ('github', 'gitlab')",
            name="ck_provider_install_states_provider_install_state_provider_valid",
        ),
    )
    op.create_index(
        "ix_provider_install_states_conn_expires",
        "provider_install_states",
        ["workspace_id", "connection_id", "expires_at"],
    )

    # 4. repositories (S-09 / SRC-01 / SEC-031)
    op.create_table(
        "repositories",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("provider_connection_id", sa.String(length=36), nullable=False),
        sa.Column("external_repo_id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column(
            "default_branch",
            sa.String(length=120),
            nullable=False,
            server_default=sa.text("'main'"),
        ),
        sa.Column(
            "visibility",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'unknown'"),
        ),
        sa.Column(
            "mode",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'monitor'"),
        ),
        sa.Column(
            "paused",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "archived",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "is_fork",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "policy_revision",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "tags_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "workflow_hazard_status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'unscanned'"),
        ),
        sa.Column(
            "workflow_hazards_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "auto_repair_blocked",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_repositories"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_repositories_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "provider_connection_id",
            "external_repo_id",
            name="uq_repositories_ws_conn_ext_id",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_repositories_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "provider_connection_id"],
            ["provider_connections.workspace_id", "provider_connections.id"],
            name="fk_repositories_tenant_conn_provider_connections",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "visibility IN ('public', 'private', 'internal', 'unknown')",
            name="ck_repositories_repository_visibility_valid",
        ),
        sa.CheckConstraint(
            "mode IN ('monitor', 'approval', 'auto_repair')",
            name="ck_repositories_repository_mode_valid",
        ),
        sa.CheckConstraint(
            "workflow_hazard_status IN ('clean', 'flagged', 'unscanned')",
            name="ck_repositories_repository_hazard_status_valid",
        ),
        sa.CheckConstraint(
            "NOT (mode = 'auto_repair' AND auto_repair_blocked IS TRUE)",
            name="ck_repositories_repository_hazard_blocks_auto_repair",
        ),
        sa.CheckConstraint(
            "policy_revision >= 1",
            name="ck_repositories_repository_policy_revision_pos",
        ),
        sa.CheckConstraint("version >= 1", name="ck_repositories_version_pos"),
    )
    op.create_index("ix_repositories_ws_name", "repositories", ["workspace_id", "name"])
    op.create_index(
        "ix_repositories_ws_conn_active",
        "repositories",
        ["workspace_id", "provider_connection_id", "active", "created_at", "id"],
    )

    # 5. Enable + Force Row-Level Security across all U09 tables (SEC-032)
    for tbl in _U09_TABLES:
        op.execute(f"ALTER TABLE public.{tbl} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE public.{tbl} FORCE ROW LEVEL SECURITY;")

        op.execute(
            f"""
            CREATE POLICY rls_{tbl}_select ON public.{tbl}
            FOR SELECT
            USING (
                (
                    current_setting('red2pr.scope_mode', true) = 'workspace'
                    AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
                )
                OR current_setting('red2pr.scope_mode', true)
                IN ('instance_admin', 'audit_verifier')
            );
            """
        )
        op.execute(
            f"""
            CREATE POLICY rls_{tbl}_write ON public.{tbl}
            FOR ALL
            USING (
                (
                    current_setting('red2pr.scope_mode', true) = 'workspace'
                    AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
                )
                OR current_setting('red2pr.scope_mode', true) = 'instance_admin'
            )
            WITH CHECK (
                (
                    current_setting('red2pr.scope_mode', true) = 'workspace'
                    AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
                )
                OR current_setting('red2pr.scope_mode', true) = 'instance_admin'
            );
            """
        )

    # 6. Least-privilege table grants for runtime app role
    joined_tables = ", ".join(f"public.{t}" for t in _U09_TABLES)
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {joined_tables} TO "{app_role}";')

    # 7. Record expand-phase metadata in schema_migrations
    conn = op.get_bind()
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
                :parent_revision,
                'expand',
                :checksum,
                '0.1.0',
                true
            )
            """
        ),
        {
            "revision": revision,
            "parent_revision": "0005_task_jobs_leases_dlq",
            "checksum": _migration_checksum_sha256(),
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    for tbl in reversed(_U09_TABLES):
        op.drop_table(tbl)
