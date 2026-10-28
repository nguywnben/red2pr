"""Immutable versioned repository policies, W-02 repo review gate & RLS.

Revision ID: 0008_repository_policies
Revises: 0007_webhook_inbox_sync_cursors
Create Date: 2026-10-28T09:40:00Z

Implements Unit U12 (`REP-01`, `REP-02`, `REP-03`, `A-07`, `S-09`, `W-02`, `W-04`, `W-05`,
`W-06`, `ADR-015`, `ADR-031`, `ADR-033`, `SEC-007`, `SEC-009`, `SEC-010`, `SEC-022`,
`SEC-031`, `SEC-032`):
- Adds `grant_review_required` boolean column (`DEFAULT false`) on `repositories` so
  reconnected installations (`W-02`) retain an explicit per-repository administrative
  review gate before autonomous repair modes can be re-enabled.
- Creates `repository_policies` storing immutable versioned policy snapshots per
  `(workspace_id, repository_id, revision)` with composite tenant FK isolation,
  DB-enforced `require_baseline IS TRUE` (`ADR-031`), `version = 1`, and a PL/pgSQL
  immutability trigger blocking in-place `UPDATE` or standalone `DELETE` while allowing
  cascade teardown when the parent repository is purged.
- `ENABLE` + `FORCE ROW LEVEL SECURITY` on `repository_policies` (`SEC-032`, 36 total RLS tables).
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

from py_contracts.primitives import new_uuid7

revision: str = "0008_repository_policies"
down_revision: str | Sequence[str] | None = "0007_webhook_inbox_sync_cursors"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

_U12_TABLES: tuple[str, ...] = ("repository_policies",)


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

    # 1. Expand repositories with per-repository W-02 grant review gate
    op.add_column(
        "repositories",
        sa.Column(
            "grant_review_required",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )

    # 2. Immutable versioned repository_policies snapshots (REP-02, REP-03, S-09, ADR-031)
    op.create_table(
        "repository_policies",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
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
            "branch_allowlist_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "branch_denylist_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "file_allowlist_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "file_denylist_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "sensitive_rules_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "allow_test_edits",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "allow_config_edits",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "max_attempts",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("2"),
        ),
        sa.Column(
            "max_diff_lines",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("500"),
        ),
        sa.Column("max_calls_per_session", sa.Integer(), nullable=True),
        sa.Column("max_tokens_per_session", sa.Integer(), nullable=True),
        sa.Column("max_wall_seconds", sa.Integer(), nullable=True),
        sa.Column(
            "max_cost_per_session_amount",
            sa.Numeric(precision=12, scale=4),
            nullable=True,
        ),
        sa.Column("max_cost_currency", sa.String(length=3), nullable=True),
        sa.Column(
            "require_baseline",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("inference_consent_id", sa.String(length=36), nullable=True),
        sa.Column(
            "runtime_profile_id",
            sa.String(length=120),
            nullable=False,
            server_default=sa.text("'default-isolated'"),
        ),
        sa.Column("change_reason", sa.String(length=1000), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_repository_policies"),
        sa.UniqueConstraint(
            "workspace_id",
            "id",
            name="uq_repository_policies_workspace_id_id",
        ),
        sa.UniqueConstraint(
            "workspace_id",
            "repository_id",
            "revision",
            name="uq_repository_policies_ws_repo_rev",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_repository_policies_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_repository_policies_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_repository_policies_created_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "revision >= 1",
            name="ck_repository_policies_repository_policy_revision_pos",
        ),
        sa.CheckConstraint(
            "mode IN ('monitor', 'approval', 'auto_repair')",
            name="ck_repository_policies_repository_policy_mode_valid",
        ),
        sa.CheckConstraint(
            "max_attempts >= 1 AND max_attempts <= 5",
            name="ck_repository_policies_repository_policy_max_attempts_bounds",
        ),
        sa.CheckConstraint(
            "max_diff_lines >= 1 AND max_diff_lines <= 2000",
            name="ck_repository_policies_repository_policy_max_diff_lines_bounds",
        ),
        sa.CheckConstraint(
            "max_calls_per_session IS NULL "
            "OR (max_calls_per_session >= 1 AND max_calls_per_session <= 100)",
            name="ck_repository_policies_repository_policy_max_calls_bounds",
        ),
        sa.CheckConstraint(
            "max_tokens_per_session IS NULL "
            "OR (max_tokens_per_session >= 1 AND max_tokens_per_session <= 1000000)",
            name="ck_repository_policies_repository_policy_max_tokens_bounds",
        ),
        sa.CheckConstraint(
            "max_wall_seconds IS NULL OR (max_wall_seconds >= 60 AND max_wall_seconds <= 7200)",
            name="ck_repository_policies_repository_policy_max_wall_bounds",
        ),
        sa.CheckConstraint(
            "max_cost_per_session_amount IS NULL OR max_cost_per_session_amount >= 0",
            name="ck_repository_policies_repository_policy_max_cost_nonneg",
        ),
        sa.CheckConstraint(
            "require_baseline IS TRUE",
            name="ck_repository_policies_repository_policy_require_baseline_true",
        ),
        sa.CheckConstraint(
            "version = 1",
            name="ck_repository_policies_repository_policy_immutable_version",
        ),
    )
    op.create_index(
        "ix_repository_policies_ws_repo_rev_desc",
        "repository_policies",
        ["workspace_id", "repository_id", "revision"],
    )

    # 3. Backfill initial immutable snapshot for any existing repositories rows
    conn = op.get_bind()
    existing_repos = conn.execute(
        sa.text(
            """
            SELECT id, workspace_id, policy_revision, mode, paused, created_at
            FROM public.repositories
            ORDER BY created_at ASC, id ASC
            """
        )
    ).fetchall()
    for repo_row in existing_repos:
        created_dt = repo_row.created_at
        if not isinstance(created_dt, datetime):
            created_dt = datetime.now(tz=UTC)
        elif created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=UTC)
        conn.execute(
            sa.text(
                """
                INSERT INTO public.repository_policies (
                    id,
                    workspace_id,
                    repository_id,
                    revision,
                    mode,
                    paused,
                    require_baseline,
                    runtime_profile_id,
                    change_reason,
                    version,
                    created_at,
                    updated_at
                ) VALUES (
                    :id,
                    :workspace_id,
                    :repository_id,
                    :revision,
                    :mode,
                    :paused,
                    true,
                    'default-isolated',
                    'Initial policy snapshot backfilled by migration 0008.',
                    1,
                    :created_at,
                    :created_at
                )
                """
            ),
            {
                "id": new_uuid7(now=created_dt),
                "workspace_id": repo_row.workspace_id,
                "repository_id": repo_row.id,
                "revision": int(repo_row.policy_revision),
                "mode": str(repo_row.mode),
                "paused": bool(repo_row.paused),
                "created_at": created_dt,
            },
        )

    # 4. Append-only immutability trigger on repository_policies (allows parent cascade purge)
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.red2pr_forbid_policy_revision_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET red2pr.scope_mode = 'instance_admin'
        AS $$
        BEGIN
            IF TG_OP = 'UPDATE' THEN
                RAISE EXCEPTION
                    'append_only_table_violation: UPDATE on repository_policies is forbidden'
                    USING ERRCODE = '55000';
            END IF;
            IF TG_OP = 'DELETE' THEN
                IF EXISTS (
                    SELECT 1
                    FROM public.repositories r
                    WHERE r.workspace_id = OLD.workspace_id
                      AND r.id = OLD.repository_id
                ) THEN
                    RAISE EXCEPTION
                        'append_only_table_violation: DELETE on repository_policies is forbidden'
                        USING ERRCODE = '55000';
                END IF;
                RETURN OLD;
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_repository_policies_immutable
        BEFORE UPDATE OR DELETE ON public.repository_policies
        FOR EACH ROW EXECUTE FUNCTION public.red2pr_forbid_policy_revision_mutation();
        """
    )

    # 5. Enable + Force Row-Level Security on repository_policies (SEC-032)
    for tbl in _U12_TABLES:
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
    joined_tables = ", ".join(f"public.{t}" for t in _U12_TABLES)
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {joined_tables} TO "{app_role}";')

    # 7. Record expand-phase metadata in schema_migrations
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
            "parent_revision": "0007_webhook_inbox_sync_cursors",
            "checksum": _migration_checksum_sha256(),
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_repository_policies_immutable ON public.repository_policies;"
    )
    op.execute("DROP FUNCTION IF EXISTS public.red2pr_forbid_policy_revision_mutation();")
    for tbl in reversed(_U12_TABLES):
        op.drop_table(tbl)
    op.drop_column("repositories", "grant_review_required")
