"""Multi-workspace memberships, invitations, repo grants, break-glass & RLS.

Revision ID: 0003_workspaces_rbac_grants
Revises: 0002_iam_users_sessions_mfa
Create Date: 2026-10-27T02:00:00Z

Implements Unit U06 (`IAM-02`, `A-04`, `A-05`, `A-21`, `S-07`, `W-01`, `ADR-030`,
`ADR-034`, `ADR-038`, `SEC-010`, `SEC-022`, `SEC-032`, `SEC-038`):
- `memberships`: workspace-scoped RBAC roles (`admin`, `maintainer`, `reviewer`,
  `viewer`, `auditor`) with composite `(workspace_id, id)` uniqueness.
- `invitations`: email-bound single-use workspace invitations with SHA-256 `token_hash`
  and partial unique index on pending `(workspace_id, email)`.
- `repo_grants`: deny-by-default per-repository grants with composite tenant FK
  `(workspace_id, membership_id) -> memberships(workspace_id, id)` and cross-workspace
  repository binding guard.
- `break_glass_grants`: time-bounded audited instance-owner break-glass read grants.
- `trg_memberships_protect_last_admin`: advisory-locked + row-locked invariant trigger
  preventing removal or demotion of the last active workspace `admin`.
- `red2pr_bump_user_grant_epoch()`: narrow `SECURITY DEFINER` function allowing atomic
  `users.grant_epoch` increments from workspace-scoped transactions without granting
  general `UPDATE` privileges on `users` to workspace RLS scope.
- `ENABLE` + `FORCE ROW LEVEL SECURITY` on all U06 tables (`SEC-032`).
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

revision: str = "0003_workspaces_rbac_grants"
down_revision: str | Sequence[str] | None = "0002_iam_users_sessions_mfa"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

_U06_TABLES: tuple[str, ...] = (
    "memberships",
    "invitations",
    "repo_grants",
    "break_glass_grants",
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

    # 1. memberships (S-07 workspace RBAC roles including auditor per ADR-038)
    op.create_table(
        "memberships",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("invited_by_user_id", sa.String(length=36), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_memberships"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_memberships_workspace_id_id"),
        sa.UniqueConstraint("workspace_id", "user_id", name="uq_memberships_workspace_user"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_memberships_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_memberships_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["invited_by_user_id"],
            ["users.id"],
            name="fk_memberships_invited_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "role IN ('admin', 'maintainer', 'reviewer', 'viewer', 'auditor')",
            name="ck_memberships_membership_role_valid",
        ),
        sa.CheckConstraint("version >= 1", name="ck_memberships_version_pos"),
    )
    op.create_index(
        "ix_memberships_user_workspace",
        "memberships",
        ["user_id", "workspace_id"],
    )
    op.create_index(
        "ix_memberships_workspace_created",
        "memberships",
        ["workspace_id", "created_at", "id"],
    )

    # 2. invitations (S-07 email-bound single-use local workspace invitations, SEC-038)
    op.create_table(
        "invitations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "repository_grants_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column("invited_by_user_id", sa.String(length=36), nullable=False),
        sa.Column("accepted_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_invitations"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_invitations_workspace_id_id"),
        sa.UniqueConstraint("token_hash", name="uq_invitations_token_hash"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_invitations_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["invited_by_user_id"],
            ["users.id"],
            name="fk_invitations_invited_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["accepted_by_user_id"],
            ["users.id"],
            name="fk_invitations_accepted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "role IN ('admin', 'maintainer', 'reviewer', 'viewer', 'auditor')",
            name="ck_invitations_invitation_role_valid",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'accepted', 'expired', 'revoked')",
            name="ck_invitations_invitation_status_valid",
        ),
        sa.CheckConstraint("version >= 1", name="ck_invitations_version_pos"),
    )
    op.create_index(
        "ix_invitations_workspace_status",
        "invitations",
        ["workspace_id", "status", "created_at", "id"],
    )
    op.create_index(
        "uq_invitations_workspace_email_pending",
        "invitations",
        ["workspace_id", "email"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )

    # 3. repo_grants (deny-by-default per-repository grants with composite tenant FK)
    op.create_table(
        "repo_grants",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("membership_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("granted_by_user_id", sa.String(length=36), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_repo_grants"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_repo_grants_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "membership_id",
            "repository_id",
            name="uq_repo_grants_ws_member_repo",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_repo_grants_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "membership_id"],
            ["memberships.workspace_id", "memberships.id"],
            name="fk_repo_grants_tenant_membership_memberships",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["granted_by_user_id"],
            ["users.id"],
            name="fk_repo_grants_granted_by_user_id_users",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_repo_grants_ws_repo",
        "repo_grants",
        ["workspace_id", "repository_id"],
    )

    # 4. break_glass_grants (ADR-034 time-bounded audited instance-owner break-glass grants)
    op.create_table(
        "break_glass_grants",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("reason", sa.String(length=512), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name="pk_break_glass_grants"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_break_glass_grants_workspace_id_id"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_break_glass_grants_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_break_glass_grants_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("version >= 1", name="ck_break_glass_grants_version_pos"),
    )
    op.create_index(
        "ix_break_glass_grants_ws_user_expires",
        "break_glass_grants",
        ["workspace_id", "user_id", "expires_at"],
    )
    op.create_index(
        "ix_break_glass_grants_user_expires",
        "break_glass_grants",
        ["user_id", "expires_at"],
    )

    # 5. Widen auth_rate_limits check constraint for invitation rate limiting (SEC-038)
    op.drop_constraint(
        "ck_auth_rate_limits_auth_rate_action_valid",
        "auth_rate_limits",
        type_="check",
    )
    op.create_check_constraint(
        "ck_auth_rate_limits_auth_rate_action_valid",
        "auth_rate_limits",
        "action IN ("
        "'login', 'step_up', 'recovery', 'bootstrap_claim', 'mfa_verify', "
        "'invite_create', 'invite_accept'"
        ")",
    )

    # 6. Narrow SECURITY DEFINER helper to bump users.grant_epoch from workspace transactions
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.red2pr_bump_user_grant_epoch(p_user_id VARCHAR(36))
        RETURNS INTEGER
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET red2pr.scope_mode = 'instance_only'
        AS $$
        DECLARE
            v_new_epoch INTEGER;
        BEGIN
            UPDATE public.users
            SET grant_epoch = grant_epoch + 1,
                version = version + 1,
                updated_at = now()
            WHERE id = p_user_id
            RETURNING grant_epoch INTO v_new_epoch;
            IF v_new_epoch IS NULL THEN
                RAISE EXCEPTION 'user_not_found: cannot bump grant_epoch for missing user'
                    USING ERRCODE = 'P0002';
            END IF;
            RETURN v_new_epoch;
        END;
        $$;
        """
    )
    op.execute("REVOKE ALL ON FUNCTION public.red2pr_bump_user_grant_epoch(VARCHAR) FROM PUBLIC;")
    op.execute(
        f'GRANT EXECUTE ON FUNCTION public.red2pr_bump_user_grant_epoch(VARCHAR) TO "{app_role}";'
    )

    # 7. Last-admin protection trigger on memberships (SEC-038, W-01)
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.red2pr_protect_last_workspace_admin()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET red2pr.scope_mode = 'instance_admin'
        AS $$
        DECLARE
            v_ws_status VARCHAR(32);
            v_remaining BIGINT;
        BEGIN
            IF OLD.role = 'admin' THEN
                IF TG_OP = 'DELETE'
                   OR NEW.role <> 'admin'
                   OR NEW.workspace_id <> OLD.workspace_id THEN
                    PERFORM pg_advisory_xact_lock(hashtext('ws_admin:' || OLD.workspace_id));
                    SELECT status INTO v_ws_status
                    FROM public.workspaces
                    WHERE id = OLD.workspace_id;

                    IF v_ws_status IS NOT NULL AND v_ws_status <> 'deleting' THEN
                        SELECT COUNT(*) INTO v_remaining
                        FROM (
                            SELECT m.id
                            FROM public.memberships m
                            JOIN public.users u ON u.id = m.user_id
                            WHERE m.workspace_id = OLD.workspace_id
                              AND m.role = 'admin'
                              AND m.id <> OLD.id
                              AND u.status = 'active'
                            FOR UPDATE OF m
                        ) AS remaining_admins;

                        IF v_remaining = 0 THEN
                            RAISE EXCEPTION
                                'last_admin: workspace must retain at least one active admin'
                                USING ERRCODE = '55000';
                        END IF;
                    END IF;
                END IF;
            END IF;
            IF TG_OP = 'DELETE' THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_memberships_protect_last_admin
        BEFORE UPDATE OR DELETE ON public.memberships
        FOR EACH ROW EXECUTE FUNCTION public.red2pr_protect_last_workspace_admin();
        """
    )

    # 8. Cross-workspace repository_id binding guard on repo_grants (SEC-032)
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.red2pr_forbid_cross_workspace_repo_grant()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET red2pr.scope_mode = 'instance_admin'
        AS $$
        DECLARE
            v_conflict BOOLEAN;
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtext('repo_grant_ws:' || NEW.repository_id));
            SELECT EXISTS (
                SELECT 1
                FROM public.repo_grants rg
                WHERE rg.repository_id = NEW.repository_id
                  AND rg.workspace_id <> NEW.workspace_id
                  AND rg.id <> NEW.id
            ) INTO v_conflict;

            IF NOT v_conflict AND to_regclass('public.repositories') IS NOT NULL THEN
                EXECUTE
                    'SELECT EXISTS (SELECT 1 FROM public.repositories r '
                    'WHERE r.id = $1 AND r.workspace_id <> $2)'
                INTO v_conflict
                USING NEW.repository_id, NEW.workspace_id;
            END IF;

            IF v_conflict THEN
                RAISE EXCEPTION
                    'cross_workspace_repository_grant: repository_id belongs to another workspace'
                    USING ERRCODE = '23503';
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_repo_grants_forbid_cross_workspace_repo
        BEFORE INSERT OR UPDATE ON public.repo_grants
        FOR EACH ROW EXECUTE FUNCTION public.red2pr_forbid_cross_workspace_repo_grant();
        """
    )

    # 9. Enable & FORCE Row-Level Security on all U06 tables (SEC-032)
    for tbl in _U06_TABLES:
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
                OR current_setting('red2pr.scope_mode', true) IN (
                    'instance_admin', 'audit_verifier'
                )
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

    # 10. Least-privilege table grants for runtime app role
    joined_tables = ", ".join(f"public.{t}" for t in _U06_TABLES)
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {joined_tables} TO "{app_role}";')

    # 11. Record expand-phase metadata in schema_migrations
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
            "parent_revision": "0002_iam_users_sessions_mfa",
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
        "DROP TRIGGER IF EXISTS trg_repo_grants_forbid_cross_workspace_repo ON public.repo_grants;"
    )
    op.execute("DROP FUNCTION IF EXISTS public.red2pr_forbid_cross_workspace_repo_grant();")

    op.execute("DROP TRIGGER IF EXISTS trg_memberships_protect_last_admin ON public.memberships;")
    op.execute("DROP FUNCTION IF EXISTS public.red2pr_protect_last_workspace_admin();")

    op.execute("DROP FUNCTION IF EXISTS public.red2pr_bump_user_grant_epoch(VARCHAR);")

    conn.execute(
        sa.text(
            "DELETE FROM public.auth_rate_limits WHERE action IN ('invite_create', 'invite_accept')"
        )
    )
    op.drop_constraint(
        "ck_auth_rate_limits_auth_rate_action_valid",
        "auth_rate_limits",
        type_="check",
    )
    op.create_check_constraint(
        "ck_auth_rate_limits_auth_rate_action_valid",
        "auth_rate_limits",
        "action IN ('login', 'step_up', 'recovery', 'bootstrap_claim', 'mfa_verify')",
    )

    for tbl in reversed(_U06_TABLES):
        op.drop_table(tbl)
