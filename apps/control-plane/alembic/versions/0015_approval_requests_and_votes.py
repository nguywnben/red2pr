"""Tenant-scoped approval requests and immutable decisions (U19).

Revision ID: 0015_approval_requests_and_votes
Revises: 0014_verification_runs_and_manifests
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Sequence
from pathlib import Path

import sqlalchemy as sa
from alembic import context, op

revision: str = "0015_approval_requests_and_votes"
down_revision: str | Sequence[str] | None = "0014_verification_runs_and_manifests"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
_TABLES = ("approval_requests", "approval_votes")
_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def _resolve_app_role() -> str:
    raw = context.config.attributes.get("red2pr_app_role_name") or os.environ.get(
        "RED2PR_APP_DB_ROLE", "red2pr_app"
    )
    role = str(raw).strip()
    if not _ROLE_RE.fullmatch(role):
        raise ValueError(f"Unsafe PostgreSQL role identifier: {role!r}")
    return role


def _checksum() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def upgrade() -> None:
    app_role = _resolve_app_role()
    conn = op.get_bind()
    op.create_table(
        "approval_requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("repository_id", sa.String(36), nullable=False),
        sa.Column("repair_id", sa.String(36), nullable=False),
        sa.Column("intent_type", sa.String(40), nullable=False),
        sa.Column("patch_digest", sa.String(64), nullable=False),
        sa.Column("base_sha", sa.String(64), nullable=False),
        sa.Column("target_ref", sa.String(120), nullable=False),
        sa.Column("policy_revision", sa.Integer(), nullable=False),
        sa.Column("requested_by", sa.String(36), nullable=True),
        sa.Column("risk_level", sa.String(32), nullable=False, server_default="review"),
        sa.Column("scope_description", sa.String(1000), nullable=False),
        sa.Column("sensitive_change", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("decision", sa.String(16), nullable=True),
        sa.Column("decision_actor", sa.String(36), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.String(1000), nullable=True),
        sa.Column("correlation_id", sa.String(120), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("workspace_id", "id", name="uq_approval_requests_workspace_id_id"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_approval_requests_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repair_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_approval_requests_tenant_repair_repair_sessions",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["decision_actor"], ["users.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "intent_type IN ('publish_draft_pr', 'sensitive_path_change', 'test_modification')",
            name="ck_approval_request_intent_valid",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired', 'revoked')",
            name="ck_approval_request_status_valid",
        ),
        sa.CheckConstraint("policy_revision >= 1", name="ck_approval_request_policy_revision_pos"),
        sa.CheckConstraint("version >= 1", name="ck_approval_request_version_pos"),
        sa.CheckConstraint(
            "expires_at > created_at", name="ck_approval_request_expiry_after_create"
        ),
    )
    op.create_index(
        "ix_approval_requests_ws_status_expiry",
        "approval_requests",
        ["workspace_id", "status", "expires_at"],
    )
    op.create_index(
        "ix_approval_requests_ws_repo_created",
        "approval_requests",
        ["workspace_id", "repository_id", "created_at"],
    )
    op.create_index(
        "uq_approval_requests_ws_repair_digest_revision_pending",
        "approval_requests",
        ["workspace_id", "repair_id", "patch_digest", "policy_revision"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_table(
        "approval_votes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("approval_request_id", sa.String(36), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=True),
        sa.Column("idempotency_key", sa.String(120), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("correlation_id", sa.String(120), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("workspace_id", "id", name="uq_approval_votes_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "approval_request_id",
            "user_id",
            name="uq_approval_votes_ws_request_user",
        ),
        sa.UniqueConstraint(
            "workspace_id", "idempotency_key", name="uq_approval_votes_ws_idempotency"
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "approval_request_id"],
            ["approval_requests.workspace_id", "approval_requests.id"],
            name="fk_approval_votes_tenant_approval_requests",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "decision IN ('approve', 'reject')", name="ck_approval_vote_decision_valid"
        ),
    )
    op.create_index(
        "ix_approval_votes_ws_request_created",
        "approval_votes",
        ["workspace_id", "approval_request_id", "created_at"],
    )
    op.execute("""
        CREATE OR REPLACE FUNCTION public.red2pr_forbid_approval_vote_mutation()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET red2pr.scope_mode = 'instance_admin'
        AS $$ BEGIN
            RAISE EXCEPTION 'append_only_table_violation: % on approval_votes', TG_OP
                USING ERRCODE = '55000';
        END; $$;
        CREATE TRIGGER trg_approval_votes_immutable BEFORE UPDATE OR DELETE
        ON public.approval_votes FOR EACH ROW
        EXECUTE FUNCTION public.red2pr_forbid_approval_vote_mutation();
    """)
    for table in _TABLES:
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;")
        op.execute(f"""
            CREATE POLICY rls_{table}_select ON public.{table} FOR SELECT USING (
                (current_setting('red2pr.scope_mode', true) = 'workspace'
                 AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), ''))
                OR current_setting('red2pr.scope_mode', true) IN (
                    'instance_admin', 'audit_verifier'
                )
            );
            CREATE POLICY rls_{table}_write ON public.{table} FOR ALL
            USING ((current_setting('red2pr.scope_mode', true) = 'workspace'
                    AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), ''))
                   OR current_setting('red2pr.scope_mode', true) = 'instance_admin')
            WITH CHECK ((current_setting('red2pr.scope_mode', true) = 'workspace'
                         AND workspace_id = NULLIF(
                             current_setting('red2pr.workspace_id', true), ''
                         ))
                        OR current_setting('red2pr.scope_mode', true) = 'instance_admin');
        """)
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON TABLE public.approval_requests TO "{app_role}";')
    op.execute(f'GRANT SELECT, INSERT ON TABLE public.approval_votes TO "{app_role}";')
    conn.execute(
        sa.text("""INSERT INTO public.schema_migrations (
        revision, parent_revision, phase, checksum_sha256,
        compatible_min_app_version, reversible
    ) VALUES (:revision, :parent, 'expand', :checksum, '0.1.0', true)"""),
        {
            "revision": revision,
            "parent": "0014_verification_runs_and_manifests",
            "checksum": _checksum(),
        },
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    op.execute("DROP TRIGGER IF EXISTS trg_approval_votes_immutable ON public.approval_votes;")
    op.execute("DROP FUNCTION IF EXISTS public.red2pr_forbid_approval_vote_mutation();")
    for table in reversed(_TABLES):
        op.drop_table(table)
