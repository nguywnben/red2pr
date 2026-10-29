"""Deterministic verification ledger and signed evidence manifests (U18).

Revision ID: 0014_verification_runs_and_manifests
Revises: 0013_repair_sessions_diagnostics_steps
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

revision: str = "0014_verification_runs_and_manifests"
down_revision: str | Sequence[str] | None = "0013_repair_sessions_diagnostics_steps"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLES = ("verification_runs", "evidence_manifests")
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
        "verification_runs",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("repository_id", sa.String(36), nullable=False),
        sa.Column("repair_id", sa.String(36), nullable=False),
        sa.Column("idempotency_key", sa.String(120), nullable=False),
        sa.Column("patch_digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("proof_grade", sa.String(32), nullable=False),
        sa.Column("gates_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("baseline_result_digest", sa.String(64), nullable=False),
        sa.Column("patched_result_digest", sa.String(64), nullable=False),
        sa.Column("correlation_id", sa.String(120), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_verification_runs"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_verification_runs_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id", "idempotency_key", name="uq_verification_runs_ws_idempotency_key"
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_verification_runs_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repair_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_verification_runs_tenant_repair_repair_sessions",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "status IN ('verified', 'failed', 'human_review', 'blocked', 'cancelled')",
            name="ck_verification_runs_verification_run_status_valid",
        ),
        sa.CheckConstraint(
            "proof_grade IN ('baseline_confirmed', 'locally_verified')",
            name="ck_verification_runs_verification_run_proof_grade_valid",
        ),
    )
    op.create_index(
        "ix_verification_runs_ws_repair_created",
        "verification_runs",
        ["workspace_id", "repair_id", "created_at"],
    )
    op.create_table(
        "evidence_manifests",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("repository_id", sa.String(36), nullable=False),
        sa.Column("repair_id", sa.String(36), nullable=False),
        sa.Column("verification_run_id", sa.String(36), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("manifest_digest", sa.String(64), nullable=False),
        sa.Column("signer_key_id", sa.String(120), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_evidence_manifests"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_evidence_manifests_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id", "verification_run_id", name="uq_evidence_manifests_ws_verification_run"
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_evidence_manifests_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repair_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_evidence_manifests_tenant_repair_repair_sessions",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "verification_run_id"],
            ["verification_runs.workspace_id", "verification_runs.id"],
            name="fk_evidence_manifests_tenant_verification_run",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "schema_version = 1", name="ck_evidence_manifests_evidence_manifest_version_valid"
        ),
    )
    op.create_index(
        "ix_evidence_manifests_ws_repair_created",
        "evidence_manifests",
        ["workspace_id", "repair_id", "created_at"],
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.red2pr_forbid_u18_evidence_mutation()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET red2pr.scope_mode = 'instance_admin'
        AS $$ BEGIN
            RAISE EXCEPTION
                'append_only_table_violation: % on % is forbidden (U18 evidence)',
                TG_OP, TG_TABLE_NAME
                USING ERRCODE = '55000';
        END; $$;
        """
    )
    for table in _TABLES:
        op.execute(
            f"CREATE TRIGGER trg_{table}_immutable BEFORE UPDATE OR DELETE ON public.{table} "
            "FOR EACH ROW EXECUTE FUNCTION public.red2pr_forbid_u18_evidence_mutation();"
        )
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;")
        op.execute(
            f"""
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
            """
        )
    granted_tables = "public.verification_runs, public.evidence_manifests"
    op.execute(f'GRANT SELECT, INSERT ON TABLE {granted_tables} TO "{app_role}";')
    conn.execute(
        sa.text(
            """INSERT INTO public.schema_migrations (
                revision, parent_revision, phase, checksum_sha256,
                compatible_min_app_version, reversible
            ) VALUES (:revision, :parent, 'expand', :checksum, '0.1.0', true)"""
        ),
        {
            "revision": revision,
            "parent": "0013_repair_sessions_diagnostics_steps",
            "checksum": _checksum(),
        },
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    for table in _TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_immutable ON public.{table};")
    op.execute("DROP FUNCTION IF EXISTS public.red2pr_forbid_u18_evidence_mutation();")
    for table in reversed(_TABLES):
        op.drop_table(table)
