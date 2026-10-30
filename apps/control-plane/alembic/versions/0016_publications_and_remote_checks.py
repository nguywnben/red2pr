"""Durable draft publication saga and V-08 observations (U20).

Revision ID: 0016_publications_and_remote_checks
Revises: 0015_approval_requests_and_votes
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Sequence
from pathlib import Path

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0016_publications_and_remote_checks"
down_revision: str | Sequence[str] | None = "0015_approval_requests_and_votes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
_TABLES = ("publication_records", "required_check_sets", "remote_ci_checks")
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
    role = _resolve_app_role()
    conn = op.get_bind()
    op.add_column(
        "repository_policies",
        sa.Column("required_check_names_json", JSONB(), nullable=True),
    )
    op.execute(
        "UPDATE public.repository_policies SET required_check_names_json = '[]'::jsonb "
        "WHERE required_check_names_json IS NULL"
    )
    op.execute("""
        CREATE FUNCTION public.red2pr_carry_required_check_names() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.required_check_names_json IS NULL THEN
                SELECT rp.required_check_names_json INTO NEW.required_check_names_json
                FROM public.repository_policies rp
                WHERE rp.workspace_id = NEW.workspace_id
                  AND rp.repository_id = NEW.repository_id
                ORDER BY rp.revision DESC LIMIT 1;
                IF NEW.required_check_names_json IS NULL THEN
                    NEW.required_check_names_json := '[]'::jsonb;
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$;
        CREATE TRIGGER trg_repository_policy_required_checks_carry_forward
        BEFORE INSERT ON public.repository_policies
        FOR EACH ROW EXECUTE FUNCTION public.red2pr_carry_required_check_names();
    """)
    op.alter_column("repository_policies", "required_check_names_json", nullable=False)
    op.create_table(
        "publication_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("repository_id", sa.String(36), nullable=False),
        sa.Column("repair_id", sa.String(36), nullable=False),
        sa.Column("approval_request_id", sa.String(36), nullable=False),
        sa.Column("provider", sa.String(16), nullable=False),
        sa.Column("operation", sa.String(32), nullable=False, server_default="publish_draft"),
        sa.Column("intent_id", sa.String(36), nullable=False),
        sa.Column("correlation_id", sa.String(120), nullable=False),
        sa.Column("marker", sa.String(120), nullable=False),
        sa.Column("branch", sa.String(240), nullable=False),
        sa.Column("base_sha", sa.String(64), nullable=False),
        sa.Column("expected_commit_sha", sa.String(64), nullable=True),
        sa.Column("required_check_set_digest", sa.String(64), nullable=True),
        sa.Column("target_ref", sa.String(120), nullable=False),
        sa.Column("policy_revision", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="intent"),
        sa.Column("provider_object_id", sa.String(128), nullable=True),
        sa.Column("provider_number", sa.String(64), nullable=True),
        sa.Column("url", sa.String(2048), nullable=True),
        sa.Column("error_code", sa.String(80), nullable=True),
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
        sa.UniqueConstraint("workspace_id", "id", name="uq_publications_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id", "repair_id", "provider", "operation", name="uq_publications_effect"
        ),
        sa.UniqueConstraint("workspace_id", "intent_id", name="uq_publications_intent"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repair_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "approval_request_id"],
            ["approval_requests.workspace_id", "approval_requests.id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint("provider IN ('github', 'gitlab')", name="publication_provider_valid"),
        sa.CheckConstraint(
            "status IN ('intent','pushing','creating','published','reconciling',"
            "'failed','unknown')",
            name="publication_status_valid",
        ),
        sa.CheckConstraint("operation = 'publish_draft'", name="publication_operation_valid"),
        sa.CheckConstraint("policy_revision >= 1", name="publication_policy_revision_pos"),
        sa.CheckConstraint(
            "required_check_set_digest IS NULL OR length(required_check_set_digest) = 64",
            name="publication_check_set_digest_valid",
        ),
    )
    op.create_index(
        "ix_publications_ws_status_created",
        "publication_records",
        ["workspace_id", "status", "created_at"],
    )
    op.create_index(
        "ix_publications_ws_repo_created",
        "publication_records",
        ["workspace_id", "repository_id", "created_at"],
    )
    op.create_table(
        "required_check_sets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("repository_id", sa.String(36), nullable=False),
        sa.Column("policy_revision", sa.Integer(), nullable=False),
        sa.Column("names_json", JSONB(), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("workspace_id", "id", name="uq_required_check_sets_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "repository_id",
            "policy_revision",
            name="uq_required_check_sets_revision",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint("policy_revision >= 1", name="required_check_set_policy_revision_pos"),
    )
    op.create_index(
        "ix_required_check_sets_ws_repo", "required_check_sets", ["workspace_id", "repository_id"]
    )
    op.execute("""
        CREATE FUNCTION public.red2pr_reject_required_check_set_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'append_only_table_violation: % on required_check_sets', TG_OP
                USING ERRCODE = '55000';
        END;
        $$;
        CREATE TRIGGER trg_required_check_sets_immutable
        BEFORE UPDATE OR DELETE ON public.required_check_sets
        FOR EACH ROW EXECUTE FUNCTION public.red2pr_reject_required_check_set_mutation();
    """)
    op.create_table(
        "remote_ci_checks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("publication_id", sa.String(36), nullable=False),
        sa.Column("head_sha", sa.String(64), nullable=False),
        sa.Column("expected_check_set_digest", sa.String(64), nullable=False),
        sa.Column("observations_json", JSONB(), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False, server_default="pending"),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("workspace_id", "id", name="uq_remote_ci_checks_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id", "publication_id", name="uq_remote_ci_checks_publication"
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "publication_id"],
            ["publication_records.workspace_id", "publication_records.id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "outcome IN ('pending', 'passed', 'failed', 'unknown')", name="remote_ci_outcome_valid"
        ),
    )
    op.create_index("ix_remote_ci_checks_ws_sha", "remote_ci_checks", ["workspace_id", "head_sha"])

    for table in _TABLES:
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;")
        op.execute(f"""
            CREATE POLICY rls_{table}_select ON public.{table} FOR SELECT USING (
                (current_setting('red2pr.scope_mode', true) = 'workspace'
                 AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), ''))
                OR current_setting('red2pr.scope_mode', true)
                   IN ('instance_admin', 'audit_verifier')
            );
            CREATE POLICY rls_{table}_write ON public.{table} FOR ALL
            USING ((current_setting('red2pr.scope_mode', true) = 'workspace'
                    AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), ''))
                   OR current_setting('red2pr.scope_mode', true) = 'instance_admin')
            WITH CHECK ((current_setting('red2pr.scope_mode', true) = 'workspace'
                         AND workspace_id = NULLIF(
                             current_setting('red2pr.workspace_id', true), ''))
                        OR current_setting('red2pr.scope_mode', true) = 'instance_admin');
        """)
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON TABLE public.publication_records TO "{role}";')
    op.execute(f'GRANT SELECT, INSERT ON TABLE public.required_check_sets TO "{role}";')
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON TABLE public.remote_ci_checks TO "{role}";')
    conn.execute(
        sa.text("""INSERT INTO public.schema_migrations
        (revision,parent_revision,phase,checksum_sha256,compatible_min_app_version,reversible)
        VALUES (:revision,:parent,'expand',:checksum,'0.1.0',true)"""),
        {
            "revision": revision,
            "parent": "0015_approval_requests_and_votes",
            "checksum": _checksum(),
        },
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_required_check_sets_immutable ON public.required_check_sets;"
    )
    op.execute("DROP FUNCTION IF EXISTS public.red2pr_reject_required_check_set_mutation();")
    for table in reversed(_TABLES):
        op.drop_table(table)
    op.execute(
        "DROP TRIGGER IF EXISTS trg_repository_policy_required_checks_carry_forward "
        "ON public.repository_policies"
    )
    op.execute("DROP FUNCTION IF EXISTS public.red2pr_carry_required_check_names();")
    op.drop_column("repository_policies", "required_check_names_json")
