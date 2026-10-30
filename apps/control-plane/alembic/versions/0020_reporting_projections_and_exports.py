"""U24 deterministic reporting projections and expiring encrypted exports.

Revision ID: 0020_reporting_projections_and_exports
Revises: 0019_api_tokens_and_webhook_keys
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

revision: str = "0020_reporting_projections_and_exports"
down_revision: str | Sequence[str] | None = "0019_api_tokens_and_webhook_keys"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def _role() -> str:
    role = str(
        context.config.attributes.get("red2pr_app_role_name")
        or os.environ.get("RED2PR_APP_DB_ROLE", "red2pr_app")
    ).strip()
    if not _ROLE_RE.fullmatch(role):
        raise ValueError(f"Unsafe PostgreSQL role identifier: {role!r}")
    return role


def _checksum() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _secure_workspace_table(table: str, *, role: str) -> None:
    op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;")
    op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;")
    scope = (
        "(current_setting('red2pr.scope_mode', true) = 'workspace' "
        "AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), ''))"
    )
    select_policy = (
        f"CREATE POLICY rls_{table}_select ON public.{table} FOR SELECT USING ({scope});"
    )
    op.execute(select_policy)
    op.execute(
        f"CREATE POLICY rls_{table}_write ON public.{table} FOR ALL "
        f"USING ({scope}) WITH CHECK ({scope});"
    )
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.{table} TO "{role}";')


def upgrade() -> None:
    role = _role()
    op.create_table(
        "reporting_projections",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("projection_key", sa.String(64), nullable=False),
        sa.Column("scope_digest", sa.String(64), nullable=False),
        sa.Column("range_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("range_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("watermark", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload_json", JSONB(), nullable=False),
        sa.Column("rebuilt_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("workspace_id", "projection_key", name="uq_reporting_projection_key"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.CheckConstraint("range_end >= range_start", name="reporting_projection_range_valid"),
        sa.CheckConstraint(
            "projection_key ~ '^[0-9a-f]{64}$' AND scope_digest ~ '^[0-9a-f]{64}$'",
            name="reporting_projection_digests_valid",
        ),
    )
    op.create_index(
        "ix_reporting_projection_scope",
        "reporting_projections",
        ["workspace_id", "scope_digest", "range_end"],
    )
    op.create_table(
        "report_exports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("created_by_user_id", sa.String(36), nullable=False),
        sa.Column("created_by_role", sa.String(24), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("format", sa.String(8), nullable=False),
        sa.Column("range_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("range_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("repository_ids_json", JSONB(), nullable=False),
        sa.Column("scope_digest", sa.String(64), nullable=False),
        sa.Column("storage_ref", sa.String(1024), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("idempotency_key", sa.String(120), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("workspace_id", "id", name="uq_report_exports_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "created_by_user_id",
            "idempotency_key",
            name="uq_report_exports_idempotency",
        ),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "kind IN ('funnel','usage','audit','proof_summary')", name="report_export_kind_valid"
        ),
        sa.CheckConstraint(
            "created_by_role IN ('admin','maintainer','reviewer','viewer','auditor')",
            name="report_export_creator_role_valid",
        ),
        sa.CheckConstraint("format IN ('csv','json')", name="report_export_format_valid"),
        sa.CheckConstraint("range_end >= range_start", name="report_export_range_valid"),
        sa.CheckConstraint("expires_at > created_at", name="report_export_expiry_valid"),
        sa.CheckConstraint(
            "length(digest) = 64 AND digest ~ '^[0-9a-f]{64}$'", name="report_export_digest_valid"
        ),
        sa.CheckConstraint(
            "length(scope_digest) = 64 AND scope_digest ~ '^[0-9a-f]{64}$'",
            name="report_export_scope_digest_valid",
        ),
        sa.CheckConstraint(
            "length(request_digest) = 64 AND request_digest ~ '^[0-9a-f]{64}$'",
            name="report_export_request_digest_valid",
        ),
        sa.CheckConstraint("size_bytes >= 0", name="report_export_size_valid"),
        sa.CheckConstraint(
            "jsonb_typeof(repository_ids_json) = 'array'", name="report_export_repositories_array"
        ),
    )
    op.create_index("ix_report_exports_expiry", "report_exports", ["workspace_id", "expires_at"])
    _secure_workspace_table("reporting_projections", role=role)
    _secure_workspace_table("report_exports", role=role)
    op.get_bind().execute(
        sa.text(
            "INSERT INTO public.schema_migrations "
            "(revision,parent_revision,phase,checksum_sha256,"
            "compatible_min_app_version,reversible) "
            "VALUES (:revision,:parent,'expand',:checksum,'0.1.0',true)"
        ),
        {
            "revision": revision,
            "parent": "0019_api_tokens_and_webhook_keys",
            "checksum": _checksum(),
        },
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    op.drop_table("report_exports")
    op.drop_table("reporting_projections")
