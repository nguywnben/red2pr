"""U23 scoped API tokens, signed-webhook key rotation, and complete S-19 projections.

Revision ID: 0019_api_tokens_and_webhook_keys
Revises: 0018_telegram_links_and_challenges
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

revision: str = "0019_api_tokens_and_webhook_keys"
down_revision: str | Sequence[str] | None = "0018_telegram_links_and_challenges"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
_TABLES = ("api_tokens", "webhook_signing_keys")
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
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("secret_hash", sa.String(64), nullable=False),
        sa.Column("scopes_json", JSONB(), nullable=False),
        sa.Column("repository_ids_json", JSONB(), nullable=False),
        sa.Column("grant_epoch", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("workspace_id", "id", name="uq_api_tokens_workspace_id_id"),
        sa.UniqueConstraint("secret_hash", name="uq_api_tokens_secret_hash"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.CheckConstraint("secret_hash ~ '^[0-9a-f]{64}$'", name="api_token_hash_valid"),
        sa.CheckConstraint("grant_epoch >= 1", name="api_token_grant_epoch_pos"),
        sa.CheckConstraint("jsonb_typeof(scopes_json) = 'array'", name="api_token_scopes_array"),
        sa.CheckConstraint(
            "jsonb_typeof(repository_ids_json) = 'array'", name="api_token_repos_array"
        ),
    )
    op.create_index(
        "ix_api_tokens_user_active", "api_tokens", ["user_id", "revoked_at", "expires_at"]
    )
    op.create_table(
        "webhook_signing_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("destination_id", sa.String(36), nullable=False),
        sa.Column("key_id", sa.String(120), nullable=False),
        sa.Column("secret_ref", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("workspace_id", "id", name="uq_webhook_keys_workspace_id_id"),
        sa.UniqueConstraint("key_id", name="uq_webhook_signing_key_id"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "destination_id"],
            ["notification_destinations.workspace_id", "notification_destinations.id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "status IN ('active','overlap','revoked')", name="webhook_signing_key_status_valid"
        ),
        sa.CheckConstraint("length(key_id) BETWEEN 1 AND 120", name="webhook_signing_key_id_len"),
    )
    op.create_index(
        "uq_webhook_key_one_active",
        "webhook_signing_keys",
        ["workspace_id", "destination_id"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_index(
        "ix_webhook_keys_destination_status",
        "webhook_signing_keys",
        ["workspace_id", "destination_id", "status"],
    )
    op.add_column("notification_events", sa.Column("aggregate_id", sa.String(36), nullable=True))
    op.add_column(
        "notification_events", sa.Column("aggregate_version", sa.Integer(), nullable=True)
    )
    op.add_column("notification_events", sa.Column("causation_id", sa.String(36), nullable=True))
    for table in _TABLES:
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;")
        read_modes = (
            "('instance_admin','instance_only')" if table == "api_tokens" else "('instance_admin')"
        )
        read = (
            "((current_setting('red2pr.scope_mode', true) = 'workspace' "
            "AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')) "
            f"OR current_setting('red2pr.scope_mode', true) IN {read_modes})"
        )
        write = (
            "((current_setting('red2pr.scope_mode', true) = 'workspace' "
            "AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')) "
            "OR current_setting('red2pr.scope_mode', true) = 'instance_admin')"
        )
        op.execute(f"CREATE POLICY rls_{table}_select ON public.{table} FOR SELECT USING ({read});")
        op.execute(
            f"CREATE POLICY rls_{table}_write ON public.{table} FOR ALL "
            f"USING ({write}) WITH CHECK ({write});"
        )
        op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.{table} TO "{role}";')
    op.get_bind().execute(
        sa.text(
            "INSERT INTO public.schema_migrations "
            "(revision,parent_revision,phase,checksum_sha256,"
            "compatible_min_app_version,reversible) "
            "VALUES (:revision,:parent,'expand',:checksum,'0.1.0',true)"
        ),
        {
            "revision": revision,
            "parent": "0018_telegram_links_and_challenges",
            "checksum": _checksum(),
        },
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    op.drop_column("notification_events", "causation_id")
    op.drop_column("notification_events", "aggregate_version")
    op.drop_column("notification_events", "aggregate_id")
    for table in reversed(_TABLES):
        op.drop_table(table)
