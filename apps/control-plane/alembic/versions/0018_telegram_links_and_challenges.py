"""U22 Telegram private-account links, one-use challenges and update inbox.

Revision ID: 0018_telegram_links_and_challenges
Revises: 0017_notifications_inbox_deliveries
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

revision: str = "0018_telegram_links_and_challenges"
down_revision: str | Sequence[str] | None = "0017_notifications_inbox_deliveries"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
_TABLES = (
    "telegram_links",
    "telegram_link_challenges",
    "telegram_update_offsets",
    "telegram_updates",
)
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
        "telegram_links",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("bot_id", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("telegram_user_id", sa.String(32), nullable=False),
        sa.Column("private_chat_id", sa.String(32), nullable=False),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("bot_id", "user_id", name="uq_telegram_links_bot_user"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "length(telegram_user_id) BETWEEN 1 AND 32", name="telegram_user_id_len"
        ),
        sa.CheckConstraint("length(private_chat_id) BETWEEN 1 AND 32", name="telegram_chat_id_len"),
        sa.CheckConstraint("version >= 1", name="telegram_link_version_pos"),
    )
    op.create_index(
        "uq_telegram_links_bot_tg_user_active",
        "telegram_links",
        ["bot_id", "telegram_user_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.create_table(
        "telegram_link_challenges",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("bot_id", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("scope", sa.String(24), nullable=False),
        sa.Column("workspace_id", sa.String(36)),
        sa.Column("action", sa.String(24)),
        sa.Column("target_id", sa.String(36)),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column("result_json", JSONB()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("token_hash", name="uq_telegram_link_challenges_token_hash"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "scope IN ('account_link','action')", name="telegram_challenge_scope_valid"
        ),
        sa.CheckConstraint("expires_at > created_at", name="telegram_challenge_expiry_valid"),
        sa.CheckConstraint(
            "(scope = 'account_link' AND workspace_id IS NULL AND action IS NULL "
            "AND target_id IS NULL) OR "
            "(scope = 'action' AND action IN ('pause','resume','retry','unlink'))",
            name="telegram_challenge_scope_payload_valid",
        ),
    )
    op.create_index(
        "ix_telegram_challenges_user_expiry",
        "telegram_link_challenges",
        ["user_id", "scope", "expires_at"],
    )
    op.create_table(
        "telegram_update_offsets",
        sa.Column("bot_id", sa.String(64), primary_key=True),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("credential_fingerprint", sa.String(64), nullable=False),
        sa.Column("next_update_id", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("lease_owner", sa.String(64)),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.Column("lease_epoch", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("next_update_id >= 0", name="telegram_next_update_id_nonnegative"),
        sa.CheckConstraint("lease_epoch >= 0", name="telegram_lease_epoch_nonnegative"),
        sa.CheckConstraint("mode IN ('polling','webhook')", name="telegram_mode_valid"),
        sa.CheckConstraint(
            "credential_fingerprint ~ '^[0-9a-f]{64}$'",
            name="telegram_credential_fingerprint_valid",
        ),
    )
    op.create_table(
        "telegram_updates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("bot_id", sa.String(64), nullable=False),
        sa.Column("update_id", sa.BigInteger(), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("normalized_json", JSONB(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False, server_default="received"),
        sa.Column("correlation_id", sa.String(120), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True)),
        sa.Column("processing_started_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("bot_id", "update_id", name="uq_telegram_updates_bot_update"),
        sa.CheckConstraint("update_id >= 0", name="telegram_update_id_nonnegative"),
        sa.CheckConstraint(
            "state IN ('received','processing','sent','ignored','unknown')",
            name="telegram_update_state_valid",
        ),
    )
    op.create_index(
        "ix_telegram_updates_pending",
        "telegram_updates",
        ["bot_id", "state", "received_at", "update_id"],
    )
    op.create_index(
        "ix_telegram_updates_stale_processing",
        "telegram_updates",
        ["bot_id", "state", "processing_started_at"],
    )
    for table in _TABLES:
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;")
        allowed = "current_setting('red2pr.scope_mode', true) = 'instance_admin'"
        op.execute(
            f"CREATE POLICY rls_{table}_select ON public.{table} FOR SELECT USING ({allowed});"
        )
        op.execute(
            f"CREATE POLICY rls_{table}_write ON public.{table} FOR ALL "
            f"USING ({allowed}) WITH CHECK ({allowed});"
        )
        op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.{table} TO "{role}";')
    op.get_bind().execute(
        sa.text(
            "INSERT INTO public.schema_migrations "
            "(revision,parent_revision,phase,checksum_sha256,compatible_min_app_version,"
            "reversible) "
            "VALUES (:revision,:parent,'expand',:checksum,'0.1.0',true)"
        ),
        {
            "revision": revision,
            "parent": "0017_notifications_inbox_deliveries",
            "checksum": _checksum(),
        },
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    for table in reversed(_TABLES):
        op.drop_table(table)
