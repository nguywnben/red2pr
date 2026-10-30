"""U21 notification outbox projections, inbox, destinations and preferences.

Revision ID: 0017_notifications_inbox_deliveries
Revises: 0016_publications_and_remote_checks
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

revision: str = "0017_notifications_inbox_deliveries"
down_revision: str | Sequence[str] | None = "0016_publications_and_remote_checks"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
_TABLES = (
    "notification_destinations",
    "notification_events",
    "user_inbox_items",
    "notification_deliveries",
    "delivery_attempts",
    "user_notification_preferences",
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
    conn = op.get_bind()
    op.create_table(
        "notification_destinations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("user_id", sa.String(36)),
        sa.Column("channel", sa.String(24), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("address", sa.String(512), nullable=False),
        sa.Column("secret_ref", sa.String(128)),
        sa.Column("consent_id", sa.String(36)),
        sa.Column("status", sa.String(32), nullable=False, server_default="not_configured"),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
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
        sa.UniqueConstraint(
            "workspace_id", "id", name="uq_notification_destinations_workspace_id_id"
        ),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "consent_id"],
            ["consents.workspace_id", "consents.id"],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "channel IN ('in_app','telegram','email','slack','discord','webhook')",
            name="notification_channel_valid",
        ),
        sa.CheckConstraint("scope IN ('user','workspace')", name="notification_scope_valid"),
        sa.CheckConstraint(
            "status IN ('not_configured','pending_verification','ready','degraded',"
            "'suppressed','quarantined','disabled')",
            name="notification_destination_status_valid",
        ),
        sa.CheckConstraint(
            "(scope = 'user' AND user_id IS NOT NULL) OR (scope = 'workspace' AND user_id IS NULL)",
            name="notification_destination_scope_binding",
        ),
        sa.CheckConstraint("version >= 1", name="version_pos"),
    )
    op.create_index(
        "uq_notification_destination_owner",
        "notification_destinations",
        ["workspace_id", "channel", "scope", sa.text("coalesce(user_id, '')")],
        unique=True,
    )
    op.create_index(
        "ix_notification_destinations_ws_status",
        "notification_destinations",
        ["workspace_id", "status", "created_at", "id"],
    )
    op.create_table(
        "notification_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("event_type", sa.String(120), nullable=False),
        sa.Column("correlation_id", sa.String(120), nullable=False),
        sa.Column("repository_id", sa.String(36)),
        sa.Column("payload_json", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("template_revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("workspace_id", "id", name="uq_notification_events_workspace_id_id"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.CheckConstraint("template_revision >= 1", name="notification_template_revision_pos"),
    )
    op.create_index(
        "ix_notification_events_ws_created",
        "notification_events",
        ["workspace_id", "created_at", "id"],
    )
    op.create_table(
        "user_inbox_items",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("event_id", sa.String(36), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("repository_id", sa.String(36)),
        sa.Column("event_type", sa.String(120), nullable=False),
        sa.Column("title", sa.String(120), nullable=False),
        sa.Column("body", sa.String(4096), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("deep_link", sa.String(512)),
        sa.Column("is_security", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("read_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("workspace_id", "id", name="uq_user_inbox_items_workspace_id_id"),
        sa.UniqueConstraint("workspace_id", "event_id", "user_id", name="uq_user_inbox_event_user"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "event_id"],
            ["notification_events.workspace_id", "notification_events.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "severity IN ('info','warning','action','success','error','high','critical')",
            name="notification_inbox_severity_valid",
        ),
        sa.CheckConstraint(
            "length(title) <= 120 AND length(body) <= 4096", name="notification_inbox_text_bounds"
        ),
    )
    op.create_index(
        "ix_user_inbox_user_created",
        "user_inbox_items",
        ["workspace_id", "user_id", "created_at", "id"],
    )
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("event_id", sa.String(36), nullable=False),
        sa.Column("destination_id", sa.String(36), nullable=False),
        sa.Column("template_revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("state", sa.String(24), nullable=False, server_default="pending"),
        sa.Column("possible_duplicate", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_retry_at", sa.DateTime(timezone=True)),
        sa.Column("provider_id", sa.String(128)),
        sa.Column("last_error_code", sa.String(120)),
        sa.Column("request_digest", sa.String(64)),
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
        sa.UniqueConstraint(
            "workspace_id", "id", name="uq_notification_deliveries_workspace_id_id"
        ),
        sa.UniqueConstraint(
            "event_id",
            "destination_id",
            "template_revision",
            name="uq_notification_logical_delivery",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "event_id"],
            ["notification_events.workspace_id", "notification_events.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "destination_id"],
            ["notification_destinations.workspace_id", "notification_destinations.id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "state IN ('pending','sending','accepted','delivered','bounced','retry_wait',"
            "'unknown','possible_duplicate','failed_final','suppressed')",
            name="notification_delivery_state_valid",
        ),
        sa.CheckConstraint(
            "attempt >= 0 AND template_revision >= 1", name="notification_delivery_attempt_bounds"
        ),
    )
    op.create_index(
        "ix_notification_delivery_retry",
        "notification_deliveries",
        ["workspace_id", "state", "next_retry_at", "id"],
    )
    op.create_table(
        "delivery_attempts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("delivery_id", sa.String(36), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(24), nullable=False),
        sa.Column("error_code", sa.String(120)),
        sa.Column("request_digest", sa.String(64)),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "workspace_id", "delivery_id", "attempt", name="uq_delivery_attempt_number"
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "delivery_id"],
            ["notification_deliveries.workspace_id", "notification_deliveries.id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint("attempt >= 1", name="delivery_attempt_pos"),
        sa.CheckConstraint(
            "outcome IN ('accepted','retry_wait','unknown','failed_final','suppressed')",
            name="delivery_attempt_outcome_valid",
        ),
    )
    op.create_table(
        "user_notification_preferences",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36)),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column(
            "event_types_json", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        sa.Column("min_severity", sa.String(16), nullable=False, server_default="info"),
        sa.Column("quiet_hours_json", JSONB()),
        sa.Column("timezone", sa.String(64), nullable=False, server_default="UTC"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
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
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "min_severity IN ('info','warning','action','success','error','high','critical')",
            name="notification_preference_severity_valid",
        ),
        sa.CheckConstraint("version >= 1", name="version_pos"),
    )
    op.create_index(
        "uq_notification_preferences_ws_user",
        "user_notification_preferences",
        ["workspace_id", "user_id"],
        unique=True,
        postgresql_where=sa.text("workspace_id IS NOT NULL"),
    )
    op.create_index(
        "uq_notification_preferences_global_user",
        "user_notification_preferences",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("workspace_id IS NULL"),
    )

    for table in _TABLES:
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;")
        if table == "user_notification_preferences":
            scope_read = (
                "((current_setting('red2pr.scope_mode', true) = 'workspace' "
                "AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')) "
                "OR (current_setting('red2pr.scope_mode', true) = 'instance_admin' "
                "AND workspace_id IS NULL) OR "
                "current_setting('red2pr.scope_mode', true) = 'audit_verifier')"
            )
            scope_write = (
                "((current_setting('red2pr.scope_mode', true) = 'workspace' "
                "AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')) "
                "OR (current_setting('red2pr.scope_mode', true) = 'instance_admin' "
                "AND workspace_id IS NULL))"
            )
        else:
            scope_read = (
                "((current_setting('red2pr.scope_mode', true) = 'workspace' "
                "AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')) "
                "OR current_setting('red2pr.scope_mode', true) "
                "IN ('instance_admin','audit_verifier'))"
            )
            scope_write = (
                "((current_setting('red2pr.scope_mode', true) = 'workspace' "
                "AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')) "
                "OR current_setting('red2pr.scope_mode', true) = 'instance_admin')"
            )
        op.execute(
            f"CREATE POLICY rls_{table}_select ON public.{table} FOR SELECT USING ({scope_read});"
        )
        op.execute(
            f"CREATE POLICY rls_{table}_write ON public.{table} FOR ALL "
            f"USING ({scope_write}) WITH CHECK ({scope_write});"
        )

    op.execute("""
        CREATE FUNCTION public.red2pr_protect_security_inbox_delete() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF OLD.is_security THEN
                RAISE EXCEPTION 'security inbox items are non-removable' USING ERRCODE = '42501';
            END IF;
            RETURN OLD;
        END;
        $$;
        CREATE TRIGGER trg_user_inbox_security_no_delete
        BEFORE DELETE ON public.user_inbox_items
        FOR EACH ROW EXECUTE FUNCTION public.red2pr_protect_security_inbox_delete();
        CREATE FUNCTION public.red2pr_protect_delivery_attempts() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'delivery attempts are append-only';
        END;
        $$;
        CREATE TRIGGER trg_delivery_attempts_append_only
        BEFORE UPDATE OR DELETE ON public.delivery_attempts
        FOR EACH ROW EXECUTE FUNCTION public.red2pr_protect_delivery_attempts();
    """)
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.notification_destinations "
        f'TO "{role}";'
    )
    op.execute(f'GRANT SELECT, INSERT ON TABLE public.notification_events TO "{role}";')
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON TABLE public.user_inbox_items TO "{role}";')
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON TABLE public.notification_deliveries TO "{role}";')
    op.execute(f'GRANT SELECT, INSERT ON TABLE public.delivery_attempts TO "{role}";')
    op.execute(
        f'GRANT SELECT, INSERT, UPDATE ON TABLE public.user_notification_preferences TO "{role}";'
    )
    conn.execute(
        sa.text("""INSERT INTO public.schema_migrations
        (revision,parent_revision,phase,checksum_sha256,compatible_min_app_version,reversible)
        VALUES (:revision,:parent,'expand',:checksum,'0.1.0',true)"""),
        {
            "revision": revision,
            "parent": "0016_publications_and_remote_checks",
            "checksum": _checksum(),
        },
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_user_inbox_security_no_delete ON public.user_inbox_items;"
    )
    op.execute("DROP FUNCTION IF EXISTS public.red2pr_protect_security_inbox_delete();")
    op.execute(
        "DROP TRIGGER IF EXISTS trg_delivery_attempts_append_only ON public.delivery_attempts;"
    )
    op.execute("DROP FUNCTION IF EXISTS public.red2pr_protect_delivery_attempts();")
    for table in reversed(_TABLES):
        op.drop_table(table)
