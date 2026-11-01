"""U29 opt-in customer-operated relay and consented model fallback policies.

Revision ID: 0024_relay_and_model_fallback
Revises: 0023_extensions_and_oidc
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

revision: str = "0024_relay_and_model_fallback"
down_revision: str | Sequence[str] | None = "0023_extensions_and_oidc"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def _role() -> str:
    role = str(
        context.config.attributes.get("red2pr_app_role_name")
        or os.environ.get("RED2PR_APP_DB_ROLE", "red2pr_app")
    ).strip()
    if not _ROLE_RE.fullmatch(role):
        raise ValueError("Unsafe PostgreSQL role identifier.")
    return role


def _checksum() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _secure_workspace_table(
    table: str, role: str, *, instance_admin_read: bool = False
) -> None:
    scope = (
        "(current_setting('red2pr.scope_mode', true) = 'workspace' "
        "AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), ''))"
    )
    op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
    read_scope = (
        f"({scope} OR current_setting('red2pr.scope_mode', true) = 'instance_admin')"
        if instance_admin_read
        else scope
    )
    op.execute(
        f"CREATE POLICY rls_{table}_select ON public.{table} FOR SELECT USING ({read_scope})"
    )
    op.execute(
        f"CREATE POLICY rls_{table}_write ON public.{table} FOR ALL "
        f"USING ({scope}) WITH CHECK ({scope})"
    )
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.{table} TO "{role}"')


def _drop_scheme_check(*, includes_wss: bool) -> None:
    rows = op.get_bind().execute(
        sa.text(
            "SELECT c.conname FROM pg_constraint AS c "
            "JOIN pg_attribute AS a ON a.attrelid = c.conrelid "
            "AND a.attnum = ANY(c.conkey) "
            "WHERE c.conrelid = 'public.endpoint_registrations'::regclass "
            "AND c.contype = 'c' AND a.attname = 'scheme' "
            "AND pg_get_constraintdef(c.oid) LIKE '%https%' "
            "AND pg_get_constraintdef(c.oid) LIKE '%http%' "
            "AND ((:includes_wss AND pg_get_constraintdef(c.oid) LIKE '%wss%') "
            "OR (NOT :includes_wss AND pg_get_constraintdef(c.oid) NOT LIKE '%wss%'))"
        ),
        {"includes_wss": includes_wss},
    ).scalars().all()
    if len(rows) != 1:
        raise RuntimeError("Expected exactly one endpoint scheme constraint to replace.")
    op.drop_constraint(op.f(rows[0]), "endpoint_registrations", type_="check")


def upgrade() -> None:
    role = _role()
    _drop_scheme_check(includes_wss=False)
    op.create_check_constraint(
        "endpoint_scheme_valid",
        "endpoint_registrations",
        "scheme IN ('https', 'http', 'wss')",
    )

    op.create_table(
        "relay_subscriptions",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("provider_connection_id", sa.String(36), nullable=False),
        sa.Column("endpoint_registration_id", sa.String(36), nullable=False),
        sa.Column("consent_id", sa.String(36), nullable=False),
        sa.Column("relay_secret_ref", sa.String(128), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("status", sa.String(24), nullable=False, server_default="disabled"),
        sa.Column("last_relay_seq", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_received_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status_detail", sa.String(120), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_relay_subscriptions"),
        sa.UniqueConstraint(
            "workspace_id", "id", name="uq_relay_subscriptions_workspace_id_id"
        ),
        sa.UniqueConstraint(
            "workspace_id", "provider_connection_id", name="uq_relay_subscriptions_ws_connection"
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "provider_connection_id"],
            ["provider_connections.workspace_id", "provider_connections.id"],
            name="fk_relay_subscriptions_tenant_connection",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "consent_id"],
            ["consents.workspace_id", "consents.id"],
            name="fk_relay_subscriptions_tenant_consent",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["endpoint_registration_id"],
            ["endpoint_registrations.id"],
            name="fk_relay_subscriptions_endpoint_registration",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["relay_secret_ref"],
            ["secret_entries.secret_ref"],
            name="fk_relay_subscriptions_secret_ref",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "status IN ('disabled','ready','degraded','gap_detected')",
            name="relay_subscription_status_valid",
        ),
        sa.CheckConstraint("last_relay_seq >= 0", name="relay_subscription_seq_nonneg"),
        sa.CheckConstraint("version >= 1", name="version_pos"),
    )
    op.create_index(
        "ix_relay_subscriptions_enabled",
        "relay_subscriptions",
        ["workspace_id", "enabled", "status"],
    )
    _secure_workspace_table("relay_subscriptions", role, instance_admin_read=True)

    op.create_table(
        "model_fallback_policies",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("repository_id", sa.String(36), nullable=False),
        sa.Column("primary_model_profile_id", sa.String(36), nullable=False),
        sa.Column("secondary_model_profile_id", sa.String(36), nullable=False),
        sa.Column(
            "trigger_conditions_json",
            JSONB(),
            nullable=False,
            server_default=sa.text("'[\"429\",\"503\",\"capability_unavailable\"]'::jsonb"),
        ),
        sa.Column("consent_id", sa.String(36), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_fallback_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_fallback_reason", sa.String(32), nullable=True),
        sa.Column("updated_by_user_id", sa.String(36), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_model_fallback_policies"),
        sa.UniqueConstraint(
            "workspace_id", "id", name="uq_model_fallback_policies_workspace_id_id"
        ),
        sa.UniqueConstraint(
            "workspace_id", "repository_id", name="uq_model_fallback_policy_workspace_repo"
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_model_fallback_policies_tenant_repository",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "consent_id"],
            ["consents.workspace_id", "consents.id"],
            name="fk_model_fallback_policies_tenant_consent",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "primary_model_profile_id"],
            ["workspace_agent_profiles.workspace_id", "workspace_agent_profiles.id"],
            name="fk_model_fallback_policies_primary_profile",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "secondary_model_profile_id"],
            ["workspace_agent_profiles.workspace_id", "workspace_agent_profiles.id"],
            name="fk_model_fallback_policies_secondary_profile",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by_user_id"],
            ["users.id"],
            name="fk_model_fallback_policies_updated_by_user",
            ondelete="SET NULL",
        ),
        sa.CheckConstraint(
            "primary_model_profile_id <> secondary_model_profile_id",
            name="model_fallback_profiles_distinct",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(trigger_conditions_json) = 'array' AND "
            "trigger_conditions_json <@ '[\"429\",\"503\",\"capability_unavailable\"]'::jsonb",
            name="model_fallback_triggers_valid",
        ),
        sa.CheckConstraint(
            "last_fallback_reason IS NULL OR last_fallback_reason IN "
            "('429','503','capability_unavailable')",
            name="model_fallback_reason_valid",
        ),
        sa.CheckConstraint("version >= 1", name="version_pos"),
    )
    op.create_index(
        "ix_model_fallback_policies_enabled",
        "model_fallback_policies",
        ["workspace_id", "repository_id", "enabled"],
    )
    _secure_workspace_table("model_fallback_policies", role)

    op.get_bind().execute(
        sa.text(
            "INSERT INTO public.schema_migrations "
            "(revision,parent_revision,phase,checksum_sha256,"
            "compatible_min_app_version,reversible) "
            "VALUES (:revision,:parent,'expand',:checksum,'0.1.0',true)"
        ),
        {"revision": revision, "parent": down_revision, "checksum": _checksum()},
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    op.drop_index("ix_model_fallback_policies_enabled", table_name="model_fallback_policies")
    op.drop_table("model_fallback_policies")
    op.drop_index("ix_relay_subscriptions_enabled", table_name="relay_subscriptions")
    op.drop_table("relay_subscriptions")
    _drop_scheme_check(includes_wss=True)
    op.create_check_constraint(
        "ck_endpoint_registrations_endpoint_scheme_valid",
        "endpoint_registrations",
        "scheme IN ('https', 'http')",
    )
