"""U28 extension capability state and OIDC federation persistence."""

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

revision: str = "0023_extensions_and_oidc"
down_revision: str | Sequence[str] | None = "0022_backups_migrations_ops"
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


def _instance_table(table: str, role: str) -> None:
    op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY rls_{table}_instance ON public.{table} FOR ALL "
        "USING (current_setting('red2pr.scope_mode', true) = 'instance_admin') "
        "WITH CHECK (current_setting('red2pr.scope_mode', true) = 'instance_admin')"
    )
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.{table} TO "{role}"')


def _drop_session_auth_strength_constraint() -> None:
    op.execute(
        """
        DO $$
        DECLARE constraint_name text;
        BEGIN
            SELECT conname INTO constraint_name
            FROM pg_constraint
            WHERE conrelid = 'public.sessions'::regclass
              AND contype = 'c'
              AND pg_get_constraintdef(oid) ILIKE '%auth_strength%'
            LIMIT 1;
            IF constraint_name IS NULL THEN
                RAISE EXCEPTION 'sessions auth_strength constraint is missing';
            END IF;
            EXECUTE format(
                'ALTER TABLE public.sessions DROP CONSTRAINT %I', constraint_name
            );
        END $$;
        """
    )


def _install_oidc_admin_anchor_guard() -> None:
    """Retain an active local admin while OIDC supplies additional admins."""
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
            v_local_remaining BIGINT;
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
                        SELECT COUNT(*), COUNT(*) FILTER (
                            WHERE NOT EXISTS (
                                SELECT 1
                                FROM public.oidc_membership_grants g
                                WHERE g.membership_id = m.id
                                  AND g.membership_version = m.version
                                  AND g.granted_role = 'admin'
                            )
                        )
                        INTO v_remaining, v_local_remaining
                        FROM public.memberships m
                        JOIN public.users u ON u.id = m.user_id
                        WHERE m.workspace_id = OLD.workspace_id
                          AND m.role = 'admin'
                          AND m.id <> OLD.id
                          AND u.status = 'active';

                        IF v_remaining = 0 THEN
                            RAISE EXCEPTION
                                'last_admin: workspace must retain at least one active admin'
                                USING ERRCODE = '55000';
                        END IF;
                        IF v_local_remaining = 0 THEN
                            RAISE EXCEPTION
                                'last_admin: workspace must retain an active locally managed admin'
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


def _restore_last_admin_guard() -> None:
    """Restore the pre-U28 last-active-admin invariant on downgrade."""
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


def upgrade() -> None:
    role = _role()
    op.create_table(
        "extension_capabilities",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("reason", sa.String(120), nullable=False),
        sa.Column("probed_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('enabled','disabled','not_configured','unsupported')",
            name="extension_capability_status_valid",
        ),
    )
    op.create_table(
        "oidc_providers",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("client_id", sa.String(256), nullable=False),
        sa.Column("client_secret_ref", sa.String(120), nullable=False),
        sa.Column("authorization_endpoint", sa.Text(), nullable=False),
        sa.Column("token_endpoint", sa.Text(), nullable=False),
        sa.Column("jwks_uri", sa.Text(), nullable=False),
        sa.Column("scopes_json", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("probed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('not_configured','enabled','disabled','unavailable')",
            name="oidc_provider_status_valid",
        ),
        sa.UniqueConstraint("issuer", name="uq_oidc_providers_issuer"),
    )
    op.create_table(
        "oidc_auth_transactions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("provider_id", sa.String(64), nullable=False),
        sa.Column("state_hash", sa.String(64), nullable=False),
        sa.Column("nonce", sa.String(128), nullable=False),
        sa.Column("verifier_ciphertext", sa.Text(), nullable=False),
        sa.Column("browser_binding_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["provider_id"], ["oidc_providers.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("state_hash", name="uq_oidc_auth_transactions_state_hash"),
    )
    op.create_index("ix_oidc_auth_transactions_expiry", "oidc_auth_transactions", ["expires_at"])
    op.create_table(
        "oidc_identities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("provider_id", sa.String(64), nullable=False),
        sa.Column("subject", sa.String(512), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("provider_id", "subject", name="uq_oidc_identity_subject"),
        sa.ForeignKeyConstraint(["provider_id"], ["oidc_providers.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("provider_id", "user_id", name="uq_oidc_identity_user"),
    )
    op.create_index("ix_oidc_identities_user", "oidc_identities", ["user_id"])
    op.create_table(
        "oidc_group_mappings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("provider_id", sa.String(64), nullable=False),
        sa.Column("group_name", sa.String(256), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "workspace_id", "provider_id", "group_name", name="uq_oidc_group_mapping"
        ),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["provider_id"], ["oidc_providers.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "role IN ('admin','maintainer','reviewer','viewer','auditor')",
            name="oidc_group_role_valid",
        ),
    )
    op.create_table(
        "oidc_membership_grants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("provider_id", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("membership_id", sa.String(36), nullable=False),
        sa.Column("group_name", sa.String(256), nullable=False),
        sa.Column("granted_role", sa.String(32), nullable=False),
        sa.Column("membership_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("workspace_id", "user_id", name="uq_oidc_membership_user_workspace"),
        sa.ForeignKeyConstraint(["provider_id"], ["oidc_providers.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["workspace_id", "membership_id"],
            ["memberships.workspace_id", "memberships.id"],
            ondelete="CASCADE",
        ),
    )
    _install_oidc_admin_anchor_guard()
    op.execute("ALTER TABLE public.oidc_group_mappings ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE public.oidc_group_mappings FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY rls_oidc_group_mappings_select ON public.oidc_group_mappings "
        "FOR SELECT USING (current_setting('red2pr.scope_mode', true) = 'instance_admin' OR "
        "(current_setting('red2pr.scope_mode', true) = 'workspace' AND "
        "workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')))"
    )
    op.execute(
        "CREATE POLICY rls_oidc_group_mappings_write ON public.oidc_group_mappings "
        "FOR ALL USING (current_setting('red2pr.scope_mode', true) = 'instance_admin' OR "
        "(current_setting('red2pr.scope_mode', true) = 'workspace' AND "
        "workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), ''))) "
        "WITH CHECK (current_setting('red2pr.scope_mode', true) = 'instance_admin' OR "
        "(current_setting('red2pr.scope_mode', true) = 'workspace' AND "
        "workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')))"
    )
    op.execute(
        f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oidc_group_mappings TO "{role}"'
    )
    for table in (
        "extension_capabilities",
        "oidc_providers",
        "oidc_auth_transactions",
        "oidc_identities",
    ):
        _instance_table(table, role)
    op.execute("ALTER TABLE public.oidc_membership_grants ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE public.oidc_membership_grants FORCE ROW LEVEL SECURITY")
    grant_scope = (
        "(current_setting('red2pr.scope_mode', true) = 'instance_admin' OR "
        "(current_setting('red2pr.scope_mode', true) = 'workspace' AND "
        "workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')))"
    )
    op.execute(
        f"CREATE POLICY rls_oidc_membership_grants_scope ON public.oidc_membership_grants "
        f"FOR ALL USING {grant_scope} WITH CHECK {grant_scope}"
    )
    op.execute(
        f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.oidc_membership_grants TO "{role}"'
    )
    _drop_session_auth_strength_constraint()
    op.create_check_constraint(
        "session_auth_strength_valid",
        "sessions",
        "auth_strength IN ('password','mfa','oidc')",
    )
    op.bulk_insert(
        sa.table(
            "extension_capabilities",
            sa.column("id", sa.String()),
            sa.column("status", sa.String()),
            sa.column("reason", sa.String()),
            sa.column("probed_at", sa.DateTime(timezone=True)),
            sa.column("updated_at", sa.DateTime(timezone=True)),
        ),
        [
            {
                "id": "iam-03-oidc",
                "status": "not_configured",
                "reason": "provider_not_configured",
                "probed_at": None,
                "updated_at": datetime.now(UTC),
            },
            {
                "id": "src-05-relay",
                "status": "disabled",
                "reason": "feature_disabled",
                "probed_at": None,
                "updated_at": datetime.now(UTC),
            },
            {
                "id": "agt-04-model-fallback",
                "status": "disabled",
                "reason": "feature_disabled",
                "probed_at": None,
                "updated_at": datetime.now(UTC),
            },
            {
                "id": "san-04-fleet-sandbox",
                "status": "unsupported",
                "reason": "runtime_not_supported",
                "probed_at": None,
                "updated_at": datetime.now(UTC),
            },
            {
                "id": "ext-02-mcp",
                "status": "disabled",
                "reason": "feature_disabled",
                "probed_at": None,
                "updated_at": datetime.now(UTC),
            },
        ],
    )
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
    # OIDC sessions cannot satisfy the restored pre-U28 constraint. Revoking these
    # short-lived sessions is the only rollback data change; credentials remain intact.
    op.execute("DELETE FROM public.sessions WHERE auth_strength = 'oidc'")
    _drop_session_auth_strength_constraint()
    op.execute(
        "ALTER TABLE public.sessions ADD CONSTRAINT "
        "ck_sessions_session_auth_strength_valid "
        "CHECK (auth_strength IN ('password','mfa'))"
    )
    _restore_last_admin_guard()
    op.drop_table("oidc_membership_grants")
    op.drop_table("oidc_group_mappings")
    op.drop_index("ix_oidc_identities_user", table_name="oidc_identities")
    op.drop_table("oidc_identities")
    op.drop_index("ix_oidc_auth_transactions_expiry", table_name="oidc_auth_transactions")
    op.drop_table("oidc_auth_transactions")
    op.drop_table("oidc_providers")
    op.drop_table("extension_capabilities")
