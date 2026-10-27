"""IAM users, bootstrap tokens, sessions, TOTP MFA, recovery codes & auth rate limits.

Revision ID: 0002_iam_users_sessions_mfa
Revises: 0001_foundation_spine
Create Date: 2026-10-27T01:00:00Z

Implements Unit U05 (`IAM-01`, `A-01`, `A-02`, `A-03`, `S-06`, `W-01`, `NFR-05`,
`SEC-026`, `SEC-032`, `SEC-038`):
- `users`: S-06 user accounts with Argon2id password digests, `grant_epoch`, and active
  instance-owner non-deletion trigger (`W-01`).
- `bootstrap_tokens`: expiring one-use SHA-256 hashed owner claim tokens (`A-01`).
- `sessions`: 256-bit opaque cookie sessions (SHA-256 hashed at rest), 30m idle / 12h
  absolute expiry, 5m `step_up_at`, and `grant_epoch` / `recovery_epoch` fences.
- `mfa_credentials`: RFC 6238 TOTP credentials referencing Z2 `secret_entries` (`mfa_totp`),
  partial unique active-credential index, and `last_used_timestep` replay prevention.
- `recovery_codes`: single-use HMAC-SHA256 hashed break-glass codes (`SEC-038`).
- `auth_challenges`: short-lived cookie-free MFA login challenge tickets.
- `auth_rate_limits`: multi-process PostgreSQL sliding-window failure buckets (`NFR-05`).
- `ENABLE` + `FORCE ROW LEVEL SECURITY` and least-privilege grants for `red2pr_app`.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Sequence
from pathlib import Path

import sqlalchemy as sa
from alembic import context, op

revision: str = "0002_iam_users_sessions_mfa"
down_revision: str | Sequence[str] | None = "0001_foundation_spine"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

_U05_TABLES: tuple[str, ...] = (
    "users",
    "bootstrap_tokens",
    "sessions",
    "mfa_credentials",
    "recovery_codes",
    "auth_challenges",
    "auth_rate_limits",
)


def _resolve_app_role_name() -> str:
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
    app_role = _resolve_app_role_name()

    # 1. users (S-06 instance-scoped accounts)
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("username", sa.String(length=120), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=True),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column(
            "is_instance_owner",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'active'"),
        ),
        sa.Column(
            "mfa_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "grant_epoch",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("username", name="uq_users_username"),
        sa.UniqueConstraint("email", name="uq_users_email"),
        sa.CheckConstraint(
            "status IN ('active', 'disabled')",
            name="ck_users_user_status_valid",
        ),
        sa.CheckConstraint("grant_epoch >= 1", name="ck_users_user_grant_epoch_pos"),
        sa.CheckConstraint("version >= 1", name="ck_users_version_pos"),
    )

    # 2. bootstrap_tokens (one-time expiring SHA-256 hashed owner claim tokens)
    op.create_table(
        "bootstrap_tokens",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "loopback_only",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claimed_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_bootstrap_tokens"),
        sa.UniqueConstraint("token_hash", name="uq_bootstrap_tokens_token_hash"),
        sa.ForeignKeyConstraint(
            ["claimed_by_user_id"],
            ["users.id"],
            name="fk_bootstrap_tokens_claimed_by_user_id_users",
            ondelete="RESTRICT",
        ),
    )

    # 3. sessions (S-06 authenticated browser/CLI sessions, SHA-256 hashed cookie token)
    op.create_table(
        "sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("csrf_secret_hash", sa.String(length=64), nullable=False),
        sa.Column("auth_strength", sa.String(length=32), nullable=False),
        sa.Column("step_up_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "grant_epoch",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "recovery_epoch",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("client_ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=256), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.String(length=120), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_sessions"),
        sa.UniqueConstraint("token_hash", name="uq_sessions_token_hash"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_sessions_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "auth_strength IN ('password', 'mfa')",
            name="ck_sessions_session_auth_strength_valid",
        ),
        sa.CheckConstraint("grant_epoch >= 1", name="ck_sessions_session_grant_epoch_pos"),
        sa.CheckConstraint(
            "recovery_epoch >= 1",
            name="ck_sessions_session_recovery_epoch_pos",
        ),
        sa.CheckConstraint("version >= 1", name="ck_sessions_version_pos"),
    )
    op.create_index(
        "ix_sessions_user_active",
        "sessions",
        ["user_id", "revoked_at", "expires_at"],
    )

    # 4. mfa_credentials (RFC 6238 TOTP referencing Z2 secret_entries)
    op.create_table(
        "mfa_credentials",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("secret_ref", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("last_used_timestep", sa.BigInteger(), nullable=True),
        sa.Column("challenge_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_mfa_credentials"),
        sa.UniqueConstraint("secret_ref", name="uq_mfa_credentials_secret_ref"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_mfa_credentials_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'active', 'revoked')",
            name="ck_mfa_credentials_mfa_credential_status_valid",
        ),
        sa.CheckConstraint("version >= 1", name="ck_mfa_credentials_version_pos"),
    )
    op.create_index(
        "ix_mfa_credentials_user_status",
        "mfa_credentials",
        ["user_id", "status"],
    )
    op.create_index(
        "uq_mfa_credentials_user_active",
        "mfa_credentials",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )

    # 5. recovery_codes (single-use HMAC-SHA256 hashed break-glass codes)
    op.create_table(
        "recovery_codes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("batch_id", sa.String(length=36), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_recovery_codes"),
        sa.UniqueConstraint("code_hash", name="uq_recovery_codes_code_hash"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_recovery_codes_user_id_users",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_recovery_codes_user_unused",
        "recovery_codes",
        ["user_id", "used_at", "revoked_at"],
    )

    # 6. auth_challenges (cookie-free MFA login challenge tickets)
    op.create_table(
        "auth_challenges",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column(
            "purpose",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'login_mfa'"),
        ),
        sa.Column("client_ip", sa.String(length=64), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "failed_attempts",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_auth_challenges"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_auth_challenges_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "purpose IN ('login_mfa')",
            name="ck_auth_challenges_auth_challenge_purpose_valid",
        ),
        sa.CheckConstraint(
            "failed_attempts >= 0",
            name="ck_auth_challenges_auth_challenge_attempts_nonneg",
        ),
    )
    op.create_index(
        "ix_auth_challenges_user_expires",
        "auth_challenges",
        ["user_id", "expires_at"],
    )

    # 7. auth_rate_limits (multi-process sliding-window failure attempts for NFR-05 & SEC-038)
    op.create_table(
        "auth_rate_limits",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("bucket_key", sa.String(length=256), nullable=False),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_auth_rate_limits"),
        sa.CheckConstraint(
            "action IN ('login', 'step_up', 'recovery', 'bootstrap_claim', 'mfa_verify')",
            name="ck_auth_rate_limits_auth_rate_action_valid",
        ),
    )
    op.create_index(
        "ix_auth_rate_limits_lookup",
        "auth_rate_limits",
        ["action", "bucket_key", "attempted_at"],
    )
    op.create_index(
        "ix_auth_rate_limits_expires",
        "auth_rate_limits",
        ["expires_at"],
    )

    # 8. W-01 invariant trigger: forbid deleting or disabling the last active instance owner
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.red2pr_protect_last_active_owner()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET red2pr.scope_mode = 'instance_admin'
        AS $$
        DECLARE
            v_remaining BIGINT;
        BEGIN
            IF OLD.is_instance_owner IS TRUE AND OLD.status = 'active' THEN
                IF TG_OP = 'DELETE'
                   OR NEW.is_instance_owner IS NOT TRUE
                   OR NEW.status <> 'active' THEN
                    SELECT COUNT(*) INTO v_remaining
                    FROM public.users
                    WHERE is_instance_owner IS TRUE
                      AND status = 'active'
                      AND id <> OLD.id;
                    IF v_remaining = 0 THEN
                        RAISE EXCEPTION
                            'active_owner_removal_forbidden: last active owner cannot be removed'
                            USING ERRCODE = '55000';
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
        CREATE TRIGGER trg_users_protect_last_active_owner
        BEFORE UPDATE OR DELETE ON public.users
        FOR EACH ROW EXECUTE FUNCTION public.red2pr_protect_last_active_owner();
        """
    )

    # 9. Enable & FORCE Row-Level Security on all U05 tables (SEC-032)
    for tbl in _U05_TABLES:
        op.execute(f"ALTER TABLE public.{tbl} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE public.{tbl} FORCE ROW LEVEL SECURITY;")

    # users: readable in instance, workspace (for membership joins), and audit_verifier scopes;
    # sessions: readable strictly in instance and audit_verifier scopes (never workspace scope)
    op.execute(
        """
        CREATE POLICY rls_users_select ON public.users
        FOR SELECT
        USING (
            current_setting('red2pr.scope_mode', true)
            IN ('instance_only', 'instance_admin', 'workspace', 'audit_verifier')
        );
        """
    )
    op.execute(
        """
        CREATE POLICY rls_sessions_select ON public.sessions
        FOR SELECT
        USING (
            current_setting('red2pr.scope_mode', true)
            IN ('instance_only', 'instance_admin', 'audit_verifier')
        );
        """
    )
    for readable_tbl in ("users", "sessions"):
        op.execute(
            f"""
            CREATE POLICY rls_{readable_tbl}_insert ON public.{readable_tbl}
            FOR INSERT
            WITH CHECK (
                current_setting('red2pr.scope_mode', true)
                IN ('instance_only', 'instance_admin')
            );
            """
        )
        op.execute(
            f"""
            CREATE POLICY rls_{readable_tbl}_update ON public.{readable_tbl}
            FOR UPDATE
            USING (
                current_setting('red2pr.scope_mode', true)
                IN ('instance_only', 'instance_admin')
            )
            WITH CHECK (
                current_setting('red2pr.scope_mode', true)
                IN ('instance_only', 'instance_admin')
            );
            """
        )
        op.execute(
            f"""
            CREATE POLICY rls_{readable_tbl}_delete ON public.{readable_tbl}
            FOR DELETE
            USING (
                current_setting('red2pr.scope_mode', true)
                IN ('instance_only', 'instance_admin')
            );
            """
        )

    # Strictly instance-scoped IAM credential & rate-limit tables (zero workspace visibility)
    for inst_tbl in (
        "bootstrap_tokens",
        "mfa_credentials",
        "recovery_codes",
        "auth_challenges",
        "auth_rate_limits",
    ):
        op.execute(
            f"""
            CREATE POLICY rls_{inst_tbl}_instance_isolation ON public.{inst_tbl}
            FOR ALL
            USING (
                current_setting('red2pr.scope_mode', true)
                IN ('instance_only', 'instance_admin')
            )
            WITH CHECK (
                current_setting('red2pr.scope_mode', true)
                IN ('instance_only', 'instance_admin')
            );
            """
        )

    # 10. Least-privilege table grants for runtime app role
    joined_tables = ", ".join(f"public.{t}" for t in _U05_TABLES)
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
            "parent_revision": "0001_foundation_spine",
            "checksum": _migration_checksum_sha256(),
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )

    op.execute("DROP TRIGGER IF EXISTS trg_users_protect_last_active_owner ON public.users;")
    op.execute("DROP FUNCTION IF EXISTS public.red2pr_protect_last_active_owner();")

    for tbl in reversed(_U05_TABLES):
        op.drop_table(tbl)
