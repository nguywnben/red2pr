"""Durable setup wizard checkpoints, outbound consents, endpoint registry & RLS.

Revision ID: 0004_setup_consents_endpoints
Revises: 0003_workspaces_rbac_grants
Create Date: 2026-10-27T04:00:00Z

Implements Unit U07 (`INS-02`, `A-01`, `S-18`, `UI-S01`, `W-01`, `ADR-037`,
`SEC-014`, `SEC-018`, `SEC-032`, `SEC-033`):
- `setup_checkpoints`: durable 10-phase onboarding checkpoints with optimistic
  `checkpoint_token` concurrency, redacted draft state, probe verdicts, and partial
  uniqueness on `(instance_id) WHERE is_current_phase IS TRUE`.
- `consents`: explicit data-sharing consent ledger separated by purpose (`inference`,
  `notification`, `telemetry`, `provider`) and scope (`instance`, `workspace`,
  `repository`), forbidding `'secret'` in `data_classes_json`.
- `endpoint_registrations`: instance-owner registered private adapter endpoints
  (`adapter`, `scheme`, `host`, `port`, `cidrs_json`, `ca_ref`) with partial uniqueness
  on active `(adapter, scheme, host, port) WHERE revoked_at IS NULL`.
- `ENABLE` + `FORCE ROW LEVEL SECURITY` on all U07 tables (`SEC-032`).
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

revision: str = "0004_setup_consents_endpoints"
down_revision: str | Sequence[str] | None = "0003_workspaces_rbac_grants"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

_U07_TABLES: tuple[str, ...] = (
    "setup_checkpoints",
    "consents",
    "endpoint_registrations",
)


def _resolve_app_role() -> str:
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
    app_role = _resolve_app_role()

    # 1. setup_checkpoints (INS-02 resumable 10-phase setup wizard persistence)
    op.create_table(
        "setup_checkpoints",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("instance_id", sa.String(length=36), nullable=False),
        sa.Column("phase", sa.String(length=64), nullable=False),
        sa.Column("phase_order", sa.SmallInteger(), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column(
            "is_current_phase",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("checkpoint_token", sa.String(length=120), nullable=False),
        sa.Column(
            "draft_payload_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("probe_status", sa.String(length=32), nullable=True),
        sa.Column("probe_detail", sa.String(length=512), nullable=True),
        sa.Column(
            "blocking_reasons_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("completed_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_setup_checkpoints"),
        sa.UniqueConstraint("instance_id", "phase", name="uq_setup_checkpoints_instance_phase"),
        sa.ForeignKeyConstraint(
            ["instance_id"],
            ["instances.id"],
            name="fk_setup_checkpoints_instance_id_instances",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["completed_by_user_id"],
            ["users.id"],
            name="fk_setup_checkpoints_completed_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "phase IN ("
            "'owner_claim', 'topology_tls', 'storage_keys', 'workspace_admin', "
            "'provider_connect', 'model_consent', 'worker_readiness', 'repo_policy', "
            "'notifications', 'readiness_review'"
            ")",
            name="ck_setup_checkpoints_setup_phase_valid",
        ),
        sa.CheckConstraint(
            "phase_order >= 1 AND phase_order <= 10",
            name="ck_setup_checkpoints_setup_phase_order_valid",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'completed', 'not_configured', 'degraded', 'blocked')",
            name="ck_setup_checkpoints_setup_status_valid",
        ),
        sa.CheckConstraint(
            "probe_status IS NULL OR probe_status IN ("
            "'passed', 'failed', 'needs_admin', 'needs_restart', "
            "'not_configured', 'blocked', 'unsupported'"
            ")",
            name="ck_setup_checkpoints_setup_probe_status_valid",
        ),
        sa.CheckConstraint("version >= 1", name="ck_setup_checkpoints_version_pos"),
    )
    op.create_index(
        "ix_setup_checkpoints_instance_order",
        "setup_checkpoints",
        ["instance_id", "phase_order"],
    )
    op.create_index(
        "uq_setup_checkpoints_one_current",
        "setup_checkpoints",
        ["instance_id"],
        unique=True,
        postgresql_where=sa.text("is_current_phase IS TRUE"),
    )

    # 2. consents (S-18 & SEC-018 explicit data-sharing consent ledger)
    op.create_table(
        "consents",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("scope", sa.String(length=32), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=True),
        sa.Column("repository_id", sa.String(length=36), nullable=True),
        sa.Column("destination", sa.String(length=512), nullable=False),
        sa.Column(
            "data_classes_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("granted_by_user_id", sa.String(length=36), nullable=False),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("revoked_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.String(length=512), nullable=True),
        sa.Column(
            "policy_version",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
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
        sa.PrimaryKeyConstraint("id", name="pk_consents"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_consents_workspace_id_id"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_consents_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["granted_by_user_id"],
            ["users.id"],
            name="fk_consents_granted_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["revoked_by_user_id"],
            ["users.id"],
            name="fk_consents_revoked_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "purpose IN ('inference', 'notification', 'telemetry', 'provider')",
            name="ck_consents_consent_purpose_valid",
        ),
        sa.CheckConstraint(
            "scope IN ('instance', 'workspace', 'repository')",
            name="ck_consents_consent_scope_valid",
        ),
        sa.CheckConstraint(
            "(scope = 'instance' AND workspace_id IS NULL AND repository_id IS NULL) OR "
            "(scope = 'workspace' AND workspace_id IS NOT NULL AND repository_id IS NULL) OR "
            "(scope = 'repository' AND workspace_id IS NOT NULL AND repository_id IS NOT NULL)",
            name="ck_consents_consent_scope_binding_valid",
        ),
        sa.CheckConstraint(
            "NOT jsonb_exists(data_classes_json, 'secret')",
            name="ck_consents_consent_forbid_secret_class",
        ),
        sa.CheckConstraint("policy_version >= 1", name="ck_consents_consent_policy_version_pos"),
        sa.CheckConstraint("version >= 1", name="ck_consents_version_pos"),
    )
    op.create_index(
        "ix_consents_purpose_active",
        "consents",
        ["purpose", "revoked_at", "created_at", "id"],
    )
    op.create_index(
        "ix_consents_workspace_purpose",
        "consents",
        ["workspace_id", "purpose", "revoked_at"],
    )

    # 3. endpoint_registrations (ADR-037 owner-registered private adapter endpoints)
    op.create_table(
        "endpoint_registrations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("adapter", sa.String(length=32), nullable=False),
        sa.Column("scheme", sa.String(length=16), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column(
            "cidrs_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("ca_ref", sa.String(length=128), nullable=True),
        sa.Column("description", sa.String(length=512), nullable=True),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=False),
        sa.Column("revoked_by_user_id", sa.String(length=36), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_endpoint_registrations"),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_endpoint_registrations_created_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["revoked_by_user_id"],
            ["users.id"],
            name="fk_endpoint_registrations_revoked_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "adapter IN ("
            "'github', 'gitlab', 'meta_inference', 'oidc', 's3_artifacts', "
            "'telegram', 'slack', 'discord', 'webhook', 'smtp'"
            ")",
            name="ck_endpoint_registrations_endpoint_adapter_valid",
        ),
        sa.CheckConstraint(
            "scheme IN ('https', 'http')",
            name="ck_endpoint_registrations_endpoint_scheme_valid",
        ),
        sa.CheckConstraint(
            "port >= 1 AND port <= 65535",
            name="ck_endpoint_registrations_endpoint_port_valid",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(cidrs_json) = 'array' AND jsonb_array_length(cidrs_json) >= 1",
            name="ck_endpoint_registrations_endpoint_cidrs_nonempty",
        ),
        sa.CheckConstraint("version >= 1", name="ck_endpoint_registrations_version_pos"),
    )
    op.create_index(
        "ix_endpoint_registrations_adapter_host",
        "endpoint_registrations",
        ["adapter", "host", "port", "revoked_at"],
    )
    op.create_index(
        "uq_endpoint_registrations_active_target",
        "endpoint_registrations",
        ["adapter", "scheme", "host", "port"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )

    # 4. Enable & FORCE Row-Level Security on all U07 tables (SEC-032)
    for tbl in _U07_TABLES:
        op.execute(f"ALTER TABLE public.{tbl} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE public.{tbl} FORCE ROW LEVEL SECURITY;")

    # setup_checkpoints RLS policies: instance-scoped read, instance_admin write only
    op.execute(
        """
        CREATE POLICY rls_setup_checkpoints_select ON public.setup_checkpoints
        FOR SELECT
        USING (
            current_setting('red2pr.scope_mode', true)
            IN ('instance_only', 'instance_admin', 'audit_verifier')
        );
        """
    )
    op.execute(
        """
        CREATE POLICY rls_setup_checkpoints_write ON public.setup_checkpoints
        FOR ALL
        USING (current_setting('red2pr.scope_mode', true) = 'instance_admin')
        WITH CHECK (current_setting('red2pr.scope_mode', true) = 'instance_admin');
        """
    )

    # consents RLS policies: strict cross-workspace isolation + instance_admin management
    op.execute(
        """
        CREATE POLICY rls_consents_select ON public.consents
        FOR SELECT
        USING (
            (
                current_setting('red2pr.scope_mode', true) = 'workspace'
                AND (
                    workspace_id IS NULL
                    OR workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
                )
            )
            OR (
                current_setting('red2pr.scope_mode', true) = 'instance_only'
                AND workspace_id IS NULL
            )
            OR current_setting('red2pr.scope_mode', true) IN ('instance_admin', 'audit_verifier')
        );
        """
    )
    op.execute(
        """
        CREATE POLICY rls_consents_write ON public.consents
        FOR ALL
        USING (
            (
                current_setting('red2pr.scope_mode', true) = 'workspace'
                AND workspace_id IS NOT NULL
                AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
            )
            OR current_setting('red2pr.scope_mode', true) = 'instance_admin'
        )
        WITH CHECK (
            (
                current_setting('red2pr.scope_mode', true) = 'workspace'
                AND workspace_id IS NOT NULL
                AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
            )
            OR current_setting('red2pr.scope_mode', true) = 'instance_admin'
        );
        """
    )

    # endpoint_registrations RLS policies: adapter policy evaluation read, instance_admin write
    op.execute(
        """
        CREATE POLICY rls_endpoint_registrations_select ON public.endpoint_registrations
        FOR SELECT
        USING (
            current_setting('red2pr.scope_mode', true)
            IN ('instance_only', 'instance_admin', 'workspace', 'audit_verifier')
        );
        """
    )
    op.execute(
        """
        CREATE POLICY rls_endpoint_registrations_write ON public.endpoint_registrations
        FOR ALL
        USING (current_setting('red2pr.scope_mode', true) = 'instance_admin')
        WITH CHECK (current_setting('red2pr.scope_mode', true) = 'instance_admin');
        """
    )

    # 5. Least-privilege table grants for runtime app role
    joined_tables = ", ".join(f"public.{t}" for t in _U07_TABLES)
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {joined_tables} TO "{app_role}";')

    # 6. Record expand-phase metadata in schema_migrations
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
            "parent_revision": "0003_workspaces_rbac_grants",
            "checksum": _migration_checksum_sha256(),
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    for tbl in reversed(_U07_TABLES):
        op.drop_table(tbl)
