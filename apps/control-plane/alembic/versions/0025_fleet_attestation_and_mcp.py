"""U30 fleet runtime attestations and scoped MCP approval intents.

Revision ID: 0025_fleet_attestation_and_mcp
Revises: 0024_relay_and_model_fallback
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

revision: str = "0025_fleet_attestation_and_mcp"
down_revision: str | Sequence[str] | None = "0024_relay_and_model_fallback"
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


def _workspace_rls(table: str, role: str) -> None:
    scope = (
        "current_setting('red2pr.scope_mode', true) = 'workspace' "
        "AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')"
    )
    op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
    op.execute(f"CREATE POLICY rls_{table}_select ON public.{table} FOR SELECT USING ({scope})")
    op.execute(
        f"CREATE POLICY rls_{table}_write ON public.{table} FOR ALL "
        f"USING ({scope}) WITH CHECK ({scope})"
    )
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.{table} TO "{role}"')


def _instance_rls(table: str, role: str) -> None:
    op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY rls_{table}_instance ON public.{table} FOR ALL "
        "USING (current_setting('red2pr.scope_mode', true) IN ('instance_only','instance_admin')) "
        "WITH CHECK (current_setting('red2pr.scope_mode', true) "
        "IN ('instance_only','instance_admin'))"
    )
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.{table} TO "{role}"')


def _replace_auth_rate_action_check(*, includes_mcp: bool) -> None:
    marker = "%mcp_intent%" if includes_mcp else "%invite_accept%"
    rows = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT c.conname FROM pg_constraint AS c "
                "JOIN pg_attribute AS a ON a.attrelid = c.conrelid "
                "AND a.attnum = ANY(c.conkey) "
                "WHERE c.conrelid = 'public.auth_rate_limits'::regclass "
                "AND c.contype = 'c' AND a.attname = 'action' "
                "AND pg_get_constraintdef(c.oid) LIKE :marker"
            ),
            {"marker": marker},
        )
        .scalars()
        .all()
    )
    if len(rows) != 1:
        raise RuntimeError("Expected exactly one auth_rate_limits action constraint to replace.")
    op.drop_constraint(op.f(str(rows[0])), "auth_rate_limits", type_="check")


def upgrade() -> None:
    role = _role()
    _replace_auth_rate_action_check(includes_mcp=False)
    op.create_check_constraint(
        op.f("ck_auth_rate_limits_ck_auth_rate_limits_auth_rate_action_valid"),
        "auth_rate_limits",
        "action IN ('login','step_up','recovery','bootstrap_claim','mfa_verify',"
        "'invite_create','invite_accept','mcp_read','mcp_intent')",
    )
    op.create_table(
        "worker_attestations",
        sa.Column("worker_id", sa.String(36), primary_key=True),
        sa.Column("backend", sa.String(32), nullable=False),
        sa.Column("kernel_version", sa.String(120), nullable=False),
        sa.Column("runtime_version", sa.String(120), nullable=False),
        sa.Column("checks_json", postgresql.JSONB(), nullable=False),
        sa.Column("self_test_digest", sa.String(64), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("multi_tenant_hardened", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "backend IN ('oci_rootless','gvisor_runsc','ephemeral_vm')",
            name="worker_attestation_backend_valid",
        ),
        sa.CheckConstraint(
            "self_test_digest ~ '^[0-9a-f]{64}$'", name="worker_attestation_digest_valid"
        ),
        sa.ForeignKeyConstraint(["worker_id"], ["workers.id"], ondelete="CASCADE"),
    )
    _instance_rls("worker_attestations", role)

    op.create_table(
        "worker_trust_domains",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("worker_id", sa.String(36), nullable=False),
        sa.Column("trust_domain", sa.String(120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("workspace_id", "worker_id", name="uq_worker_trust_domains_ws_worker"),
        sa.UniqueConstraint(
            "workspace_id", "trust_domain", "worker_id", name="uq_worker_trust_domains_scope"
        ),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["worker_id"], ["workers.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_worker_trust_domains_domain", "worker_trust_domains", ["workspace_id", "trust_domain"]
    )
    _workspace_rls("worker_trust_domains", role)

    op.create_table(
        "mcp_approval_intents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("repository_id", sa.String(36), nullable=False),
        sa.Column("repair_id", sa.String(36), nullable=False),
        sa.Column("principal_id", sa.String(36), nullable=False),
        sa.Column("kind", sa.String(48), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("idempotency_key", sa.String(120), nullable=False),
        sa.Column("correlation_id", sa.String(120), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_repair_id", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("workspace_id", "id", name="uq_mcp_approval_intents_workspace_id_id"),
        sa.UniqueConstraint("token_hash", name="uq_mcp_approval_intents_token_hash"),
        sa.UniqueConstraint(
            "workspace_id",
            "principal_id",
            "idempotency_key",
            name="uq_mcp_approval_intents_idempotency",
        ),
        sa.CheckConstraint("kind = 'request_recheck'", name="mcp_intent_kind_valid"),
        sa.CheckConstraint(
            "state IN ('pending','approved','consumed','expired','cancelled')",
            name="mcp_intent_state_valid",
        ),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["principal_id"], ["users.id"], ondelete="CASCADE"),
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
    )
    op.create_index(
        "ix_mcp_intents_pending", "mcp_approval_intents", ["workspace_id", "state", "expires_at"]
    )
    _workspace_rls("mcp_approval_intents", role)
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
    op.drop_index("ix_mcp_intents_pending", table_name="mcp_approval_intents")
    op.drop_table("mcp_approval_intents")
    op.drop_index("ix_worker_trust_domains_domain", table_name="worker_trust_domains")
    op.drop_table("worker_trust_domains")
    op.drop_table("worker_attestations")
    _replace_auth_rate_action_check(includes_mcp=True)
    op.create_check_constraint(
        op.f("ck_auth_rate_limits_ck_auth_rate_limits_auth_rate_action_valid"),
        "auth_rate_limits",
        "action IN ('login','step_up','recovery','bootstrap_claim','mfa_verify',"
        "'invite_create','invite_accept')",
    )
