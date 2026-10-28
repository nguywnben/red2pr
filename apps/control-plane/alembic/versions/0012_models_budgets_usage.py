"""Meta Muse model registry, capability snapshots, atomic NUMERIC budgets & usage ledger.

Revision ID: 0012_models_budgets_usage
Revises: 0011_profiles_and_reproduction_runs
Create Date: 2026-10-28T17:20:00Z

Implements Unit U16 (`AGT-01`, `AGT-03`, `A-20`, `S-17`, `S-18`, `S-19`, `NFR-06`,
`ADR-008`, `ADR-020`, `ADR-037`, `SEC-012`, `SEC-013`, `SEC-017`, `SEC-018`,
`SEC-023`, `SEC-032`, `SEC-033`):
- Creates `workspace_model_configs` storing per-workspace Meta Muse endpoint, `SecretBroker`
  credential reference (`purpose='meta_inference'`), active `inference` consent reference,
  pricing revisions, `NFR-06` budget policy defaults, and `muse-wonder-1.0` escalation rules.
- Creates immutable `model_capability_snapshots` storing observed consented capability probe
  verdicts for `muse-spark-1.3` and `muse-wonder-1.0` protected by an append-only trigger.
- Creates `budget_accounts` and `budget_reservations` using exact `NUMERIC(18, 6)` monetary
  columns (zero floating point) and DB-enforced cap invariants supporting `SELECT ... FOR UPDATE`
  atomic pre-call worst-case reservation and settlement (`SEC-033`).
- Creates append-only `usage_ledger` (`S-17` `ModelUsageRecord`, zero raw CoT columns,
  `unknown` usage strictly `NULL` and never coerced to `0`) protected by an append-only
  PL/pgSQL trigger (`SQLSTATE 55000`).
- `ENABLE` + `FORCE ROW LEVEL SECURITY` across all 5 tables (52 total forced-RLS tables).
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

revision: str = "0012_models_budgets_usage"
down_revision: str | Sequence[str] | None = "0011_profiles_and_reproduction_runs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

_U16_TABLES: tuple[str, ...] = (
    "workspace_model_configs",
    "model_capability_snapshots",
    "budget_accounts",
    "budget_reservations",
    "usage_ledger",
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
    conn = op.get_bind()

    op.execute(
        "ALTER TABLE IF EXISTS public.alembic_version ALTER COLUMN version_num TYPE VARCHAR(128);"
    )

    # 1. Per-workspace Meta Muse configuration, secret ref, pricing & budget/escalation policy
    op.create_table(
        "workspace_model_configs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column(
            "endpoint_base_url",
            sa.String(length=2048),
            nullable=False,
            server_default=sa.text("'https://api.meta.ai/v1'"),
        ),
        sa.Column("endpoint_registration_id", sa.String(length=36), nullable=True),
        sa.Column("credential_secret_ref", sa.String(length=128), nullable=True),
        sa.Column("credential_secret_version", sa.Integer(), nullable=True),
        sa.Column("active_inference_consent_id", sa.String(length=36), nullable=True),
        sa.Column(
            "pricing_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "budget_policy_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "escalation_policy_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("suspension_reason", sa.String(length=64), nullable=True),
        sa.Column("status_detail", sa.String(length=1000), nullable=True),
        sa.Column("retry_after_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by_user_id", sa.String(length=36), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_workspace_model_configs"),
        sa.UniqueConstraint("workspace_id", name="uq_workspace_model_configs_workspace_id"),
        sa.UniqueConstraint(
            "workspace_id", "id", name="uq_workspace_model_configs_workspace_id_id"
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_workspace_model_configs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["endpoint_registration_id"],
            ["endpoint_registrations.id"],
            name="fk_workspace_model_configs_endpoint_reg_endpoint_registrations",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["active_inference_consent_id"],
            ["consents.id"],
            name="fk_workspace_model_configs_consent_id_consents",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by_user_id"],
            ["users.id"],
            name="fk_workspace_model_configs_updated_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "suspension_reason IS NULL OR suspension_reason IN ("
            "'maintenance', 'model_unavailable', 'quota', "
            "'worker_unavailable', 'operator_pause'"
            ")",
            name="ck_workspace_model_configs_model_cfg_suspension_valid",
        ),
        sa.CheckConstraint(
            "version >= 1",
            name="ck_workspace_model_configs_version_pos",
        ),
    )

    # 2. Immutable capability probe snapshots per workspace & Meta model (AGT-01)
    op.create_table(
        "model_capability_snapshots",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("model_id", sa.String(length=120), nullable=False),
        sa.Column("tier_role", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column(
            "capabilities_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("provider_request_id", sa.String(length=256), nullable=True),
        sa.Column("consent_id", sa.String(length=36), nullable=True),
        sa.Column("probed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status_detail", sa.String(length=1000), nullable=True),
        sa.Column("suspension_reason", sa.String(length=64), nullable=True),
        sa.Column("retry_after_seconds", sa.Integer(), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_model_capability_snapshots"),
        sa.UniqueConstraint(
            "workspace_id", "id", name="uq_model_capability_snapshots_workspace_id_id"
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_model_capability_snapshots_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["consent_id"],
            ["consents.id"],
            name="fk_model_capability_snapshots_consent_id_consents",
            ondelete="SET NULL",
        ),
        sa.CheckConstraint(
            "model_id IN ('muse-spark-1.3', 'muse-wonder-1.0')",
            name="ck_model_capability_snapshots_model_snapshot_model_id_valid",
        ),
        sa.CheckConstraint(
            "tier_role IN ('primary', 'escalation')",
            name="ck_model_capability_snapshots_model_snapshot_tier_role_valid",
        ),
        sa.CheckConstraint(
            "status IN ('available', 'unavailable', 'not_probed', 'degraded', 'disabled')",
            name="ck_model_capability_snapshots_model_snapshot_status_valid",
        ),
        sa.CheckConstraint(
            "suspension_reason IS NULL OR suspension_reason IN ("
            "'maintenance', 'model_unavailable', 'quota', "
            "'worker_unavailable', 'operator_pause'"
            ")",
            name="ck_model_capability_snapshots_model_snapshot_suspension_valid",
        ),
        sa.CheckConstraint(
            "retry_after_seconds IS NULL OR retry_after_seconds >= 0",
            name="ck_model_capability_snapshots_model_snapshot_retry_nonneg",
        ),
        sa.CheckConstraint(
            "version = 1",
            name="ck_model_capability_snapshots_model_snapshot_immutable_version",
        ),
    )
    op.create_index(
        "ix_model_capability_snapshots_ws_model_probed",
        "model_capability_snapshots",
        ["workspace_id", "model_id", "probed_at", "id"],
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.red2pr_forbid_model_snapshot_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET red2pr.scope_mode = 'instance_admin'
        AS $$
        BEGIN
            RAISE EXCEPTION
                'append_only_table_violation: % on model_capability_snapshots forbidden (AGT-01)',
                TG_OP
                USING ERRCODE = '55000';
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_model_capability_snapshots_immutable
        BEFORE UPDATE OR DELETE ON public.model_capability_snapshots
        FOR EACH ROW EXECUTE FUNCTION public.red2pr_forbid_model_snapshot_mutation();
        """
    )

    # 3. Row-locked NUMERIC(18, 6) token, call, attempt & cost budget accounts (AGT-03, SEC-033)
    op.create_table(
        "budget_accounts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=True),
        sa.Column("repair_id", sa.String(length=36), nullable=True),
        sa.Column("scope_kind", sa.String(length=32), nullable=False),
        sa.Column("scope_key", sa.String(length=120), nullable=False),
        sa.Column(
            "currency",
            sa.String(length=3),
            nullable=False,
            server_default=sa.text("'USD'"),
        ),
        sa.Column("cost_cap", sa.Numeric(precision=18, scale=6), nullable=False),
        sa.Column(
            "reserved_cost",
            sa.Numeric(precision=18, scale=6),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "settled_cost",
            sa.Numeric(precision=18, scale=6),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "unknown_cost",
            sa.Numeric(precision=18, scale=6),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("token_cap", sa.Integer(), nullable=False),
        sa.Column(
            "reserved_tokens",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "settled_tokens",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "unknown_tokens",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("call_cap", sa.Integer(), nullable=False),
        sa.Column(
            "reserved_calls",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "settled_calls",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "unknown_calls",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "max_patch_attempts",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("2"),
        ),
        sa.Column(
            "patch_attempts_used",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "max_wall_seconds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1800"),
        ),
        sa.Column(
            "threshold_alert_emitted",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_budget_accounts"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_budget_accounts_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "scope_kind",
            "scope_key",
            name="uq_budget_accounts_ws_scope_kind_key",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_budget_accounts_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "scope_kind IN ('workspace_daily', 'workspace_total', 'repair_session', 'model_probe')",
            name="ck_budget_accounts_budget_scope_kind_valid",
        ),
        sa.CheckConstraint(
            "currency ~ '^[A-Z]{3}$'",
            name="ck_budget_accounts_budget_currency_iso",
        ),
        sa.CheckConstraint(
            "cost_cap >= 0 AND reserved_cost >= 0 AND settled_cost >= 0 AND unknown_cost >= 0",
            name="ck_budget_accounts_budget_costs_nonneg",
        ),
        sa.CheckConstraint(
            "token_cap >= 0 AND reserved_tokens >= 0 "
            "AND settled_tokens >= 0 AND unknown_tokens >= 0",
            name="ck_budget_accounts_budget_tokens_nonneg",
        ),
        sa.CheckConstraint(
            "call_cap >= 0 AND reserved_calls >= 0 AND settled_calls >= 0 AND unknown_calls >= 0",
            name="ck_budget_accounts_budget_calls_nonneg",
        ),
        sa.CheckConstraint(
            "max_patch_attempts >= 0 AND patch_attempts_used >= 0 "
            "AND patch_attempts_used <= max_patch_attempts",
            name="ck_budget_accounts_budget_patch_attempts_bounds",
        ),
        sa.CheckConstraint(
            "max_wall_seconds >= 0",
            name="ck_budget_accounts_budget_wall_seconds_nonneg",
        ),
        sa.CheckConstraint(
            "reserved_calls = 0 OR ("
            "(reserved_cost + settled_cost + unknown_cost) <= cost_cap "
            "AND (reserved_tokens + settled_tokens + unknown_tokens) <= token_cap "
            "AND (reserved_calls + settled_calls + unknown_calls) <= call_cap"
            ")",
            name="ck_budget_accounts_budget_active_reservation_within_caps",
        ),
        sa.CheckConstraint(
            "version >= 1",
            name="ck_budget_accounts_version_pos",
        ),
    )
    op.create_index(
        "ix_budget_accounts_ws_scope_window",
        "budget_accounts",
        ["workspace_id", "scope_kind", "window_started_at"],
    )

    # 4. Pre-call worst-case budget reservations & settlement records (AGT-03, SEC-033)
    op.create_table(
        "budget_reservations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=True),
        sa.Column("repair_id", sa.String(length=36), nullable=True),
        sa.Column("budget_account_id", sa.String(length=36), nullable=False),
        sa.Column("secondary_budget_account_id", sa.String(length=36), nullable=True),
        sa.Column("consent_id", sa.String(length=36), nullable=False),
        sa.Column("model_id", sa.String(length=120), nullable=False),
        sa.Column("pricing_revision", sa.String(length=120), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'reserved'"),
        ),
        sa.Column("estimated_input_tokens", sa.Integer(), nullable=False),
        sa.Column("max_output_tokens", sa.Integer(), nullable=False),
        sa.Column("actual_input_tokens", sa.Integer(), nullable=True),
        sa.Column("actual_output_tokens", sa.Integer(), nullable=True),
        sa.Column("reserved_cost", sa.Numeric(precision=18, scale=6), nullable=False),
        sa.Column("settled_cost", sa.Numeric(precision=18, scale=6), nullable=True),
        sa.Column(
            "currency",
            sa.String(length=3),
            nullable=False,
            server_default=sa.text("'USD'"),
        ),
        sa.Column("provider_request_id", sa.String(length=256), nullable=True),
        sa.Column("prompt_redacted_digest", sa.String(length=64), nullable=False),
        sa.Column("response_redacted_digest", sa.String(length=64), nullable=True),
        sa.Column(
            "tool_call_digests_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "late_after_cancel",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("correlation_id", sa.String(length=120), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name="pk_budget_reservations"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_budget_reservations_workspace_id_id"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_budget_reservations_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "budget_account_id"],
            ["budget_accounts.workspace_id", "budget_accounts.id"],
            name="fk_budget_reservations_tenant_account_budget_accounts",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["consent_id"],
            ["consents.id"],
            name="fk_budget_reservations_consent_id_consents",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "model_id IN ('muse-spark-1.3', 'muse-wonder-1.0')",
            name="ck_budget_reservations_reservation_model_id_valid",
        ),
        sa.CheckConstraint(
            "status IN ('reserved', 'settled', 'released', 'unknown_outcome')",
            name="ck_budget_reservations_reservation_status_valid",
        ),
        sa.CheckConstraint(
            "estimated_input_tokens >= 0 AND max_output_tokens >= 0",
            name="ck_budget_reservations_reservation_estimated_tokens_nonneg",
        ),
        sa.CheckConstraint(
            "(actual_input_tokens IS NULL OR actual_input_tokens >= 0) "
            "AND (actual_output_tokens IS NULL OR actual_output_tokens >= 0)",
            name="ck_budget_reservations_reservation_actual_tokens_nonneg",
        ),
        sa.CheckConstraint(
            "reserved_cost >= 0 AND (settled_cost IS NULL OR settled_cost >= 0)",
            name="ck_budget_reservations_reservation_costs_nonneg",
        ),
        sa.CheckConstraint(
            "status <> 'unknown_outcome' OR settled_cost IS NULL",
            name="ck_budget_reservations_reservation_unknown_never_settled",
        ),
        sa.CheckConstraint(
            "currency ~ '^[A-Z]{3}$'",
            name="ck_budget_reservations_reservation_currency_iso",
        ),
        sa.CheckConstraint(
            "version >= 1",
            name="ck_budget_reservations_version_pos",
        ),
    )
    op.create_index(
        "ix_budget_reservations_ws_account_status",
        "budget_reservations",
        ["workspace_id", "budget_account_id", "status", "created_at"],
    )

    # 5. Append-only S-17 ModelUsageRecord ledger (unknown != 0, zero raw CoT columns)
    op.create_table(
        "usage_ledger",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=True),
        sa.Column("repair_id", sa.String(length=36), nullable=True),
        sa.Column("reservation_id", sa.String(length=36), nullable=False),
        sa.Column("provider_request_id", sa.String(length=256), nullable=True),
        sa.Column("model_id", sa.String(length=120), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=True),
        sa.Column("output_tokens", sa.Integer(), nullable=True),
        sa.Column("estimated_cost", sa.Numeric(precision=18, scale=6), nullable=False),
        sa.Column("settled_cost", sa.Numeric(precision=18, scale=6), nullable=True),
        sa.Column(
            "currency",
            sa.String(length=3),
            nullable=False,
            server_default=sa.text("'USD'"),
        ),
        sa.Column("pricing_revision", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("correlation_id", sa.String(length=120), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name="pk_usage_ledger"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_usage_ledger_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "reservation_id",
            name="uq_usage_ledger_ws_reservation_id",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_usage_ledger_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "reservation_id"],
            ["budget_reservations.workspace_id", "budget_reservations.id"],
            name="fk_usage_ledger_tenant_reservation_budget_reservations",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "model_id IN ('muse-spark-1.3', 'muse-wonder-1.0')",
            name="ck_usage_ledger_usage_model_id_valid",
        ),
        sa.CheckConstraint(
            "status IN ('reserved', 'settled', 'released', 'failed', 'unknown')",
            name="ck_usage_ledger_usage_status_valid",
        ),
        sa.CheckConstraint(
            "(input_tokens IS NULL OR input_tokens >= 0) "
            "AND (output_tokens IS NULL OR output_tokens >= 0)",
            name="ck_usage_ledger_usage_tokens_nonneg",
        ),
        sa.CheckConstraint(
            "estimated_cost >= 0 AND (settled_cost IS NULL OR settled_cost >= 0)",
            name="ck_usage_ledger_usage_costs_nonneg",
        ),
        sa.CheckConstraint(
            "status <> 'unknown' OR ("
            "settled_cost IS NULL AND input_tokens IS NULL AND output_tokens IS NULL"
            ")",
            name="ck_usage_ledger_usage_unknown_never_zero",
        ),
        sa.CheckConstraint(
            "status <> 'settled' OR ("
            "settled_cost IS NOT NULL AND input_tokens IS NOT NULL AND output_tokens IS NOT NULL"
            ")",
            name="ck_usage_ledger_usage_settled_complete",
        ),
        sa.CheckConstraint(
            "currency ~ '^[A-Z]{3}$'",
            name="ck_usage_ledger_usage_currency_iso",
        ),
        sa.CheckConstraint(
            "version = 1",
            name="ck_usage_ledger_usage_immutable_version",
        ),
    )
    op.create_index(
        "ix_usage_ledger_ws_created",
        "usage_ledger",
        ["workspace_id", "created_at", "id"],
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.red2pr_forbid_usage_ledger_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET red2pr.scope_mode = 'instance_admin'
        AS $$
        BEGIN
            RAISE EXCEPTION
                'append_only_table_violation: % on usage_ledger is forbidden (S-17 / AGT-03)',
                TG_OP
                USING ERRCODE = '55000';
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_usage_ledger_immutable
        BEFORE UPDATE OR DELETE ON public.usage_ledger
        FOR EACH ROW EXECUTE FUNCTION public.red2pr_forbid_usage_ledger_mutation();
        """
    )

    # 6. Enable + Force Row-Level Security on all 5 U16 workspace-scoped tables (SEC-032)
    for tbl in _U16_TABLES:
        op.execute(f"ALTER TABLE public.{tbl} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE public.{tbl} FORCE ROW LEVEL SECURITY;")
        op.execute(
            f"""
            CREATE POLICY rls_{tbl}_select ON public.{tbl}
            FOR SELECT
            USING (
                (
                    current_setting('red2pr.scope_mode', true) = 'workspace'
                    AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
                )
                OR current_setting('red2pr.scope_mode', true)
                IN ('instance_admin', 'audit_verifier')
            );
            """
        )
        op.execute(
            f"""
            CREATE POLICY rls_{tbl}_write ON public.{tbl}
            FOR ALL
            USING (
                (
                    current_setting('red2pr.scope_mode', true) = 'workspace'
                    AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
                )
                OR current_setting('red2pr.scope_mode', true) = 'instance_admin'
            )
            WITH CHECK (
                (
                    current_setting('red2pr.scope_mode', true) = 'workspace'
                    AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
                )
                OR current_setting('red2pr.scope_mode', true) = 'instance_admin'
            );
            """
        )

    # 7. Least-privilege table grants for runtime app role
    joined_tables = ", ".join(f"public.{t}" for t in _U16_TABLES)
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {joined_tables} TO "{app_role}";')

    # 8. Record expand-phase metadata in schema_migrations
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
            "parent_revision": "0011_profiles_and_reproduction_runs",
            "checksum": _migration_checksum_sha256(),
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    op.execute("DROP TRIGGER IF EXISTS trg_usage_ledger_immutable ON public.usage_ledger;")
    op.execute("DROP FUNCTION IF EXISTS public.red2pr_forbid_usage_ledger_mutation();")
    op.execute(
        "DROP TRIGGER IF EXISTS trg_model_capability_snapshots_immutable "
        "ON public.model_capability_snapshots;"
    )
    op.execute("DROP FUNCTION IF EXISTS public.red2pr_forbid_model_snapshot_mutation();")
    for tbl in reversed(_U16_TABLES):
        op.drop_table(tbl)
