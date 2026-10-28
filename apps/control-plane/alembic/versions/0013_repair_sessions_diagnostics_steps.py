"""Repair sessions, agent profiles, context manifests, diagnostics, steps & patch attempts.

Revision ID: 0013_repair_sessions_diagnostics_steps
Revises: 0012_models_budgets_usage
Create Date: 2026-10-28T19:15:00Z

Implements Unit U17 (`TRI-02`, `AGT-02`, `A-20`, `S-11`, `S-12`, `S-19`, `S-20`,
`W-04`, `W-05`, `ADR-031`, `ADR-038`, `SEC-005`, `SEC-012`, `SEC-024`, `SEC-028`,
`SEC-032`, `SEC-040`):
- Creates `workspace_agent_profiles` storing bounded per-workspace agent role settings
  (`triage_diagnosis` and `bounded_patch`) without arbitrary prompt overrides.
- Creates `repair_sessions` enforcing the canonical 25-state lower_snake_case state
  machine (`docs/08` + `ADR-038`) and `ADR-031` proof-grade gate (`proof_grade <> 'none'`
  for `repro_confirmed`, `patching`, and all downstream states).
- Creates append-only `context_manifests`, `diagnostics`, and `agent_steps` tables
  protected by PL/pgSQL `SQLSTATE 55000` immutability triggers.
- Creates `patch_attempts` storing candidate patch digests, changed paths, line counts,
  `S-22` `ModelToolProvenance`, and sandbox reproduction bindings.
- `ENABLE` + `FORCE ROW LEVEL SECURITY` across all 6 tables (58 total forced-RLS tables).
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

revision: str = "0013_repair_sessions_diagnostics_steps"
down_revision: str | Sequence[str] | None = "0012_models_budgets_usage"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

_U17_TABLES: tuple[str, ...] = (
    "workspace_agent_profiles",
    "repair_sessions",
    "context_manifests",
    "diagnostics",
    "agent_steps",
    "patch_attempts",
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

    # 1. Bounded per-workspace agent profiles (A-20, UI-S11)
    op.create_table(
        "workspace_agent_profiles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("role_key", sa.String(length=32), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=False),
        sa.Column(
            "model_id",
            sa.String(length=120),
            nullable=False,
            server_default=sa.text("'muse-spark-1.3'"),
        ),
        sa.Column("escalation_model_id", sa.String(length=120), nullable=True),
        sa.Column(
            "reasoning_effort",
            sa.String(length=16),
            nullable=False,
            server_default=sa.text("'medium'"),
        ),
        sa.Column(
            "allowed_tools_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "max_steps",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("8"),
        ),
        sa.Column(
            "max_tool_calls_per_step",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("4"),
        ),
        sa.Column(
            "max_schema_repair_retries",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("2"),
        ),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
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
        sa.PrimaryKeyConstraint("id", name="pk_workspace_agent_profiles"),
        sa.UniqueConstraint(
            "workspace_id", "id", name="uq_workspace_agent_profiles_workspace_id_id"
        ),
        sa.UniqueConstraint(
            "workspace_id", "role_key", name="uq_workspace_agent_profiles_ws_role_key"
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_workspace_agent_profiles_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by_user_id"],
            ["users.id"],
            name="fk_workspace_agent_profiles_updated_by_user_id_users",
            ondelete="SET NULL",
        ),
        sa.CheckConstraint(
            "role_key IN ('triage_diagnosis', 'bounded_patch')",
            name="ck_workspace_agent_profiles_agent_profile_role_key_valid",
        ),
        sa.CheckConstraint(
            "model_id IN ('muse-spark-1.3', 'muse-wonder-1.0')",
            name="ck_workspace_agent_profiles_agent_profile_model_id_valid",
        ),
        sa.CheckConstraint(
            "escalation_model_id IS NULL OR escalation_model_id = 'muse-wonder-1.0'",
            name="ck_workspace_agent_profiles_agent_profile_escalation_model_id_valid",
        ),
        sa.CheckConstraint(
            "reasoning_effort IN ('low', 'medium', 'high')",
            name="ck_workspace_agent_profiles_agent_profile_reasoning_effort_valid",
        ),
        sa.CheckConstraint(
            "max_steps >= 1 AND max_steps <= 16",
            name="ck_workspace_agent_profiles_agent_profile_max_steps_bounds",
        ),
        sa.CheckConstraint(
            "max_tool_calls_per_step >= 1 AND max_tool_calls_per_step <= 8",
            name="ck_workspace_agent_profiles_agent_profile_max_tool_calls_bounds",
        ),
        sa.CheckConstraint(
            "max_schema_repair_retries >= 0 AND max_schema_repair_retries <= 2",
            name="ck_workspace_agent_profiles_agent_profile_schema_retries_bounds",
        ),
        sa.CheckConstraint("version >= 1", name="ck_workspace_agent_profiles_version_pos"),
    )

    # 2. Repair session aggregate (S-11, W-04, W-05, ADR-031, ADR-038)
    op.create_table(
        "repair_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("ci_run_id", sa.String(length=36), nullable=False),
        sa.Column("parent_id", sa.String(length=36), nullable=True),
        sa.Column("supersedes_id", sa.String(length=36), nullable=True),
        sa.Column("semantic_trigger_key", sa.String(length=256), nullable=False),
        sa.Column("base_sha", sa.String(length=64), nullable=False),
        sa.Column("target_ref", sa.String(length=120), nullable=False),
        sa.Column("policy_revision", sa.Integer(), nullable=False),
        sa.Column(
            "state",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'received'"),
        ),
        sa.Column(
            "proof_grade",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'none'"),
        ),
        sa.Column(
            "remote_status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'not_published'"),
        ),
        sa.Column(
            "suspension_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("budget_account_id", sa.String(length=36), nullable=False),
        sa.Column("active_reproduction_id", sa.String(length=36), nullable=True),
        sa.Column("latest_diagnosis_id", sa.String(length=36), nullable=True),
        sa.Column(
            "patch_attempts_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("reason_code", sa.String(length=120), nullable=True),
        sa.Column("status_detail", sa.String(length=1000), nullable=True),
        sa.Column("correlation_id", sa.String(length=120), nullable=False),
        sa.Column("causation_event_id", sa.String(length=36), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_repair_sessions"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_repair_sessions_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "repository_id",
            "semantic_trigger_key",
            name="uq_repair_sessions_ws_repo_trigger_key",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_repair_sessions_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_repair_sessions_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "ci_run_id"],
            ["ci_runs.workspace_id", "ci_runs.id"],
            name="fk_repair_sessions_tenant_run_ci_runs",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "budget_account_id"],
            ["budget_accounts.workspace_id", "budget_accounts.id"],
            name="fk_repair_sessions_tenant_budget_budget_accounts",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "parent_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_repair_sessions_tenant_parent_repair_sessions",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "supersedes_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_repair_sessions_tenant_supersedes_repair_sessions",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "active_reproduction_id"],
            ["reproduction_runs.workspace_id", "reproduction_runs.id"],
            name="fk_repair_sessions_tenant_repro_reproduction_runs",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "state IN ("
            "'received', 'authorized', 'collecting', 'triaging', 'diagnosed_only', "
            "'unsupported', 'reproducing', 'repro_confirmed', 'repro_unconfirmed', "
            "'blocked', 'patching', 'verifying', 'rejected', 'policy_gate', "
            "'awaiting_approval', 'expired', 'publishing', 'publish_reconcile', "
            "'needs_human', 'remote_validating', 'remote_verified', 'remote_failed', "
            "'remote_unknown', 'cancel_requested', 'cancelled'"
            ")",
            name="ck_repair_sessions_repair_session_state_valid",
        ),
        sa.CheckConstraint(
            "proof_grade IN ("
            "'none', 'baseline_confirmed', 'locally_verified', 'remotely_verified'"
            ")",
            name="ck_repair_sessions_repair_session_proof_grade_valid",
        ),
        sa.CheckConstraint(
            "remote_status IN ('not_published', 'pending', 'passed', 'failed', 'unknown')",
            name="ck_repair_sessions_repair_session_remote_status_valid",
        ),
        sa.CheckConstraint(
            "state NOT IN ("
            "'repro_confirmed', 'patching', 'verifying', 'policy_gate', "
            "'awaiting_approval', 'publishing', 'publish_reconcile', "
            "'remote_validating', 'remote_verified', 'remote_failed', 'remote_unknown'"
            ") OR proof_grade <> 'none'",
            name="ck_repair_sessions_repair_session_adr031_proof_grade_gate",
        ),
        sa.CheckConstraint(
            "policy_revision >= 1",
            name="ck_repair_sessions_repair_session_policy_revision_pos",
        ),
        sa.CheckConstraint(
            "patch_attempts_count >= 0 AND patch_attempts_count <= 5",
            name="ck_repair_sessions_repair_session_patch_attempts_bounds",
        ),
        sa.CheckConstraint("version >= 1", name="ck_repair_sessions_version_pos"),
    )
    op.create_index(
        "ix_repair_sessions_ws_repo_created",
        "repair_sessions",
        ["workspace_id", "repository_id", "created_at", "id"],
    )
    op.create_index(
        "ix_repair_sessions_ws_state_updated",
        "repair_sessions",
        ["workspace_id", "state", "updated_at"],
    )

    # 3. Append-only redacted context manifests (SEC-005, SEC-032)
    op.create_table(
        "context_manifests",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("repair_id", sa.String(length=36), nullable=False),
        sa.Column("base_sha", sa.String(length=64), nullable=False),
        sa.Column("policy_revision", sa.Integer(), nullable=False),
        sa.Column("redaction_version", sa.String(length=120), nullable=False),
        sa.Column("cache_key", sa.String(length=64), nullable=False),
        sa.Column("context_digest", sa.String(length=64), nullable=False),
        sa.Column(
            "entries_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "truncated",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
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
        sa.PrimaryKeyConstraint("id", name="pk_context_manifests"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_context_manifests_workspace_id_id"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_context_manifests_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_context_manifests_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repair_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_context_manifests_tenant_repair_repair_sessions",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "policy_revision >= 1",
            name="ck_context_manifests_context_manifest_policy_rev_pos",
        ),
        sa.CheckConstraint(
            "version = 1",
            name="ck_context_manifests_context_manifest_immutable_version",
        ),
    )
    op.create_index(
        "ix_context_manifests_ws_cache_key",
        "context_manifests",
        ["workspace_id", "repository_id", "cache_key"],
    )
    op.create_index(
        "ix_context_manifests_ws_repair",
        "context_manifests",
        ["workspace_id", "repair_id", "created_at"],
    )

    # 4. Append-only evidence-backed diagnostics (S-11, TRI-02, AGT-02, SEC-012, SEC-024)
    op.create_table(
        "diagnostics",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("repair_id", sa.String(length=36), nullable=False),
        sa.Column("failure_class", sa.String(length=32), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("summary", sa.String(length=4000), nullable=False),
        sa.Column(
            "evidence_refs_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "evidence_citations_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "hypotheses_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "uncertainties_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("proposed_profile", sa.String(length=120), nullable=True),
        sa.Column(
            "proposed_command_ids_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("fingerprint_hash", sa.String(length=64), nullable=True),
        sa.Column("model_id", sa.String(length=120), nullable=True),
        sa.Column("provider_request_id", sa.String(length=256), nullable=True),
        sa.Column(
            "schema_repair_retries_used",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("deterministic_rule_id", sa.String(length=120), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_diagnostics"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_diagnostics_workspace_id_id"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_diagnostics_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_diagnostics_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repair_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_diagnostics_tenant_repair_repair_sessions",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "failure_class IN ("
            "'code_regression', 'test_defect', 'config', 'dependency', "
            "'flaky', 'infra', 'network', 'auth', 'unsupported', 'unknown'"
            ")",
            name="ck_diagnostics_diagnostic_failure_class_valid",
        ),
        sa.CheckConstraint(
            "decision IN ('continue', 'abstain', 'human')",
            name="ck_diagnostics_diagnostic_decision_valid",
        ),
        sa.CheckConstraint(
            "model_id IS NULL OR model_id IN ('muse-spark-1.3', 'muse-wonder-1.0')",
            name="ck_diagnostics_diagnostic_model_id_valid",
        ),
        sa.CheckConstraint(
            "schema_repair_retries_used >= 0 AND schema_repair_retries_used <= 2",
            name="ck_diagnostics_diagnostic_schema_retries_bounds",
        ),
        sa.CheckConstraint(
            "version = 1",
            name="ck_diagnostics_diagnostic_immutable_version",
        ),
    )
    op.create_index(
        "ix_diagnostics_ws_repair_created",
        "diagnostics",
        ["workspace_id", "repair_id", "created_at", "id"],
    )

    # 5. Append-only bounded agent steps & S-20 tool audit records (S-20, SEC-028)
    op.create_table(
        "agent_steps",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("repair_id", sa.String(length=36), nullable=False),
        sa.Column("agent_role", sa.String(length=32), nullable=False),
        sa.Column(
            "attempt_number",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("step_number", sa.Integer(), nullable=False),
        sa.Column("step_kind", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("tool_call_id", sa.String(length=36), nullable=True),
        sa.Column("tool_name", sa.String(length=120), nullable=True),
        sa.Column("args_redacted_digest", sa.String(length=64), nullable=True),
        sa.Column("result_redacted_digest", sa.String(length=64), nullable=True),
        sa.Column("context_digest", sa.String(length=64), nullable=False),
        sa.Column("deny_reason_code", sa.String(length=120), nullable=True),
        sa.Column("deny_explanation", sa.String(length=4000), nullable=True),
        sa.Column("model_id", sa.String(length=120), nullable=True),
        sa.Column("provider_request_id", sa.String(length=256), nullable=True),
        sa.Column("usage_record_id", sa.String(length=36), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_agent_steps"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_agent_steps_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "repair_id",
            "step_number",
            name="uq_agent_steps_ws_repair_step_number",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_agent_steps_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_agent_steps_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repair_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_agent_steps_tenant_repair_repair_sessions",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "usage_record_id"],
            ["usage_ledger.workspace_id", "usage_ledger.id"],
            name="fk_agent_steps_tenant_usage_usage_ledger",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "agent_role IN ('diagnosis', 'patch')",
            name="ck_agent_steps_agent_step_role_valid",
        ),
        sa.CheckConstraint(
            "attempt_number >= 0 AND attempt_number <= 10",
            name="ck_agent_steps_agent_step_attempt_bounds",
        ),
        sa.CheckConstraint(
            "step_number >= 1 AND step_number <= 500",
            name="ck_agent_steps_agent_step_number_bounds",
        ),
        sa.CheckConstraint(
            "step_kind IN ("
            "'model_call', 'tool_call', 'schema_repair', 'abstention', 'policy_denial'"
            ")",
            name="ck_agent_steps_agent_step_kind_valid",
        ),
        sa.CheckConstraint(
            "status IN ('ok', 'denied', 'failed', 'pending')",
            name="ck_agent_steps_agent_step_status_valid",
        ),
        sa.CheckConstraint(
            "version = 1",
            name="ck_agent_steps_agent_step_immutable_version",
        ),
    )
    op.create_index(
        "ix_agent_steps_ws_created",
        "agent_steps",
        ["workspace_id", "created_at", "id"],
    )

    # 6. Candidate patch attempts (S-12, AGT-02)
    op.create_table(
        "patch_attempts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("repair_id", sa.String(length=36), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("base_sha", sa.String(length=64), nullable=False),
        sa.Column("patch_digest", sa.String(length=64), nullable=False),
        sa.Column("diff_artifact_id", sa.String(length=36), nullable=False),
        sa.Column(
            "changed_paths_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "diff_lines_added",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "diff_lines_removed",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("claimed_root_cause", sa.String(length=4000), nullable=False),
        sa.Column("target_test_selection_id", sa.String(length=120), nullable=True),
        sa.Column("integrity_outcome", sa.String(length=32), nullable=False),
        sa.Column("sandbox_reproduction_id", sa.String(length=36), nullable=True),
        sa.Column(
            "provenance_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
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
        sa.PrimaryKeyConstraint("id", name="pk_patch_attempts"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_patch_attempts_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "repair_id",
            "attempt_number",
            name="uq_patch_attempts_ws_repair_attempt",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_patch_attempts_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_patch_attempts_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repair_id"],
            ["repair_sessions.workspace_id", "repair_sessions.id"],
            name="fk_patch_attempts_tenant_repair_repair_sessions",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "diff_artifact_id"],
            ["artifacts.workspace_id", "artifacts.id"],
            name="fk_patch_attempts_tenant_artifact_artifacts",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "sandbox_reproduction_id"],
            ["reproduction_runs.workspace_id", "reproduction_runs.id"],
            name="fk_patch_attempts_tenant_repro_reproduction_runs",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "attempt_number >= 1 AND attempt_number <= 5",
            name="ck_patch_attempts_patch_attempt_number_bounds",
        ),
        sa.CheckConstraint(
            "diff_lines_added >= 0 AND diff_lines_removed >= 0",
            name="ck_patch_attempts_patch_attempt_diff_lines_nonneg",
        ),
        sa.CheckConstraint(
            "integrity_outcome IN ('accepted', 'rejected_policy', 'rejected_integrity')",
            name="ck_patch_attempts_patch_attempt_integrity_outcome_valid",
        ),
        sa.CheckConstraint("version >= 1", name="ck_patch_attempts_version_pos"),
    )
    op.create_index(
        "ix_patch_attempts_ws_repair_created",
        "patch_attempts",
        ["workspace_id", "repair_id", "created_at", "id"],
    )

    # 7. Append-only immutability triggers (SQLSTATE 55000) for context_manifests,
    #    diagnostics, and agent_steps.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.red2pr_forbid_u17_append_only_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET red2pr.scope_mode = 'instance_admin'
        AS $$
        BEGIN
            RAISE EXCEPTION
                'append_only_table_violation: % on % is forbidden (S-11 / S-20 / U17)',
                TG_OP,
                TG_TABLE_NAME
                USING ERRCODE = '55000';
        END;
        $$;
        """
    )
    for immutable_tbl in ("context_manifests", "diagnostics", "agent_steps"):
        op.execute(
            f"""
            CREATE TRIGGER trg_{immutable_tbl}_immutable
            BEFORE UPDATE OR DELETE ON public.{immutable_tbl}
            FOR EACH ROW EXECUTE FUNCTION public.red2pr_forbid_u17_append_only_mutation();
            """
        )

    # 8. Enable + Force Row-Level Security on all 6 U17 workspace-scoped tables (SEC-032)
    for tbl in _U17_TABLES:
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

    # 9. Least-privilege table grants for runtime app role
    joined_tables = ", ".join(f"public.{t}" for t in _U17_TABLES)
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {joined_tables} TO "{app_role}";')

    # 10. Record expand-phase metadata in schema_migrations
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
            "parent_revision": "0012_models_budgets_usage",
            "checksum": _migration_checksum_sha256(),
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    for immutable_tbl in ("agent_steps", "diagnostics", "context_manifests"):
        op.execute(
            f"DROP TRIGGER IF EXISTS trg_{immutable_tbl}_immutable ON public.{immutable_tbl};"
        )
    op.execute("DROP FUNCTION IF EXISTS public.red2pr_forbid_u17_append_only_mutation();")
    for tbl in reversed(_U17_TABLES):
        op.drop_table(tbl)
