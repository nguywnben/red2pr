"""Normalized CI runs, matrix jobs, staged encrypted artifacts, failure fingerprints & RLS.

Revision ID: 0009_ci_runs_jobs_artifacts
Revises: 0008_repository_policies
Create Date: 2026-10-28T11:45:00Z

Implements Unit U13 (`TRI-01`, `TRI-03`, `A-08`, `A-10`, `S-10`, `S-14`, `W-03`, `W-04`, `W-09`,
`NFR-14`, `SEC-007`, `SEC-016`, `SEC-024`, `SEC-025`, `SEC-032`, `SEC-036`, `SEC-040`):
- Creates `artifact_blobs` tracking tenant-scoped encrypted blob lifecycle
  (`staged -> verified -> finalized | quarantined | purged`) with `UNIQUE (workspace_id, digest)`
  so identical digests never deduplicate across tenants (`SEC-032`).
- Creates `failure_fingerprints` storing historical failure signatures & bounded flaky-test
  observation rings per `(workspace_id, repository_id, fingerprint_hash)` (`TRI-03`).
- Creates `ci_runs`, `artifacts`, and `ci_jobs` with composite `(workspace_id, ...)` foreign
  keys enforcing strict tenant boundary integrity.
- `ENABLE` + `FORCE ROW LEVEL SECURITY` on all 5 new tables (`SEC-032`, 41 total RLS tables).
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

revision: str = "0009_ci_runs_jobs_artifacts"
down_revision: str | Sequence[str] | None = "0008_repository_policies"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

_U13_TABLES: tuple[str, ...] = (
    "artifact_blobs",
    "failure_fingerprints",
    "ci_runs",
    "artifacts",
    "ci_jobs",
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

    # 1. Tenant-scoped physical encrypted blob lifecycle table (SEC-025, SEC-032)
    op.create_table(
        "artifact_blobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("storage_backend", sa.String(length=32), nullable=False),
        sa.Column("storage_ref", sa.String(length=1024), nullable=False),
        sa.Column("staged_ref", sa.String(length=1024), nullable=True),
        sa.Column(
            "blob_state",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'staged'"),
        ),
        sa.Column("kek_version", sa.Integer(), nullable=False),
        sa.Column("aad_digest", sa.String(length=64), nullable=False),
        sa.Column("quarantine_reason", sa.String(length=256), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finalized_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_artifact_blobs"),
        sa.UniqueConstraint(
            "workspace_id",
            "id",
            name="uq_artifact_blobs_workspace_id_id",
        ),
        sa.UniqueConstraint(
            "workspace_id",
            "digest",
            name="uq_artifact_blobs_workspace_digest",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_artifact_blobs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "storage_backend IN ('local_encrypted', 's3_encrypted')",
            name="ck_artifact_blobs_artifact_blob_backend_valid",
        ),
        sa.CheckConstraint(
            "blob_state IN ('staged', 'verified', 'finalized', 'quarantined', 'purged')",
            name="ck_artifact_blobs_artifact_blob_state_valid",
        ),
        sa.CheckConstraint(
            "size_bytes >= 0",
            name="ck_artifact_blobs_artifact_blob_size_nonneg",
        ),
        sa.CheckConstraint(
            "kek_version >= 1",
            name="ck_artifact_blobs_artifact_blob_kek_version_pos",
        ),
        sa.CheckConstraint("version >= 1", name="ck_artifact_blobs_version_pos"),
    )
    op.create_index(
        "ix_artifact_blobs_ws_state_created",
        "artifact_blobs",
        ["workspace_id", "blob_state", "created_at", "id"],
    )

    # 2. Historical failure fingerprints & bounded flaky analyzer table (TRI-03)
    op.create_table(
        "failure_fingerprints",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("fingerprint_hash", sa.String(length=64), nullable=False),
        sa.Column("signature_label", sa.String(length=1000), nullable=False),
        sa.Column("test_identifier", sa.String(length=1024), nullable=True),
        sa.Column("error_kind", sa.String(length=120), nullable=True),
        sa.Column(
            "classification",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'insufficient_history'"),
        ),
        sa.Column("confidence_reason", sa.String(length=1000), nullable=False),
        sa.Column(
            "failure_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "pass_on_same_sha_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "distinct_sha_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "recent_observations_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name="pk_failure_fingerprints"),
        sa.UniqueConstraint(
            "workspace_id",
            "id",
            name="uq_failure_fingerprints_workspace_id_id",
        ),
        sa.UniqueConstraint(
            "workspace_id",
            "repository_id",
            "fingerprint_hash",
            name="uq_failure_fingerprints_ws_repo_hash",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_failure_fingerprints_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_failure_fingerprints_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "classification IN ("
            "'flaky', 'persistent_failure', 'single_pass_unproven', "
            "'insufficient_history', 'unknown'"
            ")",
            name="ck_failure_fingerprints_failure_fingerprint_classification_valid",
        ),
        sa.CheckConstraint(
            "failure_count >= 0",
            name="ck_failure_fingerprints_failure_fingerprint_failures_nonneg",
        ),
        sa.CheckConstraint(
            "pass_on_same_sha_count >= 0",
            name="ck_failure_fingerprints_failure_fingerprint_same_sha_passes_nonneg",
        ),
        sa.CheckConstraint(
            "distinct_sha_count >= 0",
            name="ck_failure_fingerprints_failure_fingerprint_distinct_shas_nonneg",
        ),
        sa.CheckConstraint("version >= 1", name="ck_failure_fingerprints_version_pos"),
    )
    op.create_index(
        "ix_failure_fingerprints_ws_repo_last_seen",
        "failure_fingerprints",
        ["workspace_id", "repository_id", "last_seen_at", "id"],
    )

    # 3. Normalized attempt-pinned CI runs (S-10, TRI-01, SEC-016)
    op.create_table(
        "ci_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("connection_id", sa.String(length=36), nullable=False),
        sa.Column("trigger_id", sa.String(length=36), nullable=True),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("external_id", sa.String(length=128), nullable=False),
        sa.Column("attempt_key", sa.String(length=128), nullable=False),
        sa.Column(
            "attempt_number",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column("head_sha", sa.String(length=64), nullable=False),
        sa.Column("observed_head_sha", sa.String(length=64), nullable=True),
        sa.Column(
            "head_sha_verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("ref", sa.String(length=120), nullable=False),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'completed'"),
        ),
        sa.Column("conclusion", sa.String(length=32), nullable=True),
        sa.Column(
            "jobs_complete",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("raw_vendor_status", sa.String(length=120), nullable=True),
        sa.Column(
            "is_rerun",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "untrusted_fork",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "ingestion_state",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'ingested'"),
        ),
        sa.Column("incomplete_reason", sa.String(length=1000), nullable=True),
        sa.Column(
            "failed_job_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "total_job_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "artifact_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "flaky_classification",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'unknown'"),
        ),
        sa.Column(
            "child_pipeline_ids_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_ci_runs"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_ci_runs_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "repository_id",
            "external_id",
            "attempt_key",
            name="uq_ci_runs_ws_repo_ext_attempt",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_ci_runs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_ci_runs_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["provider_connections.workspace_id", "provider_connections.id"],
            name="fk_ci_runs_tenant_conn_provider_connections",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "trigger_id"],
            ["ci_run_triggers.workspace_id", "ci_run_triggers.id"],
            name="fk_ci_runs_tenant_trigger_ci_run_triggers",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "provider IN ('github', 'gitlab')",
            name="ck_ci_runs_ci_run_provider_valid",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'in_progress', 'completed', 'unknown')",
            name="ck_ci_runs_ci_run_status_valid",
        ),
        sa.CheckConstraint(
            "conclusion IS NULL OR conclusion IN ("
            "'failure', 'timed_out', 'action_required', 'cancelled', "
            "'success', 'skipped', 'neutral', 'unknown'"
            ")",
            name="ck_ci_runs_ci_run_conclusion_valid",
        ),
        sa.CheckConstraint(
            "ingestion_state IN ("
            "'pending', 'collecting', 'ingested', 'incomplete', 'stale_sha', 'failed'"
            ")",
            name="ck_ci_runs_ci_run_ingestion_state_valid",
        ),
        sa.CheckConstraint(
            "flaky_classification IN ("
            "'flaky', 'persistent_failure', 'single_pass_unproven', "
            "'insufficient_history', 'unknown'"
            ")",
            name="ck_ci_runs_ci_run_flaky_class_valid",
        ),
        sa.CheckConstraint(
            "attempt_number >= 1",
            name="ck_ci_runs_ci_run_attempt_number_pos",
        ),
        sa.CheckConstraint(
            "failed_job_count >= 0",
            name="ck_ci_runs_ci_run_failed_jobs_nonneg",
        ),
        sa.CheckConstraint(
            "total_job_count >= 0",
            name="ck_ci_runs_ci_run_total_jobs_nonneg",
        ),
        sa.CheckConstraint(
            "artifact_count >= 0",
            name="ck_ci_runs_ci_run_artifacts_nonneg",
        ),
        sa.CheckConstraint("version >= 1", name="ck_ci_runs_version_pos"),
    )
    op.create_index(
        "ix_ci_runs_ws_repo_created",
        "ci_runs",
        ["workspace_id", "repository_id", "created_at", "id"],
    )
    op.create_index(
        "ix_ci_runs_ws_sha",
        "ci_runs",
        ["workspace_id", "head_sha", "created_at"],
    )

    # 4. Workspace-scoped artifacts metadata table (S-14, A-10)
    op.create_table(
        "artifacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=True),
        sa.Column("job_id", sa.String(length=36), nullable=True),
        sa.Column("blob_id", sa.String(length=36), nullable=True),
        sa.Column("manifest_id", sa.String(length=36), nullable=True),
        sa.Column("external_artifact_id", sa.String(length=128), nullable=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("kind", sa.String(length=120), nullable=False),
        sa.Column("mime", sa.String(length=120), nullable=False),
        sa.Column(
            "size_bytes",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("storage_ref", sa.String(length=1024), nullable=False),
        sa.Column(
            "redaction_version",
            sa.String(length=64),
            nullable=False,
            server_default=sa.text("'v1'"),
        ),
        sa.Column("retention_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "access_class",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'workspace_internal'"),
        ),
        sa.Column(
            "lifecycle_state",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'finalized'"),
        ),
        sa.Column("extracted_file_count", sa.Integer(), nullable=True),
        sa.Column("purge_reason", sa.String(length=120), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_artifacts"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_artifacts_workspace_id_id"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_artifacts_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_artifacts_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "run_id"],
            ["ci_runs.workspace_id", "ci_runs.id"],
            name="fk_artifacts_tenant_run_ci_runs",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "blob_id"],
            ["artifact_blobs.workspace_id", "artifact_blobs.id"],
            name="fk_artifacts_tenant_blob_artifact_blobs",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "access_class IN ('public', 'workspace_internal', 'restricted')",
            name="ck_artifacts_artifact_access_class_valid",
        ),
        sa.CheckConstraint(
            "lifecycle_state IN ('staged', 'finalized', 'quarantined', 'expired', 'purged')",
            name="ck_artifacts_artifact_lifecycle_state_valid",
        ),
        sa.CheckConstraint("size_bytes >= 0", name="ck_artifacts_artifact_size_nonneg"),
        sa.CheckConstraint(
            "extracted_file_count IS NULL OR extracted_file_count >= 0",
            name="ck_artifacts_artifact_extracted_files_nonneg",
        ),
        sa.CheckConstraint("version >= 1", name="ck_artifacts_version_pos"),
    )
    op.create_index(
        "ix_artifacts_ws_run_created",
        "artifacts",
        ["workspace_id", "run_id", "created_at", "id"],
    )
    op.create_index(
        "ix_artifacts_ws_retention",
        "artifacts",
        ["workspace_id", "retention_until"],
    )

    # 5. Normalized CI jobs with matrix dimensions, retry lineage & log status (S-10, TRI-01)
    op.create_table(
        "ci_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("external_id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("stage", sa.String(length=120), nullable=True),
        sa.Column(
            "matrix_dimensions_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("retry_of_id", sa.String(length=128), nullable=True),
        sa.Column(
            "is_child_pipeline_job",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("child_pipeline_id", sa.String(length=128), nullable=True),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'completed'"),
        ),
        sa.Column("conclusion", sa.String(length=32), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("log_artifact_id", sa.String(length=36), nullable=True),
        sa.Column(
            "log_status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'unavailable'"),
        ),
        sa.Column(
            "log_size_bytes",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "log_truncated",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("failure_excerpt", sa.String(length=1000), nullable=True),
        sa.Column("failure_fingerprint_id", sa.String(length=36), nullable=True),
        sa.Column("failure_fingerprint_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "flaky_classification",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'unknown'"),
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
        sa.PrimaryKeyConstraint("id", name="pk_ci_jobs"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_ci_jobs_workspace_id_id"),
        sa.UniqueConstraint(
            "workspace_id",
            "run_id",
            "external_id",
            name="uq_ci_jobs_ws_run_ext_id",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_ci_jobs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_ci_jobs_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "run_id"],
            ["ci_runs.workspace_id", "ci_runs.id"],
            name="fk_ci_jobs_tenant_run_ci_runs",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "log_artifact_id"],
            ["artifacts.workspace_id", "artifacts.id"],
            name="fk_ci_jobs_tenant_log_artifact_artifacts",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "failure_fingerprint_id"],
            ["failure_fingerprints.workspace_id", "failure_fingerprints.id"],
            name="fk_ci_jobs_tenant_fp_failure_fingerprints",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'in_progress', 'completed', 'unknown')",
            name="ck_ci_jobs_ci_job_status_valid",
        ),
        sa.CheckConstraint(
            "conclusion IS NULL OR conclusion IN ("
            "'failure', 'timed_out', 'action_required', 'cancelled', "
            "'success', 'skipped', 'neutral', 'unknown'"
            ")",
            name="ck_ci_jobs_ci_job_conclusion_valid",
        ),
        sa.CheckConstraint(
            "log_status IN ('pending', 'available', 'truncated', 'expired', 'unavailable')",
            name="ck_ci_jobs_ci_job_log_status_valid",
        ),
        sa.CheckConstraint(
            "flaky_classification IN ("
            "'flaky', 'persistent_failure', 'single_pass_unproven', "
            "'insufficient_history', 'unknown'"
            ")",
            name="ck_ci_jobs_ci_job_flaky_class_valid",
        ),
        sa.CheckConstraint(
            "log_size_bytes >= 0",
            name="ck_ci_jobs_ci_job_log_size_nonneg",
        ),
        sa.CheckConstraint("version >= 1", name="ck_ci_jobs_version_pos"),
    )
    op.create_index(
        "ix_ci_jobs_ws_run_created",
        "ci_jobs",
        ["workspace_id", "run_id", "created_at", "id"],
    )

    # 6. Enable + Force Row-Level Security on all U13 tables (SEC-032)
    for tbl in _U13_TABLES:
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
    joined_tables = ", ".join(f"public.{t}" for t in _U13_TABLES)
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
            "parent_revision": "0008_repository_policies",
            "checksum": _migration_checksum_sha256(),
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    for tbl in reversed(_U13_TABLES):
        op.drop_table(tbl)
