"""Reviewed runner profile revisions, immutable A/B reproduction runs, ADR-031 triggers & RLS.

Revision ID: 0011_profiles_and_reproduction_runs
Revises: 0010_workers_and_sandbox_leases
Create Date: 2026-10-28T15:50:00Z

Implements Unit U15 (`SAN-02`, `SAN-03`, `W-04`, `ADR-018`, `ADR-031`, `SEC-006`, `SEC-024`,
`SEC-032`, `SEC-036`):
- Creates `profile_revisions` storing immutable SHA-256 pinned runner profile manifests
  (`python-pytest-linux`, `node-jest-linux`, `node-vitest-linux`, `custom-linux-declared`)
  protected by an append-only PL/pgSQL immutability trigger (`SQLSTATE 55000`).
- Creates `reproduction_runs` storing workspace-scoped Sandbox A (`baseline_a`) and Sandbox B
  (`patched_b`) reproduction records, fidelity grades (`F1_TARGETED`, `F2_APPROX`,
  `F3_VALIDATED`, `FX_UNSUPPORTED`), test execution counts, failure fingerprint parity, and
  non-waivable `ADR-031` DB constraints + PL/pgSQL trigger (blocking any mutation once sealed
  and blocking any `patched_b` run without a sealed `repro_confirmed` baseline or if Sandbox A's
  container/job is reused).
- `ENABLE` + `FORCE ROW LEVEL SECURITY` on both new tables (47 total RLS tables).
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

revision: str = "0011_profiles_and_reproduction_runs"
down_revision: str | Sequence[str] | None = "0010_workers_and_sandbox_leases"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

_U15_TABLES: tuple[str, ...] = (
    "profile_revisions",
    "reproduction_runs",
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

    # Alembic's default `alembic_version.version_num` is VARCHAR(32); widen to VARCHAR(128)
    # so descriptive canonical revision IDs (>= 33 chars) never truncate on version write.
    op.execute(
        "ALTER TABLE IF EXISTS public.alembic_version ALTER COLUMN version_num TYPE VARCHAR(128);"
    )

    # 1. Immutable reviewed runner profile registry (instance-scoped, workspace-readable)
    op.create_table(
        "profile_revisions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("profile_id", sa.String(length=120), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("manifest_digest", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("ecosystem", sa.String(length=32), nullable=False),
        sa.Column(
            "platform",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'linux/amd64'"),
        ),
        sa.Column("base_image", sa.String(length=512), nullable=False),
        sa.Column("image_digest", sa.String(length=64), nullable=False),
        sa.Column(
            "requires_isolated_vm_tier",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "requires_admin_opt_in",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "manifest_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
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
        sa.PrimaryKeyConstraint("id", name="pk_profile_revisions"),
        sa.UniqueConstraint(
            "profile_id",
            "revision",
            name="uq_profile_revisions_profile_id_revision",
        ),
        sa.UniqueConstraint(
            "manifest_digest",
            name="uq_profile_revisions_manifest_digest",
        ),
        sa.CheckConstraint(
            "revision >= 1",
            name="ck_profile_revisions_profile_revision_pos",
        ),
        sa.CheckConstraint(
            "ecosystem IN ('python', 'node', 'custom')",
            name="ck_profile_revisions_profile_ecosystem_valid",
        ),
        sa.CheckConstraint(
            "platform IN ('linux/amd64', 'linux/arm64')",
            name="ck_profile_revisions_profile_platform_valid",
        ),
        sa.CheckConstraint(
            "version = 1",
            name="ck_profile_revisions_profile_immutable_version",
        ),
    )
    op.create_index(
        "ix_profile_revisions_profile_rev",
        "profile_revisions",
        ["profile_id", "revision"],
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.red2pr_forbid_profile_revision_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET red2pr.scope_mode = 'instance_admin'
        AS $$
        BEGIN
            RAISE EXCEPTION
                'append_only_table_violation: % on profile_revisions is forbidden (SAN-03)',
                TG_OP
                USING ERRCODE = '55000';
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_profile_revisions_immutable
        BEFORE UPDATE OR DELETE ON public.profile_revisions
        FOR EACH ROW EXECUTE FUNCTION public.red2pr_forbid_profile_revision_mutation();
        """
    )

    # 2. Workspace-scoped immutable Sandbox A / Sandbox B reproduction runs (SAN-02, ADR-031)
    op.create_table(
        "reproduction_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("repair_id", sa.String(length=36), nullable=False),
        sa.Column("ci_run_id", sa.String(length=36), nullable=False),
        sa.Column("ci_job_id", sa.String(length=36), nullable=False),
        sa.Column("phase", sa.String(length=32), nullable=False),
        sa.Column("baseline_reproduction_id", sa.String(length=36), nullable=True),
        sa.Column("sandbox_job_id", sa.String(length=36), nullable=True),
        sa.Column("sandbox_lease_id", sa.String(length=36), nullable=True),
        sa.Column("profile_revision_id", sa.String(length=36), nullable=True),
        sa.Column("profile_id", sa.String(length=120), nullable=False),
        sa.Column(
            "profile_revision",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column("profile_digest", sa.String(length=64), nullable=True),
        sa.Column("image_digest", sa.String(length=64), nullable=True),
        sa.Column("base_sha", sa.String(length=64), nullable=False),
        sa.Column("source_archive_digest", sa.String(length=64), nullable=True),
        sa.Column("dependency_lock_digest", sa.String(length=64), nullable=True),
        sa.Column("cache_key", sa.String(length=256), nullable=True),
        sa.Column("patch_digest", sa.String(length=64), nullable=True),
        sa.Column(
            "command_ids_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("command_digest", sa.String(length=64), nullable=True),
        sa.Column("environment_digest", sa.String(length=64), nullable=True),
        sa.Column("expected_fingerprint_hash", sa.String(length=64), nullable=True),
        sa.Column("observed_fingerprint_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "fingerprint_matched",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "executed_tests_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "passed_tests_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "failed_tests_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "skipped_tests_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("termination", sa.String(length=32), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("fidelity_grade", sa.String(length=32), nullable=False),
        sa.Column(
            "fidelity_differences_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("handoff_outcome", sa.String(length=64), nullable=False),
        sa.Column(
            "allow_patching",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "allow_publication",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("failure_reason_code", sa.String(length=120), nullable=True),
        sa.Column("failure_detail", sa.String(length=1000), nullable=True),
        sa.Column("result_digest", sa.String(length=64), nullable=True),
        sa.Column(
            "artifact_refs_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "immutable_sealed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_reproduction_runs"),
        sa.UniqueConstraint(
            "workspace_id",
            "id",
            name="uq_reproduction_runs_workspace_id_id",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_reproduction_runs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_reproduction_runs_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "ci_run_id"],
            ["ci_runs.workspace_id", "ci_runs.id"],
            name="fk_reproduction_runs_tenant_ci_run_ci_runs",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "ci_job_id"],
            ["ci_jobs.workspace_id", "ci_jobs.id"],
            name="fk_reproduction_runs_tenant_ci_job_ci_jobs",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "baseline_reproduction_id"],
            ["reproduction_runs.workspace_id", "reproduction_runs.id"],
            name="fk_reproduction_runs_tenant_baseline_reproduction_runs",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "sandbox_job_id"],
            ["task_jobs.workspace_id", "task_jobs.id"],
            name="fk_reproduction_runs_tenant_sandbox_job_task_jobs",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "sandbox_lease_id"],
            ["sandbox_leases.workspace_id", "sandbox_leases.id"],
            name="fk_reproduction_runs_tenant_sandbox_lease_sandbox_leases",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["profile_revision_id"],
            ["profile_revisions.id"],
            name="fk_reproduction_runs_profile_revision_id_profile_revisions",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "phase IN ('baseline_a', 'patched_b')",
            name="ck_reproduction_runs_repro_phase_valid",
        ),
        sa.CheckConstraint(
            "status IN ("
            "'running', 'repro_confirmed', 'repro_unconfirmed', "
            "'patched_passed', 'patched_failed', 'unsupported', 'blocked', 'cancelled'"
            ")",
            name="ck_reproduction_runs_repro_status_valid",
        ),
        sa.CheckConstraint(
            "fidelity_grade IN ('F1_TARGETED', 'F2_APPROX', 'F3_VALIDATED', 'FX_UNSUPPORTED')",
            name="ck_reproduction_runs_repro_fidelity_valid",
        ),
        sa.CheckConstraint(
            "handoff_outcome IN ("
            "'pending', 'proceed_to_patch', 'diagnosis_and_human_handoff', "
            "'unsupported_abstain', 'verified_red_to_green', 'patch_still_failing'"
            ")",
            name="ck_reproduction_runs_repro_handoff_valid",
        ),
        sa.CheckConstraint(
            "termination IS NULL OR termination IN ("
            "'exited', 'timeout', 'oom', 'cancelled', 'infrastructure_error'"
            ")",
            name="ck_reproduction_runs_repro_termination_valid",
        ),
        sa.CheckConstraint(
            "profile_revision >= 1",
            name="ck_reproduction_runs_repro_profile_rev_pos",
        ),
        sa.CheckConstraint(
            "executed_tests_count >= 0 AND passed_tests_count >= 0 "
            "AND failed_tests_count >= 0 AND skipped_tests_count >= 0",
            name="ck_reproduction_runs_repro_test_counts_nonneg",
        ),
        sa.CheckConstraint(
            "(phase = 'baseline_a' AND patch_digest IS NULL AND baseline_reproduction_id IS NULL) "
            "OR (phase = 'patched_b' AND patch_digest IS NOT NULL "
            "AND baseline_reproduction_id IS NOT NULL)",
            name="ck_reproduction_runs_repro_phase_parity",
        ),
        sa.CheckConstraint(
            "(NOT allow_patching) OR ("
            "phase = 'baseline_a' AND status = 'repro_confirmed' "
            "AND fidelity_grade <> 'FX_UNSUPPORTED' "
            "AND executed_tests_count > 0 AND failed_tests_count > 0 "
            "AND fingerprint_matched IS TRUE"
            ")",
            name="ck_reproduction_runs_adr031_patching_gate",
        ),
        sa.CheckConstraint(
            "(NOT allow_publication) OR ("
            "phase = 'patched_b' AND status = 'patched_passed' "
            "AND fidelity_grade <> 'FX_UNSUPPORTED' "
            "AND executed_tests_count > 0 AND failed_tests_count = 0 "
            "AND termination = 'exited' AND exit_code = 0"
            ")",
            name="ck_reproduction_runs_adr031_publication_gate",
        ),
        sa.CheckConstraint(
            "(status = 'running' AND immutable_sealed IS FALSE) "
            "OR (status <> 'running' AND immutable_sealed IS TRUE AND finished_at IS NOT NULL)",
            name="ck_reproduction_runs_repro_sealed_when_terminal",
        ),
        sa.CheckConstraint("version >= 1", name="ck_reproduction_runs_version_pos"),
    )
    op.create_index(
        "ix_reproduction_runs_ws_repair_phase",
        "reproduction_runs",
        ["workspace_id", "repair_id", "phase", "created_at"],
    )
    op.create_index(
        "ix_reproduction_runs_ws_ci_job",
        "reproduction_runs",
        ["workspace_id", "ci_job_id", "status"],
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.red2pr_guard_reproduction_runs_immutability_and_adr031()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        SET red2pr.scope_mode = 'instance_admin'
        AS $$
        DECLARE
            baseline_rec RECORD;
        BEGIN
            IF TG_OP = 'UPDATE' THEN
                IF OLD.immutable_sealed IS TRUE THEN
                    RAISE EXCEPTION
                        'append_only_table_violation: finished reproduction_runs % is immutable',
                        OLD.id
                        USING ERRCODE = '55000';
                END IF;
            END IF;

            IF TG_OP = 'DELETE' THEN
                IF EXISTS (
                    SELECT 1
                    FROM public.repositories r
                    WHERE r.workspace_id = OLD.workspace_id
                      AND r.id = OLD.repository_id
                ) THEN
                    RAISE EXCEPTION
                        'append_only_table_violation: DELETE on reproduction_runs is forbidden'
                        USING ERRCODE = '55000';
                END IF;
                RETURN OLD;
            END IF;

            IF (TG_OP = 'INSERT' OR TG_OP = 'UPDATE') AND NEW.phase = 'patched_b' THEN
                SELECT
                    id,
                    phase,
                    status,
                    immutable_sealed,
                    allow_patching,
                    fidelity_grade,
                    profile_id,
                    profile_revision,
                    image_digest,
                    base_sha,
                    source_archive_digest,
                    sandbox_job_id
                INTO baseline_rec
                FROM public.reproduction_runs
                WHERE workspace_id = NEW.workspace_id
                  AND id = NEW.baseline_reproduction_id;

                IF NOT FOUND
                   OR baseline_rec.phase <> 'baseline_a'
                   OR baseline_rec.status <> 'repro_confirmed'
                   OR baseline_rec.immutable_sealed IS NOT TRUE
                   OR baseline_rec.allow_patching IS NOT TRUE
                   OR baseline_rec.fidelity_grade = 'FX_UNSUPPORTED'
                THEN
                    RAISE EXCEPTION
                        'adr031_unconfirmed_baseline_violation: '
                        'patched_b requires sealed repro_confirmed baseline_a (ADR-031)'
                        USING ERRCODE = '55000';
                END IF;

                IF baseline_rec.profile_id <> NEW.profile_id
                   OR baseline_rec.profile_revision <> NEW.profile_revision
                   OR baseline_rec.image_digest IS DISTINCT FROM NEW.image_digest
                   OR baseline_rec.base_sha <> NEW.base_sha
                   OR baseline_rec.source_archive_digest IS DISTINCT FROM NEW.source_archive_digest
                THEN
                    RAISE EXCEPTION
                        'ab_reproduction_environment_drift: '
                        'Sandbox B must match Sandbox A profile, image, sha, and archive'
                        USING ERRCODE = '55000';
                END IF;

                IF NEW.sandbox_job_id IS NOT NULL
                   AND baseline_rec.sandbox_job_id IS NOT NULL
                   AND baseline_rec.sandbox_job_id = NEW.sandbox_job_id
                THEN
                    RAISE EXCEPTION
                        'ab_reproduction_sandbox_reuse_forbidden: '
                        'Sandbox B must never reuse Sandbox A job or container'
                        USING ERRCODE = '55000';
                END IF;
            END IF;

            RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_reproduction_runs_immutable_and_adr031
        BEFORE INSERT OR UPDATE OR DELETE ON public.reproduction_runs
        FOR EACH ROW
        EXECUTE FUNCTION public.red2pr_guard_reproduction_runs_immutability_and_adr031();
        """
    )

    # 3. Enable + Force Row-Level Security on both U15 tables (SEC-032)
    for tbl in _U15_TABLES:
        op.execute(f"ALTER TABLE public.{tbl} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE public.{tbl} FORCE ROW LEVEL SECURITY;")

    op.execute(
        """
        CREATE POLICY rls_profile_revisions_select ON public.profile_revisions
        FOR SELECT
        USING (
            current_setting('red2pr.scope_mode', true)
            IN ('workspace', 'instance_only', 'instance_admin', 'audit_verifier')
        );
        """
    )
    op.execute(
        """
        CREATE POLICY rls_profile_revisions_write ON public.profile_revisions
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

    op.execute(
        """
        CREATE POLICY rls_reproduction_runs_select ON public.reproduction_runs
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
        """
        CREATE POLICY rls_reproduction_runs_write ON public.reproduction_runs
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

    # 4. Least-privilege table grants for runtime app role
    joined_tables = ", ".join(f"public.{t}" for t in _U15_TABLES)
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {joined_tables} TO "{app_role}";')

    # 5. Record expand-phase metadata in schema_migrations
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
            "parent_revision": "0010_workers_and_sandbox_leases",
            "checksum": _migration_checksum_sha256(),
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_reproduction_runs_immutable_and_adr031 "
        "ON public.reproduction_runs;"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS public.red2pr_guard_reproduction_runs_immutability_and_adr031();"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_profile_revisions_immutable ON public.profile_revisions;"
    )
    op.execute("DROP FUNCTION IF EXISTS public.red2pr_forbid_profile_revision_mutation();")
    for tbl in reversed(_U15_TABLES):
        op.drop_table(tbl)
