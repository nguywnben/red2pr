"""Isolated worker registry, mTLS enrollments, Ed25519 signing keys, sandbox leases & RLS.

Revision ID: 0010_workers_and_sandbox_leases
Revises: 0009_ci_runs_jobs_artifacts
Create Date: 2026-10-28T13:35:00Z

Implements Unit U14 (`SAN-01`, `A-13`, `S-15`, `S-21`, `UI-S13`, `W-04`, `W-08`, `NFR-02`,
`NFR-14`, `ADR-016`, `ADR-034`, `ADR-035`, `SEC-006`, `SEC-013`, `SEC-014`, `SEC-021`,
`SEC-029`, `SEC-030`, `SEC-032`):
- Creates `workers` storing enrolled isolated Z3 worker supervisor nodes, X.509 mTLS leaf
  certificate metadata & revocation timestamps, isolation mode (`oci_rootless`,
  `vm_isolated`, `oci_trusted_local`), and quarantine/drain states.
- Creates `worker_enrollments` storing single-use SHA-256 hashed mTLS enrollment tokens
  (raw enrollment tokens are never stored at rest).
- Creates `signing_keys` storing Ed25519 verification public keys retained across rotations
  (`SEC-030`).
- Creates `sandbox_leases` storing workspace-scoped fenced `SandboxJobV1` / `ResultV1`
  execution leases with composite `(workspace_id, ...)` foreign keys.
- `ENABLE` + `FORCE ROW LEVEL SECURITY` on all 4 new tables (45 total RLS tables).
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

revision: str = "0010_workers_and_sandbox_leases"
down_revision: str | Sequence[str] | None = "0009_ci_runs_jobs_artifacts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

_U14_TABLES: tuple[str, ...] = (
    "workers",
    "worker_enrollments",
    "signing_keys",
    "sandbox_leases",
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

    # 1. Global isolated worker supervisor registry (instance-scoped)
    op.create_table(
        "workers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("host_id", sa.String(length=120), nullable=False),
        sa.Column("trust_domain", sa.String(length=120), nullable=False),
        sa.Column(
            "isolation_mode",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'oci_rootless'"),
        ),
        sa.Column("runtime_name", sa.String(length=120), nullable=False),
        sa.Column(
            "profile_ids_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "capabilities_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "cpu_limit",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("4"),
        ),
        sa.Column(
            "memory_limit_bytes",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("8589934592"),
        ),
        sa.Column(
            "disk_limit_bytes",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("42949672960"),
        ),
        sa.Column(
            "pids_limit",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("512"),
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'online'"),
        ),
        sa.Column(
            "heartbeat_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("mtls_cert_serial", sa.String(length=64), nullable=False),
        sa.Column("mtls_cert_fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("mtls_cert_pem", sa.Text(), nullable=False),
        sa.Column("mtls_cert_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("mtls_cert_revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("active_signer_key_id", sa.String(length=120), nullable=True),
        sa.Column("last_workspace_id", sa.String(length=36), nullable=True),
        sa.Column(
            "host_escape_risk_acknowledged",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("quarantine_reason", sa.String(length=1000), nullable=True),
        sa.Column("drain_reason", sa.String(length=1000), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_workers"),
        sa.UniqueConstraint(
            "mtls_cert_fingerprint_sha256",
            name="uq_workers_mtls_cert_fingerprint",
        ),
        sa.CheckConstraint(
            "status IN ('online', 'offline', 'draining', 'quarantined')",
            name="ck_workers_worker_status_valid",
        ),
        sa.CheckConstraint(
            "isolation_mode IN ('oci_rootless', 'vm_isolated', 'oci_trusted_local')",
            name="ck_workers_worker_isolation_mode_valid",
        ),
        sa.CheckConstraint(
            "cpu_limit >= 1 AND cpu_limit <= 256",
            name="ck_workers_worker_cpu_bounds",
        ),
        sa.CheckConstraint("memory_limit_bytes >= 1", name="ck_workers_worker_memory_pos"),
        sa.CheckConstraint("disk_limit_bytes >= 1", name="ck_workers_worker_disk_pos"),
        sa.CheckConstraint(
            "pids_limit >= 1 AND pids_limit <= 65536",
            name="ck_workers_worker_pids_bounds",
        ),
        sa.CheckConstraint("version >= 1", name="ck_workers_version_pos"),
    )
    op.create_index(
        "ix_workers_status_heartbeat",
        "workers",
        ["status", "heartbeat_at", "id"],
    )
    op.create_index(
        "ix_workers_trust_domain",
        "workers",
        ["trust_domain", "status"],
    )

    # 2. One-use SHA-256 hashed mTLS enrollment tokens (instance-scoped)
    op.create_table(
        "worker_enrollments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("trust_domain", sa.String(length=120), nullable=False),
        sa.Column(
            "profile_ids_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "isolation_mode",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'oci_rootless'"),
        ),
        sa.Column(
            "host_escape_risk_acknowledged",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=False),
        sa.Column("enrolled_worker_id", sa.String(length=36), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_worker_enrollments"),
        sa.UniqueConstraint("token_hash", name="uq_worker_enrollments_token_hash"),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_worker_enrollments_created_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["enrolled_worker_id"],
            ["workers.id"],
            name="fk_worker_enrollments_enrolled_worker_id_workers",
            ondelete="SET NULL",
        ),
        sa.CheckConstraint(
            "isolation_mode IN ('oci_rootless', 'vm_isolated', 'oci_trusted_local')",
            name="ck_worker_enrollments_worker_enrollment_isolation_mode_valid",
        ),
        sa.CheckConstraint("version >= 1", name="ck_worker_enrollments_version_pos"),
    )
    op.create_index(
        "ix_worker_enrollments_expires_at",
        "worker_enrollments",
        ["expires_at", "used_at"],
    )

    # 3. Ed25519 verification public keys retained across rotations (SEC-030)
    op.create_table(
        "signing_keys",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("key_id", sa.String(length=120), nullable=False),
        sa.Column(
            "algorithm",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'ed25519'"),
        ),
        sa.Column(
            "purpose",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'worker_result'"),
        ),
        sa.Column("public_key_b64", sa.String(length=256), nullable=False),
        sa.Column("worker_id", sa.String(length=36), nullable=True),
        sa.Column("trust_domain", sa.String(length=120), nullable=True),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.String(length=512), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_signing_keys"),
        sa.UniqueConstraint("key_id", name="uq_signing_keys_key_id"),
        sa.ForeignKeyConstraint(
            ["worker_id"],
            ["workers.id"],
            name="fk_signing_keys_worker_id_workers",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "algorithm = 'ed25519'",
            name="ck_signing_keys_signing_key_algorithm_ed25519",
        ),
        sa.CheckConstraint(
            "purpose IN ("
            "'worker_result', 'evidence_manifest', 'audit_checkpoint', 'release_manifest'"
            ")",
            name="ck_signing_keys_signing_key_purpose_valid",
        ),
        sa.CheckConstraint("version >= 1", name="ck_signing_keys_version_pos"),
    )
    op.create_index(
        "ix_signing_keys_worker_purpose",
        "signing_keys",
        ["worker_id", "purpose", "revoked_at"],
    )

    # 4. Workspace-scoped fenced sandbox leases (SEC-021, SEC-032)
    op.create_table(
        "sandbox_leases",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("repair_id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("worker_id", sa.String(length=36), nullable=False),
        sa.Column("lease_epoch", sa.Integer(), nullable=False),
        sa.Column("capability_nonce", sa.String(length=120), nullable=False),
        sa.Column("expected_worker_trust_domain", sa.String(length=120), nullable=False),
        sa.Column("profile_id", sa.String(length=120), nullable=False),
        sa.Column(
            "profile_revision",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column("image_digest", sa.String(length=64), nullable=False),
        sa.Column("base_sha", sa.String(length=64), nullable=False),
        sa.Column("source_archive_digest", sa.String(length=64), nullable=False),
        sa.Column("patch_digest", sa.String(length=64), nullable=True),
        sa.Column("network_policy_digest", sa.String(length=64), nullable=False),
        sa.Column("supervisor_policy_digest", sa.String(length=64), nullable=False),
        sa.Column(
            "sandbox_job_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "upload_slots_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "uploaded_artifacts_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "output_bytes_uploaded",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'leased'"),
        ),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_digest", sa.String(length=64), nullable=True),
        sa.Column(
            "result_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "cleanup_verified",
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
        sa.PrimaryKeyConstraint("id", name="pk_sandbox_leases"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_sandbox_leases_workspace_id_id"),
        sa.UniqueConstraint("job_id", "lease_epoch", name="uq_sandbox_leases_job_lease_epoch"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_sandbox_leases_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_sandbox_leases_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "job_id"],
            ["task_jobs.workspace_id", "task_jobs.id"],
            name="fk_sandbox_leases_tenant_job_task_jobs",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["worker_id"],
            ["workers.id"],
            name="fk_sandbox_leases_worker_id_workers",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "status IN ("
            "'leased', 'running', 'completed', 'cancel_requested', "
            "'cancelled', 'expired', 'quarantined'"
            ")",
            name="ck_sandbox_leases_sandbox_lease_status_valid",
        ),
        sa.CheckConstraint("lease_epoch >= 1", name="ck_sandbox_leases_sandbox_lease_epoch_pos"),
        sa.CheckConstraint(
            "profile_revision >= 1",
            name="ck_sandbox_leases_sandbox_lease_profile_rev_pos",
        ),
        sa.CheckConstraint(
            "output_bytes_uploaded >= 0",
            name="ck_sandbox_leases_sandbox_lease_output_nonneg",
        ),
        sa.CheckConstraint(
            "lease_expires_at > issued_at",
            name="ck_sandbox_leases_sandbox_lease_expiry_after_issue",
        ),
        sa.CheckConstraint("version >= 1", name="ck_sandbox_leases_version_pos"),
    )
    op.create_index(
        "ix_sandbox_leases_ws_status_exp",
        "sandbox_leases",
        ["workspace_id", "status", "lease_expires_at"],
    )
    op.create_index(
        "ix_sandbox_leases_worker_status",
        "sandbox_leases",
        ["worker_id", "status", "lease_expires_at"],
    )

    # 5. Enable + Force Row-Level Security on all 4 U14 tables (SEC-032)
    for tbl in _U14_TABLES:
        op.execute(f"ALTER TABLE public.{tbl} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE public.{tbl} FORCE ROW LEVEL SECURITY;")

    # Instance-scoped tables: workers, worker_enrollments
    for inst_tbl in ("workers", "worker_enrollments"):
        op.execute(
            f"""
            CREATE POLICY rls_{inst_tbl}_select ON public.{inst_tbl}
            FOR SELECT
            USING (
                current_setting('red2pr.scope_mode', true)
                IN ('instance_only', 'instance_admin', 'audit_verifier')
            );
            """
        )
        op.execute(
            f"""
            CREATE POLICY rls_{inst_tbl}_write ON public.{inst_tbl}
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

    # signing_keys: public verification keys readable by workspace/instance/audit,
    # writable only in instance scope
    op.execute(
        """
        CREATE POLICY rls_signing_keys_select ON public.signing_keys
        FOR SELECT
        USING (
            current_setting('red2pr.scope_mode', true)
            IN ('workspace', 'instance_only', 'instance_admin', 'audit_verifier')
        );
        """
    )
    op.execute(
        """
        CREATE POLICY rls_signing_keys_write ON public.signing_keys
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

    # sandbox_leases: strict tenant isolation matching workspace_id
    op.execute(
        """
        CREATE POLICY rls_sandbox_leases_select ON public.sandbox_leases
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
        CREATE POLICY rls_sandbox_leases_write ON public.sandbox_leases
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

    # 6. Least-privilege table grants for runtime app role
    joined_tables = ", ".join(f"public.{t}" for t in _U14_TABLES)
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {joined_tables} TO "{app_role}";')

    # 7. Record expand-phase metadata in schema_migrations
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
            "parent_revision": "0009_ci_runs_jobs_artifacts",
            "checksum": _migration_checksum_sha256(),
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    for tbl in reversed(_U14_TABLES):
        op.drop_table(tbl)
