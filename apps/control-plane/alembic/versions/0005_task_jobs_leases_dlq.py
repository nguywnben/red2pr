"""Durable task queue, lease fencing, DLQ, operation receipts & RLS.

Revision ID: 0005_task_jobs_leases_dlq
Revises: 0004_setup_consents_endpoints
Create Date: 2026-10-27T05:00:00Z

Implements Unit U08 (`JOB-01`, `JOB-02`, `A-14`, `A-24`, `S-15`, `UI-S14`, `W-08`,
`NFR-01`, `NFR-02`, `NFR-05`, `SEC-021`, `SEC-032`):
- `seq_task_job_dispatch`: monotonic PostgreSQL sequence backing deficit round-robin
  per-workspace dispatch watermarks (`last_dispatch_seq`).
- `task_jobs`: authoritative durable task queue with monotonic `lease_epoch` fencing,
  per-workspace active `dedup_key` uniqueness, preserved `logical_effect_key` and
  `budget_key`, and ready/lease-expiry partial/composite indexes.
- `task_attempts`: per-attempt worker execution history bound via composite tenant FK
  `(workspace_id, job_id) -> task_jobs(workspace_id, id)` and unique `(job_id, lease_epoch)`.
- `dead_letter_jobs`: terminal/exhausted/ambiguous failure ledger preserving original
  `logical_effect_key` and `budget_key` with partial uniqueness on open DLQ entries.
- `operation_receipts`: durable `S-05` `ActionReceipt` store for `A-24`
  `GET /api/v1/operations/{id}` enforcing originating scope and live principal rights.
- `ENABLE` + `FORCE ROW LEVEL SECURITY` on all U08 tables (`SEC-032`).
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

revision: str = "0005_task_jobs_leases_dlq"
down_revision: str | Sequence[str] | None = "0004_setup_consents_endpoints"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

_U08_TABLES: tuple[str, ...] = (
    "task_jobs",
    "task_attempts",
    "dead_letter_jobs",
    "operation_receipts",
)

_WORKSPACE_SCOPED_TABLES: tuple[str, ...] = (
    "task_jobs",
    "task_attempts",
    "dead_letter_jobs",
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

    # 1. Monotonic sequence for per-workspace deficit round-robin fairness watermarks
    op.execute(
        "CREATE SEQUENCE public.seq_task_job_dispatch AS BIGINT START WITH 1 INCREMENT BY 1;"
    )

    # 2. task_jobs (JOB-01 / S-15 authoritative durable task queue)
    op.create_table(
        "task_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=True),
        sa.Column("repair_id", sa.String(length=36), nullable=True),
        sa.Column("kind", sa.String(length=120), nullable=False),
        sa.Column(
            "is_repair_job",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("resource_id", sa.String(length=36), nullable=False),
        sa.Column(
            "state",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'queued'"),
        ),
        sa.Column(
            "priority",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("100"),
        ),
        sa.Column("dedup_key", sa.String(length=256), nullable=True),
        sa.Column("logical_effect_key", sa.String(length=256), nullable=False),
        sa.Column("budget_key", sa.String(length=256), nullable=True),
        sa.Column("correlation_id", sa.String(length=120), nullable=False),
        sa.Column(
            "payload_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "attempt",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "max_attempts",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("3"),
        ),
        sa.Column(
            "lease_epoch",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("last_dispatch_seq", sa.BigInteger(), nullable=True),
        sa.Column("leased_by_worker_id", sa.String(length=36), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error_code", sa.String(length=120), nullable=True),
        sa.Column("last_error_detail", sa.String(length=4096), nullable=True),
        sa.Column("cancel_reason", sa.String(length=1000), nullable=True),
        sa.Column("cancelled_by_user_id", sa.String(length=36), nullable=True),
        sa.Column(
            "recoverable",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "reconcile_required",
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
        sa.PrimaryKeyConstraint("id", name="pk_task_jobs"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_task_jobs_workspace_id_id"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_task_jobs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["cancelled_by_user_id"],
            ["users.id"],
            name="fk_task_jobs_cancelled_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "state IN ("
            "'queued', 'leased', 'running', 'succeeded', 'failed', "
            "'cancel_requested', 'cancelled', 'dead_letter'"
            ")",
            name="ck_task_jobs_task_job_state_valid",
        ),
        sa.CheckConstraint(
            "priority >= 0 AND priority <= 1000",
            name="ck_task_jobs_task_job_priority_bounds",
        ),
        sa.CheckConstraint("attempt >= 1", name="ck_task_jobs_task_job_attempt_pos"),
        sa.CheckConstraint("max_attempts >= 1", name="ck_task_jobs_task_job_max_attempts_pos"),
        sa.CheckConstraint("lease_epoch >= 0", name="ck_task_jobs_task_job_lease_epoch_nonneg"),
        sa.CheckConstraint(
            "deadline >= not_before",
            name="ck_task_jobs_task_job_deadline_after_not_before",
        ),
        sa.CheckConstraint("version >= 1", name="ck_task_jobs_version_pos"),
    )
    op.create_index(
        "ix_task_jobs_ready_queue",
        "task_jobs",
        ["state", "not_before", "priority", "created_at", "id"],
    )
    op.create_index(
        "ix_task_jobs_workspace_state",
        "task_jobs",
        ["workspace_id", "state", "created_at", "id"],
    )
    op.create_index(
        "ix_task_jobs_lease_sweeper",
        "task_jobs",
        ["state", "lease_expires_at"],
    )
    op.create_index(
        "ix_task_jobs_workspace_dispatch_seq",
        "task_jobs",
        ["workspace_id", "last_dispatch_seq"],
    )
    op.create_index(
        "uq_task_jobs_active_dedup",
        "task_jobs",
        ["workspace_id", "dedup_key"],
        unique=True,
        postgresql_where=sa.text(
            "dedup_key IS NOT NULL AND state IN ('queued', 'leased', 'running', 'cancel_requested')"
        ),
    )

    # 3. task_attempts (NFR-02 per-attempt lease history)
    op.create_table(
        "task_attempts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("lease_epoch", sa.Integer(), nullable=False),
        sa.Column("worker_id", sa.String(length=36), nullable=False),
        sa.Column(
            "state",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'leased'"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=120), nullable=True),
        sa.Column("error_detail", sa.String(length=4096), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_task_attempts"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_task_attempts_workspace_id_id"),
        sa.UniqueConstraint("job_id", "lease_epoch", name="uq_task_attempts_job_lease_epoch"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_task_attempts_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "job_id"],
            ["task_jobs.workspace_id", "task_jobs.id"],
            name="fk_task_attempts_workspace_job_task_jobs",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "state IN ('leased', 'running', 'succeeded', 'failed', 'cancelled', 'orphaned')",
            name="ck_task_attempts_task_attempt_state_valid",
        ),
        sa.CheckConstraint(
            "attempt_number >= 1",
            name="ck_task_attempts_task_attempt_number_pos",
        ),
        sa.CheckConstraint(
            "lease_epoch >= 1",
            name="ck_task_attempts_task_attempt_lease_epoch_pos",
        ),
    )
    op.create_index(
        "ix_task_attempts_job_epoch",
        "task_attempts",
        ["workspace_id", "job_id", "lease_epoch"],
    )

    # 4. dead_letter_jobs (JOB-02 / W-08 DLQ entries preserving effect & budget keys)
    op.create_table(
        "dead_letter_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=True),
        sa.Column("original_job_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=120), nullable=False),
        sa.Column("resource_id", sa.String(length=36), nullable=False),
        sa.Column("logical_effect_key", sa.String(length=256), nullable=False),
        sa.Column("budget_key", sa.String(length=256), nullable=True),
        sa.Column("error_code", sa.String(length=120), nullable=False),
        sa.Column("error_detail", sa.String(length=4096), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column(
            "recoverable",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "reconcile_required",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'open'"),
        ),
        sa.Column("requeued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requeued_by_user_id", sa.String(length=36), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_dead_letter_jobs"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_dead_letter_jobs_workspace_id_id"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_dead_letter_jobs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "original_job_id"],
            ["task_jobs.workspace_id", "task_jobs.id"],
            name="fk_dead_letter_jobs_workspace_job_task_jobs",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requeued_by_user_id"],
            ["users.id"],
            name="fk_dead_letter_jobs_requeued_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'requeued', 'reconciled', 'discarded')",
            name="ck_dead_letter_jobs_dlq_status_valid",
        ),
        sa.CheckConstraint("attempts >= 1", name="ck_dead_letter_jobs_dlq_attempts_pos"),
        sa.CheckConstraint("version >= 1", name="ck_dead_letter_jobs_version_pos"),
    )
    op.create_index(
        "ix_dead_letter_jobs_workspace_status",
        "dead_letter_jobs",
        ["workspace_id", "status", "created_at", "id"],
    )
    op.create_index(
        "uq_dead_letter_jobs_open_per_job",
        "dead_letter_jobs",
        ["workspace_id", "original_job_id"],
        unique=True,
        postgresql_where=sa.text("status = 'open'"),
    )

    # 5. operation_receipts (A-24 / S-05 durable asynchronous receipts)
    op.create_table(
        "operation_receipts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column(
            "scope",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'workspace'"),
        ),
        sa.Column("workspace_id", sa.String(length=36), nullable=True),
        sa.Column("repository_id", sa.String(length=36), nullable=True),
        sa.Column("principal_id", sa.String(length=128), nullable=False),
        sa.Column("required_role", sa.String(length=32), nullable=False),
        sa.Column("operation_kind", sa.String(length=120), nullable=False),
        sa.Column("resource_id", sa.String(length=36), nullable=False),
        sa.Column(
            "state",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'running'"),
        ),
        sa.Column("correlation_id", sa.String(length=120), nullable=False),
        sa.Column("status_url", sa.String(length=2048), nullable=False),
        sa.Column("result_id", sa.String(length=36), nullable=True),
        sa.Column(
            "problem_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("logical_effect_key", sa.String(length=256), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name="pk_operation_receipts"),
        sa.UniqueConstraint("workspace_id", "id", name="uq_operation_receipts_workspace_id_id"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_operation_receipts_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "scope IN ('workspace', 'instance')",
            name="ck_operation_receipts_operation_receipt_scope_valid",
        ),
        sa.CheckConstraint(
            "(scope = 'instance' AND workspace_id IS NULL AND repository_id IS NULL) OR "
            "(scope = 'workspace' AND workspace_id IS NOT NULL)",
            name="ck_operation_receipts_operation_receipt_scope_binding_valid",
        ),
        sa.CheckConstraint(
            "required_role IN ("
            "'instance_owner', 'admin', 'maintainer', 'reviewer', 'viewer', 'auditor', 'self'"
            ")",
            name="ck_operation_receipts_operation_receipt_required_role_valid",
        ),
        sa.CheckConstraint(
            "state IN ('accepted', 'running', 'succeeded', 'failed', 'unknown')",
            name="ck_operation_receipts_operation_receipt_state_valid",
        ),
        sa.CheckConstraint("version >= 1", name="ck_operation_receipts_version_pos"),
    )
    op.create_index(
        "ix_operation_receipts_workspace_created",
        "operation_receipts",
        ["workspace_id", "created_at", "id"],
    )

    # 6. Enable + Force Row-Level Security across all U08 tables (SEC-032)
    for tbl in _U08_TABLES:
        op.execute(f"ALTER TABLE public.{tbl} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE public.{tbl} FORCE ROW LEVEL SECURITY;")

    # Purely workspace-scoped queue tables (`task_jobs`, `task_attempts`, `dead_letter_jobs`)
    for tbl in _WORKSPACE_SCOPED_TABLES:
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

    # Hybrid instance/workspace RLS on `operation_receipts`
    op.execute(
        """
        CREATE POLICY rls_operation_receipts_select ON public.operation_receipts
        FOR SELECT
        USING (
            (
                current_setting('red2pr.scope_mode', true) = 'workspace'
                AND workspace_id IS NOT NULL
                AND workspace_id = NULLIF(current_setting('red2pr.workspace_id', true), '')
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
        CREATE POLICY rls_operation_receipts_write ON public.operation_receipts
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

    # 7. Least-privilege table & sequence grants for runtime app role
    joined_tables = ", ".join(f"public.{t}" for t in _U08_TABLES)
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {joined_tables} TO "{app_role}";')
    op.execute(f'GRANT USAGE, SELECT ON SEQUENCE public.seq_task_job_dispatch TO "{app_role}";')

    # 8. Record expand-phase metadata in schema_migrations
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
            "parent_revision": "0004_setup_consents_endpoints",
            "checksum": _migration_checksum_sha256(),
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    for tbl in reversed(_U08_TABLES):
        op.drop_table(tbl)
    op.execute("DROP SEQUENCE IF EXISTS public.seq_task_job_dispatch;")
