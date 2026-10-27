"""Webhook inbox, provider sync cursors, semantic CI run triggers & RLS.

Revision ID: 0007_webhook_inbox_sync_cursors
Revises: 0006_provider_connections_repos
Create Date: 2026-10-27T23:30:00Z

Implements Unit U11 (`SRC-03`, `SRC-04`, `A-22`, `S-10`, `S-19`, `W-03`, `NFR-01`,
`NFR-03`, `NFR-04`, `SEC-001`, `SEC-002`, `SEC-003`, `SEC-011`, `SEC-027`, `SEC-032`):
- `ci_run_triggers`: workspace-scoped normalized semantic run-attempt trigger ledger
  enforcing `UNIQUE (workspace_id, repository_id, provider_run_id, attempt_key)` so
  concurrent duplicate/reordered webhooks and overlapping polling converge on at most
  one repair/triage trigger while genuine reruns (`5001:1` vs `5001:2`) stay distinct.
- `webhook_inbox`: durable verified webhook & poll delivery inbox enforcing
  `UNIQUE (connection_id, provider_delivery_id)` and `signature_valid IS TRUE`, storing
  only sanitized headers and redacted summary payloads (`90d` default retention).
- `provider_sync_cursors`: resumable per-repository polling checkpoint (`ETag`,
  `high_water_mark_at`, `5m` overlap window, `429 Retry-After` backoff ceiling, and
  explicit offline history-TTL gap tracking).
- `ENABLE` + `FORCE ROW LEVEL SECURITY` on all 3 U11 tables (`SEC-032`, 35 total RLS tables).
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

revision: str = "0007_webhook_inbox_sync_cursors"
down_revision: str | Sequence[str] | None = "0006_provider_connections_repos"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

_U11_TABLES: tuple[str, ...] = (
    "ci_run_triggers",
    "webhook_inbox",
    "provider_sync_cursors",
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

    # 1. ci_run_triggers (W-03 / S-10 / SEC-002 semantic run-attempt dedup guard)
    op.create_table(
        "ci_run_triggers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("connection_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("provider_run_id", sa.String(length=128), nullable=False),
        sa.Column("attempt_key", sa.String(length=128), nullable=False),
        sa.Column("head_sha", sa.String(length=64), nullable=False),
        sa.Column("ref", sa.String(length=120), nullable=False),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'completed'"),
        ),
        sa.Column(
            "conclusion",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'failure'"),
        ),
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
        sa.Column("first_source", sa.String(length=32), nullable=False),
        sa.Column("first_inbox_id", sa.String(length=36), nullable=True),
        sa.Column("job_id", sa.String(length=36), nullable=True),
        sa.Column("correlation_id", sa.String(length=120), nullable=False),
        sa.Column("triggered_at", sa.DateTime(timezone=True), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name="pk_ci_run_triggers"),
        sa.UniqueConstraint(
            "workspace_id",
            "id",
            name="uq_ci_run_triggers_workspace_id_id",
        ),
        sa.UniqueConstraint(
            "workspace_id",
            "repository_id",
            "provider_run_id",
            "attempt_key",
            name="uq_ci_run_triggers_semantic",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_ci_run_triggers_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["provider_connections.workspace_id", "provider_connections.id"],
            name="fk_ci_run_triggers_tenant_conn_provider_connections",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_ci_run_triggers_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "provider IN ('github', 'gitlab')",
            name="ck_ci_run_triggers_ci_run_trigger_provider_valid",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'in_progress', 'completed', 'unknown')",
            name="ck_ci_run_triggers_ci_run_trigger_status_valid",
        ),
        sa.CheckConstraint(
            "conclusion IN ("
            "'failure', 'timed_out', 'action_required', 'cancelled', "
            "'success', 'skipped', 'neutral', 'unknown'"
            ")",
            name="ck_ci_run_triggers_ci_run_trigger_conclusion_valid",
        ),
        sa.CheckConstraint(
            "first_source IN ('webhook', 'poll', 'reconcile')",
            name="ck_ci_run_triggers_ci_run_trigger_source_valid",
        ),
        sa.CheckConstraint("version >= 1", name="ck_ci_run_triggers_version_pos"),
    )
    op.create_index(
        "ix_ci_run_triggers_ws_repo_run",
        "ci_run_triggers",
        ["workspace_id", "repository_id", "provider_run_id", "triggered_at"],
    )

    # 2. webhook_inbox (SRC-03 / A-22 / NFR-01 durable verified delivery inbox)
    op.create_table(
        "webhook_inbox",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("connection_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=True),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column(
            "source",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'webhook'"),
        ),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column("provider_delivery_id", sa.String(length=256), nullable=False),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        sa.Column(
            "signature_valid",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("provider_run_id", sa.String(length=128), nullable=True),
        sa.Column("attempt_key", sa.String(length=128), nullable=True),
        sa.Column("head_sha", sa.String(length=64), nullable=True),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'received'"),
        ),
        sa.Column("disposition_reason", sa.String(length=120), nullable=True),
        sa.Column(
            "sanitized_headers_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "normalized_summary_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("trigger_id", sa.String(length=36), nullable=True),
        sa.Column("correlation_id", sa.String(length=120), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retention_until", sa.DateTime(timezone=True), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name="pk_webhook_inbox"),
        sa.UniqueConstraint(
            "workspace_id",
            "id",
            name="uq_webhook_inbox_workspace_id_id",
        ),
        sa.UniqueConstraint(
            "connection_id",
            "provider_delivery_id",
            name="uq_webhook_inbox_conn_delivery",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_webhook_inbox_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["provider_connections.workspace_id", "provider_connections.id"],
            name="fk_webhook_inbox_tenant_conn_provider_connections",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_webhook_inbox_tenant_repo_repositories",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "provider IN ('github', 'gitlab')",
            name="ck_webhook_inbox_webhook_inbox_provider_valid",
        ),
        sa.CheckConstraint(
            "source IN ('webhook', 'poll', 'reconcile')",
            name="ck_webhook_inbox_webhook_inbox_source_valid",
        ),
        sa.CheckConstraint(
            "signature_valid IS TRUE",
            name="ck_webhook_inbox_webhook_inbox_signature_verified",
        ),
        sa.CheckConstraint(
            "status IN ("
            "'received', 'normalized', 'duplicate_semantic', "
            "'ignored', 'reconcile_pending', 'quarantined'"
            ")",
            name="ck_webhook_inbox_webhook_inbox_status_valid",
        ),
        sa.CheckConstraint("version >= 1", name="ck_webhook_inbox_version_pos"),
    )
    op.create_index(
        "ix_webhook_inbox_ws_status_received",
        "webhook_inbox",
        ["workspace_id", "status", "received_at", "id"],
    )
    op.create_index(
        "ix_webhook_inbox_conn_received",
        "webhook_inbox",
        ["workspace_id", "connection_id", "received_at"],
    )
    op.create_index(
        "ix_webhook_inbox_retention",
        "webhook_inbox",
        ["workspace_id", "retention_until"],
    )

    # 3. provider_sync_cursors (SRC-04 / NFR-04 resumable local polling cursor)
    op.create_table(
        "provider_sync_cursors",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("connection_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("etag", sa.String(length=512), nullable=True),
        sa.Column("high_water_mark_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_run_id", sa.String(length=128), nullable=True),
        sa.Column(
            "last_stable_page",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "overlap_seconds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("300"),
        ),
        sa.Column(
            "poll_interval_seconds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("60"),
        ),
        sa.Column("last_polled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_poll_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rate_limit_remaining", sa.Integer(), nullable=True),
        sa.Column("rate_limit_reset_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "consecutive_failures",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "last_status",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'idle'"),
        ),
        sa.Column("last_error_code", sa.String(length=120), nullable=True),
        sa.Column("last_error_detail", sa.String(length=1000), nullable=True),
        sa.Column(
            "history_gap_detected",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("history_gap_since", sa.DateTime(timezone=True), nullable=True),
        sa.Column("history_gap_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("history_gap_detail", sa.String(length=1000), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_provider_sync_cursors"),
        sa.UniqueConstraint(
            "workspace_id",
            "id",
            name="uq_provider_sync_cursors_workspace_id_id",
        ),
        sa.UniqueConstraint(
            "workspace_id",
            "connection_id",
            "repository_id",
            name="uq_provider_sync_cursors_ws_conn_repo",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_provider_sync_cursors_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "connection_id"],
            ["provider_connections.workspace_id", "provider_connections.id"],
            name="fk_provider_sync_cursors_tenant_conn_provider_connections",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "repository_id"],
            ["repositories.workspace_id", "repositories.id"],
            name="fk_provider_sync_cursors_tenant_repo_repositories",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "provider IN ('github', 'gitlab')",
            name="ck_provider_sync_cursors_provider_sync_cursor_provider_valid",
        ),
        sa.CheckConstraint(
            "last_stable_page >= 1",
            name="ck_provider_sync_cursors_provider_sync_cursor_page_pos",
        ),
        sa.CheckConstraint(
            "overlap_seconds >= 0 AND overlap_seconds <= 3600",
            name="ck_provider_sync_cursors_provider_sync_cursor_overlap_bounds",
        ),
        sa.CheckConstraint(
            "poll_interval_seconds >= 10 AND poll_interval_seconds <= 3600",
            name="ck_provider_sync_cursors_provider_sync_cursor_interval_bounds",
        ),
        sa.CheckConstraint(
            "consecutive_failures >= 0",
            name="ck_provider_sync_cursors_provider_sync_cursor_failures_nonneg",
        ),
        sa.CheckConstraint(
            "last_status IN ("
            "'idle', 'ok', 'not_modified', 'rate_limited', 'gap_detected', 'error', 'revoked'"
            ")",
            name="ck_provider_sync_cursors_provider_sync_cursor_status_valid",
        ),
        sa.CheckConstraint("version >= 1", name="ck_provider_sync_cursors_version_pos"),
    )
    op.create_index(
        "ix_provider_sync_cursors_due",
        "provider_sync_cursors",
        ["workspace_id", "connection_id", "next_poll_after"],
    )

    # 4. Enable + Force Row-Level Security across all U11 tables (SEC-032)
    for tbl in _U11_TABLES:
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

    # 5. Least-privilege table grants for runtime app role
    joined_tables = ", ".join(f"public.{t}" for t in _U11_TABLES)
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
            "parent_revision": "0006_provider_connections_repos",
            "checksum": _migration_checksum_sha256(),
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM public.schema_migrations WHERE revision = :revision"),
        {"revision": revision},
    )
    for tbl in reversed(_U11_TABLES):
        op.drop_table(tbl)
