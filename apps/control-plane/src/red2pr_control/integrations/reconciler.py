"""Missed-event webhook reconciler & `A-06` operator reconciliation service (`U11`).

Implements `SRC-03`, `SRC-04`, `A-06` (`POST /workspaces/{ws}/integrations/{id}/reconcile`),
`S-05`, `S-10`, `S-19`, `W-03`, `NFR-04`, `SEC-010`, `SEC-011`, and `SEC-032`:
- `MissedEventReconciler`:
  - Resolves `webhook_inbox` rows in `status='reconcile_pending'` (e.g., partial/early
    `workflow_job` or GitLab `Job Hook` deliveries before terminal workflow/pipeline state) by
    querying live provider run status (`get_run`), normalizing completed failures via
    `record_normalized_run_failure_trigger`, ignoring runs that subsequently passed/cancelled,
    cascading revocation on `401`/`REVOKED`, and quarantining items stuck past bounded retention.
  - Exposes idempotent (`S-05`) operator reconciliation (`reconcile_connection`) combining
    optional explicit `acknowledge_history_gap`, pending-inbox resolution, and resumable
    repository polling while honoring active `429 Retry-After` ceilings and reporting honest
    `complete_recovery=False` whenever any history gap, rate-limit window, error, or pending
    item remains (`T-SRC-04-N`).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from pydantic import TypeAdapter, ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.integrations import (
    ConnectionReconcileRequest,
    ConnectionReconcileResponse,
    ProviderKind,
    ProviderSyncCursor,
)
from py_contracts.primitives import InternalId, new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import ConflictError, NotFoundError
from red2pr_control.core.logging import bind_telemetry_context, get_structured_logger
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.db.base import (
    ProviderConnectionModel,
    ProviderSyncCursorModel,
    RepositoryModel,
    WebhookInboxModel,
)
from red2pr_control.db.idempotency import (
    claim_idempotent_operation,
    complete_idempotent_operation,
    upsert_operation_receipt,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.rbac import WorkspaceAccessContext
from red2pr_control.integrations.base import (
    ProviderConnectionContext,
    ProviderError,
)
from red2pr_control.integrations.github_app import (
    GitHubAppAdapter,
    GitHubIntegrationService,
    WorkflowHazardScanner,
    _to_connection_context,
    _to_sync_cursor_dto,
)
from red2pr_control.integrations.gitlab_client import GitLabAdapter
from red2pr_control.integrations.poller import LocalPollingService
from red2pr_control.integrations.webhooks import (
    FAILURE_CONCLUSIONS,
    NormalizedRunCandidate,
    record_normalized_run_failure_trigger,
)

DEFAULT_RECONCILE_BATCH_LIMIT = 50
DEFAULT_MAX_PENDING_AGE = timedelta(hours=24)

_UUID_ADAPTER: TypeAdapter[str] = TypeAdapter(InternalId)
_LOGGER = get_structured_logger("red2pr_control.integrations.reconciler")


@dataclass(frozen=True, slots=True)
class PendingInboxReconcileSummary:
    """Summary of resolving `reconcile_pending` webhook inbox rows for one connection."""

    connection_id: str
    workspace_id: str
    resolved_count: int
    triggers_created_count: int
    remaining_pending_count: int


def _validate_uuid_or_404(raw_id: str, *, code: str, detail: str) -> str:
    try:
        return _UUID_ADAPTER.validate_python(raw_id.strip())
    except ValidationError as exc:
        raise NotFoundError(code=code, detail=detail) from exc


class MissedEventReconciler:
    """Reconciles `reconcile_pending` webhook inbox entries and missed polling events (`U11`)."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        github_adapter: GitHubAppAdapter,
        gitlab_adapter: GitLabAdapter,
        poller: LocalPollingService,
        integration_service: GitHubIntegrationService | None = None,
        redactor: Redactor | None = None,
        clock: Callable[[], datetime] | None = None,
        batch_limit: int = DEFAULT_RECONCILE_BATCH_LIMIT,
        max_pending_age: timedelta = DEFAULT_MAX_PENDING_AGE,
    ) -> None:
        self._session_factory = session_factory
        self._github = github_adapter
        self._gitlab = gitlab_adapter
        self._poller = poller
        self._integration_service = integration_service
        self._redactor = redactor or DEFAULT_REDACTOR
        self._clock = clock or (lambda: datetime.now(tz=UTC))
        self._batch_limit = max(1, min(batch_limit, 250))
        self._max_pending_age = max_pending_age

    def now(self) -> datetime:
        return self._clock().astimezone(UTC)

    def _adapter_for(self, provider: ProviderKind) -> GitHubAppAdapter | GitLabAdapter:
        if provider == "github":
            return self._github
        return self._gitlab

    async def reconcile_pending_inbox_for_connection(
        self,
        *,
        workspace_id: str,
        connection_id: str,
        repository_ids: list[str] | None = None,
        correlation_id: str | None = None,
        now: datetime | None = None,
    ) -> PendingInboxReconcileSummary:
        """Resolve `status='reconcile_pending'` webhook inbox rows via live `get_run`."""
        ref_now = now.astimezone(UTC) if now is not None else self.now()
        corr_id = correlation_id or new_uuid7(now=ref_now)
        resolved_count = 0
        triggers_created = 0
        remaining_pending = 0

        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            conn_row = await db.scalar(
                select(ProviderConnectionModel).where(
                    ProviderConnectionModel.workspace_id == workspace_id,
                    ProviderConnectionModel.id == connection_id,
                )
            )
            stmt = (
                select(WebhookInboxModel)
                .where(
                    WebhookInboxModel.workspace_id == workspace_id,
                    WebhookInboxModel.connection_id == connection_id,
                    WebhookInboxModel.status == "reconcile_pending",
                )
                .order_by(WebhookInboxModel.received_at.asc())
                .limit(self._batch_limit)
                .with_for_update(skip_locked=True)
            )
            if repository_ids is not None:
                stmt = stmt.where(WebhookInboxModel.repository_id.in_(repository_ids))

            pending_rows = list((await db.scalars(stmt)).all())
            for inbox_row in pending_rows:
                if conn_row is None or conn_row.status == "revoked":
                    inbox_row.status = "ignored"
                    inbox_row.disposition_reason = "connection_revoked"
                    inbox_row.processed_at = ref_now
                    inbox_row.version += 1
                    inbox_row.updated_at = ref_now
                    resolved_count += 1
                    continue

                if inbox_row.repository_id is None:
                    inbox_row.status = "ignored"
                    inbox_row.disposition_reason = "untracked_repository"
                    inbox_row.processed_at = ref_now
                    inbox_row.version += 1
                    inbox_row.updated_at = ref_now
                    resolved_count += 1
                    continue

                repo_row = await db.scalar(
                    select(RepositoryModel).where(
                        RepositoryModel.workspace_id == workspace_id,
                        RepositoryModel.provider_connection_id == conn_row.id,
                        RepositoryModel.id == inbox_row.repository_id,
                    )
                )
                if repo_row is None or not repo_row.active:
                    inbox_row.status = "ignored"
                    inbox_row.disposition_reason = "repository_inactive_or_missing"
                    inbox_row.processed_at = ref_now
                    inbox_row.version += 1
                    inbox_row.updated_at = ref_now
                    resolved_count += 1
                    continue

                if not inbox_row.provider_run_id:
                    inbox_row.status = "quarantined"
                    inbox_row.disposition_reason = "missing_provider_run_id"
                    inbox_row.processed_at = ref_now
                    inbox_row.version += 1
                    inbox_row.updated_at = ref_now
                    resolved_count += 1
                    continue

                provider = cast(ProviderKind, conn_row.provider)
                adapter = self._adapter_for(provider)
                conn_ctx: ProviderConnectionContext = _to_connection_context(conn_row)

                try:
                    live_run = await adapter.get_run(
                        db,
                        conn_ctx,
                        repo_full_name=repo_row.name,
                        external_run_id=inbox_row.provider_run_id,
                        now=ref_now,
                    )
                except ProviderError as exc:
                    if exc.code == "NOT_FOUND":
                        inbox_row.status = "ignored"
                        inbox_row.disposition_reason = "provider_run_not_found"
                        inbox_row.processed_at = ref_now
                        inbox_row.version += 1
                        inbox_row.updated_at = ref_now
                        resolved_count += 1
                        continue

                    if exc.code == "REVOKED" and self._integration_service is not None:
                        await self._integration_service._suspend_connection_work_and_mark_revoked(
                            db,
                            conn_row=conn_row,
                            actor_type="system",
                            actor_id=f"reconciler:{provider}",
                            reason_code="provider_credentials_revoked",
                            detail=exc.detail,
                            correlation_id=corr_id,
                            client_ip=None,
                            revoke_stored_secrets=False,
                            now=ref_now,
                        )
                        inbox_row.status = "ignored"
                        inbox_row.disposition_reason = "connection_revoked"
                        inbox_row.processed_at = ref_now
                        inbox_row.version += 1
                        inbox_row.updated_at = ref_now
                        resolved_count += 1
                        break

                    if (ref_now - inbox_row.received_at) > self._max_pending_age:
                        inbox_row.status = "quarantined"
                        inbox_row.disposition_reason = f"reconcile_timeout_{exc.code.lower()}"[:120]
                        inbox_row.processed_at = ref_now
                        inbox_row.version += 1
                        inbox_row.updated_at = ref_now
                        resolved_count += 1
                    else:
                        inbox_row.disposition_reason = f"deferred_{exc.code.lower()}"[:120]
                        inbox_row.updated_at = ref_now
                    if exc.code == "RATE_LIMIT":
                        break
                    continue

                if not live_run.jobs_complete:
                    if (ref_now - inbox_row.received_at) > self._max_pending_age:
                        inbox_row.status = "quarantined"
                        inbox_row.disposition_reason = "reconcile_incomplete_timeout"
                        inbox_row.processed_at = ref_now
                        inbox_row.version += 1
                        inbox_row.updated_at = ref_now
                        resolved_count += 1
                    else:
                        inbox_row.disposition_reason = "run_still_in_progress"
                        inbox_row.updated_at = ref_now
                    continue

                if live_run.conclusion not in FAILURE_CONCLUSIONS:
                    inbox_row.status = "ignored"
                    inbox_row.disposition_reason = f"reconciled_non_failure_{live_run.conclusion}"[
                        :120
                    ]
                    inbox_row.processed_at = ref_now
                    inbox_row.version += 1
                    inbox_row.updated_at = ref_now
                    resolved_count += 1
                    continue

                untrusted_fork = live_run.head_repo_fork
                if provider == "github" and live_run.head_repo_id:
                    verdict = WorkflowHazardScanner.classify_pull_request_trust(
                        base_repo_id=repo_row.external_repo_id,
                        head_repo_id=live_run.head_repo_id,
                        head_repo_fork=live_run.head_repo_fork,
                    )
                    untrusted_fork = verdict.untrusted_fork

                explicit_rerun = False
                if provider == "github" and ":" in live_run.attempt_key:
                    att_part = live_run.attempt_key.rsplit(":", 1)[-1]
                    explicit_rerun = att_part.isdigit() and int(att_part) > 1

                candidate = NormalizedRunCandidate(
                    provider=provider,
                    external_repo_id=repo_row.external_repo_id,
                    repo_full_name=repo_row.name,
                    provider_run_id=live_run.external_run_id,
                    attempt_key=live_run.attempt_key,
                    head_sha=live_run.head_sha,
                    ref=live_run.ref,
                    event_type=live_run.event_type,
                    status=live_run.status,
                    conclusion=live_run.conclusion,
                    jobs_complete=live_run.jobs_complete,
                    raw_vendor_status=live_run.raw_vendor_status,
                    untrusted_fork=untrusted_fork,
                    event_timestamp=inbox_row.received_at,
                    explicit_rerun=explicit_rerun,
                )
                resolution = await record_normalized_run_failure_trigger(
                    db,
                    workspace_id=workspace_id,
                    conn_row=conn_row,
                    repo_row=repo_row,
                    candidate=candidate,
                    source="reconcile",
                    inbox_id=inbox_row.id,
                    correlation_id=corr_id,
                    redactor=self._redactor,
                    now=ref_now,
                )
                if resolution.created:
                    triggers_created += 1

                inbox_row.status = resolution.inbox_status
                inbox_row.disposition_reason = resolution.reason_code[:120]
                inbox_row.trigger_id = resolution.trigger_id
                inbox_row.processed_at = ref_now
                inbox_row.version += 1
                inbox_row.updated_at = ref_now
                resolved_count += 1

            await db.flush()
            rem_stmt = select(func.count(WebhookInboxModel.id)).where(
                WebhookInboxModel.workspace_id == workspace_id,
                WebhookInboxModel.connection_id == connection_id,
                WebhookInboxModel.status == "reconcile_pending",
            )
            if repository_ids is not None:
                rem_stmt = rem_stmt.where(WebhookInboxModel.repository_id.in_(repository_ids))
            remaining_pending = int((await db.scalar(rem_stmt)) or 0)

        return PendingInboxReconcileSummary(
            connection_id=connection_id,
            workspace_id=workspace_id,
            resolved_count=resolved_count,
            triggers_created_count=triggers_created,
            remaining_pending_count=remaining_pending,
        )

    async def reconcile_connection(
        self,
        ctx: WorkspaceAccessContext,
        *,
        connection_id: str,
        payload: ConnectionReconcileRequest,
        idempotency_key: str,
        client_ip: str,
        correlation_id: str,
        now: datetime | None = None,
    ) -> ConnectionReconcileResponse:
        """Execute `A-06` idempotent (`S-05`) connection run reconciliation (`UI-S15`)."""
        ws_id = ctx.workspace_id
        ref_now = now.astimezone(UTC) if now is not None else self.now()
        clean_id = _validate_uuid_or_404(
            connection_id,
            code="connection_not_found",
            detail="Provider connection not found.",
        )

        requested_repo_ids: list[str] | None = None
        if payload.repository_ids is not None:
            requested_repo_ids = [
                _validate_uuid_or_404(
                    rid,
                    code="repository_not_found",
                    detail="Repository not found.",
                )
                for rid in payload.repository_ids
            ]

        effect_key = f"integration.reconcile:{ws_id}:{clean_id}:{idempotency_key}"
        target_repo_ids: list[str] = []

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            conn_row = await db.scalar(
                select(ProviderConnectionModel)
                .where(
                    ProviderConnectionModel.workspace_id == ws_id,
                    ProviderConnectionModel.id == clean_id,
                )
                .with_for_update()
            )
            if conn_row is None:
                raise NotFoundError(
                    code="connection_not_found",
                    detail="Provider connection not found.",
                )

            repo_rows = list(
                (
                    await db.scalars(
                        select(RepositoryModel)
                        .where(
                            RepositoryModel.workspace_id == ws_id,
                            RepositoryModel.provider_connection_id == clean_id,
                            RepositoryModel.active.is_(True),
                        )
                        .order_by(RepositoryModel.name.asc())
                    )
                ).all()
            )
            visible_repo_ids = {r.id for r in repo_rows if ctx.can_read_repository(r.id)}
            if requested_repo_ids is not None:
                for rid in requested_repo_ids:
                    if rid not in visible_repo_ids:
                        raise NotFoundError(
                            code="repository_not_found",
                            detail="Repository not found.",
                        )
                target_repo_ids = list(dict.fromkeys(requested_repo_ids))
            else:
                target_repo_ids = [r.id for r in repo_rows if r.id in visible_repo_ids]

            claim = await claim_idempotent_operation(
                db,
                workspace_id=ws_id,
                principal_id=ctx.auth.user.id,
                operation="integrations.reconcile",
                idempotency_key=idempotency_key,
                request_payload=payload.model_dump(mode="json"),
                logical_effect_key=effect_key,
                resource_id=clean_id,
                correlation_id=correlation_id,
                now=ref_now,
            )
            if not claim.is_new_claim:
                if claim.cached_response is not None:
                    return ConnectionReconcileResponse.model_validate(claim.cached_response)
                raise ConflictError(
                    code="operation_in_progress",
                    detail=(
                        "Reconciliation for this Idempotency-Key is currently in progress; "
                        "poll the operation receipt or retry once complete."
                    ),
                )

            await upsert_operation_receipt(
                db,
                operation_id=claim.receipt.operation_id,
                scope="workspace",
                workspace_id=ws_id,
                repository_id=None,
                principal_id=ctx.auth.user.id,
                required_role="admin",
                operation_kind="integrations.reconcile",
                resource_id=clean_id,
                state=claim.receipt.state,
                correlation_id=claim.receipt.correlation_id,
                status_url=claim.receipt.status_url,
                logical_effect_key=effect_key,
                result_id=clean_id,
                now=ref_now,
            )

        if payload.acknowledge_history_gap:
            await self._poller.acknowledge_connection_history_gaps(
                workspace_id=ws_id,
                connection_id=clean_id,
                repository_ids=target_repo_ids if requested_repo_ids is not None else None,
                actor_user_id=ctx.auth.user.id,
                correlation_id=correlation_id,
                client_ip=client_ip,
                now=ref_now,
            )

        inbox_summary = await self.reconcile_pending_inbox_for_connection(
            workspace_id=ws_id,
            connection_id=clean_id,
            repository_ids=target_repo_ids if requested_repo_ids is not None else None,
            correlation_id=correlation_id,
            now=ref_now,
        )
        poll_summary = await self._poller.poll_connection(
            workspace_id=ws_id,
            connection_id=clean_id,
            repository_ids=target_repo_ids,
            force_poll=payload.force_poll,
            correlation_id=correlation_id,
            now=ref_now,
        )

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            conn_row = await db.scalar(
                select(ProviderConnectionModel).where(
                    ProviderConnectionModel.workspace_id == ws_id,
                    ProviderConnectionModel.id == clean_id,
                )
            )
            if conn_row is None:
                raise NotFoundError(
                    code="connection_not_found",
                    detail="Provider connection not found.",
                )

            cursor_rows = list(
                (
                    await db.scalars(
                        select(ProviderSyncCursorModel)
                        .where(
                            ProviderSyncCursorModel.workspace_id == ws_id,
                            ProviderSyncCursorModel.connection_id == clean_id,
                        )
                        .order_by(
                            ProviderSyncCursorModel.created_at.asc(),
                            ProviderSyncCursorModel.id.asc(),
                        )
                    )
                ).all()
            )
            visible_cursors: list[ProviderSyncCursor] = [
                _to_sync_cursor_dto(c)
                for c in cursor_rows
                if ctx.can_read_repository(c.repository_id)
            ]

            rate_limited_count = sum(1 for c in visible_cursors if c.last_status == "rate_limited")
            history_gap_count = sum(1 for c in visible_cursors if c.history_gap_detected)
            degraded_cursor_present = any(
                c.history_gap_detected
                or c.last_status in {"rate_limited", "gap_detected", "error", "revoked"}
                for c in visible_cursors
            )
            complete_recovery = (
                conn_row.status in {"ready", "degraded"}
                and inbox_summary.remaining_pending_count == 0
                and not degraded_cursor_present
            )

            total_triggers = (
                inbox_summary.triggers_created_count + poll_summary.triggers_created_count
            )
            await append_audit_entry(
                db,
                workspace_id=ws_id,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                action="integration.connection_reconciled",
                target=f"provider_connection:{clean_id}",
                decision="reconcile",
                reason_code="complete" if complete_recovery else "incomplete_or_gap_detected",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={
                    "polled_repository_count": poll_summary.polled_repository_count,
                    "reconciled_inbox_count": inbox_summary.resolved_count,
                    "triggers_created_count": total_triggers,
                    "rate_limited_count": rate_limited_count,
                    "history_gap_count": history_gap_count,
                    "complete_recovery": complete_recovery,
                },
                occurred_at=ref_now,
            )

            receipt = await complete_idempotent_operation(
                db,
                workspace_id=ws_id,
                operation_id=claim.receipt.operation_id,
                state="succeeded",
                status_code=200,
                result_id=conn_row.id,
                now=ref_now,
            )
            await upsert_operation_receipt(
                db,
                operation_id=receipt.operation_id,
                scope="workspace",
                workspace_id=ws_id,
                repository_id=None,
                principal_id=ctx.auth.user.id,
                required_role="admin",
                operation_kind="integrations.reconcile",
                resource_id=conn_row.id,
                state=receipt.state,
                correlation_id=receipt.correlation_id,
                status_url=receipt.status_url,
                logical_effect_key=effect_key,
                result_id=conn_row.id,
                now=ref_now,
            )

            resp_dto = ConnectionReconcileResponse(
                receipt=receipt,
                connection_id=conn_row.id,
                polled_repository_count=poll_summary.polled_repository_count,
                rate_limited_count=rate_limited_count,
                history_gap_count=history_gap_count,
                triggers_created_count=total_triggers,
                pending_inbox_reconciled_count=inbox_summary.resolved_count,
                complete_recovery=complete_recovery,
                sync_cursors=visible_cursors,
            )
            await complete_idempotent_operation(
                db,
                workspace_id=ws_id,
                operation_id=claim.receipt.operation_id,
                state="succeeded",
                status_code=200,
                result_id=conn_row.id,
                response_payload=resp_dto.model_dump(mode="json"),
                now=ref_now,
            )
            return resp_dto

    async def reconcile_all_connections(
        self,
        *,
        now: datetime | None = None,
    ) -> tuple[PendingInboxReconcileSummary, ...]:
        """Sweep all `ready`/`degraded` connections resolving `reconcile_pending` inbox entries."""
        ref_now = now.astimezone(UTC) if now is not None else self.now()
        async with instance_rls_session(self._session_factory, mode="instance_admin") as lookup:
            pairs = list(
                (
                    await lookup.execute(
                        select(
                            ProviderConnectionModel.workspace_id,
                            ProviderConnectionModel.id,
                        )
                        .where(ProviderConnectionModel.status.in_(("ready", "degraded")))
                        .order_by(ProviderConnectionModel.created_at.asc())
                    )
                ).all()
            )

        summaries: list[PendingInboxReconcileSummary] = []
        for ws_id, conn_id in pairs:
            corr_id = new_uuid7(now=ref_now)
            with bind_telemetry_context(
                correlation_id=corr_id,
                workspace_id=str(ws_id),
                entry_point="scheduler",
            ):
                summary = await self.reconcile_pending_inbox_for_connection(
                    workspace_id=str(ws_id),
                    connection_id=str(conn_id),
                    correlation_id=corr_id,
                    now=ref_now,
                )
                summaries.append(summary)
        return tuple(summaries)

    async def run_loop(
        self,
        stop_event: asyncio.Event,
        *,
        tick_seconds: float = 60.0,
    ) -> None:
        """Cancellable background reconciler loop (`<=5m` missed-event catchup, `NFR-04`)."""
        bounded_tick = max(5.0, tick_seconds)
        while not stop_event.is_set():
            try:
                await self.reconcile_all_connections()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                _LOGGER.error(
                    "Background missed-event reconciler sweep encountered an error",
                    extra={
                        "event": "integration.reconciler.sweep_error",
                        "error_code": type(exc).__name__,
                    },
                )
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=bounded_tick)
            except TimeoutError:
                continue
