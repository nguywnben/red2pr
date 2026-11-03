"""Background coordinator consuming durable `ci_run.triage` queue jobs in the control plane."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.primitives import new_uuid7
from red2pr_control.core.errors import Red2PrError
from red2pr_control.core.logging import get_structured_logger
from red2pr_control.db.base import (
    BudgetAccountModel,
    RepositoryModel,
    RepositoryPolicyModel,
    WorkspaceModelConfigModel,
)
from red2pr_control.db.budget_accounts import (
    ensure_repair_session_budget_account_in_tx,
    ensure_workspace_daily_budget_account_in_tx,
    resolve_workspace_budget_policy_in_tx,
)
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.orchestrator import DurableTaskQueueService
from red2pr_control.orchestrator.state_machine import RepairSessionStateMachine
from red2pr_control.triage_evidence.collector import CiRunCollectorService

_LOGGER = get_structured_logger("red2pr_control.runtime_pipeline")


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


class RuntimePipelineCoordinator:
    """Drains durable `ci_run.triage` jobs into `CiRunCollectorService` and auto-repair intake."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        queue_service: DurableTaskQueueService,
        collector_service: CiRunCollectorService,
        state_machine: RepairSessionStateMachine,
        worker_id: str | None = None,
        poll_interval_seconds: float = 1.0,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._session_factory = session_factory
        self._queue = queue_service
        self._collector = collector_service
        self._state_machine = state_machine
        self._worker_id = worker_id if worker_id is not None else new_uuid7(now=clock())
        self._poll_interval = max(0.05, poll_interval_seconds)
        self._clock = clock

    async def run_once(self, *, now: datetime | None = None) -> bool:
        """Process at most one queued `ci_run.triage` job; return True if a job was handled."""
        ref_now = now.astimezone(UTC) if now is not None else self._clock().astimezone(UTC)
        leased = await self._queue.acquire_next_lease(
            worker_id=self._worker_id,
            now=ref_now,
            allowed_kinds=("ci_run.triage",),
        )
        if leased is None:
            return False

        job = leased.job
        lease_epoch = job.lease_epoch
        await self._queue.mark_lease_running(
            job_id=job.id,
            worker_id=self._worker_id,
            lease_epoch=lease_epoch,
            now=ref_now,
        )
        try:
            ci_run = await self._collector.collect_from_trigger(
                workspace_id=job.workspace_id,
                trigger_id=job.resource_id,
                correlation_id=job.correlation_id,
                now=ref_now,
            )
            payload = leased.payload or {}
            if bool(payload.get("allow_sandbox_execution")) and ci_run.head_sha_verified:
                await self._maybe_enqueue_auto_repair_session(
                    workspace_id=job.workspace_id,
                    repository_id=ci_run.repository_id,
                    ci_run_id=ci_run.id,
                    head_sha=ci_run.head_sha,
                    target_ref=ci_run.ref,
                    conclusion=ci_run.conclusion,
                    correlation_id=job.correlation_id or new_uuid7(now=ref_now),
                    now=ref_now,
                )
            await self._queue.complete_lease(
                job_id=job.id,
                worker_id=self._worker_id,
                lease_epoch=lease_epoch,
                now=self._clock().astimezone(UTC),
            )
            return True
        except Red2PrError as exc:
            recoverable = exc.status in (429, 502, 503, 504)
            await self._queue.fail_lease(
                job_id=job.id,
                worker_id=self._worker_id,
                lease_epoch=lease_epoch,
                error_code=exc.code,
                error_detail=exc.detail,
                now=self._clock().astimezone(UTC),
                recoverable=recoverable,
            )
            return True
        except Exception as exc:
            _LOGGER.error(
                "Unhandled ci_run.triage pipeline failure",
                exc_info=exc,
                extra={"event": "pipeline.triage_failed", "job_id": job.id},
            )
            await self._queue.fail_lease(
                job_id=job.id,
                worker_id=self._worker_id,
                lease_epoch=lease_epoch,
                error_code="triage_internal_error",
                error_detail="CI run collection failed due to an unexpected internal error.",
                now=self._clock().astimezone(UTC),
                recoverable=True,
            )
            return True

    async def _maybe_enqueue_auto_repair_session(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        ci_run_id: str,
        head_sha: str,
        target_ref: str,
        conclusion: str | None,
        correlation_id: str,
        now: datetime,
    ) -> None:
        if conclusion not in {"failure", "timed_out", "action_required"}:
            return
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            repo = await db.scalar(
                select(RepositoryModel).where(
                    RepositoryModel.workspace_id == workspace_id,
                    RepositoryModel.id == repository_id,
                )
            )
            if repo is None or repo.paused or repo.mode != "auto_repair":
                return
            policy = await db.scalar(
                select(RepositoryPolicyModel)
                .where(
                    RepositoryPolicyModel.workspace_id == workspace_id,
                    RepositoryPolicyModel.repository_id == repository_id,
                )
                .order_by(RepositoryPolicyModel.revision.desc())
                .limit(1)
            )
            if policy is None or policy.paused or policy.mode != "auto_repair":
                return
            daily_budget = await db.scalar(
                select(BudgetAccountModel)
                .where(
                    BudgetAccountModel.workspace_id == workspace_id,
                    BudgetAccountModel.scope_kind.in_(("workspace_daily", "workspace_total")),
                    BudgetAccountModel.cancelled_at.is_(None),
                )
                .order_by(BudgetAccountModel.scope_kind)
                .limit(1)
            )
            if daily_budget is None:
                cfg_row = await db.scalar(
                    select(WorkspaceModelConfigModel).where(
                        WorkspaceModelConfigModel.workspace_id == workspace_id
                    )
                )
                if cfg_row is not None and cfg_row.budget_policy_json:
                    pol = await resolve_workspace_budget_policy_in_tx(db, workspace_id=workspace_id)
                    if pol.max_cost_per_session.amount > 0:
                        daily_budget = await ensure_workspace_daily_budget_account_in_tx(
                            db,
                            workspace_id=workspace_id,
                            policy=pol,
                            now=now,
                        )
            if daily_budget is None:
                return
            budget_policy = await resolve_workspace_budget_policy_in_tx(
                db,
                workspace_id=workspace_id,
                fallback_account=daily_budget,
            )
            if budget_policy.max_cost_per_session.amount <= 0:
                return
            trigger_key = f"auto:{ci_run_id}"
            session_budget = await ensure_repair_session_budget_account_in_tx(
                db,
                workspace_id=workspace_id,
                scope_key=trigger_key,
                policy=budget_policy,
                repository_id=repository_id,
                now=now,
            )
            repair_row, created = await self._state_machine.create_or_get_session_in_tx(
                db,
                workspace_id=workspace_id,
                repository_id=repository_id,
                ci_run_id=ci_run_id,
                semantic_trigger_key=trigger_key,
                base_sha=head_sha,
                target_ref=target_ref,
                policy_revision=policy.revision,
                budget_account_id=session_budget.id,
                correlation_id=correlation_id,
                actor="system:auto_repair_intake",
            )
            if created and session_budget.repair_id is None:
                session_budget.repair_id = repair_row.id
                await db.flush()

    async def run_forever(self) -> None:
        """Continuously poll durable `ci_run.triage` jobs until cancelled."""
        while True:
            processed = await self.run_once()
            if not processed:
                await asyncio.sleep(self._poll_interval)
