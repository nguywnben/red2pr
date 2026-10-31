"""Database-backed SLI probes and tenant-scoped in-app operational alarms (U25)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.crypto import KeyRing
from py_contracts.events import EventEnvelope, OperationalAlarmEventPayload
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import (
    AuditIntegrityError,
    ExternalCheckpointStore,
    append_audit_entry,
    verify_audit_chain,
)
from red2pr_control.core.alarms import Alarm, AlarmEvaluator, AlarmObservation
from red2pr_control.core.telemetry import get_control_plane_meter
from red2pr_control.db.base import (
    OperationalAlarmModel,
    OutboxEventModel,
    TaskJobModel,
    WorkerModel,
    WorkspaceModel,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session

_LOGGER = logging.getLogger(__name__)
_ALARM_POLL_SECONDS = 15
_BACKUP_FAILURE_WINDOW = timedelta(hours=24)


class OperationalAlarmWorker:
    """Poll bounded probes, persist alarm transitions, audit and enqueue notifications."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        artifact_store: Any | None = None,
        task_queue_service: Any | None = None,
        checkpoint_store: ExternalCheckpointStore | None = None,
        checkpoint_keyring: KeyRing | None = None,
        storage_usage_probe: Callable[[], float | None] | None = None,
        poll_interval: float = _ALARM_POLL_SECONDS,
    ) -> None:
        if (checkpoint_store is None) != (checkpoint_keyring is None):
            raise ValueError("Audit checkpoint store and keyring must be supplied together.")
        if poll_interval <= 0 or poll_interval > 60:
            raise ValueError("Alarm poll interval must be between 0 and 60 seconds.")
        self.session_factory = session_factory
        self.artifact_store = artifact_store
        self.task_queue_service = task_queue_service
        self.checkpoint_store = checkpoint_store
        self.checkpoint_keyring = checkpoint_keyring
        self.storage_usage_probe = storage_usage_probe
        self.poll_interval = poll_interval
        self._evaluators: dict[str, AlarmEvaluator] = {}
        self._alarm_counter = get_control_plane_meter().create_counter(
            "red2pr.operations.alarms.transitions",
            description="Firing and resolved operational alarms",
        )

    def _storage_percent(self) -> float | None:
        if self.storage_usage_probe is not None:
            observed = self.storage_usage_probe()
            return observed if observed is not None and 0.0 <= observed <= 100.0 else None
        root = getattr(self.artifact_store, "root_dir", None)
        if not isinstance(root, (str, Path)):
            return None
        try:
            import shutil

            disk = shutil.disk_usage(root)
        except OSError:
            return None
        if disk.total <= 0:
            return None
        return 100.0 * disk.used / disk.total

    async def _probe_workspace(
        self,
        workspace_id: str,
        *,
        now: datetime,
        worker_quarantined: bool,
        storage_percent: float | None,
        audit_chain_mismatch: bool,
    ) -> AlarmObservation:
        async with workspace_rls_session(self.session_factory, workspace_id=workspace_id) as db:
            oldest_queued = await db.scalar(
                select(func.min(TaskJobModel.created_at)).where(TaskJobModel.state == "queued")
            )
            queue_lag = (
                max(0.0, (now - oldest_queued.astimezone(UTC)).total_seconds())
                if oldest_queued is not None
                else 0.0
            )
            backup_failed = bool(
                await db.scalar(
                    select(OutboxEventModel.id)
                    .where(
                        OutboxEventModel.event_type == "backup.failed",
                        OutboxEventModel.occurred_at >= now - _BACKUP_FAILURE_WINDOW,
                    )
                    .limit(1)
                )
            )
        return AlarmObservation(
            queue_lag_seconds=queue_lag,
            backup_failed=backup_failed,
            worker_quarantined=worker_quarantined,
            storage_percent=storage_percent or 0.0,
            audit_chain_mismatch=audit_chain_mismatch,
        )

    async def _restore_active(self, db: AsyncSession, evaluator: AlarmEvaluator) -> None:
        rows = (
            await db.scalars(
                select(OperationalAlarmModel).where(OperationalAlarmModel.state == "firing")
            )
        ).all()
        for row in rows:
            evaluator.restore_firing(row.alarm_code, first_seen_at=row.first_seen_at)

    async def _persist_transition(
        self,
        workspace_id: str,
        alarm: Alarm,
        *,
        now: datetime,
    ) -> None:
        async with workspace_rls_session(self.session_factory, workspace_id=workspace_id) as db:
            row = await db.scalar(
                select(OperationalAlarmModel)
                .where(
                    OperationalAlarmModel.workspace_id == workspace_id,
                    OperationalAlarmModel.alarm_code == alarm.code,
                )
                .with_for_update()
            )
            if row is not None and row.state == alarm.state:
                row.last_observed_at = now
                return
            is_new = row is None
            alarm_id = row.id if row is not None else new_uuid7(now=now)
            version = 1 if row is None else row.version + 1
            if row is None:
                row = OperationalAlarmModel(
                    id=alarm_id,
                    workspace_id=workspace_id,
                    alarm_code=alarm.code,
                    state=alarm.state,
                    first_seen_at=alarm.first_seen_at,
                    last_observed_at=now,
                    resolved_at=now if alarm.state == "resolved" else None,
                    version=version,
                    correlation_id=f"alarm:{workspace_id}:{alarm.code}",
                )
                db.add(row)
            else:
                row.state = alarm.state
                row.first_seen_at = alarm.first_seen_at
                row.last_observed_at = now
                row.resolved_at = now if alarm.state == "resolved" else None
                row.version = version
            await db.flush()
            event = EventEnvelope(
                event_id=new_uuid7(now=now),
                type="operations.alarm",
                occurred_at=now,
                workspace_id=workspace_id,
                aggregate_id=alarm_id,
                aggregate_version=version,
                correlation_id=f"alarm:{workspace_id}:{alarm.code}",
                payload=OperationalAlarmEventPayload(
                    alarm_id=alarm_id,
                    alarm_code=alarm.code,
                    state=alarm.state,
                ),
            )
            from red2pr_control.db.outbox import enqueue_outbox_event

            await enqueue_outbox_event(db, event, now=now)
            await append_audit_entry(
                db,
                actor_type="system",
                actor_id="operations-alarm-monitor",
                action=f"operations.alarm.{alarm.state}",
                target=f"operational_alarm:{alarm_id}",
                decision="allow",
                reason_code=alarm.code,
                correlation_id=event.correlation_id,
                workspace_id=workspace_id,
                occurred_at=now,
                metadata={"state": alarm.state, "version": version},
            )
            self._alarm_counter.add(1, {"alarm_code": alarm.code, "state": alarm.state})
            del is_new

    async def process_once(self, *, now: datetime | None = None) -> int:
        observed_at = now.astimezone(UTC) if now is not None else datetime.now(tz=UTC)
        async with instance_rls_session(self.session_factory, mode="instance_admin") as db:
            workspace_ids = list(await db.scalars(select(WorkspaceModel.id)))
            worker_quarantined = bool(
                await db.scalar(
                    select(WorkerModel.id).where(WorkerModel.status == "quarantined").limit(1)
                )
            )
        storage_percent = self._storage_percent()
        if self.task_queue_service is not None and storage_percent is not None:
            setter = getattr(self.task_queue_service, "set_storage_admission_paused", None)
            if callable(setter):
                setter(storage_percent >= 90)
        audit_mismatch = False
        if self.checkpoint_store is not None and self.checkpoint_keyring is not None:
            try:
                async with instance_rls_session(
                    self.session_factory, mode="audit_verifier"
                ) as audit_db:
                    await verify_audit_chain(
                        audit_db,
                        external_store=self.checkpoint_store,
                        keyring=self.checkpoint_keyring,
                    )
            except AuditIntegrityError:
                audit_mismatch = True
        transitions = 0
        for workspace_id in workspace_ids:
            evaluator = self._evaluators.setdefault(workspace_id, AlarmEvaluator())
            observation = await self._probe_workspace(
                workspace_id,
                now=observed_at,
                worker_quarantined=worker_quarantined,
                storage_percent=storage_percent,
                audit_chain_mismatch=audit_mismatch,
            )
            async with workspace_rls_session(self.session_factory, workspace_id=workspace_id) as db:
                await self._restore_active(db, evaluator)
            for alarm in evaluator.evaluate(observation, now=observed_at):
                await self._persist_transition(workspace_id, alarm, now=observed_at)
                transitions += 1
        return transitions

    async def run_forever(self) -> None:
        """Keep monitoring through transient DB faults without swallowing cancellation."""
        from red2pr_control.operations.runtime import shared_operation_lease

        while True:
            try:
                async with shared_operation_lease(self.session_factory) as state:
                    if not state.enabled:
                        await self.process_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                _LOGGER.exception("operations_alarm_iteration_failed")
            await asyncio.sleep(self.poll_interval)
