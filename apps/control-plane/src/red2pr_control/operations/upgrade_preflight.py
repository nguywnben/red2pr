"""Conservative schema/worker compatibility preflight for U26."""

from __future__ import annotations

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.operations import UpgradePreflightRequest, UpgradePreflightResponse
from red2pr_control.db.base import (
    InstanceModel,
    OperationReceiptModel,
    WorkerModel,
)
from red2pr_control.db.rls import instance_rls_session

_SUPPORTED_SCHEMA_REVISIONS = frozenset(
    {"0021_retention_jobs_and_exceptions", "0022_backups_migrations_ops"}
)


def schema_revision_compatible(current_revision: str, target_revision: str) -> bool:
    """Permit the current schema or its adjacent U26 N/N-1 revision only."""
    return (
        current_revision == target_revision and current_revision in _SUPPORTED_SCHEMA_REVISIONS
    ) or {current_revision, target_revision} == _SUPPORTED_SCHEMA_REVISIONS


def worker_protocol_compatible(protocol_versions: object, target_protocols: frozenset[str]) -> bool:
    """Missing or malformed protocol inventory blocks upgrades closed."""
    if not isinstance(protocol_versions, list) or not protocol_versions:
        return False
    declared = {item for item in protocol_versions if isinstance(item, str) and item}
    return bool(declared.intersection(target_protocols))


async def run_upgrade_preflight(
    session_factory: async_sessionmaker[AsyncSession],
    request: UpgradePreflightRequest,
    *,
    current_version: str,
) -> UpgradePreflightResponse:
    async with instance_rls_session(session_factory, mode="instance_admin") as db:
        instance = await db.scalar(select(InstanceModel).with_for_update())
        if instance is None:
            return UpgradePreflightResponse(
                compatible=False,
                current_version=current_version,
                target_version=request.target_version,
                current_schema_revision="uninitialized",
                target_schema_revision=request.target_schema_revision,
                pending_effects=0,
                required_actions=("initialize_instance_state",),
            )
        current_revision = str(
            (
                await db.execute(text("SELECT version_num FROM public.alembic_version LIMIT 1"))
            ).scalar_one_or_none()
            or "uninitialized"
        )
        incompatible: list[str] = []
        for worker in await db.scalars(
            select(WorkerModel).where(WorkerModel.status.in_(["online", "draining"]))
        ):
            if not worker_protocol_compatible(
                worker.protocol_versions_json,
                frozenset(request.target_worker_protocols),
            ):
                incompatible.append(worker.id)
        pending = int(
            await db.scalar(
                select(func.count())
                .select_from(OperationReceiptModel)
                .where(
                    OperationReceiptModel.scope == "instance",
                    OperationReceiptModel.state.in_(["accepted", "running", "unknown"]),
                )
            )
            or 0
        )
        compatible_schema = schema_revision_compatible(
            current_revision, request.target_schema_revision
        )
        compatible = compatible_schema and not incompatible and pending == 0
        actions = []
        if incompatible:
            actions.append("drain_or_upgrade_workers")
        if pending:
            actions.append("reconcile_pending_operations")
        if not compatible_schema:
            actions.append("install_compatible_schema_migration")
        return UpgradePreflightResponse(
            compatible=compatible,
            current_version=current_version,
            target_version=request.target_version,
            current_schema_revision=current_revision,
            target_schema_revision=request.target_schema_revision,
            incompatible_workers=tuple(sorted(incompatible)),
            pending_effects=pending,
            required_actions=tuple(actions),
        )
