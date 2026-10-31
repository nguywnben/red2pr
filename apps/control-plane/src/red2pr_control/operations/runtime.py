"""Cross-process write fencing for system maintenance and recovery (U26)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from weakref import WeakKeyDictionary

from fastapi import Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

SYSTEM_RECOVERY_LOCK = 1_328_921_027
_LOCK_ENGINES: WeakKeyDictionary[AsyncEngine, AsyncEngine] = WeakKeyDictionary()


@dataclass(frozen=True, slots=True)
class MaintenanceState:
    enabled: bool
    reason: str | None


def _engine(session_factory: async_sessionmaker[AsyncSession]) -> AsyncEngine:
    bind = session_factory.kw.get("bind")
    if not isinstance(bind, AsyncEngine):
        raise RuntimeError("system_database_unavailable")
    return bind


def _lock_engine(session_factory: async_sessionmaker[AsyncSession]) -> AsyncEngine:
    """Use a stable database for cluster fencing so the target DB can be renamed safely."""
    app_engine = _engine(session_factory)
    if app_engine.dialect.name != "postgresql":
        raise RuntimeError("system_postgres_required")
    lock_engine = _LOCK_ENGINES.get(app_engine)
    if lock_engine is None:
        lock_engine = create_async_engine(
            app_engine.url.set(database="postgres"),
            pool_size=2,
            max_overflow=2,
            pool_pre_ping=True,
        )
        _LOCK_ENGINES[app_engine] = lock_engine
    return lock_engine


async def dispose_operation_lock_engine(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Release the stable-database pool when the application shuts down."""
    app_engine = _engine(session_factory)
    lock_engine = _LOCK_ENGINES.pop(app_engine, None)
    if lock_engine is not None:
        await lock_engine.dispose()


async def _read_maintenance(connection: AsyncConnection) -> MaintenanceState:
    await connection.execute(
        text(
            "SELECT set_config('red2pr.scope_mode','instance_only',true), "
            "set_config('red2pr.workspace_id','',true)"
        )
    )
    row = (
        await connection.execute(
            text(
                "SELECT maintenance_enabled, maintenance_reason "
                "FROM public.instances ORDER BY id LIMIT 1"
            )
        )
    ).one_or_none()
    if row is None:
        return MaintenanceState(False, None)
    return MaintenanceState(bool(row[0]), str(row[1]) if row[1] is not None else None)


@asynccontextmanager
async def shared_operation_lease(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[MaintenanceState]:
    """Fence one API/background write against a cluster-wide restore's exclusive lock."""
    app_engine = _engine(session_factory)
    async with _lock_engine(session_factory).connect() as connection:
        try:
            await connection.execute(
                text("SELECT pg_advisory_lock_shared(:lock_id)"),
                {"lock_id": SYSTEM_RECOVERY_LOCK},
            )
            async with app_engine.connect() as state_connection:
                state = await _read_maintenance(state_connection)
            yield state
        finally:
            try:
                await connection.execute(
                    text("SELECT pg_advisory_unlock_shared(:lock_id)"),
                    {"lock_id": SYSTEM_RECOVERY_LOCK},
                )
            finally:
                await connection.rollback()


@asynccontextmanager
async def exclusive_recovery_lease(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[MaintenanceState]:
    """Stop cross-process API writes and background effects until recovery completes."""
    app_engine = _engine(session_factory)
    async with _lock_engine(session_factory).connect() as connection:
        try:
            await connection.execute(
                text("SELECT pg_advisory_lock(:lock_id)"),
                {"lock_id": SYSTEM_RECOVERY_LOCK},
            )
            async with app_engine.connect() as state_connection:
                state = await _read_maintenance(state_connection)
            yield state
        finally:
            try:
                await connection.execute(
                    text("SELECT pg_advisory_unlock(:lock_id)"),
                    {"lock_id": SYSTEM_RECOVERY_LOCK},
                )
            finally:
                await connection.rollback()


async def maintenance_for_request(request: Request) -> MaintenanceState:
    iam = getattr(request.app.state, "iam_service", None)
    if iam is None:
        return MaintenanceState(False, None)
    engine = _engine(iam.session_factory)
    async with engine.connect() as connection:
        return await _read_maintenance(connection)
