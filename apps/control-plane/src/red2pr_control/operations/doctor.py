"""Read-only, bounded instance diagnostics for U26."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.operations import DoctorResponse, SystemCheck
from red2pr_control.db.base import InstanceModel
from red2pr_control.db.rls import instance_rls_session


async def build_doctor_response(
    session_factory: async_sessionmaker[AsyncSession],
) -> DoctorResponse:
    """Run fixed, non-mutating diagnostics; never include DSNs, paths or secret values."""
    checks: list[SystemCheck] = []
    async with instance_rls_session(session_factory, mode="instance_only") as db:
        try:
            db_version = str((await db.execute(text("SHOW server_version_num"))).scalar_one())
            checks.append(
                SystemCheck(
                    check_id="database",
                    state="ok",
                    summary=f"PostgreSQL {db_version} is reachable.",
                )
            )
        except Exception:
            checks.append(
                SystemCheck(
                    check_id="database", state="failed", summary="Database health check failed."
                )
            )
            return DoctorResponse(
                generated_at=datetime.now(UTC), overall_state="failed", checks=tuple(checks)
            )
        instance = await db.scalar(select(InstanceModel).limit(1))
        if instance is None:
            checks.append(
                SystemCheck(
                    check_id="instance_state",
                    state="failed",
                    summary="Instance state is not initialized.",
                )
            )
        elif instance.maintenance_enabled:
            checks.append(
                SystemCheck(
                    check_id="maintenance", state="warning", summary="Maintenance mode is enabled."
                )
            )
        else:
            checks.append(
                SystemCheck(
                    check_id="maintenance", state="ok", summary="Maintenance mode is disabled."
                )
            )
        migrations = list(
            (
                await db.execute(
                    text("SELECT revision FROM public.schema_migrations ORDER BY revision")
                )
            ).scalars()
        )
        checks.append(
            SystemCheck(
                check_id="schema_migrations",
                state="ok" if migrations else "failed",
                summary=f"{len(migrations)} migration records are available.",
            )
        )
        state: Literal["healthy", "degraded", "failed"] = (
            "failed"
            if any(c.state == "failed" for c in checks)
            else "degraded"
            if any(c.state in {"warning", "blocked"} for c in checks)
            else "healthy"
        )
    return DoctorResponse(generated_at=datetime.now(UTC), overall_state=state, checks=tuple(checks))
