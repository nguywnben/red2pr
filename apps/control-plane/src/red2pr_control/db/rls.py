"""PostgreSQL Row-Level Security (RLS) transaction context & pool reset guards (SEC-032).

Enforces defense-in-depth multi-workspace isolation (ADR-030, ADR-035):
- Every workspace transaction sets transaction-local `red2pr.scope_mode = 'workspace'`
  and `red2pr.workspace_id = <validated-uuid>` via `set_config(..., is_local=true)`.
- Non-tenant background/system paths explicitly opt into narrow modes
  (`instance_only`, `instance_admin`, or `audit_verifier`).
- Connection pool `reset` / `checkout` listeners unconditionally roll back uncommitted
  work and commit `RESET red2pr.workspace_id; RESET red2pr.scope_mode;` so even a
  rogue session-level `set_config(..., false)` can never leak across pooled checkouts.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import Any, Literal

from pydantic import TypeAdapter, ValidationError
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from py_contracts.primitives import InternalId
from red2pr_control.core.errors import BadRequestError, Red2PrError

RlsScopeMode = Literal["workspace", "instance_only", "instance_admin", "audit_verifier"]
InstanceScopeMode = Literal["instance_only", "instance_admin", "audit_verifier"]

_INTERNAL_ID_ADAPTER: TypeAdapter[str] = TypeAdapter(InternalId)


class RlsConfigurationError(Red2PrError):
    """Fatal database role or RLS boundary misconfiguration error (SEC-032)."""

    def __init__(self, *, code: str = "rls_misconfigured", detail: str) -> None:
        super().__init__(
            code=code,
            title="Database isolation misconfiguration",
            detail=detail,
            status=503,
        )


def _validate_workspace_id(workspace_id: str) -> str:
    try:
        return _INTERNAL_ID_ADAPTER.validate_python(workspace_id)
    except ValidationError as exc:
        raise BadRequestError(
            code="invalid_workspace_id",
            detail="Workspace identifier must be a canonical lowercase UUID string.",
        ) from exc


def _scrub_dbapi_rls_gucs(dbapi_connection: Any) -> None:
    """Clear any session-level RLS GUC state and leave the pooled connection clean & IDLE."""
    try:
        dbapi_connection.rollback()
    except Exception:
        return

    cursor = None
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("RESET red2pr.workspace_id; RESET red2pr.scope_mode")
        dbapi_connection.commit()
    except Exception:
        try:
            dbapi_connection.rollback()
        except Exception:
            return
    finally:
        if cursor is not None:
            with suppress(Exception):
                cursor.close()


def install_rls_pool_guards(engine: AsyncEngine) -> None:
    """Attach pool reset & checkout guards preventing session GUC leakage (SEC-032)."""

    @event.listens_for(engine.sync_engine, "reset")
    def _on_pool_reset(dbapi_connection: Any, _connection_record: Any, _reset_state: Any) -> None:
        _scrub_dbapi_rls_gucs(dbapi_connection)

    @event.listens_for(engine.sync_engine, "checkout")
    def _on_pool_checkout(
        dbapi_connection: Any,
        _connection_record: Any,
        _connection_proxy: Any,
    ) -> None:
        _scrub_dbapi_rls_gucs(dbapi_connection)


@asynccontextmanager
async def workspace_rls_session(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    workspace_id: str,
) -> AsyncIterator[AsyncSession]:
    """Execute a unit-of-work strictly scoped to a single workspace via `SET LOCAL`."""
    validated_ws = _validate_workspace_id(workspace_id)
    async with session_factory() as session, session.begin():
        await session.execute(
            text(
                "SELECT set_config('red2pr.scope_mode', 'workspace', true), "
                "set_config('red2pr.workspace_id', :ws_id, true)"
            ),
            {"ws_id": validated_ws},
        )
        yield session


@asynccontextmanager
async def instance_rls_session(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    mode: InstanceScopeMode = "instance_only",
) -> AsyncIterator[AsyncSession]:
    """Execute an explicitly scoped non-tenant transaction (instance or audit verifier)."""
    if mode not in {"instance_only", "instance_admin", "audit_verifier"}:
        raise RlsConfigurationError(
            code="invalid_rls_scope_mode",
            detail=f"Unsupported instance RLS scope mode: {mode!r}",
        )
    async with session_factory() as session, session.begin():
        await session.execute(
            text(
                "SELECT set_config('red2pr.scope_mode', :mode, true), "
                "set_config('red2pr.workspace_id', '', true)"
            ),
            {"mode": mode},
        )
        yield session
