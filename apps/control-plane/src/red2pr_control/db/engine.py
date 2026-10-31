"""Async SQLAlchemy 2.0 PostgreSQL engine, durability probes, and Alembic runner.

Implements:
- Windows SelectorEventLoop compatibility helper for psycopg v3 async.
- Runtime app engine with mandatory RLS pool guards vs migration-only admin engine.
- PostgreSQL >= 16 and fsync = on durability checks (NFR-01).
- Non-superuser / non-BYPASSRLS runtime role enforcement (SEC-032).
- Programmatic Alembic upgrade/downgrade runner for CLI, setup wizard, and tests.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from red2pr_control.core.errors import DependencyUnavailableError
from red2pr_control.db.rls import RlsConfigurationError, install_rls_pool_guards

MIN_POSTGRES_VERSION_NUM: int = 160_000


def ensure_compatible_event_loop() -> None:
    """Configure SelectorEventLoopPolicy on Windows required by psycopg v3 async."""
    if sys.platform == "win32":
        policy = asyncio.get_event_loop_policy()
        if not isinstance(policy, asyncio.WindowsSelectorEventLoopPolicy):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def normalize_psycopg_url(database_url: str) -> str:
    """Normalize PostgreSQL DSN to SQLAlchemy psycopg v3 dialect URL."""
    stripped = database_url.strip()
    if stripped.startswith("postgresql+psycopg://"):
        return stripped
    if stripped.startswith("postgresql://"):
        return "postgresql+psycopg://" + stripped[len("postgresql://") :]
    if stripped.startswith("postgres://"):
        return "postgresql+psycopg://" + stripped[len("postgres://") :]
    raise ValueError("Database URL must use postgresql:// or postgresql+psycopg:// scheme")


def create_admin_engine(database_url: str) -> AsyncEngine:
    """Create unpooled migration/maintenance AsyncEngine (never used for tenant requests)."""
    ensure_compatible_event_loop()
    return create_async_engine(
        normalize_psycopg_url(database_url),
        poolclass=NullPool,
        future=True,
    )


def create_app_engine(
    database_url: str,
    *,
    pool_size: int = 5,
    max_overflow: int = 10,
    pool_timeout: float = 30.0,
) -> AsyncEngine:
    """Create pooled control-plane AsyncEngine protected by RLS pool reset guards."""
    ensure_compatible_event_loop()
    engine = create_async_engine(
        normalize_psycopg_url(database_url),
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
        pool_pre_ping=True,
        future=True,
    )
    install_rls_pool_guards(engine)
    return engine


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create strict AsyncSession factory with expire_on_commit=False."""
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


async def assert_postgres_16_and_durability(
    session: AsyncSession,
    *,
    require_fsync: bool = True,
) -> dict[str, str]:
    """Verify PostgreSQL >= 16 and fsync durability before accepting mutations (NFR-01)."""
    row = (
        await session.execute(
            text(
                "SELECT current_setting('server_version_num'), "
                "current_setting('server_version'), "
                "current_setting('fsync'), "
                "current_setting('synchronous_commit')"
            )
        )
    ).one()
    version_num_str = str(row[0])
    server_version = str(row[1])
    fsync_val = str(row[2]).lower()
    sync_commit_val = str(row[3]).lower()

    if int(version_num_str) < MIN_POSTGRES_VERSION_NUM:
        raise DependencyUnavailableError(
            code="unsupported_postgres_version",
            detail=(
                f"PostgreSQL 16+ is required; connected server reported version {server_version}."
            ),
        )
    if require_fsync and fsync_val != "on":
        raise DependencyUnavailableError(
            code="postgres_fsync_disabled",
            detail="PostgreSQL fsync must be enabled ('on') to satisfy NFR-01 durability.",
        )
    return {
        "server_version_num": version_num_str,
        "server_version": server_version,
        "fsync": fsync_val,
        "synchronous_commit": sync_commit_val,
    }


async def assert_non_bypassrls_role(session: AsyncSession) -> str:
    """Refuse runtime operation if the connected DB role has SUPERUSER or BYPASSRLS (SEC-032)."""
    row = (
        await session.execute(
            text(
                "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
            )
        )
    ).one_or_none()
    if row is None:
        raise RlsConfigurationError(
            code="rls_role_unknown",
            detail="Unable to inspect current_user privileges in pg_roles.",
        )
    rolname = str(row[0])
    rolsuper = bool(row[1])
    rolbypassrls = bool(row[2])
    if rolsuper or rolbypassrls:
        raise RlsConfigurationError(
            code="rls_bypass_role_forbidden",
            detail=(
                f"Runtime application database role {rolname!r} has "
                f"rolsuper={rolsuper}, rolbypassrls={rolbypassrls}; "
                "control-plane traffic must run under a non-superuser, non-BYPASSRLS role."
            ),
        )
    return rolname


def _build_alembic_config(
    admin_database_url: str,
    *,
    app_role_name: str,
    app_role_password: str | None = None,
) -> AlembicConfig:
    control_plane_root = Path(__file__).resolve().parents[3]
    ini_path = control_plane_root / "alembic.ini"
    normalized_url = normalize_psycopg_url(admin_database_url)
    cfg = AlembicConfig(str(ini_path))
    cfg.set_main_option("script_location", str(control_plane_root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", normalized_url.replace("%", "%%"))
    cfg.attributes["sqlalchemy_url"] = normalized_url
    cfg.attributes["red2pr_app_role_name"] = app_role_name
    if app_role_password is not None:
        cfg.attributes["red2pr_app_role_password"] = app_role_password
    return cfg


def run_alembic_upgrade(
    admin_database_url: str,
    revision: str = "head",
    *,
    app_role_name: str = "red2pr_app",
    app_role_password: str | None = None,
) -> None:
    """Apply Alembic schema migrations up to target revision."""
    cfg = _build_alembic_config(
        admin_database_url,
        app_role_name=app_role_name,
        app_role_password=app_role_password,
    )
    command.upgrade(cfg, revision)


def run_alembic_downgrade(
    admin_database_url: str,
    revision: str = "base",
    *,
    app_role_name: str = "red2pr_app",
) -> None:
    """Revert reversible expand-phase Alembic schema migrations down to target revision."""
    cfg = _build_alembic_config(
        admin_database_url,
        app_role_name=app_role_name,
    )
    command.downgrade(cfg, revision)
