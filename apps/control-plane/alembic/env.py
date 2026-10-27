"""Alembic migration environment for Red2PR control-plane (PostgreSQL 16 + psycopg v3).

Uses synchronous psycopg v3 connections (`NullPool`) during DDL migrations so programmatic
migrations execute deterministically both inside and outside active asyncio event loops.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from red2pr_control.db.base import Base
from red2pr_control.db.engine import normalize_psycopg_url

config = context.config

if config.config_file_name is not None and config.attributes.get("configure_logging", False):
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _resolve_migration_url() -> str:
    attr_url = config.attributes.get("sqlalchemy_url")
    if isinstance(attr_url, str) and attr_url.strip():
        return normalize_psycopg_url(attr_url)
    env_url = os.environ.get("RED2PR_ADMIN_DATABASE_URL")
    if env_url and env_url.strip():
        return normalize_psycopg_url(env_url)
    ini_url = config.get_main_option("sqlalchemy.url")
    if not ini_url:
        raise RuntimeError("No PostgreSQL migration URL configured for Alembic.")
    return normalize_psycopg_url(ini_url)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' SQL-generation mode."""
    url = _resolve_migration_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' DDL transaction mode."""
    url = _resolve_migration_url()
    connectable = create_engine(
        url,
        poolclass=pool.NullPool,
        future=True,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            transaction_per_migration=True,
        )

        with context.begin_transaction():
            context.run_migrations()

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
