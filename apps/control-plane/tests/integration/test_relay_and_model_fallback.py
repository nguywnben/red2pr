from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

import pgserver
import pytest
from sqlalchemy import text

from red2pr_control.api.app import create_app
from red2pr_control.db.engine import (
    create_admin_engine,
    ensure_compatible_event_loop,
    run_alembic_downgrade,
    run_alembic_upgrade,
)
from red2pr_control.extensions.registry import list_capabilities

APP_ROLE_NAME = "red2pr_app"
APP_ROLE_PASSWORD = "red2pr_u29_test_only"


@dataclass(frozen=True)
class PostgresUrl:
    admin_url: str


@pytest.fixture(scope="module")
def postgres_url() -> Iterator[PostgresUrl]:
    ensure_compatible_event_loop()
    external_admin = os.environ.get("RED2PR_TEST_ADMIN_DATABASE_URL")
    if external_admin:
        run_alembic_downgrade(external_admin, "base", app_role_name=APP_ROLE_NAME)
        yield PostgresUrl(admin_url=external_admin)
        return

    with (
        tempfile.TemporaryDirectory(prefix="red2pr_u29_pg16_") as temp_dir,
        pgserver.get_server(temp_dir, cleanup_mode="delete") as server,
    ):
        parsed = urlparse(server.get_uri())
        admin_url = urlunparse(
            (
                "postgresql+psycopg",
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
        yield PostgresUrl(admin_url=admin_url)


def test_u29_routes_are_in_openapi_and_extensions_default_off() -> None:
    schema = create_app().openapi()

    assert "/api/v1/workspaces/{ws}/integrations/{connection_id}/relay" in schema["paths"]
    assert "/api/v1/workspaces/{ws}/repositories/{repository_id}/model-fallback" in schema["paths"]
    capabilities = schema["components"]["schemas"]["CapabilityInventoryResponse"]
    assert "capabilities" in capabilities["properties"]
    capability_states = {item.id: item.status for item in list_capabilities()}
    assert capability_states["src-05-relay"] == "disabled"
    assert capability_states["agt-04-model-fallback"] == "disabled"


@pytest.mark.asyncio
async def test_migration_0024_rls_schema_and_downgrade_are_reversible(
    postgres_url: PostgresUrl,
) -> None:
    run_alembic_upgrade(
        postgres_url.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
    admin_engine = create_admin_engine(postgres_url.admin_url)
    try:
        async with admin_engine.connect() as connection:
            revision = await connection.scalar(
                text("SELECT version_num FROM public.alembic_version")
            )
            assert revision == "0025_fleet_attestation_and_mcp"
            for table_name in ("relay_subscriptions", "model_fallback_policies"):
                rls_result = await connection.execute(
                    text(
                        "SELECT relrowsecurity, relforcerowsecurity "
                        "FROM pg_class WHERE relname = :table_name"
                    ),
                    {"table_name": table_name},
                )
                rls_enabled, rls_forced = rls_result.one()
                assert rls_enabled is True
                assert rls_forced is True
            policies = (
                await connection.execute(
                    text(
                        "SELECT c.relname, p.polname, pg_get_expr(p.polqual, p.polrelid) "
                        "FROM pg_policy AS p JOIN pg_class AS c ON c.oid = p.polrelid "
                        "WHERE c.relname IN ('relay_subscriptions', 'model_fallback_policies') "
                        "AND p.polname LIKE 'rls_%_select'"
                    )
                )
            ).all()
            policy_scopes = {(table, name): scope for table, name, scope in policies}
            assert (
                "instance_admin"
                in policy_scopes[("relay_subscriptions", "rls_relay_subscriptions_select")]
            )
            assert (
                "instance_admin"
                not in policy_scopes[
                    ("model_fallback_policies", "rls_model_fallback_policies_select")
                ]
            )
            relay_columns = (
                (
                    await connection.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_schema='public' AND table_name='relay_subscriptions'"
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert {"last_relay_seq", "relay_secret_ref", "consent_id"}.issubset(set(relay_columns))
            fallback_columns = (
                (
                    await connection.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_schema='public' AND table_name='model_fallback_policies'"
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert {
                "primary_model_profile_id",
                "secondary_model_profile_id",
                "consent_id",
            }.issubset(set(fallback_columns))
    finally:
        await admin_engine.dispose()

    run_alembic_downgrade(
        postgres_url.admin_url,
        "0023_extensions_and_oidc",
        app_role_name=APP_ROLE_NAME,
    )
    run_alembic_upgrade(
        postgres_url.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
