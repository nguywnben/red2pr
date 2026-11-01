"""U30 hardened fleet attestation and MCP extension boundary tests."""

from __future__ import annotations

import hashlib
import importlib.util
import secrets
import sys
from collections.abc import AsyncIterator, Iterator
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import pgserver
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from py_contracts.primitives import new_uuid7
from red2pr_control.api.app import create_app
from red2pr_control.db.base import (
    ApiTokenModel,
    AuditLogModel,
    BudgetAccountModel,
    CiRunModel,
    CiRunTriggerModel,
    McpApprovalIntentModel,
    MembershipModel,
    RepairSessionModel,
    RepoGrantModel,
    RepositoryModel,
)
from red2pr_control.db.engine import run_alembic_downgrade, run_alembic_upgrade
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.extensions.mcp_adapter import PROTOCOL_VERSION, _tool_definitions

_SUPPORT_PATH = Path(__file__).with_name("test_agents_and_state_machine.py")
_SPEC = importlib.util.spec_from_file_location("red2pr_u30_test_support", _SUPPORT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_SUPPORT = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SUPPORT
_SPEC.loader.exec_module(_SUPPORT)
ManualClock = _SUPPORT.ManualClock
_build_harness = _SUPPORT._build_u17_harness
_bootstrap = _SUPPORT._bootstrap_workspace_and_repo
_csrf_headers = _SUPPORT._csrf_headers


@pytest.fixture(scope="module")
def pg_urls() -> Iterator[object]:
    yield from _SUPPORT.pg_urls.__wrapped__()


@pytest.fixture
async def migrated_db(pg_urls: object) -> AsyncIterator[object]:
    async for result in _SUPPORT.migrated_db.__wrapped__(pg_urls):
        yield result


def test_mcp_is_disabled_by_default_with_canonical_problem() -> None:
    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/extensions/mcp",
            headers={"content-type": "application/json"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION},
            },
        )
    assert response.status_code == 409
    assert response.json()["code"] == "extension_disabled"


def test_mcp_enabled_endpoint_still_requires_scoped_a19_authentication() -> None:
    app = create_app()
    app.state.mcp_extension_enabled = True
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/extensions/mcp",
            headers={"content-type": "application/json"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION},
            },
        )
    assert response.status_code == 401


def test_mcp_tool_surface_matches_the_accepted_five_tool_contract() -> None:
    assert [tool["name"] for tool in _tool_definitions()] == [
        "get_repair_status",
        "get_diagnosis",
        "get_evidence_summary",
        "request_recheck",
        "create_web_approval_link",
    ]
    for tool in _tool_definitions():
        assert tool["inputSchema"]["additionalProperties"] is False


@pytest.mark.asyncio
async def test_mcp_a19_read_token_and_scope_denials(migrated_db: object, tmp_path: Path) -> None:
    clock = ManualClock()
    harness = _build_harness(migrated_db.app_url, clock=clock, store_dir=tmp_path / "mcp-artifacts")
    client, csrf, owner_id, workspace_id, repo_id = await _bootstrap(
        harness, clock=clock, ws_slug="u30-mcp-token"
    )
    harness.api_app.state.mcp_extension_enabled = True
    try:
        now = clock()
        trigger_id = new_uuid7(now=now)
        ci_run_id = new_uuid7(now=now)
        budget_id = new_uuid7(now=now)
        repair_id = new_uuid7(now=now)
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            repository = await db.scalar(
                select(RepositoryModel).where(
                    RepositoryModel.workspace_id == workspace_id,
                    RepositoryModel.id == repo_id,
                )
            )
            assert repository is not None
            connection_id = repository.provider_connection_id
            membership = await db.scalar(
                select(MembershipModel).where(
                    MembershipModel.workspace_id == workspace_id,
                    MembershipModel.user_id == owner_id,
                )
            )
            assert membership is not None
            db.add(
                RepoGrantModel(
                    id=new_uuid7(now=now),
                    workspace_id=workspace_id,
                    membership_id=membership.id,
                    repository_id=repo_id,
                    granted_by_user_id=owner_id,
                    created_at=now,
                )
            )
            db.add(
                CiRunTriggerModel(
                    id=trigger_id,
                    workspace_id=workspace_id,
                    connection_id=connection_id,
                    repository_id=repo_id,
                    provider="github",
                    provider_run_id="u30-mcp-run",
                    attempt_key="u30-mcp-attempt",
                    head_sha="d" * 40,
                    ref="refs/heads/main",
                    event_type="workflow_run",
                    first_source="webhook",
                    correlation_id="u30-mcp-trigger",
                    triggered_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )
            await db.flush()
            db.add(
                CiRunModel(
                    id=ci_run_id,
                    workspace_id=workspace_id,
                    repository_id=repo_id,
                    connection_id=connection_id,
                    trigger_id=trigger_id,
                    provider="github",
                    external_id="u30-mcp-run",
                    attempt_key="u30-mcp-attempt",
                    head_sha="d" * 40,
                    ref="refs/heads/main",
                    event_type="workflow_run",
                    created_at=now,
                    updated_at=now,
                )
            )
            db.add(
                BudgetAccountModel(
                    id=budget_id,
                    workspace_id=workspace_id,
                    scope_kind="workspace_total",
                    scope_key="u30-mcp-test",
                    cost_cap=Decimal("100"),
                    token_cap=100_000,
                    call_cap=1_000,
                    window_started_at=now,
                    window_ends_at=now + timedelta(days=1),
                )
            )
            await db.flush()
            db.add(
                RepairSessionModel(
                    id=repair_id,
                    workspace_id=workspace_id,
                    repository_id=repo_id,
                    ci_run_id=ci_run_id,
                    semantic_trigger_key="u30-mcp-repair",
                    base_sha="d" * 40,
                    target_ref="refs/heads/main",
                    policy_revision=1,
                    state="diagnosed_only",
                    proof_grade="none",
                    remote_status="not_published",
                    budget_account_id=budget_id,
                    correlation_id="u30-mcp-repair",
                    created_at=now,
                    updated_at=now,
                )
            )
            await db.flush()

        issued = await client.post(
            "/api/v1/workspaces/u30-mcp-token/api-tokens",
            headers=_csrf_headers(csrf),
            json={
                "name": "MCP read",
                "scopes": ["mcp:read"],
                "repository_ids": [repo_id],
                "expires_at": (clock() + timedelta(days=1)).isoformat(),
            },
        )
        assert issued.status_code == 201, issued.text
        raw_token = issued.json()["token"]
        token_id = issued.json()["metadata"]["id"]
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            persisted = await db.scalar(select(ApiTokenModel).where(ApiTokenModel.id == token_id))
            assert persisted is not None
            assert persisted.scopes_json == ["mcp:read"]

        headers = {
            "Authorization": f"Bearer {raw_token}",
            "Content-Type": "application/json",
        }
        initialized = await client.post(
            "/api/v1/extensions/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION},
            },
        )
        assert initialized.status_code == 200, initialized.text
        assert initialized.json()["result"]["protocolVersion"] == PROTOCOL_VERSION

        cross_origin = await client.post(
            "/api/v1/extensions/mcp",
            headers={**headers, "Origin": "https://attacker.invalid"},
            json={"jsonrpc": "2.0", "id": 9, "method": "ping"},
        )
        assert cross_origin.status_code == 403
        assert cross_origin.json()["code"] == "csrf_origin_denied"

        listed = await client.post(
            "/api/v1/extensions/mcp",
            headers={**headers, "MCP-Protocol-Version": PROTOCOL_VERSION},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
        assert listed.status_code == 200, listed.text
        assert [tool["name"] for tool in listed.json()["result"]["tools"]] == [
            tool["name"] for tool in _tool_definitions()
        ]

        for tool_name in (
            "get_repair_status",
            "get_diagnosis",
            "get_evidence_summary",
        ):
            read_result = await client.post(
                "/api/v1/extensions/mcp",
                headers={**headers, "MCP-Protocol-Version": PROTOCOL_VERSION},
                json={
                    "jsonrpc": "2.0",
                    "id": tool_name,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": {"repair_id": repair_id}},
                },
            )
            assert read_result.status_code == 200, read_result.text
            assert read_result.json()["result"]["isError"] is False

        write_token_response = await client.post(
            "/api/v1/workspaces/u30-mcp-token/api-tokens",
            headers=_csrf_headers(csrf),
            json={
                "name": "MCP intent",
                "scopes": ["mcp:read", "mcp:intent:create"],
                "repository_ids": [repo_id],
                "expires_at": (clock() + timedelta(days=1)).isoformat(),
            },
        )
        assert write_token_response.status_code == 201, write_token_response.text
        write_headers = {
            "Authorization": f"Bearer {write_token_response.json()['token']}",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
        }
        intent_call = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "request_recheck",
                "arguments": {
                    "repair_id": repair_id,
                    "reason": "retry after owner review",
                    "idempotency_key": "u30-positive-recheck-1",
                },
            },
        }
        intent_response = await client.post(
            "/api/v1/extensions/mcp", headers=write_headers, json=intent_call
        )
        assert intent_response.status_code == 200, intent_response.text
        intent = intent_response.json()["result"]["structuredContent"]
        assert intent["state"] == "pending"
        replay_response = await client.post(
            "/api/v1/extensions/mcp", headers=write_headers, json=intent_call
        )
        assert replay_response.status_code == 200, replay_response.text
        assert (
            replay_response.json()["result"]["structuredContent"]["approval_intent_id"]
            == (intent["approval_intent_id"])
        )

        link_response = await client.post(
            "/api/v1/extensions/mcp",
            headers=write_headers,
            json={
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "create_web_approval_link",
                    "arguments": {"approval_intent_id": intent["approval_intent_id"]},
                },
            },
        )
        assert link_response.status_code == 200, link_response.text
        approval_url = link_response.json()["result"]["structuredContent"]["approval_url"]
        raw_approval_token = approval_url.partition("#")[2]
        assert len(raw_approval_token) == 43
        assert f"workspace_id={workspace_id}" in approval_url
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            stored_intent = await db.scalar(
                select(McpApprovalIntentModel).where(
                    McpApprovalIntentModel.id == intent["approval_intent_id"]
                )
            )
            assert stored_intent is not None
            assert (
                stored_intent.token_hash
                == hashlib.sha256(raw_approval_token.encode("ascii")).hexdigest()
            )

        preview = await client.post(
            "/api/v1/extensions/mcp/approval/preview",
            json={"token": raw_approval_token, "workspace_id": workspace_id},
        )
        assert preview.status_code == 200, preview.text
        assert preview.json()["intent_id"] == intent["approval_intent_id"]
        confirmed = await client.post(
            "/api/v1/extensions/mcp/approval/confirm",
            headers=_csrf_headers(csrf),
            json={"token": raw_approval_token, "workspace_id": workspace_id},
        )
        assert confirmed.status_code == 200, confirmed.text
        assert confirmed.json()["state"] == "consumed"
        replay_confirm = await client.post(
            "/api/v1/extensions/mcp/approval/confirm",
            headers=_csrf_headers(csrf),
            json={"token": raw_approval_token, "workspace_id": workspace_id},
        )
        assert replay_confirm.status_code == 409

        invalid_args = await client.post(
            "/api/v1/extensions/mcp",
            headers={**headers, "MCP-Protocol-Version": PROTOCOL_VERSION},
            json={
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": "get_repair_status", "arguments": {"unexpected": "x"}},
            },
        )
        assert invalid_args.status_code == 200
        assert invalid_args.json()["error"]["code"] == -32602
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            audit = await db.scalar(
                select(AuditLogModel)
                .where(AuditLogModel.action == "mcp.tool.get_repair_status")
                .order_by(AuditLogModel.seq.desc())
                .limit(1)
            )
            assert audit is not None
            assert audit.decision == "deny"
            assert audit.correlation_id

        mutation = await client.post(
            "/api/v1/extensions/mcp",
            headers={**headers, "MCP-Protocol-Version": PROTOCOL_VERSION},
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "request_recheck",
                    "arguments": {
                        "repair_id": "0196f000-0000-7000-8000-000000000001",
                        "reason": "retry after repair",
                        "idempotency_key": "mcp-test-key-1",
                    },
                },
            },
        )
        assert mutation.status_code == 403
        assert mutation.json()["code"] == "api_token_scope_denied"
    finally:
        await client.aclose()
        await harness.app_engine.dispose()


@pytest.fixture
def migration_database(tmp_path: Path) -> Iterator[str]:
    directory = str(tmp_path / "u30-postgres")
    with pgserver.get_server(directory, cleanup_mode="delete") as server:
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
        yield admin_url


def test_migration_0025_round_trips_from_0024(migration_database: str) -> None:
    app_role = "red2pr_app"
    password = secrets.token_urlsafe(32)
    run_alembic_downgrade(migration_database, "base", app_role_name=app_role)
    run_alembic_upgrade(
        migration_database,
        "head",
        app_role_name=app_role,
        app_role_password=password,
    )
    run_alembic_downgrade(
        migration_database,
        "0024_relay_and_model_fallback",
        app_role_name=app_role,
    )
    run_alembic_upgrade(
        migration_database,
        "head",
        app_role_name=app_role,
        app_role_password=password,
    )
