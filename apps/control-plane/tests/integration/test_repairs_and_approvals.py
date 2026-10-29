"""U19 repair/evidence/approval API integration and negative authorization tests."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import AsyncIterator, Iterator
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select

from py_contracts.primitives import new_uuid7
from red2pr_control.approvals.service import ApprovalService
from red2pr_control.db.base import (
    ApprovalRequestModel,
    ApprovalVoteModel,
    BudgetAccountModel,
    PatchAttemptModel,
    RepositoryPolicyModel,
)
from red2pr_control.db.rls import workspace_rls_session

_U17_PATH = Path(__file__).with_name("test_agents_and_state_machine.py")
_U17_SPEC = importlib.util.spec_from_file_location("red2pr_u17_test_support", _U17_PATH)
assert _U17_SPEC is not None and _U17_SPEC.loader is not None
_U17 = importlib.util.module_from_spec(_U17_SPEC)
sys.modules[_U17_SPEC.name] = _U17
_U17_SPEC.loader.exec_module(_U17)

ManualClock = _U17.ManualClock
_bootstrap_workspace_and_repo = _U17._bootstrap_workspace_and_repo
_build_u17_harness = _U17._build_u17_harness
_create_repair_session_with_budget = _U17._create_repair_session_with_budget
_seed_ci_run_job_and_log_artifact = _U17._seed_ci_run_job_and_log_artifact
_csrf_headers = _U17._csrf_headers


@pytest.fixture(scope="module")
def pg_urls() -> Iterator[Any]:
    yield from _U17.pg_urls.__wrapped__()


@pytest.fixture
async def migrated_db(pg_urls: Any) -> AsyncIterator[Any]:
    async for result in _U17.migrated_db.__wrapped__(pg_urls):
        yield result


@pytest.mark.asyncio
async def test_u19_repair_and_approval_reads_are_workspace_scoped(migrated_db, tmp_path):
    clock = ManualClock()
    harness = _build_u17_harness(
        migrated_db.app_url,
        clock=clock,
        store_dir=tmp_path / "artifacts",
    )
    client, csrf, owner_id, workspace_id, repo_id = await _bootstrap_workspace_and_repo(
        harness,
        clock=clock,
        ws_slug="u19-scope",
    )
    try:
        run_id, _job_id, _artifact_id, _fingerprint = await _seed_ci_run_job_and_log_artifact(
            harness,
            workspace_id=workspace_id,
            repository_id=repo_id,
            head_sha="a" * 40,
            job_name="pytest",
            ci_failure_log=(
                "FAILED tests/test_sample.py::test_sample - AssertionError: expected 1 got 2"
            ),
            now=clock(),
        )
        repair_id, _budget_id = await _create_repair_session_with_budget(
            harness,
            workspace_id=workspace_id,
            repository_id=repo_id,
            ci_run_id=run_id,
            base_sha="a" * 40,
            semantic_key="u19-positive",
            now=clock(),
        )
        repairs = await client.get("/api/v1/workspaces/u19-scope/repairs")
        approvals = await client.get("/api/v1/workspaces/u19-scope/approvals")
        assert repairs.status_code == 200, repairs.text
        assert [item["id"] for item in repairs.json()["items"]] == [repair_id]
        assert repairs.json()["snapshot_at"]
        detail = await client.get(f"/api/v1/workspaces/u19-scope/repairs/{repair_id}")
        assert detail.status_code == 200, detail.text
        assert detail.json()["run_id"] == run_id
        timeline = await client.get(f"/api/v1/workspaces/u19-scope/repairs/{repair_id}/timeline")
        assert timeline.status_code == 200, timeline.text
        assert timeline.json()["items"]
        action_key = new_uuid7(now=clock())
        action_payload = {
            "action": "pause",
            "reason": "Pause for operator review",
            "expected_version": detail.json()["version"],
        }
        action_headers = _csrf_headers(csrf, extra={"Idempotency-Key": action_key})
        paused = await client.post(
            f"/api/v1/workspaces/u19-scope/repairs/{repair_id}/actions",
            headers=action_headers,
            json=action_payload,
        )
        assert paused.status_code == 200, paused.text
        replayed_action = await client.post(
            f"/api/v1/workspaces/u19-scope/repairs/{repair_id}/actions",
            headers=action_headers,
            json=action_payload,
        )
        assert replayed_action.status_code == 200, replayed_action.text
        assert replayed_action.json() == paused.json()
        after_replay = await client.get(f"/api/v1/workspaces/u19-scope/repairs/{repair_id}")
        assert after_replay.json()["version"] == detail.json()["version"] + 1
        malformed_cursor = await client.get(
            "/api/v1/workspaces/u19-scope/repairs?cursor=abc.invalid"
        )
        assert malformed_cursor.status_code == 400
        assert approvals.status_code == 200, approvals.text
        assert approvals.json()["items"] == []
        approval_id = new_uuid7(now=clock())
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            db.add(
                ApprovalRequestModel(
                    id=approval_id,
                    workspace_id=workspace_id,
                    repository_id=repo_id,
                    repair_id=repair_id,
                    intent_type="publish_draft_pr",
                    patch_digest="c" * 64,
                    base_sha="a" * 40,
                    target_ref="refs/heads/main",
                    policy_revision=1,
                    requested_by=owner_id,
                    risk_level="review",
                    scope_description="U19 step-up negative case",
                    sensitive_change=False,
                    expires_at=clock() + timedelta(hours=1),
                    status="pending",
                    correlation_id="corr-u19-approval-test",
                    created_at=clock(),
                )
            )
        step_up_required = await client.post(
            f"/api/v1/workspaces/u19-scope/approvals/{approval_id}/decisions",
            headers=_csrf_headers(csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={
                "decision": "approve",
                "reason": None,
                "expected_patch_digest": "c" * 64,
                "expected_policy_revision": 1,
            },
        )
        assert step_up_required.status_code == 403, step_up_required.text
        assert step_up_required.json()["code"] == "step_up_required"
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            votes = await db.scalar(
                select(func.count())
                .select_from(ApprovalVoteModel)
                .where(
                    ApprovalVoteModel.workspace_id == workspace_id,
                    ApprovalVoteModel.approval_request_id == approval_id,
                )
            )
            assert votes == 0
            db.add(
                RepositoryPolicyModel(
                    id=new_uuid7(now=clock()),
                    workspace_id=workspace_id,
                    repository_id=repo_id,
                    revision=1,
                    mode="approval",
                    paused=False,
                    branch_allowlist_json=["refs/heads/main"],
                    branch_denylist_json=[],
                    file_allowlist_json=[],
                    file_denylist_json=[],
                    sensitive_rules_json=[],
                    allow_test_edits=False,
                    allow_config_edits=False,
                    max_attempts=2,
                    max_diff_lines=500,
                    require_baseline=True,
                    runtime_profile_id="default-isolated",
                    created_by_user_id=owner_id,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
            db.add(
                PatchAttemptModel(
                    id=new_uuid7(now=clock()),
                    workspace_id=workspace_id,
                    repository_id=repo_id,
                    repair_id=repair_id,
                    attempt_number=1,
                    base_sha="a" * 40,
                    patch_digest="c" * 64,
                    diff_artifact_id=_artifact_id,
                    changed_paths_json=["src/sample.py"],
                    diff_lines_added=1,
                    diff_lines_removed=1,
                    claimed_root_cause="U19 approval binding fixture",
                    target_test_selection_id=None,
                    integrity_outcome="accepted",
                    sandbox_reproduction_id=None,
                    provenance_json=[],
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )

        approval_service = ApprovalService(session_factory=harness.app_factory)
        decision_key = new_uuid7(now=clock())
        approved = await approval_service.decide(
            workspace_id=workspace_id,
            approval_id=approval_id,
            actor_id=owner_id,
            decision="approve",
            reason="U19 positive approval service case",
            expected_patch_digest="c" * 64,
            expected_policy_revision=1,
            idempotency_key=decision_key,
            correlation_id="corr-u19-approval-positive",
            now=clock(),
        )
        assert approved.status == "approved"
        assert approved.decision == "approve"
        replayed_decision = await approval_service.decide(
            workspace_id=workspace_id,
            approval_id=approval_id,
            actor_id=owner_id,
            decision="approve",
            reason="U19 positive approval service case",
            expected_patch_digest="c" * 64,
            expected_policy_revision=1,
            idempotency_key=decision_key,
            correlation_id="corr-u19-approval-positive-replay",
            now=clock(),
        )
        assert replayed_decision.id == approved.id
        assert replayed_decision.version == approved.version

        wrong_workspace = await client.get(f"/api/v1/workspaces/u19-scope/repairs/{workspace_id}")
        assert wrong_workspace.status_code == 404

        csrf_failure = await client.post(
            "/api/v1/workspaces/u19-scope/repairs",
            json={
                "run_id": "11111111-1111-4111-8111-111111111111",
                "mode": "approval",
                "reason": "manual",
            },
        )
        assert csrf_failure.status_code == 403

        anonymous_client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=harness.api_app),
            base_url="http://127.0.0.1:4287",
        )
        bearer_only = await anonymous_client.post(
            "/api/v1/workspaces/u19-scope/approvals/11111111-1111-4111-8111-111111111111/decisions",
            headers={
                "Authorization": "Bearer test-scoped-api-token",
                "Origin": "http://127.0.0.1:4287",
            },
            json={
                "decision": "approve",
                "reason": None,
                "expected_patch_digest": "a" * 64,
                "expected_policy_revision": 1,
            },
        )
        assert bearer_only.status_code == 401, bearer_only.text
        await anonymous_client.aclose()

        extra_fields = await client.post(
            "/api/v1/workspaces/u19-scope/approvals/11111111-1111-4111-8111-111111111111/decisions",
            headers={"X-CSRF-Token": csrf, "Origin": "http://127.0.0.1:4287"},
            json={
                "decision": "approve",
                "reason": None,
                "expected_patch_digest": "a" * 64,
                "expected_policy_revision": 1,
                "status": "approved",
            },
        )
        assert extra_fields.status_code == 422

        create_key = new_uuid7(now=clock())
        create_headers = _csrf_headers(csrf, extra={"Idempotency-Key": create_key})
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            db.add(
                BudgetAccountModel(
                    id=new_uuid7(now=clock()),
                    workspace_id=workspace_id,
                    scope_kind="workspace_daily",
                    scope_key="u19-test-day",
                    currency="USD",
                    cost_cap=Decimal("10.000000"),
                    token_cap=100_000,
                    call_cap=100,
                    max_patch_attempts=2,
                    max_wall_seconds=1800,
                    window_started_at=clock(),
                    window_ends_at=clock() + timedelta(days=1),
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
        create_body = {
            "run_id": run_id,
            "mode": "approval",
            "reason": "U19 API create positive case",
        }
        created_repair = await client.post(
            "/api/v1/workspaces/u19-scope/repairs",
            headers=create_headers,
            json=create_body,
        )
        assert created_repair.status_code == 202, created_repair.text
        assert created_repair.json()["state"] == "succeeded"
        replayed_create = await client.post(
            "/api/v1/workspaces/u19-scope/repairs",
            headers=create_headers,
            json=create_body,
        )
        assert replayed_create.status_code == 202, replayed_create.text
        assert replayed_create.json() == created_repair.json()
    finally:
        await client.aclose()
        await harness.app_engine.dispose()
