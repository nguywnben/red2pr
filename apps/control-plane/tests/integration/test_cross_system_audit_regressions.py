"""Cross-system business consistency & integration regression tests (Pre-Hackathon Audit).

Covers end-to-end interactions across setup, budgets, verification/approvals/publisher,
dynamic pricing catalog isolation, worker readiness probes, and durable triage intake:
1. Per-session `repair_session` budget account isolation on cancel & retry (`AGT-03`, `NFR-06`).
2. Setup Wizard `model_consent` -> `WorkspaceModelConfigModel` + `workspace_daily` sync and
   `worker_readiness` backend-to-isolation mapping (`remote_vm_worker`, `podman_rootless`).
3. `VerificationService.verify` (`policy_gate`) -> `ApprovalService.decide("reject")` (`rejected`)
   and `ApprovalService.decide("approve")` -> `PublisherSaga.publish_approved` without manual
   state manipulation.
4. `ADR-051` `litellm-*` dynamic catalog pricing revisions stripped from manual `pricing_json`.
5. `RuntimePipelineCoordinator.run_once()` draining `ci_run.triage` jobs and auto-enqueuing
   `auto_repair` sessions with isolated `repair_session` budgets.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import tarfile
from collections import deque
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from py_contracts.crypto import (
    DOMAIN_RESULT_V1,
    KeyRing,
    MasterKeyRing,
    canonical_json_bytes,
    export_ed25519_public_key_record,
    sha256_canonical_json,
    sign_model_ed25519,
)
from py_contracts.integrations import CiRun
from py_contracts.primitives import new_uuid7
from py_contracts.worker import ResultV1
from red2pr_control.api.app import create_app
from red2pr_control.approvals.service import ApprovalService
from red2pr_control.core.egress import EgressPolicyEngine
from red2pr_control.core.redaction import Redactor
from red2pr_control.db.base import (
    ApprovalRequestModel,
    BudgetAccountModel,
    CiRunModel,
    PatchAttemptModel,
    PublicationRecordModel,
    RepairSessionModel,
    RepositoryModel,
    RepositoryPolicyModel,
    ReproductionRunModel,
    SandboxLeaseModel,
    SigningKeyModel,
    TaskJobModel,
    WorkerModel,
    WorkspaceModelConfigModel,
)
from red2pr_control.db.engine import create_app_engine, create_session_factory
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.sessions import IamService
from red2pr_control.inference.budgets import AtomicBudgetLedger
from red2pr_control.inference.meta_client import MetaMuseInferenceService
from red2pr_control.inference.patch_agent import BoundedPatchAgentService
from red2pr_control.integrations import GitHubIntegrationService
from red2pr_control.integrations.base import (
    ProviderConnectionContext,
    ProviderDraftReviewRecord,
    ProviderRemoteCheckRecord,
)
from red2pr_control.operations.setup_wizard import DbEndpointAllowlistProvider, SetupStepRegistry
from red2pr_control.orchestrator import (
    DurableTaskQueueService,
    ReproductionOrchestrator,
    WorkerBrokerService,
)
from red2pr_control.publisher.saga import PublisherSaga
from red2pr_control.repositories import RepositoryCatalogService
from red2pr_control.runtime_pipeline import RuntimePipelineCoordinator
from red2pr_control.secrets.broker import SecretBroker, SecretBrokerTotpVault
from red2pr_control.triage_evidence import (
    CiRunCollectorService,
    LocalEncryptedArtifactStore,
    persist_encrypted_artifact,
)
from red2pr_control.triage_evidence.collector import ci_run_model_to_dto
from red2pr_control.verification.service import VerificationService
from red2pr_control.verification.verifier import (
    DeterministicVerifier,
    create_signed_evidence_manifest,
)

_U17_PATH = Path(__file__).with_name("test_agents_and_state_machine.py")
_U17_SPEC = importlib.util.spec_from_file_location("red2pr_audit_u17_support", _U17_PATH)
assert _U17_SPEC is not None and _U17_SPEC.loader is not None
_U17 = importlib.util.module_from_spec(_U17_SPEC)
sys.modules[_U17_SPEC.name] = _U17
_U17_SPEC.loader.exec_module(_U17)

_U18_PATH = Path(__file__).with_name("test_deterministic_verifier.py")
_U18_SPEC = importlib.util.spec_from_file_location("red2pr_audit_u18_support", _U18_PATH)
assert _U18_SPEC is not None and _U18_SPEC.loader is not None
_U18 = importlib.util.module_from_spec(_U18_SPEC)
sys.modules[_U18_SPEC.name] = _U18
_U18_SPEC.loader.exec_module(_U18)

ManualClock = _U17.ManualClock
_bootstrap_workspace_and_repo = _U17._bootstrap_workspace_and_repo
_build_u17_harness = _U17._build_u17_harness
_seed_ci_run_job_and_log_artifact = _U17._seed_ci_run_job_and_log_artifact
_csrf_headers = _U17._csrf_headers
PUBLIC_BASE_URL = _U17.PUBLIC_BASE_URL
OWNER_CREDENTIAL = _U17.OWNER_CREDENTIAL


@pytest.fixture(scope="module")
def pg_urls() -> Iterator[Any]:
    yield from _U17.pg_urls.__wrapped__()


@pytest.fixture
async def migrated_db(pg_urls: Any) -> AsyncIterator[Any]:
    async for result in _U17.migrated_db.__wrapped__(pg_urls):
        yield result


@pytest.mark.asyncio
async def test_per_session_budget_isolation_on_cancel_and_retry(
    migrated_db: Any,
    tmp_path: Path,
) -> None:
    clock = ManualClock()
    harness = _build_u17_harness(
        migrated_db.app_url,
        clock=clock,
        store_dir=tmp_path / "artifacts-budget",
    )
    client, csrf, _owner_id, workspace_id, repo_id = await _bootstrap_workspace_and_repo(
        harness,
        clock=clock,
        ws_slug="audit-budget-iso",
    )
    try:
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            repo_row = await db.get(RepositoryModel, repo_id)
            assert repo_row is not None
            repo_row.mode = "approval"
            repo_row.policy_revision = 1
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
                    required_check_names_json=[],
                    allow_test_edits=False,
                    allow_config_edits=False,
                    max_attempts=2,
                    max_diff_lines=500,
                    require_baseline=True,
                    runtime_profile_id="default-isolated",
                    created_by_user_id=_owner_id,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )

        # Seed workspace_daily budget account via PATCH /models/config
        models_get = await client.get("/api/v1/workspaces/audit-budget-iso/models")
        assert models_get.status_code == 200, models_get.text
        cfg_ver = int(models_get.json()["version"])
        patch_cfg = await client.patch(
            "/api/v1/workspaces/audit-budget-iso/models/config",
            headers=_csrf_headers(
                csrf,
                extra={"Idempotency-Key": new_uuid7(now=clock()), "If-Match": f'"v{cfg_ver}"'},
            ),
            json={
                "expected_version": cfg_ver,
                "budget_policy": {
                    "max_calls_per_session": 20,
                    "max_tokens_per_session": 80000,
                    "max_patch_attempts": 2,
                    "max_wall_seconds": 1200,
                    "max_cost_per_session": {"amount": "3.000000", "currency": "USD"},
                    "daily_workspace_cap": {"amount": "30.000000", "currency": "USD"},
                    "alert_threshold_percent": 80,
                },
            },
        )
        assert patch_cfg.status_code == 200, patch_cfg.text

        run1_id, _, _, _ = await _seed_ci_run_job_and_log_artifact(
            harness,
            workspace_id=workspace_id,
            repository_id=repo_id,
            head_sha="1" * 40,
            job_name="pytest-1",
            ci_failure_log="FAILED tests/test_one.py::test_a - AssertionError",
            now=clock(),
        )
        run2_id, _, _, _ = await _seed_ci_run_job_and_log_artifact(
            harness,
            workspace_id=workspace_id,
            repository_id=repo_id,
            head_sha="2" * 40,
            job_name="pytest-2",
            ci_failure_log="FAILED tests/test_two.py::test_b - AssertionError",
            now=clock(),
        )

        r1 = await client.post(
            "/api/v1/workspaces/audit-budget-iso/repairs",
            headers=_csrf_headers(csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={"run_id": run1_id, "mode": "approval", "reason": "Investigate run 1"},
        )
        assert r1.status_code == 202, r1.text
        repair1_id = str(r1.json()["resource_id"])

        r2 = await client.post(
            "/api/v1/workspaces/audit-budget-iso/repairs",
            headers=_csrf_headers(csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={"run_id": run2_id, "mode": "approval", "reason": "Investigate run 2"},
        )
        assert r2.status_code == 202, r2.text
        repair2_id = str(r2.json()["resource_id"])

        detail1 = (
            await client.get(f"/api/v1/workspaces/audit-budget-iso/repairs/{repair1_id}")
        ).json()
        detail2 = (
            await client.get(f"/api/v1/workspaces/audit-budget-iso/repairs/{repair2_id}")
        ).json()
        assert detail1["budget_id"] != detail2["budget_id"]

        cancel1 = await client.post(
            f"/api/v1/workspaces/audit-budget-iso/repairs/{repair1_id}/actions",
            headers=_csrf_headers(csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={
                "action": "cancel",
                "reason": "Cancel repair 1 only",
                "expected_version": detail1["version"],
            },
        )
        assert cancel1.status_code == 200, cancel1.text
        assert cancel1.json()["state"] == "succeeded"
        cancelled_detail = (
            await client.get(f"/api/v1/workspaces/audit-budget-iso/repairs/{repair1_id}")
        ).json()
        assert cancelled_detail["state"] == "cancelled"

        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            b1 = await db.get(BudgetAccountModel, detail1["budget_id"])
            b2 = await db.get(BudgetAccountModel, detail2["budget_id"])
            daily = await db.scalar(
                select(BudgetAccountModel).where(
                    BudgetAccountModel.workspace_id == workspace_id,
                    BudgetAccountModel.scope_kind == "workspace_daily",
                )
            )
            assert b1 is not None and b1.scope_kind == "repair_session"
            assert b1.cost_cap == Decimal("3.000000")
            assert b1.cancelled_at is not None
            assert b2 is not None and b2.scope_kind == "repair_session"
            assert b2.cancelled_at is None
            assert daily is not None and daily.cancelled_at is None

        retry1 = await client.post(
            f"/api/v1/workspaces/audit-budget-iso/repairs/{repair1_id}/actions",
            headers=_csrf_headers(csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={
                "action": "retry",
                "reason": "Retry after transient cancellation",
                "expected_version": cancelled_detail["version"],
            },
        )
        assert retry1.status_code == 200, retry1.text
        assert retry1.json()["state"] == "succeeded"
        retried_repair_id = str(retry1.json()["resource_id"])
        retried_detail = (
            await client.get(f"/api/v1/workspaces/audit-budget-iso/repairs/{retried_repair_id}")
        ).json()
        retried_budget_id = retried_detail["budget_id"]
        assert retried_budget_id != detail1["budget_id"]
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            b_retry = await db.get(BudgetAccountModel, retried_budget_id)
            assert b_retry is not None
            assert b_retry.scope_kind == "repair_session"
            assert b_retry.cancelled_at is None
    finally:
        await client.aclose()
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_setup_wizard_model_consent_syncs_workspace_config_and_worker_readiness_mapping(
    migrated_db: Any,
    tmp_path: Path,
) -> None:
    clock = ManualClock()
    app_engine = create_app_engine(migrated_db.app_url, pool_size=6, max_overflow=6)
    app_factory = create_session_factory(app_engine)
    redactor = Redactor()
    kek_ring = MasterKeyRing(active_version=1, keys={1: b"\x61" * 32})
    secret_broker = SecretBroker(key_ring=kek_ring, redactor=redactor)
    iam = IamService(
        session_factory=app_factory,
        totp_vault=SecretBrokerTotpVault(secret_broker),
        iam_seed_key=b"\x62" * 32,
        public_base_url=PUBLIC_BASE_URL,
        clock=clock,
    )
    artifact_store = LocalEncryptedArtifactStore(root_dir=tmp_path / "setup-art", key_ring=kek_ring)
    budget_ledger = AtomicBudgetLedger(session_factory=app_factory, redactor=redactor, clock=clock)
    egress_policy = EgressPolicyEngine(
        dns_resolver=_U17.ScriptedDnsResolver({"api.meta.ai": [["157.240.22.35"]]}),
        allowlist_provider=DbEndpointAllowlistProvider(app_factory),
    )
    meta_service = MetaMuseInferenceService(
        iam_service=iam,
        secret_broker=secret_broker,
        budget_ledger=budget_ledger,
        egress_policy=egress_policy,
        redactor=redactor,
    )
    queue_service = DurableTaskQueueService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        redactor=redactor,
    )
    worker_broker = WorkerBrokerService(
        session_factory=app_factory,
        signing_key=iam.csrf_signing_key,
        queue_service=queue_service,
        artifact_store=artifact_store,
        master_key_ring=kek_ring,
        redactor=redactor,
        clock=clock,
    )
    setup_registry = SetupStepRegistry()
    meta_service.register_setup_probe(setup_registry)
    worker_broker.register_setup_probe(setup_registry)
    api_app = create_app(
        iam_service=iam,
        setup_step_registry=setup_registry,
        task_queue_service=queue_service,
        worker_broker_service=worker_broker,
        artifact_store=artifact_store,
        meta_inference_service=meta_service,
        pricing_catalog_refresh_enabled=False,
    )
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api_app),
        base_url=PUBLIC_BASE_URL,
    )
    try:
        raw_boot, _ = await iam.issue_bootstrap_token()
        pre_csrf = str((await client.get("/api/v1/auth/csrf")).json()["csrf_token"])
        claim = await client.post(
            "/api/v1/setup/claim",
            headers=_csrf_headers(pre_csrf),
            json={
                "bootstrap_token": raw_boot,
                "display_name": "Audit Owner",
                "email": "owner@red2pr.local",
                "password": OWNER_CREDENTIAL,
            },
        )
        assert claim.status_code == 201, claim.text
        csrf = str(claim.json()["csrf_token"])

        async def _step(phase: str, body: dict[str, Any]) -> dict[str, Any]:
            cur = (await client.get("/api/v1/setup")).json()
            resp = await client.post(
                f"/api/v1/setup/steps/{phase}",
                headers=_csrf_headers(csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
                json={"expected_checkpoint": cur["checkpoint"], **body},
            )
            assert resp.status_code == 200, resp.text
            return cast(dict[str, Any], resp.json())

        await _step(
            "topology_tls",
            {
                "action": "save",
                "deployment_mode": "local",
                "public_base_url": PUBLIC_BASE_URL,
                "tls_mode": "loopback_http",
            },
        )
        await _step(
            "storage_keys",
            {
                "action": "save",
                "storage_backend": "local",
                "backup_retention_days": 30,
                "master_key_custody_confirmed": True,
            },
        )
        ws_state = await _step(
            "workspace_admin",
            {
                "action": "save",
                "workspace_name": "Audit Core",
                "workspace_slug": "audit-core",
            },
        )
        ws_id = str(ws_state["default_workspace_id"])
        await _step("provider_connect", {"action": "skip"})

        consent_resp = await client.post(
            "/api/v1/setup/consents",
            headers=_csrf_headers(csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={
                "purpose": "inference",
                "scope": "instance",
                "destination": "https://api.meta.ai/v1",
                "data_classes": ["public", "workspace_internal"],
                "policy_notice_acknowledged": True,
            },
        )
        assert consent_resp.status_code == 201, consent_resp.text
        consent_id = str(consent_resp.json()["id"])

        after_model = await _step(
            "model_consent",
            {
                "action": "save",
                "primary_model": "muse-spark-1.3",
                "escalation_model": "muse-wonder-1.0",
                "max_cost_per_session": {"amount": "4.000000", "currency": "USD"},
                "max_tokens_per_session": 75000,
                "max_calls_per_session": 15,
                "inference_consent_id": consent_id,
            },
        )
        # Advances cleanly to Phase 7 with status="not_configured" and ready_repair=False
        assert after_model["phase"] == "worker_readiness"
        assert after_model["ready_repair"] is False
        mdl_step = next(s for s in after_model["steps"] if s["phase"] == "model_consent")
        assert mdl_step["status"] == "not_configured"

        async with workspace_rls_session(app_factory, workspace_id=ws_id) as db:
            cfg = await db.scalar(
                select(WorkspaceModelConfigModel).where(
                    WorkspaceModelConfigModel.workspace_id == ws_id
                )
            )
            assert cfg is not None
            assert cfg.active_inference_consent_id == consent_id
            assert cfg.budget_policy_json["max_tokens_per_session"] == 75000
            daily = await db.scalar(
                select(BudgetAccountModel).where(
                    BudgetAccountModel.workspace_id == ws_id,
                    BudgetAccountModel.scope_kind == "workspace_daily",
                )
            )
            assert daily is not None
            assert daily.cost_cap == Decimal("25.000000")

        # Seed vm_isolated & oci_rootless workers and verify backend mapping in worker_readiness
        async with instance_rls_session(app_factory, mode="instance_admin") as db:
            for idx, (iso_mode, rt_name) in enumerate(
                [("vm_isolated", "firecracker"), ("oci_rootless", "podman")]
            ):
                wid = new_uuid7(now=clock())
                db.add(
                    WorkerModel(
                        id=wid,
                        host_id=f"audit-worker-{idx}",
                        trust_domain="red2pr.internal",
                        isolation_mode=iso_mode,
                        runtime_name=rt_name,
                        profile_ids_json=["python-pytest-linux"],
                        capabilities_json={"network_none": True, "rootless": True},
                        cpu_limit=2,
                        memory_limit_bytes=2_147_483_648,
                        disk_limit_bytes=10_737_418_240,
                        pids_limit=256,
                        status="online",
                        heartbeat_at=clock(),
                        mtls_cert_serial=f"audit-serial-{idx}",
                        mtls_cert_fingerprint_sha256=hashlib.sha256(wid.encode()).hexdigest(),
                        mtls_cert_pem=(
                            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
                        ),
                        mtls_cert_expires_at=clock() + timedelta(days=1),
                        active_signer_key_id=f"key-{idx}",
                        host_escape_risk_acknowledged=True,
                        created_at=clock(),
                        updated_at=clock(),
                    )
                )

        after_vm_worker = await _step(
            "worker_readiness",
            {
                "action": "save",
                "sandbox_backend": "remote_vm_worker",
                "runtime_profile_id": "python-pytest-linux",
                "host_escape_risk_acknowledged": True,
                "run_self_test": True,
            },
        )
        wrk_step = next(s for s in after_vm_worker["steps"] if s["phase"] == "worker_readiness")
        assert wrk_step["status"] == "completed"
        assert wrk_step["probe_status"] == "passed"

        after_podman_worker = await _step(
            "worker_readiness",
            {
                "action": "save",
                "sandbox_backend": "podman_rootless",
                "runtime_profile_id": "python-pytest-linux",
                "host_escape_risk_acknowledged": True,
                "run_self_test": True,
            },
        )
        pod_step = next(s for s in after_podman_worker["steps"] if s["phase"] == "worker_readiness")
        assert pod_step["status"] == "completed"
        assert pod_step["probe_status"] == "passed"
    finally:
        await client.aclose()
        await app_engine.dispose()


@pytest.mark.asyncio
async def test_policy_gate_approval_reject_and_publish_handoff_without_manual_transition(
    migrated_db: Any,
    tmp_path: Path,
) -> None:
    clock = ManualClock(datetime.now(tz=UTC))
    harness = _build_u17_harness(
        migrated_db.app_url,
        clock=clock,
        store_dir=tmp_path / "artifacts-pub",
    )

    class _Provider:
        base_sha = "a" * 40
        commit_sha = "c" * 40

        def __init__(self) -> None:
            self.branches: dict[str, str] = {}
            self.files: dict[str, str | None] = {}
            self.review: ProviderDraftReviewRecord | None = None

        async def get_branch_head(
            self, _db: Any, _ctx: Any, *, branch_name: str, **_kw: Any
        ) -> str | None:
            if branch_name == "refs/heads/main":
                return self.base_sha
            return self.branches.get(branch_name)

        async def get_file_contents_at_ref(
            self, _db: Any, _ctx: Any, *, path: str, ref: str, **_kw: Any
        ) -> str | None:
            if ref == self.base_sha:
                return "return old()\n"
            return self.files.get(path)

        async def create_branch(
            self, _db: Any, _ctx: Any, *, branch_name: str, from_sha: str, **_kw: Any
        ) -> None:
            self.branches[branch_name] = from_sha

        async def push_commit(
            self,
            _db: Any,
            _ctx: Any,
            *,
            branch_name: str,
            file_changes: dict[str, str | None],
            **_kw: Any,
        ) -> str:
            self.branches[branch_name] = self.commit_sha
            self.files.update(file_changes)
            return self.commit_sha

        async def find_review_by_marker(
            self, _db: Any, _ctx: Any, **_kw: Any
        ) -> ProviderDraftReviewRecord | None:
            return self.review

        async def create_draft_review(
            self,
            _db: Any,
            _ctx: Any,
            *,
            head_branch: str,
            base_branch: str,
            **_kw: Any,
        ) -> ProviderDraftReviewRecord:
            self.review = ProviderDraftReviewRecord(
                external_review_id="audit-pr-1",
                number="42",
                html_url="https://github.com/acme/fixture/pull/42",
                head_branch=head_branch,
                base_branch=base_branch,
                head_sha=self.commit_sha,
                draft=True,
                state="open",
            )
            return self.review

        async def get_remote_checks(
            self,
            _db: Any,
            _ctx: Any,
            *,
            head_sha: str,
            **_kw: Any,
        ) -> tuple[ProviderRemoteCheckRecord, ...]:
            return (
                ProviderRemoteCheckRecord(
                    external_check_id="chk-1",
                    name="build",
                    head_sha=head_sha,
                    status="completed",
                    conclusion="success",
                ),
            )

    provider = _Provider()

    class _Integrations:
        async def resolve_publisher_target(
            self,
            *,
            workspace_id: str,
            repository_id: str,
        ) -> tuple[Any, ProviderConnectionContext, str]:
            _ = repository_id
            ctx = ProviderConnectionContext(
                workspace_id=workspace_id,
                connection_id="conn-audit",
                provider="github",
                base_url="https://api.github.com",
                app_id=None,
                client_id=None,
                installation_id="inst-audit",
                credential_secret_ref="sec-audit",
                webhook_secret_ref=None,
            )
            return provider, ctx, "acme/fixture"

    client, _csrf, owner_id, workspace_id, repository_id = await _bootstrap_workspace_and_repo(
        harness,
        clock=clock,
        ws_slug="audit-pub-gate",
    )
    await client.aclose()
    try:
        base_sha = "a" * 40
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            repo = await db.get(RepositoryModel, repository_id)
            assert repo is not None
            repo.mode = "approval"
            repo.policy_revision = 1
            db.add(
                RepositoryPolicyModel(
                    id=new_uuid7(now=clock()),
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    revision=1,
                    mode="approval",
                    paused=False,
                    branch_allowlist_json=["refs/heads/main"],
                    branch_denylist_json=[],
                    file_allowlist_json=[],
                    file_denylist_json=[],
                    sensitive_rules_json=[],
                    required_check_names_json=["build"],
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

        diff_text = (
            "diff --git a/src/fix.py b/src/fix.py\n"
            "--- a/src/fix.py\n"
            "+++ b/src/fix.py\n"
            "@@ -1 +1 @@\n"
            "-return old()\n"
            "+return new()\n"
        )
        diff_digest = hashlib.sha256(diff_text.encode()).hexdigest()
        worker_private_key = Ed25519PrivateKey.generate()
        shared_worker_id: str | None = None

        async def _prepare_verified_policy_gate_repair(
            tag: str,
        ) -> tuple[str, str, str, int, KeyRing, str]:
            nonlocal shared_worker_id
            run_id, _, _, _ = await _seed_ci_run_job_and_log_artifact(
                harness,
                workspace_id=workspace_id,
                repository_id=repository_id,
                head_sha=base_sha,
                job_name=f"pytest-{tag}",
                ci_failure_log="FAILED tests/test_sample.py::test_sample - AssertionError",
                now=clock(),
            )
            repair_id, _ = await _U17._create_repair_session_with_budget(
                harness,
                workspace_id=workspace_id,
                repository_id=repository_id,
                ci_run_id=run_id,
                base_sha=base_sha,
                semantic_key=f"audit-gate-{tag}",
                now=clock(),
            )
            (
                manifest,
                _,
                proof_blobs,
                trust_domain,
                evidence_private_key,
                _,
            ) = _U18._make_signed_manifest_case(
                workspace_id=workspace_id,
                repository_id=repository_id,
                repair_id=repair_id,
                base_sha=base_sha,
                now=clock(),
            )
            baseline_res = ResultV1.model_validate_json(
                proof_blobs[manifest.baseline_result_job_id]
            )
            patched_res = ResultV1.model_validate_json(proof_blobs[manifest.patched_result_job_id])
            if shared_worker_id is None:
                shared_worker_id = baseline_res.worker_id
                async with instance_rls_session(harness.app_factory, mode="instance_only") as db:
                    db.add(
                        WorkerModel(
                            id=shared_worker_id,
                            host_id="audit-proof-worker",
                            trust_domain="worker-trust-zone",
                            isolation_mode="vm_isolated",
                            runtime_name="firecracker",
                            profile_ids_json=["python-pytest-linux"],
                            capabilities_json={"network_none": True, "rootless": True},
                            cpu_limit=2,
                            memory_limit_bytes=2_147_483_648,
                            disk_limit_bytes=10_737_418_240,
                            pids_limit=256,
                            status="online",
                            heartbeat_at=clock(),
                            mtls_cert_serial="audit-proof-01",
                            mtls_cert_fingerprint_sha256=hashlib.sha256(
                                shared_worker_id.encode()
                            ).hexdigest(),
                            mtls_cert_pem=(
                                "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
                            ),
                            mtls_cert_expires_at=clock() + timedelta(days=1),
                            active_signer_key_id="worker-proof-key",
                            last_workspace_id=workspace_id,
                            host_escape_risk_acknowledged=True,
                            created_at=clock(),
                            updated_at=clock(),
                        )
                    )
            baseline_res = sign_model_ed25519(
                baseline_res.model_copy(
                    update={"worker_id": shared_worker_id, "signature": "ed25519:pending"}
                ),
                private_key=worker_private_key,
                key_id="worker-proof-key",
                domain=DOMAIN_RESULT_V1,
            )
            patched_res = sign_model_ed25519(
                patched_res.model_copy(
                    update={
                        "worker_id": shared_worker_id,
                        "patch_digest": diff_digest,
                        "signature": "ed25519:pending",
                    }
                ),
                private_key=worker_private_key,
                key_id="worker-proof-key",
                domain=DOMAIN_RESULT_V1,
            )
            proof_blobs[manifest.baseline_result_job_id] = canonical_json_bytes(
                baseline_res.model_dump(mode="json", by_alias=True)
            )
            proof_blobs[manifest.patched_result_job_id] = canonical_json_bytes(
                patched_res.model_dump(mode="json", by_alias=True)
            )
            mp = manifest.model_dump(mode="json", by_alias=True)
            mp["diff_digest"] = diff_digest
            mp["baseline_result_digest"] = hashlib.sha256(
                proof_blobs[manifest.baseline_result_job_id]
            ).hexdigest()
            mp["patched_result_digest"] = hashlib.sha256(
                proof_blobs[manifest.patched_result_job_id]
            ).hexdigest()
            manifest = create_signed_evidence_manifest(
                mp,
                private_key=evidence_private_key,
                key_id=manifest.signer_key_id,
            )
            manifest_keyring = KeyRing(
                [
                    export_ed25519_public_key_record(
                        private_key=worker_private_key,
                        key_id="worker-proof-key",
                        not_before=clock() - timedelta(days=1),
                        trust_domain="worker-trust-zone",
                    ),
                    export_ed25519_public_key_record(
                        private_key=evidence_private_key,
                        key_id=manifest.signer_key_id,
                        not_before=clock() - timedelta(days=1),
                        trust_domain=trust_domain,
                    ),
                ]
            )
            for res in (baseline_res, patched_res):
                res_json = res.model_dump(mode="json")
                async with workspace_rls_session(
                    harness.app_factory, workspace_id=workspace_id
                ) as db:
                    db.add(
                        TaskJobModel(
                            id=res.job_id,
                            workspace_id=workspace_id,
                            repository_id=repository_id,
                            repair_id=repair_id,
                            kind="sandbox.execute",
                            is_repair_job=True,
                            resource_id=repair_id,
                            state="succeeded",
                            priority=100,
                            dedup_key=None,
                            logical_effect_key=f"audit-proof:{res.job_id}",
                            budget_key=None,
                            correlation_id=f"audit-proof-{tag}",
                            payload_json={"repair_id": repair_id},
                            attempt=1,
                            max_attempts=1,
                            lease_epoch=1,
                            leased_by_worker_id=shared_worker_id,
                            heartbeat_at=clock(),
                            lease_expires_at=clock() + timedelta(minutes=5),
                            not_before=clock(),
                            deadline=clock() + timedelta(hours=1),
                            recoverable=True,
                            reconcile_required=False,
                            version=1,
                            created_at=clock(),
                            updated_at=clock(),
                        )
                    )
                    await db.flush()
                    db.add(
                        SandboxLeaseModel(
                            id=new_uuid7(now=clock()),
                            workspace_id=workspace_id,
                            repository_id=repository_id,
                            repair_id=repair_id,
                            job_id=res.job_id,
                            worker_id=shared_worker_id,
                            lease_epoch=res.lease_epoch,
                            capability_nonce=res.capability_nonce,
                            expected_worker_trust_domain="worker-trust-zone",
                            profile_id="python-pytest-linux",
                            profile_revision=1,
                            image_digest=res.image_digest,
                            base_sha=base_sha,
                            source_archive_digest=res.source_digest,
                            patch_digest=res.patch_digest,
                            network_policy_digest="d" * 64,
                            supervisor_policy_digest="e" * 64,
                            sandbox_job_json={"job_id": res.job_id},
                            upload_slots_json=[],
                            uploaded_artifacts_json=[],
                            output_bytes_uploaded=0,
                            status="completed",
                            issued_at=res.started_at,
                            heartbeat_at=res.ended_at,
                            lease_expires_at=res.ended_at + timedelta(minutes=5),
                            ended_at=res.ended_at,
                            result_digest=sha256_canonical_json(res_json),
                            result_json=res_json,
                            cleanup_verified=True,
                            version=1,
                            created_at=res.started_at,
                            updated_at=res.ended_at,
                        )
                    )
            async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
                diff_art = await persist_encrypted_artifact(
                    db,
                    store=harness.artifact_store,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    name=f"verified-{tag}.patch",
                    kind="patch_diff",
                    mime="text/x-diff",
                    plaintext=diff_text.encode(),
                    expected_digest=diff_digest,
                    now=clock(),
                )
                db.add(
                    PatchAttemptModel(
                        id=new_uuid7(now=clock()),
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        repair_id=repair_id,
                        attempt_number=1,
                        base_sha=base_sha,
                        patch_digest=diff_digest,
                        diff_artifact_id=diff_art.id,
                        changed_paths_json=["src/fix.py"],
                        diff_lines_added=1,
                        diff_lines_removed=1,
                        claimed_root_cause="Audit fix",
                        target_test_selection_id=None,
                        integrity_outcome="accepted",
                        sandbox_reproduction_id=None,
                        provenance_json=[],
                        version=1,
                        created_at=clock(),
                        updated_at=clock(),
                    )
                )
            for st in ("authorized", "collecting", "triaging", "reproducing"):
                await harness.state_machine.transition_session(
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state=st,
                    correlation_id=f"audit-st-{tag}",
                )
            await harness.state_machine.transition_session(
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state="repro_confirmed",
                target_proof_grade="baseline_confirmed",
                correlation_id=f"audit-st-{tag}",
            )
            for st in ("patching", "verifying"):
                await harness.state_machine.transition_session(
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state=st,
                    correlation_id=f"audit-st-{tag}",
                )
            v_svc = VerificationService(
                session_factory=harness.app_factory,
                verifier=DeterministicVerifier(keyring=manifest_keyring),
                state_machine=harness.state_machine,
                manifest_keyring=manifest_keyring,
                evidence_trust_domain=trust_domain,
            )
            proof = await v_svc.verify(
                workspace_id=workspace_id,
                repair_id=repair_id,
                verification_id=new_uuid7(now=clock()),
                idempotency_key=f"audit-verify-{tag}",
                facts=_U18._facts_for_signed_manifest(manifest, proof_blobs, diff_text),
                signed_manifest=manifest,
                evidence_blobs=proof_blobs,
                correlation_id=f"audit-verify-{tag}",
                now=clock(),
            )
            assert proof.status == "verified"
            async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
                rep_row = await db.get(RepairSessionModel, repair_id)
                assert rep_row is not None and rep_row.state == "policy_gate"
                app_row = await db.scalar(
                    select(ApprovalRequestModel).where(
                        ApprovalRequestModel.workspace_id == workspace_id,
                        ApprovalRequestModel.repair_id == repair_id,
                        ApprovalRequestModel.status == "pending",
                    )
                )
                assert app_row is not None
                return (
                    repair_id,
                    app_row.id,
                    app_row.patch_digest,
                    app_row.policy_revision,
                    manifest_keyring,
                    trust_domain,
                )

        approval_svc = ApprovalService(session_factory=harness.app_factory)

        # 1) Reject from policy_gate -> transitions repair to terminal "rejected"
        (
            rej_repair_id,
            rej_app_id,
            rej_digest,
            rej_rev,
            _,
            _,
        ) = await _prepare_verified_policy_gate_repair("reject")
        rej_dec = await approval_svc.decide(
            workspace_id=workspace_id,
            approval_id=rej_app_id,
            actor_id=owner_id,
            decision="reject",
            reason="Operator rejected candidate patch",
            expected_patch_digest=rej_digest,
            expected_policy_revision=rej_rev,
            idempotency_key=new_uuid7(now=clock()),
            correlation_id="audit-reject-01",
            now=clock(),
        )
        assert rej_dec.status == "rejected"
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            rej_row = await db.get(RepairSessionModel, rej_repair_id)
            assert rej_row is not None
            assert rej_row.state == "rejected"

        # 2) Approve from policy_gate -> PublisherSaga.publish_approved succeeds directly!
        (
            pub_repair_id,
            pub_app_id,
            pub_digest,
            pub_rev,
            pub_keyring,
            pub_trust_domain,
        ) = await _prepare_verified_policy_gate_repair("approve")
        app_dec = await approval_svc.decide(
            workspace_id=workspace_id,
            approval_id=pub_app_id,
            actor_id=owner_id,
            decision="approve",
            reason="Approved for draft PR publication",
            expected_patch_digest=pub_digest,
            expected_policy_revision=pub_rev,
            idempotency_key=new_uuid7(now=clock()),
            correlation_id="audit-approve-01",
            now=clock(),
        )
        assert app_dec.status == "approved"

        saga = PublisherSaga(
            session_factory=harness.app_factory,
            integrations=cast(GitHubIntegrationService, _Integrations()),
            artifact_store=harness.artifact_store,
            manifest_keyring=pub_keyring,
            evidence_trust_domain=pub_trust_domain,
            intent_signing_key=b"audit-publisher-intent-key-32byt",
            state_machine=harness.state_machine,
        )
        pub = await saga.publish_approved(
            workspace_id=workspace_id,
            approval_id=pub_app_id,
            correlation_id="audit-publish-01",
        )
        assert pub.status == "published"
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            pub_row = await db.get(RepairSessionModel, pub_repair_id)
            assert pub_row is not None
            assert pub_row.state == "remote_validating"
    finally:
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_litellm_catalog_pricing_revisions_are_not_persisted_as_manual_overrides(
    migrated_db: Any,
    tmp_path: Path,
) -> None:
    clock = ManualClock()
    harness = _build_u17_harness(
        migrated_db.app_url,
        clock=clock,
        store_dir=tmp_path / "artifacts-pricing",
    )
    client, csrf, _owner_id, workspace_id, _repo_id = await _bootstrap_workspace_and_repo(
        harness,
        clock=clock,
        ws_slug="audit-pricing",
    )
    try:
        initial = await client.get("/api/v1/workspaces/audit-pricing/models")
        ver = int(initial.json()["version"])
        resp = await client.patch(
            "/api/v1/workspaces/audit-pricing/models/config",
            headers=_csrf_headers(
                csrf,
                extra={"Idempotency-Key": new_uuid7(now=clock()), "If-Match": f'"v{ver}"'},
            ),
            json={
                "expected_version": ver,
                "pricing_updates": {
                    "muse-spark-1.3": {
                        "pricing_revision": "litellm-2026-10-30",
                        "input_per_1m_tokens": {"amount": "1.200000", "currency": "USD"},
                        "output_per_1m_tokens": {"amount": "4.800000", "currency": "USD"},
                        "configured": True,
                    },
                    "muse-wonder-1.0": {
                        "pricing_revision": "manual-2026-11",
                        "input_per_1m_tokens": {"amount": "4.000000", "currency": "USD"},
                        "output_per_1m_tokens": {"amount": "16.000000", "currency": "USD"},
                        "configured": True,
                    },
                },
            },
        )
        assert resp.status_code == 200, resp.text
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            cfg = await db.scalar(
                select(WorkspaceModelConfigModel).where(
                    WorkspaceModelConfigModel.workspace_id == workspace_id
                )
            )
            assert cfg is not None
            assert "muse-spark-1.3" not in cfg.pricing_json
            assert cfg.pricing_json["muse-wonder-1.0"]["pricing_revision"] == "manual-2026-11"
    finally:
        await client.aclose()
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_runtime_pipeline_coordinator_drains_triage_job_and_creates_auto_repair_session(
    migrated_db: Any,
    tmp_path: Path,
) -> None:
    clock = ManualClock()
    harness = _build_u17_harness(
        migrated_db.app_url,
        clock=clock,
        store_dir=tmp_path / "artifacts-pipeline",
    )
    client, _csrf, owner_id, workspace_id, repository_id = await _bootstrap_workspace_and_repo(
        harness,
        clock=clock,
        ws_slug="audit-pipeline",
    )
    await client.aclose()
    try:
        head_sha = "d" * 40
        run_id, _, _, _ = await _seed_ci_run_job_and_log_artifact(
            harness,
            workspace_id=workspace_id,
            repository_id=repository_id,
            head_sha=head_sha,
            job_name="pytest-auto",
            ci_failure_log="FAILED tests/test_auto.py::test_auto - AssertionError",
            now=clock(),
        )

        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            repo = await db.get(RepositoryModel, repository_id)
            assert repo is not None
            repo.mode = "auto_repair"
            repo.policy_revision = 1
            db.add(
                RepositoryPolicyModel(
                    id=new_uuid7(now=clock()),
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    revision=1,
                    mode="auto_repair",
                    paused=False,
                    branch_allowlist_json=["refs/heads/main"],
                    branch_denylist_json=[],
                    file_allowlist_json=[],
                    file_denylist_json=[],
                    sensitive_rules_json=[],
                    required_check_names_json=[],
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
                WorkspaceModelConfigModel(
                    id=new_uuid7(now=clock()),
                    workspace_id=workspace_id,
                    endpoint_base_url="https://api.meta.ai/v1",
                    pricing_json={},
                    budget_policy_json={
                        "max_calls_per_session": 20,
                        "max_tokens_per_session": 80000,
                        "max_patch_attempts": 2,
                        "max_wall_seconds": 1200,
                        "max_cost_per_session": {"amount": "3.500000", "currency": "USD"},
                        "daily_workspace_cap": {"amount": "25.000000", "currency": "USD"},
                        "alert_threshold_percent": 80,
                    },
                    escalation_policy_json={},
                    updated_by_user_id=owner_id,
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )

        class _HermeticCollector(CiRunCollectorService):
            async def collect_from_trigger(
                self,
                *,
                workspace_id: str,
                trigger_id: str,
                correlation_id: str | None = None,
                now: datetime | None = None,
            ) -> CiRun:
                _ = (trigger_id, correlation_id, now)
                async with workspace_rls_session(
                    self._session_factory, workspace_id=workspace_id
                ) as db:
                    row = await db.get(CiRunModel, run_id)
                    assert row is not None
                    row.head_sha_verified = True
                    row.conclusion = "failure"
                    row.ref = "refs/heads/main"
                    await db.flush()
                    return ci_run_model_to_dto(row)

        queue_svc = DurableTaskQueueService(
            session_factory=harness.app_factory,
            signing_key=harness.iam.csrf_signing_key,
            redactor=harness.redactor,
        )
        collector = _HermeticCollector(
            session_factory=harness.app_factory,
            artifact_store=harness.artifact_store,
            redactor=harness.redactor,
            clock=clock,
        )
        coordinator = RuntimePipelineCoordinator(
            session_factory=harness.app_factory,
            queue_service=queue_svc,
            collector_service=collector,
            state_machine=harness.state_machine,
            clock=clock,
        )

        trigger_id = new_uuid7(now=clock())
        enqueued = await queue_svc.enqueue_job(
            workspace_id=workspace_id,
            repository_id=repository_id,
            kind="ci_run.triage",
            resource_id=trigger_id,
            correlation_id="corr-audit-pipeline-01",
            payload={"allow_sandbox_execution": True},
            now=clock(),
        )
        handled = await coordinator.run_once(now=clock())
        assert handled is True

        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            job_row = await db.get(TaskJobModel, enqueued.id)
            assert job_row is not None and job_row.state == "succeeded"
            auto_repair = await db.scalar(
                select(RepairSessionModel).where(
                    RepairSessionModel.workspace_id == workspace_id,
                    RepairSessionModel.ci_run_id == run_id,
                )
            )
            assert auto_repair is not None
            assert auto_repair.semantic_trigger_key == f"auto:{run_id}"
            sess_budget = await db.get(BudgetAccountModel, auto_repair.budget_account_id)
            assert sess_budget is not None
            assert sess_budget.scope_kind == "repair_session"
            assert sess_budget.cost_cap == Decimal("3.500000")
            assert sess_budget.repair_id == auto_repair.id
    finally:
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_runtime_pipeline_coordinator_end_to_end_auto_repair_publication(
    migrated_db: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify `RuntimePipelineCoordinator` drives a repair from `received` to Draft PR."""
    pki = _U17._generate_pki_material(["api.meta.ai"])
    ca_file = tmp_path / "meta_e2e_pipeline_ca.pem"
    ca_file.write_text(pki.ca_pem, encoding="utf-8")
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_file))

    scripted_responses: deque[Callable[[Any], tuple[int, dict[str, str], bytes]]] = deque()

    async def _meta_handler(req: Any) -> tuple[int, dict[str, str], bytes]:
        body_json = json.loads(req.body_bytes.decode("utf-8"))
        resp_schema_name = (
            (body_json.get("response_format") or {}).get("json_schema", {}).get("name")
        )
        if resp_schema_name == "red2pr_capability_probe":
            return (
                200,
                {"Content-Type": "application/json", "x-request-id": "req_e2e_probe"},
                _U17._load_meta_fixture_bytes("probe_spark_available.json"),
            )
        assert scripted_responses, f"Unexpected unscripted Meta call: {body_json}"
        responder = scripted_responses.popleft()
        return responder(req)

    clock = ManualClock(datetime.now(tz=UTC))
    async with _U17.LocalAsyncTlsMetaServer(pki=pki, handler=_meta_handler) as tls_srv:
        harness = _build_u17_harness(
            migrated_db.app_url,
            clock=clock,
            store_dir=tmp_path / "artifacts-e2e-pipeline",
            local_tls_port=tls_srv.port,
            ca_pem=pki.ca_pem,
        )
        client, _csrf, owner_id, workspace_id, repository_id = await _bootstrap_workspace_and_repo(
            harness,
            clock=clock,
            ws_slug="audit-e2e-auto",
            configure_meta_inference=True,
        )
        await client.aclose()
        try:
            base_sha = "e" * 40
            calc_buggy = "def add(a: int, b: int) -> int:\n    return a - b\n"
            valid_diff = (
                "--- a/src/calc.py\n"
                "+++ b/src/calc.py\n"
                "@@ -1,2 +1,2 @@\n"
                " def add(a: int, b: int) -> int:\n"
                "-    return a - b\n"
                "+    return a + b\n"
            )
            ci_log = (
                "=== test session starts ===\n"
                "FAILED tests/test_calc.py::test_add - AssertionError: assert -1 == 5\n"
                "=== 1 failed, 3 passed ===\n"
            )
            run_id, _job_id, art_id, _fp_hash = await _seed_ci_run_job_and_log_artifact(
                harness,
                workspace_id=workspace_id,
                repository_id=repository_id,
                head_sha=base_sha,
                job_name="pytest (ubuntu-latest)",
                ci_failure_log=ci_log,
                now=clock(),
            )

            # Build GitHub-style tarball with wrapper directory + PAX header
            tar_buf = io.BytesIO()
            with tarfile.open(fileobj=tar_buf, mode="w:gz", format=tarfile.PAX_FORMAT) as tf:
                for rel, raw_txt in {
                    "pyproject.toml": "[project]\nname = 'calc'\n",
                    "uv.lock": "version = 1\n",
                    "src/calc.py": calc_buggy,
                    "tests/test_calc.py": (
                        "from src.calc import add\n\n"
                        "def test_add() -> None:\n"
                        "    assert add(2, 3) == 5\n"
                    ),
                }.items():
                    b_data = raw_txt.encode("utf-8")
                    ti = tarfile.TarInfo(name=f"acme-calc-{base_sha[:7]}/{rel}")
                    ti.size = len(b_data)
                    tf.addfile(ti, io.BytesIO(b_data))
            github_tar_bytes = tar_buf.getvalue()

            worker_priv = Ed25519PrivateKey.generate()
            worker_pub_rec = export_ed25519_public_key_record(
                private_key=worker_priv,
                key_id="worker-e2e-key",
                not_before=clock() - timedelta(days=1),
                trust_domain="worker-trust-zone",
            )
            worker_id = new_uuid7(now=clock())
            await harness.profile_registry.sync_profiles_to_db(harness.app_factory, now=clock())
            async with instance_rls_session(harness.app_factory, mode="instance_only") as inst_db:
                inst_db.add(
                    WorkerModel(
                        id=worker_id,
                        host_id="e2e-worker-01",
                        trust_domain="worker-trust-zone",
                        isolation_mode="vm_isolated",
                        runtime_name="firecracker",
                        profile_ids_json=["python-pytest-linux"],
                        capabilities_json={"network_none": True, "rootless": True},
                        cpu_limit=2,
                        memory_limit_bytes=2_147_483_648,
                        disk_limit_bytes=10_737_418_240,
                        pids_limit=256,
                        status="online",
                        heartbeat_at=clock(),
                        mtls_cert_serial="e2e-serial-01",
                        mtls_cert_fingerprint_sha256=hashlib.sha256(
                            worker_id.encode()
                        ).hexdigest(),
                        mtls_cert_pem=(
                            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
                        ),
                        mtls_cert_expires_at=clock() + timedelta(days=1),
                        active_signer_key_id="worker-e2e-key",
                        last_workspace_id=workspace_id,
                        host_escape_risk_acknowledged=True,
                        created_at=clock(),
                        updated_at=clock(),
                    )
                )
                await inst_db.flush()
                inst_db.add(
                    SigningKeyModel(
                        id=new_uuid7(now=clock()),
                        key_id="worker-e2e-key",
                        algorithm="ed25519",
                        purpose="worker_result",
                        public_key_b64=worker_pub_rec.public_key_b64,
                        worker_id=worker_id,
                        trust_domain="worker-trust-zone",
                        not_before=worker_pub_rec.not_before,
                        revoked_at=None,
                        revoke_reason=None,
                        version=1,
                        created_at=clock(),
                        updated_at=clock(),
                    )
                )

            async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
                repo = await db.get(RepositoryModel, repository_id)
                assert repo is not None
                repo.mode = "auto_repair"
                repo.policy_revision = 1
                db.add(
                    RepositoryPolicyModel(
                        id=new_uuid7(now=clock()),
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        revision=1,
                        mode="auto_repair",
                        paused=False,
                        branch_allowlist_json=["refs/heads/main"],
                        branch_denylist_json=[],
                        file_allowlist_json=[],
                        file_denylist_json=[],
                        sensitive_rules_json=[],
                        required_check_names_json=[],
                        allow_test_edits=False,
                        allow_config_edits=False,
                        max_attempts=2,
                        max_diff_lines=500,
                        require_baseline=True,
                        runtime_profile_id="python-pytest-linux",
                        created_by_user_id=owner_id,
                        created_at=clock(),
                        updated_at=clock(),
                    )
                )

            class _AutoProvider:
                def __init__(self) -> None:
                    self.branches: dict[str, str] = {"refs/heads/main": base_sha}
                    self.files: dict[str, str | None] = {"src/calc.py": calc_buggy}
                    self.review: ProviderDraftReviewRecord | None = None
                    self.commit_sha = "f" * 40

                async def get_branch_head(
                    self, _db: Any, _ctx: Any, *, branch_name: str, **_kw: Any
                ) -> str | None:
                    return self.branches.get(branch_name)

                async def get_file_contents_at_ref(
                    self, _db: Any, _ctx: Any, *, path: str, ref: str, **_kw: Any
                ) -> str | None:
                    if ref == base_sha and path == "src/calc.py":
                        return calc_buggy
                    return self.files.get(path)

                async def create_branch(
                    self, _db: Any, _ctx: Any, *, branch_name: str, from_sha: str, **_kw: Any
                ) -> None:
                    self.branches[branch_name] = from_sha

                async def push_commit(
                    self,
                    _db: Any,
                    _ctx: Any,
                    *,
                    branch_name: str,
                    file_changes: dict[str, str | None],
                    **_kw: Any,
                ) -> str:
                    self.branches[branch_name] = self.commit_sha
                    self.files.update(file_changes)
                    return self.commit_sha

                async def find_review_by_marker(
                    self, _db: Any, _ctx: Any, **_kw: Any
                ) -> ProviderDraftReviewRecord | None:
                    return self.review

                async def create_draft_review(
                    self,
                    _db: Any,
                    _ctx: Any,
                    *,
                    head_branch: str,
                    base_branch: str,
                    **_kw: Any,
                ) -> ProviderDraftReviewRecord:
                    self.review = ProviderDraftReviewRecord(
                        external_review_id="e2e-pr-99",
                        number="99",
                        html_url="https://github.com/acme/calc/pull/99",
                        head_branch=head_branch,
                        base_branch=base_branch,
                        head_sha=self.commit_sha,
                        draft=True,
                        state="open",
                    )
                    return self.review

            auto_provider = _AutoProvider()

            class _AutoIntegrations:
                async def resolve_publisher_target(
                    self,
                    *,
                    workspace_id: str,
                    repository_id: str,
                ) -> tuple[Any, ProviderConnectionContext, str]:
                    _ = repository_id
                    return (
                        auto_provider,
                        ProviderConnectionContext(
                            workspace_id=workspace_id,
                            connection_id="conn-e2e",
                            provider="github",
                            base_url="https://api.github.com",
                            app_id=None,
                            client_id=None,
                            installation_id="inst-e2e",
                            credential_secret_ref="sec-e2e",
                            webhook_secret_ref=None,
                        ),
                        "acme/calc",
                    )

            class _E2eCollector(CiRunCollectorService):
                async def collect_from_trigger(
                    self,
                    *,
                    workspace_id: str,
                    trigger_id: str,
                    correlation_id: str | None = None,
                    now: datetime | None = None,
                ) -> CiRun:
                    _ = (trigger_id, correlation_id, now)
                    async with workspace_rls_session(
                        self._session_factory, workspace_id=workspace_id
                    ) as db:
                        row = await db.get(CiRunModel, run_id)
                        assert row is not None
                        return ci_run_model_to_dto(row)

            queue_svc = DurableTaskQueueService(
                session_factory=harness.app_factory,
                signing_key=harness.iam.csrf_signing_key,
                redactor=harness.redactor,
            )
            worker_broker = WorkerBrokerService(
                session_factory=harness.app_factory,
                signing_key=harness.iam.csrf_signing_key,
                queue_service=queue_svc,
                artifact_store=harness.artifact_store,
                master_key_ring=MasterKeyRing(active_version=1, keys={1: b"\x77" * 32}),
                redactor=harness.redactor,
                clock=clock,
            )
            reproducer = ReproductionOrchestrator(
                session_factory=harness.app_factory,
                worker_broker=worker_broker,
                profile_registry=harness.profile_registry,
                redactor=harness.redactor,
            )
            patch_agent = BoundedPatchAgentService(
                session_factory=harness.app_factory,
                state_machine=harness.state_machine,
                reproduction_orchestrator=reproducer,
                meta_inference_service=harness.meta_service,
                budget_ledger=harness.budget_ledger,
                agent_profile_service=harness.agent_profiles,
                artifact_store=harness.artifact_store,
                profile_registry=harness.profile_registry,
                redactor=harness.redactor,
            )
            catalog_svc = RepositoryCatalogService(
                session_factory=harness.app_factory,
                signing_key=harness.iam.csrf_signing_key,
                redactor=harness.redactor,
                clock=clock,
            )
            evidence_priv = Ed25519PrivateKey.generate()
            evidence_key_id = "e2e-manifest-key"
            evidence_trust_domain = "control-plane-verifier"
            manifest_keyring = KeyRing(
                [
                    export_ed25519_public_key_record(
                        private_key=evidence_priv,
                        key_id=evidence_key_id,
                        not_before=clock() - timedelta(days=1),
                        trust_domain=evidence_trust_domain,
                    )
                ]
            )
            verifier = DeterministicVerifier(keyring=manifest_keyring)
            verification_svc = VerificationService(
                session_factory=harness.app_factory,
                verifier=verifier,
                state_machine=harness.state_machine,
                manifest_keyring=manifest_keyring,
                evidence_trust_domain=evidence_trust_domain,
            )
            publisher_saga = PublisherSaga(
                session_factory=harness.app_factory,
                integrations=cast(GitHubIntegrationService, _AutoIntegrations()),
                artifact_store=harness.artifact_store,
                manifest_keyring=manifest_keyring,
                evidence_trust_domain=evidence_trust_domain,
                intent_signing_key=b"e2e-publisher-intent-key-32bytes",
                state_machine=harness.state_machine,
            )

            async def _fetch_archive(_ws_id: str, _repo_id: str, _sha: str) -> bytes:
                return github_tar_bytes

            coordinator = RuntimePipelineCoordinator(
                session_factory=harness.app_factory,
                queue_service=queue_svc,
                collector_service=_E2eCollector(
                    session_factory=harness.app_factory,
                    artifact_store=harness.artifact_store,
                    redactor=harness.redactor,
                    clock=clock,
                ),
                state_machine=harness.state_machine,
                catalog_service=catalog_svc,
                diagnosis_agent=harness.diagnosis_agent,
                patch_agent=patch_agent,
                reproducer=reproducer,
                worker_broker=worker_broker,
                profile_registry=harness.profile_registry,
                verifier=verifier,
                verification_service=verification_svc,
                publisher_saga=publisher_saga,
                artifact_store=harness.artifact_store,
                manifest_signer=evidence_priv,
                manifest_key_id=evidence_key_id,
                manifest_keyring=manifest_keyring,
                evidence_trust_domain=evidence_trust_domain,
                archive_fetcher=_fetch_archive,
                clock=clock,
            )

            # Script Diagnosis (1 turn) + Patch Agent (1 turn)
            scripted_responses.append(
                lambda _r: _U17._meta_chat_response_bytes(
                    model=_U17.PRIMARY_META_MODEL_ID,
                    req_id="req_e2e_diag",
                    content=json.dumps(
                        {
                            "failure_class": "code_regression",
                            "decision": "continue",
                            "summary": "src/calc.py subtracts instead of adding.",
                            "evidence_artifact_ids": [art_id],
                            "hypothesis_statement": "Operator '-' in add(a, b) causes -1 != 5.",
                            "hypothesis_confidence": "high",
                            "suspected_paths": ["src/calc.py"],
                            "uncertainties": [],
                            "proposed_profile": "python-pytest-linux",
                            "proposed_command_ids": ["pytest"],
                        }
                    ),
                )
            )
            scripted_responses.append(
                lambda _r: _U17._meta_chat_response_bytes(
                    model=_U17.PRIMARY_META_MODEL_ID,
                    req_id="req_e2e_patch",
                    content=json.dumps(
                        {
                            "unified_diff": valid_diff,
                            "claimed_root_cause": "Use '+' in add(a, b).",
                            "changed_paths": ["src/calc.py"],
                            "target_test_selection_id": "pytest",
                            "uncertainties": [],
                        }
                    ),
                )
            )

            _, _, template_blobs, _, _, _ = _U18._make_signed_manifest_case(
                workspace_id=workspace_id,
                repository_id=repository_id,
                repair_id=new_uuid7(now=clock()),
                base_sha=base_sha,
                now=clock(),
            )
            template_res = ResultV1.model_validate_json(next(iter(template_blobs.values())))

            async def _complete_latest_sandbox_run(
                *, phase: str, exit_code: int, stdout_text: str, junit_xml: str
            ) -> None:
                async with workspace_rls_session(
                    harness.app_factory, workspace_id=workspace_id
                ) as db:
                    repro = await db.scalar(
                        select(ReproductionRunModel)
                        .where(
                            ReproductionRunModel.workspace_id == workspace_id,
                            ReproductionRunModel.phase == phase,
                        )
                        .order_by(ReproductionRunModel.created_at.desc())
                        .limit(1)
                    )
                    assert repro is not None and repro.sandbox_job_id is not None
                    assert repro.image_digest is not None
                    assert repro.source_archive_digest is not None
                    out_bytes = stdout_text.encode("utf-8")
                    xml_bytes = junit_xml.encode("utf-8")
                    out_art = await persist_encrypted_artifact(
                        db,
                        store=harness.artifact_store,
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        name=f"{phase}-stdout.log",
                        kind="sandbox_stdout",
                        mime="text/plain",
                        plaintext=out_bytes,
                        expected_digest=hashlib.sha256(out_bytes).hexdigest(),
                        now=clock(),
                    )
                    xml_art = await persist_encrypted_artifact(
                        db,
                        store=harness.artifact_store,
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        name=f"{phase}-junit.xml",
                        kind="junit_xml",
                        mime="application/xml",
                        plaintext=xml_bytes,
                        expected_digest=hashlib.sha256(xml_bytes).hexdigest(),
                        now=clock(),
                    )
                    signed_res = sign_model_ed25519(
                        template_res.model_copy(
                            update={
                                "job_id": repro.sandbox_job_id,
                                "lease_epoch": 1,
                                "capability_nonce": f"nonce-{phase}-{repro.sandbox_job_id[:16]}",
                                "worker_id": worker_id,
                                "started_at": clock(),
                                "ended_at": clock(),
                                "exit_code": exit_code,
                                "termination": "exited",
                                "command_digest": (
                                    repro.command_digest or template_res.command_digest
                                ),
                                "image_digest": repro.image_digest,
                                "environment_digest": (
                                    repro.environment_digest or template_res.environment_digest
                                ),
                                "source_digest": repro.source_archive_digest,
                                "patch_digest": repro.patch_digest,
                                "signature": "ed25519:pending",
                            }
                        ),
                        private_key=worker_priv,
                        key_id="worker-e2e-key",
                        domain=DOMAIN_RESULT_V1,
                    )
                    res_json = signed_res.model_dump(mode="json")
                    job_row = await db.get(TaskJobModel, repro.sandbox_job_id)
                    assert job_row is not None
                    job_row.state = "succeeded"
                    db.add(
                        SandboxLeaseModel(
                            id=new_uuid7(now=clock()),
                            workspace_id=workspace_id,
                            repository_id=repository_id,
                            repair_id=repro.repair_id,
                            job_id=repro.sandbox_job_id,
                            worker_id=worker_id,
                            lease_epoch=1,
                            capability_nonce=signed_res.capability_nonce,
                            expected_worker_trust_domain="worker-trust-zone",
                            profile_id=repro.profile_id,
                            profile_revision=repro.profile_revision,
                            image_digest=repro.image_digest,
                            base_sha=base_sha,
                            source_archive_digest=repro.source_archive_digest,
                            patch_digest=repro.patch_digest,
                            network_policy_digest="d" * 64,
                            supervisor_policy_digest="e" * 64,
                            sandbox_job_json={"job_id": repro.sandbox_job_id},
                            upload_slots_json=[],
                            uploaded_artifacts_json=[
                                {"slot_name": "stdout", "id": out_art.id},
                                {"slot_name": "junit_xml", "id": xml_art.id},
                            ],
                            output_bytes_uploaded=len(out_bytes) + len(xml_bytes),
                            status="completed",
                            issued_at=clock(),
                            heartbeat_at=clock(),
                            lease_expires_at=clock() + timedelta(minutes=5),
                            ended_at=clock(),
                            result_digest=sha256_canonical_json(res_json),
                            result_json=res_json,
                            cleanup_verified=True,
                            version=1,
                            created_at=clock(),
                            updated_at=clock(),
                        )
                    )

            # 1) Enqueue ci_run.triage -> creates RepairSessionModel ("received")
            await queue_svc.enqueue_job(
                workspace_id=workspace_id,
                repository_id=repository_id,
                kind="ci_run.triage",
                resource_id=new_uuid7(now=clock()),
                correlation_id="corr-e2e-auto-01",
                payload={"allow_sandbox_execution": True},
                now=clock(),
            )
            assert await coordinator.run_once(now=clock()) is True

            # 2) "received" -> DiagnosisAgent + dispatches Sandbox A ("reproducing")
            assert await coordinator.run_once(now=clock()) is True
            await _complete_latest_sandbox_run(
                phase="baseline_a",
                exit_code=1,
                stdout_text=ci_log,
                junit_xml='<testsuite tests="4" failures="1" skipped="0"/>',
            )

            # 3) "reproducing" -> finalizes Sandbox A -> "repro_confirmed"
            assert await coordinator.run_once(now=clock()) is True

            # 4) "repro_confirmed" -> BoundedPatchAgent + dispatches Sandbox B ("verifying")
            assert await coordinator.run_once(now=clock()) is True
            await _complete_latest_sandbox_run(
                phase="patched_b",
                exit_code=0,
                stdout_text="=== 4 passed in 0.04s ===\n",
                junit_xml='<testsuite tests="4" failures="0" skipped="0"/>',
            )

            # 5) "verifying" -> V-01..V-07 + signed EvidenceManifestV1 -> "policy_gate"
            assert await coordinator.run_once(now=clock()) is True

            # 6) "policy_gate" (auto_repair) -> auto-approval + PublisherSaga -> Draft PR!
            assert await coordinator.run_once(now=clock()) is True

            async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
                rep = await db.scalar(
                    select(RepairSessionModel).where(
                        RepairSessionModel.workspace_id == workspace_id,
                        RepairSessionModel.ci_run_id == run_id,
                    )
                )
                assert rep is not None
                assert rep.state == "remote_validating"
                assert rep.proof_grade == "locally_verified"
                pub_rec = await db.scalar(
                    select(PublicationRecordModel).where(
                        PublicationRecordModel.workspace_id == workspace_id,
                        PublicationRecordModel.repair_id == rep.id,
                    )
                )
                assert pub_rec is not None
                assert pub_rec.status == "published"
                assert pub_rec.url == "https://github.com/acme/calc/pull/99"
            assert auto_provider.review is not None and auto_provider.review.draft is True
            assert auto_provider.files["src/calc.py"] == (
                "def add(a: int, b: int) -> int:\n    return a + b\n"
            )
        finally:
            await harness.app_engine.dispose()
