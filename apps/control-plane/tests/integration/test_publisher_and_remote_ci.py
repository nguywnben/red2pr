"""U20 database migration and deterministic V-08 tests (provider APIs remain hermetic)."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import os
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import pgserver
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select, text

from py_contracts.crypto import (
    DOMAIN_RESULT_V1,
    KeyRing,
    canonical_json_bytes,
    export_ed25519_public_key_record,
    sha256_canonical_json,
    sign_model_ed25519,
)
from py_contracts.primitives import new_uuid7
from py_contracts.worker import ResultV1
from red2pr_control.approvals.service import ApprovalService
from red2pr_control.db.base import (
    ApprovalRequestModel,
    PatchAttemptModel,
    PublicationRecordModel,
    RemoteCiCheckModel,
    RepairSessionModel,
    RepositoryModel,
    RepositoryPolicyModel,
    RequiredCheckSetModel,
    SandboxLeaseModel,
    TaskJobModel,
    WorkerModel,
)
from red2pr_control.db.engine import (
    create_admin_engine,
    ensure_compatible_event_loop,
    run_alembic_downgrade,
    run_alembic_upgrade,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.integrations.base import (
    ProviderConnectionContext,
    ProviderDraftReviewRecord,
    ProviderRemoteCheckRecord,
)
from red2pr_control.orchestrator.state_machine import RepairSessionStateMachine
from red2pr_control.publisher.remote_observer import RemoteCiObserver, evaluate_required_checks
from red2pr_control.publisher.saga import PublisherSaga
from red2pr_control.triage_evidence.artifact_store import persist_encrypted_artifact
from red2pr_control.verification.service import VerificationService
from red2pr_control.verification.verifier import (
    DeterministicVerifier,
    create_signed_evidence_manifest,
)

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

APP_ROLE_NAME = "red2pr_app"
APP_ROLE_PASSWORD = "{{SECRET_u20_pg_role}}"


def _remote_check(
    name: str,
    *,
    sha: str = "a" * 40,
    status: str = "completed",
    conclusion: str = "success",
) -> ProviderRemoteCheckRecord:
    return ProviderRemoteCheckRecord(
        external_check_id=f"id-{name}",
        name=name,
        head_sha=sha,
        status=status,
        conclusion=conclusion,
    )


def test_v08_requires_all_configured_contexts_on_the_published_sha() -> None:
    verdict = evaluate_required_checks(
        expected_sha="a" * 40,
        required_names=("build", "tests"),
        checks=(_remote_check("build"), _remote_check("tests")),
    )
    assert verdict.outcome == "passed"

    missing = evaluate_required_checks(
        expected_sha="a" * 40,
        required_names=("build", "tests"),
        checks=(_remote_check("build", sha="b" * 40),),
    )
    assert missing.outcome == "pending"
    assert missing.missing_required == ("tests",)
    assert missing.wrong_sha_required == ("build",)


@pytest.mark.parametrize("conclusion", ["failure", "skipped", "neutral", "cancelled", None])
def test_v08_terminal_non_success_never_promotes_remote_proof(conclusion: str | None) -> None:
    check = _remote_check("build", conclusion=conclusion or "")
    result = evaluate_required_checks(
        expected_sha="a" * 40,
        required_names=("build",),
        checks=(check,),
    )
    assert result.outcome == "failed"


def test_v08_empty_required_set_and_running_duplicate_are_not_green() -> None:
    empty = evaluate_required_checks(expected_sha="a" * 40, required_names=(), checks=())
    assert empty.outcome == "unknown"
    running = evaluate_required_checks(
        expected_sha="a" * 40,
        required_names=("build",),
        checks=(
            _remote_check("build"),
            _remote_check("build", status="in_progress", conclusion="success"),
        ),
    )
    assert running.outcome == "pending"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "exact_sha",
        "required_names",
        "expected_outcome",
        "expected_state",
        "expected_proof",
    ),
    [
        (True, ["build"], "passed", "remote_verified", "remotely_verified"),
        (False, ["build"], "pending", "remote_validating", "locally_verified"),
        (True, [], "unknown", "remote_unknown", "locally_verified"),
    ],
)
async def test_v08_observer_persists_exact_sha_proof_transition(
    migrated_db,
    tmp_path,
    exact_sha,
    required_names,
    expected_outcome,
    expected_state,
    expected_proof,
) -> None:
    helpers_path = Path(__file__).with_name("test_agents_and_state_machine.py")
    helpers_spec = importlib.util.spec_from_file_location("u17_u20_test_helpers", helpers_path)
    assert helpers_spec is not None and helpers_spec.loader is not None
    helpers = importlib.util.module_from_spec(helpers_spec)
    sys.modules[helpers_spec.name] = helpers
    helpers_spec.loader.exec_module(helpers)

    now = helpers.ManualClock()
    harness = helpers._build_u17_harness(
        _app_url(migrated_db.admin_url), clock=now, store_dir=tmp_path / "u20-observer-artifacts"
    )

    class _Adapter:
        async def get_remote_checks(self, _db, _ctx, *, head_sha: str, **_kwargs):
            observed_sha = head_sha if exact_sha else "d" * 40
            return (_remote_check("build", sha=observed_sha),)

    class _Integrations:
        async def resolve_publisher_target(self, *, workspace_id: str, repository_id: str):
            ctx = ProviderConnectionContext(
                workspace_id=workspace_id,
                connection_id="provider-connection",
                provider="github",
                base_url="https://api.github.com",
                app_id=None,
                client_id=None,
                installation_id="installation-id",
                credential_secret_ref="credential-ref",
                webhook_secret_ref=None,
            )
            return _Adapter(), ctx, "acme/fixture"

    async def exercise() -> None:
        (
            client,
            _csrf,
            _owner_id,
            workspace_id,
            repository_id,
        ) = await helpers._bootstrap_workspace_and_repo(
            harness, clock=now, ws_slug="u20-v08-observer", ws_name="U20 V08 Observer"
        )
        await client.aclose()
        (
            run_id,
            _job_id,
            _artifact_id,
            _fingerprint,
        ) = await helpers._seed_ci_run_job_and_log_artifact(
            harness,
            workspace_id=workspace_id,
            repository_id=repository_id,
            head_sha="a" * 40,
            job_name="pytest",
            ci_failure_log="FAILED test.py::test_failure - AssertionError",
            now=now(),
        )
        repair_id, _budget_id = await helpers._create_repair_session_with_budget(
            harness,
            workspace_id=workspace_id,
            repository_id=repository_id,
            ci_run_id=run_id,
            base_sha="a" * 40,
            semantic_key="u20-v08-observer",
            now=now(),
        )
        for state in ("authorized", "collecting", "triaging", "reproducing"):
            await harness.state_machine.transition_session(
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state=state,
                correlation_id="u20-v08-observer-setup",
            )
        await harness.state_machine.transition_session(
            workspace_id=workspace_id,
            repair_id=repair_id,
            target_state="repro_confirmed",
            target_proof_grade="baseline_confirmed",
            correlation_id="u20-v08-observer-setup",
        )
        for state in ("patching", "verifying"):
            await harness.state_machine.transition_session(
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state=state,
                correlation_id="u20-v08-observer-setup",
            )
        await harness.state_machine.transition_session(
            workspace_id=workspace_id,
            repair_id=repair_id,
            target_state="policy_gate",
            target_proof_grade="locally_verified",
            correlation_id="u20-v08-observer-setup",
        )
        await harness.state_machine.transition_session(
            workspace_id=workspace_id,
            repair_id=repair_id,
            target_state="publishing",
            remote_status="pending",
            correlation_id="u20-v08-observer-setup",
        )
        await harness.state_machine.transition_session(
            workspace_id=workspace_id,
            repair_id=repair_id,
            target_state="remote_validating",
            correlation_id="u20-v08-observer-setup",
        )

        required_digest = sha256_canonical_json(required_names)
        approval_id = new_uuid7(now=now())
        publication_id = new_uuid7(now=now())
        pushed_sha = "c" * 40
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            db.add(
                ApprovalRequestModel(
                    id=approval_id,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    intent_type="publish_draft_pr",
                    patch_digest="b" * 64,
                    base_sha="a" * 40,
                    target_ref="refs/heads/main",
                    policy_revision=1,
                    requested_by=None,
                    risk_level="review",
                    scope_description="U20 V-08 observer integration fixture",
                    sensitive_change=False,
                    expires_at=now() + timedelta(hours=1),
                    status="approved",
                    decision="approve",
                    decision_actor=None,
                    decided_at=now(),
                    reason=None,
                    correlation_id="u20-v08-observer",
                    version=2,
                    created_at=now(),
                )
            )
            db.add(
                RequiredCheckSetModel(
                    id=new_uuid7(now=now()),
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    policy_revision=1,
                    names_json=required_names,
                    digest=required_digest,
                    created_at=now(),
                )
            )
            db.add(
                PublicationRecordModel(
                    id=publication_id,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    approval_request_id=approval_id,
                    provider="github",
                    operation="publish_draft",
                    intent_id=new_uuid7(now=now()),
                    correlation_id="u20-v08-observer",
                    marker="<!-- red2pr-publication:fixture -->",
                    branch="red2pr/run/fixture",
                    base_sha="a" * 40,
                    expected_commit_sha=pushed_sha,
                    required_check_set_digest=required_digest,
                    target_ref="refs/heads/main",
                    policy_revision=1,
                    status="published",
                    provider_object_id="pr-1",
                    provider_number="1",
                    url="https://github.com/acme/fixture/pull/1",
                    created_at=now(),
                    updated_at=now(),
                )
            )

        observer = RemoteCiObserver(
            session_factory=harness.app_factory,
            integrations=_Integrations(),
            state_machine=RepairSessionStateMachine(session_factory=harness.app_factory),
        )
        publication, remote = await observer.reconcile(
            workspace_id=workspace_id,
            publication_id=publication_id,
            correlation_id="u20-v08-observer-run",
            now=now(),
        )
        assert publication.status == "published"
        assert remote.head_sha == pushed_sha
        assert remote.expected_check_set_digest == required_digest
        assert remote.outcome == expected_outcome
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            repair = await db.get(RepairSessionModel, repair_id)
            persisted = await db.scalar(
                select(RemoteCiCheckModel).where(
                    RemoteCiCheckModel.workspace_id == workspace_id,
                    RemoteCiCheckModel.publication_id == publication_id,
                )
            )
            assert repair is not None
            assert repair.state == expected_state
            assert repair.proof_grade == expected_proof
            assert persisted is not None and persisted.outcome == expected_outcome

    try:
        await exercise()
    finally:
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_publisher_persists_proof_and_reconciles_timeout_without_duplicate_draft(
    migrated_db, tmp_path
) -> None:
    helpers_path = Path(__file__).with_name("test_agents_and_state_machine.py")
    helpers_spec = importlib.util.spec_from_file_location("u17_u20_saga_helpers", helpers_path)
    assert helpers_spec is not None and helpers_spec.loader is not None
    helpers = importlib.util.module_from_spec(helpers_spec)
    sys.modules[helpers_spec.name] = helpers
    helpers_spec.loader.exec_module(helpers)

    verifier_path = Path(__file__).with_name("test_deterministic_verifier.py")
    verifier_spec = importlib.util.spec_from_file_location("u18_u20_saga_helpers", verifier_path)
    assert verifier_spec is not None and verifier_spec.loader is not None
    verifier_helpers = importlib.util.module_from_spec(verifier_spec)
    sys.modules[verifier_spec.name] = verifier_helpers
    verifier_spec.loader.exec_module(verifier_helpers)

    clock = helpers.ManualClock(datetime.now(tz=UTC))
    harness = helpers._build_u17_harness(
        _app_url(migrated_db.admin_url), clock=clock, store_dir=tmp_path / "u20-saga-artifacts"
    )

    class _Provider:
        base_sha = "a" * 40
        commit_sha = "c" * 40

        def __init__(self) -> None:
            self.branches: dict[str, str] = {}
            self.files: dict[str, str | None] = {}
            self.review: ProviderDraftReviewRecord | None = None
            self.create_review_calls = 0
            self.push_calls = 0

        async def get_branch_head(self, _db, _ctx, *, branch_name: str, **_kwargs):
            if branch_name == "refs/heads/main":
                return self.base_sha
            return self.branches.get(branch_name)

        async def get_file_contents_at_ref(self, _db, _ctx, *, path: str, ref: str, **_kwargs):
            if ref == self.base_sha:
                return "return old()\n"
            return self.files.get(path)

        async def create_branch(self, _db, _ctx, *, branch_name: str, from_sha: str, **_kwargs):
            self.branches[branch_name] = from_sha

        async def push_commit(self, _db, _ctx, *, branch_name: str, file_changes, **_kwargs):
            self.push_calls += 1
            self.branches[branch_name] = self.commit_sha
            self.files.update(file_changes)
            return self.commit_sha

        async def find_review_by_marker(self, _db, _ctx, **_kwargs):
            return self.review

        async def create_draft_review(
            self, _db, _ctx, *, head_branch: str, base_branch: str, **_kwargs
        ):
            self.create_review_calls += 1
            self.review = ProviderDraftReviewRecord(
                external_review_id="fixture-pr-1",
                number="1",
                html_url="https://github.com/acme/fixture/pull/1?token=redacted",
                head_branch=head_branch,
                base_branch=base_branch,
                head_sha=self.commit_sha,
                draft=True,
                state="open",
            )
            if self.create_review_calls == 1:
                raise TimeoutError("simulated response timeout after provider created the draft")
            return self.review

        async def get_remote_checks(self, _db, _ctx, *, head_sha: str, **_kwargs):
            return (_remote_check("build", sha=head_sha),)

    provider = _Provider()

    class _Integrations:
        async def resolve_publisher_target(self, *, workspace_id: str, repository_id: str):
            ctx = ProviderConnectionContext(
                workspace_id=workspace_id,
                connection_id="provider-connection",
                provider="github",
                base_url="https://api.github.com",
                app_id=None,
                client_id=None,
                installation_id="installation-id",
                credential_secret_ref="credential-ref",
                webhook_secret_ref=None,
            )
            return provider, ctx, "acme/fixture"

    async def exercise() -> None:
        (
            client,
            _csrf,
            owner_id,
            workspace_id,
            repository_id,
        ) = await helpers._bootstrap_workspace_and_repo(
            harness, clock=clock, ws_slug="u20-publisher-saga", ws_name="U20 Publisher Saga"
        )
        await client.aclose()
        base_sha = "a" * 40
        (
            run_id,
            _job_id,
            _ci_artifact_id,
            _fingerprint,
        ) = await helpers._seed_ci_run_job_and_log_artifact(
            harness,
            workspace_id=workspace_id,
            repository_id=repository_id,
            head_sha=base_sha,
            job_name="pytest",
            ci_failure_log="FAILED tests/test_sample.py::test_sample - AssertionError",
            now=clock(),
        )
        repair_id, _budget_id = await helpers._create_repair_session_with_budget(
            harness,
            workspace_id=workspace_id,
            repository_id=repository_id,
            ci_run_id=run_id,
            base_sha=base_sha,
            semantic_key="u20-publisher-saga",
            now=clock(),
        )

        policy_id = new_uuid7(now=clock())
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            repo = await db.scalar(
                select(RepositoryModel).where(
                    RepositoryModel.workspace_id == workspace_id,
                    RepositoryModel.id == repository_id,
                )
            )
            assert repo is not None
            repo.mode = "approval"
            repo.policy_revision = 1
            db.add(
                RepositoryPolicyModel(
                    id=policy_id,
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
        (
            manifest,
            _original_keyring,
            proof_blobs,
            trust_domain,
            evidence_private_key,
            _old_diff,
        ) = verifier_helpers._make_signed_manifest_case(
            workspace_id=workspace_id,
            repository_id=repository_id,
            repair_id=repair_id,
            base_sha=base_sha,
            now=clock(),
        )
        worker_private_key = Ed25519PrivateKey.generate()
        baseline_result = ResultV1.model_validate_json(proof_blobs[manifest.baseline_result_job_id])
        patched_result = ResultV1.model_validate_json(proof_blobs[manifest.patched_result_job_id])
        baseline_result = sign_model_ed25519(
            baseline_result,
            private_key=worker_private_key,
            key_id="worker-proof-key",
            domain=DOMAIN_RESULT_V1,
        )
        patched_result = sign_model_ed25519(
            patched_result.model_copy(
                update={"patch_digest": diff_digest, "signature": "ed25519:pending"}
            ),
            private_key=worker_private_key,
            key_id="worker-proof-key",
            domain=DOMAIN_RESULT_V1,
        )
        proof_blobs[manifest.baseline_result_job_id] = canonical_json_bytes(
            baseline_result.model_dump(mode="json", by_alias=True)
        )
        proof_blobs[manifest.patched_result_job_id] = canonical_json_bytes(
            patched_result.model_dump(mode="json", by_alias=True)
        )
        manifest_payload = manifest.model_dump(mode="json", by_alias=True)
        manifest_payload["diff_digest"] = diff_digest
        manifest_payload["baseline_result_digest"] = hashlib.sha256(
            proof_blobs[manifest.baseline_result_job_id]
        ).hexdigest()
        manifest_payload["patched_result_digest"] = hashlib.sha256(
            proof_blobs[manifest.patched_result_job_id]
        ).hexdigest()
        manifest = create_signed_evidence_manifest(
            manifest_payload,
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
        worker_id = baseline_result.worker_id
        assert patched_result.worker_id == worker_id
        async with instance_rls_session(harness.app_factory, mode="instance_only") as db:
            db.add(
                WorkerModel(
                    id=worker_id,
                    host_id="u20-hermetic-worker",
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
                    mtls_cert_serial="u20-hermetic-01",
                    mtls_cert_fingerprint_sha256=hashlib.sha256(worker_id.encode()).hexdigest(),
                    mtls_cert_pem="-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
                    mtls_cert_expires_at=clock() + timedelta(days=1),
                    active_signer_key_id="worker-proof-key",
                    last_workspace_id=workspace_id,
                    host_escape_risk_acknowledged=True,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
        for result in (baseline_result, patched_result):
            result_json = result.model_dump(mode="json")
            async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
                db.add(
                    TaskJobModel(
                        id=result.job_id,
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        repair_id=repair_id,
                        kind="sandbox.execute",
                        is_repair_job=True,
                        resource_id=repair_id,
                        state="succeeded",
                        priority=100,
                        dedup_key=None,
                        logical_effect_key=f"u20-proof:{result.job_id}",
                        budget_key=None,
                        correlation_id="u20-proof-results",
                        payload_json={"repair_id": repair_id},
                        attempt=1,
                        max_attempts=1,
                        lease_epoch=1,
                        leased_by_worker_id=worker_id,
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
                        job_id=result.job_id,
                        worker_id=worker_id,
                        lease_epoch=result.lease_epoch,
                        capability_nonce=result.capability_nonce,
                        expected_worker_trust_domain="worker-trust-zone",
                        profile_id="python-pytest-linux",
                        profile_revision=1,
                        image_digest=result.image_digest,
                        base_sha=base_sha,
                        source_archive_digest=result.source_digest,
                        patch_digest=result.patch_digest,
                        network_policy_digest="d" * 64,
                        supervisor_policy_digest="e" * 64,
                        sandbox_job_json={"job_id": result.job_id},
                        upload_slots_json=[],
                        uploaded_artifacts_json=[],
                        output_bytes_uploaded=0,
                        status="completed",
                        issued_at=result.started_at,
                        heartbeat_at=result.ended_at,
                        lease_expires_at=result.ended_at + timedelta(minutes=5),
                        ended_at=result.ended_at,
                        result_digest=sha256_canonical_json(result_json),
                        result_json=result_json,
                        cleanup_verified=True,
                        version=1,
                        created_at=result.started_at,
                        updated_at=result.ended_at,
                    )
                )
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            diff_artifact = await persist_encrypted_artifact(
                db,
                store=harness.artifact_store,
                workspace_id=workspace_id,
                repository_id=repository_id,
                name="verified.patch",
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
                    diff_artifact_id=diff_artifact.id,
                    changed_paths_json=["src/fix.py"],
                    diff_lines_added=1,
                    diff_lines_removed=1,
                    claimed_root_cause="Verified provider-side sample repair",
                    target_test_selection_id=None,
                    integrity_outcome="accepted",
                    sandbox_reproduction_id=None,
                    provenance_json=[],
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )

        for state in ("authorized", "collecting", "triaging", "reproducing"):
            await harness.state_machine.transition_session(
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state=state,
                correlation_id="u20-publisher-state-setup",
            )
        await harness.state_machine.transition_session(
            workspace_id=workspace_id,
            repair_id=repair_id,
            target_state="repro_confirmed",
            target_proof_grade="baseline_confirmed",
            correlation_id="u20-publisher-state-setup",
        )
        for state in ("patching", "verifying"):
            await harness.state_machine.transition_session(
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state=state,
                correlation_id="u20-publisher-state-setup",
            )
        verification = VerificationService(
            session_factory=harness.app_factory,
            verifier=DeterministicVerifier(keyring=manifest_keyring),
            state_machine=harness.state_machine,
            manifest_keyring=manifest_keyring,
            evidence_trust_domain=trust_domain,
        )
        proof = await verification.verify(
            workspace_id=workspace_id,
            repair_id=repair_id,
            verification_id=new_uuid7(now=clock()),
            idempotency_key="u20-publisher-verification",
            facts=verifier_helpers._facts_for_signed_manifest(manifest, proof_blobs, diff_text),
            signed_manifest=manifest,
            evidence_blobs=proof_blobs,
            correlation_id="u20-publisher-verification",
            now=clock(),
        )
        assert proof.status == "verified"
        assert proof.proof_grade == "locally_verified"
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            approval = await db.scalar(
                select(ApprovalRequestModel).where(
                    ApprovalRequestModel.workspace_id == workspace_id,
                    ApprovalRequestModel.repair_id == repair_id,
                    ApprovalRequestModel.status == "pending",
                )
            )
            assert approval is not None
            approval_id = approval.id
            approval_digest = approval.patch_digest
            approval_revision = approval.policy_revision
        decision = await ApprovalService(session_factory=harness.app_factory).decide(
            workspace_id=workspace_id,
            approval_id=approval_id,
            actor_id=owner_id,
            decision="approve",
            reason="U20 hermetic publication integration approval",
            expected_patch_digest=approval_digest,
            expected_policy_revision=approval_revision,
            idempotency_key=new_uuid7(now=clock()),
            correlation_id="u20-publisher-approval",
            now=clock(),
        )
        assert decision.status == "approved"
        await harness.state_machine.transition_session(
            workspace_id=workspace_id,
            repair_id=repair_id,
            target_state="awaiting_approval",
            correlation_id="u20-publisher-awaiting-approval",
        )
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            repair_before_publish = await db.get(RepairSessionModel, repair_id)
            assert repair_before_publish is not None
            assert repair_before_publish.state == "awaiting_approval"

        required_names = ["build"]
        required_digest = sha256_canonical_json(required_names)

        publisher = PublisherSaga(
            session_factory=harness.app_factory,
            integrations=_Integrations(),
            artifact_store=harness.artifact_store,
            manifest_keyring=manifest_keyring,
            evidence_trust_domain=trust_domain,
            intent_signing_key=b"u20-internal-intent-signing-key-32-bytes",
            state_machine=harness.state_machine,
        )
        first = await publisher.publish_approved(
            workspace_id=workspace_id,
            approval_id=approval_id,
            correlation_id="u20-publisher-first-attempt",
        )
        assert first.status == "reconciling"
        assert provider.create_review_calls == 1
        replay = await publisher.publish_approved(
            workspace_id=workspace_id,
            approval_id=approval_id,
            correlation_id="u20-publisher-replay",
        )
        assert replay.status == "published"
        assert replay.expected_commit_sha == provider.commit_sha
        assert replay.required_check_set_digest == required_digest
        assert provider.push_calls == 1
        assert provider.create_review_calls == 1
        assert replay.url == "https://github.com/acme/fixture/pull/1"
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            derived_check_set = await db.scalar(
                select(RequiredCheckSetModel).where(
                    RequiredCheckSetModel.repository_id == repository_id,
                    RequiredCheckSetModel.policy_revision == approval_revision,
                )
            )
            assert derived_check_set is not None
            assert derived_check_set.names_json == required_names
            assert derived_check_set.digest == required_digest

        observer = RemoteCiObserver(
            session_factory=harness.app_factory,
            integrations=_Integrations(),
            state_machine=harness.state_machine,
        )
        _, remote = await observer.reconcile(
            workspace_id=workspace_id,
            publication_id=replay.id,
            correlation_id="u20-publisher-v08",
            now=clock(),
        )
        assert remote.outcome == "passed"
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            repair = await db.get(RepairSessionModel, repair_id)
            publication_count = await db.scalar(
                select(func.count())
                .select_from(PublicationRecordModel)
                .where(
                    PublicationRecordModel.workspace_id == workspace_id,
                    PublicationRecordModel.repair_id == repair_id,
                )
            )
            assert repair is not None
            assert repair.state == "remote_verified"
            assert repair.proof_grade == "remotely_verified"
            assert publication_count == 1

    try:
        await exercise()
    finally:
        await harness.app_engine.dispose()


@dataclass(frozen=True)
class PgTestUrls:
    admin_url: str


def _app_url(base_uri: str) -> str:
    parsed = urlparse(base_uri)
    return urlunparse(
        (
            "postgresql+psycopg",
            f"{APP_ROLE_NAME}:{APP_ROLE_PASSWORD}@{parsed.hostname or '127.0.0.1'}:{parsed.port}",
            parsed.path or "/postgres",
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


@pytest.fixture(scope="module")
def pg_urls() -> Iterator[PgTestUrls]:
    ensure_compatible_event_loop()
    external = os.environ.get("RED2PR_TEST_ADMIN_DATABASE_URL")
    if external:
        yield PgTestUrls(external)
        return
    with (
        tempfile.TemporaryDirectory(prefix="red2pr_u20_pg16_") as temp_dir,
        pgserver.get_server(temp_dir, cleanup_mode="delete") as server,
    ):
        uri = server.get_uri()
        parsed = urlparse(uri)
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
        yield PgTestUrls(admin_url)


@pytest.fixture
def migrated_db(pg_urls: PgTestUrls) -> Iterator[PgTestUrls]:
    run_alembic_downgrade(pg_urls.admin_url, "base", app_role_name=APP_ROLE_NAME)
    run_alembic_upgrade(
        pg_urls.admin_url,
        "head",
        app_role_name=APP_ROLE_NAME,
        app_role_password=APP_ROLE_PASSWORD,
    )
    yield pg_urls


def test_0016_publication_tables_force_rls_and_rollback_is_reversible(
    migrated_db: PgTestUrls,
) -> None:
    engine = create_admin_engine(migrated_db.admin_url)
    try:

        async def inspect() -> None:
            async with engine.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
                        "WHERE relname IN ('publication_records','required_check_sets',"
                        "'remote_ci_checks')"
                    )
                )
                assert {
                    row.relname: (row.relrowsecurity, row.relforcerowsecurity) for row in rows
                } == {
                    "publication_records": (True, True),
                    "required_check_sets": (True, True),
                    "remote_ci_checks": (True, True),
                }
                immutable_trigger = await conn.scalar(
                    text(
                        "SELECT EXISTS (SELECT 1 FROM pg_trigger "
                        "WHERE tgname='trg_required_check_sets_immutable' AND NOT tgisinternal)"
                    )
                )
                assert immutable_trigger is True
                can_update_required_set = await conn.scalar(
                    text("SELECT has_table_privilege(:role, 'required_check_sets', 'UPDATE')"),
                    {"role": APP_ROLE_NAME},
                )
                assert can_update_required_set is False
                ledger = await conn.scalar(
                    text(
                        "SELECT revision FROM schema_migrations "
                        "WHERE revision='0016_publications_and_remote_checks'"
                    )
                )
                assert ledger == "0016_publications_and_remote_checks"
                required_column = await conn.scalar(
                    text(
                        "SELECT is_nullable FROM information_schema.columns "
                        "WHERE table_schema='public' AND table_name='repository_policies' "
                        "AND column_name='required_check_names_json'"
                    )
                )
                assert required_column == "NO"
                carry_forward_trigger = await conn.scalar(
                    text(
                        "SELECT EXISTS (SELECT 1 FROM pg_trigger "
                        "WHERE tgname='trg_repository_policy_required_checks_carry_forward' "
                        "AND NOT tgisinternal)"
                    )
                )
                assert carry_forward_trigger is True

        asyncio.run(inspect())
        run_alembic_downgrade(
            migrated_db.admin_url,
            "0015_approval_requests_and_votes",
            app_role_name=APP_ROLE_NAME,
        )

        async def assert_dropped() -> None:
            async with engine.connect() as conn:
                for table in ("publication_records", "required_check_sets", "remote_ci_checks"):
                    assert (
                        await conn.scalar(
                            text("SELECT to_regclass(:table)"), {"table": f"public.{table}"}
                        )
                        is None
                    )
                assert (
                    await conn.scalar(
                        text(
                            "SELECT 1 FROM information_schema.columns "
                            "WHERE table_schema='public' AND table_name='repository_policies' "
                            "AND column_name='required_check_names_json'"
                        )
                    )
                    is None
                )

        asyncio.run(assert_dropped())
        run_alembic_upgrade(
            migrated_db.admin_url,
            "head",
            app_role_name=APP_ROLE_NAME,
            app_role_password=APP_ROLE_PASSWORD,
        )
    finally:
        asyncio.run(engine.dispose())
