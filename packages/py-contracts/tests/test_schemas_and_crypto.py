"""Unit, property, and adversarial security tests for U02 canonical schemas (S-06..S-22) and crypto.

Covers:
- S-06..S-18 domain resource DTOs, extra='forbid', non-coerced opaque provider IDs,
  'auditor' in S-07 Membership.role (ADR-038), require_baseline=True invariant (ADR-031),
  and 10-phase setup wizard enum in S-18 (ADR-038).
- S-19 Domain Event Envelope & typed allowlisted payloads (rejecting legacy event names).
- S-20 Typed Agent Tool Protocol (exact 8 tools, path-traversal defense, SEC-028).
- S-21 SandboxJobV1 & ResultV1 (passed_cleanly invariant on timeout/missing exit code).
- S-22 EvidenceManifestV1 provenance & digests.
- Canonical JSON serialization, AES-256-GCM versioned envelope encryption (OPS-03),
  domain-separated Ed25519 signing/verification (SEC-030 1-byte tamper, unknown key,
  wrong domain, revoked-at-signing), and constant-time HMAC-SHA256 / webhook v1 signing.
- Deterministic JSON Schema export parity against contracts/schemas/*.json.
"""

from __future__ import annotations

import pathlib
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from py_contracts.crypto import (
    DOMAIN_EVIDENCE_MANIFEST_V1,
    DOMAIN_RESULT_V1,
    CryptoVerificationError,
    KeyRing,
    MasterKeyRing,
    canonical_json_bytes,
    compute_hmac_sha256_hex,
    decrypt_envelope,
    encrypt_envelope,
    export_ed25519_public_key_record,
    sign_model_ed25519,
    sign_red2pr_webhook_v1,
    verify_hmac_sha256_hex,
    verify_model_ed25519,
    verify_red2pr_webhook_v1,
)
from py_contracts.events import EventEnvelope
from py_contracts.evidence import (
    Artifact,
    ArtifactRecord,
    AuditRecord,
    EvidenceManifestV1,
    ModelToolProvenance,
    ModelUsageRecord,
    RegressionSuiteSummary,
    ReportExportRequest,
)
from py_contracts.iam import Invite, Membership, Session, User, Workspace
from py_contracts.integrations import (
    BulkRepositoryPreviewItem,
    BulkRepositoryPreviewRequest,
    BulkRepositoryPreviewResponse,
    BulkRepositoryUpdateRequest,
    BulkRepositoryUpdateResponse,
    CiJob,
    CiRun,
    Connection,
    ConnectionWrite,
    ConsentCreateRequest,
    EffectiveRepositoryPolicy,
    EndpointRegistrationCreateRequest,
    NotificationDelivery,
    NotificationDestination,
    NotificationPreference,
    PolicyReadinessGates,
    QuietHoursWindow,
    Repository,
    RepositoryCatalogPage,
    RepositoryDetailResponse,
    RepositoryFacetSummary,
    RepositoryPolicy,
    RepositoryPolicyPreviewRequest,
    RepositoryPolicyPreviewResponse,
    RepositoryPolicyRevision,
    RepositoryPolicyStateResponse,
    RepositoryPolicyUpdateRequest,
    RepositoryUpdateRequest,
    SecretPresence,
)
from py_contracts.primitives import Money, new_uuid7
from py_contracts.repairs import (
    SETUP_WIZARD_PHASES,
    Approval,
    Diagnosis,
    LifecycleOperation,
    Patch,
    Publication,
    RemoteCheck,
    RemoteCheckObservation,
    Repair,
    RepairSuspension,
    SetupPrerequisite,
    SetupState,
    SetupStepSubmitRequest,
    SystemHealthResponse,
    Verification,
    VerificationGateResult,
)
from py_contracts.schema_export import render_canonical_json_schemas
from py_contracts.tools import ToolCallRequest, ToolCallResponse
from py_contracts.worker import (
    DeadLetterJobSummary,
    IsolationCheckResult,
    ResultArtifactRef,
    ResultV1,
    SandboxJobV1,
    SandboxResourceLimits,
    SandboxResourceUsage,
    TaskAttemptSummary,
    TaskJob,
    TaskJobActionRequest,
    TaskJobDetail,
    TaskJobPage,
    Worker,
    WorkspaceQueueFairnessSummary,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
SAMPLE_SHA = "a" * 40
SAMPLE_SHA_2 = "b" * 40
SAMPLE_DIGEST = "c" * 64
FIXED_NOW = datetime(2026, 10, 27, 6, 0, 0, tzinfo=UTC)


def test_s06_s07_iam_workspace_membership_includes_auditor_and_forbids_secrets() -> None:
    uid = new_uuid7()
    ws_id = new_uuid7()

    user = User(
        id=uid,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        display_name="Ada Lovelace",
        email="  Ada.Lovelace@Example.COM ",
        status="active",
    )
    assert user.email == "ada.lovelace@example.com"

    # Extra or secret fields on User DTO must fail validation
    with pytest.raises(ValidationError):
        User.model_validate(
            {
                **user.model_dump(mode="json"),
                "password_hash": "$argon2id$v=19$...",
            }
        )

    sess = Session(
        id=new_uuid7(),
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        user_id=uid,
        expires_at=FIXED_NOW + timedelta(hours=12),
        auth_strength="mfa",
        step_up_at=FIXED_NOW,
        grant_epoch=2,
    )
    assert sess.auth_strength == "mfa"

    ws = Workspace(
        id=ws_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        name="Core Platform",
        status="active",
    )
    assert ws.paused is False

    # ADR-038 alignment: S-07 Membership.role MUST include 'auditor'
    for role in ("admin", "maintainer", "reviewer", "viewer", "auditor"):
        member = Membership(
            id=new_uuid7(),
            workspace_id=ws_id,
            version=1,
            created_at=FIXED_NOW,
            updated_at=FIXED_NOW,
            user_id=uid,
            role=role,
        )
        assert member.role == role

    with pytest.raises(ValidationError):
        Membership(
            id=new_uuid7(),
            workspace_id=ws_id,
            version=1,
            created_at=FIXED_NOW,
            updated_at=FIXED_NOW,
            user_id=uid,
            role="superadmin",  # type: ignore[arg-type]
        )

    invite = Invite(
        id=new_uuid7(),
        workspace_id=ws_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        email="Auditor@Example.org",
        role="auditor",
        expires_at=FIXED_NOW + timedelta(days=3),
        status="pending",
    )
    assert invite.email == "auditor@example.org"


def test_s08_s09_s10_s16_integrations_repositories_runs_and_notifications() -> None:
    ws_id = new_uuid7()
    conn_id = new_uuid7()
    repo_id = new_uuid7()

    # S-08 write accepts opaque ref, rejects plaintext secret
    write_ok = ConnectionWrite(
        provider="gitlab",
        base_url="https://gitlab.example.com",
        auth_mode="signed_webhook",
        secret_ref="sec_gitlab_hook_v1",
    )
    assert write_ok.secret_ref == "sec_gitlab_hook_v1"

    with pytest.raises(ValidationError):
        ConnectionWrite(
            provider="github",
            base_url="https://api.github.com",
            auth_mode="github_app",
            secret_ref="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        )

    conn = Connection(
        id=conn_id,
        workspace_id=ws_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        provider="gitlab",
        base_url="https://gitlab.example.com",
        auth_mode="signed_webhook",
        secret_presence=SecretPresence(configured=True, secret_version=1),
        status="ready",
        capabilities={"mr_draft": "available", "signed_webhooks": "available"},
        checked_at=FIXED_NOW,
        vendor_version="19.1.0",
        api_version="v4",
    )
    assert "secret_ref" not in conn.model_dump(mode="json")

    # S-09 RepositoryPolicy enforces ADR-031 require_baseline=True and safe globs
    policy = RepositoryPolicy(
        branch_allowlist=["main", "release/*"],
        file_denylist=["secrets/**"],
        sensitive_rules=[".github/workflows/**"],
        max_attempts=2,
        max_diff_lines=300,
        runtime_profile_id="python-pytest-linux",
    )
    assert policy.require_baseline is True

    with pytest.raises(ValidationError):
        RepositoryPolicy(
            runtime_profile_id="python-pytest-linux",
            require_baseline=False,  # type: ignore[arg-type]
        )

    with pytest.raises(ValidationError):
        RepositoryPolicy(
            file_denylist=["../../etc/passwd"],
            runtime_profile_id="python-pytest-linux",
        )

    # S-09 Repository rejects numeric coercion on external_id
    with pytest.raises(ValidationError):
        Repository.model_validate(
            {
                "id": repo_id,
                "workspace_id": ws_id,
                "version": 1,
                "created_at": "2026-10-27T06:00:00Z",
                "updated_at": "2026-10-27T06:00:00Z",
                "external_id": 99887766,
                "connection_id": conn_id,
                "name": "org/service",
                "default_branch": "main",
                "visibility": "private",
                "mode": "monitor",
                "paused": False,
                "policy_revision": 1,
            }
        )

    repo = Repository(
        id=repo_id,
        workspace_id=ws_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        external_id="99887766",
        connection_id=conn_id,
        name="org/service",
        default_branch="main",
        visibility="private",
        mode="monitor",
        paused=False,
        policy_revision=1,
    )
    assert repo.external_id == "99887766"

    # S-10 CiRun & CiJob preserve opaque attempt_key and retry_of_id
    run_id = new_uuid7()
    ci_run = CiRun(
        id=run_id,
        workspace_id=ws_id,
        repository_id=repo_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        external_id="gl-pipeline-8812",
        attempt_key="gl-pipeline-8812:retry-2",
        head_sha=SAMPLE_SHA,
        ref="refs/heads/main",
        event_type="push",
        status="completed",
        conclusion="failure",
        jobs_complete=True,
    )
    ci_job = CiJob(
        id=new_uuid7(),
        workspace_id=ws_id,
        repository_id=repo_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        external_id="gl-job-55110",
        run_id=run_id,
        name="pytest (py312)",
        matrix_dimensions={"python": "3.12", "os": "ubuntu-24.04"},
        retry_of_id="gl-job-55001",
        started_at=FIXED_NOW - timedelta(minutes=2),
        completed_at=FIXED_NOW,
        conclusion="failure",
    )
    assert ci_run.attempt_key == "gl-pipeline-8812:retry-2"
    assert ci_job.retry_of_id == "gl-job-55001"

    # S-16 Notification destination, delivery, preference
    dest_id = new_uuid7()
    dest = NotificationDestination(
        id=dest_id,
        workspace_id=ws_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        channel="webhook",
        scope="workspace",
        verified_at=FIXED_NOW,
        consent_id=new_uuid7(),
        status="ready",
        secret_presence=SecretPresence(configured=True, secret_version=1),
    )
    delivery = NotificationDelivery(
        id=new_uuid7(),
        workspace_id=ws_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        event_id=new_uuid7(),
        destination_id=dest.id,
        template_revision=1,
        state="possible_duplicate",
        attempt=2,
    )
    pref = NotificationPreference(
        id=new_uuid7(),
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        workspace_id=ws_id,
        event_types=["repair.approval.requested", "worker.quarantined"],
        min_severity="warning",
        quiet_hours=QuietHoursWindow(start_hhmm="22:00", end_hhmm="07:00"),
        timezone="UTC",
    )
    assert delivery.state == "possible_duplicate"
    assert pref.quiet_hours is not None


def test_s11_s12_s13_s18_repairs_verification_publication_and_10_phase_setup() -> None:
    ws_id = new_uuid7()
    repo_id = new_uuid7()
    repair_id = new_uuid7()

    repair = Repair(
        id=repair_id,
        workspace_id=ws_id,
        repository_id=repo_id,
        version=3,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        run_id=new_uuid7(),
        state="needs_human",
        proof_grade="locally_verified",
        remote_status="unknown",
        policy_revision=2,
        base_sha=SAMPLE_SHA,
        target_ref="refs/heads/main",
        suspension=RepairSuspension(
            reason="model_unavailable",
            checkpoint_state="patching",
            requested_by="system",
            at=FIXED_NOW,
        ),
        budget_id=new_uuid7(),
    )
    assert repair.state == "needs_human"

    # Uppercase or non-canonical repair states rejected (doc08)
    with pytest.raises(ValidationError):
        Repair.model_validate({**repair.model_dump(mode="json"), "state": "WAITING_MODEL"})

    diag = Diagnosis.model_validate(
        {
            "id": new_uuid7(),
            "workspace_id": ws_id,
            "repository_id": repo_id,
            "version": 1,
            "created_at": "2026-10-27T06:00:00Z",
            "updated_at": "2026-10-27T06:00:00Z",
            "repair_id": repair_id,
            "class": "code_regression",
            "summary": "Null check missing in token parser",
            "evidence_refs": [new_uuid7()],
            "uncertainties": [],
            "proposed_profile": "python-pytest-linux",
            "decision": "continue",
        }
    )
    assert diag.model_dump(mode="json", by_alias=True)["class"] == "code_regression"

    patch = Patch(
        id=new_uuid7(),
        workspace_id=ws_id,
        repository_id=repo_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        repair_id=repair_id,
        base_sha=SAMPLE_SHA,
        patch_digest=SAMPLE_DIGEST,
        changed_paths=["src/parser.py"],
        diff_artifact_id=new_uuid7(),
        attempt=1,
    )
    verif = Verification(
        id=new_uuid7(),
        workspace_id=ws_id,
        repository_id=repo_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        repair_id=repair_id,
        gates=[
            VerificationGateResult(id="V-01", outcome="pass", evidence_ids=[new_uuid7()]),
            VerificationGateResult(id="V-08", outcome="unknown", evidence_ids=[]),
        ],
        manifest_id=new_uuid7(),
    )
    approval = Approval(
        id=new_uuid7(),
        workspace_id=ws_id,
        repository_id=repo_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        repair_id=repair_id,
        intent_type="publish_draft_pr",
        patch_digest=patch.patch_digest,
        base_sha=SAMPLE_SHA,
        target_ref="refs/heads/main",
        policy_revision=2,
        expires_at=FIXED_NOW + timedelta(hours=24),
        status="pending",
    )
    assert verif.gates[0].id == "V-01"
    assert approval.status == "pending"

    # S-13 Publication rejects unsanitized credentialed URLs
    with pytest.raises(ValidationError):
        Publication(
            id=new_uuid7(),
            workspace_id=ws_id,
            repository_id=repo_id,
            version=1,
            created_at=FIXED_NOW,
            updated_at=FIXED_NOW,
            intent_id=new_uuid7(),
            repair_id=repair_id,
            branch="red2pr/run-1/abcd1234",
            expected_commit_sha=SAMPLE_SHA_2,
            url="https://bot:ghp_secret@github.com/org/repo/pull/12",
            status="published",
        )

    pub = Publication(
        id=new_uuid7(),
        workspace_id=ws_id,
        repository_id=repo_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        intent_id=new_uuid7(),
        repair_id=repair_id,
        branch="red2pr/run-1/abcd1234",
        expected_commit_sha=SAMPLE_SHA_2,
        provider_object_id="12",
        url="https://github.com/org/repo/pull/12",
        status="published",
    )
    rc = RemoteCheck(
        id=new_uuid7(),
        workspace_id=ws_id,
        repository_id=repo_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        publication_id=pub.id,
        head_sha=SAMPLE_SHA_2,
        expected_check_set_digest=SAMPLE_DIGEST,
        observations=[
            RemoteCheckObservation(
                check_name="pytest",
                external_id="chk-1",
                head_sha=SAMPLE_SHA_2,
                status="completed",
                conclusion="success",
                observed_at=FIXED_NOW,
            )
        ],
        outcome="passed",
    )
    assert rc.outcome == "passed"

    # S-18 canonical 10-phase wizard enum (ADR-038 / U07)
    expected_10_phases = (
        "owner_claim",
        "topology_tls",
        "storage_keys",
        "workspace_admin",
        "provider_connect",
        "model_consent",
        "worker_readiness",
        "repo_policy",
        "notifications",
        "readiness_review",
    )
    assert expected_10_phases == SETUP_WIZARD_PHASES
    for phase in expected_10_phases:
        state = SetupState(
            id=new_uuid7(),
            version=1,
            created_at=FIXED_NOW,
            updated_at=FIXED_NOW,
            phase=phase,  # type: ignore[arg-type]
            checkpoint=f"ckpt-{phase}",
            prerequisites=[
                SetupPrerequisite(
                    id="docker_rootless",
                    status="passed",
                    remediation="None required",
                )
            ],
            readiness="ready_monitor",
        )
        assert state.phase == phase
        assert state.ready_monitor is True
        assert state.ready_repair is False

    # Contradictory readiness vs ready_repair flags fail validation
    with pytest.raises(ValidationError):
        SetupState(
            id=new_uuid7(),
            version=1,
            created_at=FIXED_NOW,
            updated_at=FIXED_NOW,
            phase="readiness_review",
            checkpoint="ckpt-bad",
            prerequisites=[],
            readiness="ready_monitor",
            ready_repair=True,
        )

    op = LifecycleOperation(
        id=new_uuid7(),
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        kind="doctor",
        status="succeeded",
        dry_run=True,
        scope="instance",
    )
    health = SystemHealthResponse(status="ok", timestamp=FIXED_NOW)
    assert op.kind == "doctor"
    assert health.api_version == "v1"


def test_s14_s15_s17_s19_s20_s21_artifacts_events_tools_and_worker() -> None:
    ws_id = new_uuid7()
    repo_id = new_uuid7()
    repair_id = new_uuid7()

    # S-14 public Artifact forbids storage_ref leakage
    internal_art = ArtifactRecord(
        id=new_uuid7(),
        workspace_id=ws_id,
        repository_id=repo_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        kind="ci_log",
        mime="text/plain",
        size_bytes=2048,
        digest=SAMPLE_DIGEST,
        storage_ref="s3://internal-bucket/tenant-a/blob-1",
        redaction_version="v1",
        retention_until=FIXED_NOW + timedelta(days=7),
        access_class="restricted",
    )
    public_art = internal_art.to_public_dto(available=True)
    assert "storage_ref" not in public_art.model_dump(mode="json")
    with pytest.raises(ValidationError):
        Artifact.model_validate(
            {
                **public_art.model_dump(mode="json"),
                "storage_ref": "s3://leak",
            }
        )

    # S-17 AuditRecord, ModelUsageRecord (unknown != zero), ReportExportRequest
    audit = AuditRecord(
        id=new_uuid7(),
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        workspace_id=ws_id,
        actor=new_uuid7(),
        action="repository.policy.updated",
        target=repo_id,
        decision="allow",
        reason_code="policy_valid",
        correlation_id="corr-100",
        prev_hash="0" * 64,
        entry_hash=SAMPLE_DIGEST,
    )
    usage = ModelUsageRecord(
        id=new_uuid7(),
        workspace_id=ws_id,
        repository_id=repo_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        reservation_id=new_uuid7(),
        model_id="muse-spark-1.3",
        input_tokens=None,
        output_tokens=None,
        estimated_cost=Money(amount=Decimal("0.12"), currency="USD"),
        settled_cost=None,
        currency="USD",
        pricing_revision="2026-10",
        status="unknown",
    )
    assert audit.decision == "allow"
    assert usage.settled_cost is None

    with pytest.raises(ValidationError):
        ReportExportRequest(
            kind="funnel",
            range_start=FIXED_NOW,
            range_end=FIXED_NOW + timedelta(days=370),
            format="csv",
        )

    # S-19 EventEnvelope enforces canonical doc08 event registry & typed payloads
    evt = EventEnvelope.model_validate(
        {
            "event_id": new_uuid7(),
            "type": "repair.verification.completed",
            "occurred_at": FIXED_NOW,
            "workspace_id": ws_id,
            "repository_id": repo_id,
            "session_id": repair_id,
            "aggregate_id": repair_id,
            "aggregate_version": 5,
            "correlation_id": "corr-evt-1",
            "payload": {
                "repair_id": repair_id,
                "outcome": "locally_verified",
                "manifest_id": new_uuid7(),
            },
        }
    )
    assert evt.schema_version == 1

    # Retired legacy event name rejected
    with pytest.raises(ValidationError):
        EventEnvelope.model_validate(
            {
                "event_id": new_uuid7(),
                "type": "repair.pr_created",
                "occurred_at": FIXED_NOW,
                "workspace_id": ws_id,
                "aggregate_id": repair_id,
                "aggregate_version": 1,
                "correlation_id": "corr-evt-2",
                "payload": {"publication_id": new_uuid7(), "status": "published"},
            }
        )

    # S-20 ToolCallRequest enforces exact 8 tools, bounds, and path traversal guard (SEC-028)
    valid_tool = ToolCallRequest.model_validate(
        {
            "tool_call_id": new_uuid7(),
            "repair_id": repair_id,
            "step_id": "diag-step-1",
            "tool_name": "read_file",
            "arguments": {"path": "src/service/auth.py", "offset": 0, "length": 4096},
            "context_digest": SAMPLE_DIGEST,
        }
    )
    tool_resp = ToolCallResponse.model_validate(
        {
            "tool_call_id": valid_tool.tool_call_id,
            "status": "ok",
            "result": {
                "text": "def verify(): pass\n",
                "digest": SAMPLE_DIGEST,
                "truncated": False,
            },
        }
    )
    assert tool_resp.status == "ok"

    for forbidden_tool in ("run_targeted_tests", "get_run_result", "publish_pr", "run_shell"):
        with pytest.raises(ValidationError):
            ToolCallRequest.model_validate(
                {
                    "tool_call_id": new_uuid7(),
                    "repair_id": repair_id,
                    "step_id": "step-bad",
                    "tool_name": forbidden_tool,
                    "arguments": {},
                    "context_digest": SAMPLE_DIGEST,
                }
            )

    with pytest.raises(ValidationError):
        ToolCallRequest.model_validate(
            {
                "tool_call_id": new_uuid7(),
                "repair_id": repair_id,
                "step_id": "step-traversal",
                "tool_name": "read_file",
                "arguments": {"path": "../../etc/shadow", "offset": 0, "length": 100},
                "context_digest": SAMPLE_DIGEST,
            }
        )

    # S-15 Worker/TaskJob & S-21 SandboxJobV1/ResultV1
    worker = Worker(
        id=new_uuid7(),
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        trust_domain="pool-isolated-linux",
        profile_ids=["python-pytest-linux"],
        capabilities={"rootless_oci": True, "network_none": True},
        heartbeat_at=FIXED_NOW,
        status="online",
    )
    tjob = TaskJob(
        id=new_uuid7(),
        workspace_id=ws_id,
        repository_id=repo_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        kind="sandbox.reproduce",
        resource_id=repair_id,
        state="leased",
        lease_epoch=1,
        attempt=1,
        not_before=FIXED_NOW,
        deadline=FIXED_NOW + timedelta(minutes=30),
    )
    sjob = SandboxJobV1(
        job_id=tjob.id,
        workspace_id=ws_id,
        repository_id=repo_id,
        repair_id=repair_id,
        lease_epoch=1,
        capability_nonce="nonce-abc-123",
        issued_at=FIXED_NOW,
        expires_at=FIXED_NOW + timedelta(minutes=20),
        base_sha=SAMPLE_SHA,
        source_archive_digest=SAMPLE_DIGEST,
        patch_digest=None,
        profile_id="python-pytest-linux",
        profile_revision=1,
        image_digest=SAMPLE_DIGEST,
        command_ids=["pytest-default"],
        resource_limits=SandboxResourceLimits(
            cpu=4,
            memory_bytes=8 * 1024**3,
            disk_bytes=20 * 1024**3,
            pids=512,
            wall_seconds=900,
            output_bytes=16 * 1024**2,
        ),
        network_policy_digest=SAMPLE_DIGEST,
        artifact_upload_capability="cap_upload_v1_opaque",
        expected_worker_trust_domain=worker.trust_domain,
        supervisor_policy_digest=SAMPLE_DIGEST,
    )
    assert sjob.patch_digest is None

    timed_out_res = ResultV1(
        job_id=sjob.job_id,
        lease_epoch=1,
        capability_nonce="nonce-abc-123",
        worker_id=worker.id,
        started_at=FIXED_NOW,
        ended_at=FIXED_NOW + timedelta(minutes=15),
        exit_code=0,
        termination="timeout",
        command_digest=SAMPLE_DIGEST,
        image_digest=SAMPLE_DIGEST,
        environment_digest=SAMPLE_DIGEST,
        source_digest=SAMPLE_DIGEST,
        resource_usage=SandboxResourceUsage(
            wall_ms=900_000,
            max_memory_bytes=1024,
            disk_written_bytes=1024,
            output_bytes=512,
        ),
        artifact_refs=[ResultArtifactRef(id=new_uuid7(), digest=SAMPLE_DIGEST, size=512)],
        isolation_checks=[IsolationCheckResult(check_id="net_none", passed=True)],
        signer_key_id="worker-key-1",
        signature="ed25519:placeholder",
    )
    # Timeout termination can NEVER count as passing tests even if exit_code=0!
    assert timed_out_res.passed_cleanly() is False


def _build_unsigned_manifest(signer_key_id: str, created_at: datetime) -> EvidenceManifestV1:
    art_id = new_uuid7()
    return EvidenceManifestV1(
        manifest_id=new_uuid7(),
        workspace_id=new_uuid7(),
        repository_id=new_uuid7(),
        repair_id=new_uuid7(),
        source_sha=SAMPLE_SHA,
        base_sha=SAMPLE_SHA,
        patched_sha=SAMPLE_SHA_2,
        diff_digest=SAMPLE_DIGEST,
        ci_run_id=new_uuid7(),
        ci_job_ids=[new_uuid7()],
        ci_attempt_key="1",
        profile_id="python-pytest-linux",
        profile_digest=SAMPLE_DIGEST,
        image_digest=SAMPLE_DIGEST,
        dependency_lock_digest=SAMPLE_DIGEST,
        commands_digest=SAMPLE_DIGEST,
        environment_digest=SAMPLE_DIGEST,
        baseline_result_job_id=new_uuid7(),
        baseline_result_digest=SAMPLE_DIGEST,
        patched_result_job_id=new_uuid7(),
        patched_result_digest="d" * 64,
        failure_fingerprint="e" * 64,
        fidelity_grade="F1_TARGETED",
        fidelity_differences=[],
        regression=RegressionSuiteSummary(
            selection_id="full-pytest",
            selection_digest=SAMPLE_DIGEST,
            passed_count=42,
            failed_count=0,
            skipped_count=0,
            result_job_id=new_uuid7(),
        ),
        integrity_outcome="pass",
        security_outcome="pass",
        policy_outcome="pass",
        provenance=[
            ModelToolProvenance(
                model_id="muse-spark-1.3",
                adapter_version="1.0.0",
                provider_request_id="req-meta-01",
                redacted_context_hashes=[SAMPLE_DIGEST],
                tool_call_digests=[SAMPLE_DIGEST],
                usage_record_id=new_uuid7(),
            )
        ],
        redaction_revision="v1",
        artifact_digests={art_id: SAMPLE_DIGEST},
        created_at=created_at,
        signer_key_id=signer_key_id,
        signature="ed25519:unsigned",
    )


def test_sec030_ed25519_manifest_and_result_signing_tamper_revocation_and_domain_separation() -> (
    None
):
    priv_key = Ed25519PrivateKey.generate()
    pub_record = export_ed25519_public_key_record(
        private_key=priv_key,
        key_id="sup-key-2026-10",
        not_before=FIXED_NOW - timedelta(days=1),
        trust_domain="pool-isolated-linux",
    )
    keyring = KeyRing([pub_record])

    unsigned_manifest = _build_unsigned_manifest("sup-key-2026-10", FIXED_NOW)
    signed_manifest = sign_model_ed25519(
        unsigned_manifest,
        private_key=priv_key,
        key_id="sup-key-2026-10",
        domain=DOMAIN_EVIDENCE_MANIFEST_V1,
    )

    # Valid signature passes verification
    verify_model_ed25519(
        signed_manifest,
        keyring=keyring,
        domain=DOMAIN_EVIDENCE_MANIFEST_V1,
        signed_at=signed_manifest.created_at,
        expected_trust_domain="pool-isolated-linux",
    )

    # 1. Tampering 1 byte of EvidenceManifestV1 payload fails verification (SEC-030)
    tampered_manifest = signed_manifest.model_copy(update={"diff_digest": "f" + SAMPLE_DIGEST[1:]})
    with pytest.raises(CryptoVerificationError) as tamper_exc:
        verify_model_ed25519(
            tampered_manifest,
            keyring=keyring,
            domain=DOMAIN_EVIDENCE_MANIFEST_V1,
            signed_at=tampered_manifest.created_at,
        )
    assert tamper_exc.value.code == "invalid_signature"

    # 2. Tampering 1 byte of ResultV1 payload fails verification (SEC-030)
    unsigned_result = ResultV1(
        job_id=new_uuid7(),
        lease_epoch=1,
        capability_nonce="nonce-xyz",
        worker_id=new_uuid7(),
        started_at=FIXED_NOW,
        ended_at=FIXED_NOW + timedelta(seconds=12),
        exit_code=0,
        termination="exited",
        command_digest=SAMPLE_DIGEST,
        image_digest=SAMPLE_DIGEST,
        environment_digest=SAMPLE_DIGEST,
        source_digest=SAMPLE_DIGEST,
        resource_usage=SandboxResourceUsage(
            wall_ms=12_000,
            max_memory_bytes=4096,
            disk_written_bytes=2048,
            output_bytes=1024,
        ),
        artifact_refs=[],
        isolation_checks=[IsolationCheckResult(check_id="seccomp", passed=True)],
        signer_key_id="sup-key-2026-10",
        signature="ed25519:unsigned",
    )
    signed_result = sign_model_ed25519(
        unsigned_result,
        private_key=priv_key,
        key_id="sup-key-2026-10",
        domain=DOMAIN_RESULT_V1,
    )
    assert signed_result.passed_cleanly() is True
    verify_model_ed25519(
        signed_result,
        keyring=keyring,
        domain=DOMAIN_RESULT_V1,
        signed_at=signed_result.ended_at,
        expected_trust_domain="pool-isolated-linux",
    )

    tampered_result = signed_result.model_copy(update={"exit_code": 1})
    with pytest.raises(CryptoVerificationError) as res_tamper_exc:
        verify_model_ed25519(
            tampered_result,
            keyring=keyring,
            domain=DOMAIN_RESULT_V1,
            signed_at=tampered_result.ended_at,
        )
    assert res_tamper_exc.value.code == "invalid_signature"

    # 3. Domain separation: valid ResultV1 signature rejected under EvidenceManifestV1 domain
    with pytest.raises(CryptoVerificationError):
        verify_model_ed25519(
            signed_result,
            keyring=keyring,
            domain=DOMAIN_EVIDENCE_MANIFEST_V1,
            signed_at=signed_result.ended_at,
        )

    # 4. Unknown signer key rejected
    unknown_key_manifest = signed_manifest.model_copy(update={"signer_key_id": "unknown-key-99"})
    with pytest.raises(CryptoVerificationError) as unk_exc:
        verify_model_ed25519(
            unknown_key_manifest,
            keyring=keyring,
            domain=DOMAIN_EVIDENCE_MANIFEST_V1,
            signed_at=signed_manifest.created_at,
        )
    assert unk_exc.value.code == "unknown_signer_key"

    # 5. Revoked-at-signing key rejected, while historical signature prior to rotation passes
    rotated_record = pub_record.model_copy(update={"revoked_at": FIXED_NOW + timedelta(hours=1)})
    rotated_keyring = KeyRing([rotated_record])
    # Signed at FIXED_NOW (< revoked_at) -> still verifiable for historical audit
    verify_model_ed25519(
        signed_manifest,
        keyring=rotated_keyring,
        domain=DOMAIN_EVIDENCE_MANIFEST_V1,
        signed_at=FIXED_NOW,
    )
    # Signed at FIXED_NOW + 2h (>= revoked_at) -> rejected!
    late_manifest = sign_model_ed25519(
        _build_unsigned_manifest("sup-key-2026-10", FIXED_NOW + timedelta(hours=2)),
        private_key=priv_key,
        key_id="sup-key-2026-10",
        domain=DOMAIN_EVIDENCE_MANIFEST_V1,
    )
    with pytest.raises(CryptoVerificationError) as rev_exc:
        verify_model_ed25519(
            late_manifest,
            keyring=rotated_keyring,
            domain=DOMAIN_EVIDENCE_MANIFEST_V1,
            signed_at=late_manifest.created_at,
        )
    assert rev_exc.value.code == "signer_key_revoked"


@given(
    plaintext=st.binary(min_size=0, max_size=4096),
    scope_id=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz0123456789-",
        min_size=3,
        max_size=40,
    ),
)
@settings(max_examples=50, deadline=None)
def test_aes256_gcm_envelope_encryption_roundtrip_and_tamper_rejection(
    plaintext: bytes,
    scope_id: str,
) -> None:
    kek_v1 = b"\x11" * 32
    kek_v2 = b"\x22" * 32
    ring = MasterKeyRing(active_version=2, keys={1: kek_v1, 2: kek_v2})

    aad = {"purpose": "provider_secret", "scope_id": scope_id}
    envelope = encrypt_envelope(plaintext, key_ring=ring, aad_context=aad)
    assert envelope.kek_version == 2

    restored = decrypt_envelope(envelope, key_ring=ring, aad_context=aad)
    assert restored == plaintext

    # Wrong AAD context fails decryption
    with pytest.raises(CryptoVerificationError):
        decrypt_envelope(
            envelope,
            key_ring=ring,
            aad_context={"purpose": "wrong_purpose", "scope_id": scope_id},
        )


def test_canonical_json_key_order_invariance_and_hmac_webhook_v1() -> None:
    a: dict[str, Any] = {"z": 1, "a": {"y": "hello", "b": [3, 2, 1]}}
    b: dict[str, Any] = {"a": {"b": [3, 2, 1], "y": "hello"}, "z": 1}
    assert canonical_json_bytes(a) == canonical_json_bytes(b)

    with pytest.raises(ValueError):
        canonical_json_bytes({"bad": float("nan")})

    secret = b"webhook-signing-secret-key-bytes-0123"
    body = b'{"event_id":"0192ce00-0000-7000-8000-000000000001"}'
    digest = compute_hmac_sha256_hex(secret, body)
    assert verify_hmac_sha256_hex(secret, body, f"sha256={digest}") is True
    assert verify_hmac_sha256_hex(secret, body + b" ", f"sha256={digest}") is False

    sig_header = sign_red2pr_webhook_v1(
        secret=secret,
        timestamp_unix=1_793_080_800,
        delivery_id="deliv-001",
        raw_body=body,
    )
    assert sig_header.startswith("v1,")
    verify_red2pr_webhook_v1(
        secret=secret,
        signature_header=sig_header,
        timestamp_unix=1_793_080_800,
        now_unix=1_793_080_920,
        delivery_id="deliv-001",
        raw_body=body,
    )
    # Clock skew > 300s rejected
    with pytest.raises(CryptoVerificationError) as skew_exc:
        verify_red2pr_webhook_v1(
            secret=secret,
            signature_header=sig_header,
            timestamp_unix=1_793_080_800,
            now_unix=1_793_081_200,
            delivery_id="deliv-001",
            raw_body=body,
        )
    assert skew_exc.value.code == "webhook_timestamp_skew"


def test_exported_json_schemas_match_committed_artifacts_without_drift() -> None:
    rendered = render_canonical_json_schemas()
    schema_dir = REPO_ROOT / "contracts" / "schemas"
    assert set(rendered.keys()) == {
        "s19-event-envelope.v1.schema.json",
        "s20-agent-tool-protocol.v1.schema.json",
        "s21-sandbox-worker.v1.schema.json",
        "s22-evidence-manifest.v1.schema.json",
    }
    for filename, expected_text in rendered.items():
        committed_path = schema_dir / filename
        assert committed_path.is_file(), f"Missing committed JSON Schema: {committed_path}"
        assert committed_path.read_text(encoding="utf-8") == expected_text


def test_u07_consent_and_endpoint_registration_contracts_reject_ssrf_and_secrets() -> None:
    consent = ConsentCreateRequest(
        purpose="inference",
        scope="instance",
        destination="https://api.meta.ai/v1",
        data_classes=["restricted", "workspace_internal", "restricted"],
        policy_notice_acknowledged=True,
    )
    assert consent.data_classes == ["restricted", "workspace_internal"]

    # Secret data class is never allowed for outbound sharing
    with pytest.raises(ValidationError):
        ConsentCreateRequest.model_validate(
            {
                "purpose": "inference",
                "scope": "instance",
                "destination": "https://api.meta.ai/v1",
                "data_classes": ["secret"],
                "policy_notice_acknowledged": True,
            }
        )

    # Workspace-scoped consent requires workspace_id; instance-scoped forbids it
    with pytest.raises(ValidationError):
        ConsentCreateRequest(
            purpose="provider",
            scope="workspace",
            destination="https://gitlab.corp.internal",
            data_classes=["workspace_internal"],
        )

    reg = EndpointRegistrationCreateRequest(
        adapter="gitlab",
        scheme="https",
        host="GitLab.Corp.Internal.",
        port=8443,
        cidrs=["10.24.0.0/16", "10.24.0.0/16", "fd00:1234::/32"],
        ca_ref="ref:ca/corp-root-v1",
    )
    assert reg.host == "gitlab.corp.internal"
    assert reg.cidrs == ["10.24.0.0/16", "fd00:1234::/32"]

    # Forbidden CIDRs & hosts: loopback, cloud metadata, blanket 0.0.0.0/0, integer IPv4
    for bad_cidr in (
        "127.0.0.1/32",
        "169.254.169.254/32",
        "0.0.0.0/0",
        "::1/128",
        "fe80::/10",
        "::ffff:169.254.169.254/128",
    ):
        with pytest.raises(ValidationError):
            EndpointRegistrationCreateRequest(
                adapter="gitlab",
                scheme="https",
                host="gitlab.corp.internal",
                port=443,
                cidrs=[bad_cidr],
            )

    for bad_host in (
        "127.0.0.1",
        "169.254.169.254",
        "::1",
        "[::ffff:169.254.169.254]",
        "2130706433",
        "0x7f.0.0.1",
        "gitlab.corp.internal:8443",
    ):
        with pytest.raises(ValidationError):
            EndpointRegistrationCreateRequest(
                adapter="gitlab",
                scheme="https",
                host=bad_host,
                port=443,
                cidrs=["10.24.0.0/16"],
            )

    step_req = SetupStepSubmitRequest(
        expected_checkpoint="ckpt_1",
        action="save",
        deployment_mode="local",
        public_base_url="http://127.0.0.1:4280",
        tls_mode="loopback_http",
    )
    assert step_req.expected_checkpoint == "ckpt_1"


def test_u08_task_job_queue_and_dlq_contracts() -> None:
    ws_id = new_uuid7()
    repo_id = new_uuid7()
    repair_id = new_uuid7()
    job_id = new_uuid7()
    worker_id = new_uuid7()

    attempt = TaskAttemptSummary(
        id=new_uuid7(),
        job_id=job_id,
        attempt_number=1,
        lease_epoch=1,
        worker_id=worker_id,
        state="orphaned",
        started_at=FIXED_NOW,
        heartbeat_at=FIXED_NOW + timedelta(seconds=15),
        lease_expires_at=FIXED_NOW + timedelta(seconds=75),
        ended_at=FIXED_NOW + timedelta(seconds=90),
        error_code="lease_expired",
        error_detail="Worker missed heartbeat past lease_expires_at.",
    )
    dlq = DeadLetterJobSummary(
        id=new_uuid7(),
        workspace_id=ws_id,
        repository_id=repo_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        original_job_id=job_id,
        kind="repair.verify",
        resource_id=repair_id,
        logical_effect_key="eff:repair:verify:01",
        budget_key="budget:repair:01",
        error_code="lease_expired_reconcile_required",
        error_detail="Orphaned lease had ambiguous side effects requiring reconciliation.",
        attempts=2,
        recoverable=True,
        reconcile_required=True,
        status="open",
    )
    detail = TaskJobDetail(
        id=job_id,
        workspace_id=ws_id,
        repository_id=repo_id,
        repair_id=repair_id,
        version=3,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW + timedelta(seconds=90),
        kind="repair.verify",
        resource_id=repair_id,
        state="dead_letter",
        lease_epoch=1,
        attempt=2,
        not_before=FIXED_NOW,
        deadline=FIXED_NOW + timedelta(minutes=30),
        priority=50,
        max_attempts=3,
        logical_effect_key="eff:repair:verify:01",
        budget_key="budget:repair:01",
        correlation_id="corr-u08-01",
        recoverable=True,
        reconcile_required=True,
        attempts_history=[attempt],
        dead_letter_entry=dlq,
    )
    assert detail.dead_letter_entry is not None
    assert detail.dead_letter_entry.logical_effect_key == "eff:repair:verify:01"
    assert detail.attempts_history[0].state == "orphaned"

    page = TaskJobPage(
        items=[
            TaskJob.model_validate(
                detail.model_dump(exclude={"attempts_history", "dead_letter_entry"})
            )
        ],
        next_cursor=None,
        snapshot_at=FIXED_NOW,
        summary=WorkspaceQueueFairnessSummary(
            max_running_repairs=2,
            active_running_repairs=2,
            queued_count=12,
            leased_count=1,
            running_count=1,
            cancel_requested_count=0,
            dead_letter_count=1,
            workspace_paused=False,
            backpressure_active=True,
            transport_status="healthy",
            transport_detail="Redis 7 wakeup broker reachable.",
        ),
    )
    assert page.summary is not None
    assert page.summary.backpressure_active is True

    # Deadline preceding not_before fails validation
    with pytest.raises(ValidationError):
        TaskJob(
            id=new_uuid7(),
            workspace_id=ws_id,
            version=1,
            created_at=FIXED_NOW,
            updated_at=FIXED_NOW,
            kind="repair.diagnose",
            resource_id=repair_id,
            state="queued",
            lease_epoch=0,
            attempt=1,
            not_before=FIXED_NOW + timedelta(minutes=10),
            deadline=FIXED_NOW + timedelta(minutes=5),
        )

    # TaskJobActionRequest enforces reconciled_outcome only on action='reconcile' and forbids extra
    valid_reconcile = TaskJobActionRequest(
        action="reconcile",
        reason="Verified draft PR was not created upstream.",
        expected_version=3,
        reconciled_outcome="confirmed_absent",
    )
    assert valid_reconcile.reconciled_outcome == "confirmed_absent"

    with pytest.raises(ValidationError):
        TaskJobActionRequest(
            action="requeue",
            reason="Should reject reconciled_outcome when action != reconcile.",
            reconciled_outcome="confirmed_absent",
        )

    with pytest.raises(ValidationError):
        TaskJobActionRequest.model_validate(
            {
                "action": "cancel",
                "reason": "Stop run",
                "unexpected_extra": True,
            }
        )


def test_u09_rs256_github_app_jwt_and_a06_a23_contracts() -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    from py_contracts.crypto import (
        sign_github_app_jwt_rs256,
        validate_rsa_private_key_pem,
        verify_rs256_jwt,
    )
    from py_contracts.integrations import (
        CapabilitySnapshot,
        ConnectionPatchRequest,
        GitHubInstallationConfirmRequest,
        WorkflowHazardFinding,
    )

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = rsa_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    pub_pem = rsa_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    validate_rsa_private_key_pem(priv_pem)
    jwt_token = sign_github_app_jwt_rs256(
        private_key_pem=priv_pem,
        issuer="412009",
        now=FIXED_NOW,
        ttl_seconds=540,
        clock_drift_seconds=60,
    )
    claims = verify_rs256_jwt(jwt_token, public_key_pem=pub_pem, now=FIXED_NOW)
    assert claims["iss"] == "412009"
    assert claims["exp"] - claims["iat"] == 600

    # Rejects > 600s total JWT lifetime
    with pytest.raises(CryptoVerificationError) as exc_info:
        sign_github_app_jwt_rs256(
            private_key_pem=priv_pem,
            issuer="412009",
            now=FIXED_NOW,
            ttl_seconds=541,
            clock_drift_seconds=60,
        )
    assert exc_info.value.code == "invalid_jwt_lifetime"

    # Rejects expired JWT
    with pytest.raises(CryptoVerificationError) as exp_err:
        verify_rs256_jwt(
            jwt_token,
            public_key_pem=pub_pem,
            now=FIXED_NOW + timedelta(minutes=10),
        )
    assert exp_err.value.code == "jwt_expired"

    # Rejects Ed25519 key when RSA is required
    ed_pem = Ed25519PrivateKey.generate().private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    with pytest.raises(CryptoVerificationError) as type_err:
        validate_rsa_private_key_pem(ed_pem)
    assert type_err.value.code == "unsupported_private_key_type"

    # Rejects mutually exclusive secret_ref and private_key_pem
    with pytest.raises(ValidationError):
        ConnectionWrite(
            provider="github",
            base_url="https://api.github.com",
            auth_mode="github_app",
            secret_ref="sec_github_app_v1",
            private_key_pem=priv_pem.decode("utf-8"),
        )

    with pytest.raises(ValidationError):
        ConnectionPatchRequest(
            secret_ref="sec_github_app_v1",
            private_key_pem=priv_pem.decode("utf-8"),
        )

    ws_id = new_uuid7()
    conn_id = new_uuid7()
    snap = CapabilitySnapshot(
        id=new_uuid7(),
        workspace_id=ws_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        connection_id=conn_id,
        provider="github",
        status="ready",
        capabilities={"repo_discovery": "available", "draft_pr": "available"},
        granted_permissions={"contents": "read", "metadata": "read"},
        checked_at=FIXED_NOW,
        api_version="2026-03-10",
    )
    assert snap.api_version == "2026-03-10"

    hazard = WorkflowHazardFinding(
        code="pull_request_target",
        severity="high",
        workflow_path=".github/workflows/pr-target.yml",
        detail="Workflow triggers on pull_request_target with base-repo privileges.",
    )
    repo = Repository(
        id=new_uuid7(),
        workspace_id=ws_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        external_id="700101",
        connection_id=conn_id,
        name="acme-platform/payments-service",
        default_branch="main",
        visibility="private",
        mode="monitor",
        paused=False,
        policy_revision=1,
        workflow_hazard_status="flagged",
        workflow_hazards=[hazard],
        auto_repair_blocked=True,
    )
    assert repo.auto_repair_blocked is True

    confirm_req = GitHubInstallationConfirmRequest(
        installation_id="99001",
        state="st_" + "a" * 32,
    )
    assert confirm_req.installation_id == "99001"


def test_u10_gitlab_webhook_v19_signing_rotation_and_s08_pinned_auth_contracts() -> None:
    import base64

    from py_contracts import (
        ConnectionPatchRequest,
        decode_gitlab_signing_key,
        sign_gitlab_webhook_v19,
        verify_gitlab_legacy_token,
        verify_gitlab_webhook_v19,
    )

    raw_key_1 = b"0123456789abcdef0123456789abcdef"
    whsec_key_1 = "whsec_" + base64.b64encode(raw_key_1).decode("ascii")
    raw_key_2 = b"fedcba9876543210fedcba9876543210"
    whsec_key_2 = "whsec_" + base64.b64encode(raw_key_2).decode("ascii")

    assert decode_gitlab_signing_key(whsec_key_1) == raw_key_1
    body = b'{"object_kind":"pipeline","object_attributes":{"id":7701}}'
    ts = int(FIXED_NOW.timestamp())
    msg_id = "msg_0192ce00aabbccdd"

    sig_v1 = sign_gitlab_webhook_v19(
        secret=whsec_key_1,
        webhook_id=msg_id,
        timestamp_unix=ts,
        raw_body=body,
    )
    assert sig_v1.startswith("v1,")
    assert verify_gitlab_webhook_v19(
        secrets=[whsec_key_1],
        webhook_id=msg_id,
        webhook_timestamp=str(ts),
        webhook_signature=sig_v1,
        raw_body=body,
        now_unix=ts + 120,
    )

    # Rotated key overlap: active = whsec_key_2, previous = whsec_key_1 -> still verifies!
    assert verify_gitlab_webhook_v19(
        secrets=[whsec_key_2, whsec_key_1],
        webhook_id=msg_id,
        webhook_timestamp=str(ts),
        webhook_signature=f"v1,dW5rbm93bg== {sig_v1}",
        raw_body=body,
        now_unix=ts + 60,
    )

    # Expired (>300s skew), tampered body, or missing signature MUST fail (SEC-027)
    assert not verify_gitlab_webhook_v19(
        secrets=[whsec_key_1],
        webhook_id=msg_id,
        webhook_timestamp=str(ts - 301),
        webhook_signature=sig_v1,
        raw_body=body,
        now_unix=ts,
    )
    assert not verify_gitlab_webhook_v19(
        secrets=[whsec_key_1],
        webhook_id=msg_id,
        webhook_timestamp=str(ts),
        webhook_signature=sig_v1,
        raw_body=body + b" ",
        now_unix=ts,
    )
    assert not verify_gitlab_webhook_v19(
        secrets=[whsec_key_1],
        webhook_id=msg_id,
        webhook_timestamp=str(ts),
        webhook_signature=None,
        raw_body=body,
        now_unix=ts,
    )

    with pytest.raises(CryptoVerificationError) as bad_whsec:
        decode_gitlab_signing_key("whsec_@@@not_base64@@@")
    assert bad_whsec.value.code == "invalid_gitlab_signing_key"

    # Constant-time legacy token verification
    assert verify_gitlab_legacy_token(
        secrets=["glwh_legacy_secret_2026"],
        header_token="glwh_legacy_secret_2026",
    )
    assert not verify_gitlab_legacy_token(
        secrets=["glwh_legacy_secret_2026"],
        header_token="glwh_wrong_secret_2026",
    )

    # S-08 write-only access_token & pinned GitLab auth_mode contracts
    gl_write = ConnectionWrite(
        provider="gitlab",
        base_url="https://gitlab.com",
        auth_mode="gitlab_signed_v19",
        display_name="GitLab Cloud Prod",
        access_token="glpat-1234567890abcdef1234",
        webhook_secret=whsec_key_1,
    )
    assert gl_write.auth_mode == "gitlab_signed_v19"

    # Mutually exclusive access_token vs secret_ref / private_key_pem
    with pytest.raises(ValidationError):
        ConnectionWrite(
            provider="gitlab",
            base_url="https://gitlab.com",
            auth_mode="gitlab_legacy_token",
            secret_ref="sec_gl_token_v1",
            access_token="glpat-1234567890abcdef1234",
        )
    with pytest.raises(ValidationError):
        ConnectionPatchRequest(
            secret_ref="sec_gl_token_v1",
            access_token="glpat-1234567890abcdef1234",
        )


def test_u11_webhook_ingress_sync_cursor_and_reconcile_contracts() -> None:
    from py_contracts import (
        ActionReceipt,
        ConnectionDetailResponse,
        ConnectionReconcileRequest,
        ConnectionReconcileResponse,
        ProviderSyncCursor,
        WebhookIngressReceipt,
    )

    ws_id = new_uuid7()
    conn_id = new_uuid7()
    repo_id = new_uuid7()
    inbox_id = new_uuid7()
    trigger_id = new_uuid7()

    ingress = WebhookIngressReceipt(
        inbox_id=inbox_id,
        connection_id=conn_id,
        provider="github",
        delivery_id="deliv-gh-5001-a",
        status="normalized",
        disposition="accepted_trigger",
        duplicate=False,
        trigger_id=trigger_id,
        correlation_id="corr-u11-01",
        received_at=FIXED_NOW,
    )
    assert ingress.status == "normalized"
    assert ingress.disposition == "accepted_trigger"

    cursor = ProviderSyncCursor(
        id=new_uuid7(),
        workspace_id=ws_id,
        version=2,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        connection_id=conn_id,
        repository_id=repo_id,
        provider="github",
        etag='W/"runs-etag-1"',
        high_water_mark_at=FIXED_NOW,
        last_seen_run_id="5001",
        last_stable_page=1,
        overlap_seconds=300,
        poll_interval_seconds=60,
        last_polled_at=FIXED_NOW,
        last_success_at=FIXED_NOW,
        next_poll_after=FIXED_NOW + timedelta(seconds=64),
        last_status="gap_detected",
        history_gap_detected=True,
        history_gap_since=FIXED_NOW - timedelta(days=95),
        history_gap_until=FIXED_NOW - timedelta(days=90),
        history_gap_detail="Offline duration (95d) exceeded provider retention (90d).",
    )
    assert cursor.history_gap_detected is True
    assert cursor.last_status == "gap_detected"

    req = ConnectionReconcileRequest(
        repository_ids=[repo_id],
        acknowledge_history_gap=True,
        force_poll=True,
    )
    assert req.acknowledge_history_gap is True

    op_id = new_uuid7()
    reconcile_resp = ConnectionReconcileResponse(
        receipt=ActionReceipt(
            operation_id=op_id,
            resource_id=conn_id,
            state="succeeded",
            correlation_id="corr-u11-rec",
            status_url=f"/api/v1/operations/{op_id}",
            result_id=conn_id,
        ),
        connection_id=conn_id,
        polled_repository_count=1,
        rate_limited_count=0,
        history_gap_count=1,
        triggers_created_count=1,
        pending_inbox_reconciled_count=1,
        complete_recovery=False,
        sync_cursors=[cursor],
    )
    assert reconcile_resp.complete_recovery is False
    assert len(reconcile_resp.sync_cursors) == 1

    # ConnectionDetailResponse exposes additive sync_cursors (defaulting to [])
    conn_dto = Connection(
        id=conn_id,
        workspace_id=ws_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        provider="github",
        base_url="https://api.github.com",
        auth_mode="github_app",
        secret_presence=SecretPresence(configured=True, secret_version=1),
        webhook_secret_presence=SecretPresence(configured=True, secret_version=1),
        status="ready",
    )
    detail = ConnectionDetailResponse(connection=conn_dto, sync_cursors=[cursor])
    assert detail.sync_cursors[0].history_gap_detected is True

    # Extra unknown properties rejected on StrictContractModel
    with pytest.raises(ValidationError):
        WebhookIngressReceipt.model_validate(
            {
                **ingress.model_dump(mode="json"),
                "raw_secret_leak": "forbidden",
            }
        )


def test_u12_repository_policy_and_preview_contracts_reject_unsafe_globs_and_enforce_baseline() -> (
    None
):
    ws_id = new_uuid7()
    conn_id = new_uuid7()
    repo_id = new_uuid7()
    user_id = new_uuid7()

    # CanonicalGlobPattern normalizes Unicode NFC and accepts clean POSIX globs
    policy = RepositoryPolicy(
        branch_allowlist=["main", "release/*", "feature/**"],
        branch_denylist=["experimental/**"],
        file_allowlist=["src/**", "cafe\u0301/*.py"],
        file_denylist=["secrets/**"],
        sensitive_rules=["migrations/**"],
        allow_test_edits=False,
        allow_config_edits=False,
        max_attempts=3,
        max_diff_lines=400,
        max_calls_per_session=40,
        max_tokens_per_session=250_000,
        max_wall_seconds=1800,
        max_cost_per_session=Money(amount=Decimal("2.50"), currency="USD"),
        require_baseline=True,
        runtime_profile_id="python-3.12-isolated",
    )
    assert "caf\u00e9/*.py" in policy.file_allowlist
    assert policy.require_baseline is True

    # ADR-031 invariant: require_baseline=False is rejected at the schema boundary
    with pytest.raises(ValidationError):
        RepositoryPolicy.model_validate(
            {
                **policy.model_dump(mode="json"),
                "require_baseline": False,
            }
        )

    # SEC-007: CanonicalGlobPattern rejects absolute, Windows drive, backslash, double-slash,
    # dot-segment traversal, and control characters
    for unsafe_glob in (
        "/etc/passwd",
        "C:/Windows/System32/**",
        "src\\main.py",
        "src//nested.py",
        "../outside/**",
        "src/../secret.py",
        "./src/app.py",
        "src/\x00bad.py",
    ):
        with pytest.raises(ValidationError):
            RepositoryPolicy(
                file_allowlist=[unsafe_glob],
                runtime_profile_id="python-3.12-isolated",
            )

    repo = Repository(
        id=repo_id,
        workspace_id=ws_id,
        version=2,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        connection_id=conn_id,
        provider="github",
        external_id="700101",
        name="acme/payments-service",
        organization="acme",
        default_branch="main",
        visibility="private",
        mode="monitor",
        paused=False,
        tags=["tier-1"],
        policy_revision=2,
        grant_review_required=True,
        workflow_hazard_status="clean",
    )
    assert repo.grant_review_required is True
    assert repo.organization == "acme"

    catalog = RepositoryCatalogPage(
        items=[repo],
        next_cursor=None,
        snapshot_at=FIXED_NOW,
        facets=RepositoryFacetSummary(
            tags=["tier-1"],
            organizations=["acme"],
            mode_counts={"monitor": 1},
            paused_count=0,
            hazard_flagged_count=0,
            partial_sync_connection_ids=[],
        ),
    )
    assert catalog.facets.tags == ["tier-1"]

    upd = RepositoryUpdateRequest(
        expected_version=2,
        mode="approval",
        paused=False,
        tags=["tier-1", "payments"],
        acknowledge_grant_review=True,
        reason="Reviewed grants after GitHub App reconnect.",
    )
    assert upd.acknowledge_grant_review is True

    gates = PolicyReadinessGates(
        worker_isolation_ready=True,
        inference_consent_ready=True,
        workflow_hazard_blocked=False,
        grant_review_required=False,
    )
    effective = EffectiveRepositoryPolicy(
        mode="approval",
        effective_mode="approval",
        paused=False,
        effective_paused=False,
        allow_sandbox_execution=True,
        allow_auto_publication=False,
        branch_allowlist=["main"],
        max_attempts=3,
        max_diff_lines=400,
        max_calls_per_session=40,
        max_tokens_per_session=250_000,
        max_wall_seconds=1800,
        max_cost_per_session=Money(amount=Decimal("2.50"), currency="USD"),
        runtime_profile_id="python-3.12-isolated",
        field_sources={"mode": "repository", "require_baseline": "hard_invariant"},
    )
    rev_snap = RepositoryPolicyRevision(
        id=new_uuid7(),
        workspace_id=ws_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        repository_id=repo_id,
        revision=2,
        mode="approval",
        paused=False,
        policy=policy,
        change_reason="Enable approval mode.",
        created_by_user_id=user_id,
    )
    state_resp = RepositoryPolicyStateResponse(
        repository_id=repo_id,
        workspace_id=ws_id,
        current_revision=2,
        mode="approval",
        paused=False,
        policy=policy,
        effective_policy=effective,
        readiness_gates=gates,
        revisions=[rev_snap],
    )
    assert state_resp.current_revision == 2

    pol_upd = RepositoryPolicyUpdateRequest(
        expected_revision=2,
        mode="approval",
        paused=False,
        policy=policy,
        reason="Tighten file allowlist.",
    )
    assert pol_upd.expected_revision == 2

    prev_req = RepositoryPolicyPreviewRequest(
        mode="auto_repair",
        paused=False,
        policy=policy,
        sample_branches=["main"],
        sample_paths=["src/app.py", ".github/workflows/ci.yml", ".env"],
        sample_diff_lines=120,
    )
    prev_resp = RepositoryPolicyPreviewResponse(
        repository_id=repo_id,
        current_revision=2,
        next_revision=3,
        can_apply=True,
        requires_step_up=True,
        readiness_gates=gates,
        effective_policy=effective,
        diff_lines_verdict="allow",
        diff_lines_reason="Within max_diff_lines (400).",
    )
    assert prev_req.sample_diff_lines == 120
    assert prev_resp.next_revision == 3

    bulk_prev_req = BulkRepositoryPreviewRequest(
        repository_ids=[repo_id],
        mode="approval",
        add_tags=["critical"],
    )
    bulk_prev_resp = BulkRepositoryPreviewResponse(
        can_apply_all=True,
        requires_step_up=False,
        items=[
            BulkRepositoryPreviewItem(
                repository_id=repo_id,
                repository_name=repo.name,
                current_version=2,
                current_mode="monitor",
                target_mode="approval",
                current_paused=False,
                target_paused=False,
                can_apply=True,
                requires_step_up=False,
                active_job_count=0,
            )
        ],
    )
    assert bulk_prev_req.repository_ids == [repo_id]
    assert bulk_prev_resp.can_apply_all is True

    bulk_upd_req = BulkRepositoryUpdateRequest(
        repository_ids=[repo_id],
        expected_versions={repo_id: 2},
        mode="approval",
        add_tags=["critical"],
        reason="Roll out approval mode.",
    )
    bulk_upd_resp = BulkRepositoryUpdateResponse(
        updated_repositories=[repo],
    )
    detail_resp = RepositoryDetailResponse(
        repository=repo,
        connection_status="ready",
        current_policy_revision=2,
        policy=policy,
        effective_policy=effective,
        readiness_gates=gates,
    )
    assert bulk_upd_req.expected_versions[repo_id] == 2
    assert len(bulk_upd_resp.updated_repositories) == 1
    assert detail_resp.connection_status == "ready"


def test_u12_required_check_names_are_exact_bounded_and_duplicate_free() -> None:
    policy = RepositoryPolicy(
        required_check_names=["unit-tests", "Build / Linux"],
        runtime_profile_id="python-3.12-isolated",
    )
    assert policy.required_check_names == ["unit-tests", "Build / Linux"]

    for names in (
        ["unit-tests", "unit-tests"],
        [" unit-tests"],
        [""],
        ["bad\nname"],
        ["bad\u0085name"],
        ["x" * 121],
        [f"check-{index}" for index in range(129)],
    ):
        with pytest.raises(ValidationError):
            RepositoryPolicy(required_check_names=names, runtime_profile_id="python-3.12-isolated")


def test_u14_worker_mtls_pki_upload_capability_and_a13_contracts() -> None:
    """Verify `U14` X.509 mTLS PKI, upload capability HMAC tickets & `A-13`/`S-15`/`S-21` DTOs."""
    from py_contracts.crypto import (
        CryptoVerificationError,
        build_worker_spiffe_uri,
        generate_worker_ca_keypair,
        generate_worker_csr,
        issue_worker_client_certificate,
        mint_upload_capability_ticket,
        parse_worker_spiffe_uri,
        verify_upload_capability_ticket,
        verify_worker_client_certificate,
    )
    from py_contracts.worker import (
        WorkerEnrollmentCreateRequest,
        WorkspaceWorkerReadinessResponse,
    )

    worker_id = new_uuid7()
    spiffe = build_worker_spiffe_uri(trust_domain="worker-supervisor", worker_id=worker_id)
    assert parse_worker_spiffe_uri(spiffe) == ("worker-supervisor", worker_id)

    ca_cert_pem, ca_key_pem = generate_worker_ca_keypair(now=FIXED_NOW)
    csr_pem, _ = generate_worker_csr(host_id="vm-01.internal", trust_domain="worker-supervisor")
    leaf_pem, serial_hex, fp_hex, expires_at = issue_worker_client_certificate(
        ca_cert_pem=ca_cert_pem,
        ca_private_key_pem=ca_key_pem,
        csr_pem=csr_pem,
        worker_id=worker_id,
        trust_domain="worker-supervisor",
        valid_hours=24,
        now=FIXED_NOW,
    )
    verified = verify_worker_client_certificate(
        cert_der_or_pem=leaf_pem,
        ca_cert_pem=ca_cert_pem,
        now=FIXED_NOW + timedelta(hours=1),
    )
    assert verified.worker_id == worker_id
    assert verified.trust_domain == "worker-supervisor"
    assert verified.serial_hex == serial_hex
    assert verified.fingerprint_sha256 == fp_hex
    assert verified.not_valid_after == expires_at

    # Rogue CA rejection:
    rogue_ca, _ = generate_worker_ca_keypair(now=FIXED_NOW)
    with pytest.raises(CryptoVerificationError):
        verify_worker_client_certificate(
            cert_der_or_pem=leaf_pem,
            ca_cert_pem=rogue_ca,
            now=FIXED_NOW + timedelta(hours=1),
        )

    # Scoped write-only upload capability ticket (`S-21`):
    signing_key = b"\x55" * 32
    job_id = new_uuid7()
    ws_id = new_uuid7()
    repo_id = new_uuid7()
    ticket = mint_upload_capability_ticket(
        signing_key=signing_key,
        job_id=job_id,
        workspace_id=ws_id,
        repository_id=repo_id,
        lease_epoch=2,
        capability_nonce="nonce_u14_01",
        allowed_slots=("stdout", "stderr"),
        max_output_bytes=65536,
        expires_at=FIXED_NOW + timedelta(seconds=60),
    )
    cap = verify_upload_capability_ticket(
        signing_key=signing_key,
        ticket=ticket,
        expected_job_id=job_id,
        now=FIXED_NOW + timedelta(seconds=10),
    )
    assert cap.lease_epoch == 2
    assert cap.allowed_slots == ("stderr", "stdout")

    with pytest.raises(CryptoVerificationError):
        verify_upload_capability_ticket(
            signing_key=signing_key,
            ticket=ticket,
            expected_job_id=job_id,
            now=FIXED_NOW + timedelta(seconds=61),
        )

    # ADR-016: `oci_trusted_local` requires `host_escape_risk_acknowledged=True`:
    with pytest.raises(ValidationError):
        WorkerEnrollmentCreateRequest(
            trust_domain="worker-supervisor",
            profile_ids=["python-3.12-node-22"],
            isolation_mode="oci_trusted_local",
            host_escape_risk_acknowledged=False,
        )

    readiness = WorkspaceWorkerReadinessResponse(
        workspace_id=ws_id,
        ready=True,
        eligible_online_workers=1,
        available_profiles=["python-3.12-node-22"],
        vm_isolation_available=True,
        trusted_local_warning=False,
        active_workspace_leases=[],
        snapshot_at=FIXED_NOW,
    )
    assert readiness.ready is True


def test_u15_runner_profile_manifests_and_adr031_reproduction_contract() -> None:
    """`SAN-02` / `SAN-03` / `ADR-031`: Validate reviewed profile manifests & A/B invariants."""
    from py_contracts.worker import (
        ReproductionRunRecord,
        RunnerProfileCommandSpec,
        RunnerProfileManifest,
        load_reviewed_profile_manifests,
    )

    profiles_dir = REPO_ROOT / "apps" / "worker-supervisor" / "profiles"
    manifests = load_reviewed_profile_manifests(profiles_dir)
    assert set(manifests.keys()) == {
        "python-pytest-linux",
        "node-jest-linux",
        "node-vitest-linux",
        "custom-linux-declared",
    }
    assert len(manifests["python-pytest-linux"].manifest_digest()) == 64
    assert manifests["custom-linux-declared"].requires_isolated_vm_tier is True
    assert manifests["custom-linux-declared"].requires_admin_opt_in is True

    # Shell wrappers and secret env vars in manifests must fail closed:
    with pytest.raises(ValidationError):
        RunnerProfileCommandSpec(
            command_id="bad-shell",
            phase="reproduce",
            argv=["bash", "-c", "pytest"],
            description="Shell wrapper must be rejected",
        )
    with pytest.raises(ValidationError):
        RunnerProfileManifest(
            profile_id="bad-secret-profile",
            revision=1,
            display_name="Bad Secret Profile",
            ecosystem="python",
            platform="linux/amd64",
            base_image="ghcr.io/red2pr/bad",
            image_digest=SAMPLE_DIGEST,
            supported_lockfiles=["uv.lock"],
            env_allowlist=["GITHUB_TOKEN"],
            commands=[
                RunnerProfileCommandSpec(
                    command_id="pytest-repro",
                    phase="reproduce",
                    argv=["python3", "-m", "pytest"],
                    description="Test",
                )
            ],
        )

    ws_id = new_uuid7(now=FIXED_NOW)
    repo_id = new_uuid7(now=FIXED_NOW)
    repair_id = new_uuid7(now=FIXED_NOW)
    run_id = new_uuid7(now=FIXED_NOW)
    job_id = new_uuid7(now=FIXED_NOW)

    # ADR-031: repro_unconfirmed can NEVER set allow_patching=True:
    with pytest.raises(ValidationError):
        ReproductionRunRecord(
            id=new_uuid7(now=FIXED_NOW),
            workspace_id=ws_id,
            version=1,
            created_at=FIXED_NOW,
            updated_at=FIXED_NOW,
            repository_id=repo_id,
            repair_id=repair_id,
            ci_run_id=run_id,
            ci_job_id=job_id,
            phase="baseline_a",
            profile_id="python-pytest-linux",
            profile_revision=1,
            base_sha=SAMPLE_SHA,
            status="repro_unconfirmed",
            fidelity_grade="F2_APPROX",
            handoff_outcome="diagnosis_and_human_handoff",
            allow_patching=True,
            immutable_sealed=True,
            started_at=FIXED_NOW,
            finished_at=FIXED_NOW,
        )

    valid_confirmed = ReproductionRunRecord(
        id=new_uuid7(now=FIXED_NOW),
        workspace_id=ws_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        repository_id=repo_id,
        repair_id=repair_id,
        ci_run_id=run_id,
        ci_job_id=job_id,
        phase="baseline_a",
        profile_id="python-pytest-linux",
        profile_revision=1,
        base_sha=SAMPLE_SHA,
        fingerprint_matched=True,
        executed_tests_count=5,
        passed_tests_count=4,
        failed_tests_count=1,
        exit_code=1,
        termination="exited",
        status="repro_confirmed",
        fidelity_grade="F3_VALIDATED",
        handoff_outcome="proceed_to_patch",
        allow_patching=True,
        allow_publication=False,
        immutable_sealed=True,
        started_at=FIXED_NOW,
        finished_at=FIXED_NOW,
    )
    assert valid_confirmed.allow_patching is True
    assert valid_confirmed.allow_publication is False


def test_u17_s20_tool_schemas_s11_s12_and_agent_profile_contracts() -> None:
    """Verify U17 S-20 closed 8-tool schemas, S-11/S-12 DTOs, and AgentProfile guardrails."""
    from py_contracts import (
        AGENT_TOOL_NAMES,
        DIAGNOSIS_ALLOWED_TOOLS,
        FORBIDDEN_AGENT_CAPABILITIES,
        PATCH_ALLOWED_TOOLS,
        AgentProfile,
        AgentProfileUpdateRequest,
        ContextManifest,
        ContextManifestEntry,
        Diagnosis,
        DiagnosisHypothesis,
        EvidenceLineCitation,
        PatchAttemptRecord,
    )

    assert len(AGENT_TOOL_NAMES) == 8
    assert len(DIAGNOSIS_ALLOWED_TOOLS) == 6
    assert "apply_patch" not in DIAGNOSIS_ALLOWED_TOOLS
    assert "run_targeted_test" not in DIAGNOSIS_ALLOWED_TOOLS
    assert set(PATCH_ALLOWED_TOOLS) == set(AGENT_TOOL_NAMES)
    assert {
        "publish",
        "merge",
        "approve",
        "rotate_secret",
        "edit_policy",
        "send_network_request",
        "run_host_shell",
    } == set(FORBIDDEN_AGENT_CAPABILITIES)

    # AgentProfile rejects granting apply_patch to triage_diagnosis and arbitrary prompt overrides
    with pytest.raises(ValidationError):
        AgentProfile(
            id=new_uuid7(now=FIXED_NOW),
            workspace_id=new_uuid7(now=FIXED_NOW),
            version=1,
            created_at=FIXED_NOW,
            updated_at=FIXED_NOW,
            role_key="triage_diagnosis",
            display_name="Bad Diagnosis Profile",
            description="Invalid tool ceiling",
            model_id="muse-spark-1.3",
            reasoning_effort="medium",
            allowed_tools=["read_file", "apply_patch"],
            immutable_role_tool_ceiling=list(DIAGNOSIS_ALLOWED_TOOLS),
            max_steps=8,
            max_tool_calls_per_step=4,
            max_schema_repair_retries=2,
            enabled=True,
        )

    with pytest.raises(ValidationError):
        AgentProfileUpdateRequest.model_validate(
            {"reasoning_effort": "high", "system_prompt": "override"}
        )

    repo_id = new_uuid7(now=FIXED_NOW)
    art_id = new_uuid7(now=FIXED_NOW)
    citation = EvidenceLineCitation(
        artifact_id=art_id,
        start_line=10,
        end_line=15,
        excerpt_digest=SAMPLE_DIGEST,
    )
    diag = Diagnosis.model_validate(
        {
            "id": new_uuid7(now=FIXED_NOW),
            "workspace_id": new_uuid7(now=FIXED_NOW),
            "version": 1,
            "created_at": FIXED_NOW,
            "updated_at": FIXED_NOW,
            "repository_id": repo_id,
            "repair_id": new_uuid7(now=FIXED_NOW),
            "class": "code_regression",
            "decision": "continue",
            "summary": "Operator bug in calc.py",
            "evidence_refs": [art_id],
            "evidence_citations": [citation.model_dump(mode="json")],
            "hypotheses": [
                DiagnosisHypothesis(
                    id="h1",
                    statement="Wrong operator",
                    confidence="high",
                    suspected_paths=["src/calc.py"],
                ).model_dump(mode="json")
            ],
            "proposed_profile": "python-pytest-linux",
            "proposed_command_ids": ["pytest-repro"],
        }
    )
    assert diag.evidence_citations[0].start_line == 10

    manifest = ContextManifest(
        id=new_uuid7(now=FIXED_NOW),
        workspace_id=diag.workspace_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        repository_id=repo_id,
        repair_id=diag.repair_id,
        base_sha=SAMPLE_SHA,
        policy_revision=1,
        redaction_version="v1",
        cache_key=SAMPLE_DIGEST,
        context_digest=SAMPLE_DIGEST,
        entries=[
            ContextManifestEntry(
                kind="ci_log",
                ref_id=art_id,
                digest=SAMPLE_DIGEST,
                byte_length=128,
            )
        ],
    )
    assert manifest.entries[0].byte_length == 128

    patch_rec = PatchAttemptRecord(
        id=new_uuid7(now=FIXED_NOW),
        workspace_id=diag.workspace_id,
        version=1,
        created_at=FIXED_NOW,
        updated_at=FIXED_NOW,
        repository_id=manifest.repository_id,
        repair_id=diag.repair_id,
        attempt=1,
        base_sha=SAMPLE_SHA,
        patch_digest=SAMPLE_DIGEST,
        diff_artifact_id=new_uuid7(now=FIXED_NOW),
        changed_paths=["src/calc.py"],
        diff_lines_added=1,
        diff_lines_removed=1,
        claimed_root_cause="Fix operator",
        integrity_outcome="accepted",
    )
    assert patch_rec.attempt == 1
