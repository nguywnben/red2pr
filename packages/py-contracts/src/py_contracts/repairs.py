"""Canonical repairs, verification gates, approvals, publications, and setup (S-11..13, S-18).

Implements:
- S-11: Repair state machine (lower_snake_case per docs/08 + ADR-038) and Diagnosis.
- S-12: Patch, Verification (V-01..V-08), and patch/base/policy-bound Approval.
- S-13: Publication (sanitized URLs without credentials) and RemoteCheck.
- S-18 & A-18: Canonical 10-phase setup wizard (ADR-038), LifecycleOperation, SystemHealthResponse.
"""

from __future__ import annotations

import urllib.parse
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field, StrictBool, StrictInt

from py_contracts.integrations import CiConclusion, GitSha
from py_contracts.primitives import (
    BoundedName,
    BoundedText,
    BoundedUrl,
    InstanceResourceBase,
    InternalId,
    OpaqueProviderId,
    PositiveVersion,
    Sha256Digest,
    StrictContractModel,
    UtcTimestamp,
    WorkspaceResourceBase,
)


def _validate_sanitized_http_url(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("URL must be a string")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must be a valid http or https URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Publication URL must not embed credentials")
    return value


SanitizedHttpUrl = Annotated[BoundedUrl, BeforeValidator(_validate_sanitized_http_url)]

# S-11 Repair & Diagnosis
RepairState = Literal[
    "received",
    "authorized",
    "collecting",
    "triaging",
    "diagnosed_only",
    "unsupported",
    "reproducing",
    "repro_confirmed",
    "repro_unconfirmed",
    "blocked",
    "patching",
    "verifying",
    "rejected",
    "policy_gate",
    "awaiting_approval",
    "expired",
    "publishing",
    "publish_reconcile",
    "needs_human",
    "remote_validating",
    "remote_verified",
    "remote_failed",
    "remote_unknown",
    "cancel_requested",
    "cancelled",
]
ProofGrade = Literal["none", "baseline_confirmed", "locally_verified", "remotely_verified"]
RemoteStatus = Literal["not_published", "pending", "passed", "failed", "unknown"]
SuspensionReason = Literal[
    "maintenance",
    "model_unavailable",
    "quota",
    "worker_unavailable",
    "operator_pause",
]


class RepairSuspension(StrictContractModel):
    """Pause/suspension metadata on a nonterminal repair session (docs/08)."""

    reason: SuspensionReason
    checkpoint_state: RepairState
    requested_by: BoundedName
    at: UtcTimestamp


class Repair(WorkspaceResourceBase):
    """S-11 autonomous CI repair session resource."""

    repository_id: InternalId
    run_id: InternalId
    state: RepairState
    proof_grade: ProofGrade
    remote_status: RemoteStatus
    policy_revision: PositiveVersion
    base_sha: GitSha
    parent_id: InternalId | None = None
    suspension: RepairSuspension | None = None
    budget_id: InternalId


DiagnosisClass = Literal[
    "code_regression",
    "test_defect",
    "config",
    "dependency",
    "flaky",
    "infra",
    "network",
    "auth",
    "unsupported",
    "unknown",
]
DiagnosisDecision = Literal["continue", "abstain", "human"]


class Diagnosis(WorkspaceResourceBase):
    """S-11 evidence-backed failure classification and triage decision."""

    repository_id: InternalId
    repair_id: InternalId
    failure_class: DiagnosisClass = Field(alias="class", serialization_alias="class")
    summary: BoundedText
    evidence_refs: list[InternalId]
    uncertainties: list[BoundedText] = Field(default_factory=list)
    proposed_profile: BoundedName | None = None
    decision: DiagnosisDecision


# S-12 Patch, Verification & Approval
VerificationGateId = Literal["V-01", "V-02", "V-03", "V-04", "V-05", "V-06", "V-07", "V-08"]
GateOutcome = Literal["pass", "fail", "unknown", "not_applicable"]


class VerificationGateResult(StrictContractModel):
    """S-12 deterministic verification gate evaluation entry."""

    id: VerificationGateId
    outcome: GateOutcome
    evidence_ids: list[InternalId] = Field(default_factory=list)


class Patch(WorkspaceResourceBase):
    """S-12 candidate patch diff metadata."""

    repository_id: InternalId
    repair_id: InternalId
    base_sha: GitSha
    patch_digest: Sha256Digest
    changed_paths: list[BoundedText]
    diff_artifact_id: InternalId
    attempt: Annotated[StrictInt, Field(ge=1, le=5)]


class Verification(WorkspaceResourceBase):
    """S-12 deterministic local/remote verification verdict."""

    repository_id: InternalId
    repair_id: InternalId
    gates: list[VerificationGateResult]
    manifest_id: InternalId


ApprovalIntentType = Literal["publish_draft_pr", "sensitive_path_change", "test_modification"]
ApprovalStatus = Literal["pending", "approved", "rejected", "expired", "revoked"]


class Approval(WorkspaceResourceBase):
    """S-12 human approval bound to exact patch digest, base SHA, and policy revision."""

    repository_id: InternalId
    repair_id: InternalId
    intent_type: ApprovalIntentType
    patch_digest: Sha256Digest
    base_sha: GitSha
    target_ref: BoundedName
    policy_revision: PositiveVersion
    expires_at: UtcTimestamp
    status: ApprovalStatus
    decision_actor: InternalId | None = None


# S-13 Publication & RemoteCheck
PublicationStatus = Literal[
    "intent",
    "pushing",
    "creating",
    "published",
    "reconciling",
    "failed",
    "unknown",
]
RemoteCheckOutcome = Literal["pending", "passed", "failed", "unknown"]


class Publication(WorkspaceResourceBase):
    """S-13 draft PR/MR publication saga record."""

    repository_id: InternalId
    intent_id: InternalId
    repair_id: InternalId
    branch: BoundedName
    expected_commit_sha: GitSha
    provider_object_id: OpaqueProviderId | None = None
    url: SanitizedHttpUrl | None = None
    status: PublicationStatus


class RemoteCheckObservation(StrictContractModel):
    """Individual provider CI check observation for V-08."""

    check_name: BoundedName
    external_id: OpaqueProviderId
    status: BoundedName
    conclusion: CiConclusion | None = None
    observed_at: UtcTimestamp


class RemoteCheck(WorkspaceResourceBase):
    """S-13 remote CI check-suite verification state on published SHA."""

    repository_id: InternalId
    publication_id: InternalId
    head_sha: GitSha
    expected_check_set_digest: Sha256Digest
    observations: list[RemoteCheckObservation] = Field(default_factory=list)
    outcome: RemoteCheckOutcome


# S-18 Setup Wizard, Lifecycle Operations & A-18 Public Minimal Liveness
SetupWizardPhase = Literal[
    "owner_claim",
    "topology_tls",
    "storage_recovery",
    "workspace_membership",
    "provider_connection",
    "inference_consent",
    "worker_validation",
    "repository_policy",
    "notification_setup",
    "readiness_review",
]
PrerequisiteStatus = Literal[
    "passed",
    "failed",
    "needs_admin",
    "needs_restart",
    "not_configured",
    "blocked",
    "unsupported",
]
SetupReadiness = Literal["not_ready", "ready_monitor", "ready_repair"]


class SetupPrerequisite(StrictContractModel):
    """S-18 onboarding prerequisite check item."""

    id: BoundedName
    status: PrerequisiteStatus
    remediation: BoundedText


class SetupState(InstanceResourceBase):
    """S-18 resumable 10-phase setup wizard checkpoint and readiness state (ADR-038)."""

    phase: SetupWizardPhase
    checkpoint: BoundedName
    prerequisites: list[SetupPrerequisite]
    readiness: SetupReadiness


LifecycleOperationKind = Literal[
    "status",
    "doctor",
    "backup",
    "restore",
    "update",
    "uninstall",
]
LifecycleOperationStatus = Literal["accepted", "running", "succeeded", "failed", "unknown"]


class LifecycleOperation(InstanceResourceBase):
    """S-18 instance lifecycle/maintenance operation record."""

    kind: LifecycleOperationKind
    status: LifecycleOperationStatus
    dry_run: StrictBool
    scope: BoundedName
    approved_manifest_digest: Sha256Digest | None = None
    result_artifact_id: InternalId | None = None


class SystemHealthResponse(StrictContractModel):
    """A-18 public minimal liveness response (zero host/secret/tenant disclosure)."""

    status: Literal["ok", "degraded"]
    service: Literal["red2pr-control-plane"] = "red2pr-control-plane"
    api_version: Literal["v1"] = "v1"
    timestamp: UtcTimestamp
