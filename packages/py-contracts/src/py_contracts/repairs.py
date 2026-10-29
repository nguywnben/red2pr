"""Canonical repairs, verification gates, approvals, publications, and setup (S-11..13, S-18).

Implements:
- S-11: Repair state machine (lower_snake_case per docs/08 + ADR-038) and Diagnosis.
- S-12: Patch, Verification (V-01..V-08), and patch/base/policy-bound Approval.
- S-13: Publication (sanitized URLs without credentials) and RemoteCheck.
- S-18 & A-18: Canonical 10-phase setup wizard (ADR-038 / U07), LifecycleOperation,
  SystemHealthResponse.
"""

from __future__ import annotations

import urllib.parse
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field, StrictBool, StrictInt, model_validator

from py_contracts.iam import WorkspaceSlugStr
from py_contracts.integrations import (
    CanonicalGlobPattern,
    CiConclusion,
    ConnectionAuthMode,
    GitSha,
    NotificationChannel,
    OpaqueSecretRef,
    ProviderKind,
    RepositoryMode,
)
from py_contracts.primitives import (
    BoundedName,
    BoundedText,
    BoundedUrl,
    InstanceResourceBase,
    InternalId,
    Money,
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
    target_ref: BoundedName
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
HypothesisConfidence = Literal["high", "medium", "low"]


class EvidenceLineCitation(StrictContractModel):
    """Immutable session-verified artifact line-range citation (`TRI-02`, `SEC-024`)."""

    artifact_id: InternalId
    start_line: Annotated[StrictInt, Field(ge=1)]
    end_line: Annotated[StrictInt, Field(ge=1)]
    excerpt_digest: Sha256Digest

    @model_validator(mode="after")
    def _validate_line_bounds(self) -> EvidenceLineCitation:
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        return self


class DiagnosisHypothesis(StrictContractModel):
    """Structured root-cause hypothesis proposed by the diagnosis agent (`AGT-02`)."""

    id: BoundedName
    statement: BoundedText
    confidence: HypothesisConfidence
    suspected_paths: list[BoundedText] = Field(default_factory=list)


class Diagnosis(WorkspaceResourceBase):
    """S-11 evidence-backed failure classification and triage decision."""

    repository_id: InternalId
    repair_id: InternalId
    failure_class: DiagnosisClass = Field(alias="class", serialization_alias="class")
    summary: BoundedText
    evidence_refs: list[InternalId]
    uncertainties: list[BoundedText] = Field(default_factory=list)
    proposed_profile: BoundedName | None = None
    proposed_command_ids: list[BoundedName] = Field(default_factory=list)
    hypotheses: list[DiagnosisHypothesis] = Field(default_factory=list)
    evidence_citations: list[EvidenceLineCitation] = Field(default_factory=list)
    fingerprint_hash: Sha256Digest | None = None
    model_id: BoundedName | None = None
    schema_repair_retries_used: Annotated[StrictInt, Field(ge=0, le=2)] = 0
    deterministic_rule_id: BoundedName | None = None
    decision: DiagnosisDecision


ContextManifestEntryKind = Literal[
    "ci_log",
    "repo_file",
    "commit_diff",
    "policy_summary",
    "profile_manifest",
]


class ContextManifestEntry(StrictContractModel):
    """Single redacted context slice included in an agent session context manifest."""

    kind: ContextManifestEntryKind
    ref_id: BoundedText
    digest: Sha256Digest
    byte_length: Annotated[StrictInt, Field(ge=0)]
    truncated: StrictBool = False


class ContextManifest(WorkspaceResourceBase):
    """Immutable redacted context manifest isolated by workspace/repo/SHA/policy/redaction."""

    repository_id: InternalId
    repair_id: InternalId
    base_sha: GitSha
    policy_revision: PositiveVersion
    redaction_version: BoundedName
    cache_key: Sha256Digest
    context_digest: Sha256Digest
    entries: list[ContextManifestEntry] = Field(default_factory=list)
    truncated: StrictBool = False


AgentExecutionRole = Literal["diagnosis", "patch"]
AgentStepKind = Literal[
    "model_call",
    "tool_call",
    "schema_repair",
    "abstention",
    "policy_denial",
]
AgentStepStatus = Literal["ok", "denied", "failed", "pending"]


class AgentStepRecord(WorkspaceResourceBase):
    """Immutable audit record of a bounded model call, tool invocation, or policy denial."""

    repository_id: InternalId
    repair_id: InternalId
    agent_role: AgentExecutionRole
    attempt_number: Annotated[StrictInt, Field(ge=0, le=10)]
    step_number: Annotated[StrictInt, Field(ge=1, le=500)]
    step_kind: AgentStepKind
    status: AgentStepStatus
    tool_call_id: InternalId | None = None
    tool_name: BoundedName | None = None
    args_redacted_digest: Sha256Digest | None = None
    result_redacted_digest: Sha256Digest | None = None
    context_digest: Sha256Digest
    deny_reason_code: BoundedName | None = None
    deny_explanation: BoundedText | None = None
    model_id: BoundedName | None = None
    provider_request_id: OpaqueProviderId | None = None
    usage_record_id: InternalId | None = None


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
    "storage_keys",
    "workspace_admin",
    "provider_connect",
    "model_consent",
    "worker_readiness",
    "repo_policy",
    "notifications",
    "readiness_review",
]
SETUP_WIZARD_PHASES: tuple[SetupWizardPhase, ...] = (
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
OPTIONAL_SETUP_PHASES: frozenset[SetupWizardPhase] = frozenset(
    {
        "provider_connect",
        "model_consent",
        "worker_readiness",
        "notifications",
    }
)
SetupStepStatus = Literal["pending", "completed", "not_configured", "degraded", "blocked"]
SetupStepAction = Literal["save", "skip", "back"]
SetupDeploymentMode = Literal["local", "server", "distributed"]
SetupTlsMode = Literal["loopback_http", "reverse_proxy_https", "custom_ca_https"]
SetupStorageBackend = Literal["local", "s3_compatible"]
SetupSandboxBackend = Literal["docker_isolated", "podman_rootless", "remote_vm_worker"]
SetupTelemetryMode = Literal["local_only", "consented_export"]
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


class SetupStepSummary(StrictContractModel):
    """Per-phase durable setup checkpoint summary with redacted configuration draft."""

    phase: SetupWizardPhase
    status: SetupStepStatus
    optional: StrictBool = False
    redacted_draft: dict[str, Any] = Field(default_factory=dict)
    probe_status: PrerequisiteStatus | None = None
    probe_detail: BoundedText | None = None
    updated_at: UtcTimestamp | None = None


class SetupState(InstanceResourceBase):
    """S-18 resumable 10-phase setup wizard checkpoint and readiness state (ADR-038, INS-02)."""

    phase: SetupWizardPhase
    checkpoint: BoundedName
    owner_claimed: StrictBool = False
    prerequisites: list[SetupPrerequisite]
    readiness: SetupReadiness
    ready_monitor: StrictBool = False
    ready_repair: StrictBool = False
    completed_at: UtcTimestamp | None = None
    default_workspace_id: InternalId | None = None
    default_workspace_slug: BoundedName | None = None
    steps: list[SetupStepSummary] = Field(default_factory=list)

    @model_validator(mode="after")
    def _enforce_readiness_flag_consistency(self) -> SetupState:
        expected_monitor = self.readiness in ("ready_monitor", "ready_repair")
        expected_repair = self.readiness == "ready_repair"
        if "ready_monitor" not in self.model_fields_set:
            object.__setattr__(self, "ready_monitor", expected_monitor)
        elif self.ready_monitor != expected_monitor:
            raise ValueError("ready_monitor flag must match SetupState.readiness")
        if "ready_repair" not in self.model_fields_set:
            object.__setattr__(self, "ready_repair", expected_repair)
        elif self.ready_repair != expected_repair:
            raise ValueError("ready_repair flag must match SetupState.readiness")
        return self


class SetupStepSubmitRequest(StrictContractModel):
    """A-01 step mutation input with mandatory expected_checkpoint optimistic locking."""

    expected_checkpoint: BoundedName
    action: SetupStepAction = "save"

    # Phase 2: topology_tls
    deployment_mode: SetupDeploymentMode | None = None
    public_base_url: BoundedUrl | None = None
    tls_mode: SetupTlsMode | None = None

    # Phase 3: storage_keys
    storage_backend: SetupStorageBackend | None = None
    master_key_custody_confirmed: StrictBool | None = None
    backup_retention_days: Annotated[StrictInt, Field(ge=1, le=3650)] | None = None
    artifact_endpoint_id: InternalId | None = None

    # Phase 4: workspace_admin
    workspace_name: BoundedName | None = None
    workspace_slug: WorkspaceSlugStr | None = None

    # Phase 5: provider_connect
    provider: ProviderKind | None = None
    provider_base_url: BoundedUrl | None = None
    auth_mode: ConnectionAuthMode | None = None
    endpoint_registration_id: InternalId | None = None
    provider_consent_id: InternalId | None = None

    # Phase 6: model_consent
    primary_model: BoundedName | None = None
    escalation_model: BoundedName | None = None
    inference_consent_id: InternalId | None = None
    max_cost_per_session: Money | None = None
    max_tokens_per_session: Annotated[StrictInt, Field(ge=1, le=1_000_000)] | None = None
    max_calls_per_session: Annotated[StrictInt, Field(ge=1, le=100)] | None = None

    # Phase 7: worker_readiness
    sandbox_backend: SetupSandboxBackend | None = None
    runtime_profile_id: BoundedName | None = None
    host_escape_risk_acknowledged: StrictBool | None = None
    run_self_test: StrictBool | None = None

    # Phase 8: repo_policy
    default_repo_mode: RepositoryMode | None = None
    require_baseline: StrictBool | None = None
    auto_merge: StrictBool | None = None
    max_attempts: Annotated[StrictInt, Field(ge=1, le=5)] | None = None
    max_diff_lines: Annotated[StrictInt, Field(ge=1, le=2000)] | None = None
    protected_branches: list[CanonicalGlobPattern] | None = None

    # Phase 9: notifications
    channel: NotificationChannel | None = None
    notification_consent_id: InternalId | None = None
    telemetry_mode: SetupTelemetryMode | None = None
    telemetry_consent_id: InternalId | None = None

    # Phase 10: readiness_review
    target_readiness: SetupReadiness | None = None
    notes: BoundedText | None = None

    # Shared write-only opaque secret ref & draft notes (redacted before persistence)
    secret_ref: OpaqueSecretRef | None = None
    draft_notes: dict[BoundedName, BoundedText] | None = None


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
