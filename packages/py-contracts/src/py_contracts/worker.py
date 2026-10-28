"""Canonical worker registry, task jobs, and sandbox execution contracts (S-15, S-21).

Enforces:
- S-15: Worker, TaskJob, TaskAttemptSummary, DeadLetterJobSummary, and queue action schemas.
- S-21: SandboxJobV1 (immutable profile command_ids, bounded resource quotas) and
  ResultV1 (missing exit_code, timeout, or infrastructure_error never passes tests).
"""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictInt, model_validator

from py_contracts.crypto import PublicKeyRecord
from py_contracts.integrations import GitSha
from py_contracts.primitives import (
    BoundedName,
    BoundedReason,
    BoundedText,
    DurationMs,
    InstanceResourceBase,
    InternalId,
    Page,
    PositiveVersion,
    Sha256Digest,
    StrictContractModel,
    UtcTimestamp,
    WorkspaceResourceBase,
)

# S-15 Worker & TaskJob
WorkerStatus = Literal["online", "offline", "draining", "quarantined"]
WorkerIsolationMode = Literal["oci_rootless", "vm_isolated", "oci_trusted_local"]
WorkerAction = Literal["drain", "quarantine", "revoke", "resume"]
SandboxLeaseStatus = Literal[
    "leased",
    "running",
    "completed",
    "cancel_requested",
    "cancelled",
    "expired",
    "quarantined",
]
TaskJobState = Literal[
    "queued",
    "leased",
    "running",
    "succeeded",
    "failed",
    "cancel_requested",
    "cancelled",
    "dead_letter",
]
TaskAttemptState = Literal[
    "leased",
    "running",
    "succeeded",
    "failed",
    "cancelled",
    "orphaned",
]
DeadLetterStatus = Literal["open", "requeued", "reconciled", "discarded"]
QueueTransportStatus = Literal["healthy", "degraded", "unconfigured"]
TaskJobAction = Literal["cancel", "requeue", "reconcile"]
TaskJobReconcileOutcome = Literal["confirmed_absent", "confirmed_applied"]


class Worker(InstanceResourceBase):
    """S-15 enrolled isolated sandbox worker supervisor node."""

    trust_domain: BoundedName
    profile_ids: list[BoundedName]
    capabilities: dict[BoundedName, StrictBool] = Field(default_factory=dict)
    heartbeat_at: UtcTimestamp
    status: WorkerStatus
    host_id: BoundedName | None = None
    isolation_mode: WorkerIsolationMode = "oci_rootless"
    runtime_name: BoundedName | None = None
    cpu_limit: Annotated[StrictInt, Field(ge=1, le=256)] = 4
    memory_limit_bytes: Annotated[StrictInt, Field(ge=1)] = 8_589_934_592
    disk_limit_bytes: Annotated[StrictInt, Field(ge=1)] = 42_949_672_960
    pids_limit: Annotated[StrictInt, Field(ge=1, le=65536)] = 512
    signer_key_id: BoundedName | None = None
    mtls_cert_fingerprint_sha256: Sha256Digest | None = None
    mtls_cert_expires_at: UtcTimestamp | None = None
    quarantine_reason: BoundedText | None = None
    drain_reason: BoundedText | None = None
    active_leases: Annotated[StrictInt, Field(ge=0)] = 0
    host_escape_warning: StrictBool = False


class WorkerFleetSummary(StrictContractModel):
    """UI-S13 / A-13 global isolated worker fleet health and isolation posture counts."""

    total_count: Annotated[StrictInt, Field(ge=0)]
    online_count: Annotated[StrictInt, Field(ge=0)]
    draining_count: Annotated[StrictInt, Field(ge=0)]
    quarantined_count: Annotated[StrictInt, Field(ge=0)]
    offline_count: Annotated[StrictInt, Field(ge=0)]
    vm_isolated_count: Annotated[StrictInt, Field(ge=0)]
    trusted_local_warning_count: Annotated[StrictInt, Field(ge=0)]
    active_leases_count: Annotated[StrictInt, Field(ge=0)]


class WorkerPage(Page[Worker]):
    """A-13 S-04 cursor-paginated worker registry listing with fleet posture summary."""

    summary: WorkerFleetSummary | None = None


class WorkerEnrollmentCreateRequest(StrictContractModel):
    """A-13 instance-owner request to mint a one-use mTLS worker enrollment token."""

    trust_domain: BoundedName
    profile_ids: Annotated[list[BoundedName], Field(min_length=1, max_length=32)]
    isolation_mode: WorkerIsolationMode = "oci_rootless"
    ttl_minutes: Annotated[StrictInt, Field(ge=5, le=120)] = 15
    host_escape_risk_acknowledged: StrictBool = False

    @model_validator(mode="after")
    def _validate_trusted_local_acknowledgement(self) -> Self:
        if self.isolation_mode == "oci_trusted_local" and not self.host_escape_risk_acknowledged:
            raise ValueError(
                "host_escape_risk_acknowledged=true is required for oci_trusted_local (ADR-016)"
            )
        return self


class WorkerEnrollmentCreateResponse(StrictContractModel):
    """A-13 one-time worker enrollment token response (raw token returned once only)."""

    enrollment_id: InternalId
    enrollment_token: BoundedText
    trust_domain: BoundedName
    profile_ids: list[BoundedName]
    isolation_mode: WorkerIsolationMode
    expires_at: UtcTimestamp
    ca_cert_pem: BoundedText


class WorkerActionRequest(StrictContractModel):
    """A-13 operator worker control action (`drain | quarantine | revoke | resume`)."""

    action: WorkerAction
    reason: BoundedReason
    expected_version: PositiveVersion | None = None


class WorkspaceSandboxLeaseSummary(StrictContractModel):
    """UI-S13 workspace-scoped active sandbox lease summary (zero global host leakage)."""

    id: InternalId
    job_id: InternalId
    repository_id: InternalId
    repair_id: InternalId
    profile_id: BoundedName
    lease_epoch: PositiveVersion
    status: SandboxLeaseStatus
    issued_at: UtcTimestamp
    lease_expires_at: UtcTimestamp


class WorkspaceWorkerReadinessResponse(StrictContractModel):
    """UI-S13 scoped sandbox readiness view for non-owner workspace members (`doc34`)."""

    workspace_id: InternalId
    ready: StrictBool
    eligible_online_workers: Annotated[StrictInt, Field(ge=0)]
    available_profiles: list[BoundedName]
    vm_isolation_available: StrictBool
    trusted_local_warning: StrictBool
    active_workspace_leases: list[WorkspaceSandboxLeaseSummary] = Field(default_factory=list)
    degraded_reason: BoundedText | None = None
    snapshot_at: UtcTimestamp


class TaskJob(WorkspaceResourceBase):
    """S-15 durable PostgreSQL-backed task queue job with lease_epoch fencing."""

    kind: BoundedName
    resource_id: InternalId
    state: TaskJobState
    lease_epoch: Annotated[StrictInt, Field(ge=0)]
    attempt: PositiveVersion
    not_before: UtcTimestamp
    deadline: UtcTimestamp
    repair_id: InternalId | None = None
    priority: Annotated[StrictInt, Field(ge=0, le=1000)] = 100
    max_attempts: PositiveVersion = 3
    logical_effect_key: BoundedText | None = None
    budget_key: BoundedText | None = None
    correlation_id: BoundedName | None = None
    leased_by_worker_id: InternalId | None = None
    heartbeat_at: UtcTimestamp | None = None
    lease_expires_at: UtcTimestamp | None = None
    last_error_code: BoundedName | None = None
    last_error_detail: BoundedText | None = None
    cancel_reason: BoundedText | None = None
    recoverable: StrictBool = True
    reconcile_required: StrictBool = False

    @model_validator(mode="after")
    def _validate_deadline(self) -> Self:
        if self.deadline < self.not_before:
            raise ValueError("TaskJob deadline must not precede not_before")
        return self


class TaskAttemptSummary(StrictContractModel):
    """S-15 immutable per-attempt worker lease execution record."""

    id: InternalId
    job_id: InternalId
    attempt_number: PositiveVersion
    lease_epoch: PositiveVersion
    worker_id: InternalId
    state: TaskAttemptState
    started_at: UtcTimestamp
    heartbeat_at: UtcTimestamp
    lease_expires_at: UtcTimestamp
    ended_at: UtcTimestamp | None = None
    error_code: BoundedName | None = None
    error_detail: BoundedText | None = None


class DeadLetterJobSummary(WorkspaceResourceBase):
    """S-15 dead-letter queue record preserving original effect & spend budget keys."""

    original_job_id: InternalId
    kind: BoundedName
    resource_id: InternalId
    logical_effect_key: BoundedText
    budget_key: BoundedText | None = None
    error_code: BoundedName
    error_detail: BoundedText
    attempts: PositiveVersion
    recoverable: StrictBool
    reconcile_required: StrictBool
    status: DeadLetterStatus
    requeued_at: UtcTimestamp | None = None
    requeued_by_user_id: InternalId | None = None


class WorkspaceQueueFairnessSummary(StrictContractModel):
    """UI-S14 / NFR-05 per-workspace concurrency cap, fairness, and transport health summary."""

    max_running_repairs: PositiveVersion
    active_running_repairs: Annotated[StrictInt, Field(ge=0)]
    queued_count: Annotated[StrictInt, Field(ge=0)]
    leased_count: Annotated[StrictInt, Field(ge=0)]
    running_count: Annotated[StrictInt, Field(ge=0)]
    cancel_requested_count: Annotated[StrictInt, Field(ge=0)]
    dead_letter_count: Annotated[StrictInt, Field(ge=0)]
    workspace_paused: StrictBool
    backpressure_active: StrictBool
    transport_status: QueueTransportStatus
    transport_detail: BoundedText | None = None


class TaskJobDetail(TaskJob):
    """A-14 detailed task-job view including attempt history and DLQ entry."""

    attempts_history: list[TaskAttemptSummary] = Field(default_factory=list)
    dead_letter_entry: DeadLetterJobSummary | None = None


class TaskJobPage(Page[TaskJob]):
    """A-14 S-04 cursor-paginated task-job listing with scoped fairness summary."""

    summary: WorkspaceQueueFairnessSummary | None = None


class TaskJobActionRequest(StrictContractModel):
    """A-14 operator queue control action input (`cancel | requeue | reconcile`)."""

    action: TaskJobAction
    reason: BoundedReason
    expected_version: PositiveVersion | None = None
    reconciled_outcome: TaskJobReconcileOutcome | None = None

    @model_validator(mode="after")
    def _validate_reconcile_fields(self) -> Self:
        if self.reconciled_outcome is not None and self.action != "reconcile":
            raise ValueError("reconciled_outcome is only permitted when action is 'reconcile'")
        return self


# S-21 SandboxJobV1 & ResultV1
class SandboxResourceLimits(StrictContractModel):
    """S-21 hard execution quotas enforced by isolated worker supervisor."""

    cpu: Annotated[StrictInt, Field(ge=1, le=64)]
    memory_bytes: Annotated[StrictInt, Field(ge=1)]
    disk_bytes: Annotated[StrictInt, Field(ge=1)]
    pids: Annotated[StrictInt, Field(ge=1, le=65536)]
    wall_seconds: Annotated[StrictInt, Field(ge=1, le=7200)]
    output_bytes: Annotated[StrictInt, Field(ge=1)]


class SandboxJobV1(StrictContractModel):
    """S-21 lease-fenced immutable execution directive dispatched to worker supervisor."""

    schema_version: Literal[1] = 1
    job_id: InternalId
    workspace_id: InternalId
    repository_id: InternalId
    repair_id: InternalId
    lease_epoch: PositiveVersion
    capability_nonce: BoundedName
    issued_at: UtcTimestamp
    expires_at: UtcTimestamp
    base_sha: GitSha
    source_archive_digest: Sha256Digest
    patch_digest: Sha256Digest | None = None
    profile_id: BoundedName
    profile_revision: PositiveVersion
    image_digest: Sha256Digest
    command_ids: Annotated[list[BoundedName], Field(min_length=1, max_length=32)]
    resource_limits: SandboxResourceLimits
    network_policy_digest: Sha256Digest
    artifact_upload_capability: BoundedText
    expected_worker_trust_domain: BoundedName
    supervisor_policy_digest: Sha256Digest

    @model_validator(mode="after")
    def _validate_expiry(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("SandboxJobV1 expires_at must be strictly after issued_at")
        return self


ResultTermination = Literal[
    "exited",
    "timeout",
    "oom",
    "cancelled",
    "infrastructure_error",
]


class SandboxResourceUsage(StrictContractModel):
    """S-21 measured guest resource consumption."""

    wall_ms: DurationMs
    max_memory_bytes: Annotated[StrictInt, Field(ge=0)]
    disk_written_bytes: Annotated[StrictInt, Field(ge=0)]
    output_bytes: Annotated[StrictInt, Field(ge=0)]


class ResultArtifactRef(StrictContractModel):
    """S-21 content-addressed execution output artifact descriptor."""

    id: InternalId
    digest: Sha256Digest
    size: Annotated[StrictInt, Field(ge=0)]


class IsolationCheckResult(StrictContractModel):
    """S-21 supervisor-attested confinement/cleanup check result."""

    check_id: BoundedName
    passed: StrictBool
    detail: BoundedText | None = None


class ResultV1(StrictContractModel):
    """S-21 supervisor-signed sandbox execution outcome (never signed inside guest)."""

    schema_version: Literal[1] = 1
    job_id: InternalId
    lease_epoch: PositiveVersion
    capability_nonce: BoundedName
    worker_id: InternalId
    started_at: UtcTimestamp
    ended_at: UtcTimestamp
    exit_code: StrictInt | None = None
    termination: ResultTermination
    command_digest: Sha256Digest
    image_digest: Sha256Digest
    environment_digest: Sha256Digest
    source_digest: Sha256Digest
    patch_digest: Sha256Digest | None = None
    resource_usage: SandboxResourceUsage
    artifact_refs: list[ResultArtifactRef] = Field(default_factory=list)
    isolation_checks: Annotated[list[IsolationCheckResult], Field(min_length=1)]
    signer_key_id: BoundedName
    signature: BoundedText

    @model_validator(mode="after")
    def _validate_timestamps(self) -> Self:
        if self.ended_at < self.started_at:
            raise ValueError("ResultV1 ended_at must not precede started_at")
        return self

    def passed_cleanly(self) -> bool:
        """S-21 invariant: missing exit_code, timeout, or infra error never passes tests."""
        return (
            self.termination == "exited"
            and self.exit_code == 0
            and all(chk.passed for chk in self.isolation_checks)
        )


class WorkerSelfTestResponse(StrictContractModel):
    """UI-S13 / INS-02 deterministic isolated worker confinement & signing self-test report."""

    worker_id: InternalId
    passed: StrictBool
    isolation_mode: WorkerIsolationMode
    checks: Annotated[list[IsolationCheckResult], Field(min_length=1)]
    checked_at: UtcTimestamp
    detail: BoundedText


class WorkerIsolationAttestation(StrictContractModel):
    """S-21 worker supervisor preflight isolation & quota attestation."""

    host_id: BoundedName
    runtime_name: BoundedName
    isolation_mode: WorkerIsolationMode
    rootless_verified: StrictBool
    seccomp_verified: StrictBool
    no_new_privileges_verified: StrictBool
    network_none_supported: StrictBool
    cpu_limit: Annotated[StrictInt, Field(ge=1, le=256)]
    memory_limit_bytes: Annotated[StrictInt, Field(ge=1)]
    disk_limit_bytes: Annotated[StrictInt, Field(ge=1)]
    pids_limit: Annotated[StrictInt, Field(ge=1, le=65536)]


class WorkerEnrollHandshakeRequest(StrictContractModel):
    """S-21 one-time enrollment token + PKCS#10 CSR + Ed25519 public key exchange."""

    enrollment_token: BoundedText
    csr_pem: BoundedText
    signer_public_key: PublicKeyRecord
    attestation: WorkerIsolationAttestation
    profile_ids: Annotated[list[BoundedName], Field(min_length=1, max_length=32)]


class WorkerEnrollHandshakeResponse(StrictContractModel):
    """S-21 issued mTLS client certificate, Worker CA bundle, and enrolled Worker record."""

    worker: Worker
    client_cert_pem: BoundedText
    ca_cert_pem: BoundedText
    cert_expires_at: UtcTimestamp


class WorkerPollRequest(StrictContractModel):
    """S-21 mTLS worker poll & node heartbeat payload."""

    status_hint: Literal["ready", "draining"] = "ready"
    capabilities: dict[BoundedName, StrictBool] = Field(default_factory=dict)


class WorkerPollResponse(StrictContractModel):
    """S-21 mTLS worker poll response optionally leasing one `SandboxJobV1`."""

    worker_status: WorkerStatus
    sandbox_job: SandboxJobV1 | None = None
    source_archive_b64: str | None = Field(default=None, max_length=16_777_216)
    patch_diff_text: BoundedText | None = None
    heartbeat_interval_seconds: Annotated[StrictInt, Field(ge=1, le=300)] = 15


class WorkerJobHeartbeatRequest(StrictContractModel):
    """S-21 per-job 15s heartbeat payload fenced by `lease_epoch` and `capability_nonce`."""

    lease_epoch: PositiveVersion
    capability_nonce: BoundedName


class WorkerJobHeartbeatResponse(StrictContractModel):
    """S-21 per-job heartbeat renewal & live cancellation signal."""

    job_id: InternalId
    lease_epoch: PositiveVersion
    lease_expires_at: UtcTimestamp
    cancel_requested: StrictBool


class WorkerArtifactUploadRequest(StrictContractModel):
    """S-21 write-only per-job artifact slot upload payload (`<=100MiB` total output cap)."""

    lease_epoch: PositiveVersion
    capability_nonce: BoundedName
    slot_name: BoundedName
    mime: BoundedName = "text/plain"
    content_b64: str = Field(max_length=140_000_000)
    digest: Sha256Digest


class WorkerArtifactUploadResponse(StrictContractModel):
    """S-21 verified encrypted artifact upload receipt."""

    artifact_ref: ResultArtifactRef
    remaining_output_bytes: Annotated[StrictInt, Field(ge=0)]


class WorkerJobResultReceipt(StrictContractModel):
    """S-21 control-plane receipt for a verified `ResultV1` submission."""

    job_id: InternalId
    lease_epoch: PositiveVersion
    accepted: StrictBool
    idempotent_replay: StrictBool = False
    worker_quarantined: StrictBool = False


class WorkerCancelAckRequest(StrictContractModel):
    """S-21 worker confirmation of guest process teardown and ephemeral cleanup."""

    lease_epoch: PositiveVersion
    capability_nonce: BoundedName
    ended_at: UtcTimestamp
    container_killed: StrictBool
    cleanup_verified: StrictBool
    isolation_checks: Annotated[list[IsolationCheckResult], Field(min_length=1)]


class WorkerCancelAckResponse(StrictContractModel):
    """S-21 control-plane receipt for job cancellation acknowledgement."""

    job_id: InternalId
    lease_epoch: PositiveVersion
    state: TaskJobState
    worker_quarantined: StrictBool = False
