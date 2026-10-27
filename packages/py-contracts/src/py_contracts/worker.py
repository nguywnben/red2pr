"""Canonical worker registry, task jobs, and sandbox execution contracts (S-15, S-21).

Enforces:
- S-15: Worker, TaskJob, TaskAttemptSummary, DeadLetterJobSummary, and queue action schemas.
- S-21: SandboxJobV1 (immutable profile command_ids, bounded resource quotas) and
  ResultV1 (missing exit_code, timeout, or infrastructure_error never passes tests).
"""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictInt, model_validator

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
