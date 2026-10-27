"""Canonical worker registry, task jobs, and sandbox execution contracts (S-15, S-21).

Enforces:
- S-15: Worker and TaskJob status/fencing schemas.
- S-21: SandboxJobV1 (immutable profile command_ids, bounded resource quotas) and
  ResultV1 (missing exit_code, timeout, or infrastructure_error never passes tests).
"""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictInt, model_validator

from py_contracts.integrations import GitSha
from py_contracts.primitives import (
    BoundedName,
    BoundedText,
    DurationMs,
    InstanceResourceBase,
    InternalId,
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

    @model_validator(mode="after")
    def _validate_deadline(self) -> Self:
        if self.deadline < self.not_before:
            raise ValueError("TaskJob deadline must not precede not_before")
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
