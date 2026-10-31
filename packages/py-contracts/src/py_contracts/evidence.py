"""Canonical artifacts, audit/usage/report DTOs, and signed EvidenceManifestV1 (S-14, S-17, S-22).

Enforces:
- S-14: Public Artifact DTO never exposes internal storage_ref / bucket keys.
- S-17: Hash-chained AuditRecord, ModelUsageRecord (unknown != zero), bounded ReportExportRequest.
- S-22: Signed EvidenceManifestV1 binding source/patched SHAs, digests, fidelity, and provenance.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, StrictInt, model_validator

from py_contracts.integrations import (
    CiJob,
    CiRun,
    FailureFingerprintSummary,
    GitSha,
)
from py_contracts.primitives import (
    BoundedName,
    BoundedText,
    BoundedUrl,
    CurrencyCode,
    InstanceResourceBase,
    InternalId,
    Money,
    MoneyAmount,
    OpaqueProviderId,
    Sha256Digest,
    StrictContractModel,
    UtcTimestamp,
    WorkspaceResourceBase,
)
from py_contracts.repairs import GateOutcome

# S-14 Artifact & Evidence
ArtifactAccessClass = Literal["public", "workspace_internal", "restricted"]


class Artifact(WorkspaceResourceBase):
    """S-14 public artifact metadata DTO (never exposes internal storage_ref or bucket keys)."""

    name: BoundedName | None = None
    run_id: InternalId | None = None
    job_id: InternalId | None = None
    kind: BoundedName
    mime: BoundedName
    size_bytes: Annotated[StrictInt, Field(ge=0)]
    digest: Sha256Digest
    redaction_version: BoundedName
    retention_until: UtcTimestamp
    access_class: ArtifactAccessClass
    manifest_id: InternalId | None = None
    extracted_file_count: Annotated[StrictInt, Field(ge=0)] | None = None
    available: StrictBool
    purge_reason: BoundedName | None = None


class ArtifactRecord(WorkspaceResourceBase):
    """S-14 internal control-plane artifact record including storage_ref."""

    name: BoundedName | None = None
    run_id: InternalId | None = None
    job_id: InternalId | None = None
    kind: BoundedName
    mime: BoundedName
    size_bytes: Annotated[StrictInt, Field(ge=0)]
    digest: Sha256Digest
    storage_ref: BoundedText
    redaction_version: BoundedName
    retention_until: UtcTimestamp
    access_class: ArtifactAccessClass
    manifest_id: InternalId | None = None
    extracted_file_count: Annotated[StrictInt, Field(ge=0)] | None = None

    def to_public_dto(
        self,
        *,
        available: bool,
        purge_reason: str | None = None,
    ) -> Artifact:
        """Project internal artifact record to safe public S-14 DTO without storage_ref."""
        return Artifact(
            id=self.id,
            workspace_id=self.workspace_id,
            repository_id=self.repository_id,
            version=self.version,
            created_at=self.created_at,
            updated_at=self.updated_at,
            name=self.name,
            run_id=self.run_id,
            job_id=self.job_id,
            kind=self.kind,
            mime=self.mime,
            size_bytes=self.size_bytes,
            digest=self.digest,
            redaction_version=self.redaction_version,
            retention_until=self.retention_until,
            access_class=self.access_class,
            manifest_id=self.manifest_id,
            extracted_file_count=self.extracted_file_count,
            available=available,
            purge_reason=purge_reason,
        )


class CiRunDetailResponse(StrictContractModel):
    """A-08 detailed CI run view with sibling attempts, matrix jobs, S-14 artifacts & flaky data."""

    run: CiRun
    sibling_attempts: list[CiRun] = Field(default_factory=list)
    jobs: list[CiJob] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    fingerprints: list[FailureFingerprintSummary] = Field(default_factory=list)


# S-17 Audit, Model Usage & Report Export
AuditDecision = Literal["allow", "deny", "error", "reconcile"]
UsageStatus = Literal["reserved", "settled", "released", "failed", "unknown"]
ReportKind = Literal["funnel", "usage", "audit", "proof_summary"]
ReportFormat = Literal["csv", "json"]


class AuditRecord(InstanceResourceBase):
    """S-17 tamper-evident append-only hash-chained audit entry."""

    workspace_id: InternalId | None = None
    actor: BoundedName
    action: BoundedName
    target: BoundedText
    decision: AuditDecision
    reason_code: BoundedName
    correlation_id: BoundedName
    prev_hash: Sha256Digest
    entry_hash: Sha256Digest
    checkpoint_id: InternalId | None = None


class ModelUsageRecord(WorkspaceResourceBase):
    """S-17 AI token & cost accounting record (unknown usage remains None, never coerced to 0)."""

    reservation_id: InternalId
    provider_request_id: OpaqueProviderId | None = None
    model_id: BoundedName
    input_tokens: Annotated[StrictInt, Field(ge=0)] | None = None
    output_tokens: Annotated[StrictInt, Field(ge=0)] | None = None
    estimated_cost: Money
    settled_cost: Money | None = None
    currency: CurrencyCode
    pricing_revision: BoundedName
    status: UsageStatus


class ReportExportRequest(StrictContractModel):
    """S-17 / A-17 bounded analytics, usage, or audit export request (<= 366 days)."""

    kind: ReportKind
    range_start: UtcTimestamp
    range_end: UtcTimestamp
    filters: dict[BoundedName, BoundedText] = Field(default_factory=dict)
    format: ReportFormat

    @model_validator(mode="after")
    def _validate_range(self) -> Self:
        if self.range_end < self.range_start:
            raise ValueError("range_end must not precede range_start")
        if self.range_end - self.range_start > timedelta(days=366):
            raise ValueError("Export time range must not exceed 366 days (A-17)")
        return self


class AnalyticsFunnelStage(StrictContractModel):
    """One explicit repair funnel stage with its authoritative denominator."""

    key: BoundedName
    value: Annotated[StrictInt, Field(ge=0)]
    numerator: Annotated[StrictInt, Field(ge=0)] | None = None
    denominator: Annotated[StrictInt, Field(ge=0)] | None = None


class AnalyticsCostSummary(StrictContractModel):
    """Exact cost ledger summary; unknown billing is kept explicit."""

    currency: CurrencyCode
    settled: MoneyAmount
    estimated_unsettled: MoneyAmount
    total: MoneyAmount
    unknown_rows: Annotated[StrictInt, Field(ge=0)]
    usage_rows: Annotated[StrictInt, Field(ge=0)]


class WorkspaceAnalyticsResponse(StrictContractModel):
    """A-17 workspace-scoped analytics projection with source watermark."""

    workspace_id: InternalId
    range_start: UtcTimestamp
    range_end: UtcTimestamp
    repository_count: Annotated[StrictInt, Field(ge=0)]
    funnel: Annotated[list[AnalyticsFunnelStage], Field(min_length=8, max_length=8)]
    local_success_count: Annotated[StrictInt, Field(ge=0)]
    remote_success_count: Annotated[StrictInt, Field(ge=0)]
    unknown_count: Annotated[StrictInt, Field(ge=0)]
    pending_count: Annotated[StrictInt, Field(ge=0)]
    abstained_count: Annotated[StrictInt, Field(ge=0)]
    costs: list[AnalyticsCostSummary]
    watermark: UtcTimestamp


class WorkspaceUsageResponse(StrictContractModel):
    """A-17 scoped model usage cost ledger summary with source watermark."""

    workspace_id: InternalId
    range_start: UtcTimestamp
    range_end: UtcTimestamp
    costs: list[AnalyticsCostSummary]
    watermark: UtcTimestamp


class ReportExportReceipt(StrictContractModel):
    """Receipt for encrypted bounded report export and its authorized download route."""

    export_id: InternalId
    kind: ReportKind
    format: ReportFormat
    digest: Sha256Digest
    size_bytes: Annotated[StrictInt, Field(ge=0)]
    expires_at: UtcTimestamp
    download_path: BoundedUrl
    reused: StrictBool = False


# S-22 Proof & Audit Manifest (docs/10_SANDBOX_REPRODUCTION.md canonical fidelity grades)
FidelityGrade = Literal[
    "F1_TARGETED",
    "F2_APPROX",
    "F3_VALIDATED",
    "FX_UNSUPPORTED",
]


class ModelToolProvenance(StrictContractModel):
    """S-22 redacted model/tool provenance record (no raw chain-of-thought or secrets)."""

    model_id: BoundedName
    adapter_version: BoundedName
    provider_request_id: OpaqueProviderId | None = None
    redacted_context_hashes: list[Sha256Digest]
    tool_call_digests: list[Sha256Digest] = Field(default_factory=list)
    usage_record_id: InternalId


class RegressionSuiteSummary(StrictContractModel):
    """S-22 deterministic regression test suite summary."""

    selection_id: BoundedName
    selection_digest: Sha256Digest
    passed_count: Annotated[StrictInt, Field(ge=0)]
    failed_count: Annotated[StrictInt, Field(ge=0)]
    skipped_count: Annotated[StrictInt, Field(ge=0)]
    result_job_id: InternalId


class SecurityFindingV1(StrictContractModel):
    """Structured verifier finding covered by the signed evidence manifest."""

    finding_ref: BoundedName
    severity: Literal["info", "low", "medium", "high", "critical"]
    artifact_digest: Sha256Digest
    invariant_violation: StrictBool = False


class ReleaseExceptionCreateRequest(StrictContractModel):
    finding_ref: BoundedName
    artifact_digest: Sha256Digest
    security_reviewer_user_id: InternalId
    mitigation: Annotated[str, Field(min_length=20, max_length=2000)]
    expires_at: UtcTimestamp


class ReleaseExceptionRecord(StrictContractModel):
    id: InternalId
    finding_ref: BoundedName
    severity: Literal["high"]
    artifact_digest: Sha256Digest
    owner_user_id: InternalId
    security_reviewer_user_id: InternalId
    mitigation: Annotated[str, Field(min_length=20, max_length=2000)]
    created_at: UtcTimestamp
    expires_at: UtcTimestamp
    revoked_at: UtcTimestamp | None = None


class ReleaseExceptionList(StrictContractModel):
    items: list[ReleaseExceptionRecord] = Field(max_length=500)


class EvidenceManifestV1(StrictContractModel):
    """S-22 canonical domain-separated Ed25519-signed local proof manifest."""

    schema_version: Literal[1] = 1
    manifest_id: InternalId
    workspace_id: InternalId
    repository_id: InternalId
    repair_id: InternalId
    source_sha: GitSha
    base_sha: GitSha
    patched_sha: GitSha
    diff_digest: Sha256Digest
    ci_run_id: InternalId
    ci_job_ids: Annotated[list[InternalId], Field(min_length=1)]
    ci_attempt_key: OpaqueProviderId
    profile_id: BoundedName
    profile_digest: Sha256Digest
    image_digest: Sha256Digest
    dependency_lock_digest: Sha256Digest
    commands_digest: Sha256Digest
    environment_digest: Sha256Digest
    baseline_result_job_id: InternalId
    baseline_result_digest: Sha256Digest
    patched_result_job_id: InternalId
    patched_result_digest: Sha256Digest
    failure_fingerprint: Sha256Digest
    fidelity_grade: FidelityGrade
    fidelity_differences: list[BoundedText] = Field(default_factory=list)
    regression: RegressionSuiteSummary
    integrity_outcome: GateOutcome
    security_outcome: GateOutcome
    security_findings: list[SecurityFindingV1] = Field(default_factory=list, max_length=500)
    policy_outcome: GateOutcome
    provenance: list[ModelToolProvenance] = Field(default_factory=list)
    redaction_revision: BoundedName
    artifact_digests: dict[InternalId, Sha256Digest]
    created_at: UtcTimestamp
    signer_key_id: BoundedName
    signature: BoundedText
