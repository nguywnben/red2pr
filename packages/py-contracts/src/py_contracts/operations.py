"""Instance lifecycle, backup, restore and support-bundle contracts (U26)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, StrictBool, StrictInt

from py_contracts.primitives import (
    BoundedName,
    BoundedText,
    InternalId,
    PositiveVersion,
    Sha256Digest,
    StrictContractModel,
    UtcTimestamp,
)

OperationCheckState = Literal["ok", "warning", "failed", "blocked"]
SupportBundleFileId = Literal[
    "health_summary",
    "doctor_report",
    "migration_status",
    "worker_status",
    "telemetry_snapshot",
    "recent_redacted_logs",
]


class SystemCheck(StrictContractModel):
    check_id: BoundedName
    state: OperationCheckState
    summary: BoundedText


class SystemStatus(StrictContractModel):
    state: Literal["ready", "degraded", "maintenance", "failed"]
    generated_at: UtcTimestamp
    application_version: BoundedName
    schema_revision: BoundedName
    database_version: BoundedText | None = None
    recovery_epoch: PositiveVersion
    maintenance_enabled: StrictBool
    maintenance_reason: BoundedText | None = None
    worker_protocols: tuple[BoundedName, ...] = ()
    checks: tuple[SystemCheck, ...] = ()


class DoctorResponse(StrictContractModel):
    generated_at: UtcTimestamp
    overall_state: Literal["healthy", "degraded", "failed"]
    checks: tuple[SystemCheck, ...]


class BackupObjectEntry(StrictContractModel):
    workspace_id: InternalId
    blob_id: InternalId
    digest: Sha256Digest
    size_bytes: StrictInt = Field(ge=0)
    storage_ref: BoundedText


class BackupKeyReference(StrictContractModel):
    secret_ref: BoundedName
    workspace_id: InternalId | None = None
    purpose: BoundedName
    active_key_version: PositiveVersion
    kek_version: PositiveVersion


class BackupManifestV1(StrictContractModel):
    """Signed inventory for one internally consistent, encrypted recovery bundle."""

    schema_version: Literal[1] = 1
    backup_id: InternalId
    created_at: UtcTimestamp
    snapshot_lsn: BoundedName
    postgres_version: BoundedName
    database_encoding: BoundedName
    database_locale_provider: Literal["libc", "icu"]
    database_collation: BoundedText
    database_character_type: BoundedText
    database_icu_locale: BoundedText | None = None
    schema_revision: BoundedName
    application_version: BoundedName
    build_digest: Sha256Digest
    config_digest: Sha256Digest
    workspace_ids: tuple[InternalId, ...]
    objects: tuple[BackupObjectEntry, ...]
    key_references: tuple[BackupKeyReference, ...]
    payload_sha256: Sha256Digest
    payload_kek_version: PositiveVersion
    signer_key_id: BoundedName
    signature: BoundedText


class BackupRecord(StrictContractModel):
    id: InternalId
    state: Literal["creating", "succeeded", "failed", "expired"]
    created_at: UtcTimestamp
    completed_at: UtcTimestamp | None = None
    manifest_digest: Sha256Digest | None = None
    size_bytes: StrictInt = Field(ge=0)
    object_count: StrictInt = Field(ge=0)
    error_code: BoundedName | None = None


class BackupCreateRequest(StrictContractModel):
    label: BoundedName | None = None


class RestoreDryRunRequest(StrictContractModel):
    backup_id: InternalId
    target_schema_revision: BoundedName | None = None


class RestorePlan(StrictContractModel):
    backup_id: InternalId
    manifest_digest: Sha256Digest
    plan_digest: Sha256Digest
    target_schema_revision: BoundedName
    compatible: StrictBool
    requires_maintenance: StrictBool = True
    restores_artifacts: StrictBool
    rotates_recovery_epoch: StrictBool = True
    reapplies_retention_tombstones: StrictBool = True
    requires_remote_reconciliation: StrictBool = True
    blockers: tuple[BoundedName, ...] = ()
    warnings: tuple[BoundedText, ...] = ()


class RestoreStartRequest(StrictContractModel):
    backup_id: InternalId
    manifest_digest: Sha256Digest
    plan_digest: Sha256Digest


class RestoreExecutionResult(StrictContractModel):
    restore_id: InternalId
    backup_id: InternalId
    state: Literal["succeeded", "blocked", "failed"]
    recovery_epoch: PositiveVersion
    maintenance_enabled: StrictBool
    requires_external_reconciliation: StrictBool
    message: BoundedText


class OperationCancelRequest(StrictContractModel):
    reason: BoundedText = Field(min_length=8, max_length=1000)
    expected_version: PositiveVersion | None = None


class OperationCancelStatus(StrictContractModel):
    operation_id: InternalId
    state: Literal["accepted", "running", "succeeded", "failed", "unknown"]
    cancelable: StrictBool
    reason: BoundedName | None = None


class MaintenanceRequest(StrictContractModel):
    enabled: StrictBool
    reason: BoundedText = Field(min_length=8, max_length=500)
    reconciliation_confirmed: StrictBool = False


class SupportBundlePreview(StrictContractModel):
    manifest_digest: Sha256Digest
    file_ids: tuple[SupportBundleFileId, ...]
    redacted_file_count: StrictInt = Field(ge=0)
    excluded_secrets: StrictBool = True
    excluded_repository_source: StrictBool = True
    expires_at: UtcTimestamp


class SupportBundleCreateRequest(StrictContractModel):
    manifest_digest: Sha256Digest
    file_ids: tuple[SupportBundleFileId, ...] = Field(min_length=1, max_length=6)
    confirm_export: StrictBool


class SupportBundleRecord(StrictContractModel):
    id: InternalId
    manifest_digest: Sha256Digest
    created_at: UtcTimestamp
    expires_at: UtcTimestamp
    file_count: StrictInt = Field(ge=1)
    size_bytes: StrictInt = Field(ge=0)
    download_url: BoundedText


class UpgradePreflightRequest(StrictContractModel):
    target_version: BoundedName
    target_schema_revision: BoundedName
    target_worker_protocols: tuple[BoundedName, ...] = Field(min_length=1, max_length=16)


class UpgradePreflightResponse(StrictContractModel):
    compatible: StrictBool
    current_version: BoundedName
    target_version: BoundedName
    current_schema_revision: BoundedName
    target_schema_revision: BoundedName
    incompatible_workers: tuple[BoundedName, ...] = ()
    pending_effects: StrictInt = Field(ge=0)
    required_actions: tuple[BoundedName, ...] = ()
