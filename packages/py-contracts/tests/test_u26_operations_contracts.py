from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from py_contracts.operations import (
    BackupManifestV1,
    BackupObjectEntry,
    MaintenanceRequest,
    RestoreDryRunRequest,
    SupportBundleCreateRequest,
)
from py_contracts.primitives import new_uuid7
from py_contracts.worker import WORKER_PROTOCOL_V1, WorkerPollRequest


def _manifest_payload() -> dict[str, object]:
    now = datetime.now(tz=UTC)
    return {
        "backup_id": new_uuid7(now=now),
        "created_at": now,
        "snapshot_lsn": "0/16B6C50",
        "postgres_version": "16.2",
        "database_encoding": "UTF8",
        "database_locale_provider": "libc",
        "database_collation": "C.UTF-8",
        "database_character_type": "C.UTF-8",
        "database_icu_locale": None,
        "schema_revision": "0022_backups_migrations_ops",
        "application_version": "1.0.0-dev",
        "build_digest": "a" * 64,
        "config_digest": "b" * 64,
        "workspace_ids": [new_uuid7(now=now)],
        "objects": [
            {
                "workspace_id": new_uuid7(now=now),
                "blob_id": new_uuid7(now=now),
                "digest": "c" * 64,
                "size_bytes": 128,
                "storage_ref": "local://v1/workspace/blob",
            }
        ],
        "key_references": [
            {
                "secret_ref": "sec_example_ref",
                "purpose": "provider_read",
                "active_key_version": 1,
                "kek_version": 2,
            }
        ],
        "payload_sha256": "d" * 64,
        "payload_kek_version": 2,
        "signer_key_id": "backup-key-1",
        "signature": "ed25519:test-signature",
    }


def test_backup_manifest_contract_contains_inventory_and_no_plaintext_secrets() -> None:
    manifest = BackupManifestV1.model_validate(_manifest_payload())
    encoded = manifest.model_dump_json()
    assert "envelope_json" not in encoded
    assert "access_token" not in encoded
    assert "provider_read" in encoded
    assert manifest.objects[0].digest == "c" * 64


def test_backup_contract_rejects_paths_and_secret_material_fields() -> None:
    payload = _manifest_payload()
    payload["master_key"] = "should-never-be-in-a-backup-manifest"
    with pytest.raises(ValidationError):
        BackupManifestV1.model_validate(payload)


def test_instance_operations_contracts_reject_missing_or_unsafe_confirmation() -> None:
    with pytest.raises(ValidationError):
        MaintenanceRequest.model_validate({"enabled": True, "reason": "ok"})
    with pytest.raises(ValidationError):
        SupportBundleCreateRequest.model_validate(
            {
                "manifest_digest": "e" * 64,
                "file_ids": ["/etc/passwd"],
                "confirm_export": False,
            }
        )
    with pytest.raises(ValidationError):
        RestoreDryRunRequest.model_validate({"backup_id": "not-a-uuid"})


def test_backup_object_entry_rejects_negative_sizes() -> None:
    with pytest.raises(ValidationError):
        BackupObjectEntry.model_validate(
            {
                "workspace_id": new_uuid7(),
                "blob_id": new_uuid7(),
                "digest": "f" * 64,
                "size_bytes": -1,
                "storage_ref": "local://v1/workspace/blob",
            }
        )


def test_worker_protocol_inventory_is_explicit_and_bounded_for_upgrade_preflight() -> None:
    assert WorkerPollRequest().protocol_versions == []
    request = WorkerPollRequest(protocol_versions=[WORKER_PROTOCOL_V1])
    assert request.model_dump(mode="json")["protocol_versions"] == ["worker-v1"]
    with pytest.raises(ValidationError):
        WorkerPollRequest(protocol_versions=["x" * 121])
