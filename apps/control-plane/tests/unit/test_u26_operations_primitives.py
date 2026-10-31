from __future__ import annotations

import hashlib
import io
import json
import tarfile
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import BigInteger
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from py_contracts.crypto import KeyRing, MasterKeyRing, export_ed25519_public_key_record
from py_contracts.operations import BackupKeyReference, BackupManifestV1, BackupObjectEntry
from red2pr_control.db.base import BackupRecordModel
from red2pr_control.operations.backup_encryption import BackupEncryptor, decrypt_backup_chunks
from red2pr_control.operations.backup_restore import (
    _extract_bundle_file,
    _read_restore_marker,
    _restore_database_properties,
    _unavailable_secret_key_versions,
    _write_restore_marker,
    build_bundle,
    read_bundle,
    sign_backup_manifest,
    write_bundle_file,
)
from red2pr_control.operations.runtime import _lock_engine, dispose_operation_lock_engine
from red2pr_control.operations.support_bundle import (
    create_support_bundle,
    read_recent_redacted_logs,
    render_support_bundle_preview,
)
from red2pr_control.operations.uninstall import UnsafePurgePath, validate_purge_path
from red2pr_control.operations.upgrade_preflight import (
    schema_revision_compatible,
    worker_protocol_compatible,
)
from red2pr_control.secrets.broker import SecretBroker
from red2pr_control.triage_evidence.artifact_store import (
    ArtifactIntegrityError,
    LocalEncryptedArtifactStore,
)

NOW = datetime(2026, 10, 31, tzinfo=UTC)


def test_backup_database_encryption_requires_key_and_rejects_tampering(tmp_path) -> None:
    from py_contracts.crypto import MasterKeyRing

    keyring = MasterKeyRing(active_version=2, keys={2: b"k" * 32})
    other_keys = MasterKeyRing(active_version=1, keys={1: b"z" * 32})
    payload = b"private database content" * 100
    path = tmp_path / "payload.enc"
    with path.open("wb") as stream:
        writer = BackupEncryptor(stream, keys=keyring, backup_id="backup-1")
        writer.update(payload[:200])
        writer.update(payload[200:])
        writer.finish()
    assert payload not in path.read_bytes()
    assert (
        b"".join(
            decrypt_backup_chunks(path, keys=keyring, backup_id="backup-1", expected_version=2)
        )
        == payload
    )
    with pytest.raises(ValueError, match="backup_encryption_key_missing"):
        list(decrypt_backup_chunks(path, keys=other_keys, backup_id="backup-1", expected_version=2))
    altered = bytearray(path.read_bytes())
    altered[-17] ^= 1
    path.write_bytes(altered)
    with pytest.raises(ValueError, match="backup_payload_integrity_failed"):
        list(decrypt_backup_chunks(path, keys=keyring, backup_id="backup-1", expected_version=2))


def test_backup_record_size_accepts_configured_bundle_limit() -> None:
    assert isinstance(BackupRecordModel.__table__.c.size_bytes.type, BigInteger)


def test_upgrade_preflight_allows_only_adjacent_schema_and_declared_worker_protocols() -> None:
    old = "0021_retention_jobs_and_exceptions"
    current = "0022_backups_migrations_ops"
    assert schema_revision_compatible(old, current)
    assert schema_revision_compatible(current, old)
    assert schema_revision_compatible(current, current)
    assert not schema_revision_compatible("0020_prior_revision", current)
    assert worker_protocol_compatible(["worker-v2", "worker-v3"], frozenset({"worker-v3"}))
    assert not worker_protocol_compatible([], frozenset({"worker-v3"}))
    assert not worker_protocol_compatible(["worker-v1"], frozenset({"worker-v3"}))


def test_restore_marker_rejects_database_names_outside_owned_restore_namespace(tmp_path) -> None:
    marker = {
        "restore_id": "019a0000-0000-7000-8000-000000000031",
        "target": "red2pr",
        "staging": "r2pr_r_012345abcdef",
        "quarantine": "r2pr_q_012345abcdef",
        "phase": "prepared",
        "recovery_epoch": 4,
        "backup_id": "019a0000-0000-7000-8000-000000000032",
        "manifest_digest": "a" * 64,
        "plan_digest": "b" * 64,
    }
    _write_restore_marker(tmp_path, marker)
    assert _read_restore_marker(tmp_path) == marker
    forged = dict(marker, target="postgres")
    (tmp_path / "restore-recovery.json").write_text(json.dumps(forged), encoding="utf-8")
    with pytest.raises(RuntimeError, match="restore_marker_invalid"):
        _read_restore_marker(tmp_path)


@pytest.mark.asyncio
async def test_restore_fence_uses_stable_postgres_database_and_disposes_pool() -> None:
    target_engine = create_async_engine(
        "postgresql+psycopg://red2pr:local-test@127.0.0.1:5432/red2pr"
    )
    session_factory = async_sessionmaker(target_engine)
    try:
        lock_engine = _lock_engine(session_factory)
        assert target_engine.url.database == "red2pr"
        assert lock_engine.url.database == "postgres"
        assert lock_engine is _lock_engine(session_factory)
        await dispose_operation_lock_engine(session_factory)
    finally:
        await target_engine.dispose()


def signed_manifest(private_key: Ed25519PrivateKey, payload: bytes) -> BackupManifestV1:
    draft = BackupManifestV1(
        backup_id="019a0000-0000-7000-8000-000000000001",
        created_at=NOW,
        snapshot_lsn="0/16B6C50",
        postgres_version="160004",
        database_encoding="UTF8",
        database_locale_provider="libc",
        database_collation="C.UTF-8",
        database_character_type="C.UTF-8",
        database_icu_locale=None,
        schema_revision="0022_backups_migrations_ops",
        application_version="0.1.0",
        build_digest="a" * 64,
        config_digest="b" * 64,
        workspace_ids=(),
        objects=(),
        key_references=(),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        payload_kek_version=1,
        signer_key_id="backup-key-1",
        signature="",
    )
    return sign_backup_manifest(draft, private_key=private_key)


def test_signed_backup_round_trip_and_tamper_detection() -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = b"encrypted database archive"
    manifest = signed_manifest(private_key, payload)
    record = export_ed25519_public_key_record(
        private_key=private_key,
        key_id="backup-key-1",
        not_before=NOW,
        trust_domain="red2pr-backup",
    )
    archive = build_bundle(manifest, payload=payload, objects={})
    restored_manifest, restored_payload, objects = read_bundle(
        archive, keyring=KeyRing([record]), now=NOW
    )
    assert restored_manifest.backup_id == manifest.backup_id
    assert restored_payload == payload
    assert objects == {}

    tampered = io.BytesIO()
    with (
        tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as original,
        tarfile.open(fileobj=tampered, mode="w:gz") as changed,
    ):
        for member in original.getmembers():
            source = original.extractfile(member)
            assert source is not None
            data = b"tampered database archive" if member.name == "database.dump" else source.read()
            member.size = len(data)
            changed.addfile(member, io.BytesIO(data))
    with pytest.raises(ValueError, match="digest"):
        read_bundle(tampered.getvalue(), keyring=KeyRing([record]), now=NOW)


def test_backup_inventory_keeps_same_plaintext_digest_distinct_across_workspaces(tmp_path) -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = b"database dump"
    duplicate_digest = hashlib.sha256(b"same plaintext, distinct workspace AAD").hexdigest()
    first_blob = "019a0000-0000-7000-8000-000000000011"
    second_blob = "019a0000-0000-7000-8000-000000000012"
    manifest = sign_backup_manifest(
        signed_manifest(private_key, payload).model_copy(
            update={
                "objects": (
                    BackupObjectEntry(
                        workspace_id="019a0000-0000-7000-8000-000000000021",
                        blob_id=first_blob,
                        digest=duplicate_digest,
                        size_bytes=32,
                        storage_ref="a" * 32,
                    ),
                    BackupObjectEntry(
                        workspace_id="019a0000-0000-7000-8000-000000000022",
                        blob_id=second_blob,
                        digest=duplicate_digest,
                        size_bytes=32,
                        storage_ref="b" * 32,
                    ),
                )
            }
        ),
        private_key=private_key,
    )
    record = export_ed25519_public_key_record(
        private_key=private_key,
        key_id="backup-key-1",
        not_before=NOW,
        trust_domain="red2pr-backup",
    )
    archive = build_bundle(
        manifest,
        payload=payload,
        objects={first_blob: b"ciphertext workspace A", second_blob: b"ciphertext workspace B"},
    )
    restored, restored_payload, objects = read_bundle(archive, keyring=KeyRing([record]), now=NOW)
    assert restored_payload == payload
    assert len(restored.objects) == 2
    assert objects == {
        first_blob: b"ciphertext workspace A",
        second_blob: b"ciphertext workspace B",
    }
    archive_path = tmp_path / "duplicate-digests.tar.gz"
    archive_path.write_bytes(archive)
    _manifest, _dump, streamed_objects = _extract_bundle_file(
        archive_path,
        tmp_path / "duplicate-digests",
        keyring=KeyRing([record]),
        now=NOW,
    )
    assert streamed_objects[first_blob].read_bytes() == b"ciphertext workspace A"
    assert streamed_objects[second_blob].read_bytes() == b"ciphertext workspace B"


def test_restore_database_properties_quote_signed_locale_and_require_icu_locale() -> None:
    private_key = Ed25519PrivateKey.generate()
    manifest = signed_manifest(private_key, b"dump")
    assert "LC_COLLATE 'C.UTF-8'" in _restore_database_properties(manifest)

    icu = manifest.model_copy(
        update={
            "database_locale_provider": "icu",
            "database_collation": "unused",
            "database_character_type": "unused",
            "database_icu_locale": "en_US",
        }
    )
    clauses = _restore_database_properties(icu)
    assert "ICU_LOCALE 'en_US'" in clauses

    with pytest.raises(RuntimeError, match="backup_database_locale_invalid"):
        _restore_database_properties(
            icu.model_copy(update={"database_icu_locale": "en_US'); DROP DATABASE red2pr; --"})
        )
    with pytest.raises(RuntimeError, match="backup_database_locale_invalid"):
        _restore_database_properties(icu.model_copy(update={"database_icu_locale": None}))


def test_restore_preflight_checks_external_kek_versions_not_current_secret_rows() -> None:
    private_key = Ed25519PrivateKey.generate()
    manifest = signed_manifest(private_key, b"dump").model_copy(
        update={
            "key_references": (
                BackupKeyReference(
                    secret_ref="secret-one",
                    workspace_id="019a0000-0000-7000-8000-000000000021",
                    purpose="provider_read",
                    active_key_version=4,
                    kek_version=2,
                ),
                BackupKeyReference(
                    secret_ref="secret-two",
                    workspace_id="019a0000-0000-7000-8000-000000000022",
                    purpose="notification_channel",
                    active_key_version=1,
                    kek_version=7,
                ),
            )
        }
    )
    assert _unavailable_secret_key_versions(manifest, lambda version: version == 2) == (7,)
    assert _unavailable_secret_key_versions(manifest, None) == (2, 7)

    def keyring_unavailable(_version: int) -> bool:
        raise OSError("fixture unavailable")

    assert _unavailable_secret_key_versions(manifest, keyring_unavailable) == (2, 7)


def test_secret_broker_exposes_only_external_kek_version_availability(monkeypatch) -> None:
    broker = SecretBroker(
        key_ring=MasterKeyRing(active_version=3, keys={2: b"2" * 32, 3: b"3" * 32})
    )
    monkeypatch.delenv("RED2PR_MASTER_KEY_FILE", raising=False)
    assert broker.has_master_key_version(2) is True
    assert broker.has_master_key_version(3) is True
    assert broker.has_master_key_version(4) is False


def test_streaming_backup_extraction_checks_manifest_digest_and_unsafe_paths(tmp_path) -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = b"large dump streamed in bounded chunks"
    manifest = signed_manifest(private_key, payload)
    record = export_ed25519_public_key_record(
        private_key=private_key,
        key_id="backup-key-1",
        not_before=NOW,
        trust_domain="red2pr-backup",
    )
    archive_path = tmp_path / "backup.tar.gz"
    archive_path.write_bytes(build_bundle(manifest, payload=payload, objects={}))
    extracted_manifest, dump_path, object_paths = _extract_bundle_file(
        archive_path,
        tmp_path / "members",
        keyring=KeyRing([record]),
        now=NOW,
    )
    assert extracted_manifest.backup_id == manifest.backup_id
    assert dump_path.read_bytes() == payload
    assert object_paths == {}

    missing_object_manifest = sign_backup_manifest(
        manifest.model_copy(
            update={
                "objects": (
                    BackupObjectEntry(
                        workspace_id="019a0000-0000-7000-8000-000000000011",
                        blob_id="019a0000-0000-7000-8000-000000000012",
                        digest="c" * 64,
                        size_bytes=32,
                        storage_ref="local://workspace/blob.enc",
                    ),
                ),
                "signature": "",
            }
        ),
        private_key=private_key,
    )
    missing_object_path = tmp_path / "missing-object.tar.gz"
    complete_archive = build_bundle(
        missing_object_manifest,
        payload=payload,
        objects={missing_object_manifest.objects[0].blob_id: b"x" * 32},
    )
    malformed_archive = io.BytesIO()
    with (
        tarfile.open(fileobj=io.BytesIO(complete_archive), mode="r:gz") as complete,
        tarfile.open(fileobj=malformed_archive, mode="w:gz") as malformed,
    ):
        for member in complete.getmembers():
            if member.name.startswith("objects/"):
                continue
            member_stream = complete.extractfile(member)
            assert member_stream is not None
            malformed.addfile(member, member_stream)
    missing_object_path.write_bytes(malformed_archive.getvalue())
    with pytest.raises(ValueError, match="inventory does not match"):
        _extract_bundle_file(
            missing_object_path,
            tmp_path / "missing-object-members",
            keyring=KeyRing([record]),
            now=NOW,
        )

    unsafe_archive = io.BytesIO()
    with tarfile.open(fileobj=unsafe_archive, mode="w:gz") as archive:
        member = tarfile.TarInfo("../database.dump")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    unsafe_path = tmp_path / "unsafe.tar.gz"
    unsafe_path.write_bytes(unsafe_archive.getvalue())
    with pytest.raises(ValueError, match="unsafe member"):
        _extract_bundle_file(
            unsafe_path,
            tmp_path / "unsafe-members",
            keyring=KeyRing([record]),
            now=NOW,
        )


def test_streaming_bundle_writer_round_trips_without_buffering_dump(tmp_path) -> None:
    private_key = Ed25519PrivateKey.generate()
    payload = b"streamed pg dump"
    manifest = signed_manifest(private_key, payload)
    record = export_ed25519_public_key_record(
        private_key=private_key,
        key_id="backup-key-1",
        not_before=NOW,
        trust_domain="red2pr-backup",
    )
    payload_path = tmp_path / "database.dump"
    payload_path.write_bytes(payload)
    bundle_path, digest, size = write_bundle_file(
        tmp_path / "backup.tar.gz",
        manifest=manifest,
        payload_path=payload_path,
        object_paths={},
        owned_root=tmp_path,
    )
    assert bundle_path.stat().st_size == size
    assert hashlib.sha256(bundle_path.read_bytes()).hexdigest() == digest
    extracted, dump_path, objects = _extract_bundle_file(
        bundle_path, tmp_path / "out", keyring=KeyRing([record]), now=NOW
    )
    assert extracted.backup_id == manifest.backup_id
    assert dump_path.read_bytes() == payload
    assert objects == {}


def test_support_preview_and_bundle_exclude_non_allowlisted_files_and_redact_secrets() -> None:
    preview = render_support_bundle_preview(("health_summary", "doctor_report"), now=NOW)
    assert preview.excluded_secrets and preview.excluded_repository_source
    bundle, digest = create_support_bundle(
        ("health_summary",),
        {
            "health_summary": {"status": "ok", "api_key": "canary-secret-123456"},
            "repository_source": "private",
        },
    )
    assert hashlib.sha256(bundle).hexdigest() == digest
    assert b"canary-secret-123456" not in bundle
    assert b"repository_source" not in bundle


def test_recent_support_logs_are_confined_bounded_and_redacted(tmp_path, monkeypatch) -> None:
    root = tmp_path / "logs"
    root.mkdir()
    log_file = root / "control.log"
    log_file.write_text(
        "Authorization: Bearer abcdefghijklmnop\npassword=secret-value\n", encoding="utf-8"
    )
    monkeypatch.setenv("RED2PR_LOG_DIRECTORY", str(root))
    monkeypatch.setenv("RED2PR_LOG_FILE", str(log_file))
    source = read_recent_redacted_logs(max_lines=1)
    assert source["line_count"] == 1
    assert "ffrd2qmi" not in str(source)
    assert "abcdefghijklmnop" not in str(source)

    monkeypatch.setenv("RED2PR_LOG_FILE", str(tmp_path / "outside.log"))
    with pytest.raises(RuntimeError, match="not_configured"):
        read_recent_redacted_logs()


def test_purge_path_is_confined_and_rejects_home_and_symlink(tmp_path) -> None:
    root = tmp_path / "red2pr-data"
    root.mkdir()
    owned_child = root / "cache"
    owned_child.mkdir()
    assert validate_purge_path(owned_child, owned_roots=(root,)) == owned_child.resolve()
    with pytest.raises(UnsafePurgePath):
        validate_purge_path(tmp_path, owned_roots=(root,))
    link = root / "escape"
    try:
        link.symlink_to(tmp_path, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation unavailable in this test environment")
    with pytest.raises(UnsafePurgePath):
        validate_purge_path(link / "outside", owned_roots=(root,))


@pytest.mark.asyncio
async def test_encrypted_artifact_ciphertext_export_restore_and_missing_key_block(tmp_path) -> None:
    keyring = MasterKeyRing(active_version=1, keys={1: b"k" * 32})
    source = LocalEncryptedArtifactStore(root_dir=tmp_path / "source", key_ring=keyring)
    target = LocalEncryptedArtifactStore(root_dir=tmp_path / "target", key_ring=keyring)
    plaintext = b"verified proof bytes"
    digest = hashlib.sha256(plaintext).hexdigest()
    stage = await source.stage_upload(
        workspace_id="workspace-1", plaintext=plaintext, expected_digest=digest, now=NOW
    )
    await source.verify_staged(stage)
    storage_ref = await source.finalize_staged(stage)
    ciphertext = await source.export_encrypted_blob(
        workspace_id="workspace-1", storage_ref=storage_ref, expected_digest=digest
    )
    await target.restore_encrypted_blob(
        workspace_id="workspace-1",
        storage_ref=storage_ref,
        expected_digest=digest,
        ciphertext=ciphertext,
    )
    assert (
        await target.read_verified(
            workspace_id="workspace-1", storage_ref=storage_ref, expected_digest=digest
        )
        == plaintext
    )

    no_key = LocalEncryptedArtifactStore(
        root_dir=tmp_path / "no-key", key_ring=MasterKeyRing(active_version=2, keys={2: b"n" * 32})
    )
    with pytest.raises(ArtifactIntegrityError, match="cannot be authenticated"):
        await no_key.restore_encrypted_blob(
            workspace_id="workspace-1",
            storage_ref=storage_ref,
            expected_digest=digest,
            ciphertext=ciphertext,
        )
