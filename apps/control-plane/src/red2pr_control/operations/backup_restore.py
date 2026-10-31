"""Signed backup primitives and confined bundle I/O for U26 (OPS-02 / INS-03)."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import io
import json
import logging
import os
import re
import shutil
import sys
import tarfile
import tempfile
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from sqlalchemy import select, text
from sqlalchemy import update as sa_update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from py_contracts.crypto import (
    CryptoVerificationError,
    KeyRing,
    MasterKeyRing,
    PublicKeyRecord,
    canonical_json_bytes,
    sign_domain_separated_ed25519,
    verify_model_ed25519,
)
from py_contracts.operations import (
    BackupKeyReference,
    BackupManifestV1,
    BackupObjectEntry,
    RestorePlan,
)
from py_contracts.primitives import new_uuid7
from red2pr_control.db.base import (
    ArtifactBlobModel,
    ArtifactModel,
    BackupRecordModel,
    EffectReplayGuardModel,
    EffectTombstoneModel,
    InstanceModel,
    OutboxEventModel,
    SecretEntryModel,
    TaskJobModel,
    WorkerModel,
    WorkspaceModel,
)
from red2pr_control.db.engine import normalize_psycopg_url
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.operations.backup_encryption import BackupEncryptor, decrypt_backup_chunks
from red2pr_control.operations.runtime import exclusive_recovery_lease
from red2pr_control.secrets.broker import load_master_key_ring_from_file
from red2pr_control.triage_evidence.artifact_store import ArtifactStoreProtocol

DOMAIN_BACKUP_MANIFEST_V1 = "red2pr:backup_manifest:v1"
_MAX_BUNDLE_BYTES = 20 * 1024 * 1024 * 1024
_MAX_MEMBER_COUNT = 100_000
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_OBJECT_BYTES = 500 * 1024 * 1024
BACKUP_HOLD_LOCK = 1_328_921_026
_RESTORE_MARKER = "restore-recovery.json"
_LOGGER = logging.getLogger(__name__)


def _unavailable_secret_key_versions(
    manifest: BackupManifestV1,
    key_version_available: Callable[[int], bool] | None,
) -> tuple[int, ...]:
    unavailable: list[int] = []
    for reference in manifest.key_references:
        try:
            available = key_version_available is not None and key_version_available(
                reference.kek_version
            )
        except Exception:
            available = False
        if not available:
            unavailable.append(reference.kek_version)
    return tuple(sorted(set(unavailable)))


def _backup_signer() -> tuple[Ed25519PrivateKey, str]:
    path = os.environ.get("RED2PR_BACKUP_SIGNING_KEY_FILE", "").strip()
    key_id = os.environ.get("RED2PR_BACKUP_SIGNER_KEY_ID", "").strip()
    if not path or not key_id:
        raise RuntimeError("backup_signer_not_configured")
    key = load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("backup_signer_invalid")
    return key, key_id


def _backup_trust_store() -> KeyRing:
    trust_path = os.environ.get("RED2PR_BACKUP_TRUSTED_KEYS_FILE", "").strip()
    if not trust_path:
        raise RuntimeError("backup_trust_store_not_configured")
    try:
        parsed = json.loads(Path(trust_path).read_text(encoding="utf-8"))
        raw_records = parsed.get("keys") if isinstance(parsed, dict) else None
        if not isinstance(raw_records, list) or not raw_records:
            raise ValueError("trusted keys must be a non-empty list")
        records = [PublicKeyRecord.model_validate(item) for item in raw_records]
        return KeyRing(records)
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError("backup_trust_store_invalid") from exc


async def _run_pg_dump(
    database_url: str, snapshot_id: str, destination: Path, *, keys: MasterKeyRing, backup_id: str
) -> None:
    parsed = make_url(database_url)
    executable = os.environ.get("RED2PR_PG_DUMP") or shutil.which("pg_dump")
    if not executable:
        raise RuntimeError("pg_dump_unavailable")
    env = dict(os.environ)
    env.pop("PGPASSWORD", None)
    if parsed.password:
        env["PGPASSWORD"] = parsed.password
    for query_key, env_key in (
        ("sslmode", "PGSSLMODE"),
        ("sslrootcert", "PGSSLROOTCERT"),
        ("sslcert", "PGSSLCERT"),
        ("sslkey", "PGSSLKEY"),
    ):
        value = parsed.query.get(query_key)
        if isinstance(value, str):
            env[env_key] = value
    command = [
        executable,
        "--format=custom",
        f"--snapshot={snapshot_id}",
    ]
    host = parsed.host or parsed.query.get("host")
    port = parsed.port or parsed.query.get("port")
    if isinstance(host, str) and host:
        command.extend(["--host", host])
    if port:
        command.extend(["--port", str(port)])
    if parsed.username:
        command.extend(["--username", parsed.username])
    command.extend(["--dbname", parsed.database or ""])
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env=env,
        shell=False,
    )
    try:

        async def encrypt_dump() -> None:
            assert process.stdout is not None
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                encryptor = BackupEncryptor(output, keys=keys, backup_id=backup_id)
                while chunk := await process.stdout.read(1024 * 1024):
                    encryptor.update(chunk)
                if await process.wait() != 0:
                    raise RuntimeError("pg_dump_failed")
                encryptor.finish()
                output.flush()
                os.fsync(output.fileno())

        await asyncio.wait_for(encrypt_dump(), timeout=900)
    except asyncio.CancelledError:
        process.kill()
        await process.wait()
        raise
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise RuntimeError("pg_dump_timeout") from exc
    except Exception:
        if process.returncode is None:
            process.kill()
            await process.wait()
        raise


def _restore_database_properties(manifest: BackupManifestV1) -> str:
    """Build the locale clause for a stage DB from signed, SQL-literal-quoted metadata."""

    def literal(value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,120}", value):
            raise RuntimeError("backup_database_locale_invalid")
        return "'" + value.replace("'", "''") + "'"

    clauses = [f"ENCODING {literal(manifest.database_encoding)}"]
    if manifest.database_locale_provider == "icu":
        if not manifest.database_icu_locale:
            raise RuntimeError("backup_database_locale_invalid")
        clauses.extend(
            [
                "LOCALE_PROVIDER icu",
                f"ICU_LOCALE {literal(manifest.database_icu_locale)}",
            ]
        )
    else:
        clauses.extend(
            [
                f"LC_COLLATE {literal(manifest.database_collation)}",
                f"LC_CTYPE {literal(manifest.database_character_type)}",
            ]
        )
    return " ".join(clauses)


async def _run_pg_restore(
    database_url: str,
    destination_db: str,
    dump_path: Path,
    *,
    keys: MasterKeyRing,
    backup_id: str,
    key_version: int,
) -> None:
    """Restore into a new isolated database with one transaction and no shell."""
    parsed = make_url(database_url)
    executable = os.environ.get("RED2PR_PG_RESTORE") or shutil.which("pg_restore")
    if not executable:
        raise RuntimeError("pg_restore_unavailable")
    env = dict(os.environ)
    env.pop("PGPASSWORD", None)
    if parsed.password:
        env["PGPASSWORD"] = parsed.password
    for query_key, env_key in (
        ("sslmode", "PGSSLMODE"),
        ("sslrootcert", "PGSSLROOTCERT"),
        ("sslcert", "PGSSLCERT"),
        ("sslkey", "PGSSLKEY"),
    ):
        value = parsed.query.get(query_key)
        if value:
            env[env_key] = str(value)
    command = [
        executable,
        "--format=custom",
        "--exit-on-error",
        "--single-transaction",
    ]
    host = parsed.host or parsed.query.get("host")
    port = parsed.port or parsed.query.get("port")
    if isinstance(host, str) and host:
        command.extend(["--host", host])
    if port:
        command.extend(["--port", str(port)])
    if parsed.username:
        command.extend(["--username", parsed.username])
    command.extend(["--dbname", destination_db])
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        env=env,
        shell=False,
    )
    try:

        async def restore_dump() -> None:
            assert process.stdin is not None
            for chunk in decrypt_backup_chunks(
                dump_path, keys=keys, backup_id=backup_id, expected_version=key_version
            ):
                process.stdin.write(chunk)
                await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()
            await process.wait()

        await asyncio.wait_for(restore_dump(), timeout=1800)
    except asyncio.CancelledError:
        process.kill()
        await process.wait()
        raise
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise RuntimeError("pg_restore_timeout") from exc
    except Exception:
        if process.returncode is None:
            process.kill()
            await process.wait()
        raise
    if process.returncode != 0:
        raise RuntimeError("pg_restore_failed")


def _safe_database_name(value: str) -> str:
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,62}", value) or value.casefold() in {
        "postgres",
        "template0",
        "template1",
    }:
        raise RuntimeError("restore_database_name_invalid")
    return value


def _restore_marker_path(root: Path) -> Path:
    path = root / _RESTORE_MARKER
    if path.is_symlink():
        raise RuntimeError("restore_marker_unsafe")
    return path


def _write_restore_marker(root: Path, value: dict[str, str | int]) -> None:
    path = _restore_marker_path(root)
    fd, temp_name = tempfile.mkstemp(prefix=".red2pr-restore-", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
        if os.name != "nt":
            descriptor = os.open(root, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise


def _read_restore_marker(root: Path) -> dict[str, str | int] | None:
    path = _restore_marker_path(root)
    if not path.exists():
        return None
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError("restore_marker_invalid") from exc
    required = {
        "restore_id",
        "target",
        "staging",
        "quarantine",
        "phase",
        "recovery_epoch",
        "backup_id",
        "manifest_digest",
        "plan_digest",
    }
    if not isinstance(parsed, dict) or set(parsed) != required:
        raise RuntimeError("restore_marker_invalid")
    if parsed["phase"] not in {
        "prepared",
        "current_moved",
        "stage_promoted",
        "complete",
        "aborted",
    }:
        raise RuntimeError("restore_marker_invalid")
    for key in ("target", "staging", "quarantine"):
        try:
            parsed[key] = _safe_database_name(str(parsed[key]))
        except RuntimeError as exc:
            raise RuntimeError("restore_marker_invalid") from exc
    try:
        canonical_restore_id = str(uuid.UUID(str(parsed["restore_id"])))
        canonical_backup_id = str(uuid.UUID(str(parsed["backup_id"])))
    except (ValueError, AttributeError) as exc:
        raise RuntimeError("restore_marker_invalid") from exc
    staging = str(parsed["staging"])
    quarantine = str(parsed["quarantine"])
    if (
        canonical_restore_id != parsed["restore_id"]
        or canonical_backup_id != parsed["backup_id"]
        or not re.fullmatch(r"[0-9a-f]{64}", str(parsed["manifest_digest"]))
        or not re.fullmatch(r"[0-9a-f]{64}", str(parsed["plan_digest"]))
        or not re.fullmatch(r"r2pr_r_[0-9a-f]{12}", staging)
        or not re.fullmatch(r"r2pr_q_[0-9a-f]{12}", quarantine)
        or staging[7:] != quarantine[7:]
        or isinstance(parsed["recovery_epoch"], bool)
        or not isinstance(parsed["recovery_epoch"], int)
        or parsed["recovery_epoch"] < 1
    ):
        raise RuntimeError("restore_marker_invalid")
    return parsed


async def _admin_connection(database_url: str) -> AsyncEngine:
    parsed = make_url(database_url)
    if parsed.drivername not in {"postgresql", "postgresql+psycopg", "postgres"}:
        raise RuntimeError("restore_database_url_invalid")
    admin_url = parsed.set(database="postgres")
    engine = create_async_engine(
        normalize_psycopg_url(admin_url.render_as_string(hide_password=False))
    )
    return engine


async def _create_staging_database(
    database_url: str, name: str, manifest: BackupManifestV1
) -> None:
    admin = await _admin_connection(database_url)
    role = _safe_database_name(os.environ.get("RED2PR_APP_DB_ROLE", "red2pr_app").strip())
    try:
        properties = _restore_database_properties(manifest)
        async with admin.connect() as connection:
            await connection.execution_options(isolation_level="AUTOCOMMIT")
            preparer = connection.dialect.identifier_preparer
            await connection.execute(
                text(
                    f"CREATE DATABASE {preparer.quote(name)} OWNER {preparer.quote(role)} "
                    f"TEMPLATE template0 {properties}"
                )
            )
    finally:
        await admin.dispose()


async def _drop_staging_database(database_url: str, name: str) -> None:
    admin = await _admin_connection(database_url)
    try:
        async with admin.connect() as connection:
            await connection.execution_options(isolation_level="AUTOCOMMIT")
            preparer = connection.dialect.identifier_preparer
            await connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname=:name AND pid <> pg_backend_pid()"
                ),
                {"name": name},
            )
            await connection.execute(text(f"DROP DATABASE IF EXISTS {preparer.quote(name)}"))
    finally:
        await admin.dispose()


async def _rename_database(database_url: str, source: str, destination: str) -> None:
    admin = await _admin_connection(database_url)
    try:
        async with admin.connect() as connection:
            await connection.execution_options(isolation_level="AUTOCOMMIT")
            preparer = connection.dialect.identifier_preparer
            deadline = asyncio.get_running_loop().time() + 10
            while True:
                await connection.execute(
                    text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname=:name AND pid <> pg_backend_pid()"
                    ),
                    {"name": source},
                )
                remaining = await connection.scalar(
                    text("SELECT count(*) FROM pg_stat_activity WHERE datname=:name"),
                    {"name": source},
                )
                if not remaining:
                    break
                if asyncio.get_running_loop().time() >= deadline:
                    raise RuntimeError("restore_database_connections_not_drained")
                await asyncio.sleep(0.05)
            await connection.execute(
                text(
                    f"ALTER DATABASE {preparer.quote(source)} "
                    f"RENAME TO {preparer.quote(destination)}"
                )
            )
    finally:
        await admin.dispose()


async def _set_database_connections(database_url: str, name: str, allowed: bool) -> None:
    admin = await _admin_connection(database_url)
    try:
        async with admin.connect() as connection:
            await connection.execution_options(isolation_level="AUTOCOMMIT")
            preparer = connection.dialect.identifier_preparer
            await connection.execute(
                text(
                    f"ALTER DATABASE {preparer.quote(name)} WITH ALLOW_CONNECTIONS "
                    f"{'true' if allowed else 'false'}"
                )
            )
    finally:
        await admin.dispose()


async def recover_interrupted_restore(database_url: str, backup_root: Path) -> str | None:
    """Finish an interrupted DB rename before serving traffic; never delete quarantine data."""
    root = backup_root.resolve(strict=True)
    marker = _read_restore_marker(root)
    if marker is None or marker["phase"] in {"complete", "aborted"}:
        return None if marker is None else str(marker["phase"])
    target, staging, quarantine = (str(marker[key]) for key in ("target", "staging", "quarantine"))
    configured_target = make_url(database_url).database
    if configured_target is None or target != _safe_database_name(configured_target):
        raise RuntimeError("restore_marker_target_mismatch")
    admin = await _admin_connection(database_url)
    try:
        async with admin.connect() as connection:
            exists = set(
                await connection.scalars(
                    text(
                        "SELECT datname FROM pg_database WHERE datname IN "
                        "(:target,:stage,:quarantine)"
                    ),
                    {"target": target, "stage": staging, "quarantine": quarantine},
                )
            )
        if target not in exists and staging in exists and quarantine in exists:
            await _rename_database(database_url, staging, target)
            await _set_database_connections(database_url, quarantine, True)
            marker["phase"] = "complete"
            _write_restore_marker(root, marker)
            return "complete"
        if target in exists and staging in exists and quarantine not in exists:
            # The old database is still authoritative; discard only the isolated staging DB.
            await _set_database_connections(database_url, target, True)
            await _drop_staging_database(database_url, staging)
            marker["phase"] = "aborted"
            _write_restore_marker(root, marker)
            return "complete"
        if target in exists and staging not in exists and quarantine not in exists:
            await _set_database_connections(database_url, target, True)
            marker["phase"] = "aborted"
            _write_restore_marker(root, marker)
            return "complete"
        if target in exists and staging not in exists and quarantine in exists:
            await _set_database_connections(database_url, quarantine, True)
            marker["phase"] = "complete"
            _write_restore_marker(root, marker)
            return "complete"
        raise RuntimeError("restore_recovery_topology_invalid")
    finally:
        await admin.dispose()


async def _run_stage_migrations(database_url: str, staging: str, target_revision: str) -> None:
    stage_url = make_url(database_url).set(database=staging).render_as_string(hide_password=False)
    env = dict(os.environ)
    env["RED2PR_ADMIN_DATABASE_URL"] = stage_url
    config = Path(__file__).resolve().parents[3] / "alembic.ini"
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "alembic",
        "-c",
        str(config),
        "upgrade",
        target_revision,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        env=env,
        shell=False,
    )
    try:
        await asyncio.wait_for(process.wait(), timeout=900)
    except asyncio.CancelledError:
        process.kill()
        await process.wait()
        raise
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise RuntimeError("restore_migration_timeout") from exc
    if process.returncode != 0:
        raise RuntimeError("restore_migration_failed")


async def _copy_replay_protection(
    source_factory: async_sessionmaker[AsyncSession],
    target_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Merge current replay tombstones into the restored snapshot without overwriting it."""
    async with instance_rls_session(source_factory, mode="instance_admin") as source:
        source_workspaces = {row.id: row for row in await source.scalars(select(WorkspaceModel))}
        tombstones = [
            {
                column.name: getattr(row, column.name)
                for column in EffectTombstoneModel.__table__.columns
            }
            for row in await source.scalars(select(EffectTombstoneModel))
        ]
        guards = [
            {
                column.name: getattr(row, column.name)
                for column in EffectReplayGuardModel.__table__.columns
            }
            for row in await source.scalars(select(EffectReplayGuardModel))
        ]
    async with instance_rls_session(target_factory, mode="instance_admin") as target:
        target_workspaces = set(await target.scalars(select(WorkspaceModel.id)))
    surviving_workspaces = source_workspaces.keys() & target_workspaces
    for workspace_id in surviving_workspaces:
        current_workspace = source_workspaces[workspace_id]
        async with instance_rls_session(target_factory, mode="instance_admin") as target:
            restored_workspace = await target.get(WorkspaceModel, workspace_id)
            if current_workspace.deleted_at is not None and restored_workspace is not None:
                restored_workspace.deleted_at = current_workspace.deleted_at
                restored_workspace.status = "deleting"
                restored_workspace.paused = True
                restored_workspace.version = max(
                    restored_workspace.version, current_workspace.version
                )
                restored_workspace.updated_at = max(
                    restored_workspace.updated_at, current_workspace.updated_at
                )
        async with workspace_rls_session(source_factory, workspace_id=workspace_id) as source:
            purged_artifacts = list(
                await source.scalars(
                    select(ArtifactModel).where(ArtifactModel.lifecycle_state == "purged")
                )
            )
            purged_blobs = list(
                await source.scalars(
                    select(ArtifactBlobModel).where(ArtifactBlobModel.blob_state == "purged")
                )
            )
        async with workspace_rls_session(target_factory, workspace_id=workspace_id) as target:
            for artifact in purged_artifacts:
                await target.execute(
                    sa_update(ArtifactModel)
                    .where(
                        ArtifactModel.workspace_id == workspace_id,
                        ArtifactModel.id == artifact.id,
                    )
                    .values(
                        lifecycle_state="purged",
                        purge_reason=artifact.purge_reason,
                        version=ArtifactModel.version + 1,
                        updated_at=artifact.updated_at,
                    )
                )
            for blob in purged_blobs:
                await target.execute(
                    sa_update(ArtifactBlobModel)
                    .where(
                        ArtifactBlobModel.workspace_id == workspace_id,
                        ArtifactBlobModel.id == blob.id,
                    )
                    .values(
                        blob_state="purged",
                        version=ArtifactBlobModel.version + 1,
                        updated_at=blob.updated_at,
                    )
                )
            for model, rows in (
                (EffectTombstoneModel, tombstones),
                (EffectReplayGuardModel, guards),
            ):
                selected = [row for row in rows if row["workspace_id"] == workspace_id]
                if selected:
                    await target.execute(pg_insert(model).values(selected).on_conflict_do_nothing())


async def _prepare_restored_instance(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    recovery_epoch_floor: int,
    now: datetime,
    restore_id: str,
) -> int:
    """Fence stale workers and ambiguous external intents and leave maintenance enabled."""
    async with instance_rls_session(session_factory, mode="instance_admin") as db:
        instance = await db.scalar(select(InstanceModel).with_for_update())
        if instance is None:
            raise RuntimeError("restore_instance_state_missing")
        instance.recovery_epoch = max(instance.recovery_epoch, recovery_epoch_floor) + 1
        instance.maintenance_enabled = True
        instance.maintenance_reason = "Restore completed; reconcile external effects before resume."
        instance.maintenance_started_at = now
        instance.maintenance_started_by_user_id = None
        instance.version += 1
        instance.updated_at = now
        epoch = instance.recovery_epoch
        for worker in await db.scalars(select(WorkerModel)):
            if worker.status in {"online", "draining"}:
                worker.status = "offline"
            worker.mtls_cert_revoked_at = now
            worker.version += 1
            worker.updated_at = now
        for job in await db.scalars(
            select(TaskJobModel).where(
                TaskJobModel.state.in_(("queued", "leased", "running", "cancel_requested"))
            )
        ):
            job.state = "dead_letter"
            job.last_error_code = "restore_reconciliation_required"
            job.recoverable = False
            job.reconcile_required = True
            job.lease_epoch += 1
            job.leased_by_worker_id = None
            job.heartbeat_at = None
            job.lease_expires_at = None
            job.version += 1
            job.updated_at = now
        for outbox in await db.scalars(
            select(OutboxEventModel).where(OutboxEventModel.status == "claimed")
        ):
            outbox.status = "dead_letter"
            outbox.last_error_code = "restore_reconciliation_required"
        await db.execute(
            text(
                "UPDATE public.notification_deliveries SET state='unknown', next_retry_at=NULL, "
                "last_error_code='restore_reconciliation_required', updated_at=:now "
                "WHERE state IN ('sending','retry_wait')"
            ),
            {"now": now},
        )
        await db.execute(
            text(
                "UPDATE public.publication_records SET status='unknown', "
                "error_code='restore_reconciliation_required', updated_at=:now "
                "WHERE status IN ('intent','pushing','creating','reconciling')"
            ),
            {"now": now},
        )
        await db.execute(
            text(
                "UPDATE public.operation_receipts SET state='unknown', version=version+1, "
                "updated_at=:now WHERE state IN ('accepted','running')"
            ),
            {"now": now},
        )
        await db.execute(
            text(
                "UPDATE public.sessions SET revoked_at=:now, revoke_reason="
                "'restore_recovery', version=version+1, updated_at=:now "
                "WHERE revoked_at IS NULL"
            ),
            {"now": now},
        )
        await db.execute(
            text(
                "UPDATE public.api_tokens SET revoked_at=:now, grant_epoch=grant_epoch+1 "
                "WHERE revoked_at IS NULL"
            ),
            {"now": now},
        )
        from red2pr_control.analytics_audit.audit_chain import append_audit_entry

        await append_audit_entry(
            db,
            actor_type="system",
            actor_id="system-restore",
            action="instance.restore.completed",
            target=f"restore:{restore_id}",
            decision="allow",
            reason_code="signed_backup_and_plan_verified",
            correlation_id=f"restore:{restore_id}",
            occurred_at=now,
            metadata={"recovery_epoch": epoch, "maintenance_enabled": True},
        )
        return epoch


async def execute_restore(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    artifact_store: ArtifactStoreProtocol,
    backup_id: str,
    manifest_digest: str,
    plan_digest: str,
    key_version_available: Callable[[int], bool] | None = None,
    now: datetime | None = None,
) -> tuple[str, int]:
    """Restore to an isolated DB, preserve replay protection, then promote with a marker."""
    database_url = os.environ.get("RED2PR_ADMIN_DATABASE_URL", "").strip()
    backup_root_raw = os.environ.get("RED2PR_BACKUP_DIRECTORY", "").strip()
    if not database_url or not backup_root_raw:
        raise RuntimeError("restore_database_or_directory_not_configured")
    root = Path(backup_root_raw).resolve(strict=True)
    previous_marker = _read_restore_marker(root)
    if previous_marker is not None and previous_marker["phase"] not in {
        "complete",
        "stage_promoted",
        "aborted",
    }:
        raise RuntimeError("restore_recovery_pending")
    archive_path = (root / f"{backup_id}.tar.gz").resolve(strict=False)
    if (
        not archive_path.is_relative_to(root)
        or not archive_path.is_file()
        or archive_path.is_symlink()
    ):
        raise RuntimeError("backup_bundle_missing")
    restore_temp = tempfile.TemporaryDirectory(prefix=".restore-", dir=root)
    manifest, dump_path, object_paths = _extract_bundle_file(
        archive_path,
        Path(restore_temp.name) / "members",
        keyring=_backup_trust_store(),
    )
    if manifest.backup_id != backup_id:
        raise RuntimeError("backup_manifest_identity_mismatch")
    async with instance_rls_session(session_factory, mode="instance_admin") as db:
        record = await db.get(BackupRecordModel, backup_id)
        if record is None or record.state != "succeeded":
            raise RuntimeError("backup_record_unavailable")
        actual_bundle_digest = _file_sha256(archive_path)
        actual_manifest_digest = hashlib.sha256(
            canonical_json_bytes(manifest.model_dump(mode="json"))
        ).hexdigest()
        if (
            record.bundle_key != actual_bundle_digest
            or record.manifest_digest != actual_manifest_digest
        ):
            raise RuntimeError("backup_record_digest_mismatch")
        if not hmac.compare_digest(actual_manifest_digest, manifest_digest):
            raise RuntimeError("restore_manifest_digest_mismatch")
        current_revision = str(
            (
                await db.execute(text("SELECT version_num FROM public.alembic_version LIMIT 1"))
            ).scalar_one()
        )
        instance = await db.scalar(select(InstanceModel))
        if instance is None or not instance.maintenance_enabled:
            raise RuntimeError("restore_maintenance_required")
        recovery_epoch_floor = instance.recovery_epoch
    dry_run = await build_restore_dry_run(
        session_factory=session_factory,
        artifact_store=artifact_store,
        backup_id=backup_id,
        requested_target_revision=current_revision,
        key_version_available=key_version_available,
    )
    if not dry_run.compatible or not hmac.compare_digest(dry_run.plan_digest, plan_digest):
        raise RuntimeError("restore_plan_stale_or_incompatible")

    if (
        previous_marker is not None
        and previous_marker["phase"] == "complete"
        and previous_marker["backup_id"] == backup_id
        and hmac.compare_digest(str(previous_marker["manifest_digest"]), manifest_digest)
        and hmac.compare_digest(str(previous_marker["plan_digest"]), plan_digest)
    ):
        return str(previous_marker["restore_id"]), int(previous_marker["recovery_epoch"])

    parsed = make_url(database_url)
    target_db = _safe_database_name(parsed.database or "")
    if target_db.startswith(("r2pr_r_", "r2pr_q_")):
        raise RuntimeError("restore_database_name_reserved")
    suffix = uuid.uuid4().hex[:12]
    staging = _safe_database_name(f"r2pr_r_{suffix}")
    quarantine = _safe_database_name(f"r2pr_q_{suffix}")
    restore_id = str(new_uuid7(now=now.astimezone(UTC) if now else datetime.now(UTC)))
    marker: dict[str, str | int] = {
        "restore_id": restore_id,
        "target": target_db,
        "staging": staging,
        "quarantine": quarantine,
        "phase": "prepared",
        "recovery_epoch": recovery_epoch_floor,
        "backup_id": backup_id,
        "manifest_digest": manifest_digest,
        "plan_digest": plan_digest,
    }
    _write_restore_marker(root, marker)
    stage_engine = None
    try:
        async with exclusive_recovery_lease(session_factory) as state:
            if not state.enabled:
                raise RuntimeError("restore_maintenance_required")
            await _create_staging_database(database_url, staging, manifest)
            await _run_pg_restore(
                database_url,
                staging,
                dump_path,
                keys=load_master_key_ring_from_file(),
                backup_id=backup_id,
                key_version=manifest.payload_kek_version,
            )
            await _run_stage_migrations(database_url, staging, current_revision)
            stage_url = (
                make_url(database_url).set(database=staging).render_as_string(hide_password=False)
            )
            stage_engine = create_async_engine(normalize_psycopg_url(stage_url))
            stage_factory = async_sessionmaker(
                stage_engine, expire_on_commit=False, autoflush=False
            )
            await _copy_replay_protection(session_factory, stage_factory)
            for item in manifest.objects:
                async with workspace_rls_session(
                    stage_factory, workspace_id=item.workspace_id
                ) as stage:
                    blob_is_purged = await stage.scalar(
                        select(ArtifactBlobModel.id).where(
                            ArtifactBlobModel.workspace_id == item.workspace_id,
                            ArtifactBlobModel.id == item.blob_id,
                            ArtifactBlobModel.blob_state == "purged",
                        )
                    )
                if blob_is_purged is not None:
                    continue
                await artifact_store.restore_encrypted_blob(
                    workspace_id=item.workspace_id,
                    storage_ref=item.storage_ref,
                    expected_digest=item.digest,
                    ciphertext=object_paths[item.blob_id].read_bytes(),
                )
            epoch = await _prepare_restored_instance(
                stage_factory,
                recovery_epoch_floor=recovery_epoch_floor,
                now=now.astimezone(UTC) if now else datetime.now(UTC),
                restore_id=restore_id,
            )
            await stage_engine.dispose()
            stage_engine = None
            marker["recovery_epoch"] = epoch
            _write_restore_marker(root, marker)
        # Maintenance is committed and all admitted writes have drained before the rename.
        await _set_database_connections(database_url, target_db, False)
        target_engine = session_factory.kw.get("bind")
        if isinstance(target_engine, AsyncEngine):
            # Close idle pooled sessions before fencing/renaming the database. The
            # same engine will reconnect to the promoted database after cutover.
            await target_engine.dispose()
        await _rename_database(database_url, target_db, quarantine)
        marker["phase"] = "current_moved"
        _write_restore_marker(root, marker)
        await _rename_database(database_url, staging, target_db)
        marker["phase"] = "stage_promoted"
        _write_restore_marker(root, marker)
        await _set_database_connections(database_url, quarantine, True)
        marker["phase"] = "complete"
        _write_restore_marker(root, marker)
        return restore_id, int(marker["recovery_epoch"])
    except (Exception, asyncio.CancelledError):
        if stage_engine is not None:
            await stage_engine.dispose()
        try:
            current_marker = _read_restore_marker(root)
            if current_marker is not None and current_marker["phase"] in {
                "prepared",
                "current_moved",
                "stage_promoted",
            }:
                await recover_interrupted_restore(database_url, root)
                current_marker = _read_restore_marker(root)
                if (
                    current_marker is not None
                    and current_marker["phase"] in {"stage_promoted", "complete"}
                    and current_marker["restore_id"] == restore_id
                ):
                    await _set_database_connections(database_url, quarantine, True)
                    current_marker["phase"] = "complete"
                    _write_restore_marker(root, current_marker)
                    return restore_id, int(current_marker["recovery_epoch"])
        except Exception:
            _LOGGER.error("restore_staging_cleanup_failed", extra={"restore_id": restore_id})
        raise
    finally:
        restore_temp.cleanup()


async def create_consistent_backup(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    artifact_store: ArtifactStoreProtocol,
    created_by_user_id: str,
    correlation_id: str,
    label: str | None = None,
    now: datetime | None = None,
) -> tuple[BackupRecordModel, Path]:
    """Create a signed logical dump and encrypted object inventory bound to one snapshot."""
    database_url = os.environ.get("RED2PR_ADMIN_DATABASE_URL", "").strip()
    backup_root_raw = os.environ.get("RED2PR_BACKUP_DIRECTORY", "").strip()
    build_digest = os.environ.get("RED2PR_BUILD_DIGEST", "").strip().lower()
    config_digest = os.environ.get("RED2PR_CONFIG_DIGEST", "").strip().lower()
    if not database_url or not backup_root_raw:
        raise RuntimeError("backup_database_or_directory_not_configured")
    if not re.fullmatch(r"[0-9a-f]{64}", build_digest) or not re.fullmatch(
        r"[0-9a-f]{64}", config_digest
    ):
        raise RuntimeError("backup_build_or_config_digest_not_configured")
    signer, signer_id = _backup_signer()
    payload_keys = load_master_key_ring_from_file()
    ref_now = now.astimezone(UTC) if now else datetime.now(UTC)
    backup_id = new_uuid7(now=ref_now)
    root = Path(backup_root_raw)
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve(strict=True)
    dump_path = root / f".{backup_id}.dump.tmp"
    bundle_path = root / f"{backup_id}.tar.gz"
    object_temp_paths: list[Path] = []
    async with instance_rls_session(
        session_factory, mode="instance_admin", isolation_level="REPEATABLE READ"
    ) as db:
        await db.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": BACKUP_HOLD_LOCK}
        )
        try:
            snapshot_id, snapshot_lsn = (
                await db.execute(text("SELECT pg_export_snapshot(), pg_current_wal_lsn()::text"))
            ).one()
            if not re.fullmatch(r"[0-9A-Fa-f-]{1,80}", str(snapshot_id)):
                raise RuntimeError("database_snapshot_id_invalid")
            schema_revision = str(
                (
                    await db.execute(text("SELECT version_num FROM public.alembic_version LIMIT 1"))
                ).scalar_one()
            )
            postgres_version = str((await db.execute(text("SHOW server_version_num"))).scalar_one())
            database_properties = (
                await db.execute(
                    text(
                        "SELECT current_setting('server_encoding'), d.datlocprovider::text, "
                        "d.datcollate, d.datctype, d.daticulocale "
                        "FROM pg_database AS d WHERE d.datname=current_database()"
                    )
                )
            ).one()
            workspace_ids = tuple(
                await db.scalars(select(WorkspaceModel.id).order_by(WorkspaceModel.id))
            )
            blobs: list[ArtifactBlobModel] = []
            for workspace_id in workspace_ids:
                await db.execute(
                    text(
                        "SELECT set_config('red2pr.scope_mode','workspace',true), "
                        "set_config('red2pr.workspace_id',:ws,true)"
                    ),
                    {"ws": workspace_id},
                )
                blobs.extend(
                    await db.scalars(
                        select(ArtifactBlobModel)
                        .where(
                            ArtifactBlobModel.workspace_id == workspace_id,
                            ArtifactBlobModel.blob_state == "finalized",
                        )
                        .order_by(ArtifactBlobModel.id)
                    )
                )
            await db.execute(
                text(
                    "SELECT set_config('red2pr.scope_mode','instance_admin',true), "
                    "set_config('red2pr.workspace_id','',true)"
                )
            )
            key_references = tuple(
                BackupKeyReference(
                    secret_ref=item.secret_ref,
                    workspace_id=item.workspace_id,
                    purpose=item.purpose,
                    active_key_version=item.active_key_version,
                    kek_version=item.kek_version,
                )
                for item in await db.scalars(
                    select(SecretEntryModel).order_by(SecretEntryModel.secret_ref)
                )
            )
            encrypted_object_paths: dict[str, Path] = {}
            object_entries: list[BackupObjectEntry] = []
            for blob in blobs:
                ciphertext = await artifact_store.export_encrypted_blob(
                    workspace_id=blob.workspace_id,
                    storage_ref=blob.storage_ref,
                    expected_digest=blob.digest,
                )
                encrypted_path = root / f".{backup_id}.{blob.id}.enc.tmp"
                with encrypted_path.open("xb") as output:
                    output.write(ciphertext)
                    output.flush()
                    os.fsync(output.fileno())
                object_temp_paths.append(encrypted_path)
                encrypted_object_paths[blob.id] = encrypted_path
                object_entries.append(
                    BackupObjectEntry(
                        workspace_id=blob.workspace_id,
                        blob_id=blob.id,
                        digest=blob.digest,
                        size_bytes=blob.size_bytes,
                        storage_ref=blob.storage_ref,
                    )
                )
            await _run_pg_dump(
                database_url, str(snapshot_id), dump_path, keys=payload_keys, backup_id=backup_id
            )
            manifest = BackupManifestV1(
                backup_id=backup_id,
                created_at=ref_now,
                snapshot_lsn=str(snapshot_lsn),
                postgres_version=postgres_version,
                database_encoding=str(database_properties[0]),
                database_locale_provider=("icu" if database_properties[1] == "i" else "libc"),
                database_collation=str(database_properties[2]),
                database_character_type=str(database_properties[3]),
                database_icu_locale=(
                    str(database_properties[4]) if database_properties[4] is not None else None
                ),
                schema_revision=schema_revision,
                application_version="0.1.0",
                build_digest=build_digest,
                config_digest=config_digest,
                workspace_ids=workspace_ids,
                objects=tuple(object_entries),
                key_references=key_references,
                payload_sha256=_file_sha256(dump_path),
                payload_kek_version=payload_keys.active_version,
                signer_key_id=signer_id,
                signature="",
            )
            signed = sign_backup_manifest(manifest, private_key=signer)
            _, bundle_digest, bundle_size = write_bundle_file(
                bundle_path,
                manifest=signed,
                payload_path=dump_path,
                object_paths=encrypted_object_paths,
                owned_root=root,
            )
            digest = hashlib.sha256(
                canonical_json_bytes(signed.model_dump(mode="json"))
            ).hexdigest()
            record = BackupRecordModel(
                id=backup_id,
                state="succeeded",
                created_by_user_id=created_by_user_id,
                correlation_id=correlation_id,
                label=label,
                bundle_key=bundle_digest,
                manifest_json=signed.model_dump(mode="json"),
                manifest_digest=digest,
                snapshot_lsn=str(snapshot_lsn),
                schema_revision=schema_revision,
                size_bytes=bundle_size,
                object_count=len(object_entries),
                completed_at=ref_now,
                expires_at=ref_now + timedelta(days=365),
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(record)
            return record, bundle_path
        finally:
            dump_path.unlink(missing_ok=True)
            for path in object_temp_paths:
                path.unlink(missing_ok=True)


async def build_restore_dry_run(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    artifact_store: ArtifactStoreProtocol,
    backup_id: str,
    requested_target_revision: str | None = None,
    key_version_available: Callable[[int], bool] | None = None,
) -> RestorePlan:
    """Verify signed archive, object keys, key references and one-step schema compatibility."""
    backup_root_raw = os.environ.get("RED2PR_BACKUP_DIRECTORY", "").strip()
    if not backup_root_raw:
        raise RuntimeError("backup_directory_not_configured")
    root = Path(backup_root_raw).resolve(strict=True)
    archive_path = (root / f"{backup_id}.tar.gz").resolve(strict=False)
    if (
        not archive_path.is_relative_to(root)
        or not archive_path.is_file()
        or archive_path.is_symlink()
    ):
        raise RuntimeError("backup_bundle_missing")
    keyring = _backup_trust_store()
    with tempfile.TemporaryDirectory(prefix=".restore-preflight-", dir=root) as temporary:
        manifest, dump_path, object_paths = _extract_bundle_file(
            archive_path,
            Path(temporary) / "members",
            keyring=keyring,
        )
        if manifest.backup_id != backup_id:
            raise RuntimeError("backup_manifest_identity_mismatch")
        bundle_digest = _file_sha256(archive_path)
        async with instance_rls_session(session_factory, mode="instance_admin") as db:
            backup = await db.get(BackupRecordModel, backup_id)
            if backup is None or backup.state != "succeeded":
                raise RuntimeError("backup_record_unavailable")
            if backup.bundle_key != bundle_digest:
                raise RuntimeError("backup_bundle_digest_mismatch")
            manifest_digest = hashlib.sha256(
                canonical_json_bytes(manifest.model_dump(mode="json"))
            ).hexdigest()
            if backup.manifest_digest != manifest_digest:
                raise RuntimeError("backup_manifest_digest_mismatch")
            current_revision = str(
                (
                    await db.execute(text("SELECT version_num FROM public.alembic_version LIMIT 1"))
                ).scalar_one()
            )
            target_revision = requested_target_revision or current_revision
            parent_revision = (
                await db.execute(
                    text(
                        "SELECT parent_revision FROM public.schema_migrations "
                        "WHERE revision=:revision"
                    ),
                    {"revision": current_revision},
                )
            ).scalar_one_or_none()
            source_schema_compatible = manifest.schema_revision in {
                current_revision,
                parent_revision,
            }
            compatible_schema = target_revision == current_revision and source_schema_compatible
        missing_key_refs = _unavailable_secret_key_versions(manifest, key_version_available)
        blockers: list[str] = []
        if not compatible_schema:
            blockers.append("schema_incompatible")
        if missing_key_refs:
            blockers.append("key_reference_missing")
        try:
            for _ in decrypt_backup_chunks(
                dump_path,
                keys=load_master_key_ring_from_file(),
                backup_id=backup_id,
                expected_version=manifest.payload_kek_version,
            ):
                pass
        except (ValueError, RuntimeError):
            blockers.append("backup_payload_key_or_integrity_missing")
        for item in manifest.objects:
            try:
                await artifact_store.verify_encrypted_blob(
                    workspace_id=item.workspace_id,
                    expected_digest=item.digest,
                    ciphertext=object_paths[item.blob_id].read_bytes(),
                )
            except Exception:
                blockers.append("artifact_key_or_integrity_missing")
                break
    plan_fields: dict[str, object] = {
        "backup_id": manifest.backup_id,
        "manifest_digest": manifest_digest,
        "target_schema_revision": target_revision,
        "compatible": not blockers,
        "requires_maintenance": True,
        "restores_artifacts": True,
        "rotates_recovery_epoch": True,
        "reapplies_retention_tombstones": True,
        "requires_remote_reconciliation": True,
        "blockers": tuple(dict.fromkeys(blockers)),
        "warnings": (
            "External publication and notification effects require explicit "
            "reconciliation after restore.",
        ),
    }
    plan_digest = hashlib.sha256(canonical_json_bytes(plan_fields)).hexdigest()
    return RestorePlan(
        backup_id=manifest.backup_id,
        manifest_digest=manifest_digest,
        target_schema_revision=target_revision,
        compatible=not blockers,
        requires_maintenance=True,
        restores_artifacts=True,
        rotates_recovery_epoch=True,
        reapplies_retention_tombstones=True,
        requires_remote_reconciliation=True,
        blockers=tuple(dict.fromkeys(blockers)),
        warnings=(
            "External publication and notification effects require explicit "
            "reconciliation after restore.",
        ),
        plan_digest=plan_digest,
    )


def sign_backup_manifest(
    manifest: BackupManifestV1, *, private_key: Ed25519PrivateKey
) -> BackupManifestV1:
    payload = manifest.model_dump(mode="json", exclude={"signature"})
    return manifest.model_copy(
        update={
            "signature": sign_domain_separated_ed25519(
                payload, private_key=private_key, domain=DOMAIN_BACKUP_MANIFEST_V1
            )
        }
    )


def verify_backup_manifest(
    manifest: BackupManifestV1, *, keyring: KeyRing, now: datetime | None = None
) -> None:
    verify_model_ed25519(
        manifest,
        keyring=keyring,
        domain=DOMAIN_BACKUP_MANIFEST_V1,
        signed_at=now or datetime.now(UTC),
        expected_trust_domain="red2pr-backup",
    )


def build_bundle(
    manifest: BackupManifestV1, *, payload: bytes, objects: Mapping[str, bytes]
) -> bytes:
    """Create deterministic gzip tar; archive members are fixed names, never caller paths."""
    if hashlib.sha256(payload).hexdigest() != manifest.payload_sha256:
        raise ValueError("Database payload digest does not match backup manifest.")
    expected = {obj.blob_id for obj in manifest.objects}
    if set(objects) != expected:
        raise ValueError("Encrypted object inventory differs from signed manifest.")
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as archive:
        entries = {
            "manifest.json": canonical_json_bytes(manifest.model_dump(mode="json")),
            "database.dump": payload,
        }
        entries.update({f"objects/{blob_id}.enc": raw for blob_id, raw in objects.items()})
        for name, data in sorted(entries.items()):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o600
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return out.getvalue()


def read_bundle(
    raw: bytes, *, keyring: KeyRing, now: datetime | None = None
) -> tuple[BackupManifestV1, bytes, dict[str, bytes]]:
    """Validate all members/digests/signature before returning any restore bytes."""
    if not raw or len(raw) > _MAX_BUNDLE_BYTES:
        raise ValueError("Backup bundle is empty or exceeds the configured size limit.")
    files: dict[str, bytes] = {}
    expanded_size = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r|gz") as archive:
        for member_count, member in enumerate(archive, start=1):
            if member_count > _MAX_MEMBER_COUNT:
                raise ValueError("Backup bundle contains too many entries.")
            path = PurePosixPath(member.name)
            if (
                "\\" in member.name
                or path.is_absolute()
                or ".." in path.parts
                or member.issym()
                or member.islnk()
                or not member.isfile()
            ):
                raise ValueError("Backup bundle contains an unsafe member path or type.")
            if member.name in files:
                raise ValueError("Backup bundle contains a duplicate member name.")
            if member.size < 0 or member.size > _MAX_BUNDLE_BYTES:
                raise ValueError("Backup bundle member exceeds configured size limits.")
            expanded_size += member.size
            if expanded_size > _MAX_BUNDLE_BYTES:
                raise ValueError("Expanded backup bundle exceeds configured size limits.")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("Backup bundle member could not be read.")
            files[member.name] = stream.read(member.size + 1)
            if len(files[member.name]) != member.size:
                raise ValueError("Backup bundle member size is inconsistent.")
    if not {"manifest.json", "database.dump"}.issubset(files):
        raise ValueError("Backup bundle is missing required manifest or database payload.")
    try:
        manifest = BackupManifestV1.model_validate_json(files["manifest.json"])
        verify_backup_manifest(manifest, keyring=keyring, now=now)
    except (ValueError, CryptoVerificationError) as exc:
        raise ValueError("Backup manifest signature or schema is invalid.") from exc
    payload = files["database.dump"]
    if hashlib.sha256(payload).hexdigest() != manifest.payload_sha256:
        raise ValueError("Database dump digest does not match signed manifest.")
    expected = {f"objects/{obj.blob_id}.enc" for obj in manifest.objects}
    actual = set(files) - {"manifest.json", "database.dump"}
    if expected != actual:
        raise ValueError("Encrypted artifact object inventory does not match signed manifest.")
    return (
        manifest,
        payload,
        {obj.blob_id: files[f"objects/{obj.blob_id}.enc"] for obj in manifest.objects},
    )


def _extract_bundle_file(
    archive_path: Path,
    destination: Path,
    *,
    keyring: KeyRing,
    now: datetime | None = None,
) -> tuple[BackupManifestV1, Path, dict[str, Path]]:
    """Stream and validate an untrusted archive to a private temp directory with hard caps."""
    if not archive_path.is_file() or archive_path.is_symlink():
        raise ValueError("Backup bundle path is unavailable or unsafe.")
    if archive_path.stat().st_size <= 0 or archive_path.stat().st_size > _MAX_BUNDLE_BYTES:
        raise ValueError("Backup bundle is empty or exceeds the configured limit.")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    extracted: dict[str, Path] = {}
    seen_members: set[str] = set()
    manifest_raw: bytes | None = None
    expanded_size = 0
    database_digest = hashlib.sha256()
    try:
        with (
            archive_path.open("rb") as source,
            tarfile.open(fileobj=source, mode="r|gz") as archive,
        ):
            for member_count, member in enumerate(archive, start=1):
                if member_count > _MAX_MEMBER_COUNT:
                    raise ValueError("Backup bundle contains too many entries.")
                path = PurePosixPath(member.name)
                if (
                    "\\" in member.name
                    or path.is_absolute()
                    or ".." in path.parts
                    or member.issym()
                    or member.islnk()
                    or not member.isfile()
                    or member.name in seen_members
                    or member.size < 0
                    or member.size > _MAX_BUNDLE_BYTES
                ):
                    raise ValueError("Backup bundle contains an unsafe member.")
                seen_members.add(member.name)
                if (
                    member.name != "manifest.json"
                    and member.name != "database.dump"
                    and (
                        len(path.parts) != 2
                        or path.parts[0] != "objects"
                        or not path.name.endswith(".enc")
                    )
                ):
                    raise ValueError("Backup bundle contains an unexpected member path.")
                expanded_size += member.size
                if expanded_size > _MAX_BUNDLE_BYTES:
                    raise ValueError("Expanded backup bundle exceeds the configured limit.")
                if member.name == "manifest.json" and member.size > _MAX_MANIFEST_BYTES:
                    raise ValueError("Backup manifest exceeds the configured limit.")
                member_stream = archive.extractfile(member)
                if member_stream is None:
                    raise ValueError("Backup bundle member could not be read.")
                if member.name == "manifest.json":
                    manifest_raw = member_stream.read(_MAX_MANIFEST_BYTES + 1)
                    if len(manifest_raw) != member.size:
                        raise ValueError("Backup manifest size is inconsistent.")
                    continue
                target = destination / (
                    "database.dump" if member.name == "database.dump" else path.name
                )
                hasher = database_digest if member.name == "database.dump" else None
                written = 0
                with target.open("xb") as output:
                    while chunk := member_stream.read(1024 * 1024):
                        written += len(chunk)
                        if written > member.size:
                            raise ValueError("Backup bundle member exceeds its declared size.")
                        output.write(chunk)
                        if hasher is not None:
                            hasher.update(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                if written != member.size:
                    raise ValueError("Backup bundle member size is inconsistent.")
                extracted[member.name] = target
        if manifest_raw is None or "database.dump" not in extracted:
            raise ValueError("Backup bundle is missing required members.")
        manifest = BackupManifestV1.model_validate_json(manifest_raw)
        verify_backup_manifest(manifest, keyring=keyring, now=now)
        if not hmac.compare_digest(database_digest.hexdigest(), manifest.payload_sha256):
            raise ValueError("Database dump digest does not match backup manifest.")
        expected = {f"objects/{item.blob_id}.enc" for item in manifest.objects}
        if expected != set(extracted) - {"database.dump"}:
            raise ValueError("Encrypted artifact inventory does not match the signed manifest.")
        objects: dict[str, Path] = {}
        for item in manifest.objects:
            object_file_path = extracted[f"objects/{item.blob_id}.enc"]
            if (
                object_file_path.stat().st_size > _MAX_OBJECT_BYTES
                or item.size_bytes > _MAX_OBJECT_BYTES
            ):
                raise ValueError("Backup artifact exceeds the configured object limit.")
            objects[item.blob_id] = object_file_path
        return manifest, extracted["database.dump"], objects
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write_bundle(path: Path, data: bytes, *, owned_root: Path) -> Path:
    """Persist a bundle using exclusive temporary creation and atomic replacement in owned root."""
    root = owned_root.resolve(strict=True)
    if path.is_symlink():
        raise ValueError("Backup destination cannot be a symlink.")
    target = path.resolve(strict=False)
    if not target.is_relative_to(root) or target == root:
        raise ValueError(
            "Backup destination must be a non-symlink child of the configured backup root."
        )
    root.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".red2pr-backup-", dir=root)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, target)
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise
    return target


def write_bundle_file(
    path: Path,
    *,
    manifest: BackupManifestV1,
    payload_path: Path,
    object_paths: Mapping[str, Path],
    owned_root: Path,
) -> tuple[Path, str, int]:
    """Write a signed bundle without buffering the database dump or full archive in RAM."""
    root = owned_root.resolve(strict=True)
    target = path.resolve(strict=False)
    if path.is_symlink() or target == root or not target.is_relative_to(root):
        raise ValueError("Backup destination must be a non-symlink child of the owned root.")
    expected = {item.blob_id for item in manifest.objects}
    if set(object_paths) != expected:
        raise ValueError("Encrypted object inventory differs from the signed manifest.")
    if _file_sha256(payload_path) != manifest.payload_sha256:
        raise ValueError("Database payload digest does not match backup manifest.")
    fd, temp_name = tempfile.mkstemp(prefix=".red2pr-backup-", dir=root)
    try:
        with os.fdopen(fd, "wb") as output:
            with tarfile.open(fileobj=output, mode="w:gz") as archive:
                manifest_bytes = canonical_json_bytes(manifest.model_dump(mode="json"))
                manifest_info = tarfile.TarInfo("manifest.json")
                manifest_info.size = len(manifest_bytes)
                manifest_info.mode = 0o600
                manifest_info.mtime = 0
                archive.addfile(manifest_info, io.BytesIO(manifest_bytes))
                payload_info = tarfile.TarInfo("database.dump")
                payload_info.size = payload_path.stat().st_size
                payload_info.mode = 0o600
                payload_info.mtime = 0
                with payload_path.open("rb") as payload:
                    archive.addfile(payload_info, payload)
                for blob_id, object_path in sorted(object_paths.items()):
                    if object_path.is_symlink() or not object_path.is_file():
                        raise ValueError("Encrypted artifact object path is unavailable or unsafe.")
                    info = tarfile.TarInfo(f"objects/{blob_id}.enc")
                    info.size = object_path.stat().st_size
                    info.mode = 0o600
                    info.mtime = 0
                    with object_path.open("rb") as encrypted:
                        archive.addfile(info, encrypted)
            output.flush()
            os.fsync(output.fileno())
        compressed_size = Path(temp_name).stat().st_size
        if compressed_size > _MAX_BUNDLE_BYTES:
            raise ValueError("Compressed backup bundle exceeds the configured limit.")
        digest = _file_sha256(Path(temp_name))
        os.replace(temp_name, path)
        return path, digest, compressed_size
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise
