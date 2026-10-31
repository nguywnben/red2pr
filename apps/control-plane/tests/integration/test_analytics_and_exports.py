"""U24 PostgreSQL, A-17 HTTP, export expiry, and tenant-boundary evidence."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select, text

from py_contracts.crypto import KeyRing, MasterKeyRing, export_ed25519_public_key_record
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import (
    ExternalCheckpointStore,
    append_audit_entry,
    create_audit_checkpoint,
)
from red2pr_control.api.app import create_app
from red2pr_control.core.errors import DependencyUnavailableError
from red2pr_control.db.base import (
    AuditLogModel,
    MembershipModel,
    OperationalAlarmModel,
    OutboxEventModel,
    UserModel,
)
from red2pr_control.db.engine import run_alembic_downgrade, run_alembic_upgrade
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.operations.alarms import OperationalAlarmWorker
from red2pr_control.orchestrator.queue import DurableTaskQueueService
from red2pr_control.secrets.broker import INFERENCE_SECRET_CAPABILITY, SecretBroker

_SUPPORT_PATH = Path(__file__).with_name("test_agents_and_state_machine.py")
_SPEC = importlib.util.spec_from_file_location("red2pr_u24_test_support", _SUPPORT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_SUPPORT = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SUPPORT
_SPEC.loader.exec_module(_SUPPORT)


@pytest.fixture(scope="module")
def pg_urls() -> Iterator[object]:
    yield from _SUPPORT.pg_urls.__wrapped__()


@pytest.fixture
async def migrated_db(pg_urls: object) -> AsyncIterator[object]:
    async for result in _SUPPORT.migrated_db.__wrapped__(pg_urls):
        yield result


@pytest.mark.asyncio
async def test_0020_upgrade_downgrade_upgrade_and_tenant_rls(
    migrated_db: object, tmp_path: Path
) -> None:
    run_alembic_downgrade(migrated_db.admin_url, "0019_api_tokens_and_webhook_keys")
    run_alembic_upgrade(
        migrated_db.admin_url,
        "head",
        app_role_name=_SUPPORT.APP_ROLE_NAME,
        app_role_password=_SUPPORT.APP_ROLE_PASSWORD,
    )
    clock = _SUPPORT.ManualClock()
    harness = _SUPPORT._build_u17_harness(
        migrated_db.app_url, clock=clock, store_dir=tmp_path / "migration-artifacts"
    )
    try:
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            policies = (
                await db.execute(
                    text(
                        "SELECT relname, relrowsecurity, relforcerowsecurity "
                        "FROM pg_class WHERE relname IN "
                        "('reporting_projections','report_exports',"
                        "'artifact_deletion_jobs','release_exceptions')"
                    )
                )
            ).all()
            assert len(policies) == 4
            assert all(row.relrowsecurity and row.relforcerowsecurity for row in policies)
            assert await db.scalar(text("SELECT count(*) FROM public.reporting_projections")) == 0
            assert await db.scalar(text("SELECT count(*) FROM public.report_exports")) == 0
    finally:
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_0021_retention_and_release_exception_migration_is_reversible(
    migrated_db: object,
) -> None:
    run_alembic_downgrade(migrated_db.admin_url, "0020_reporting_projections_and_exports")
    run_alembic_upgrade(
        migrated_db.admin_url,
        "head",
        app_role_name=_SUPPORT.APP_ROLE_NAME,
        app_role_password=_SUPPORT.APP_ROLE_PASSWORD,
    )


@pytest.mark.asyncio
async def test_a17_analytics_safe_export_idempotency_and_expiry(
    migrated_db: object, tmp_path: Path
) -> None:
    clock = _SUPPORT.ManualClock()
    harness = _SUPPORT._build_u17_harness(
        migrated_db.app_url, clock=clock, store_dir=tmp_path / "u24-encrypted-exports"
    )
    client, csrf, _owner, workspace_id, _repo_id = await _SUPPORT._bootstrap_workspace_and_repo(
        harness, clock=clock, ws_slug="u24-analytics"
    )
    start = (clock() - __import__("datetime").timedelta(days=1)).isoformat()
    end = clock().isoformat()
    try:
        analytics = await client.get(
            "/api/v1/workspaces/u24-analytics/analytics",
            params={"range_start": start, "range_end": end},
        )
        assert analytics.status_code == 200, analytics.text
        data = analytics.json()
        unverified_audit = await client.get("/api/v1/workspaces/u24-analytics/audit")
        assert unverified_audit.status_code == 503
        assert unverified_audit.json()["code"] == "audit_verification_unavailable"
        assert len(data["funnel"]) == 8
        assert data["repository_count"] == 1
        assert data["funnel"][0]["key"] == "ingested"
        assert data["funnel"][-1]["key"] == "remotely_verified"
        assert data["funnel"][-1]["value"] == 0
        assert data["costs"] == []
        usage = await client.get(
            "/api/v1/workspaces/u24-analytics/usage",
            params={"range_start": start, "range_end": end},
        )
        assert usage.status_code == 200, usage.text
        assert usage.json()["workspace_id"] == workspace_id
        assert usage.json()["costs"] == []
        assert usage.json()["watermark"]

        reversed_range = await client.get(
            "/api/v1/workspaces/u24-analytics/analytics",
            params={"range_start": end, "range_end": start},
        )
        assert reversed_range.status_code == 422
        forbidden_repo = await client.get(
            "/api/v1/workspaces/u24-analytics/analytics",
            params={
                "range_start": start,
                "range_end": end,
                "repository_id": new_uuid7(now=clock()),
            },
        )
        # Workspace admins may inspect the workspace scope; this arbitrary ID reveals zero rows.
        assert forbidden_repo.status_code == 200
        assert forbidden_repo.json()["funnel"][0]["value"] == 0

        body = {
            "kind": "proof_summary",
            "format": "csv",
            "range_start": start,
            "range_end": end,
            "filters": {},
        }
        unverified_audit_export = await client.post(
            "/api/v1/workspaces/u24-analytics/exports",
            headers=_SUPPORT._csrf_headers(csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={**body, "kind": "audit"},
        )
        assert unverified_audit_export.status_code == 503
        assert unverified_audit_export.json()["code"] == "audit_verification_unavailable"

        signer = Ed25519PrivateKey.generate()
        checkpoint_time = clock()
        public_key = export_ed25519_public_key_record(
            private_key=signer,
            key_id="u24-audit-verifier",
            not_before=checkpoint_time - __import__("datetime").timedelta(days=1),
        )
        checkpoint_store = ExternalCheckpointStore(tmp_path / "u24-audit-checkpoints")
        keyring = KeyRing([public_key])
        with pytest.raises(ValueError, match="configured together"):
            create_app(audit_checkpoint_store=checkpoint_store)
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=_owner,
                action="u24.audit_export.test_record",
                target="workspace:u24-analytics",
                decision="allow",
                reason_code="test_fixture",
                correlation_id=new_uuid7(now=clock()),
                workspace_id=workspace_id,
                occurred_at=checkpoint_time,
            )
        async with instance_rls_session(harness.app_factory, mode="audit_verifier") as db:
            checkpoint = await create_audit_checkpoint(
                db,
                external_store=checkpoint_store,
                private_key=signer,
                signer_key_id="u24-audit-verifier",
                now=checkpoint_time,
            )
        configured_app = create_app(
            iam_service=harness.iam,
            artifact_store=harness.artifact_store,
            audit_checkpoint_store=checkpoint_store,
            audit_checkpoint_keyring=keyring,
        )
        assert configured_app.state.audit_checkpoint_store is checkpoint_store
        assert configured_app.state.audit_checkpoint_keyring is keyring
        harness.api_app.state.audit_checkpoint_store = configured_app.state.audit_checkpoint_store
        harness.api_app.state.audit_checkpoint_keyring = (
            configured_app.state.audit_checkpoint_keyring
        )
        verified_audit_page = await client.get(
            "/api/v1/workspaces/u24-analytics/audit?action=u24.audit_export.test_record"
        )
        assert verified_audit_page.status_code == 200, verified_audit_page.text
        audit_items = verified_audit_page.json()["items"]
        assert len(audit_items) == 1
        assert audit_items[0]["action"] == "u24.audit_export.test_record"
        assert audit_items[0]["correlation_id"]
        verified_audit_export = await client.post(
            "/api/v1/workspaces/u24-analytics/exports",
            headers=_SUPPORT._csrf_headers(csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={**body, "kind": "audit"},
        )
        assert verified_audit_export.status_code == 201, verified_audit_export.text
        audit_receipt = verified_audit_export.json()
        audit_download = await client.get(audit_receipt["download_path"])
        assert audit_download.status_code == 200
        assert b"u24.audit_export.test_record" in audit_download.content
        assert checkpoint.entry_count > 0

        idem = new_uuid7(now=clock())
        created = await client.post(
            "/api/v1/workspaces/u24-analytics/exports",
            headers=_SUPPORT._csrf_headers(csrf, extra={"Idempotency-Key": idem}),
            json=body,
        )
        assert created.status_code == 201, created.text
        receipt = created.json()
        assert receipt["kind"] == "proof_summary"
        assert receipt["expires_at"] > clock().isoformat()
        replay = await client.post(
            "/api/v1/workspaces/u24-analytics/exports",
            headers=_SUPPORT._csrf_headers(csrf, extra={"Idempotency-Key": idem}),
            json=body,
        )
        assert replay.status_code == 201
        assert replay.json()["export_id"] == receipt["export_id"]
        assert replay.json()["reused"] is True
        mismatch = await client.post(
            "/api/v1/workspaces/u24-analytics/exports",
            headers=_SUPPORT._csrf_headers(csrf, extra={"Idempotency-Key": idem}),
            json={**body, "format": "json"},
        )
        assert mismatch.status_code == 409

        downloaded = await client.get(receipt["download_path"])
        assert downloaded.status_code == 200
        assert downloaded.headers["x-content-type-options"] == "nosniff"
        assert b"restricted_artifact_digests" in downloaded.content

        class FailFinalizeStore:
            def __init__(self, delegate: Any) -> None:
                self.delegate = delegate

            async def stage_upload(self, **kwargs: Any) -> Any:
                return await self.delegate.stage_upload(**kwargs)

            async def verify_staged(self, handle: Any) -> int:
                return await self.delegate.verify_staged(handle)

            async def finalize_staged(self, _handle: Any) -> str:
                raise OSError("simulated finalization outage")

            async def delete_blob(self, **kwargs: Any) -> bool:
                return await self.delegate.delete_blob(**kwargs)

        original_store = harness.api_app.state.artifact_store
        harness.api_app.state.artifact_store = FailFinalizeStore(original_store)
        failed_finalize = await client.post(
            "/api/v1/workspaces/u24-analytics/exports",
            headers=_SUPPORT._csrf_headers(csrf, extra={"Idempotency-Key": new_uuid7(now=clock())}),
            json={**body, "kind": "funnel"},
        )
        harness.api_app.state.artifact_store = original_store
        assert failed_finalize.status_code == 503
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            assert await db.scalar(text("SELECT count(*) FROM public.report_exports")) == 2

        backup_admin_id = new_uuid7(now=clock())
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            db.add(
                UserModel(
                    id=backup_admin_id,
                    username="u24-backup-admin",
                    email="u24-backup-admin@red2pr.local",
                    display_name="U24 Backup Admin",
                    password_hash="unused-test-password-hash",
                    status="active",
                    is_instance_owner=False,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
            await db.flush()
            db.add(
                MembershipModel(
                    id=new_uuid7(now=clock()),
                    workspace_id=workspace_id,
                    user_id=backup_admin_id,
                    role="admin",
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
        exception_body = {
            "finding_ref": "CVE-2026-U25-1",
            "artifact_digest": "a" * 64,
            "security_reviewer_user_id": backup_admin_id,
            "mitigation": "Restrict ingress to the affected worker pool until patched.",
            "expires_at": (clock() + __import__("datetime").timedelta(days=14)).isoformat(),
        }
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            await db.execute(
                text("UPDATE public.sessions SET step_up_at=NULL WHERE user_id=:user_id"),
                {"user_id": _owner},
            )
        missing_step_up = await client.post(
            "/api/v1/workspaces/u24-analytics/release-exceptions",
            headers=_SUPPORT._csrf_headers(csrf),
            json=exception_body,
        )
        assert missing_step_up.status_code == 403
        assert missing_step_up.json()["code"] == "step_up_required"
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            await db.execute(
                text("UPDATE public.sessions SET step_up_at=:now WHERE user_id=:user_id"),
                {"now": clock(), "user_id": _owner},
            )
        created_exception = await client.post(
            "/api/v1/workspaces/u24-analytics/release-exceptions",
            headers=_SUPPORT._csrf_headers(csrf),
            json=exception_body,
        )
        assert created_exception.status_code == 201, created_exception.text
        exception_id = created_exception.json()["id"]
        listed_exceptions = await client.get("/api/v1/workspaces/u24-analytics/release-exceptions")
        assert listed_exceptions.status_code == 200
        assert listed_exceptions.json()["items"][0]["artifact_digest"] == "a" * 64
        revoked_exception = await client.delete(
            f"/api/v1/workspaces/u24-analytics/release-exceptions/{exception_id}",
            headers=_SUPPORT._csrf_headers(csrf),
        )
        assert revoked_exception.status_code == 204
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            await db.execute(
                text(
                    "UPDATE public.memberships SET role='viewer' "
                    "WHERE workspace_id=:ws AND user_id=:owner"
                ),
                {"ws": workspace_id, "owner": _owner},
            )
        downgraded_analytics = await client.get(
            "/api/v1/workspaces/u24-analytics/analytics",
            params={"range_start": start, "range_end": end},
        )
        assert downgraded_analytics.status_code == 200
        assert downgraded_analytics.json()["repository_count"] == 0
        revoked_download = await client.get(receipt["download_path"])
        assert revoked_download.status_code == 404
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            await db.execute(
                text("UPDATE public.report_exports SET expires_at=:expiry WHERE id=:id"),
                {
                    "expiry": clock() + __import__("datetime").timedelta(minutes=1),
                    "id": receipt["export_id"],
                },
            )
        clock.advance(minutes=2)
        expired = await client.get(receipt["download_path"])
        assert expired.status_code == 410

        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            export_rows = await db.scalar(text("SELECT count(*) FROM public.report_exports"))
            assert export_rows == 2
    finally:
        await client.aclose()
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_u25_alarm_transitions_and_storage_admission_pause(
    migrated_db: object, tmp_path: Path
) -> None:
    clock = _SUPPORT.ManualClock()
    harness = _SUPPORT._build_u17_harness(
        migrated_db.app_url, clock=clock, store_dir=tmp_path / "u25-alarms"
    )
    client, _csrf, _owner, workspace_id, _repo_id = await _SUPPORT._bootstrap_workspace_and_repo(
        harness, clock=clock, ws_slug="u25-alarms"
    )
    queue_service = DurableTaskQueueService(
        session_factory=harness.app_factory,
        signing_key=harness.iam.csrf_signing_key,
    )
    alarm_worker = OperationalAlarmWorker(
        session_factory=harness.app_factory,
        artifact_store=harness.artifact_store,
        task_queue_service=queue_service,
        storage_usage_probe=lambda: 95.0,
    )
    try:
        await queue_service.enqueue_job(
            workspace_id=workspace_id,
            kind="repair.alarm-test",
            resource_id=new_uuid7(now=clock()),
            correlation_id="u25-alarm-correlation",
            now=clock() - __import__("datetime").timedelta(minutes=2),
            is_repair_job=True,
        )
        assert await alarm_worker.process_once(now=clock()) == 1
        with pytest.raises(DependencyUnavailableError) as paused:
            await queue_service.enqueue_job(
                workspace_id=workspace_id,
                kind="repair.alarm-test-paused",
                resource_id=new_uuid7(now=clock()),
                correlation_id="u25-paused-correlation",
                now=clock(),
                is_repair_job=True,
            )
        assert paused.value.code == "storage_capacity_exceeded"
        clock.advance(minutes=3)
        assert await alarm_worker.process_once(now=clock()) == 1
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            alarms = list((await db.scalars(select(OperationalAlarmModel))).all())
            alarm_events = list(
                (
                    await db.scalars(
                        select(OutboxEventModel).where(
                            OutboxEventModel.event_type == "operations.alarm"
                        )
                    )
                ).all()
            )
        assert {item.alarm_code: item.state for item in alarms} == {
            "queue_lag": "firing",
            "storage_hard_limit": "firing",
        }
        assert len(alarm_events) == 2
    finally:
        await client.aclose()
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_u25_secret_metadata_and_cluster_key_rotation_api(
    migrated_db: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = _SUPPORT.ManualClock()
    harness = _SUPPORT._build_u17_harness(
        migrated_db.app_url, clock=clock, store_dir=tmp_path / "u25-key-rotation"
    )
    client, csrf, owner_id, workspace_id, _repo_id = await _SUPPORT._bootstrap_workspace_and_repo(
        harness, clock=clock, ws_slug="u25-key-rotation"
    )
    key_file = tmp_path / "master-keys.json"
    key_v1 = os.urandom(32)
    key_v2 = os.urandom(32)
    key_file.write_text(
        json.dumps({"active_version": 1, "keys": {"1": base64.b64encode(key_v1).decode()}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("RED2PR_MASTER_KEY_FILE", str(key_file))
    broker = SecretBroker(key_ring=MasterKeyRing(active_version=1, keys={1: key_v1}))
    harness.api_app.state.notification_secret_broker = broker
    secret_value = b"u25-secret-rotation-canary-987654321"
    async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
        stored = await broker.store_secret(
            db,
            plaintext=secret_value,
            purpose="meta_inference",
            workspace_id=workspace_id,
            now=clock(),
        )

    async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
        await db.execute(
            text("UPDATE public.sessions SET step_up_at=NULL WHERE user_id=:user_id"),
            {"user_id": owner_id},
        )
    try:
        metadata = await client.get("/api/v1/workspaces/u25-key-rotation/security/secrets")
        assert metadata.status_code == 200, metadata.text
        assert metadata.json()["active_kek_version"] == 1
        assert metadata.json()["items"][0]["kek_version"] == 1
        assert stored.secret_ref not in metadata.text
        assert secret_value.decode() not in metadata.text

        headers = _SUPPORT._csrf_headers(csrf)
        missing_step_up = await client.post(
            "/api/v1/workspaces/u25-key-rotation/security/secrets/rotate", headers=headers
        )
        assert missing_step_up.status_code == 403
        assert missing_step_up.json()["code"] == "step_up_required"

        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            await db.execute(
                text("UPDATE public.sessions SET step_up_at=:now WHERE user_id=:user_id"),
                {"now": clock(), "user_id": owner_id},
            )
        key_file.write_text(
            json.dumps(
                {
                    "active_version": 2,
                    "keys": {
                        "1": base64.b64encode(key_v1).decode(),
                        "2": base64.b64encode(key_v2).decode(),
                    },
                }
            ),
            encoding="utf-8",
        )
        rotated = await client.post(
            "/api/v1/workspaces/u25-key-rotation/security/secrets/rotate", headers=headers
        )
        assert rotated.status_code == 200, rotated.text
        assert rotated.json()["active_kek_version"] == 2
        assert rotated.json()["rotated_count"] == 1
        assert secret_value.decode() not in rotated.text
        repeated_rotation = await client.post(
            "/api/v1/workspaces/u25-key-rotation/security/secrets/rotate", headers=headers
        )
        assert repeated_rotation.status_code == 200, repeated_rotation.text
        assert repeated_rotation.json()["active_kek_version"] == 2
        assert repeated_rotation.json()["rotated_count"] == 0
        async with instance_rls_session(harness.app_factory, mode="audit_verifier") as db:
            rotation_audit_count = await db.scalar(
                select(func.count(AuditLogModel.id)).where(
                    AuditLogModel.action == "security.secret_keyring.rotated"
                )
            )
            assert rotation_audit_count == 2

        metadata_after = await client.get("/api/v1/workspaces/u25-key-rotation/security/secrets")
        assert metadata_after.status_code == 200
        assert metadata_after.json()["active_kek_version"] == 2
        assert metadata_after.json()["items"][0]["kek_version"] == 2
        assert metadata_after.json()["items"][0]["rotated_at"]
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            resolved = await broker.resolve_secret_bytes(
                db,
                secret_ref=stored.secret_ref,
                capability=INFERENCE_SECRET_CAPABILITY,
                workspace_id=workspace_id,
            )
        assert resolved == secret_value
    finally:
        await client.aclose()
        await harness.app_engine.dispose()


def test_openapi_publishes_a17_contracts() -> None:
    from red2pr_control.api.app import render_openapi_v1_json

    spec = json.loads(render_openapi_v1_json())
    assert "/api/v1/workspaces/{ws}/analytics" in spec["paths"]
    assert "/api/v1/workspaces/{ws}/usage" in spec["paths"]
    assert "/api/v1/workspaces/{ws}/exports" in spec["paths"]
    assert "/api/v1/workspaces/{ws}/exports/{export_id}/download" in spec["paths"]
    assert "/api/v1/workspaces/{ws}/audit" in spec["paths"]
    assert "WorkspaceAnalyticsResponse" in spec["components"]["schemas"]
    assert "WorkspaceUsageResponse" in spec["components"]["schemas"]
    assert "ReportExportReceipt" in spec["components"]["schemas"]
