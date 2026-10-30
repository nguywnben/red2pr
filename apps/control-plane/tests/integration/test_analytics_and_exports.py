"""U24 PostgreSQL, A-17 HTTP, export expiry, and tenant-boundary evidence."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from py_contracts.crypto import KeyRing, export_ed25519_public_key_record
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import (
    ExternalCheckpointStore,
    append_audit_entry,
    create_audit_checkpoint,
)
from red2pr_control.api.app import create_app
from red2pr_control.db.base import MembershipModel, UserModel
from red2pr_control.db.engine import run_alembic_downgrade, run_alembic_upgrade
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session

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
                        "('reporting_projections','report_exports')"
                    )
                )
            ).all()
            assert len(policies) == 2
            assert all(row.relrowsecurity and row.relforcerowsecurity for row in policies)
            assert await db.scalar(text("SELECT count(*) FROM public.reporting_projections")) == 0
            assert await db.scalar(text("SELECT count(*) FROM public.report_exports")) == 0
    finally:
        await harness.app_engine.dispose()


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


def test_openapi_publishes_a17_contracts() -> None:
    from red2pr_control.api.app import render_openapi_v1_json

    spec = json.loads(render_openapi_v1_json())
    assert "/api/v1/workspaces/{ws}/analytics" in spec["paths"]
    assert "/api/v1/workspaces/{ws}/usage" in spec["paths"]
    assert "/api/v1/workspaces/{ws}/exports" in spec["paths"]
    assert "/api/v1/workspaces/{ws}/exports/{export_id}/download" in spec["paths"]
    assert "WorkspaceAnalyticsResponse" in spec["components"]["schemas"]
    assert "WorkspaceUsageResponse" in spec["components"]["schemas"]
    assert "ReportExportReceipt" in spec["components"]["schemas"]
