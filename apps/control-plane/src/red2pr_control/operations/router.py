"""Owner-only instance lifecycle API for U26 (A-18)."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Body, Depends, Request, Response
from sqlalchemy import select, text

from py_contracts.operations import (
    BackupCreateRequest,
    BackupRecord,
    DoctorResponse,
    MaintenanceRequest,
    RestoreDryRunRequest,
    RestoreExecutionResult,
    RestorePlan,
    RestoreStartRequest,
    SupportBundleCreateRequest,
    SupportBundleFileId,
    SupportBundlePreview,
    SupportBundleRecord,
    SystemCheck,
    SystemStatus,
    UpgradePreflightRequest,
    UpgradePreflightResponse,
)
from py_contracts.primitives import Problem
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    PROBLEM_JSON_MEDIA_TYPE,
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    NotFoundError,
)
from red2pr_control.core.logging import current_correlation_id
from red2pr_control.db.base import (
    InstanceModel,
    SupportBundleModel,
    WorkerModel,
)
from red2pr_control.db.rls import instance_rls_session
from red2pr_control.iam.router import get_iam_service
from red2pr_control.iam.sessions import (
    AuthenticatedContext,
    IamService,
    extract_client_ip,
    is_step_up_fresh,
)
from red2pr_control.operations.backup_restore import (
    build_restore_dry_run,
    create_consistent_backup,
    execute_restore,
)
from red2pr_control.operations.doctor import build_doctor_response
from red2pr_control.operations.runtime import shared_operation_lease
from red2pr_control.operations.support_bundle import (
    create_support_bundle,
    read_recent_redacted_logs,
    render_support_bundle_preview,
)
from red2pr_control.operations.upgrade_preflight import run_upgrade_preflight

_PROBLEM_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    403: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    409: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    422: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    503: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
}


async def _owner(
    request: Request,
    iam: IamService,
    *,
    mutation: bool,
    step_up: bool = False,
) -> AuthenticatedContext:
    auth = await iam.authenticate_request(
        request, require_csrf=mutation, correlation_id=current_correlation_id()
    )
    if auth.api_token is not None or not auth.user.is_instance_owner:
        raise ForbiddenError(
            code="instance_owner_required",
            detail="This operation requires an authenticated instance owner session.",
        )
    if step_up and not is_step_up_fresh(auth.session, now=iam.now()):
        raise ForbiddenError(
            code="step_up_required", detail="Fresh 5-minute owner step-up is required."
        )
    return auth


def _response_headers(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def build_operations_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/system", tags=["system"])

    @router.post(
        "/backups",
        operation_id="createSystemBackup",
        response_model=BackupRecord,
        status_code=201,
        responses=_PROBLEM_RESPONSES,
    )
    async def create_backup(
        payload: BackupCreateRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> BackupRecord:
        _response_headers(response)
        auth = await _owner(request, iam, mutation=True, step_up=True)
        store = getattr(request.app.state, "artifact_store", None)
        if store is None:
            raise DependencyUnavailableError(
                code="artifact_store_unavailable",
                detail="Encrypted artifact storage is not configured.",
            )
        try:
            row, _path = await create_consistent_backup(
                session_factory=iam.session_factory,
                artifact_store=store,
                created_by_user_id=auth.user.id,
                correlation_id=current_correlation_id(),
                label=payload.label,
                now=iam.now(),
            )
        except RuntimeError as exc:
            code = str(exc)
            raise DependencyUnavailableError(
                code=code if code.isidentifier() else "backup_prerequisite_unavailable",
                detail=(
                    "Backup prerequisites are unavailable; no backup was reported as successful."
                ),
            ) from exc
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=auth.user.id,
                action="instance.backup.created",
                target=f"backup:{row.id}",
                decision="allow",
                reason_code="signed_consistent_snapshot",
                correlation_id=row.correlation_id,
                client_ip=extract_client_ip(request),
                occurred_at=iam.now(),
                metadata={
                    "manifest_digest": row.manifest_digest,
                    "object_count": row.object_count,
                    "size_bytes": row.size_bytes,
                },
            )
        return BackupRecord(
            id=row.id,
            state="succeeded",
            created_at=row.created_at,
            completed_at=row.completed_at,
            manifest_digest=row.manifest_digest,
            size_bytes=row.size_bytes,
            object_count=row.object_count,
            error_code=None,
        )

    @router.get(
        "/status",
        operation_id="getSystemStatus",
        response_model=SystemStatus,
        responses=_PROBLEM_RESPONSES,
    )
    async def get_status(
        request: Request, response: Response, iam: Annotated[IamService, Depends(get_iam_service)]
    ) -> SystemStatus:
        _response_headers(response)
        await _owner(request, iam, mutation=False)
        async with instance_rls_session(iam.session_factory, mode="instance_only") as db:
            instance = await db.scalar(select(InstanceModel))
            if instance is None:
                raise DependencyUnavailableError(
                    code="instance_uninitialized", detail="Instance state has not been initialized."
                )
            schema_revision = str(
                (
                    await db.execute(text("SELECT version_num FROM public.alembic_version LIMIT 1"))
                ).scalar_one_or_none()
                or "uninitialized"
            )
            db_version = str((await db.execute(text("SHOW server_version"))).scalar_one())
            active_workers = int(
                await db.scalar(
                    select(__import__("sqlalchemy").func.count())
                    .select_from(WorkerModel)
                    .where(WorkerModel.status == "online")
                )
                or 0
            )
            checks = (
                SystemCheck(
                    check_id="database",
                    state="ok",
                    summary=f"PostgreSQL {db_version} is reachable.",
                ),
                SystemCheck(
                    check_id="workers",
                    state="ok" if active_workers else "warning",
                    summary=f"{active_workers} worker(s) are online.",
                ),
            )
            state: Literal["maintenance", "ready", "degraded"] = (
                "maintenance"
                if instance.maintenance_enabled
                else "ready"
                if active_workers
                else "degraded"
            )
            return SystemStatus(
                state=state,
                generated_at=iam.now(),
                application_version="0.1.0",
                schema_revision=schema_revision,
                database_version=db_version,
                recovery_epoch=instance.recovery_epoch,
                maintenance_enabled=instance.maintenance_enabled,
                maintenance_reason=instance.maintenance_reason,
                worker_protocols=(),
                checks=checks,
            )

    @router.get(
        "/doctor",
        operation_id="getSystemDoctor",
        response_model=DoctorResponse,
        responses=_PROBLEM_RESPONSES,
    )
    async def get_doctor(
        request: Request, response: Response, iam: Annotated[IamService, Depends(get_iam_service)]
    ) -> DoctorResponse:
        _response_headers(response)
        await _owner(request, iam, mutation=False)
        return await build_doctor_response(iam.session_factory)

    @router.post(
        "/maintenance",
        operation_id="setSystemMaintenance",
        response_model=SystemStatus,
        responses=_PROBLEM_RESPONSES,
    )
    async def set_maintenance(
        payload: MaintenanceRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> SystemStatus:
        _response_headers(response)
        auth = await _owner(request, iam, mutation=True, step_up=True)
        now = iam.now()
        corr = current_correlation_id()
        async with (
            shared_operation_lease(iam.session_factory),
            instance_rls_session(iam.session_factory, mode="instance_admin") as db,
        ):
            instance = await db.scalar(select(InstanceModel).with_for_update())
            if instance is None:
                raise DependencyUnavailableError(
                    code="instance_uninitialized",
                    detail="Instance state has not been initialized.",
                )
            if (
                not payload.enabled
                and instance.maintenance_enabled
                and instance.maintenance_reason is not None
                and instance.maintenance_reason.startswith("Restore completed;")
                and not payload.reconciliation_confirmed
            ):
                raise ConflictError(
                    code="restore_reconciliation_required",
                    detail=(
                        "Confirm external publication, notification, and task reconciliation "
                        "before leaving restore maintenance."
                    ),
                )
            instance.maintenance_enabled = payload.enabled
            instance.maintenance_reason = payload.reason if payload.enabled else None
            instance.maintenance_started_at = now if payload.enabled else None
            instance.maintenance_started_by_user_id = auth.user.id if payload.enabled else None
            instance.version += 1
            instance.updated_at = now
            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=auth.user.id,
                action="instance.maintenance.changed",
                target=f"instance:{instance.id}",
                decision="allow",
                reason_code=(
                    "restore_reconciliation_confirmed"
                    if payload.reconciliation_confirmed
                    else "owner_step_up_verified"
                ),
                correlation_id=corr,
                client_ip=extract_client_ip(request),
                occurred_at=now,
                metadata={
                    "enabled": payload.enabled,
                    "reason": payload.reason if payload.enabled else "disabled",
                    "reconciliation_confirmed": payload.reconciliation_confirmed,
                },
            )
        return await get_status(request, response, iam)

    @router.post(
        "/upgrade-preflight",
        operation_id="runSystemUpgradePreflight",
        response_model=UpgradePreflightResponse,
        responses=_PROBLEM_RESPONSES,
    )
    async def upgrade_preflight(
        payload: UpgradePreflightRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> UpgradePreflightResponse:
        _response_headers(response)
        auth = await _owner(request, iam, mutation=True, step_up=True)
        result = await run_upgrade_preflight(
            iam.session_factory,
            payload,
            current_version="0.1.0",
        )
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=auth.user.id,
                action="instance.upgrade.preflight",
                target=f"schema:{payload.target_schema_revision}",
                decision="allow" if result.compatible else "deny",
                reason_code="compatibility_preflight",
                correlation_id=current_correlation_id(),
                metadata={
                    "target_version": payload.target_version,
                    "compatible": result.compatible,
                    "pending_effects": result.pending_effects,
                },
            )
        return result

    @router.post(
        "/restore/dry-run",
        operation_id="dryRunSystemRestore",
        response_model=RestorePlan,
        responses=_PROBLEM_RESPONSES,
    )
    async def restore_dry_run(
        payload: RestoreDryRunRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> RestorePlan:
        _response_headers(response)
        await _owner(request, iam, mutation=True)
        store = getattr(request.app.state, "artifact_store", None)
        if store is None:
            raise DependencyUnavailableError(
                code="artifact_store_unavailable",
                detail="Encrypted artifact storage is not configured.",
            )
        try:
            secret_broker = getattr(request.app.state, "notification_secret_broker", None)
            key_version_available = getattr(secret_broker, "has_master_key_version", None)
            return await build_restore_dry_run(
                session_factory=iam.session_factory,
                artifact_store=store,
                backup_id=payload.backup_id,
                requested_target_revision=payload.target_schema_revision,
                key_version_available=key_version_available,
            )
        except (RuntimeError, ValueError) as exc:
            code = str(exc)
            if isinstance(exc, ValueError) or any(
                token in code for token in ("digest", "bundle_missing", "trust_store_invalid")
            ):
                from red2pr_control.core.errors import ConflictError

                raise ConflictError(
                    code=code if code.isidentifier() else "backup_integrity_failed",
                    detail="Backup integrity or trust verification failed.",
                ) from exc
            raise DependencyUnavailableError(
                code=code if code.isidentifier() else "restore_preflight_unavailable",
                detail="Restore preflight prerequisites are unavailable.",
            ) from exc

    @router.post(
        "/restore",
        operation_id="restoreSystemBackup",
        response_model=RestoreExecutionResult,
        responses=_PROBLEM_RESPONSES,
    )
    async def restore_backup(
        payload: RestoreStartRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> RestoreExecutionResult:
        _response_headers(response)
        await _owner(request, iam, mutation=True, step_up=True)
        store = getattr(request.app.state, "artifact_store", None)
        if store is None:
            raise DependencyUnavailableError(
                code="artifact_store_unavailable",
                detail="Encrypted artifact storage is not configured.",
            )
        try:
            secret_broker = getattr(request.app.state, "notification_secret_broker", None)
            key_version_available = getattr(secret_broker, "has_master_key_version", None)
            restore_id, recovery_epoch = await execute_restore(
                session_factory=iam.session_factory,
                artifact_store=store,
                backup_id=payload.backup_id,
                manifest_digest=payload.manifest_digest,
                plan_digest=payload.plan_digest,
                key_version_available=key_version_available,
                now=iam.now(),
            )
        except (RuntimeError, ValueError) as exc:
            code = str(exc)
            if any(
                token in code
                for token in (
                    "digest",
                    "signature",
                    "integrity",
                    "incompatible",
                    "maintenance",
                )
            ) or isinstance(exc, ValueError):
                from red2pr_control.core.errors import ConflictError

                raise ConflictError(
                    code=code if code.isidentifier() else "restore_precondition_failed",
                    detail=(
                        "Restore preconditions failed; the active database was not "
                        "reported as restored."
                    ),
                ) from exc
            raise DependencyUnavailableError(
                code=code if code.isidentifier() else "restore_unavailable",
                detail="Restore prerequisites or database recovery are unavailable.",
            ) from exc
        engine = iam.session_factory.kw.get("bind")
        if engine is not None and hasattr(engine, "dispose"):
            await engine.dispose()
        return RestoreExecutionResult(
            restore_id=restore_id,
            backup_id=payload.backup_id,
            state="succeeded",
            recovery_epoch=recovery_epoch,
            maintenance_enabled=True,
            requires_external_reconciliation=True,
            message=(
                "Restore completed. Maintenance remains enabled until external effects are "
                "reconciled."
            ),
        )

    @router.post(
        "/support-bundles/preview",
        operation_id="previewSystemSupportBundle",
        response_model=SupportBundlePreview,
        responses=_PROBLEM_RESPONSES,
    )
    async def preview_support_bundle(
        file_ids: Annotated[tuple[SupportBundleFileId, ...], Body()],
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> SupportBundlePreview:
        _response_headers(response)
        await _owner(request, iam, mutation=False)
        return render_support_bundle_preview(file_ids, now=iam.now())

    @router.post(
        "/support-bundles",
        operation_id="createSystemSupportBundle",
        response_model=SupportBundleRecord,
        responses=_PROBLEM_RESPONSES,
    )
    async def create_support_bundle_endpoint(
        payload: SupportBundleCreateRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> SupportBundleRecord:
        _response_headers(response)
        auth = await _owner(request, iam, mutation=True, step_up=True)
        if not payload.confirm_export:
            raise ForbiddenError(
                code="support_export_confirmation_required",
                detail="Explicit support bundle export confirmation is required.",
            )
        store = getattr(request.app.state, "artifact_store", None)
        if store is None:
            raise DependencyUnavailableError(
                code="artifact_store_unavailable",
                detail="Encrypted artifact storage is not configured.",
            )
        expected_preview = render_support_bundle_preview(payload.file_ids, now=iam.now())
        if expected_preview.manifest_digest != payload.manifest_digest:
            raise ForbiddenError(
                code="support_preview_stale",
                detail="The support bundle preview changed; review it again before export.",
            )
        status = await get_status(request, response, iam)
        doctor = await build_doctor_response(iam.session_factory)
        sources: dict[str, object] = {
            "health_summary": status.model_dump(mode="json"),
            "doctor_report": doctor.model_dump(mode="json"),
            "migration_status": {"schema_revision": status.schema_revision},
            "worker_status": {
                "online": next(
                    (
                        int(check.summary.split()[0])
                        for check in status.checks
                        if check.check_id == "workers"
                    ),
                    0,
                )
            },
            "telemetry_snapshot": {
                "state": status.state,
                "generated_at": status.generated_at.isoformat(),
            },
        }
        if "recent_redacted_logs" in payload.file_ids:
            try:
                sources["recent_redacted_logs"] = read_recent_redacted_logs()
            except RuntimeError as exc:
                raise DependencyUnavailableError(
                    code="support_logs_not_configured",
                    detail="Recent logs are unavailable from the configured owned log file.",
                ) from exc
        raw, archive_digest = create_support_bundle(payload.file_ids, sources)
        workspace_id = "instance-system"
        staged = await store.stage_upload(
            workspace_id=workspace_id, plaintext=raw, expected_digest=archive_digest, now=iam.now()
        )
        await store.verify_staged(staged)
        await store.finalize_staged(staged)
        now = iam.now()
        expires = now + timedelta(hours=1)
        corr = current_correlation_id()
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            row = SupportBundleModel(
                id=staged.stage_id,
                actor_user_id=auth.user.id,
                correlation_id=corr,
                manifest_digest=payload.manifest_digest,
                file_ids_json=list(payload.file_ids),
                bundle_key=archive_digest,
                file_count=len(payload.file_ids),
                size_bytes=len(raw),
                created_at=now,
                expires_at=expires,
            )
            db.add(row)
            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=auth.user.id,
                action="instance.support_bundle.created",
                target=f"support_bundle:{row.id}",
                decision="allow",
                reason_code="owner_step_up_and_preview_verified",
                correlation_id=corr,
                client_ip=extract_client_ip(request),
                occurred_at=now,
                metadata={
                    "manifest_digest": payload.manifest_digest,
                    "file_count": len(payload.file_ids),
                    "size_bytes": len(raw),
                },
            )
        return SupportBundleRecord(
            id=staged.stage_id,
            manifest_digest=payload.manifest_digest,
            created_at=now,
            expires_at=expires,
            file_count=len(payload.file_ids),
            size_bytes=len(raw),
            download_url=f"/api/v1/system/support-bundles/{staged.stage_id}",
        )

    @router.get(
        "/support-bundles/{bundle_id}",
        operation_id="downloadSystemSupportBundle",
        responses=_PROBLEM_RESPONSES,
    )
    async def download_support_bundle(
        bundle_id: str,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> Response:
        _response_headers(response)
        await _owner(request, iam, mutation=False)
        async with instance_rls_session(iam.session_factory, mode="instance_only") as db:
            row = await db.get(SupportBundleModel, bundle_id)
            if row is None or row.expires_at <= iam.now():
                raise NotFoundError(
                    code="support_bundle_expired_or_missing",
                    detail="Support bundle is unavailable or expired.",
                )
            ref = _storage_ref(request.app.state.artifact_store, row.bundle_key)
            raw = await request.app.state.artifact_store.read_verified(
                workspace_id="instance-system", storage_ref=ref, expected_digest=row.bundle_key
            )
        response.headers["Content-Type"] = "application/gzip"
        response.headers["Content-Disposition"] = (
            f'attachment; filename="red2pr-support-{bundle_id}.tar.gz"'
        )
        return Response(
            content=raw,
            media_type="application/gzip",
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": response.headers["Content-Disposition"],
            },
        )

    return router


def _storage_ref(store: object, digest: str) -> str:
    from red2pr_control.triage_evidence.artifact_store import (
        LocalEncryptedArtifactStore,
        S3CompatibleArtifactStore,
    )

    if isinstance(store, LocalEncryptedArtifactStore):
        return f"local://v1/instance-system/blobs/{digest[:2]}/{digest}.enc"
    if isinstance(store, S3CompatibleArtifactStore):
        return f"s3://v1/{store.bucket}/instance-system/blobs/{digest[:2]}/{digest}.enc"
    raise DependencyUnavailableError(
        code="artifact_store_unsupported",
        detail="Configured artifact store does not support system bundle retrieval.",
    )
