"""FastAPI routers for `A-13` workers, `A-14` task-jobs, `A-24` receipts & `S-21` mTLS."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path as FsPath
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Path, Query, Request, Response

from py_contracts.crypto import MasterKeyRing
from py_contracts.primitives import ActionReceipt, Problem
from py_contracts.worker import (
    ResultV1,
    TaskJobActionRequest,
    TaskJobDetail,
    TaskJobPage,
    TaskJobState,
    WorkerActionRequest,
    WorkerArtifactUploadRequest,
    WorkerArtifactUploadResponse,
    WorkerCancelAckRequest,
    WorkerCancelAckResponse,
    WorkerEnrollHandshakeRequest,
    WorkerEnrollHandshakeResponse,
    WorkerEnrollmentCreateRequest,
    WorkerEnrollmentCreateResponse,
    WorkerIsolationMode,
    WorkerJobHeartbeatRequest,
    WorkerJobHeartbeatResponse,
    WorkerJobResultReceipt,
    WorkerPage,
    WorkerPollRequest,
    WorkerPollResponse,
    WorkerSelfTestResponse,
    WorkerStatus,
    WorkspaceWorkerReadinessResponse,
)
from red2pr_control.core.errors import (
    PROBLEM_JSON_MEDIA_TYPE,
    DependencyUnavailableError,
)
from red2pr_control.core.logging import current_correlation_id
from red2pr_control.iam.rbac import (
    ALL_WORKSPACE_ROLES,
    WorkspaceAccessContext,
    format_version_etag,
    make_workspace_rbac_dependency,
)
from red2pr_control.iam.sessions import IamService, extract_client_ip
from red2pr_control.orchestrator.queue import (
    QUEUE_OPERATOR_ROLES,
    DurableTaskQueueService,
    OperationReceiptService,
)
from red2pr_control.orchestrator.worker_broker import WorkerBrokerService
from red2pr_control.triage_evidence.artifact_store import (
    ArtifactStoreProtocol,
    LocalEncryptedArtifactStore,
)

_COMMON_PROBLEM_RESPONSES: dict[int | str, dict[str, object]] = {
    400: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    401: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    403: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    404: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    409: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    410: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    412: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    422: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    429: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    503: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
}


def _req_corr_id(request: Request) -> str:
    state_corr = getattr(request.state, "correlation_id", None)
    if isinstance(state_corr, str) and state_corr:
        return state_corr
    return current_correlation_id()


def _resolve_iam(request: Request) -> IamService:
    svc = getattr(request.app.state, "iam_service", None)
    if not isinstance(svc, IamService):
        raise DependencyUnavailableError(
            code="iam_unconfigured",
            detail="IAM persistence service is not configured on this control-plane instance.",
        )
    return svc


def _resolve_queue_service(
    request: Request,
    iam: Annotated[IamService, Depends(_resolve_iam)],
) -> DurableTaskQueueService:
    existing = getattr(request.app.state, "task_queue_service", None)
    if isinstance(existing, DurableTaskQueueService):
        return existing
    created = DurableTaskQueueService(
        session_factory=iam.session_factory,
        signing_key=iam.csrf_signing_key,
    )
    request.app.state.task_queue_service = created
    return created


def _resolve_operation_receipt_service(
    request: Request,
    iam: Annotated[IamService, Depends(_resolve_iam)],
) -> OperationReceiptService:
    existing = getattr(request.app.state, "operation_receipt_service", None)
    if isinstance(existing, OperationReceiptService):
        return existing
    created = OperationReceiptService(session_factory=iam.session_factory)
    request.app.state.operation_receipt_service = created
    return created


def _resolve_artifact_store(
    request: Request,
    iam: Annotated[IamService, Depends(_resolve_iam)],
) -> ArtifactStoreProtocol:
    existing = getattr(request.app.state, "artifact_store", None)
    if existing is not None:
        return existing  # type: ignore[no-any-return]
    derived_kek = hashlib.sha256(b"red2pr:artifact_kek:v1:" + iam.csrf_signing_key).digest()
    fallback_dir = FsPath(tempfile.mkdtemp(prefix="red2pr-worker-artifacts-"))
    created = LocalEncryptedArtifactStore(
        root_dir=fallback_dir,
        key_ring=MasterKeyRing(active_version=1, keys={1: derived_kek}),
    )
    request.app.state.artifact_store = created
    return created


def _resolve_worker_broker_service(
    request: Request,
    iam: Annotated[IamService, Depends(_resolve_iam)],
    queue_svc: Annotated[DurableTaskQueueService, Depends(_resolve_queue_service)],
    artifact_store: Annotated[ArtifactStoreProtocol, Depends(_resolve_artifact_store)],
) -> WorkerBrokerService:
    existing = getattr(request.app.state, "worker_broker_service", None)
    if isinstance(existing, WorkerBrokerService):
        return existing
    created = WorkerBrokerService(
        session_factory=iam.session_factory,
        signing_key=iam.csrf_signing_key,
        queue_service=queue_svc,
        artifact_store=artifact_store,
    )
    request.app.state.worker_broker_service = created
    return created


_require_queue_read = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="task_job.read",
)

_require_queue_operator = make_workspace_rbac_dependency(
    allowed_roles=QUEUE_OPERATOR_ROLES,
    require_csrf=True,
    allow_break_glass=False,
    action="task_job.action",
)

_require_worker_readiness_read = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="worker.readiness.read",
)


def build_orchestrator_router() -> APIRouter:
    """Build `/api/v1` router exposing `A-13` workers, `A-14` task-jobs & `A-24` receipts."""
    router = APIRouter(prefix="/api/v1")

    @router.get(
        "/system/workers",
        operation_id="listSystemWorkers",
        tags=["workers"],
        response_model=WorkerPage,
        summary="List global enrolled isolated workers (instance owner only, A-13)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def list_system_workers(
        request: Request,
        iam: Annotated[IamService, Depends(_resolve_iam)],
        broker: Annotated[WorkerBrokerService, Depends(_resolve_worker_broker_service)],
        status: Annotated[WorkerStatus | None, Query()] = None,
        isolation_mode: Annotated[WorkerIsolationMode | None, Query()] = None,
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> WorkerPage:
        corr_id = _req_corr_id(request)
        auth = await iam.authenticate_request(
            request,
            require_csrf=False,
            correlation_id=corr_id,
        )
        return await broker.list_workers(
            auth,
            status=status,
            isolation_mode=isolation_mode,
            cursor=cursor,
            limit=limit,
            client_ip=extract_client_ip(request),
            correlation_id=corr_id,
            now=iam.now(),
        )

    @router.post(
        "/system/workers/enrollments",
        operation_id="createWorkerEnrollment",
        tags=["workers"],
        status_code=201,
        response_model=WorkerEnrollmentCreateResponse,
        summary="Mint one-time worker mTLS enrollment token (step-up gated, A-13)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def create_worker_enrollment(
        payload: WorkerEnrollmentCreateRequest,
        request: Request,
        iam: Annotated[IamService, Depends(_resolve_iam)],
        broker: Annotated[WorkerBrokerService, Depends(_resolve_worker_broker_service)],
    ) -> WorkerEnrollmentCreateResponse:
        corr_id = _req_corr_id(request)
        auth = await iam.authenticate_request(
            request,
            require_csrf=True,
            correlation_id=corr_id,
        )
        return await broker.create_enrollment(
            auth,
            payload=payload,
            client_ip=extract_client_ip(request),
            correlation_id=corr_id,
            now=iam.now(),
        )

    @router.post(
        "/system/workers/{worker_id}/actions",
        operation_id="performWorkerAction",
        tags=["workers"],
        status_code=202,
        response_model=ActionReceipt,
        summary="Drain, quarantine, revoke, or resume an enrolled worker (A-13)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def perform_worker_action(
        worker_id: Annotated[str, Path(min_length=1, max_length=64)],
        payload: WorkerActionRequest,
        request: Request,
        iam: Annotated[IamService, Depends(_resolve_iam)],
        broker: Annotated[WorkerBrokerService, Depends(_resolve_worker_broker_service)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
        if_match: Annotated[
            str | None,
            Header(alias="If-Match", max_length=128),
        ] = None,
    ) -> ActionReceipt:
        corr_id = _req_corr_id(request)
        auth = await iam.authenticate_request(
            request,
            require_csrf=True,
            correlation_id=corr_id,
        )
        return await broker.perform_worker_action(
            auth,
            worker_id=worker_id,
            payload=payload,
            idempotency_key=idempotency_key,
            if_match_header=if_match,
            client_ip=extract_client_ip(request),
            correlation_id=corr_id,
            now=iam.now(),
        )

    @router.post(
        "/system/workers/{worker_id}/self-test",
        operation_id="runWorkerSelfTest",
        tags=["workers"],
        response_model=WorkerSelfTestResponse,
        summary="Verify mTLS certificate, external signer, and sandbox isolation posture (A-13)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def run_worker_self_test(
        worker_id: Annotated[str, Path(min_length=1, max_length=64)],
        request: Request,
        iam: Annotated[IamService, Depends(_resolve_iam)],
        broker: Annotated[WorkerBrokerService, Depends(_resolve_worker_broker_service)],
    ) -> WorkerSelfTestResponse:
        corr_id = _req_corr_id(request)
        auth = await iam.authenticate_request(
            request,
            require_csrf=True,
            correlation_id=corr_id,
        )
        return await broker.run_worker_self_test(
            auth,
            worker_id=worker_id,
            client_ip=extract_client_ip(request),
            correlation_id=corr_id,
            now=iam.now(),
        )

    @router.get(
        "/workspaces/{ws}/workers/readiness",
        operation_id="getWorkspaceWorkerReadiness",
        tags=["workers"],
        response_model=WorkspaceWorkerReadinessResponse,
        summary="Get workspace-scoped sandbox worker readiness & active leases (UI-S13)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def get_workspace_worker_readiness(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_worker_readiness_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        broker: Annotated[WorkerBrokerService, Depends(_resolve_worker_broker_service)],
    ) -> WorkspaceWorkerReadinessResponse:
        return await broker.get_workspace_worker_readiness(ws_ctx, now=iam.now())

    @router.get(
        "/workspaces/{ws}/task-jobs",
        operation_id="listWorkspaceTaskJobs",
        tags=["queues"],
        response_model=TaskJobPage,
        summary="List workspace task queue jobs with fairness & cap summary (A-14)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def list_workspace_task_jobs(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_queue_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        queue_svc: Annotated[DurableTaskQueueService, Depends(_resolve_queue_service)],
        state: Annotated[TaskJobState | None, Query()] = None,
        kind: Annotated[str | None, Query(max_length=120)] = None,
        repository_id: Annotated[str | None, Query(max_length=36)] = None,
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
    ) -> TaskJobPage:
        return await queue_svc.list_workspace_jobs(
            ws_ctx,
            state=state,
            kind=kind,
            repository_id=repository_id,
            cursor=cursor,
            limit=limit,
            now=iam.now(),
        )

    @router.get(
        "/workspaces/{ws}/task-jobs/{job_id}",
        operation_id="getWorkspaceTaskJob",
        tags=["queues"],
        response_model=TaskJobDetail,
        summary="Get workspace task job detail, attempts, and DLQ state (A-14)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def get_workspace_task_job(
        job_id: Annotated[str, Path(min_length=1, max_length=64)],
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_queue_read)],
        queue_svc: Annotated[DurableTaskQueueService, Depends(_resolve_queue_service)],
    ) -> TaskJobDetail:
        detail = await queue_svc.get_workspace_job(ws_ctx, job_id=job_id)
        response.headers["ETag"] = format_version_etag(detail.version)
        return detail

    @router.post(
        "/workspaces/{ws}/task-jobs/{job_id}/actions",
        operation_id="performWorkspaceTaskJobAction",
        tags=["queues"],
        status_code=202,
        response_model=ActionReceipt,
        summary="Cancel, requeue, or reconcile a workspace task job (A-14)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def perform_workspace_task_job_action(
        job_id: Annotated[str, Path(min_length=1, max_length=64)],
        payload: TaskJobActionRequest,
        request: Request,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_queue_operator)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        queue_svc: Annotated[DurableTaskQueueService, Depends(_resolve_queue_service)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
        if_match: Annotated[
            str | None,
            Header(alias="If-Match", max_length=128),
        ] = None,
    ) -> ActionReceipt:
        corr_id = _req_corr_id(request)
        return await queue_svc.perform_job_action(
            ws_ctx,
            job_id=job_id,
            payload=payload,
            idempotency_key=idempotency_key,
            if_match_header=if_match,
            client_ip=extract_client_ip(request),
            correlation_id=corr_id,
            now=iam.now(),
        )

    @router.get(
        "/operations/{operation_id}",
        operation_id="getOperationReceipt",
        tags=["operations"],
        response_model=ActionReceipt,
        summary="Get asynchronous operation receipt enforcing originating scope (A-24)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def get_operation_receipt(
        operation_id: Annotated[str, Path(min_length=1, max_length=64)],
        request: Request,
        iam: Annotated[IamService, Depends(_resolve_iam)],
        op_svc: Annotated[
            OperationReceiptService,
            Depends(_resolve_operation_receipt_service),
        ],
    ) -> ActionReceipt:
        corr_id = _req_corr_id(request)
        auth = await iam.authenticate_request(
            request,
            require_csrf=False,
            correlation_id=corr_id,
        )
        return await op_svc.get_operation_receipt(
            auth,
            operation_id=operation_id,
            client_ip=extract_client_ip(request),
            correlation_id=corr_id,
            now=iam.now(),
        )

    return router


def build_internal_worker_router() -> APIRouter:
    """Build `/internal/v1` mTLS worker router (`S-21`; omitted from browser OpenAPI)."""
    router = APIRouter(prefix="/internal/v1", include_in_schema=False)

    @router.post("/workers/enroll", response_model=WorkerEnrollHandshakeResponse)
    async def enroll_internal_worker(
        payload: WorkerEnrollHandshakeRequest,
        request: Request,
        iam: Annotated[IamService, Depends(_resolve_iam)],
        broker: Annotated[WorkerBrokerService, Depends(_resolve_worker_broker_service)],
    ) -> WorkerEnrollHandshakeResponse:
        return await broker.enroll_worker(
            request,
            payload=payload,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
            now=iam.now(),
        )

    @router.post("/workers/{worker_id}/poll", response_model=WorkerPollResponse)
    async def poll_internal_worker(
        worker_id: Annotated[str, Path(min_length=1, max_length=64)],
        payload: WorkerPollRequest,
        request: Request,
        iam: Annotated[IamService, Depends(_resolve_iam)],
        broker: Annotated[WorkerBrokerService, Depends(_resolve_worker_broker_service)],
    ) -> WorkerPollResponse:
        return await broker.poll_worker_job(
            request,
            worker_id=worker_id,
            payload=payload,
            now=iam.now(),
        )

    @router.post("/jobs/{job_id}/heartbeat", response_model=WorkerJobHeartbeatResponse)
    async def heartbeat_internal_job(
        job_id: Annotated[str, Path(min_length=1, max_length=64)],
        payload: WorkerJobHeartbeatRequest,
        request: Request,
        iam: Annotated[IamService, Depends(_resolve_iam)],
        broker: Annotated[WorkerBrokerService, Depends(_resolve_worker_broker_service)],
    ) -> WorkerJobHeartbeatResponse:
        return await broker.heartbeat_sandbox_job(
            request,
            job_id=job_id,
            payload=payload,
            now=iam.now(),
        )

    @router.post("/jobs/{job_id}/upload", response_model=WorkerArtifactUploadResponse)
    async def upload_internal_job_artifact(
        job_id: Annotated[str, Path(min_length=1, max_length=64)],
        payload: WorkerArtifactUploadRequest,
        request: Request,
        iam: Annotated[IamService, Depends(_resolve_iam)],
        broker: Annotated[WorkerBrokerService, Depends(_resolve_worker_broker_service)],
        upload_capability: Annotated[str, Header(alias="X-Upload-Capability", max_length=4096)],
    ) -> WorkerArtifactUploadResponse:
        return await broker.upload_sandbox_artifact(
            request,
            job_id=job_id,
            upload_capability=upload_capability,
            payload=payload,
            now=iam.now(),
        )

    @router.post("/jobs/{job_id}/result", response_model=WorkerJobResultReceipt)
    async def submit_internal_job_result(
        job_id: Annotated[str, Path(min_length=1, max_length=64)],
        payload: ResultV1,
        request: Request,
        iam: Annotated[IamService, Depends(_resolve_iam)],
        broker: Annotated[WorkerBrokerService, Depends(_resolve_worker_broker_service)],
    ) -> WorkerJobResultReceipt:
        return await broker.submit_sandbox_result(
            request,
            job_id=job_id,
            result=payload,
            correlation_id=_req_corr_id(request),
            now=iam.now(),
        )

    @router.post("/jobs/{job_id}/cancel-ack", response_model=WorkerCancelAckResponse)
    async def cancel_ack_internal_job(
        job_id: Annotated[str, Path(min_length=1, max_length=64)],
        payload: WorkerCancelAckRequest,
        request: Request,
        iam: Annotated[IamService, Depends(_resolve_iam)],
        broker: Annotated[WorkerBrokerService, Depends(_resolve_worker_broker_service)],
    ) -> WorkerCancelAckResponse:
        return await broker.acknowledge_sandbox_cancel(
            request,
            job_id=job_id,
            payload=payload,
            correlation_id=_req_corr_id(request),
            now=iam.now(),
        )

    return router
