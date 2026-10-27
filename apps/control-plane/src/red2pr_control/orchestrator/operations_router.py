"""FastAPI /api/v1 HTTP router for A-14 workspace task-jobs & A-24 operation receipts."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, Path, Query, Request, Response

from py_contracts.primitives import ActionReceipt, Problem
from py_contracts.worker import (
    TaskJobActionRequest,
    TaskJobDetail,
    TaskJobPage,
    TaskJobState,
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


def build_orchestrator_router() -> APIRouter:
    """Build `/api/v1` router exposing `A-14` workspace task-jobs and `A-24` operations."""
    router = APIRouter(prefix="/api/v1")

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
