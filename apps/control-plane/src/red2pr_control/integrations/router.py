"""FastAPI `/api/v1` router for `A-06` workspace integrations & `A-23` GitHub callbacks (`U09`)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, Depends, Header, Path, Query, Request, Response

from py_contracts.integrations import (
    Connection,
    ConnectionDetailResponse,
    ConnectionPage,
    ConnectionPatchRequest,
    ConnectionProbeResponse,
    ConnectionReconcileRequest,
    ConnectionReconcileResponse,
    ConnectionSyncResponse,
    ConnectionWrite,
    GitHubCallbackResponse,
    GitHubInstallationConfirmRequest,
    GitHubInstallationConfirmResponse,
    GitHubInstallStateCreateRequest,
    GitHubInstallStateResponse,
    ProviderKind,
)
from py_contracts.primitives import ActionReceipt, Problem
from red2pr_control.core.errors import (
    PROBLEM_JSON_MEDIA_TYPE,
    BadRequestError,
    DependencyUnavailableError,
)
from red2pr_control.core.logging import current_correlation_id
from red2pr_control.iam.rbac import (
    ADMIN_ONLY_ROLES,
    ALL_WORKSPACE_ROLES,
    WorkspaceAccessContext,
    format_version_etag,
    make_workspace_rbac_dependency,
)
from red2pr_control.iam.sessions import IamService, extract_client_ip
from red2pr_control.integrations.github_app import GitHubIntegrationService
from red2pr_control.integrations.reconciler import MissedEventReconciler

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


def _resolve_github_integration_service(request: Request) -> GitHubIntegrationService:
    svc = getattr(request.app.state, "github_integration_service", None)
    if not isinstance(svc, GitHubIntegrationService):
        raise DependencyUnavailableError(
            code="integrations_unconfigured",
            detail="Provider integration service is not configured on this control-plane instance.",
        )
    return svc


def _resolve_reconciler_service(request: Request) -> MissedEventReconciler:
    svc = getattr(request.app.state, "reconciler_service", None)
    if not isinstance(svc, MissedEventReconciler):
        raise DependencyUnavailableError(
            code="reconciler_unconfigured",
            detail="Missed-event reconciler service is not configured on this instance.",
        )
    return svc


def _require_idempotency_key(raw_key: str | None, *, endpoint_label: str) -> str:
    if not raw_key or not raw_key.strip():
        raise BadRequestError(
            code="missing_idempotency_key",
            detail=f"{endpoint_label} requires an S-05 Idempotency-Key UUIDv7 header.",
        )
    return raw_key.strip()


def _extract_request_origin(request: Request) -> str | None:
    origin = request.headers.get("origin")
    if origin and origin.strip():
        return origin.strip()[:512]
    return None


_require_integrations_read = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="integration.read",
)

_require_integrations_admin = make_workspace_rbac_dependency(
    allowed_roles=ADMIN_ONLY_ROLES,
    require_csrf=True,
    allow_break_glass=False,
    action="integration.mutate",
)


def build_integrations_router() -> APIRouter:
    """Build `/api/v1` router exposing `A-06` workspace integrations and `A-23` GitHub callbacks."""
    router = APIRouter(prefix="/api/v1")

    @router.get(
        "/workspaces/{ws}/integrations",
        operation_id="listConnections",
        tags=["integrations"],
        response_model=ConnectionPage,
        summary="List workspace provider connections with secret-presence metadata (A-06)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def list_connections(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_integrations_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[GitHubIntegrationService, Depends(_resolve_github_integration_service)],
        provider: Annotated[ProviderKind | None, Query()] = None,
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
    ) -> ConnectionPage:
        return await svc.list_connections(
            ws_ctx,
            provider=provider,
            cursor=cursor,
            limit=limit,
            now=iam.now(),
        )

    @router.post(
        "/workspaces/{ws}/integrations",
        operation_id="createConnection",
        tags=["integrations"],
        status_code=201,
        response_model=Connection,
        summary="Create a workspace provider connection sealing write-only credentials (A-06)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def create_connection(
        payload: ConnectionWrite,
        request: Request,
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_integrations_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[GitHubIntegrationService, Depends(_resolve_github_integration_service)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
    ) -> Connection:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label="POST /api/v1/workspaces/{ws}/integrations",
        )
        created = await svc.create_connection(
            ws_ctx,
            payload,
            idempotency_key=idem,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
            now=iam.now(),
        )
        response.headers["ETag"] = format_version_etag(created.version)
        return created

    @router.get(
        "/workspaces/{ws}/integrations/{connection_id}",
        operation_id="getConnection",
        tags=["integrations"],
        response_model=ConnectionDetailResponse,
        summary="Get provider connection detail, capability snapshot & scoped repositories (A-06)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def get_connection(
        connection_id: Annotated[str, Path(min_length=1, max_length=64)],
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_integrations_read)],
        svc: Annotated[GitHubIntegrationService, Depends(_resolve_github_integration_service)],
    ) -> ConnectionDetailResponse:
        detail = await svc.get_connection_detail(ws_ctx, connection_id=connection_id)
        response.headers["ETag"] = format_version_etag(detail.connection.version)
        return detail

    @router.patch(
        "/workspaces/{ws}/integrations/{connection_id}",
        operation_id="updateConnection",
        tags=["integrations"],
        response_model=Connection,
        summary="Update provider connection metadata or rotate write-only credentials (A-06)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def update_connection(
        connection_id: Annotated[str, Path(min_length=1, max_length=64)],
        payload: ConnectionPatchRequest,
        request: Request,
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_integrations_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[GitHubIntegrationService, Depends(_resolve_github_integration_service)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
        if_match: Annotated[
            str | None,
            Header(alias="If-Match", max_length=128),
        ] = None,
    ) -> Connection:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label="PATCH /api/v1/workspaces/{ws}/integrations/{connection_id}",
        )
        updated = await svc.update_connection(
            ws_ctx,
            connection_id=connection_id,
            payload=payload,
            if_match_header=if_match,
            idempotency_key=idem,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
            now=iam.now(),
        )
        response.headers["ETag"] = format_version_etag(updated.version)
        return updated

    @router.delete(
        "/workspaces/{ws}/integrations/{connection_id}",
        operation_id="deleteConnection",
        tags=["integrations"],
        response_model=ActionReceipt,
        summary="Disconnect provider connection, revoke credentials & suspend active jobs (A-06)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def delete_connection(
        connection_id: Annotated[str, Path(min_length=1, max_length=64)],
        request: Request,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_integrations_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[GitHubIntegrationService, Depends(_resolve_github_integration_service)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
    ) -> ActionReceipt:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label="DELETE /api/v1/workspaces/{ws}/integrations/{connection_id}",
        )
        return await svc.delete_connection(
            ws_ctx,
            connection_id=connection_id,
            idempotency_key=idem,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
            now=iam.now(),
        )

    @router.post(
        "/workspaces/{ws}/integrations/{connection_id}/probes",
        operation_id="probeConnection",
        tags=["integrations"],
        response_model=ConnectionProbeResponse,
        summary="Run live provider capability & permission probe (A-06)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def probe_connection(
        connection_id: Annotated[str, Path(min_length=1, max_length=64)],
        request: Request,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_integrations_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[GitHubIntegrationService, Depends(_resolve_github_integration_service)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
    ) -> ConnectionProbeResponse:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label="POST /api/v1/workspaces/{ws}/integrations/{connection_id}/probes",
        )
        return await svc.probe_connection(
            ws_ctx,
            connection_id=connection_id,
            idempotency_key=idem,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
            now=iam.now(),
        )

    @router.post(
        "/workspaces/{ws}/integrations/{connection_id}/sync",
        operation_id="syncConnection",
        tags=["integrations"],
        response_model=ConnectionSyncResponse,
        summary="Synchronize paginated repositories and `.github/workflows` hazard metadata (A-06)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def sync_connection(
        connection_id: Annotated[str, Path(min_length=1, max_length=64)],
        request: Request,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_integrations_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[GitHubIntegrationService, Depends(_resolve_github_integration_service)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
    ) -> ConnectionSyncResponse:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label="POST /api/v1/workspaces/{ws}/integrations/{connection_id}/sync",
        )
        return await svc.sync_connection(
            ws_ctx,
            connection_id=connection_id,
            idempotency_key=idem,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
            now=iam.now(),
        )

    @router.post(
        "/workspaces/{ws}/integrations/{connection_id}/reconcile",
        operation_id="reconcileConnectionRuns",
        tags=["integrations"],
        response_model=ConnectionReconcileResponse,
        summary=(
            "Reconcile missed webhook events and resumable polling cursors (A-06, SRC-03, SRC-04)"
        ),
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def reconcile_connection_runs(
        connection_id: Annotated[str, Path(min_length=1, max_length=64)],
        request: Request,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_integrations_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        reconciler: Annotated[MissedEventReconciler, Depends(_resolve_reconciler_service)],
        payload: Annotated[ConnectionReconcileRequest | None, Body()] = None,
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
    ) -> ConnectionReconcileResponse:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label="POST /api/v1/workspaces/{ws}/integrations/{connection_id}/reconcile",
        )
        effective_payload = payload or ConnectionReconcileRequest()
        return await reconciler.reconcile_connection(
            ws_ctx,
            connection_id=connection_id,
            payload=effective_payload,
            idempotency_key=idem,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
            now=iam.now(),
        )

    @router.post(
        "/workspaces/{ws}/integrations/{connection_id}/installations/state",
        operation_id="mintGitHubInstallState",
        tags=["integrations"],
        status_code=201,
        response_model=GitHubInstallStateResponse,
        summary="Mint single-use 10m GitHub App callback state bound to user/workspace (A-23)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def mint_github_install_state(
        connection_id: Annotated[str, Path(min_length=1, max_length=64)],
        request: Request,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_integrations_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[GitHubIntegrationService, Depends(_resolve_github_integration_service)],
        payload: Annotated[GitHubInstallStateCreateRequest | None, Body()] = None,
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
    ) -> GitHubInstallStateResponse:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label=(
                "POST /api/v1/workspaces/{ws}/integrations/{connection_id}/installations/state"
            ),
        )
        effective_payload = payload or GitHubInstallStateCreateRequest(
            expected_origin=_extract_request_origin(request)
        )
        if effective_payload.expected_origin is None:
            effective_origin = _extract_request_origin(request)
            if effective_origin is not None:
                effective_payload = GitHubInstallStateCreateRequest(
                    expected_origin=effective_origin
                )
        return await svc.mint_install_state(
            ws_ctx,
            connection_id=connection_id,
            payload=effective_payload,
            idempotency_key=idem,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
            now=iam.now(),
        )

    @router.get(
        "/integrations/github/callback",
        operation_id="handleGitHubCallback",
        tags=["integrations"],
        response_model=GitHubCallbackResponse,
        summary="Validate single-use GitHub App callback state without mutation (A-23)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def handle_github_callback(
        request: Request,
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[GitHubIntegrationService, Depends(_resolve_github_integration_service)],
        state: Annotated[str | None, Query(max_length=512)] = None,
        installation_id: Annotated[str | None, Query(max_length=128)] = None,
        setup_action: Annotated[str | None, Query(max_length=120)] = None,
    ) -> GitHubCallbackResponse:
        corr_id = _req_corr_id(request)
        auth = await iam.authenticate_request(
            request,
            require_csrf=False,
            correlation_id=corr_id,
        )
        return await svc.validate_github_callback(
            auth,
            state=state,
            installation_id=installation_id,
            setup_action=setup_action,
            request_origin=_extract_request_origin(request),
            client_ip=extract_client_ip(request),
            correlation_id=corr_id,
            now=iam.now(),
        )

    @router.post(
        "/workspaces/{ws}/integrations/{connection_id}/installations/confirm",
        operation_id="confirmGitHubInstallation",
        tags=["integrations"],
        response_model=GitHubInstallationConfirmResponse,
        summary="Consume single-use state, verify GitHub App installation & discover repos (A-23)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def confirm_github_installation(
        connection_id: Annotated[str, Path(min_length=1, max_length=64)],
        payload: GitHubInstallationConfirmRequest,
        request: Request,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_integrations_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[GitHubIntegrationService, Depends(_resolve_github_integration_service)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
    ) -> GitHubInstallationConfirmResponse:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label=(
                "POST /api/v1/workspaces/{ws}/integrations/{connection_id}/installations/confirm"
            ),
        )
        effective_payload = payload
        if effective_payload.expected_origin is None:
            effective_origin = _extract_request_origin(request)
            if effective_origin is not None:
                effective_payload = payload.model_copy(update={"expected_origin": effective_origin})
        return await svc.confirm_github_installation(
            ws_ctx,
            connection_id=connection_id,
            payload=effective_payload,
            idempotency_key=idem,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
            now=iam.now(),
        )

    return router
