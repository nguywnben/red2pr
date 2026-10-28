"""FastAPI `/api/v1` router for `A-07` repository catalog, versioned policy & dry-run (`U12`)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, Depends, Header, Path, Query, Request, Response

from py_contracts.integrations import (
    BulkRepositoryPreviewRequest,
    BulkRepositoryPreviewResponse,
    BulkRepositoryUpdateRequest,
    BulkRepositoryUpdateResponse,
    ProviderKind,
    Repository,
    RepositoryCatalogPage,
    RepositoryDetailResponse,
    RepositoryMode,
    RepositoryPolicyPreviewRequest,
    RepositoryPolicyPreviewResponse,
    RepositoryPolicyStateResponse,
    RepositoryPolicyUpdateRequest,
    RepositoryUpdateRequest,
    WorkflowHazardStatus,
)
from py_contracts.primitives import Problem
from red2pr_control.core.errors import PROBLEM_JSON_MEDIA_TYPE, DependencyUnavailableError
from red2pr_control.core.logging import current_correlation_id
from red2pr_control.iam.csrf import set_csrf_cookie
from red2pr_control.iam.rbac import (
    ALL_WORKSPACE_ROLES,
    WorkspaceAccessContext,
    format_version_etag,
    make_workspace_rbac_dependency,
)
from red2pr_control.iam.sessions import IamService, extract_client_ip
from red2pr_control.repositories.catalog import RepositoryCatalogService

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


def _resolve_repository_catalog_service(request: Request) -> RepositoryCatalogService:
    existing = getattr(request.app.state, "repository_catalog_service", None)
    if isinstance(existing, RepositoryCatalogService):
        return existing
    iam = _resolve_iam(request)
    created = RepositoryCatalogService(
        session_factory=iam.session_factory,
        signing_key=iam.csrf_signing_key,
        clock=iam.now,
    )
    request.app.state.repository_catalog_service = created
    return created


def _maybe_refresh_csrf(
    response: Response,
    ws_ctx: WorkspaceAccessContext,
    iam: IamService,
) -> None:
    if ws_ctx.auth.csrf_cookie_refreshed:
        set_csrf_cookie(response, csrf_token=ws_ctx.auth.csrf_token, secure=iam.secure_cookies)


_require_repositories_read = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="repositories.read",
)

_require_repositories_csrf_read = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=True,
    allow_break_glass=True,
    action="repositories.preview",
)

_require_repositories_mutate = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=True,
    allow_break_glass=True,
    action="repositories.mutate",
)


def build_repositories_router() -> APIRouter:
    """Build `/api/v1` router exposing `A-07` repository catalog, policy & preview endpoints."""
    router = APIRouter(prefix="/api/v1")

    @router.get(
        "/workspaces/{ws}/repositories",
        operation_id="listWorkspaceRepositories",
        tags=["repositories"],
        response_model=RepositoryCatalogPage,
        summary="List authorized workspace repositories with S-04 cursor & scoped facets (A-07)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def list_workspace_repositories(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_repositories_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[RepositoryCatalogService, Depends(_resolve_repository_catalog_service)],
        response: Response,
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        q: Annotated[str | None, Query(max_length=256)] = None,
        connection_id: Annotated[str | None, Query(max_length=64)] = None,
        provider: Annotated[ProviderKind | None, Query()] = None,
        mode: Annotated[RepositoryMode | None, Query()] = None,
        paused: Annotated[bool | None, Query()] = None,
        hazard_status: Annotated[WorkflowHazardStatus | None, Query()] = None,
        tag: Annotated[str | None, Query(max_length=120)] = None,
        include_inactive: Annotated[bool, Query()] = False,
    ) -> RepositoryCatalogPage:
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return await svc.list_repositories(
            ws_ctx,
            cursor=cursor,
            limit=limit,
            q=q,
            connection_id=connection_id,
            provider=provider,
            mode=mode,
            paused=paused,
            hazard_status=hazard_status,
            tag=tag,
            include_inactive=include_inactive,
        )

    @router.post(
        "/workspaces/{ws}/repositories/policy-previews",
        operation_id="previewBulkRepositoryPolicies",
        tags=["repositories"],
        response_model=BulkRepositoryPreviewResponse,
        summary="Preview bulk repository mode, pause, or tag changes with zero DB mutations (A-07)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def preview_bulk_repository_policies(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_repositories_csrf_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[RepositoryCatalogService, Depends(_resolve_repository_catalog_service)],
        payload: Annotated[BulkRepositoryPreviewRequest, Body()],
        request: Request,
        response: Response,
    ) -> BulkRepositoryPreviewResponse:
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return await svc.preview_bulk_repositories(
            ws_ctx,
            payload=payload,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
        )

    @router.post(
        "/workspaces/{ws}/repositories/bulk-update",
        operation_id="bulkUpdateWorkspaceRepositories",
        tags=["repositories"],
        response_model=BulkRepositoryUpdateResponse,
        summary="Apply all-or-nothing version-checked bulk repository updates (A-07)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def bulk_update_workspace_repositories(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_repositories_mutate)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[RepositoryCatalogService, Depends(_resolve_repository_catalog_service)],
        payload: Annotated[BulkRepositoryUpdateRequest, Body()],
        request: Request,
        response: Response,
    ) -> BulkRepositoryUpdateResponse:
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return await svc.bulk_update_repositories(
            ws_ctx,
            payload=payload,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
        )

    @router.get(
        "/workspaces/{ws}/repositories/{repository_id}",
        operation_id="getWorkspaceRepository",
        tags=["repositories"],
        response_model=RepositoryDetailResponse,
        summary="Get repository overview, effective policy, CI runs, access & audit history (A-07)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def get_workspace_repository(
        repository_id: Annotated[str, Path(min_length=1, max_length=64)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_repositories_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[RepositoryCatalogService, Depends(_resolve_repository_catalog_service)],
        request: Request,
        response: Response,
    ) -> RepositoryDetailResponse:
        _maybe_refresh_csrf(response, ws_ctx, iam)
        detail_dto, version = await svc.get_repository(
            ws_ctx,
            repository_id=repository_id,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
        )
        response.headers["ETag"] = format_version_etag(version)
        return detail_dto

    @router.patch(
        "/workspaces/{ws}/repositories/{repository_id}",
        operation_id="updateWorkspaceRepository",
        tags=["repositories"],
        response_model=Repository,
        summary="Update repository mode, pause state, tags, or W-02 grant review (A-07)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def update_workspace_repository(
        repository_id: Annotated[str, Path(min_length=1, max_length=64)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_repositories_mutate)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[RepositoryCatalogService, Depends(_resolve_repository_catalog_service)],
        payload: Annotated[RepositoryUpdateRequest, Body()],
        request: Request,
        response: Response,
        if_match: Annotated[str | None, Header(alias="If-Match", max_length=128)] = None,
    ) -> Repository:
        _maybe_refresh_csrf(response, ws_ctx, iam)
        dto, version = await svc.update_repository(
            ws_ctx,
            repository_id=repository_id,
            payload=payload,
            if_match_header=if_match,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
        )
        response.headers["ETag"] = format_version_etag(version)
        return dto

    @router.get(
        "/workspaces/{ws}/repositories/{repository_id}/policy",
        operation_id="getWorkspaceRepositoryPolicy",
        tags=["repositories"],
        response_model=RepositoryPolicyStateResponse,
        summary="Get immutable repository policy snapshot, effective merge & revisions (A-07)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def get_workspace_repository_policy(
        repository_id: Annotated[str, Path(min_length=1, max_length=64)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_repositories_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[RepositoryCatalogService, Depends(_resolve_repository_catalog_service)],
        request: Request,
        response: Response,
    ) -> RepositoryPolicyStateResponse:
        _maybe_refresh_csrf(response, ws_ctx, iam)
        state_dto, revision = await svc.get_repository_policy(
            ws_ctx,
            repository_id=repository_id,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
        )
        response.headers["ETag"] = format_version_etag(revision)
        return state_dto

    @router.patch(
        "/workspaces/{ws}/repositories/{repository_id}/policy",
        operation_id="updateWorkspaceRepositoryPolicy",
        tags=["repositories"],
        response_model=RepositoryPolicyStateResponse,
        summary="Create a new immutable repository policy revision with concurrency guard (A-07)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def update_workspace_repository_policy(
        repository_id: Annotated[str, Path(min_length=1, max_length=64)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_repositories_mutate)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[RepositoryCatalogService, Depends(_resolve_repository_catalog_service)],
        payload: Annotated[RepositoryPolicyUpdateRequest, Body()],
        request: Request,
        response: Response,
        if_match: Annotated[str | None, Header(alias="If-Match", max_length=128)] = None,
    ) -> RepositoryPolicyStateResponse:
        _maybe_refresh_csrf(response, ws_ctx, iam)
        state_dto, revision = await svc.update_repository_policy(
            ws_ctx,
            repository_id=repository_id,
            payload=payload,
            if_match_header=if_match,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
        )
        response.headers["ETag"] = format_version_etag(revision)
        return state_dto

    @router.post(
        "/workspaces/{ws}/repositories/{repository_id}/policy/previews",
        operation_id="previewWorkspaceRepositoryPolicy",
        tags=["repositories"],
        response_model=RepositoryPolicyPreviewResponse,
        summary="Simulate candidate repository policy without saving or mutating rows (A-07)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def preview_workspace_repository_policy(
        repository_id: Annotated[str, Path(min_length=1, max_length=64)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_repositories_csrf_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[RepositoryCatalogService, Depends(_resolve_repository_catalog_service)],
        payload: Annotated[RepositoryPolicyPreviewRequest, Body()],
        request: Request,
        response: Response,
    ) -> RepositoryPolicyPreviewResponse:
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return await svc.preview_repository_policy(
            ws_ctx,
            repository_id=repository_id,
            payload=payload,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
        )

    return router
