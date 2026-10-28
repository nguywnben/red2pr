"""FastAPI `/api/v1` router for `A-20` workspace Meta models, probes & agent profiles (`U17`)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, Depends, Header, Path, Request, Response

from py_contracts.integrations import ConsentRecord, ConsentRevokeRequest
from py_contracts.models import (
    AgentProfile,
    AgentProfileUpdateRequest,
    AgentProfileUpdateResponse,
    ModelProbeRequest,
    ModelProbeResponse,
    WorkspaceAgentProfilesResponse,
    WorkspaceInferenceConsentCreateRequest,
    WorkspaceModelsConfigUpdateRequest,
    WorkspaceModelsConfigUpdateResponse,
    WorkspaceModelsResponse,
)
from py_contracts.primitives import Problem
from red2pr_control.core.errors import (
    PROBLEM_JSON_MEDIA_TYPE,
    BadRequestError,
    DependencyUnavailableError,
)
from red2pr_control.core.logging import current_correlation_id
from red2pr_control.iam.csrf import set_csrf_cookie
from red2pr_control.iam.rbac import (
    ADMIN_ONLY_ROLES,
    ALL_WORKSPACE_ROLES,
    WorkspaceAccessContext,
    format_version_etag,
    make_workspace_rbac_dependency,
)
from red2pr_control.iam.sessions import IamService, extract_client_ip
from red2pr_control.inference.agent_profiles import AgentProfileService
from red2pr_control.inference.meta_client import MetaMuseInferenceService

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

_EMPTY_CONSENT_REVOKE = ConsentRevokeRequest()


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


def _resolve_meta_inference_service(request: Request) -> MetaMuseInferenceService:
    svc = getattr(request.app.state, "meta_inference_service", None)
    if not isinstance(svc, MetaMuseInferenceService):
        raise DependencyUnavailableError(
            code="inference_unconfigured",
            detail="Meta Muse inference broker is not configured on this control-plane instance.",
        )
    return svc


def _resolve_agent_profile_service(request: Request) -> AgentProfileService:
    svc = getattr(request.app.state, "agent_profile_service", None)
    if isinstance(svc, AgentProfileService):
        return svc
    iam = _resolve_iam(request)
    meta = _resolve_meta_inference_service(request)
    created = AgentProfileService(
        session_factory=iam.session_factory,
        iam_service=iam,
        meta_inference_service=meta,
    )
    request.app.state.agent_profile_service = created
    return created


def _maybe_refresh_csrf(
    response: Response,
    ws_ctx: WorkspaceAccessContext,
    iam: IamService,
) -> None:
    if ws_ctx.auth.csrf_cookie_refreshed:
        set_csrf_cookie(response, csrf_token=ws_ctx.auth.csrf_token, secure=iam.secure_cookies)


def _require_idempotency_key(raw_key: str | None, *, endpoint_label: str) -> str:
    if not raw_key or not raw_key.strip():
        raise BadRequestError(
            code="missing_idempotency_key",
            detail=f"{endpoint_label} requires an S-05 Idempotency-Key UUIDv7 header.",
        )
    return raw_key.strip()


_require_models_read = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="models.read",
)

_require_models_admin = make_workspace_rbac_dependency(
    allowed_roles=ADMIN_ONLY_ROLES,
    require_csrf=True,
    allow_break_glass=False,
    action="models.mutate",
)

_require_agent_profiles_read = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="agent_profiles.read",
)

_require_agent_profiles_admin = make_workspace_rbac_dependency(
    allowed_roles=ADMIN_ONLY_ROLES,
    require_csrf=True,
    allow_break_glass=False,
    action="agent_profiles.mutate",
)


def build_inference_router() -> APIRouter:
    """Build `/api/v1` router exposing `A-20` workspace Meta models, probes & agent profiles."""
    router = APIRouter(prefix="/api/v1")

    @router.get(
        "/workspaces/{ws}/models",
        operation_id="listWorkspaceModels",
        tags=["models"],
        response_model=WorkspaceModelsResponse,
        summary="Get workspace Meta model registry, masked key presence, budgets & usage (A-20)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def list_workspace_models(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_models_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[MetaMuseInferenceService, Depends(_resolve_meta_inference_service)],
        response: Response,
    ) -> WorkspaceModelsResponse:
        dto = await svc.get_workspace_models(access=ws_ctx)
        response.headers["ETag"] = format_version_etag(dto.version)
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return dto

    @router.patch(
        "/workspaces/{ws}/models/config",
        operation_id="updateWorkspaceModelsConfig",
        tags=["models"],
        response_model=WorkspaceModelsConfigUpdateResponse,
        summary="Update workspace Meta API key, pricing, NFR-06 budgets & escalation policy (A-20)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def update_workspace_models_config(
        payload: WorkspaceModelsConfigUpdateRequest,
        request: Request,
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_models_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[MetaMuseInferenceService, Depends(_resolve_meta_inference_service)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
        if_match: Annotated[
            str | None,
            Header(alias="If-Match", max_length=64),
        ] = None,
    ) -> WorkspaceModelsConfigUpdateResponse:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label="PATCH /api/v1/workspaces/{ws}/models/config",
        )
        updated = await svc.update_workspace_models_config(
            access=ws_ctx,
            payload=payload,
            idempotency_key=idem,
            if_match_header=if_match,
            correlation_id=_req_corr_id(request),
            client_ip=extract_client_ip(request),
        )
        response.headers["ETag"] = format_version_etag(updated.models_state.version)
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return updated

    @router.post(
        "/workspaces/{ws}/models/consents",
        operation_id="grantWorkspaceInferenceConsent",
        tags=["models"],
        status_code=201,
        response_model=ConsentRecord,
        summary="Grant explicit workspace-scoped outbound Meta inference consent (SEC-018)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def grant_workspace_inference_consent(
        payload: WorkspaceInferenceConsentCreateRequest,
        request: Request,
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_models_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[MetaMuseInferenceService, Depends(_resolve_meta_inference_service)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
    ) -> ConsentRecord:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label="POST /api/v1/workspaces/{ws}/models/consents",
        )
        consent = await svc.grant_workspace_inference_consent(
            access=ws_ctx,
            payload=payload,
            idempotency_key=idem,
            correlation_id=_req_corr_id(request),
            client_ip=extract_client_ip(request),
        )
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return consent

    @router.delete(
        "/workspaces/{ws}/models/consents/{consent_id}",
        operation_id="revokeWorkspaceInferenceConsent",
        tags=["models"],
        response_model=ConsentRecord,
        summary="Revoke workspace-scoped outbound Meta inference consent (SEC-018)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def revoke_workspace_inference_consent(
        request: Request,
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_models_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[MetaMuseInferenceService, Depends(_resolve_meta_inference_service)],
        consent_id: Annotated[str, Path(min_length=1, max_length=64)],
        payload: Annotated[ConsentRevokeRequest, Body()] = _EMPTY_CONSENT_REVOKE,
    ) -> ConsentRecord:
        revoked = await svc.revoke_workspace_inference_consent(
            access=ws_ctx,
            consent_id=consent_id,
            reason=payload.reason,
            correlation_id=_req_corr_id(request),
            client_ip=extract_client_ip(request),
        )
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return revoked

    @router.post(
        "/workspaces/{ws}/model-probes",
        operation_id="createWorkspaceModelProbe",
        tags=["models"],
        response_model=ModelProbeResponse,
        summary="Run consented, budget-capped Meta Model API capability probe (A-20)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def create_workspace_model_probe(
        payload: ModelProbeRequest,
        request: Request,
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_models_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[MetaMuseInferenceService, Depends(_resolve_meta_inference_service)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
    ) -> ModelProbeResponse:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label="POST /api/v1/workspaces/{ws}/model-probes",
        )
        probe_res = await svc.probe_model(
            access=ws_ctx,
            payload=payload,
            idempotency_key=idem,
            correlation_id=_req_corr_id(request),
            client_ip=extract_client_ip(request),
        )
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return probe_res

    @router.get(
        "/workspaces/{ws}/agent-profiles",
        operation_id="listWorkspaceAgentProfiles",
        tags=["agents"],
        response_model=WorkspaceAgentProfilesResponse,
        summary="List bounded workspace agent profiles, S-20 tool matrix & recent steps (A-20)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def list_workspace_agent_profiles(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_agent_profiles_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[AgentProfileService, Depends(_resolve_agent_profile_service)],
        response: Response,
    ) -> WorkspaceAgentProfilesResponse:
        dto = await svc.list_workspace_agent_profiles(access=ws_ctx)
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return dto

    @router.get(
        "/workspaces/{ws}/agent-profiles/{profile_id}",
        operation_id="getWorkspaceAgentProfile",
        tags=["agents"],
        response_model=AgentProfile,
        summary="Get a workspace agent profile by ID or role_key (A-20)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def get_workspace_agent_profile(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_agent_profiles_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[AgentProfileService, Depends(_resolve_agent_profile_service)],
        response: Response,
        profile_id: Annotated[str, Path(min_length=1, max_length=64)],
    ) -> AgentProfile:
        dto = await svc.get_workspace_agent_profile(access=ws_ctx, profile_id=profile_id)
        response.headers["ETag"] = format_version_etag(dto.version)
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return dto

    @router.patch(
        "/workspaces/{ws}/agent-profiles/{profile_id}",
        operation_id="updateWorkspaceAgentProfile",
        tags=["agents"],
        response_model=AgentProfileUpdateResponse,
        summary="Update bounded workspace agent profile within immutable S-20 ceilings (A-20)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def update_workspace_agent_profile(
        payload: AgentProfileUpdateRequest,
        request: Request,
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_agent_profiles_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[AgentProfileService, Depends(_resolve_agent_profile_service)],
        profile_id: Annotated[str, Path(min_length=1, max_length=64)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
        if_match: Annotated[
            str | None,
            Header(alias="If-Match", max_length=64),
        ] = None,
    ) -> AgentProfileUpdateResponse:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label="PATCH /api/v1/workspaces/{ws}/agent-profiles/{profile_id}",
        )
        updated = await svc.update_workspace_agent_profile(
            access=ws_ctx,
            profile_id=profile_id,
            payload=payload,
            idempotency_key=idem,
            if_match=if_match,
            correlation_id=_req_corr_id(request),
            client_ip=extract_client_ip(request),
        )
        response.headers["ETag"] = format_version_etag(updated.profile.version)
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return updated

    return router


__all__ = ["build_inference_router"]
