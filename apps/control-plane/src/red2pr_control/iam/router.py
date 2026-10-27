"""FastAPI /api/v1 IAM, workspace RBAC, memberships, invitations & SSE routes (U05..U06).

Mounted under `/api/v1`:
- `GET    /api/v1/auth/csrf`
- `POST   /api/v1/setup/claim`
- `POST   /api/v1/auth/login`
- `POST   /api/v1/auth/logout`
- `POST   /api/v1/auth/step-up`
- `POST   /api/v1/auth/recovery`
- `GET    /api/v1/me`
- `GET    /api/v1/me/sessions`
- `DELETE /api/v1/me/sessions/{session_id}`
- `POST   /api/v1/me/mfa`
- `DELETE /api/v1/me/mfa`
- `GET    /api/v1/workspaces`
- `POST   /api/v1/workspaces`
- `GET    /api/v1/workspaces/{ws}`
- `PATCH  /api/v1/workspaces/{ws}`
- `DELETE /api/v1/workspaces/{ws}`
- `GET    /api/v1/workspaces/{ws}/break-glass`
- `POST   /api/v1/workspaces/{ws}/break-glass`
- `DELETE /api/v1/workspaces/{ws}/break-glass/{grant_id}`
- `GET    /api/v1/workspaces/{ws}/members`
- `PATCH  /api/v1/workspaces/{ws}/members/{member_id}`
- `DELETE /api/v1/workspaces/{ws}/members/{member_id}`
- `GET    /api/v1/workspaces/{ws}/invitations`
- `POST   /api/v1/workspaces/{ws}/invitations`
- `DELETE /api/v1/workspaces/{ws}/invitations/{invite_id}`
- `POST   /api/v1/invitations/accept`
- `GET    /api/v1/workspaces/{ws}/events`
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, Depends, Header, Path, Query, Request, Response, status
from fastapi.responses import StreamingResponse

from py_contracts.events import EventType
from py_contracts.iam import (
    BreakGlassCreateRequest,
    BreakGlassGrant,
    BreakGlassGrantPage,
    CsrfBootstrapResponse,
    InviteAcceptRequest,
    InviteCreateRequest,
    InviteCreateResponse,
    InvitePage,
    InviteStatus,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    Membership,
    MembershipPage,
    MemberUpdateRequest,
    MeResponse,
    MfaDeleteRequest,
    MfaEnrollRequest,
    MfaEnrollResponse,
    RecoveryRequest,
    RecoveryResponse,
    SessionPage,
    SetupClaimRequest,
    SetupClaimResponse,
    StepUpRequest,
    StepUpResponse,
    Workspace,
    WorkspaceCreateRequest,
    WorkspaceDeleteRequest,
    WorkspacePage,
    WorkspaceRole,
    WorkspaceUpdateRequest,
)
from py_contracts.primitives import ActionReceipt, InternalId, Problem
from red2pr_control.core.errors import (
    PROBLEM_JSON_MEDIA_TYPE,
    DependencyUnavailableError,
    ForbiddenError,
)
from red2pr_control.core.logging import current_correlation_id
from red2pr_control.iam.csrf import (
    clear_csrf_cookie,
    set_csrf_cookie,
    validate_double_submit_csrf,
)
from red2pr_control.iam.invitations import MemberInviteService
from red2pr_control.iam.rbac import (
    ADMIN_ONLY_ROLES,
    ADMIN_OR_AUDITOR_ROLES,
    ALL_WORKSPACE_ROLES,
    WorkspaceAccessContext,
    authorize_workspace_access,
    format_version_etag,
    make_workspace_rbac_dependency,
)
from red2pr_control.iam.sessions import (
    AuthenticatedContext,
    IamService,
    clear_session_cookie,
    extract_client_ip,
    extract_session_cookie,
    set_session_cookie,
    summarize_user_agent,
)
from red2pr_control.iam.sse import (
    SSE_MEDIA_TYPE,
    WorkspaceSseService,
    assert_no_bearer_token_on_sse,
)
from red2pr_control.iam.workspaces import WorkspaceService, to_workspace_dto

_PROBLEM_RESPONSES: dict[int | str, dict[str, object]] = {
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


_EMPTY_LOGOUT_REQUEST = LogoutRequest()
_EMPTY_MFA_ENROLL_REQUEST = MfaEnrollRequest()


def _correlation_id(request: Request) -> str:
    state_corr = getattr(request.state, "correlation_id", None)
    if isinstance(state_corr, str) and state_corr:
        return state_corr
    return current_correlation_id()


def _apply_no_store_headers(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _maybe_refresh_csrf_cookie(
    response: Response,
    *,
    ctx: AuthenticatedContext,
    iam: IamService,
) -> None:
    if ctx.csrf_cookie_refreshed:
        set_csrf_cookie(response, csrf_token=ctx.csrf_token, secure=iam.secure_cookies)


def get_iam_service(request: Request) -> IamService:
    """Resolve `IamService` bound to `app.state.iam_service` or fail closed with 503."""
    svc = getattr(request.app.state, "iam_service", None)
    if not isinstance(svc, IamService):
        raise DependencyUnavailableError(
            code="iam_unconfigured",
            detail="IAM persistence service is not configured on this control-plane instance.",
        )
    return svc


def _workspace_service(iam: IamService) -> WorkspaceService:
    return WorkspaceService(
        session_factory=iam.session_factory,
        signing_key=iam.csrf_signing_key,
    )


def _member_invite_service(iam: IamService) -> MemberInviteService:
    return MemberInviteService(
        session_factory=iam.session_factory,
        signing_key=iam.csrf_signing_key,
    )


def _workspace_sse_service(iam: IamService) -> WorkspaceSseService:
    return WorkspaceSseService(
        session_factory=iam.session_factory,
        signing_key=iam.csrf_signing_key,
        cursor_ttl=iam.sse_cursor_ttl,
        poll_interval_seconds=iam.sse_poll_interval_seconds,
        heartbeat_interval_seconds=iam.sse_heartbeat_interval_seconds,
    )


async def _enforce_preauth_csrf(request: Request, iam: IamService) -> None:
    corr_id = _correlation_id(request)
    client_ip = extract_client_ip(request)
    try:
        validate_double_submit_csrf(
            request,
            public_base_url=iam.public_base_url,
            signing_key=iam.csrf_signing_key,
        )
    except ForbiddenError as exc:
        await iam.record_csrf_denial(
            code=exc.code,
            target_path=request.url.path,
            client_ip=client_ip,
            correlation_id=corr_id,
        )
        raise


async def require_authenticated_read(
    request: Request,
    iam: Annotated[IamService, Depends(get_iam_service)],
) -> AuthenticatedContext:
    """Authenticate opaque session cookie for read-only endpoints."""
    return await iam.authenticate_request(
        request,
        require_csrf=False,
        correlation_id=_correlation_id(request),
    )


async def require_authenticated_mutation(
    request: Request,
    iam: Annotated[IamService, Depends(get_iam_service)],
) -> AuthenticatedContext:
    """Authenticate opaque session cookie + Origin + synchronizer/double-submit CSRF."""
    return await iam.authenticate_request(
        request,
        require_csrf=True,
        correlation_id=_correlation_id(request),
    )


_require_ws_read = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="workspace.read",
)
_require_ws_update = make_workspace_rbac_dependency(
    allowed_roles=ADMIN_ONLY_ROLES,
    require_csrf=True,
    allow_break_glass=False,
    action="workspace.update",
)
_require_ws_break_glass_list = make_workspace_rbac_dependency(
    allowed_roles=ADMIN_OR_AUDITOR_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="workspace.break_glass_list",
)
_require_ws_break_glass_revoke = make_workspace_rbac_dependency(
    allowed_roles=ADMIN_ONLY_ROLES,
    require_csrf=True,
    allow_break_glass=True,
    action="workspace.break_glass_revoke",
)
_require_ws_members_list = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="workspace.members_list",
)
_require_ws_member_update = make_workspace_rbac_dependency(
    allowed_roles=ADMIN_ONLY_ROLES,
    require_csrf=True,
    allow_break_glass=False,
    action="workspace.member_update",
)
_require_ws_member_remove = make_workspace_rbac_dependency(
    allowed_roles=ADMIN_ONLY_ROLES,
    require_csrf=True,
    allow_break_glass=False,
    action="workspace.member_remove",
)
_require_ws_invitations_list = make_workspace_rbac_dependency(
    allowed_roles=ADMIN_OR_AUDITOR_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="workspace.invitations_list",
)
_require_ws_invitation_create = make_workspace_rbac_dependency(
    allowed_roles=ADMIN_ONLY_ROLES,
    require_csrf=True,
    allow_break_glass=False,
    action="workspace.invitation_create",
)
_require_ws_invitation_revoke = make_workspace_rbac_dependency(
    allowed_roles=ADMIN_ONLY_ROLES,
    require_csrf=True,
    allow_break_glass=False,
    action="workspace.invitation_revoke",
)


async def _require_ws_sse_access(
    ws: Annotated[str, Path(min_length=1, max_length=120)],
    request: Request,
    iam: Annotated[IamService, Depends(get_iam_service)],
) -> WorkspaceAccessContext:
    """Enforce cookie-only SSE rule (`400` on bearer token) before cookie auth + RBAC (`A-21`)."""
    assert_no_bearer_token_on_sse(request)
    corr_id = _correlation_id(request)
    auth = await iam.authenticate_request(
        request,
        require_csrf=False,
        correlation_id=corr_id,
    )
    return await authorize_workspace_access(
        iam.session_factory,
        auth=auth,
        raw_ws=ws,
        allowed_roles=ALL_WORKSPACE_ROLES,
        allow_break_glass=True,
        action="sse.subscribe",
        client_ip=extract_client_ip(request),
        correlation_id=corr_id,
        now=iam.now(),
    )


def build_iam_router() -> APIRouter:
    """Create the `/api/v1` IAM, Workspace, Membership, Invitation & SSE router."""
    router = APIRouter(prefix="/api/v1")

    @router.get(
        "/auth/csrf",
        operation_id="getAuthCsrf",
        tags=["auth"],
        response_model=CsrfBootstrapResponse,
        summary="Issue pre-auth or session CSRF token and check unclaimed bootstrap status",
        responses=_PROBLEM_RESPONSES,
    )
    async def get_auth_csrf(
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> CsrfBootstrapResponse:
        _apply_no_store_headers(response)
        boot = await iam.get_csrf_bootstrap(request)
        set_csrf_cookie(response, csrf_token=boot.csrf_token, secure=iam.secure_cookies)
        return boot

    @router.post(
        "/setup/claim",
        operation_id="claimInstanceOwner",
        tags=["setup"],
        status_code=status.HTTP_201_CREATED,
        response_model=SetupClaimResponse,
        summary="Claim initial instance_owner account using one-time bootstrap token (A-01)",
        responses=_PROBLEM_RESPONSES,
    )
    async def claim_instance_owner(
        payload: SetupClaimRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> SetupClaimResponse:
        _apply_no_store_headers(response)
        await _enforce_preauth_csrf(request, iam)
        dto, raw_sess_token = await iam.claim_bootstrap_owner(
            payload,
            client_ip=extract_client_ip(request),
            user_agent=summarize_user_agent(request),
            request_scheme=request.url.scheme,
            correlation_id=_correlation_id(request),
        )
        set_session_cookie(
            response,
            raw_session_token=raw_sess_token,
            secure=iam.secure_cookies,
        )
        set_csrf_cookie(response, csrf_token=dto.csrf_token, secure=iam.secure_cookies)
        return dto

    @router.post(
        "/auth/login",
        operation_id="loginLocal",
        tags=["auth"],
        response_model=LoginResponse,
        summary="Authenticate local credentials with optional TOTP MFA challenge (A-02)",
        responses=_PROBLEM_RESPONSES,
    )
    async def login_local(
        payload: LoginRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> LoginResponse:
        _apply_no_store_headers(response)
        await _enforce_preauth_csrf(request, iam)
        existing_cookie = extract_session_cookie(request, secure=iam.secure_cookies)
        dto, raw_sess_token = await iam.login(
            payload,
            existing_session_cookie=existing_cookie,
            client_ip=extract_client_ip(request),
            user_agent=summarize_user_agent(request),
            correlation_id=_correlation_id(request),
        )
        if dto.status == "mfa_required" or raw_sess_token is None:
            # MFA-pending state NEVER issues a session cookie; clear any stale cookie.
            if existing_cookie:
                clear_session_cookie(response, secure=iam.secure_cookies)
            return dto

        assert dto.csrf_token is not None
        set_session_cookie(
            response,
            raw_session_token=raw_sess_token,
            secure=iam.secure_cookies,
        )
        set_csrf_cookie(response, csrf_token=dto.csrf_token, secure=iam.secure_cookies)
        return dto

    @router.post(
        "/auth/logout",
        operation_id="logoutLocal",
        tags=["auth"],
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Revoke active session and clear authentication cookies (A-02)",
        responses=_PROBLEM_RESPONSES,
    )
    async def logout_local(
        request: Request,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ctx: Annotated[AuthenticatedContext, Depends(require_authenticated_mutation)],
        _payload: Annotated[LogoutRequest, Body()] = _EMPTY_LOGOUT_REQUEST,
    ) -> Response:
        await iam.logout(
            ctx,
            client_ip=extract_client_ip(request),
            correlation_id=_correlation_id(request),
        )
        resp = Response(status_code=status.HTTP_204_NO_CONTENT)
        _apply_no_store_headers(resp)
        clear_session_cookie(resp, secure=iam.secure_cookies)
        clear_csrf_cookie(resp, secure=iam.secure_cookies)
        return resp

    @router.post(
        "/auth/step-up",
        operation_id="stepUpSession",
        tags=["auth"],
        response_model=StepUpResponse,
        summary="Verify password (+ TOTP if enrolled) for 5-minute privileged step-up (A-02)",
        responses=_PROBLEM_RESPONSES,
    )
    async def step_up_session(
        payload: StepUpRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ctx: Annotated[AuthenticatedContext, Depends(require_authenticated_mutation)],
    ) -> StepUpResponse:
        _apply_no_store_headers(response)
        dto, raw_sess_token = await iam.step_up(
            ctx,
            payload,
            client_ip=extract_client_ip(request),
            user_agent=summarize_user_agent(request),
            correlation_id=_correlation_id(request),
        )
        set_session_cookie(
            response,
            raw_session_token=raw_sess_token,
            secure=iam.secure_cookies,
        )
        set_csrf_cookie(response, csrf_token=dto.csrf_token, secure=iam.secure_cookies)
        return dto

    @router.post(
        "/auth/recovery",
        operation_id="recoverAccount",
        tags=["auth"],
        response_model=RecoveryResponse,
        summary="Redeem single-use recovery code to reset password, MFA & sessions (A-02)",
        responses=_PROBLEM_RESPONSES,
    )
    async def recover_account(
        payload: RecoveryRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> RecoveryResponse:
        _apply_no_store_headers(response)
        await _enforce_preauth_csrf(request, iam)
        dto, raw_sess_token = await iam.recover_account(
            payload,
            client_ip=extract_client_ip(request),
            user_agent=summarize_user_agent(request),
            correlation_id=_correlation_id(request),
        )
        set_session_cookie(
            response,
            raw_session_token=raw_sess_token,
            secure=iam.secure_cookies,
        )
        set_csrf_cookie(response, csrf_token=dto.csrf_token, secure=iam.secure_cookies)
        return dto

    @router.get(
        "/me",
        operation_id="getMe",
        tags=["account"],
        response_model=MeResponse,
        summary="Get current user profile, session metadata, MFA posture & grants (A-03)",
        responses=_PROBLEM_RESPONSES,
    )
    async def get_me(
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ctx: Annotated[AuthenticatedContext, Depends(require_authenticated_read)],
    ) -> MeResponse:
        _apply_no_store_headers(response)
        _maybe_refresh_csrf_cookie(response, ctx=ctx, iam=iam)
        return await iam.get_me(ctx)

    @router.get(
        "/me/sessions",
        operation_id="listMySessions",
        tags=["account"],
        response_model=SessionPage,
        summary="List active sessions for current principal without raw tokens (A-03)",
        responses=_PROBLEM_RESPONSES,
    )
    async def list_my_sessions(
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ctx: Annotated[AuthenticatedContext, Depends(require_authenticated_read)],
    ) -> SessionPage:
        _apply_no_store_headers(response)
        _maybe_refresh_csrf_cookie(response, ctx=ctx, iam=iam)
        return await iam.list_my_sessions(ctx)

    @router.delete(
        "/me/sessions/{session_id}",
        operation_id="revokeMySession",
        tags=["account"],
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Revoke one of the caller's active sessions (A-03)",
        responses=_PROBLEM_RESPONSES,
    )
    async def revoke_my_session(
        session_id: Annotated[InternalId, Path()],
        request: Request,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ctx: Annotated[AuthenticatedContext, Depends(require_authenticated_mutation)],
    ) -> Response:
        revoked_current = await iam.revoke_my_session(
            ctx,
            session_id=session_id,
            client_ip=extract_client_ip(request),
            correlation_id=_correlation_id(request),
        )
        resp = Response(status_code=status.HTTP_204_NO_CONTENT)
        _apply_no_store_headers(resp)
        if revoked_current:
            clear_session_cookie(resp, secure=iam.secure_cookies)
            clear_csrf_cookie(resp, secure=iam.secure_cookies)
        return resp

    @router.post(
        "/me/mfa",
        operation_id="enrollMyMfa",
        tags=["account"],
        response_model=MfaEnrollResponse,
        summary="Start (`{}`) or confirm (`{challenge_id, otp}`) TOTP MFA enrollment (A-03)",
        responses=_PROBLEM_RESPONSES,
    )
    async def enroll_my_mfa(
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ctx: Annotated[AuthenticatedContext, Depends(require_authenticated_mutation)],
        payload: Annotated[MfaEnrollRequest, Body()] = _EMPTY_MFA_ENROLL_REQUEST,
    ) -> MfaEnrollResponse:
        _apply_no_store_headers(response)
        dto, raw_sess_token = await iam.enroll_mfa(
            ctx,
            payload,
            client_ip=extract_client_ip(request),
            user_agent=summarize_user_agent(request),
            correlation_id=_correlation_id(request),
        )
        if raw_sess_token is not None and dto.csrf_token is not None:
            set_session_cookie(
                response,
                raw_session_token=raw_sess_token,
                secure=iam.secure_cookies,
            )
            set_csrf_cookie(response, csrf_token=dto.csrf_token, secure=iam.secure_cookies)
        return dto

    @router.delete(
        "/me/mfa",
        operation_id="deleteMyMfa",
        tags=["account"],
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Disable optional MFA with step-up + recovery code (no mandatory bypass) (A-03)",
        responses=_PROBLEM_RESPONSES,
    )
    async def delete_my_mfa(
        payload: MfaDeleteRequest,
        request: Request,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ctx: Annotated[AuthenticatedContext, Depends(require_authenticated_mutation)],
    ) -> Response:
        raw_sess_token, raw_csrf_token = await iam.delete_mfa(
            ctx,
            payload,
            client_ip=extract_client_ip(request),
            user_agent=summarize_user_agent(request),
            correlation_id=_correlation_id(request),
        )
        resp = Response(status_code=status.HTTP_204_NO_CONTENT)
        _apply_no_store_headers(resp)
        set_session_cookie(
            resp,
            raw_session_token=raw_sess_token,
            secure=iam.secure_cookies,
        )
        set_csrf_cookie(resp, csrf_token=raw_csrf_token, secure=iam.secure_cookies)
        return resp

    # ------------------------------------------------------------------
    # U06 — Multi-Workspace Lifecycle & Break-Glass (A-04, ADR-030, ADR-034)
    # ------------------------------------------------------------------

    @router.get(
        "/workspaces",
        operation_id="listWorkspaces",
        tags=["workspaces"],
        response_model=WorkspacePage,
        summary="List workspaces where caller holds membership or active break-glass grant (A-04)",
        responses=_PROBLEM_RESPONSES,
    )
    async def list_workspaces(
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ctx: Annotated[AuthenticatedContext, Depends(require_authenticated_read)],
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> WorkspacePage:
        _apply_no_store_headers(response)
        _maybe_refresh_csrf_cookie(response, ctx=ctx, iam=iam)
        return await _workspace_service(iam).list_workspaces(
            ctx,
            cursor=cursor,
            limit=limit,
            now=iam.now(),
        )

    @router.post(
        "/workspaces",
        operation_id="createWorkspace",
        tags=["workspaces"],
        status_code=status.HTTP_201_CREATED,
        response_model=Workspace,
        summary="Create a new workspace (`instance_owner` only) with initial admin member (A-04)",
        responses=_PROBLEM_RESPONSES,
    )
    async def create_workspace(
        payload: WorkspaceCreateRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ctx: Annotated[AuthenticatedContext, Depends(require_authenticated_mutation)],
    ) -> Workspace:
        _apply_no_store_headers(response)
        _maybe_refresh_csrf_cookie(response, ctx=ctx, iam=iam)
        dto = await _workspace_service(iam).create_workspace(
            ctx,
            payload,
            client_ip=extract_client_ip(request),
            correlation_id=_correlation_id(request),
            now=iam.now(),
        )
        response.headers["ETag"] = format_version_etag(dto.version)
        return dto

    @router.get(
        "/workspaces/{ws}",
        operation_id="getWorkspace",
        tags=["workspaces"],
        response_model=Workspace,
        summary="Get workspace metadata for authorized members or active break-glass (A-04)",
        responses=_PROBLEM_RESPONSES,
    )
    async def get_workspace(
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_ws_read)],
    ) -> Workspace:
        _apply_no_store_headers(response)
        _maybe_refresh_csrf_cookie(response, ctx=ws_ctx.auth, iam=iam)
        dto = to_workspace_dto(ws_ctx.workspace)
        response.headers["ETag"] = format_version_etag(dto.version)
        return dto

    @router.patch(
        "/workspaces/{ws}",
        operation_id="updateWorkspace",
        tags=["workspaces"],
        response_model=Workspace,
        summary="Update workspace settings (`admin` only) with If-Match concurrency (A-04)",
        responses=_PROBLEM_RESPONSES,
    )
    async def update_workspace(
        payload: WorkspaceUpdateRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_ws_update)],
        if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    ) -> Workspace:
        _apply_no_store_headers(response)
        _maybe_refresh_csrf_cookie(response, ctx=ws_ctx.auth, iam=iam)
        dto = await _workspace_service(iam).update_workspace(
            ws_ctx,
            payload,
            if_match_header=if_match,
            client_ip=extract_client_ip(request),
            correlation_id=_correlation_id(request),
            now=iam.now(),
        )
        response.headers["ETag"] = format_version_etag(dto.version)
        return dto

    @router.delete(
        "/workspaces/{ws}",
        operation_id="deleteWorkspace",
        tags=["workspaces"],
        status_code=status.HTTP_202_ACCEPTED,
        response_model=ActionReceipt,
        summary="Freeze, revoke grants & tombstone workspace (owner + step-up + Idempotency-Key)",
        responses=_PROBLEM_RESPONSES,
    )
    async def delete_workspace(
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        payload: WorkspaceDeleteRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ctx: Annotated[AuthenticatedContext, Depends(require_authenticated_mutation)],
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> ActionReceipt:
        _apply_no_store_headers(response)
        _maybe_refresh_csrf_cookie(response, ctx=ctx, iam=iam)
        return await _workspace_service(iam).delete_workspace(
            ctx,
            raw_ws=ws,
            payload=payload,
            idempotency_key=idempotency_key,
            client_ip=extract_client_ip(request),
            correlation_id=_correlation_id(request),
            now=iam.now(),
        )

    @router.get(
        "/workspaces/{ws}/break-glass",
        operation_id="listBreakGlassGrants",
        tags=["workspaces"],
        response_model=BreakGlassGrantPage,
        summary="List temporary owner break-glass grants for workspace admin/auditor (ADR-034)",
        responses=_PROBLEM_RESPONSES,
    )
    async def list_break_glass_grants(
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_ws_break_glass_list)],
    ) -> BreakGlassGrantPage:
        _apply_no_store_headers(response)
        _maybe_refresh_csrf_cookie(response, ctx=ws_ctx.auth, iam=iam)
        return await _workspace_service(iam).list_break_glass_grants(
            ws_ctx,
            now=iam.now(),
        )

    @router.post(
        "/workspaces/{ws}/break-glass",
        operation_id="createBreakGlassGrant",
        tags=["workspaces"],
        status_code=status.HTTP_201_CREATED,
        response_model=BreakGlassGrant,
        summary="Issue temporary audited read-only break-glass grant (owner + step-up) (ADR-034)",
        responses=_PROBLEM_RESPONSES,
    )
    async def create_break_glass_grant(
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        payload: BreakGlassCreateRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ctx: Annotated[AuthenticatedContext, Depends(require_authenticated_mutation)],
    ) -> BreakGlassGrant:
        _apply_no_store_headers(response)
        _maybe_refresh_csrf_cookie(response, ctx=ctx, iam=iam)
        return await _workspace_service(iam).create_break_glass_grant(
            ctx,
            raw_ws=ws,
            payload=payload,
            client_ip=extract_client_ip(request),
            correlation_id=_correlation_id(request),
            now=iam.now(),
        )

    @router.delete(
        "/workspaces/{ws}/break-glass/{grant_id}",
        operation_id="revokeBreakGlassGrant",
        tags=["workspaces"],
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Immediately revoke a workspace break-glass grant (ADR-034)",
        responses=_PROBLEM_RESPONSES,
    )
    async def revoke_break_glass_grant(
        grant_id: Annotated[InternalId, Path()],
        request: Request,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_ws_break_glass_revoke)],
    ) -> Response:
        await _workspace_service(iam).revoke_break_glass_grant(
            ws_ctx,
            grant_id=grant_id,
            client_ip=extract_client_ip(request),
            correlation_id=_correlation_id(request),
            now=iam.now(),
        )
        resp = Response(status_code=status.HTTP_204_NO_CONTENT)
        _apply_no_store_headers(resp)
        _maybe_refresh_csrf_cookie(resp, ctx=ws_ctx.auth, iam=iam)
        return resp

    # ------------------------------------------------------------------
    # U06 — Memberships, Repo Grants & Single-Use Invitations (A-05, SEC-038)
    # ------------------------------------------------------------------

    @router.get(
        "/workspaces/{ws}/members",
        operation_id="listWorkspaceMembers",
        tags=["members"],
        response_model=MembershipPage,
        summary="List workspace members and scoped repository grants (A-05)",
        responses=_PROBLEM_RESPONSES,
    )
    async def list_workspace_members(
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_ws_members_list)],
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        role: Annotated[WorkspaceRole | None, Query()] = None,
    ) -> MembershipPage:
        _apply_no_store_headers(response)
        _maybe_refresh_csrf_cookie(response, ctx=ws_ctx.auth, iam=iam)
        return await _member_invite_service(iam).list_members(
            ws_ctx,
            cursor=cursor,
            limit=limit,
            role_filter=role,
            now=iam.now(),
        )

    @router.patch(
        "/workspaces/{ws}/members/{member_id}",
        operation_id="updateWorkspaceMember",
        tags=["members"],
        response_model=Membership,
        summary="Update member role & repository grants (`admin` only, `409 last_admin`) (A-05)",
        responses=_PROBLEM_RESPONSES,
    )
    async def update_workspace_member(
        member_id: Annotated[InternalId, Path()],
        payload: MemberUpdateRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_ws_member_update)],
        if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    ) -> Membership:
        _apply_no_store_headers(response)
        _maybe_refresh_csrf_cookie(response, ctx=ws_ctx.auth, iam=iam)
        dto = await _member_invite_service(iam).update_member(
            ws_ctx,
            member_id=member_id,
            payload=payload,
            if_match_header=if_match,
            client_ip=extract_client_ip(request),
            correlation_id=_correlation_id(request),
            now=iam.now(),
        )
        response.headers["ETag"] = format_version_etag(dto.version)
        return dto

    @router.delete(
        "/workspaces/{ws}/members/{member_id}",
        operation_id="removeWorkspaceMember",
        tags=["members"],
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Remove workspace member (`admin` only, `409 last_admin`) (A-05)",
        responses=_PROBLEM_RESPONSES,
    )
    async def remove_workspace_member(
        member_id: Annotated[InternalId, Path()],
        request: Request,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_ws_member_remove)],
    ) -> Response:
        await _member_invite_service(iam).delete_member(
            ws_ctx,
            member_id=member_id,
            client_ip=extract_client_ip(request),
            correlation_id=_correlation_id(request),
            now=iam.now(),
        )
        resp = Response(status_code=status.HTTP_204_NO_CONTENT)
        _apply_no_store_headers(resp)
        _maybe_refresh_csrf_cookie(resp, ctx=ws_ctx.auth, iam=iam)
        return resp

    @router.get(
        "/workspaces/{ws}/invitations",
        operation_id="listWorkspaceInvitations",
        tags=["invitations"],
        response_model=InvitePage,
        summary="List workspace invitations without raw tokens (`admin`/`auditor`) (A-05)",
        responses=_PROBLEM_RESPONSES,
    )
    async def list_workspace_invitations(
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_ws_invitations_list)],
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        status_filter: Annotated[InviteStatus | None, Query(alias="status")] = None,
    ) -> InvitePage:
        _apply_no_store_headers(response)
        _maybe_refresh_csrf_cookie(response, ctx=ws_ctx.auth, iam=iam)
        return await _member_invite_service(iam).list_invitations(
            ws_ctx,
            cursor=cursor,
            limit=limit,
            status_filter=status_filter,
            now=iam.now(),
        )

    @router.post(
        "/workspaces/{ws}/invitations",
        operation_id="createWorkspaceInvitation",
        tags=["invitations"],
        status_code=status.HTTP_201_CREATED,
        response_model=InviteCreateResponse,
        summary="Create single-use email-bound workspace invitation (token returned once) (A-05)",
        responses=_PROBLEM_RESPONSES,
    )
    async def create_workspace_invitation(
        payload: InviteCreateRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_ws_invitation_create)],
    ) -> InviteCreateResponse:
        _apply_no_store_headers(response)
        _maybe_refresh_csrf_cookie(response, ctx=ws_ctx.auth, iam=iam)
        return await _member_invite_service(iam).create_invitation(
            ws_ctx,
            payload,
            client_ip=extract_client_ip(request),
            correlation_id=_correlation_id(request),
            now=iam.now(),
        )

    @router.delete(
        "/workspaces/{ws}/invitations/{invite_id}",
        operation_id="revokeWorkspaceInvitation",
        tags=["invitations"],
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Revoke a pending workspace invitation (`admin` only) (A-05)",
        responses=_PROBLEM_RESPONSES,
    )
    async def revoke_workspace_invitation(
        invite_id: Annotated[InternalId, Path()],
        request: Request,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_ws_invitation_revoke)],
    ) -> Response:
        await _member_invite_service(iam).revoke_invitation(
            ws_ctx,
            invite_id=invite_id,
            client_ip=extract_client_ip(request),
            correlation_id=_correlation_id(request),
            now=iam.now(),
        )
        resp = Response(status_code=status.HTTP_204_NO_CONTENT)
        _apply_no_store_headers(resp)
        _maybe_refresh_csrf_cookie(resp, ctx=ws_ctx.auth, iam=iam)
        return resp

    @router.post(
        "/invitations/accept",
        operation_id="acceptWorkspaceInvitation",
        tags=["invitations"],
        response_model=Membership,
        summary="Redeem single-use email-bound workspace invitation token (A-05, SEC-038)",
        responses=_PROBLEM_RESPONSES,
    )
    async def accept_workspace_invitation(
        payload: InviteAcceptRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ctx: Annotated[AuthenticatedContext, Depends(require_authenticated_mutation)],
    ) -> Membership:
        _apply_no_store_headers(response)
        _maybe_refresh_csrf_cookie(response, ctx=ctx, iam=iam)
        dto = await _member_invite_service(iam).accept_invitation(
            ctx,
            payload,
            client_ip=extract_client_ip(request),
            correlation_id=_correlation_id(request),
            now=iam.now(),
        )
        response.headers["ETag"] = format_version_etag(dto.version)
        return dto

    # ------------------------------------------------------------------
    # U06 — Workspace Server-Sent Events Stream (A-21, S-19, NFR-04)
    # ------------------------------------------------------------------

    @router.get(
        "/workspaces/{ws}/events",
        operation_id="streamWorkspaceEvents",
        tags=["events"],
        response_class=StreamingResponse,
        summary="Stream workspace-scoped S-19 events over cookie-authenticated SSE (A-21)",
        responses={
            200: {
                "description": "Live text/event-stream of workspace S-19 EventEnvelope frames.",
                "content": {SSE_MEDIA_TYPE: {"schema": {"type": "string"}}},
            },
            **_PROBLEM_RESPONSES,
        },
    )
    async def stream_workspace_events(
        request: Request,
        iam: Annotated[IamService, Depends(get_iam_service)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_ws_sse_access)],
        last_event_id_header: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
        last_event_id_query: Annotated[
            str | None,
            Query(alias="last_event_id", max_length=512),
        ] = None,
        repository_id: Annotated[InternalId | None, Query()] = None,
        event_type: Annotated[EventType | None, Query()] = None,
        max_events: Annotated[int | None, Query(ge=1, le=500, include_in_schema=False)] = None,
        max_duration_seconds: Annotated[
            float | None,
            Query(ge=0.05, le=60.0, include_in_schema=False),
        ] = None,
    ) -> StreamingResponse:
        effective_cursor = last_event_id_header or last_event_id_query
        resp = await _workspace_sse_service(iam).open_workspace_stream(
            request,
            ws_ctx,
            last_event_id=effective_cursor,
            repository_id_filter=repository_id,
            event_type_filter=event_type,
            max_events=max_events,
            max_duration_seconds=max_duration_seconds,
            client_ip=extract_client_ip(request),
            correlation_id=_correlation_id(request),
            now_fn=iam.now,
        )
        _maybe_refresh_csrf_cookie(resp, ctx=ws_ctx.auth, iam=iam)
        return resp

    return router
