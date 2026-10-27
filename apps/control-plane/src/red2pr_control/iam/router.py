"""FastAPI /api/v1 IAM, bootstrap claim, session, CSRF, MFA & recovery routes (A-01..A-03).

Mounted under `/api/v1` (`setup`, `auth`, `me`):
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
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, Depends, Path, Request, Response, status

from py_contracts.iam import (
    CsrfBootstrapResponse,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
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
)
from py_contracts.primitives import InternalId, Problem
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
from red2pr_control.iam.sessions import (
    AuthenticatedContext,
    IamService,
    clear_session_cookie,
    extract_client_ip,
    extract_session_cookie,
    set_session_cookie,
    summarize_user_agent,
)

_PROBLEM_RESPONSES: dict[int | str, dict[str, object]] = {
    400: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    401: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    403: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    404: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    409: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    410: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
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


def get_iam_service(request: Request) -> IamService:
    """Resolve `IamService` bound to `app.state.iam_service` or fail closed with 503."""
    svc = getattr(request.app.state, "iam_service", None)
    if not isinstance(svc, IamService):
        raise DependencyUnavailableError(
            code="iam_unconfigured",
            detail="IAM persistence service is not configured on this control-plane instance.",
        )
    return svc


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
    """Authenticate opaque session cookie for read-only `/me` endpoints."""
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


def build_iam_router() -> APIRouter:
    """Create the `/api/v1` IAM router covering A-01 (claim), A-02 (auth), and A-03 (me)."""
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
        if ctx.csrf_cookie_refreshed:
            set_csrf_cookie(response, csrf_token=ctx.csrf_token, secure=iam.secure_cookies)
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
        if ctx.csrf_cookie_refreshed:
            set_csrf_cookie(response, csrf_token=ctx.csrf_token, secure=iam.secure_cookies)
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

    return router
