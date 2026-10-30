"""A-19 scoped, hashed, expiring API tokens with live issuer-grant enforcement."""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, cast

from fastapi import APIRouter, Depends, Path, Request, Response
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.iam import WorkspaceRole
from py_contracts.integrations import (
    ApiToken,
    ApiTokenCreateRequest,
    ApiTokenCreateResponse,
    ApiTokenScope,
)
from py_contracts.primitives import Page, new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
    UnprocessableEntityError,
)
from red2pr_control.core.logging import current_correlation_id
from red2pr_control.db.base import (
    ApiTokenModel,
    MembershipModel,
    RepositoryModel,
    UserModel,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.rbac import (
    WorkspaceAccessContext,
    compute_query_filter_hash,
    decode_signed_cursor,
    encode_signed_cursor,
    make_workspace_rbac_dependency,
)
from red2pr_control.iam.sessions import (
    IamService,
    extract_client_ip,
)

_TOKEN_RE = re.compile(r"^r2p_[A-Za-z0-9_-]{43}$")
_READ_ROLES: frozenset[WorkspaceRole] = frozenset(
    {"admin", "maintainer", "reviewer", "viewer", "auditor"}
)
_WRITE_ROLES: frozenset[WorkspaceRole] = frozenset({"admin", "maintainer"})
_READ = make_workspace_rbac_dependency(
    allowed_roles=_READ_ROLES,
    require_csrf=False,
    allow_break_glass=False,
    action="api_token.read",
)
_WRITE = make_workspace_rbac_dependency(
    allowed_roles=_WRITE_ROLES,
    require_csrf=True,
    allow_break_glass=False,
    action="api_token.manage",
)
_ROLE_SCOPES: dict[str, frozenset[str]] = {
    "admin": frozenset(
        {
            "notifications:read",
            "notifications:write",
            "repairs:read",
            "repairs:write",
            "integrations:read",
            "integrations:write",
            "events:read",
        }
    ),
    "maintainer": frozenset(
        {
            "notifications:read",
            "notifications:write",
            "repairs:read",
            "repairs:write",
            "integrations:read",
            "events:read",
        }
    ),
    "reviewer": frozenset(
        {"notifications:read", "repairs:read", "integrations:read", "events:read"}
    ),
    "viewer": frozenset({"notifications:read", "repairs:read", "integrations:read", "events:read"}),
    "auditor": frozenset(
        {"notifications:read", "repairs:read", "integrations:read", "events:read"}
    ),
}


def hash_api_token(raw_token: str) -> str:
    """Hash a high-entropy opaque token; plaintext is never persisted."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def token_scope_is_allowed(
    *, requested_scopes: set[str] | frozenset[str], issuer_scopes: set[str] | frozenset[str]
) -> bool:
    return bool(requested_scopes) and requested_scopes <= issuer_scopes


@dataclass(frozen=True, slots=True)
class ApiTokenAuthentication:
    id: str
    workspace_id: str
    owner_user_id: str
    scopes: frozenset[str]
    repository_ids: frozenset[str]
    grant_epoch: int
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ApiTokenSession:
    """Session-compatible marker without MFA or step-up authority."""

    id: str
    user_id: str
    auth_strength: str = "password"
    step_up_at: datetime | None = None
    grant_epoch: int = 1


async def authenticate_api_token(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    raw_token: str,
    now: datetime,
) -> tuple[UserModel, ApiTokenAuthentication]:
    if not _TOKEN_RE.fullmatch(raw_token):
        raise UnauthorizedError(code="invalid_api_token", detail="API token is invalid.")
    token_hash = hash_api_token(raw_token)
    ref_now = now.astimezone(UTC)
    async with instance_rls_session(session_factory, mode="instance_only") as db:
        row = await db.scalar(select(ApiTokenModel).where(ApiTokenModel.secret_hash == token_hash))
        if row is None or row.revoked_at is not None or row.expires_at.astimezone(UTC) <= ref_now:
            raise UnauthorizedError(code="invalid_api_token", detail="API token is invalid.")
        user = await db.scalar(select(UserModel).where(UserModel.id == row.user_id))
        if user is None or user.status != "active" or user.grant_epoch != row.grant_epoch:
            raise UnauthorizedError(
                code="api_token_issuer_revoked", detail="API token issuer grants changed."
            )
        workspace_id = row.workspace_id
        user_id = row.user_id
        token_id = row.id
        stored_scopes = frozenset(str(scope) for scope in row.scopes_json)
        repository_ids = frozenset(str(value) for value in row.repository_ids_json)
        grant_epoch = row.grant_epoch
        expires_at = row.expires_at.astimezone(UTC)
        db.expunge(user)

    # Membership RLS intentionally excludes instance_only. Recheck the issuer under
    # the token's workspace context so role downgrades/revocations take effect live.
    async with workspace_rls_session(session_factory, workspace_id=workspace_id) as db:
        membership = await db.scalar(
            select(MembershipModel).where(
                MembershipModel.workspace_id == workspace_id,
                MembershipModel.user_id == user_id,
            )
        )
        if membership is None or membership.role not in _ROLE_SCOPES:
            raise UnauthorizedError(
                code="api_token_issuer_revoked", detail="API token issuer membership was revoked."
            )
        live_scopes = _ROLE_SCOPES[membership.role]
        if not token_scope_is_allowed(requested_scopes=stored_scopes, issuer_scopes=live_scopes):
            raise UnauthorizedError(
                code="api_token_issuer_revoked", detail="API token rights exceed current rights."
            )
        live_token = await db.scalar(
            select(ApiTokenModel)
            .where(
                ApiTokenModel.workspace_id == workspace_id,
                ApiTokenModel.id == token_id,
                ApiTokenModel.revoked_at.is_(None),
                ApiTokenModel.expires_at > ref_now,
            )
            .with_for_update()
        )
        if live_token is None:
            raise UnauthorizedError(code="invalid_api_token", detail="API token is invalid.")
        if live_token.last_used_at is None or ref_now - live_token.last_used_at >= timedelta(
            minutes=1
        ):
            live_token.last_used_at = ref_now
        auth = ApiTokenAuthentication(
            id=token_id,
            workspace_id=workspace_id,
            owner_user_id=user_id,
            scopes=stored_scopes,
            repository_ids=repository_ids,
            grant_epoch=grant_epoch,
            expires_at=expires_at,
        )
        return user, auth


def _dto(row: ApiTokenModel) -> ApiToken:
    return ApiToken(
        id=row.id,
        workspace_id=row.workspace_id,
        version=1,
        created_at=row.created_at,
        updated_at=row.created_at,
        owner_user_id=row.user_id,
        name=row.name,
        scopes=cast(list[ApiTokenScope], list(row.scopes_json)),
        repository_ids=list(row.repository_ids_json),
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        last_used_at=row.last_used_at,
    )


def build_api_tokens_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["iam", "api-tokens"])

    @router.get("/workspaces/{ws}/api-tokens", response_model=Page[ApiToken])
    async def list_tokens(
        request: Request,
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
        limit: int = 25,
        cursor: str | None = None,
    ) -> Page[ApiToken]:
        if ctx.auth.api_token is not None:
            raise ForbiddenError(
                code="api_token_management_denied", detail="API tokens cannot manage API tokens."
            )
        if limit < 1 or limit > 100:
            raise UnprocessableEntityError(code="invalid_limit", detail="Limit must be 1..100.")
        iam = _iam(request)
        now = iam.now().astimezone(UTC)
        qh = compute_query_filter_hash({"endpoint": "api_tokens.list"})
        decoded = (
            decode_signed_cursor(
                cursor,
                signing_key=iam.csrf_signing_key,
                expected_workspace_scope=ctx.workspace_id,
                expected_principal_id=ctx.auth.user.id,
                current_grant_epoch=ctx.auth.user.grant_epoch,
                expected_query_hash=qh,
                now=now,
            )
            if cursor
            else None
        )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            query = select(ApiTokenModel).where(ApiTokenModel.workspace_id == ctx.workspace_id)
            if ctx.membership is None or ctx.membership.role != "admin":
                query = query.where(ApiTokenModel.user_id == ctx.auth.user.id)
            if decoded:
                query = query.where(
                    or_(
                        ApiTokenModel.created_at < decoded.created_at,
                        and_(
                            ApiTokenModel.created_at == decoded.created_at,
                            ApiTokenModel.id < decoded.item_id,
                        ),
                    )
                )
            rows = list(
                (
                    await db.scalars(
                        query.order_by(
                            ApiTokenModel.created_at.desc(), ApiTokenModel.id.desc()
                        ).limit(limit + 1)
                    )
                ).all()
            )
            visible = rows[:limit]
            next_cursor = (
                encode_signed_cursor(
                    signing_key=iam.csrf_signing_key,
                    workspace_scope=ctx.workspace_id,
                    principal_id=ctx.auth.user.id,
                    grant_epoch=ctx.auth.user.grant_epoch,
                    query_hash=qh,
                    created_at=visible[-1].created_at,
                    item_id=visible[-1].id,
                    now=now,
                )
                if len(rows) > limit and visible
                else None
            )
            return Page[ApiToken](
                items=[_dto(row) for row in visible], next_cursor=next_cursor, snapshot_at=now
            )

    @router.post(
        "/workspaces/{ws}/api-tokens",
        response_model=ApiTokenCreateResponse,
        status_code=201,
    )
    async def create_token(
        body: ApiTokenCreateRequest,
        request: Request,
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        ctx: Annotated[WorkspaceAccessContext, Depends(_WRITE)],
    ) -> ApiTokenCreateResponse:
        if ctx.auth.api_token is not None:
            raise ForbiddenError(
                code="api_token_management_denied",
                detail="API tokens cannot issue or rotate API tokens.",
            )
        iam = _iam(request)
        now = iam.now().astimezone(UTC)
        expires = body.expires_at.astimezone(UTC)
        if expires <= now + timedelta(minutes=5) or expires > now + timedelta(days=365):
            raise UnprocessableEntityError(
                code="api_token_expiry_invalid",
                detail="Token expiry must be 5 minutes to 365 days from now.",
            )
        role = ctx.effective_role
        if role == "break_glass":
            raise ForbiddenError(
                code="api_token_issue_denied", detail="Break-glass access cannot issue API tokens."
            )
        ceiling = _ROLE_SCOPES[role]
        if not token_scope_is_allowed(requested_scopes=set(body.scopes), issuer_scopes=ceiling):
            raise ForbiddenError(
                code="api_token_scope_overgrant",
                detail="Requested API token scope exceeds the issuer's role.",
            )
        if body.repository_ids:
            async with workspace_rls_session(
                iam.session_factory, workspace_id=ctx.workspace_id
            ) as db:
                repositories = set(
                    (
                        await db.scalars(
                            select(RepositoryModel.id).where(
                                RepositoryModel.workspace_id == ctx.workspace_id,
                                RepositoryModel.id.in_(body.repository_ids),
                            )
                        )
                    ).all()
                )
            if repositories != set(body.repository_ids) or (
                role != "admin" and not set(body.repository_ids) <= ctx.repository_grants
            ):
                raise ForbiddenError(
                    code="api_token_repository_overgrant",
                    detail="Token repository scope exceeds live grants.",
                )
        raw_token = f"r2p_{secrets.token_urlsafe(32)}"
        row = ApiTokenModel(
            id=new_uuid7(now=now),
            workspace_id=ctx.workspace_id,
            user_id=ctx.auth.user.id,
            name=body.name,
            secret_hash=hash_api_token(raw_token),
            scopes_json=list(body.scopes),
            repository_ids_json=list(body.repository_ids),
            grant_epoch=ctx.auth.user.grant_epoch,
            expires_at=expires,
            revoked_at=None,
            last_used_at=None,
            created_at=now,
        )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            db.add(row)
            await append_audit_entry(
                db,
                workspace_id=ctx.workspace_id,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                action="iam.api_token.created",
                target=f"api_token:{row.id}",
                decision="allow",
                reason_code="scoped_expiring_token",
                correlation_id=current_correlation_id(),
                client_ip=extract_client_ip(request),
                occurred_at=now,
                metadata={
                    "scopes": sorted(body.scopes),
                    "repository_count": len(body.repository_ids),
                },
            )
            await db.flush()
            return ApiTokenCreateResponse(token=raw_token, metadata=_dto(row))

    @router.delete("/workspaces/{ws}/api-tokens/{token_id}", status_code=204)
    async def revoke_token(
        request: Request,
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        token_id: Annotated[str, Path()],
        ctx: Annotated[WorkspaceAccessContext, Depends(_WRITE)],
    ) -> Response:
        if ctx.auth.api_token is not None:
            raise ForbiddenError(
                code="api_token_management_denied",
                detail="API tokens cannot issue or revoke API tokens.",
            )
        iam = _iam(request)
        now = iam.now().astimezone(UTC)
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            row = await db.scalar(
                select(ApiTokenModel)
                .where(ApiTokenModel.workspace_id == ctx.workspace_id, ApiTokenModel.id == token_id)
                .with_for_update()
            )
            if row is None:
                raise NotFoundError(code="api_token_not_found", detail="API token was not found.")
            if row.user_id != ctx.auth.user.id and (
                ctx.membership is None or ctx.membership.role != "admin"
            ):
                raise NotFoundError(code="api_token_not_found", detail="API token was not found.")
            if row.revoked_at is None:
                row.revoked_at = now
                await append_audit_entry(
                    db,
                    workspace_id=ctx.workspace_id,
                    actor_type="user",
                    actor_id=ctx.auth.user.id,
                    action="iam.api_token.revoked",
                    target=f"api_token:{row.id}",
                    decision="allow",
                    reason_code="operator_revoked",
                    correlation_id=current_correlation_id(),
                    client_ip=extract_client_ip(request),
                    occurred_at=now,
                    metadata={"scopes": sorted(row.scopes_json)},
                )
        return Response(status_code=204)

    return router


def _iam(request: Request) -> IamService:
    service = getattr(request.app.state, "iam_service", None)
    if not isinstance(service, IamService):
        raise UnauthorizedError(code="iam_unconfigured", detail="IAM is unavailable.")
    return service
