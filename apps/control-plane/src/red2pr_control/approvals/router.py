"""Live-web, CSRF-protected approval inbox and decision routes (A-11)."""

from __future__ import annotations

from datetime import UTC, timedelta
from typing import Annotated, Literal, cast

from fastapi import APIRouter, Depends, Header, Path, Query, Request
from sqlalchemy import and_, or_, select

from py_contracts import ApprovalDecisionRequest, ApprovalInboxEntry, ApprovalPageResponse
from py_contracts.iam import WorkspaceRole
from py_contracts.primitives import Problem
from py_contracts.repairs import Approval
from red2pr_control.approvals.service import ApprovalService, approval_dto
from red2pr_control.core.errors import (
    PROBLEM_JSON_MEDIA_TYPE,
    DependencyUnavailableError,
    ForbiddenError,
    NotFoundError,
)
from red2pr_control.db.base import ApprovalRequestModel
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.iam.rbac import (
    WorkspaceAccessContext,
    compute_query_filter_hash,
    decode_signed_cursor,
    encode_signed_cursor,
    make_workspace_rbac_dependency,
)
from red2pr_control.iam.sessions import IamService
from red2pr_control.publisher.saga import PublisherSaga

_APPROVAL_ROLES: frozenset[WorkspaceRole] = frozenset({"admin", "maintainer", "reviewer"})
_READ = make_workspace_rbac_dependency(
    allowed_roles=_APPROVAL_ROLES,
    require_csrf=False,
    allow_break_glass=False,
    action="approval.read",
)
_DECIDE = make_workspace_rbac_dependency(
    allowed_roles=_APPROVAL_ROLES,
    require_csrf=True,
    allow_break_glass=False,
    action="approval.decide",
)


def build_approvals_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    @router.get("/workspaces/{ws}/approvals", tags=["approvals"])
    async def list_approvals(
        request: Request,
        ws: Annotated[str, Path()],
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
        status: Annotated[
            str | None, Query(pattern="^(pending|approved|rejected|expired|revoked)$")
        ] = "pending",
        repository_id: Annotated[str | None, Query(min_length=36, max_length=36)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
    ) -> ApprovalPageResponse:
        iam = _resolve_iam(request)
        now = iam.now()
        query_hash = compute_query_filter_hash(
            {
                "endpoint": "approvals.list",
                "status": status or "",
                "repository_id": repository_id or "",
            }
        )
        decoded = (
            decode_signed_cursor(
                cursor,
                signing_key=iam.csrf_signing_key,
                expected_workspace_scope=ctx.workspace_id,
                expected_principal_id=ctx.auth.user.id,
                current_grant_epoch=ctx.auth.user.grant_epoch,
                expected_query_hash=query_hash,
                now=now,
            )
            if cursor is not None
            else None
        )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            query = select(ApprovalRequestModel).where(
                ApprovalRequestModel.workspace_id == ctx.workspace_id
            )
            if status is not None:
                query = query.where(ApprovalRequestModel.status == status)
            if repository_id:
                query = query.where(ApprovalRequestModel.repository_id == repository_id)
            if not ctx.has_workspace_wide_repo_read:
                if not ctx.repository_grants:
                    return ApprovalPageResponse(items=[], next_cursor=None, snapshot_at=now)
                query = query.where(ApprovalRequestModel.repository_id.in_(ctx.repository_grants))
            if decoded is not None:
                query = query.where(
                    or_(
                        ApprovalRequestModel.created_at < decoded.created_at,
                        and_(
                            ApprovalRequestModel.created_at == decoded.created_at,
                            ApprovalRequestModel.id < decoded.item_id,
                        ),
                    )
                )
            rows = (
                await db.scalars(
                    query.order_by(
                        ApprovalRequestModel.created_at.desc(), ApprovalRequestModel.id.desc()
                    ).limit(limit + 1)
                )
            ).all()
            has_more = len(rows) > limit
            visible = rows[:limit]
            next_cursor = (
                encode_signed_cursor(
                    signing_key=iam.csrf_signing_key,
                    workspace_scope=ctx.workspace_id,
                    principal_id=ctx.auth.user.id,
                    grant_epoch=ctx.auth.user.grant_epoch,
                    query_hash=query_hash,
                    created_at=visible[-1].created_at,
                    item_id=visible[-1].id,
                    now=now,
                )
                if has_more and visible
                else None
            )
            return ApprovalPageResponse(
                items=[
                    ApprovalInboxEntry(
                        approval=approval_dto(row),
                        requested_by=row.requested_by,
                        risk_level=row.risk_level,
                        scope_description=row.scope_description,
                        sensitive_change=row.sensitive_change,
                        decision=cast(Literal["approve", "reject"] | None, row.decision),
                        reason=row.reason,
                    )
                    for row in visible
                ],
                next_cursor=next_cursor,
                snapshot_at=now,
            )

    @router.get(
        "/workspaces/{ws}/approvals/{approval_id}", response_model=Approval, tags=["approvals"]
    )
    async def get_approval(
        request: Request,
        ws: Annotated[str, Path()],
        approval_id: str,
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
    ) -> Approval:
        iam = _resolve_iam(request)
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            row = await db.scalar(
                select(ApprovalRequestModel).where(
                    ApprovalRequestModel.workspace_id == ctx.workspace_id,
                    ApprovalRequestModel.id == approval_id,
                )
            )
            if row is None or not ctx.can_read_repository(row.repository_id):
                raise NotFoundError(
                    code="approval_not_found", detail="Approval request was not found."
                )
            if row.status == "pending" and row.expires_at <= iam.now():
                # Expiry is materialized by the decision service; reads report effective status now.
                return approval_dto(row).model_copy(update={"status": "expired"})
            return approval_dto(row)

    @router.post(
        "/workspaces/{ws}/approvals/{approval_id}/decisions",
        response_model=Approval,
        tags=["approvals"],
        responses={403: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}}},
    )
    async def decide_approval(
        body: ApprovalDecisionRequest,
        request: Request,
        ws: Annotated[str, Path()],
        approval_id: str,
        ctx: Annotated[WorkspaceAccessContext, Depends(_DECIDE)],
        idempotency_key: Annotated[
            str, Header(alias="Idempotency-Key", min_length=1, max_length=120)
        ],
    ) -> Approval:
        iam = _resolve_iam(request)
        step_up_at = ctx.auth.session.step_up_at
        if (
            ctx.auth.session.auth_strength != "mfa"
            or step_up_at is None
            or iam.now() - step_up_at.astimezone(UTC) > timedelta(minutes=5)
        ):
            raise ForbiddenError(
                code="step_up_required",
                detail="A recent MFA step-up is required to decide an approval.",
            )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            current = await db.scalar(
                select(ApprovalRequestModel).where(
                    ApprovalRequestModel.workspace_id == ctx.workspace_id,
                    ApprovalRequestModel.id == approval_id,
                )
            )
            if current is None or not ctx.can_act_on_repository(
                current.repository_id, allowed_roles=_APPROVAL_ROLES
            ):
                raise NotFoundError(
                    code="approval_not_found", detail="Approval request was not found."
                )
            publisher = getattr(request.app.state, "publisher_saga", None)
            if (
                body.decision == "approve"
                and current.intent_type == "publish_draft_pr"
                and not isinstance(publisher, PublisherSaga)
            ):
                raise DependencyUnavailableError(
                    code="publisher_unconfigured",
                    detail=(
                        "Draft publication cannot be approved while the publisher is unavailable."
                    ),
                )
        service = ApprovalService(session_factory=iam.session_factory)
        row = await service.decide(
            workspace_id=ctx.workspace_id,
            approval_id=approval_id,
            actor_id=ctx.auth.user.id,
            decision=body.decision,
            reason=body.reason,
            expected_patch_digest=body.expected_patch_digest,
            expected_policy_revision=body.expected_policy_revision,
            idempotency_key=idempotency_key,
            correlation_id=str(getattr(request.state, "correlation_id", "unknown")),
            now=iam.now(),
        )
        if (
            row.status == "approved"
            and row.decision == "approve"
            and row.intent_type == "publish_draft_pr"
        ):
            # The approval decision is committed first. A same-key replay re-enters here
            # after a process failure and the saga reconciles the persisted intent.
            assert isinstance(publisher, PublisherSaga)
            await publisher.publish_approved(
                workspace_id=ctx.workspace_id,
                approval_id=row.id,
                correlation_id=str(getattr(request.state, "correlation_id", "unknown")),
            )
        return approval_dto(row)

    return router


def _resolve_iam(request: Request) -> IamService:
    service = getattr(request.app.state, "iam_service", None)
    if not isinstance(service, IamService):
        raise DependencyUnavailableError(
            code="iam_unconfigured", detail="IAM persistence is not configured."
        )
    return service
