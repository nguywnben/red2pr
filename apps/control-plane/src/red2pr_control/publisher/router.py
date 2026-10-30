"""Workspace-scoped publication and V-08 reconciliation APIs (A-12)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Annotated, cast

from fastapi import APIRouter, Depends, Header, Path, Request
from sqlalchemy import select

from py_contracts import (
    ActionReceipt,
    Publication,
    PublicationDetailResponse,
    PublicationPageResponse,
    PublicationReconciliationRequest,
    RemoteCheck,
    RemoteCheckObservation,
)
from py_contracts.crypto import sha256_canonical_json
from py_contracts.integrations import CiConclusion
from py_contracts.repairs import PublicationStatus, RemoteCheckOutcome
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    DependencyUnavailableError,
    NotFoundError,
    Red2PrError,
    problem_from_exception,
)
from red2pr_control.db.base import (
    PublicationRecordModel,
    RemoteCiCheckModel,
    RequiredCheckSetModel,
)
from red2pr_control.db.idempotency import (
    claim_idempotent_operation,
    complete_idempotent_operation,
)
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.iam.rbac import (
    ALL_WORKSPACE_ROLES,
    WorkspaceAccessContext,
    make_workspace_rbac_dependency,
)
from red2pr_control.iam.sessions import IamService
from red2pr_control.publisher.remote_observer import RemoteCiObserver
from red2pr_control.publisher.saga import PublisherSaga

_READ = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="publication.read",
)
_RECONCILE = make_workspace_rbac_dependency(
    allowed_roles=frozenset({"admin", "maintainer", "reviewer"}),
    require_csrf=True,
    allow_break_glass=False,
    action="publication.reconcile",
)


def _publication_dto(row: PublicationRecordModel) -> Publication:
    return Publication(
        id=row.id,
        version=1,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        repair_id=row.repair_id,
        intent_id=row.intent_id,
        branch=row.branch,
        expected_commit_sha=row.expected_commit_sha,
        provider_object_id=row.provider_object_id,
        url=row.url,
        status=cast(PublicationStatus, row.status),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _remote_dto(
    row: RemoteCiCheckModel | None,
    *,
    repository_id: str,
    required_check_names: list[str],
    publication_check_set_digest: str | None,
) -> RemoteCheck | None:
    if row is None:
        return None
    observations = [
        RemoteCheckObservation(
            check_name=str(item.get("check_name", "unknown")),
            external_id=str(item.get("external_id", "unknown")),
            head_sha=str(item.get("head_sha", row.head_sha)),
            status=str(item.get("status", "unknown")),
            conclusion=cast(
                CiConclusion | None,
                item.get("conclusion")
                if item.get("conclusion")
                in {
                    "success",
                    "failure",
                    "cancelled",
                    "timed_out",
                    "skipped",
                    "neutral",
                    "action_required",
                    "unknown",
                }
                else "unknown",
            ),
            observed_at=item.get("observed_at", row.observed_at.isoformat()),
        )
        for item in row.observations_json
    ]
    binding_matches = row.expected_check_set_digest == publication_check_set_digest
    return RemoteCheck(
        id=row.id,
        version=1,
        workspace_id=row.workspace_id,
        repository_id=repository_id,
        publication_id=row.publication_id,
        head_sha=row.head_sha,
        expected_check_set_digest=row.expected_check_set_digest,
        required_check_names=required_check_names if binding_matches else [],
        observations=observations,
        outcome=(cast(RemoteCheckOutcome, row.outcome) if binding_matches else "unknown"),
        created_at=row.observed_at,
        updated_at=row.observed_at,
    )


def build_publications_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    @router.get("/workspaces/{ws}/publications", tags=["publications"])
    async def list_publications(
        request: Request,
        ws: Annotated[str, Path()],
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
    ) -> PublicationPageResponse:
        iam = _resolve_iam(request)
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            query = select(PublicationRecordModel).where(
                PublicationRecordModel.workspace_id == ctx.workspace_id
            )
            if not ctx.has_workspace_wide_repo_read:
                if not ctx.repository_grants:
                    return PublicationPageResponse(
                        items=[], next_cursor=None, snapshot_at=iam.now()
                    )
                query = query.where(PublicationRecordModel.repository_id.in_(ctx.repository_grants))
            rows = (
                await db.scalars(
                    query.order_by(PublicationRecordModel.created_at.desc()).limit(100)
                )
            ).all()
            return PublicationPageResponse(
                items=[_publication_dto(row) for row in rows],
                next_cursor=None,
                snapshot_at=iam.now(),
            )

    @router.get("/workspaces/{ws}/publications/{publication_id}", tags=["publications"])
    async def get_publication(
        request: Request,
        ws: Annotated[str, Path()],
        publication_id: str,
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
    ) -> PublicationDetailResponse:
        iam = _resolve_iam(request)
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            row = await db.scalar(
                select(PublicationRecordModel).where(
                    PublicationRecordModel.workspace_id == ctx.workspace_id,
                    PublicationRecordModel.id == publication_id,
                )
            )
            if row is None or not ctx.can_read_repository(row.repository_id):
                raise NotFoundError(
                    code="publication_not_found", detail="Publication was not found."
                )
            remote = await db.scalar(
                select(RemoteCiCheckModel).where(
                    RemoteCiCheckModel.workspace_id == ctx.workspace_id,
                    RemoteCiCheckModel.publication_id == row.id,
                )
            )
            required = await db.scalar(
                select(RequiredCheckSetModel).where(
                    RequiredCheckSetModel.workspace_id == ctx.workspace_id,
                    RequiredCheckSetModel.repository_id == row.repository_id,
                    RequiredCheckSetModel.policy_revision == row.policy_revision,
                )
            )
            names = (
                list(required.names_json)
                if required is not None
                and required.digest == row.required_check_set_digest
                and required.digest == sha256_canonical_json(required.names_json)
                else []
            )
            return PublicationDetailResponse(
                publication=_publication_dto(row),
                remote_check=_remote_dto(
                    remote,
                    repository_id=row.repository_id,
                    required_check_names=names,
                    publication_check_set_digest=row.required_check_set_digest,
                ),
            )

    @router.post(
        "/workspaces/{ws}/publications/{publication_id}/reconciliations",
        tags=["publications"],
    )
    async def reconcile_publication(
        body: PublicationReconciliationRequest,
        request: Request,
        ws: Annotated[str, Path()],
        publication_id: str,
        ctx: Annotated[WorkspaceAccessContext, Depends(_RECONCILE)],
        idempotency_key: Annotated[
            str, Header(alias="Idempotency-Key", min_length=1, max_length=120)
        ],
    ) -> ActionReceipt:
        iam = _resolve_iam(request)
        correlation_id = str(getattr(request.state, "correlation_id", "unknown"))
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            row = await db.scalar(
                select(PublicationRecordModel).where(
                    PublicationRecordModel.workspace_id == ctx.workspace_id,
                    PublicationRecordModel.id == publication_id,
                )
            )
            if row is None or not ctx.can_act_on_repository(
                row.repository_id, allowed_roles=frozenset({"admin", "maintainer", "reviewer"})
            ):
                raise NotFoundError(
                    code="publication_not_found", detail="Publication was not found."
                )
            saga = getattr(request.app.state, "publisher_saga", None)
            if not isinstance(saga, PublisherSaga):
                raise DependencyUnavailableError(
                    code="publisher_unconfigured",
                    detail="Publisher reconciliation is unavailable.",
                )
            observer = getattr(request.app.state, "remote_ci_observer", None)
            if not isinstance(observer, RemoteCiObserver):
                raise DependencyUnavailableError(
                    code="remote_ci_unconfigured", detail="Remote CI observer is unavailable."
                )
            claim = await claim_idempotent_operation(
                db,
                workspace_id=ctx.workspace_id,
                principal_id=ctx.auth.user.id,
                operation="publication.reconcile",
                idempotency_key=idempotency_key,
                request_payload={
                    "publication_id": publication_id,
                    "reason": body.reason.strip(),
                },
                logical_effect_key=f"publication-reconcile:{publication_id}:{idempotency_key}",
                resource_id=publication_id,
                status_url=(f"/api/v1/workspaces/{ws}/publications/{publication_id}"),
                correlation_id=correlation_id,
                now=iam.now(),
            )
            if not claim.is_new_claim:
                return claim.receipt

        async def record_unknown(exc: Exception | None) -> None:
            async with workspace_rls_session(
                iam.session_factory, workspace_id=ctx.workspace_id
            ) as db:
                await complete_idempotent_operation(
                    db,
                    workspace_id=ctx.workspace_id,
                    operation_id=claim.receipt.operation_id,
                    state="unknown",
                    status_code=(exc.status if isinstance(exc, Red2PrError) else 500),
                    problem=problem_from_exception(
                        exc or RuntimeError("request_cancelled"),
                        correlation_id=correlation_id,
                    ),
                    now=iam.now(),
                )

        try:
            publication = await saga.reconcile(
                workspace_id=ctx.workspace_id,
                publication_id=publication_id,
            )
            if publication.status == "published":
                assert isinstance(observer, RemoteCiObserver)
                await observer.reconcile(
                    workspace_id=ctx.workspace_id,
                    publication_id=publication_id,
                    correlation_id=correlation_id,
                    now=datetime.now(tz=UTC),
                )
            receipt = ActionReceipt(
                operation_id=claim.receipt.operation_id,
                resource_id=publication_id,
                state="succeeded",
                correlation_id=correlation_id,
                status_url=f"/api/v1/workspaces/{ws}/publications/{publication_id}",
                result_id=publication_id,
            )
            async with workspace_rls_session(
                iam.session_factory, workspace_id=ctx.workspace_id
            ) as db:
                await complete_idempotent_operation(
                    db,
                    workspace_id=ctx.workspace_id,
                    operation_id=claim.receipt.operation_id,
                    state="succeeded",
                    status_code=200,
                    result_id=publication_id,
                    response_payload=receipt.model_dump(mode="json"),
                    now=iam.now(),
                )
                await append_audit_entry(
                    db,
                    workspace_id=ctx.workspace_id,
                    repository_id=publication.repository_id,
                    actor_type="user",
                    actor_id=ctx.auth.user.id,
                    action="publication.remote_ci.reconciled",
                    target=publication.id,
                    decision="allow",
                    reason_code="operator_requested_remote_ci_refresh",
                    correlation_id=correlation_id,
                    occurred_at=iam.now(),
                    metadata={
                        "reason": body.reason[:1000],
                        "publication_status": publication.status,
                    },
                )
            return receipt
        except asyncio.CancelledError:
            await asyncio.shield(record_unknown(None))
            raise
        except Exception as exc:
            await record_unknown(exc)
            raise

    return router


def _resolve_iam(request: Request) -> IamService:
    service = getattr(request.app.state, "iam_service", None)
    if not isinstance(service, IamService):
        raise DependencyUnavailableError(
            code="iam_unconfigured", detail="IAM persistence is not configured."
        )
    return service
