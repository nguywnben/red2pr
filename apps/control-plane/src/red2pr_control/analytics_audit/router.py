"""A-17 workspace analytics, usage ledgers, and scoped encrypted report exports (U24)."""

from __future__ import annotations

import hashlib
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, Header, Path, Query, Request, Response
from fastapi.responses import Response as RawResponse
from sqlalchemy import and_, delete, func, or_, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts import (
    AuditRecord,
    ReleaseExceptionCreateRequest,
    ReleaseExceptionList,
    ReleaseExceptionRecord,
    ReportExportReceipt,
    ReportExportRequest,
    SecretKeyMetadata,
    SecretKeyMetadataPage,
    SecretKeyRotationResult,
    SecretPurpose,
    WorkspaceAnalyticsResponse,
    WorkspaceUsageResponse,
)
from py_contracts.crypto import KeyRing, canonical_json_bytes
from py_contracts.evidence import AuditDecision, ReportFormat, ReportKind
from py_contracts.primitives import Page, new_uuid7
from red2pr_control.analytics_audit.audit_chain import (
    ExternalCheckpointStore,
    append_audit_entry,
    verify_audit_chain,
)
from red2pr_control.analytics_audit.exporter import render_csv, render_json
from red2pr_control.analytics_audit.projections import AnalyticsSource, build_analytics_projection
from red2pr_control.core.errors import (
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    GoneError,
    NotFoundError,
    UnprocessableEntityError,
)
from red2pr_control.core.redaction import DEFAULT_REDACTOR
from red2pr_control.db.base import (
    ApprovalRequestModel,
    AuditLogModel,
    CiRunModel,
    EvidenceManifestModel,
    MembershipModel,
    PublicationRecordModel,
    ReleaseExceptionModel,
    RepairSessionModel,
    RepoGrantModel,
    ReportExportModel,
    ReportingProjectionModel,
    RepositoryModel,
    ReproductionRunModel,
    SecretEntryModel,
    SecretKeyringStateModel,
    UsageLedgerModel,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.rbac import (
    WorkspaceAccessContext,
    compute_query_filter_hash,
    decode_signed_cursor,
    encode_signed_cursor,
    make_workspace_rbac_dependency,
)
from red2pr_control.iam.router import get_iam_service
from red2pr_control.iam.sessions import IamService, extract_client_ip, is_step_up_fresh
from red2pr_control.triage_evidence.artifact_store import (
    ArtifactStoreProtocol,
    StagedBlobHandle,
)

_READ = make_workspace_rbac_dependency(
    allowed_roles=frozenset({"admin", "maintainer", "reviewer", "viewer", "auditor"}),
    require_csrf=False,
    allow_break_glass=False,
    action="workspace.analytics_read",
)
_AUDIT_ROLES = frozenset({"admin", "auditor"})
_EXCEPTION_WRITE = make_workspace_rbac_dependency(
    allowed_roles=frozenset({"admin"}),
    require_csrf=True,
    allow_break_glass=False,
    action="workspace.release_exception_write",
)
_SECURITY_METADATA_READ = make_workspace_rbac_dependency(
    allowed_roles=frozenset({"admin", "auditor"}),
    require_csrf=False,
    allow_break_glass=False,
    action="workspace.security_metadata_read",
)
_EXPORT_TTL = timedelta(hours=24)
_MAX_EXPORT_BYTES = 20 * 1024 * 1024
_INITIAL_STATES = frozenset({"received", "authorized", "collecting"})
_PENDING_STATES = frozenset(
    {
        "received",
        "authorized",
        "collecting",
        "triaging",
        "reproducing",
        "patching",
        "verifying",
        "publishing",
        "remote_validating",
        "needs_human",
        "cancel_requested",
    }
)
_ABSTAIN_STATES = frozenset({"unsupported", "diagnosed_only", "rejected"})


def _timestamp(value: datetime | None, fallback: datetime) -> datetime:
    return value.astimezone(UTC) if value and value.tzinfo else fallback


async def _live_repository_scope(
    db: AsyncSession, ctx: WorkspaceAccessContext
) -> frozenset[str] | None:
    """Recheck membership and grants in the same RLS transaction as every source read."""
    if ctx.membership is None:
        if ctx.break_glass_grant is not None:
            return None
        raise ForbiddenError(
            code="workspace_access_revoked", detail="Workspace access has been revoked."
        )
    member = await db.scalar(
        select(MembershipModel).where(
            MembershipModel.workspace_id == ctx.workspace_id,
            MembershipModel.id == ctx.membership.id,
            MembershipModel.user_id == ctx.auth.user.id,
        )
    )
    if member is None:
        raise ForbiddenError(
            code="workspace_access_revoked", detail="Workspace access has been revoked."
        )
    if member.role == "admin" and getattr(ctx.auth, "api_token", None) is None:
        return None
    rows = await db.scalars(
        select(RepoGrantModel.repository_id).where(
            RepoGrantModel.workspace_id == ctx.workspace_id,
            RepoGrantModel.membership_id == member.id,
        )
    )
    granted = frozenset(rows.all())
    token = getattr(ctx.auth, "api_token", None)
    if token is not None:
        granted &= frozenset(token.repository_ids)
    return granted


async def _source_rows(
    db: AsyncSession,
    *,
    workspace_id: str,
    repo_ids: frozenset[str] | None,
    start: datetime,
    end: datetime,
) -> tuple[
    list[CiRunModel],
    list[RepairSessionModel],
    list[ReproductionRunModel],
    list[PublicationRecordModel],
    list[UsageLedgerModel],
    list[ApprovalRequestModel],
    list[EvidenceManifestModel],
    list[AuditLogModel],
]:
    def scoped(model: Any, time_col: Any) -> Any:
        stmt = select(model).where(
            model.workspace_id == workspace_id, time_col >= start, time_col <= end
        )
        return stmt.where(model.repository_id.in_(repo_ids)) if repo_ids is not None else stmt

    if repo_ids == frozenset():
        return ([], [], [], [], [], [], [], [])
    runs = list((await db.scalars(scoped(CiRunModel, CiRunModel.created_at))).all())
    repairs = list(
        (await db.scalars(scoped(RepairSessionModel, RepairSessionModel.created_at))).all()
    )
    reproductions = list(
        (await db.scalars(scoped(ReproductionRunModel, ReproductionRunModel.created_at))).all()
    )
    publications = list(
        (await db.scalars(scoped(PublicationRecordModel, PublicationRecordModel.created_at))).all()
    )
    usage = list((await db.scalars(scoped(UsageLedgerModel, UsageLedgerModel.created_at))).all())
    approvals = list(
        (await db.scalars(scoped(ApprovalRequestModel, ApprovalRequestModel.created_at))).all()
    )
    manifests = list(
        (await db.scalars(scoped(EvidenceManifestModel, EvidenceManifestModel.created_at))).all()
    )
    audit_stmt = select(AuditLogModel).where(
        AuditLogModel.workspace_id == workspace_id,
        AuditLogModel.occurred_at >= start,
        AuditLogModel.occurred_at <= end,
    )
    audit_stmt = (
        audit_stmt.where(AuditLogModel.repository_id.in_(repo_ids))
        if repo_ids is not None
        else audit_stmt
    )
    audit_rows = list((await db.scalars(audit_stmt)).all())
    return runs, repairs, reproductions, publications, usage, approvals, manifests, audit_rows


async def _repository_count(
    db: AsyncSession, *, workspace_id: str, repo_ids: frozenset[str] | None
) -> int:
    stmt = select(func.count(RepositoryModel.id)).where(
        RepositoryModel.workspace_id == workspace_id
    )
    if repo_ids is not None:
        if not repo_ids:
            return 0
        stmt = stmt.where(RepositoryModel.id.in_(repo_ids))
    return int(await db.scalar(stmt) or 0)


def _build_payload(
    rows: tuple[list[Any], ...],
    *,
    workspace_id: str,
    start: datetime,
    end: datetime,
    repos: frozenset[str] | None,
    now: datetime,
) -> dict[str, Any]:
    runs, repairs, reproductions, publications, usage, approvals, _, _ = rows
    ingested_run_ids = {r.id for r in runs if r.ingestion_state == "ingested"}
    session_rows = [r for r in repairs if r.ci_run_id in ingested_run_ids]
    eligible_run_ids = {r.ci_run_id for r in session_rows}
    eligible = len(eligible_run_ids)
    executed_rows = [r for r in session_rows if r.state not in _INITIAL_STATES | _ABSTAIN_STATES]
    executed_ids = {r.id for r in executed_rows}
    reproduced_repair_ids = {
        r.repair_id
        for r in reproductions
        if r.repair_id in executed_ids and r.phase == "baseline_a" and r.status == "repro_confirmed"
    }
    reproduced_ids = {r.ci_run_id for r in session_rows if r.id in reproduced_repair_ids}
    locally_verified_ids = {r.id for r in session_rows if r.proof_grade == "locally_verified"}
    locally_verified_run_ids = {r.ci_run_id for r in session_rows if r.id in locally_verified_ids}
    approved_ids = {
        r.repair_id
        for r in approvals
        if r.intent_type == "publish_draft_pr" and r.status == "approved"
    }
    publish_eligible_ids = locally_verified_ids & approved_ids
    publish_eligible_run_ids = {r.ci_run_id for r in session_rows if r.id in publish_eligible_ids}
    observed_repair_ids = {
        p.repair_id
        for p in publications
        if p.status == "published" and p.repair_id in publish_eligible_ids
    }
    observed_publications = {r.ci_run_id for r in session_rows if r.id in observed_repair_ids}
    remote_success_ids = {
        r.ci_run_id
        for r in session_rows
        if r.state == "remote_verified"
        and r.remote_status == "passed"
        and r.id in observed_repair_ids
    }
    settled_by_currency: dict[str, Decimal] = {}
    estimated_by_currency: dict[str, Decimal] = {}
    unknown_cost_by_currency: dict[str, int] = {}
    usage_rows_by_currency: dict[str, int] = {}
    for row in usage:
        usage_rows_by_currency[row.currency] = usage_rows_by_currency.get(row.currency, 0) + 1
        if row.status == "settled" and row.settled_cost is not None:
            settled_by_currency[row.currency] = (
                settled_by_currency.get(row.currency, Decimal(0)) + row.settled_cost
            )
        elif row.status != "released":
            estimated_by_currency[row.currency] = (
                estimated_by_currency.get(row.currency, Decimal(0)) + row.estimated_cost
            )
        if row.status == "unknown":
            unknown_cost_by_currency[row.currency] = (
                unknown_cost_by_currency.get(row.currency, 0) + 1
            )
    source_times = (
        [r.updated_at for r in runs]
        + [r.updated_at for r in repairs]
        + [r.created_at for r in reproductions]
        + [r.created_at for r in usage]
        + [r.created_at for r in publications]
        + [r.created_at for r in approvals]
    )
    watermark = max(source_times) if source_times else now
    source = AnalyticsSource(
        ingested_runs=len(ingested_run_ids),
        eligible_repairs=eligible,
        executed_repairs=len({r.ci_run_id for r in executed_rows}),
        confirmed_reproductions=len(reproduced_ids),
        locally_verified_repairs=len(locally_verified_run_ids),
        locally_verified_eligible_publications=len(publish_eligible_run_ids),
        observed_publications=len(observed_publications),
        remotely_verified_publications=len(remote_success_ids),
        unknown=sum(1 for r in session_rows if r.state in {"repro_unconfirmed", "remote_unknown"})
        + sum(1 for r in runs if r.ingestion_state in {"incomplete", "failed", "stale_sha"}),
        pending=sum(1 for r in session_rows if r.state in _PENDING_STATES)
        + sum(1 for r in runs if r.ingestion_state in {"pending", "collecting"}),
        abstained=sum(1 for r in session_rows if r.state in _ABSTAIN_STATES)
        + sum(1 for r in runs if r.ingestion_state == "failed"),
        usage_rows=len(usage),
        settled_costs=settled_by_currency,
        estimated_unsettled_costs=estimated_by_currency,
        unknown_cost_rows_by_currency=unknown_cost_by_currency,
        usage_rows_by_currency=usage_rows_by_currency,
        watermark=watermark,
    )
    projection = build_analytics_projection(source)
    costs = [
        {
            "currency": cost.currency,
            "settled": format(cost.settled, "f"),
            "estimated_unsettled": format(cost.estimated_unsettled, "f"),
            "total": format(cost.total, "f"),
            "unknown_rows": cost.unknown_rows,
            "usage_rows": cost.usage_rows,
        }
        for cost in projection.costs
    ]
    return {
        "workspace_id": workspace_id,
        "range_start": start,
        "range_end": end,
        "repository_count": len(repos)
        if repos is not None
        else len({r.repository_id for r in runs}),
        "funnel": [stage.__dict__ for stage in projection.funnel],
        "local_success_count": projection.local_success_count,
        "remote_success_count": projection.remote_success_count,
        "unknown_count": projection.unknown_count,
        "pending_count": projection.pending_count,
        "abstained_count": projection.abstained_count,
        "costs": costs,
        "watermark": watermark,
    }


def _export_records(
    kind: str, payload: dict[str, Any], rows: tuple[list[Any], ...]
) -> list[dict[str, Any]]:
    _, _, _, _, usage, _, manifests, audit_rows = rows
    if kind == "usage":
        return [
            {
                "repository_id": u.repository_id,
                "repair_id": u.repair_id,
                "model_id": u.model_id,
                "status": u.status,
                "input_tokens": u.input_tokens,
                "output_tokens": u.output_tokens,
                "estimated_cost": u.estimated_cost,
                "settled_cost": u.settled_cost,
                "currency": u.currency,
                "created_at": u.created_at,
            }
            for u in usage
        ]
    if kind == "proof_summary":
        return [
            {
                "manifest_id": m.id,
                "repository_id": m.repository_id,
                "repair_id": m.repair_id,
                "manifest_digest": m.manifest_digest,
                "restricted_artifact_digests": sorted(
                    set(m.payload_json.get("artifact_digests", {}).values())
                ),
                "created_at": m.created_at,
            }
            for m in manifests
        ]
    if kind == "audit":
        return [
            {
                "occurred_at": a.occurred_at,
                "actor_type": a.actor_type,
                "action": a.action,
                "decision": a.decision,
                "reason_code": a.reason_code,
                "target": DEFAULT_REDACTOR.redact_text(a.target),
                "repository_id": a.repository_id,
                "correlation_id": a.correlation_id,
                "entry_hash": a.entry_hash,
            }
            for a in audit_rows
        ]
    return [
        {
            "stage": step["key"],
            "value": step["value"],
            "numerator": step["numerator"],
            "denominator": step["denominator"],
        }
        for step in payload["funnel"]
    ]


def build_analytics_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    @router.get(
        "/workspaces/{ws}/audit",
        operation_id="listWorkspaceAudit",
        tags=["audit"],
        response_model=Page[AuditRecord],
    )
    async def list_workspace_audit(
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        request: Request,
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
        iam: Annotated[IamService, Depends(get_iam_service)],
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        cursor: Annotated[str | None, Query(max_length=2048)] = None,
        action: Annotated[str | None, Query(max_length=120)] = None,
        correlation_id: Annotated[str | None, Query(max_length=120)] = None,
    ) -> Page[AuditRecord]:
        if ctx.effective_role not in _AUDIT_ROLES:
            raise ForbiddenError(
                code="insufficient_role", detail="Audit search requires admin or auditor role."
            )
        checkpoint_store = getattr(request.app.state, "audit_checkpoint_store", None)
        checkpoint_keyring = getattr(request.app.state, "audit_checkpoint_keyring", None)
        if (
            not isinstance(checkpoint_store, ExternalCheckpointStore)
            or not isinstance(checkpoint_keyring, KeyRing)
            or not checkpoint_store.list_checkpoints()
        ):
            raise DependencyUnavailableError(
                code="audit_verification_unavailable",
                detail="Verified audit search requires a signed external checkpoint.",
            )
        now = iam.now().astimezone(UTC)
        async with instance_rls_session(iam.session_factory, mode="audit_verifier") as audit_db:
            await verify_audit_chain(
                audit_db,
                external_store=checkpoint_store,
                keyring=checkpoint_keyring,
            )
        filters = {
            "endpoint": "workspace.audit",
            "action": action,
            "correlation_id": correlation_id,
        }
        query_hash = compute_query_filter_hash(filters)
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
            if cursor
            else None
        )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            live_membership = await db.scalar(
                select(MembershipModel).where(
                    MembershipModel.workspace_id == ctx.workspace_id,
                    MembershipModel.user_id == ctx.auth.user.id,
                )
            )
            if (
                ctx.auth.api_token is not None
                or live_membership is None
                or live_membership.role not in _AUDIT_ROLES
            ):
                raise ForbiddenError(
                    code="insufficient_role",
                    detail="Audit search requires a live admin or auditor membership.",
                )
            query = select(AuditLogModel).where(AuditLogModel.workspace_id == ctx.workspace_id)
            if action:
                query = query.where(AuditLogModel.action == action)
            if correlation_id:
                query = query.where(AuditLogModel.correlation_id == correlation_id)
            if decoded is not None:
                query = query.where(
                    or_(
                        AuditLogModel.occurred_at < decoded.created_at,
                        and_(
                            AuditLogModel.occurred_at == decoded.created_at,
                            AuditLogModel.id < decoded.item_id,
                        ),
                    )
                )
            rows = list(
                (
                    await db.scalars(
                        query.order_by(
                            AuditLogModel.occurred_at.desc(), AuditLogModel.id.desc()
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
                    query_hash=query_hash,
                    created_at=visible[-1].occurred_at,
                    item_id=visible[-1].id,
                    now=now,
                )
                if len(rows) > limit and visible
                else None
            )
            items = [
                AuditRecord(
                    id=row.id,
                    version=row.version,
                    created_at=row.occurred_at,
                    updated_at=row.occurred_at,
                    workspace_id=ctx.workspace_id,
                    actor=row.actor_type,
                    action=row.action,
                    target=DEFAULT_REDACTOR.redact_text(row.target),
                    decision=cast(AuditDecision, row.decision),
                    reason_code=row.reason_code,
                    correlation_id=row.correlation_id,
                    prev_hash=row.prev_hash,
                    entry_hash=row.entry_hash,
                )
                for row in visible
            ]
            return Page[AuditRecord](items=items, next_cursor=next_cursor, snapshot_at=now)

    @router.get(
        "/workspaces/{ws}/release-exceptions",
        operation_id="listWorkspaceReleaseExceptions",
        tags=["security"],
        response_model=ReleaseExceptionList,
    )
    async def list_release_exceptions(
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> ReleaseExceptionList:
        if ctx.effective_role not in _AUDIT_ROLES or ctx.auth.api_token is not None:
            raise ForbiddenError(
                code="insufficient_role",
                detail="Release exceptions require a live admin or auditor session.",
            )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            member = await db.scalar(
                select(MembershipModel).where(
                    MembershipModel.workspace_id == ctx.workspace_id,
                    MembershipModel.user_id == ctx.auth.user.id,
                    MembershipModel.role.in_(_AUDIT_ROLES),
                )
            )
            if member is None:
                raise ForbiddenError(
                    code="workspace_access_revoked", detail="Audit access has been revoked."
                )
            rows = list(
                (
                    await db.scalars(
                        select(ReleaseExceptionModel)
                        .where(ReleaseExceptionModel.workspace_id == ctx.workspace_id)
                        .order_by(ReleaseExceptionModel.created_at.desc())
                        .limit(500)
                    )
                ).all()
            )
            return ReleaseExceptionList(
                items=[
                    ReleaseExceptionRecord(
                        id=row.id,
                        finding_ref=row.finding_ref,
                        severity="high",
                        artifact_digest=row.artifact_digest,
                        owner_user_id=row.owner_user_id,
                        security_reviewer_user_id=row.security_reviewer_user_id,
                        mitigation=row.mitigation,
                        created_at=row.created_at,
                        expires_at=row.expires_at,
                        revoked_at=row.revoked_at,
                    )
                    for row in rows
                ]
            )

    @router.post(
        "/workspaces/{ws}/release-exceptions",
        operation_id="createWorkspaceReleaseException",
        tags=["security"],
        response_model=ReleaseExceptionRecord,
        status_code=201,
    )
    async def create_release_exception(
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        body: ReleaseExceptionCreateRequest,
        request: Request,
        ctx: Annotated[WorkspaceAccessContext, Depends(_EXCEPTION_WRITE)],
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> ReleaseExceptionRecord:
        now = iam.now().astimezone(UTC)
        if ctx.auth.api_token is not None or not is_step_up_fresh(ctx.auth.session, now=now):
            raise ForbiddenError(
                code="step_up_required",
                detail="A recent web-session MFA step-up is required for a High exception.",
            )
        expires_at = body.expires_at.astimezone(UTC)
        if expires_at <= now or expires_at > now + timedelta(days=30):
            raise UnprocessableEntityError(
                code="release_exception_expiry_invalid",
                detail="High exceptions must expire within 30 days.",
            )
        if body.security_reviewer_user_id == ctx.auth.user.id:
            raise UnprocessableEntityError(
                code="release_exception_reviewer_not_independent",
                detail="The owner and security reviewer must be different users.",
            )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            await db.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {
                    "key": (
                        f"release-exception:{ctx.workspace_id}:{body.finding_ref}:"
                        f"{body.artifact_digest}"
                    )
                },
            )
            memberships = list(
                (
                    await db.scalars(
                        select(MembershipModel).where(
                            MembershipModel.workspace_id == ctx.workspace_id,
                            MembershipModel.user_id.in_(
                                [ctx.auth.user.id, body.security_reviewer_user_id]
                            ),
                        )
                    )
                ).all()
            )
            roles = {item.user_id: item.role for item in memberships}
            if roles.get(ctx.auth.user.id) != "admin":
                raise ForbiddenError(
                    code="insufficient_role", detail="A workspace admin must own the exception."
                )
            if roles.get(body.security_reviewer_user_id) != "admin":
                raise UnprocessableEntityError(
                    code="release_exception_reviewer_invalid",
                    detail="The independent security reviewer must be a workspace admin.",
                )
            existing = await db.scalar(
                select(ReleaseExceptionModel.id).where(
                    ReleaseExceptionModel.workspace_id == ctx.workspace_id,
                    ReleaseExceptionModel.finding_ref == body.finding_ref,
                    ReleaseExceptionModel.artifact_digest == body.artifact_digest,
                    ReleaseExceptionModel.revoked_at.is_(None),
                    ReleaseExceptionModel.expires_at > now,
                )
            )
            if existing is not None:
                raise ConflictError(
                    code="release_exception_exists",
                    detail="An active exception already exists for this finding and digest.",
                )
            row = ReleaseExceptionModel(
                id=new_uuid7(now=now),
                workspace_id=ctx.workspace_id,
                finding_ref=body.finding_ref,
                severity="high",
                artifact_digest=body.artifact_digest,
                owner_user_id=ctx.auth.user.id,
                security_reviewer_user_id=body.security_reviewer_user_id,
                mitigation=DEFAULT_REDACTOR.redact_text(body.mitigation)[:2000],
                created_at=now,
                expires_at=expires_at,
            )
            db.add(row)
            await db.flush()
            await append_audit_entry(
                db,
                workspace_id=ctx.workspace_id,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                action="security.release_exception.created",
                target=f"release_exception:{row.id}",
                decision="allow",
                reason_code="high_finding_exception",
                correlation_id=getattr(request.state, "correlation_id", "release-exception"),
                client_ip=extract_client_ip(request),
                metadata={
                    "finding_ref": body.finding_ref,
                    "artifact_digest": body.artifact_digest,
                    "security_reviewer_user_id": body.security_reviewer_user_id,
                    "expires_at": expires_at.isoformat(),
                },
                occurred_at=now,
            )
            return ReleaseExceptionRecord(
                id=row.id,
                finding_ref=row.finding_ref,
                severity="high",
                artifact_digest=row.artifact_digest,
                owner_user_id=row.owner_user_id,
                security_reviewer_user_id=row.security_reviewer_user_id,
                mitigation=row.mitigation,
                created_at=row.created_at,
                expires_at=row.expires_at,
                revoked_at=row.revoked_at,
            )

    @router.delete(
        "/workspaces/{ws}/release-exceptions/{exception_id}",
        operation_id="revokeWorkspaceReleaseException",
        tags=["security"],
        status_code=204,
        response_class=Response,
    )
    async def revoke_release_exception(
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        exception_id: Annotated[str, Path(min_length=36, max_length=36)],
        request: Request,
        ctx: Annotated[WorkspaceAccessContext, Depends(_EXCEPTION_WRITE)],
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> Response:
        now = iam.now().astimezone(UTC)
        if ctx.auth.api_token is not None or not is_step_up_fresh(ctx.auth.session, now=now):
            raise ForbiddenError(
                code="step_up_required",
                detail="A recent web-session MFA step-up is required to revoke an exception.",
            )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            row = await db.scalar(
                select(ReleaseExceptionModel)
                .where(
                    ReleaseExceptionModel.workspace_id == ctx.workspace_id,
                    ReleaseExceptionModel.id == exception_id,
                )
                .with_for_update()
            )
            if row is None:
                raise NotFoundError(
                    code="release_exception_not_found", detail="Release exception was not found."
                )
            membership = await db.scalar(
                select(MembershipModel).where(
                    MembershipModel.workspace_id == ctx.workspace_id,
                    MembershipModel.user_id == ctx.auth.user.id,
                    MembershipModel.role == "admin",
                )
            )
            if membership is None:
                raise ForbiddenError(
                    code="insufficient_role", detail="A workspace admin must revoke exceptions."
                )
            if row.revoked_at is None:
                row.revoked_at = now
                await append_audit_entry(
                    db,
                    workspace_id=ctx.workspace_id,
                    actor_type="user",
                    actor_id=ctx.auth.user.id,
                    action="security.release_exception.revoked",
                    target=f"release_exception:{row.id}",
                    decision="allow",
                    reason_code="owner_revoked_exception",
                    correlation_id=getattr(request.state, "correlation_id", "release-exception"),
                    client_ip=extract_client_ip(request),
                    metadata={"artifact_digest": row.artifact_digest},
                    occurred_at=now,
                )
        return Response(status_code=204)

    @router.get(
        "/workspaces/{ws}/security/secrets",
        operation_id="listWorkspaceSecretMetadata",
        tags=["security"],
        response_model=SecretKeyMetadataPage,
    )
    async def list_workspace_secret_metadata(
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        ctx: Annotated[WorkspaceAccessContext, Depends(_SECURITY_METADATA_READ)],
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> SecretKeyMetadataPage:
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            state = await db.scalar(
                select(SecretKeyringStateModel).where(
                    SecretKeyringStateModel.singleton_id == "global"
                )
            )
            if state is None:
                raise DependencyUnavailableError(
                    code="secret_keyring_state_missing",
                    detail=(
                        "Secret key metadata is unavailable until key rotation state "
                        "is initialized."
                    ),
                )
            rows = list(
                (
                    await db.scalars(
                        select(SecretEntryModel)
                        .where(SecretEntryModel.workspace_id == ctx.workspace_id)
                        .order_by(SecretEntryModel.purpose, SecretEntryModel.id)
                        .limit(5000)
                    )
                ).all()
            )
            return SecretKeyMetadataPage(
                active_kek_version=state.active_kek_version,
                items=[
                    SecretKeyMetadata(
                        id=row.id,
                        purpose=cast(SecretPurpose, row.purpose),
                        active_key_version=row.active_key_version,
                        kek_version=row.kek_version,
                        configured=row.revoked_at is None,
                        rotated_at=row.rotated_at,
                        revoked_at=row.revoked_at,
                        created_at=row.created_at,
                        updated_at=row.updated_at,
                    )
                    for row in rows
                ],
            )

    @router.post(
        "/workspaces/{ws}/security/secrets/rotate",
        operation_id="rotateWorkspaceSecretKeys",
        tags=["security"],
        response_model=SecretKeyRotationResult,
    )
    async def rotate_workspace_secret_keys(
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        request: Request,
        ctx: Annotated[WorkspaceAccessContext, Depends(_EXCEPTION_WRITE)],
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> SecretKeyRotationResult:
        now = iam.now().astimezone(UTC)
        if (
            ctx.auth.api_token is not None
            or not ctx.auth.user.is_instance_owner
            or not is_step_up_fresh(ctx.auth.session, now=now)
        ):
            raise ForbiddenError(
                code="step_up_required",
                detail=(
                    "A recent web-session MFA step-up by the instance owner is required "
                    "to rotate the master key."
                ),
            )
        broker = getattr(request.app.state, "notification_secret_broker", None)
        rotate_all = getattr(broker, "rotate_all_secret_keks", None)
        if not callable(rotate_all):
            raise DependencyUnavailableError(
                code="secret_rotation_unavailable",
                detail="The host has not configured the secret broker for key rotation.",
            )
        return cast(
            SecretKeyRotationResult,
            await rotate_all(
                session_factory=iam.session_factory,
                actor_id=ctx.auth.user.id,
                correlation_id=str(getattr(request.state, "correlation_id", "secret-key-rotation")),
                now=now,
            ),
        )

    @router.get(
        "/workspaces/{ws}/analytics",
        operation_id="getWorkspaceAnalytics",
        tags=["analytics"],
        response_model=WorkspaceAnalyticsResponse,
    )
    async def get_analytics(
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
        iam: Annotated[IamService, Depends(get_iam_service)],
        response: Response,
        range_start: Annotated[datetime, Query()],
        range_end: Annotated[datetime, Query()],
        repository_id: Annotated[str | None, Query(max_length=36)] = None,
    ) -> WorkspaceAnalyticsResponse:
        start, end = range_start.astimezone(UTC), range_end.astimezone(UTC)
        if end < start or end - start > timedelta(days=366):
            from red2pr_control.core.errors import UnprocessableEntityError

            raise UnprocessableEntityError(
                code="analytics_range_invalid",
                detail="Analytics range must be ordered and no longer than 366 days.",
            )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            repos = await _live_repository_scope(db, ctx)
            if repository_id is not None and (repos is not None and repository_id not in repos):
                raise NotFoundError(code="repository_not_found", detail="Repository not found.")
            if repository_id:
                repos = frozenset({repository_id})
            rows = await _source_rows(
                db, workspace_id=ctx.workspace_id, repo_ids=repos, start=start, end=end
            )
            repository_count = await _repository_count(
                db, workspace_id=ctx.workspace_id, repo_ids=repos
            )
            payload = _build_payload(
                rows,
                workspace_id=ctx.workspace_id,
                start=start,
                end=end,
                repos=repos,
                now=iam.now(),
            )
            payload["repository_count"] = repository_count
            scope_digest = hashlib.sha256(
                canonical_json_bytes(sorted(repos) if repos is not None else ["workspace-admin"])
            ).hexdigest()
            projection_key = hashlib.sha256(
                canonical_json_bytes(
                    {"scope": scope_digest, "from": start.isoformat(), "to": end.isoformat()}
                )
            ).hexdigest()
            serialized_payload = WorkspaceAnalyticsResponse.model_validate(payload).model_dump(
                mode="json"
            )
            values = {
                "id": new_uuid7(now=iam.now()),
                "workspace_id": ctx.workspace_id,
                "projection_key": projection_key,
                "scope_digest": scope_digest,
                "range_start": start,
                "range_end": end,
                "watermark": payload["watermark"],
                "payload_json": serialized_payload,
                "rebuilt_at": iam.now(),
            }
            stmt = (
                pg_insert(ReportingProjectionModel)
                .values(**values)
                .on_conflict_do_update(
                    index_elements=["workspace_id", "projection_key"],
                    set_={
                        k: v
                        for k, v in values.items()
                        if k not in {"id", "workspace_id", "projection_key"}
                    },
                )
            )
            await db.execute(stmt)
        response.headers["Cache-Control"] = "private, no-store"
        return WorkspaceAnalyticsResponse.model_validate(payload)

    @router.get(
        "/workspaces/{ws}/usage",
        operation_id="getWorkspaceUsage",
        tags=["analytics"],
        response_model=WorkspaceUsageResponse,
    )
    async def get_usage(
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
        iam: Annotated[IamService, Depends(get_iam_service)],
        response: Response,
        range_start: Annotated[datetime, Query()],
        range_end: Annotated[datetime, Query()],
        repository_id: Annotated[str | None, Query(max_length=36)] = None,
    ) -> WorkspaceUsageResponse:
        result = await get_analytics(ws, ctx, iam, response, range_start, range_end, repository_id)
        response.headers["Cache-Control"] = "private, no-store"
        return WorkspaceUsageResponse(
            workspace_id=result.workspace_id,
            range_start=result.range_start,
            range_end=result.range_end,
            costs=result.costs,
            watermark=result.watermark,
        )

    @router.post(
        "/workspaces/{ws}/exports",
        operation_id="createWorkspaceReportExport",
        tags=["analytics"],
        status_code=201,
        response_model=ReportExportReceipt,
    )
    async def create_export(
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        body: ReportExportRequest,
        request: Request,
        response: Response,
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
        iam: Annotated[IamService, Depends(get_iam_service)],
        idempotency_key: Annotated[
            str | None, Header(alias="Idempotency-Key", max_length=120)
        ] = None,
    ) -> ReportExportReceipt:
        if not idempotency_key:
            from red2pr_control.core.errors import UnprocessableEntityError

            raise UnprocessableEntityError(
                code="idempotency_key_required", detail="Report export requires Idempotency-Key."
            )
        if body.kind == "audit" and ctx.effective_role not in _AUDIT_ROLES:
            raise ForbiddenError(
                code="insufficient_role", detail="Audit export requires admin or auditor role."
            )
        if body.kind == "audit":
            checkpoint_store = getattr(request.app.state, "audit_checkpoint_store", None)
            checkpoint_keyring = getattr(request.app.state, "audit_checkpoint_keyring", None)
            if not isinstance(checkpoint_store, ExternalCheckpointStore) or not isinstance(
                checkpoint_keyring, KeyRing
            ):
                raise DependencyUnavailableError(
                    code="audit_verification_unavailable",
                    detail=(
                        "Verified audit export requires its external checkpoint store and keyring."
                    ),
                )
            if not checkpoint_store.list_checkpoints():
                raise DependencyUnavailableError(
                    code="audit_checkpoint_unavailable",
                    detail="No externally signed audit checkpoint is configured.",
                )
            async with instance_rls_session(iam.session_factory, mode="audit_verifier") as audit_db:
                await verify_audit_chain(
                    audit_db,
                    external_store=checkpoint_store,
                    keyring=checkpoint_keyring,
                )
        artifact_store = getattr(request.app.state, "artifact_store", None)
        if artifact_store is None:
            raise DependencyUnavailableError(
                code="artifact_store_unavailable", detail="Encrypted export storage is unavailable."
            )
        now = iam.now().astimezone(UTC)
        start, end = body.range_start.astimezone(UTC), body.range_end.astimezone(UTC)
        pending_finalize: StagedBlobHandle | None = None
        pending_export_id: str | None = None
        pending_storage_ref: str | None = None
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            repos = await _live_repository_scope(db, ctx)
            requested_repo = body.filters.get("repository_id")
            if body.filters.keys() - {"repository_id"}:
                from red2pr_control.core.errors import UnprocessableEntityError

                raise UnprocessableEntityError(
                    code="analytics_filter_invalid",
                    detail="Only repository_id export filter is supported.",
                )
            if requested_repo is not None and repos is not None and requested_repo not in repos:
                raise NotFoundError(code="repository_not_found", detail="Repository not found.")
            if requested_repo:
                repos = frozenset({requested_repo})
            repo_scope = sorted(repos) if repos is not None else ["workspace-admin"]
            scope_digest = hashlib.sha256(canonical_json_bytes(repo_scope)).hexdigest()
            request_data = body.model_dump(mode="json")
            request_digest = hashlib.sha256(canonical_json_bytes(request_data)).hexdigest()
            await db.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                {"key": f"report-export:{ctx.workspace_id}:{ctx.auth.user.id}:{idempotency_key}"},
            )
            existing = await db.scalar(
                select(ReportExportModel).where(
                    ReportExportModel.workspace_id == ctx.workspace_id,
                    ReportExportModel.created_by_user_id == ctx.auth.user.id,
                    ReportExportModel.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if existing.request_digest != request_digest:
                    raise ConflictError(
                        code="idempotency_payload_mismatch",
                        detail="Idempotency-Key was reused with a different export request.",
                    )
                if existing.expires_at <= now:
                    raise GoneError(
                        code="report_export_expired", detail="The report export has expired."
                    )
                result = ReportExportReceipt(
                    export_id=existing.id,
                    kind=cast(ReportKind, existing.kind),
                    format=cast(ReportFormat, existing.format),
                    digest=existing.digest,
                    size_bytes=existing.size_bytes,
                    expires_at=existing.expires_at,
                    download_path=f"/api/v1/workspaces/{ws}/exports/{existing.id}/download",
                    reused=True,
                )
            else:
                rows = await _source_rows(
                    db, workspace_id=ctx.workspace_id, repo_ids=repos, start=start, end=end
                )
                repository_count = await _repository_count(
                    db, workspace_id=ctx.workspace_id, repo_ids=repos
                )
                payload = _build_payload(
                    rows, workspace_id=ctx.workspace_id, start=start, end=end, repos=repos, now=now
                )
                payload["repository_count"] = repository_count
                records = _export_records(body.kind, payload, rows)
                if body.format == "csv":
                    fields = {
                        "funnel": ("denominator", "numerator", "stage", "value"),
                        "usage": (
                            "created_at",
                            "currency",
                            "estimated_cost",
                            "input_tokens",
                            "model_id",
                            "output_tokens",
                            "repair_id",
                            "repository_id",
                            "settled_cost",
                            "status",
                        ),
                        "audit": (
                            "action",
                            "actor_type",
                            "correlation_id",
                            "decision",
                            "entry_hash",
                            "occurred_at",
                            "reason_code",
                            "repository_id",
                            "target",
                        ),
                        "proof_summary": (
                            "created_at",
                            "manifest_digest",
                            "manifest_id",
                            "repair_id",
                            "repository_id",
                            "restricted_artifact_digests",
                        ),
                    }[body.kind]
                    rendered = render_csv(records, fieldnames=fields)
                    content = rendered.encode("utf-8")
                else:
                    rendered = render_json(
                        {
                            "kind": body.kind,
                            "range_start": start,
                            "range_end": end,
                            "data": records,
                            "summary": payload if body.kind == "funnel" else None,
                        }
                    )
                    content = rendered.encode("utf-8")
                if len(content) > _MAX_EXPORT_BYTES:
                    from red2pr_control.core.errors import UnprocessableEntityError

                    raise UnprocessableEntityError(
                        code="report_export_too_large",
                        detail="The scoped export exceeds the 20 MiB limit.",
                    )
                digest = hashlib.sha256(content).hexdigest()
                handle = await artifact_store.stage_upload(
                    workspace_id=ctx.workspace_id,
                    plaintext=content,
                    expected_digest=digest,
                    now=now,
                )
                await artifact_store.verify_staged(handle)
                export_id = new_uuid7(now=now)
                final_ref = handle.final_ref
                pending_finalize = handle
                pending_export_id = export_id
                pending_storage_ref = final_ref
                row = ReportExportModel(
                    id=export_id,
                    workspace_id=ctx.workspace_id,
                    created_by_user_id=ctx.auth.user.id,
                    created_by_role=ctx.membership.role if ctx.membership is not None else "admin",
                    kind=body.kind,
                    format=body.format,
                    range_start=start,
                    range_end=end,
                    repository_ids_json=repo_scope,
                    scope_digest=scope_digest,
                    storage_ref=final_ref,
                    digest=digest,
                    size_bytes=len(content),
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    expires_at=now + _EXPORT_TTL,
                    created_at=now,
                )
                db.add(row)
                await db.flush()
                await append_audit_entry(
                    db,
                    workspace_id=ctx.workspace_id,
                    actor_type="user",
                    actor_id=ctx.auth.user.id,
                    action="report.export.created",
                    target=f"report_export:{export_id}",
                    decision="allow",
                    reason_code="scoped_expiring_export",
                    correlation_id=getattr(request.state, "correlation_id", "analytics-export"),
                    client_ip=extract_client_ip(request),
                    metadata={
                        "kind": body.kind,
                        "format": body.format,
                        "digest": digest,
                        "repositories": len(repos) if repos is not None else "workspace_admin",
                        "expires_at": (now + _EXPORT_TTL).isoformat(),
                    },
                    occurred_at=now,
                )
                result = ReportExportReceipt(
                    export_id=export_id,
                    kind=body.kind,
                    format=body.format,
                    digest=digest,
                    size_bytes=len(content),
                    expires_at=now + _EXPORT_TTL,
                    download_path=f"/api/v1/workspaces/{ws}/exports/{export_id}/download",
                )
        if pending_finalize is not None:
            try:
                finalized_ref = await artifact_store.finalize_staged(pending_finalize)
                if finalized_ref != pending_storage_ref:
                    raise ValueError("ArtifactStore finalized a different storage reference.")
            except Exception as exc:
                if pending_export_id is not None:
                    async with workspace_rls_session(
                        iam.session_factory, workspace_id=ctx.workspace_id
                    ) as db:
                        await db.execute(
                            delete(ReportExportModel).where(
                                ReportExportModel.workspace_id == ctx.workspace_id,
                                ReportExportModel.id == pending_export_id,
                            )
                        )
                if pending_storage_ref is not None:
                    with suppress(Exception):
                        await artifact_store.delete_blob(
                            workspace_id=ctx.workspace_id,
                            storage_ref=pending_storage_ref,
                        )
                        # Unreferenced staged blobs are removed by ArtifactStore's orphan sweeper.
                raise DependencyUnavailableError(
                    code="artifact_store_unavailable",
                    detail="The encrypted report was staged but could not be finalized.",
                ) from exc
        response.headers["Cache-Control"] = "no-store"
        return result

    @router.get(
        "/workspaces/{ws}/exports/{export_id}/download",
        operation_id="downloadWorkspaceReportExport",
        tags=["analytics"],
        response_class=Response,
        responses={
            200: {
                "content": {
                    "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
                }
            }
        },
    )
    async def download_export(
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        export_id: Annotated[str, Path(min_length=36, max_length=36)],
        request: Request,
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> RawResponse:
        artifact_store: ArtifactStoreProtocol | None = getattr(
            request.app.state, "artifact_store", None
        )
        if artifact_store is None:
            raise DependencyUnavailableError(
                code="artifact_store_unavailable", detail="Encrypted export storage is unavailable."
            )
        now = iam.now().astimezone(UTC)
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            repos = await _live_repository_scope(db, ctx)
            row = await db.scalar(
                select(ReportExportModel).where(
                    ReportExportModel.workspace_id == ctx.workspace_id,
                    ReportExportModel.id == export_id,
                )
            )
            if row is None:
                raise NotFoundError(
                    code="report_export_not_found", detail="Report export not found."
                )
            if row.expires_at <= now:
                raise GoneError(
                    code="report_export_expired", detail="The report export has expired."
                )
            if ctx.membership is None or row.created_by_role != ctx.membership.role:
                raise NotFoundError(
                    code="report_export_not_found", detail="Report export not found."
                )
            stored_scope = frozenset(v for v in row.repository_ids_json if v != "workspace-admin")
            if (repos is not None and not stored_scope.issubset(repos)) or (
                repos is not None and "workspace-admin" in row.repository_ids_json
            ):
                raise NotFoundError(
                    code="report_export_not_found", detail="Report export not found."
                )
            if row.kind == "audit" and ctx.effective_role not in _AUDIT_ROLES:
                raise ForbiddenError(
                    code="insufficient_role", detail="Audit export requires admin or auditor role."
                )
            content = await artifact_store.read_verified(
                workspace_id=ctx.workspace_id,
                storage_ref=row.storage_ref,
                expected_digest=row.digest,
            )
            if len(content) != row.size_bytes:
                raise ConflictError(
                    code="report_export_integrity_failed", detail="Export size verification failed."
                )
            await append_audit_entry(
                db,
                workspace_id=ctx.workspace_id,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                action="report.export.downloaded",
                target=f"report_export:{row.id}",
                decision="allow",
                reason_code="live_scope_verified",
                correlation_id=getattr(request.state, "correlation_id", "analytics-download"),
                client_ip=extract_client_ip(request),
                metadata={"kind": row.kind, "digest": row.digest, "size_bytes": row.size_bytes},
                occurred_at=now,
            )
            mime = (
                "text/csv; charset=utf-8"
                if row.format == "csv"
                else "application/json; charset=utf-8"
            )
            filename = f"red2pr-{row.kind}-{row.id}.{row.format}"
        return RawResponse(
            content=content,
            media_type=mime,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "private, no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    return router
