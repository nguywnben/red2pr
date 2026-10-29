"""Workspace-scoped repair session and evidence APIs (U19 / A-09 / A-10)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Path, Query, Request
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts import RepairActionRequest, RepairCreateRequest, RepairPageResponse
from py_contracts.primitives import ActionReceipt
from py_contracts.repairs import Repair
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import ConflictError, DependencyUnavailableError, NotFoundError
from red2pr_control.db.base import (
    AgentStepModel,
    BudgetAccountModel,
    CiRunModel,
    DiagnosticModel,
    EvidenceManifestModel,
    IdempotencyRecordModel,
    PatchAttemptModel,
    RepairSessionModel,
    RepositoryPolicyModel,
    ReproductionRunModel,
    VerificationRunModel,
)
from red2pr_control.db.idempotency import (
    claim_idempotent_operation,
    complete_idempotent_operation,
)
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.iam.rbac import (
    ALL_WORKSPACE_ROLES,
    WorkspaceAccessContext,
    compute_query_filter_hash,
    decode_signed_cursor,
    encode_signed_cursor,
    make_workspace_rbac_dependency,
)
from red2pr_control.iam.sessions import IamService
from red2pr_control.orchestrator.state_machine import RepairSessionStateMachine, to_repair_dto

_READ = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="repair.read",
)
_WRITE = make_workspace_rbac_dependency(
    allowed_roles=frozenset({"admin", "maintainer"}),
    require_csrf=True,
    allow_break_glass=False,
    action="repair.action",
)


def _corr(request: Request) -> str:
    return str(getattr(request.state, "correlation_id", "unknown"))


async def _get_repair(db: AsyncSession, wsid: str, rid: str) -> RepairSessionModel:
    row = await db.scalar(
        select(RepairSessionModel).where(
            RepairSessionModel.workspace_id == wsid,
            RepairSessionModel.id == rid,
        )
    )
    if row is None:
        raise NotFoundError(code="repair_not_found", detail="Repair session was not found.")
    return row


def build_repairs_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    @router.get("/workspaces/{ws}/repairs", tags=["repairs"])
    async def list_repairs(
        request: Request,
        ws: Annotated[str, Path()],
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
        state: Annotated[str | None, Query(max_length=32)] = None,
        proof_grade: Annotated[str | None, Query(max_length=32)] = None,
        remote_status: Annotated[str | None, Query(max_length=32)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
    ) -> RepairPageResponse:
        iam = _resolve_iam(request)
        now = iam.now()
        query_hash = compute_query_filter_hash(
            {
                "endpoint": "repairs.list",
                "state": state or "",
                "proof_grade": proof_grade or "",
                "remote_status": remote_status or "",
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
            q = select(RepairSessionModel).where(
                RepairSessionModel.workspace_id == ctx.workspace_id
            )
            if state:
                q = q.where(RepairSessionModel.state == state)
            if proof_grade:
                q = q.where(RepairSessionModel.proof_grade == proof_grade)
            if remote_status:
                q = q.where(RepairSessionModel.remote_status == remote_status)
            if not ctx.has_workspace_wide_repo_read:
                if not ctx.repository_grants:
                    return RepairPageResponse(items=[], next_cursor=None, snapshot_at=now)
                q = q.where(RepairSessionModel.repository_id.in_(ctx.repository_grants))
            if decoded is not None:
                q = q.where(
                    or_(
                        RepairSessionModel.created_at < decoded.created_at,
                        and_(
                            RepairSessionModel.created_at == decoded.created_at,
                            RepairSessionModel.id < decoded.item_id,
                        ),
                    )
                )
            rows = list(
                (
                    await db.scalars(
                        q.order_by(
                            RepairSessionModel.created_at.desc(), RepairSessionModel.id.desc()
                        ).limit(limit + 1)
                    )
                ).all()
            )
            has_more = len(rows) > limit
            rows = rows[:limit]
            next_cursor = (
                encode_signed_cursor(
                    signing_key=iam.csrf_signing_key,
                    workspace_scope=ctx.workspace_id,
                    principal_id=ctx.auth.user.id,
                    grant_epoch=ctx.auth.user.grant_epoch,
                    query_hash=query_hash,
                    created_at=rows[-1].created_at,
                    item_id=rows[-1].id,
                    now=now,
                )
                if has_more and rows
                else None
            )
            return RepairPageResponse(
                items=[to_repair_dto(row) for row in rows],
                next_cursor=next_cursor,
                snapshot_at=now,
            )

    @router.post("/workspaces/{ws}/repairs", status_code=202, tags=["repairs"])
    async def create_repair(
        body: RepairCreateRequest,
        request: Request,
        ws: Annotated[str, Path()],
        ctx: Annotated[WorkspaceAccessContext, Depends(_WRITE)],
        idempotency_key: Annotated[
            str, Header(alias="Idempotency-Key", min_length=1, max_length=120)
        ],
    ) -> ActionReceipt:
        iam = _resolve_iam(request)
        corr = _corr(request)
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            run = await db.scalar(
                select(CiRunModel).where(
                    CiRunModel.workspace_id == ctx.workspace_id, CiRunModel.id == body.run_id
                )
            )
            if run is None or not ctx.can_act_on_repository(
                run.repository_id, allowed_roles=frozenset({"admin", "maintainer"})
            ):
                raise NotFoundError(code="run_not_found", detail="CI run was not found.")
            policy = await db.scalar(
                select(RepositoryPolicyModel)
                .where(
                    RepositoryPolicyModel.workspace_id == ctx.workspace_id,
                    RepositoryPolicyModel.repository_id == run.repository_id,
                )
                .order_by(RepositoryPolicyModel.revision.desc())
                .limit(1)
            )
            if policy is None or policy.paused or policy.mode != body.mode:
                raise ConflictError(
                    code="repair_mode_unavailable",
                    detail="Repository policy does not permit this repair mode.",
                )
            if not run.head_sha_verified or run.conclusion not in {
                "failure",
                "timed_out",
                "action_required",
            }:
                raise ConflictError(
                    code="run_not_repairable",
                    detail="Only verified failed CI runs can start a repair.",
                )
            budget = await db.scalar(
                select(BudgetAccountModel)
                .where(
                    BudgetAccountModel.workspace_id == ctx.workspace_id,
                    BudgetAccountModel.scope_kind.in_(("workspace_daily", "workspace_total")),
                    BudgetAccountModel.cancelled_at.is_(None),
                )
                .order_by(BudgetAccountModel.scope_kind)
                .limit(1)
            )
            if budget is None:
                raise ConflictError(
                    code="repair_budget_unavailable",
                    detail="No active workspace repair budget is configured.",
                )
            if budget.repository_id is not None and budget.repository_id != run.repository_id:
                raise NotFoundError(code="run_not_found", detail="CI run was not found.")
            claim = await claim_idempotent_operation(
                db,
                workspace_id=ctx.workspace_id,
                principal_id=ctx.auth.user.id,
                operation="repair.create",
                idempotency_key=idempotency_key,
                request_payload={
                    "run_id": run.id,
                    "mode": body.mode,
                    "reason": body.reason,
                },
                logical_effect_key=f"repair-create:{run.id}",
                resource_id=run.id,
                status_url=f"/api/v1/workspaces/{ws}/repairs",
                correlation_id=corr,
                now=iam.now(),
            )
            if not claim.is_new_claim:
                return (
                    claim.receipt.model_copy(
                        update={
                            "resource_id": claim.receipt.result_id,
                            "status_url": (
                                f"/api/v1/workspaces/{ws}/repairs/{claim.receipt.result_id}"
                            ),
                        }
                    )
                    if claim.receipt.result_id is not None
                    else claim.receipt
                )
            service = RepairSessionStateMachine(session_factory=iam.session_factory)
            repair, _created = await service.create_or_get_session(
                workspace_id=ctx.workspace_id,
                repository_id=run.repository_id,
                ci_run_id=run.id,
                semantic_trigger_key=f"manual:{run.id}:{idempotency_key}",
                base_sha=run.head_sha,
                target_ref=run.ref,
                policy_revision=policy.revision,
                budget_account_id=budget.id,
                correlation_id=corr,
                actor=f"user:{ctx.auth.user.id}",
            )
            receipt = ActionReceipt(
                operation_id=claim.receipt.operation_id,
                resource_id=repair.id,
                state="succeeded",
                correlation_id=corr,
                status_url=f"/api/v1/workspaces/{ws}/repairs/{repair.id}",
                result_id=repair.id,
            )
            await append_audit_entry(
                db,
                workspace_id=ctx.workspace_id,
                repository_id=run.repository_id,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                action="repair.session.requested",
                target=repair.id,
                decision="allow",
                reason_code="manual_repair_requested",
                correlation_id=corr,
                occurred_at=iam.now(),
                metadata={"mode": body.mode, "reason": body.reason},
            )
            await complete_idempotent_operation(
                db,
                workspace_id=ctx.workspace_id,
                operation_id=claim.receipt.operation_id,
                state="succeeded",
                status_code=200,
                result_id=repair.id,
                response_payload=receipt.model_dump(mode="json"),
                now=iam.now(),
            )
            return receipt

    @router.get("/workspaces/{ws}/repairs/{repair_id}", tags=["repairs"])
    async def get_repair(
        request: Request,
        ws: Annotated[str, Path()],
        repair_id: str,
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
    ) -> Repair:
        async with workspace_rls_session(
            _resolve_iam(request).session_factory, workspace_id=ctx.workspace_id
        ) as db:
            row = await _get_repair(db, ctx.workspace_id, repair_id)
            if not ctx.can_read_repository(row.repository_id):
                raise NotFoundError(code="repair_not_found", detail="Repair session was not found.")
            return to_repair_dto(row)

    @router.post("/workspaces/{ws}/repairs/{repair_id}/actions", tags=["repairs"])
    async def repair_action(
        body: RepairActionRequest,
        request: Request,
        ws: Annotated[str, Path()],
        repair_id: str,
        ctx: Annotated[WorkspaceAccessContext, Depends(_WRITE)],
        idempotency_key: Annotated[
            str, Header(alias="Idempotency-Key", min_length=1, max_length=120)
        ],
    ) -> ActionReceipt:
        iam = _resolve_iam(request)
        corr = _corr(request)
        machine = RepairSessionStateMachine(session_factory=iam.session_factory)
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            row = await _get_repair(db, ctx.workspace_id, repair_id)
            if not ctx.can_act_on_repository(
                row.repository_id, allowed_roles=frozenset({"admin", "maintainer"})
            ):
                raise NotFoundError(code="repair_not_found", detail="Repair session was not found.")
            prior = await db.scalar(
                select(IdempotencyRecordModel).where(
                    IdempotencyRecordModel.workspace_id == ctx.workspace_id,
                    IdempotencyRecordModel.principal_id == ctx.auth.user.id,
                    IdempotencyRecordModel.operation == "repair.action",
                    IdempotencyRecordModel.idempotency_key == idempotency_key,
                )
            )
            if prior is None and row.version != body.expected_version:
                raise ConflictError(
                    code="version_conflict", detail="Repair session version has changed."
                )
            claim = await claim_idempotent_operation(
                db,
                workspace_id=ctx.workspace_id,
                principal_id=ctx.auth.user.id,
                operation="repair.action",
                idempotency_key=idempotency_key,
                request_payload={
                    "repair_id": repair_id,
                    "action": body.action,
                    "reason": body.reason,
                    "expected_version": body.expected_version,
                },
                logical_effect_key=(
                    f"repair-action:{repair_id}:{body.action}:{body.expected_version}"
                ),
                resource_id=repair_id,
                status_url=f"/api/v1/workspaces/{ws}/repairs/{repair_id}",
                correlation_id=corr,
                now=iam.now(),
            )
            if not claim.is_new_claim:
                return (
                    claim.receipt.model_copy(update={"resource_id": claim.receipt.result_id})
                    if claim.receipt.result_id is not None
                    else claim.receipt
                )
        if body.action == "pause":
            repaired = await machine.suspend_session(
                workspace_id=ctx.workspace_id,
                repair_id=repair_id,
                reason="operator_pause",
                requested_by=f"user:{ctx.auth.user.id}",
                expected_version=body.expected_version,
                correlation_id=corr,
            )
        elif body.action == "resume":
            repaired = await machine.resume_session(
                workspace_id=ctx.workspace_id,
                repair_id=repair_id,
                requested_by=f"user:{ctx.auth.user.id}",
                expected_version=body.expected_version,
                correlation_id=corr,
            )
        elif body.action == "cancel":
            repaired = await machine.request_cancel(
                workspace_id=ctx.workspace_id,
                repair_id=repair_id,
                requested_by=f"user:{ctx.auth.user.id}",
                reason_code="operator_cancelled",
                expected_version=body.expected_version,
                correlation_id=corr,
            )
        else:
            async with workspace_rls_session(
                iam.session_factory, workspace_id=ctx.workspace_id
            ) as db:
                parent = await _get_repair(db, ctx.workspace_id, repair_id)
                if parent.version != body.expected_version:
                    raise ConflictError(
                        code="version_conflict",
                        detail="Repair session version has changed.",
                    )
                if parent.state not in {
                    "cancelled",
                    "blocked",
                    "rejected",
                    "needs_human",
                    "diagnosed_only",
                    "unsupported",
                    "repro_unconfirmed",
                    "remote_failed",
                    "remote_unknown",
                }:
                    raise ConflictError(
                        code="retry_requires_terminal_parent",
                        detail="Repair must be terminal before retry.",
                    )
                run = await db.scalar(
                    select(CiRunModel).where(
                        CiRunModel.workspace_id == ctx.workspace_id,
                        CiRunModel.id == parent.ci_run_id,
                    )
                )
                budget = await db.scalar(
                    select(BudgetAccountModel).where(
                        BudgetAccountModel.workspace_id == ctx.workspace_id,
                        BudgetAccountModel.id == parent.budget_account_id,
                    )
                )
                if run is None or budget is None:
                    raise ConflictError(
                        code="retry_dependencies_missing",
                        detail="Repair retry dependencies are unavailable.",
                    )
                repaired, _created = await machine.create_or_get_session(
                    workspace_id=ctx.workspace_id,
                    repository_id=parent.repository_id,
                    ci_run_id=parent.ci_run_id,
                    semantic_trigger_key=f"retry:{repair_id}:{idempotency_key}",
                    base_sha=parent.base_sha,
                    target_ref=parent.target_ref,
                    policy_revision=parent.policy_revision,
                    budget_account_id=budget.id,
                    correlation_id=corr,
                    parent_id=repair_id,
                    supersedes_id=repair_id,
                    actor=f"user:{ctx.auth.user.id}",
                )
        receipt = ActionReceipt(
            operation_id=claim.receipt.operation_id,
            resource_id=repaired.id,
            state="succeeded",
            correlation_id=corr,
            status_url=f"/api/v1/workspaces/{ws}/repairs/{repaired.id}",
            result_id=repaired.id,
        )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            await complete_idempotent_operation(
                db,
                workspace_id=ctx.workspace_id,
                operation_id=claim.receipt.operation_id,
                state="succeeded",
                status_code=200,
                result_id=repaired.id,
                response_payload=receipt.model_dump(mode="json"),
                now=iam.now(),
            )
            await append_audit_entry(
                db,
                workspace_id=ctx.workspace_id,
                repository_id=repaired.repository_id,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                action=f"repair.action.{body.action}",
                target=repaired.id,
                decision="allow",
                reason_code=f"operator_{body.action}",
                correlation_id=corr,
                occurred_at=iam.now(),
                metadata={
                    "reason": body.reason,
                    "expected_version": body.expected_version,
                    "version_after": repaired.version,
                },
            )
        return receipt

    async def evidence_rows(
        iam: IamService, ctx: WorkspaceAccessContext, repair_id: str, kind: str
    ) -> dict[str, object]:
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            repair = await _get_repair(db, ctx.workspace_id, repair_id)
            if not ctx.can_read_repository(repair.repository_id):
                raise NotFoundError(code="repair_not_found", detail="Repair session was not found.")
            items: list[dict[str, object]] = []
            reproduction_items: list[dict[str, object]] = []
            if kind == "diagnosis":
                diagnoses = (
                    await db.scalars(
                        select(DiagnosticModel)
                        .where(
                            DiagnosticModel.workspace_id == ctx.workspace_id,
                            DiagnosticModel.repair_id == repair_id,
                        )
                        .order_by(DiagnosticModel.created_at)
                    )
                ).all()
                items = [
                    {
                        "id": x.id,
                        "class": x.failure_class,
                        "decision": x.decision,
                        "summary": x.summary,
                        "evidence_refs": x.evidence_refs_json,
                        "uncertainties": x.uncertainties_json,
                        "created_at": x.created_at.isoformat(),
                    }
                    for x in diagnoses
                ]
            elif kind == "patches":
                patch_attempts = (
                    await db.scalars(
                        select(PatchAttemptModel)
                        .where(
                            PatchAttemptModel.workspace_id == ctx.workspace_id,
                            PatchAttemptModel.repair_id == repair_id,
                        )
                        .order_by(PatchAttemptModel.attempt_number)
                    )
                ).all()
                items = [
                    {
                        "id": x.id,
                        "attempt": x.attempt_number,
                        "base_sha": x.base_sha,
                        "patch_digest": x.patch_digest,
                        "changed_paths": x.changed_paths_json,
                        "diff_artifact_id": x.diff_artifact_id,
                        "diff_lines_added": x.diff_lines_added,
                        "diff_lines_removed": x.diff_lines_removed,
                        "integrity_outcome": x.integrity_outcome,
                        "created_at": x.created_at.isoformat(),
                    }
                    for x in patch_attempts
                ]
            elif kind == "verification":
                verification_runs = (
                    await db.scalars(
                        select(VerificationRunModel)
                        .where(
                            VerificationRunModel.workspace_id == ctx.workspace_id,
                            VerificationRunModel.repair_id == repair_id,
                        )
                        .order_by(VerificationRunModel.created_at)
                    )
                ).all()
                reproductions = (
                    await db.scalars(
                        select(ReproductionRunModel)
                        .where(
                            ReproductionRunModel.workspace_id == ctx.workspace_id,
                            ReproductionRunModel.repair_id == repair_id,
                        )
                        .order_by(ReproductionRunModel.created_at)
                    )
                ).all()
                reproduction_items = [
                    {
                        "id": run.id,
                        "phase": run.phase,
                        "status": run.status,
                        "base_sha": run.base_sha,
                        "patch_digest": run.patch_digest,
                        "fidelity_grade": run.fidelity_grade,
                        "executed_tests_count": run.executed_tests_count,
                        "passed_tests_count": run.passed_tests_count,
                        "failed_tests_count": run.failed_tests_count,
                        "skipped_tests_count": run.skipped_tests_count,
                        "exit_code": run.exit_code,
                        "termination": run.termination,
                        "failure_reason_code": run.failure_reason_code,
                        "result_digest": run.result_digest,
                        "started_at": run.started_at.isoformat(),
                        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                    }
                    for run in reproductions
                ]
                items = []
                for x in verification_runs:
                    items.append(
                        {
                            "id": x.id,
                            "status": x.status,
                            "proof_grade": x.proof_grade,
                            "patch_digest": x.patch_digest,
                            "gates": x.gates_json,
                            "manifest_id": (
                                await db.scalar(
                                    select(EvidenceManifestModel.id).where(
                                        EvidenceManifestModel.workspace_id == ctx.workspace_id,
                                        EvidenceManifestModel.verification_run_id == x.id,
                                    )
                                )
                            ),
                            "created_at": x.created_at.isoformat(),
                        }
                    )
            else:
                steps = (
                    await db.scalars(
                        select(AgentStepModel)
                        .where(
                            AgentStepModel.workspace_id == ctx.workspace_id,
                            AgentStepModel.repair_id == repair_id,
                        )
                        .order_by(AgentStepModel.created_at)
                    )
                ).all()
                items = [
                    {
                        "id": x.id,
                        "kind": x.step_kind,
                        "status": x.status,
                        "role": x.agent_role,
                        "tool_name": x.tool_name,
                        "deny_reason_code": x.deny_reason_code,
                        "created_at": x.created_at.isoformat(),
                    }
                    for x in steps
                ]
            return {
                "items": items,
                "reproductions": reproduction_items,
                "next_cursor": None,
                "snapshot_at": datetime.now(UTC).isoformat(),
            }

    def evidence_route(kind: str) -> Callable[..., Awaitable[dict[str, object]]]:
        async def endpoint(
            request: Request,
            ws: Annotated[str, Path()],
            repair_id: str,
            ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
        ) -> dict[str, object]:
            return await evidence_rows(_resolve_iam(request), ctx, repair_id, kind)

        return endpoint

    for kind in ("diagnosis", "patches", "verification"):
        router.add_api_route(
            f"/workspaces/{{ws}}/repairs/{{repair_id}}/{kind}",
            evidence_route(kind),
            methods=["GET"],
            tags=["repairs"],
            name=f"get_repair_{kind}",
        )

    @router.get("/workspaces/{ws}/repairs/{repair_id}/timeline", tags=["repairs"])
    async def repair_timeline(
        request: Request,
        ws: Annotated[str, Path()],
        repair_id: str,
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> dict[str, object]:
        from red2pr_control.db.base import AuditLogModel, OutboxEventModel

        async with workspace_rls_session(
            _resolve_iam(request).session_factory, workspace_id=ctx.workspace_id
        ) as db:
            repair = await _get_repair(db, ctx.workspace_id, repair_id)
            if not ctx.can_read_repository(repair.repository_id):
                raise NotFoundError(code="repair_not_found", detail="Repair session was not found.")
            audit = (
                await db.scalars(
                    select(AuditLogModel)
                    .where(
                        AuditLogModel.workspace_id == ctx.workspace_id,
                        AuditLogModel.repository_id == repair.repository_id,
                        AuditLogModel.target == repair_id,
                    )
                    .order_by(AuditLogModel.occurred_at.desc())
                    .limit(limit)
                )
            ).all()
            events = (
                await db.scalars(
                    select(OutboxEventModel)
                    .where(
                        OutboxEventModel.workspace_id == ctx.workspace_id,
                        OutboxEventModel.session_id == repair_id,
                    )
                    .order_by(OutboxEventModel.occurred_at.desc())
                    .limit(limit)
                )
            ).all()
            items = [
                {
                    "at": x.occurred_at.isoformat(),
                    "source": "audit",
                    "type": x.action,
                    "decision": x.decision,
                    "reason_code": x.reason_code,
                    "correlation_id": x.correlation_id,
                }
                for x in audit
            ]
            items += [
                {
                    "at": x.occurred_at.isoformat(),
                    "source": "event",
                    "type": x.event_type,
                    "event_id": x.id,
                    "correlation_id": x.correlation_id,
                }
                for x in events
            ]
            items.sort(key=lambda x: x["at"], reverse=True)
            return {
                "items": items[:limit],
                "next_cursor": None,
                "snapshot_at": datetime.now(UTC).isoformat(),
            }

    return router


def _resolve_iam(request: Request) -> IamService:
    service = getattr(request.app.state, "iam_service", None)
    if not isinstance(service, IamService):
        raise DependencyUnavailableError(
            code="iam_unconfigured", detail="IAM persistence is not configured."
        )
    return service
