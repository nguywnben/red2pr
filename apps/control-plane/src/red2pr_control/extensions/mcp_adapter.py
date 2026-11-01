"""MCP 2025-11-25 Streamable HTTP adapter with A-19 scoped authorization."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import func, select, text

from py_contracts.evidence import AuditDecision
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
    UnprocessableEntityError,
)
from red2pr_control.core.logging import current_correlation_id
from red2pr_control.core.redaction import DEFAULT_REDACTOR
from red2pr_control.db.base import (
    ArtifactModel,
    AuthRateLimitModel,
    BudgetAccountModel,
    CiRunModel,
    DiagnosticModel,
    EvidenceManifestModel,
    McpApprovalIntentModel,
    RepairSessionModel,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.csrf import validate_request_origin
from red2pr_control.iam.rbac import (
    ADMIN_ONLY_ROLES,
    ALL_WORKSPACE_ROLES,
    WorkspaceAccessContext,
    authorize_workspace_access,
)
from red2pr_control.iam.sessions import IamService, extract_client_ip, is_step_up_fresh
from red2pr_control.inference.diagnosis_agent import to_diagnosis_dto
from red2pr_control.orchestrator.state_machine import RepairSessionStateMachine, to_repair_dto

PROTOCOL_VERSION = "2025-11-25"
_MAX_BODY = 64 * 1024


class _McpError(Exception):
    def __init__(self, code: int, message: str) -> None:
        self.code = code
        self.message = message


class _RequestRecheckArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    repair_id: str = Field(min_length=36, max_length=36)
    reason: str = Field(min_length=1, max_length=500)
    idempotency_key: str = Field(min_length=1, max_length=120)


class _RepairArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    repair_id: str = Field(min_length=36, max_length=36)


class _ApprovalLinkArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    approval_intent_id: str = Field(min_length=36, max_length=36)


class _ApprovalConfirmBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=32, max_length=128)
    workspace_id: str = Field(
        min_length=36,
        max_length=36,
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    )


class _ApprovalPreviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    intent_id: str
    repair_id: str
    reason: str
    expires_at: datetime


def _rpc_result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": "get_repair_status",
            "description": "Read the redacted repair status DTO.",
            "inputSchema": {
                "type": "object",
                "properties": {"repair_id": {"type": "string", "format": "uuid"}},
                "required": ["repair_id"],
                "additionalProperties": False,
            },
        },
        {
            "name": "get_diagnosis",
            "description": "Read the latest redacted diagnosis DTO.",
            "inputSchema": {
                "type": "object",
                "properties": {"repair_id": {"type": "string", "format": "uuid"}},
                "required": ["repair_id"],
                "additionalProperties": False,
            },
        },
        {
            "name": "get_evidence_summary",
            "description": (
                "Read counts and sizes for retained repair evidence, without artifact contents."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"repair_id": {"type": "string", "format": "uuid"}},
                "required": ["repair_id"],
                "additionalProperties": False,
            },
        },
        {
            "name": "request_recheck",
            "description": (
                "Create a one-use web approval intent; this tool does not run a recheck."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repair_id": {"type": "string", "format": "uuid"},
                    "reason": {"type": "string", "minLength": 1, "maxLength": 500},
                    "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 120},
                },
                "required": ["repair_id", "reason", "idempotency_key"],
                "additionalProperties": False,
            },
        },
        {
            "name": "create_web_approval_link",
            "description": "Mint a one-use 15-minute web approval link for an existing intent.",
            "inputSchema": {
                "type": "object",
                "properties": {"approval_intent_id": {"type": "string", "format": "uuid"}},
                "required": ["approval_intent_id"],
                "additionalProperties": False,
            },
        },
    ]


def _iam(request: Request) -> IamService:
    service = getattr(request.app.state, "iam_service", None)
    if not isinstance(service, IamService):
        raise UnauthorizedError(code="unauthenticated", detail="Authentication is required.")
    return service


async def _authorize(
    request: Request, *, intent: bool
) -> tuple[IamService, WorkspaceAccessContext]:
    iam = _iam(request)
    auth = await iam.authenticate_request(
        request,
        require_csrf=False,
        correlation_id=current_correlation_id(),
    )
    token = auth.api_token
    if token is None:
        raise UnauthorizedError(
            code="api_token_required", detail="MCP requires an A-19 bearer token."
        )
    action = "mcp.intent.create" if intent else "mcp.read"
    ctx = await authorize_workspace_access(
        iam.session_factory,
        auth=auth,
        raw_ws=token.workspace_id,
        allowed_roles=ADMIN_ONLY_ROLES if intent else ALL_WORKSPACE_ROLES,
        allow_break_glass=False,
        action=action,
        client_ip=extract_client_ip(request),
        correlation_id=current_correlation_id(),
        now=iam.now(),
    )
    return iam, ctx


def _api_token_id(ctx: WorkspaceAccessContext) -> str:
    token = ctx.auth.api_token
    if token is None:
        raise UnauthorizedError(
            code="api_token_required", detail="MCP requires an A-19 bearer token."
        )
    return str(token.id)


async def _rate_limit(iam: IamService, *, token_id: str, intent: bool) -> None:
    now = iam.now().astimezone(UTC)
    action = "mcp_intent" if intent else "mcp_read"
    limit = 30 if intent else 120
    bucket = hashlib.sha256(token_id.encode("utf-8")).hexdigest()
    async with instance_rls_session(iam.session_factory, mode="instance_only") as db:
        await db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": f"red2pr:{action}:{bucket}"},
        )
        count = int(
            await db.scalar(
                select(func.count())
                .select_from(AuthRateLimitModel)
                .where(
                    AuthRateLimitModel.action == action,
                    AuthRateLimitModel.bucket_key == bucket,
                    AuthRateLimitModel.attempted_at > now - timedelta(minutes=1),
                )
            )
            or 0
        )
        if count >= limit:
            raise ConflictError(code="rate_limit_exceeded", detail="MCP token rate limit exceeded.")
        db.add(
            AuthRateLimitModel(
                id=new_uuid7(now=now),
                action=action,
                bucket_key=bucket,
                attempted_at=now,
                expires_at=now + timedelta(minutes=2),
            )
        )


async def _repair_for_access(
    db: Any, ctx: WorkspaceAccessContext, repair_id: str
) -> RepairSessionModel:
    row = cast(
        RepairSessionModel | None,
        await db.scalar(
            select(RepairSessionModel).where(
                RepairSessionModel.workspace_id == ctx.workspace_id,
                RepairSessionModel.id == repair_id,
            )
        ),
    )
    if row is None or not ctx.can_read_repository(row.repository_id):
        raise NotFoundError(code="repair_not_found", detail="Repair session was not found.")
    return row


async def _record_call(
    iam: IamService,
    ctx: WorkspaceAccessContext,
    *,
    action: str,
    target: str,
    decision: AuditDecision = "allow",
    reason: str = "mcp_tool_call",
) -> None:
    async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
        await append_audit_entry(
            db,
            workspace_id=ctx.workspace_id,
            actor_type="user",
            actor_id=ctx.auth.user.id,
            action=action,
            target=target,
            decision=decision,
            reason_code=reason,
            correlation_id=current_correlation_id(),
            occurred_at=iam.now(),
            metadata={"api_token_id": _api_token_id(ctx)},
        )


def build_mcp_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1/extensions")

    def _enabled(request: Request) -> bool:
        explicit = getattr(request.app.state, "mcp_extension_enabled", False)
        return explicit is True

    @router.post("/mcp", operation_id="postMcpMessage", tags=["extensions"], response_model=None)
    async def mcp_message(request: Request) -> Response | dict[str, Any]:
        if not _enabled(request):
            raise ConflictError(code="extension_disabled", detail="The MCP extension is disabled.")
        iam = _iam(request)
        validate_request_origin(request, public_base_url=iam.public_base_url)
        if (
            request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            != "application/json"
        ):
            raise UnprocessableEntityError(
                code="mcp_content_type_invalid", detail="MCP requests require application/json."
            )
        raw_body = await request.body()
        if len(raw_body) > _MAX_BODY:
            raise UnprocessableEntityError(
                code="mcp_payload_too_large", detail="MCP request exceeds the 64 KiB limit."
            )
        try:
            message = json.loads(raw_body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise UnprocessableEntityError(
                code="mcp_json_invalid", detail="MCP request must contain valid JSON."
            ) from None
        if (
            not isinstance(message, dict)
            or message.get("jsonrpc") != "2.0"
            or not isinstance(message.get("method"), str)
        ):
            return _rpc_error(
                message.get("id") if isinstance(message, dict) else None, -32600, "Invalid Request"
            )
        request_id = message.get("id")
        method = message["method"]
        if (
            method != "initialize"
            and request.headers.get("MCP-Protocol-Version") != PROTOCOL_VERSION
        ):
            raise UnprocessableEntityError(
                code="mcp_protocol_version_invalid",
                detail="MCP-Protocol-Version must be 2025-11-25 after initialize.",
            )
        if method == "notifications/initialized":
            iam, ctx = await _authorize(request, intent=False)
            await _rate_limit(iam, token_id=_api_token_id(ctx), intent=False)
            await _record_call(
                iam, ctx, action="mcp.notifications.initialized", target="mcp:server"
            )
            return Response(status_code=202)
        if method in {"initialize", "ping"}:
            iam, ctx = await _authorize(request, intent=False)
            await _rate_limit(iam, token_id=_api_token_id(ctx), intent=False)
            await _record_call(iam, ctx, action=f"mcp.{method}", target="mcp:server")
            if method == "ping":
                return _rpc_result(request_id, {})
            params = message.get("params") or {}
            if params.get("protocolVersion") != PROTOCOL_VERSION:
                return _rpc_error(request_id, -32602, "Unsupported protocol version")
            return _rpc_result(
                request_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "red2pr", "version": "1.0.0"},
                },
            )
        if method == "tools/list":
            iam, ctx = await _authorize(request, intent=False)
            await _rate_limit(iam, token_id=_api_token_id(ctx), intent=False)
            await _record_call(iam, ctx, action="mcp.tools.list", target="mcp:tools")
            return _rpc_result(request_id, {"tools": _tool_definitions()})
        if method != "tools/call":
            return _rpc_error(request_id, -32601, "Method not found")

        params = message.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return _rpc_error(request_id, -32602, "Invalid tool parameters")
        name = params["name"]
        intent = name in {"request_recheck", "create_web_approval_link"}
        if name not in {tool["name"] for tool in _tool_definitions()}:
            return _rpc_error(request_id, -32602, "Unknown tool")
        iam, ctx = await _authorize(request, intent=intent)
        await _rate_limit(iam, token_id=_api_token_id(ctx), intent=intent)
        args = params.get("arguments", {})
        if not isinstance(args, dict):
            return _rpc_error(request_id, -32602, "Tool arguments must be an object")
        corr = current_correlation_id()
        audit_recorded = False
        try:
            if name in {"get_repair_status", "get_diagnosis", "get_evidence_summary"}:
                parsed_repair = _RepairArgs.model_validate(args)
                async with workspace_rls_session(
                    iam.session_factory, workspace_id=ctx.workspace_id
                ) as db:
                    repair = await _repair_for_access(db, ctx, parsed_repair.repair_id)
                    if name == "get_repair_status":
                        result: dict[str, Any] = to_repair_dto(repair).model_dump(mode="json")
                    elif name == "get_diagnosis":
                        diagnosis = await db.scalar(
                            select(DiagnosticModel)
                            .where(
                                DiagnosticModel.workspace_id == ctx.workspace_id,
                                DiagnosticModel.repair_id == repair.id,
                            )
                            .order_by(DiagnosticModel.created_at.desc(), DiagnosticModel.id.desc())
                            .limit(1)
                        )
                        result = (
                            to_diagnosis_dto(diagnosis).model_dump(
                                mode="json", exclude={"hypotheses"}
                            )
                            if diagnosis
                            else {"diagnosis": None}
                        )
                    else:
                        manifest_count = int(
                            await db.scalar(
                                select(func.count())
                                .select_from(EvidenceManifestModel)
                                .where(
                                    EvidenceManifestModel.workspace_id == ctx.workspace_id,
                                    EvidenceManifestModel.repair_id == repair.id,
                                )
                            )
                            or 0
                        )
                        artifact_rows = (
                            await db.execute(
                                select(
                                    ArtifactModel.kind,
                                    func.count(),
                                    func.coalesce(func.sum(ArtifactModel.size_bytes), 0),
                                )
                                .where(
                                    ArtifactModel.workspace_id == ctx.workspace_id,
                                    ArtifactModel.repository_id == repair.repository_id,
                                    ArtifactModel.run_id == repair.ci_run_id,
                                    ArtifactModel.lifecycle_state == "finalized",
                                )
                                .group_by(ArtifactModel.kind)
                            )
                        ).all()
                        result = {
                            "manifest_count": manifest_count,
                            "artifact_count": sum(int(row[1]) for row in artifact_rows),
                            "total_bytes": sum(int(row[2]) for row in artifact_rows),
                            "artifact_kinds": {str(row[0]): int(row[1]) for row in artifact_rows},
                        }
                await _record_call(
                    iam,
                    ctx,
                    action=f"mcp.tool.{name}",
                    target=f"repair:{parsed_repair.repair_id}",
                )
                audit_recorded = True
                return _rpc_result(
                    request_id,
                    {
                        "content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
                        "structuredContent": result,
                        "isError": False,
                    },
                )
            if name == "request_recheck":
                parsed_recheck = _RequestRecheckArgs.model_validate(args)
                async with workspace_rls_session(
                    iam.session_factory, workspace_id=ctx.workspace_id
                ) as db:
                    repair = await _repair_for_access(db, ctx, parsed_recheck.repair_id)
                    if not ctx.can_act_on_repository(
                        repair.repository_id, allowed_roles=frozenset({"admin", "maintainer"})
                    ):
                        raise NotFoundError(
                            code="repair_not_found", detail="Repair session was not found."
                        )
                    prior = await db.scalar(
                        select(McpApprovalIntentModel).where(
                            McpApprovalIntentModel.workspace_id == ctx.workspace_id,
                            McpApprovalIntentModel.principal_id == ctx.auth.user.id,
                            McpApprovalIntentModel.idempotency_key
                            == parsed_recheck.idempotency_key,
                        )
                    )
                    safe_reason = str(DEFAULT_REDACTOR.redact_text(parsed_recheck.reason))[:500]
                    intent_row: McpApprovalIntentModel
                    if prior is None:
                        intent_row = McpApprovalIntentModel(
                            id=new_uuid7(now=iam.now()),
                            workspace_id=ctx.workspace_id,
                            repository_id=repair.repository_id,
                            repair_id=repair.id,
                            principal_id=ctx.auth.user.id,
                            kind="request_recheck",
                            reason=safe_reason,
                            idempotency_key=parsed_recheck.idempotency_key,
                            correlation_id=corr,
                            state="pending",
                            token_hash=None,
                            expires_at=iam.now() + timedelta(minutes=15),
                            consumed_at=None,
                            result_repair_id=None,
                            created_at=iam.now(),
                        )
                        db.add(intent_row)
                        await db.flush()
                    else:
                        assert prior is not None
                        if prior.repair_id != repair.id or prior.reason != safe_reason:
                            raise ConflictError(
                                code="idempotency_key_reused",
                                detail="Idempotency key was used for a different MCP intent.",
                            )
                        intent_row = prior
                    result = {
                        "approval_intent_id": intent_row.id,
                        "state": intent_row.state,
                        "expires_at": intent_row.expires_at.isoformat(),
                    }
                await _record_call(
                    iam,
                    ctx,
                    action="mcp.tool.request_recheck",
                    target=f"repair:{parsed_recheck.repair_id}",
                )
                audit_recorded = True
                return _rpc_result(
                    request_id,
                    {
                        "content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
                        "structuredContent": result,
                        "isError": False,
                    },
                )
            parsed_link = _ApprovalLinkArgs.model_validate(args)
            async with workspace_rls_session(
                iam.session_factory, workspace_id=ctx.workspace_id
            ) as db:
                link_intent_row = await db.scalar(
                    select(McpApprovalIntentModel)
                    .where(
                        McpApprovalIntentModel.workspace_id == ctx.workspace_id,
                        McpApprovalIntentModel.id == parsed_link.approval_intent_id,
                    )
                    .with_for_update()
                )
                if (
                    link_intent_row is None
                    or link_intent_row.principal_id != ctx.auth.user.id
                    or not ctx.can_read_repository(link_intent_row.repository_id)
                ):
                    raise NotFoundError(
                        code="approval_intent_not_found", detail="Approval intent was not found."
                    )
                if link_intent_row.state != "pending" or link_intent_row.expires_at <= iam.now():
                    raise ConflictError(
                        code="approval_intent_unavailable",
                        detail="Approval intent is expired or already used.",
                    )
                if link_intent_row.token_hash is not None:
                    raise ConflictError(
                        code="approval_link_already_issued",
                        detail="Approval link was already issued once.",
                    )
                raw_token = secrets.token_urlsafe(32)
                link_intent_row.token_hash = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
                result = {
                    "approval_url": (f"/mcp/approval?workspace_id={ctx.workspace_id}#{raw_token}"),
                    "expires_at": link_intent_row.expires_at.isoformat(),
                }
            await _record_call(
                iam,
                ctx,
                action="mcp.tool.create_web_approval_link",
                target=f"mcp_intent:{parsed_link.approval_intent_id}",
            )
            audit_recorded = True
            return _rpc_result(
                request_id,
                {
                    "content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
                    "structuredContent": result,
                    "isError": False,
                },
            )
        except ValidationError:
            await _record_call(
                iam,
                ctx,
                action=f"mcp.tool.{name}",
                target=f"mcp:tool:{name}",
                decision="deny",
                reason="mcp_arguments_invalid",
            )
            return _rpc_error(
                request_id, -32602, "Tool arguments do not match the published schema"
            )
        except (ConflictError, ForbiddenError, NotFoundError, UnprocessableEntityError):
            if not audit_recorded:
                await _record_call(
                    iam,
                    ctx,
                    action=f"mcp.tool.{name}",
                    target=f"mcp:tool:{name}",
                    decision="deny",
                    reason="mcp_tool_rejected",
                )
            raise
        except Exception:
            if not audit_recorded:
                await _record_call(
                    iam,
                    ctx,
                    action=f"mcp.tool.{name}",
                    target=f"mcp:tool:{name}",
                    decision="error",
                    reason="mcp_tool_error",
                )
            raise

    @router.post("/mcp/approval/confirm", operation_id="confirmMcpApproval", tags=["extensions"])
    async def confirm_mcp_approval(body: _ApprovalConfirmBody, request: Request) -> dict[str, Any]:
        if not _enabled(request):
            raise ConflictError(code="extension_disabled", detail="The MCP extension is disabled.")
        iam = _iam(request)
        auth = await iam.authenticate_request(
            request, require_csrf=True, correlation_id=current_correlation_id()
        )
        if auth.api_token is not None or not is_step_up_fresh(auth.session, now=iam.now()):
            raise ForbiddenError(
                code="step_up_required",
                detail="Authenticated browser session with fresh step-up is required.",
            )
        token_hash = hashlib.sha256(body.token.encode("ascii", errors="ignore")).hexdigest()
        ctx = await authorize_workspace_access(
            iam.session_factory,
            auth=auth,
            raw_ws=body.workspace_id,
            allowed_roles=ADMIN_ONLY_ROLES,
            allow_break_glass=False,
            action="repair.action",
            client_ip=extract_client_ip(request),
            correlation_id=current_correlation_id(),
            now=iam.now(),
        )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            intent_row = await db.scalar(
                select(McpApprovalIntentModel)
                .where(
                    McpApprovalIntentModel.workspace_id == ctx.workspace_id,
                    McpApprovalIntentModel.token_hash == token_hash,
                )
                .with_for_update()
            )
            if (
                intent_row is None
                or intent_row.state != "pending"
                or intent_row.expires_at <= iam.now()
            ):
                raise ConflictError(
                    code="approval_intent_unavailable",
                    detail="Approval intent is expired or already used.",
                )
            if not ctx.can_act_on_repository(
                intent_row.repository_id, allowed_roles=frozenset({"admin", "maintainer"})
            ):
                raise NotFoundError(
                    code="approval_intent_not_found", detail="Approval intent was not found."
                )
            repair = await db.scalar(
                select(RepairSessionModel)
                .where(
                    RepairSessionModel.workspace_id == ctx.workspace_id,
                    RepairSessionModel.id == intent_row.repair_id,
                )
                .with_for_update()
            )
            if repair is None:
                raise NotFoundError(code="repair_not_found", detail="Repair session was not found.")
            if repair.state not in {
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
                    CiRunModel.workspace_id == ctx.workspace_id, CiRunModel.id == repair.ci_run_id
                )
            )
            budget = await db.scalar(
                select(BudgetAccountModel).where(
                    BudgetAccountModel.workspace_id == ctx.workspace_id,
                    BudgetAccountModel.id == repair.budget_account_id,
                )
            )
            if run is None or budget is None:
                raise ConflictError(
                    code="retry_dependencies_missing",
                    detail="Repair retry dependencies are unavailable.",
                )
            intent_row.state = "approved"
            result_repair, _created = await RepairSessionStateMachine(
                session_factory=iam.session_factory
            ).create_or_get_session_in_tx(
                db,
                workspace_id=ctx.workspace_id,
                repository_id=repair.repository_id,
                ci_run_id=repair.ci_run_id,
                semantic_trigger_key=f"mcp-recheck:{intent_row.id}",
                base_sha=repair.base_sha,
                target_ref=repair.target_ref,
                policy_revision=repair.policy_revision,
                budget_account_id=budget.id,
                correlation_id=intent_row.correlation_id,
                parent_id=repair.id,
                supersedes_id=repair.id,
                actor=f"user:{auth.user.id}",
            )
            intent_row.state = "consumed"
            intent_row.consumed_at = iam.now()
            intent_row.result_repair_id = result_repair.id
            await append_audit_entry(
                db,
                workspace_id=ctx.workspace_id,
                repository_id=repair.repository_id,
                actor_type="user",
                actor_id=auth.user.id,
                action="mcp.approval.confirm",
                target=f"mcp_intent:{intent_row.id}",
                decision="allow",
                reason_code="web_step_up_confirmed",
                correlation_id=current_correlation_id(),
                occurred_at=iam.now(),
                metadata={"result_repair_id": result_repair.id},
            )
        return {"state": "consumed", "repair_id": result_repair.id}

    @router.post("/mcp/approval/preview", operation_id="previewMcpApproval", tags=["extensions"])
    async def preview_mcp_approval(
        body: _ApprovalConfirmBody, request: Request
    ) -> _ApprovalPreviewResponse:
        if not _enabled(request):
            raise ConflictError(code="extension_disabled", detail="The MCP extension is disabled.")
        iam = _iam(request)
        auth = await iam.authenticate_request(
            request, require_csrf=False, correlation_id=current_correlation_id()
        )
        if auth.api_token is not None:
            raise ForbiddenError(
                code="browser_session_required",
                detail="Approval links must be reviewed in a browser session.",
            )
        token_hash = hashlib.sha256(body.token.encode("ascii", errors="ignore")).hexdigest()
        ctx = await authorize_workspace_access(
            iam.session_factory,
            auth=auth,
            raw_ws=body.workspace_id,
            allowed_roles=ALL_WORKSPACE_ROLES,
            allow_break_glass=False,
            action="mcp.read",
            client_ip=extract_client_ip(request),
            correlation_id=current_correlation_id(),
            now=iam.now(),
        )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            row = await db.scalar(
                select(McpApprovalIntentModel).where(
                    McpApprovalIntentModel.workspace_id == ctx.workspace_id,
                    McpApprovalIntentModel.token_hash == token_hash,
                )
            )
            if (
                row is None
                or row.state != "pending"
                or row.expires_at <= iam.now()
                or not ctx.can_read_repository(row.repository_id)
            ):
                raise NotFoundError(
                    code="approval_intent_not_found", detail="Approval intent was not found."
                )
            return _ApprovalPreviewResponse(
                intent_id=row.id,
                repair_id=row.repair_id,
                reason=row.reason,
                expires_at=row.expires_at,
            )

    return router
