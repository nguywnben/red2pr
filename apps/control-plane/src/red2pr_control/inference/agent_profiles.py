"""A-20 / UI-S11 Bounded Workspace Agent Profiles & S-20 Capability Matrix (`U17`).

Implements `docs/09_AI_AGENT_ORCHESTRATION.md`, `docs/34_SCREEN_AND_INTERACTION_CONTRACTS.md`
(`UI-S11`), `docs/35_API_SPECIFICATION.md` (`A-20`), `SEC-028`, and `SEC-040`:
- Provisions deterministic per-workspace `triage_diagnosis` and `bounded_patch` profiles
  with role-bounded `S-20` tool ceilings (`triage_diagnosis` can never gain `apply_patch`
  or `run_targeted_test`) and zero arbitrary system-prompt override surface.
- Enforces `ETag` / `If-Match` (`412 Precondition Failed`), `S-05` `Idempotency-Key`,
  probed `muse-wonder-1.0` availability checks, and hash-chained `S-17` audit records.
"""

from __future__ import annotations

from datetime import datetime
from typing import cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.models import (
    DEFAULT_MAX_SCHEMA_REPAIR_RETRIES,
    ESCALATION_META_MODEL_ID,
    PRIMARY_META_MODEL_ID,
    AgentProfile,
    AgentProfileRoleKey,
    AgentProfileUpdateRequest,
    AgentProfileUpdateResponse,
    MetaModelId,
    ReasoningEffortLevel,
    ToolCapabilityPolicyItem,
    WorkspaceAgentProfilesResponse,
    validate_supported_meta_model_id,
)
from py_contracts.primitives import new_uuid7
from py_contracts.tools import (
    AGENT_TOOL_NAMES,
    DIAGNOSIS_ALLOWED_TOOLS,
    FORBIDDEN_AGENT_CAPABILITIES,
    PATCH_ALLOWED_TOOLS,
    TOOL_DESCRIPTIONS,
    AgentToolName,
)
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    PreconditionFailedError,
    UnprocessableEntityError,
)
from red2pr_control.db.base import (
    AgentStepModel,
    ModelCapabilitySnapshotModel,
    WorkspaceAgentProfileModel,
)
from red2pr_control.db.idempotency import (
    claim_idempotent_operation,
    complete_idempotent_operation,
    upsert_operation_receipt,
)
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.iam.rbac import (
    ADMIN_ONLY_ROLES,
    ALL_WORKSPACE_ROLES,
    WorkspaceAccessContext,
    enforce_optimistic_version,
)
from red2pr_control.iam.sessions import IamService
from red2pr_control.inference.meta_client import MetaMuseInferenceService
from red2pr_control.inference.tool_broker import to_agent_step_dto

_PROHIBITED_DESCRIPTIONS: dict[str, tuple[str, str]] = {
    "publish": (
        "Direct branch push or PR/MR creation from an agent context.",
        "Publication belongs exclusively to deterministic Z2 Publisher after V-01..V-07.",
    ),
    "merge": (
        "Merging pull/merge requests or bypassing branch protection.",
        "Red2PR never auto-merges or bypasses branch protection (AGENTS.md Principle 3).",
    ),
    "approve": (
        "Self-approving candidate patches, sensitive paths, or test edits.",
        "Human approval is cryptographically bound to human RBAC actors (ADR-015).",
    ),
    "rotate_secret": (
        "Reading, rotating, or exporting SecretBroker credentials or Meta keys.",
        "Agents operate in zero-secret trust boundary (AGENTS.md Principle 2).",
    ),
    "edit_policy": (
        "Modifying repository/workspace policy revisions, denylists, or budgets.",
        "Policies are administrator-controlled outside model reach (SEC-028).",
    ),
    "send_network_request": (
        "Arbitrary outbound HTTP/TCP sockets or webhook calls from agent tools.",
        "All outbound egress is brokered and allowlist-gated (ADR-037).",
    ),
    "run_host_shell": (
        "Arbitrary shell commands or host execution outside reviewed runner profiles.",
        "Execution uses argv-array SandboxJobV1 commands in Z3 sandboxes (SEC-006).",
    ),
}


def build_immutable_tool_matrix() -> list[ToolCapabilityPolicyItem]:
    """Return the canonical `UI-S11` / `SEC-028` allowlisted + prohibited capability matrix."""
    diag_set = set(DIAGNOSIS_ALLOWED_TOOLS)
    patch_set = set(PATCH_ALLOWED_TOOLS)
    items: list[ToolCapabilityPolicyItem] = []
    for tool_name in AGENT_TOOL_NAMES:
        in_diag = tool_name in diag_set
        items.append(
            ToolCapabilityPolicyItem(
                name=tool_name,
                category="s20_allowed",
                description=TOOL_DESCRIPTIONS[tool_name],
                permitted_for_diagnosis=in_diag,
                permitted_for_patch=tool_name in patch_set,
                immutable_reason=(
                    "Read/propose S-20 tool permitted for both diagnosis and patch roles."
                    if in_diag
                    else "Patch-stage S-20 tool; permanently blocked during triage/diagnosis."
                ),
            )
        )
    for forbidden in FORBIDDEN_AGENT_CAPABILITIES:
        desc, reason = _PROHIBITED_DESCRIPTIONS[forbidden]
        items.append(
            ToolCapabilityPolicyItem(
                name=forbidden,
                category="prohibited",
                description=desc,
                permitted_for_diagnosis=False,
                permitted_for_patch=False,
                immutable_reason=reason,
            )
        )
    return items


def _row_to_agent_profile_dto(row: WorkspaceAgentProfileModel) -> AgentProfile:
    role_key = cast(AgentProfileRoleKey, row.role_key)
    ceiling = (
        list(DIAGNOSIS_ALLOWED_TOOLS)
        if role_key == "triage_diagnosis"
        else list(PATCH_ALLOWED_TOOLS)
    )
    filtered_tools: list[AgentToolName] = [t for t in ceiling if t in row.allowed_tools_json]
    if not filtered_tools:
        filtered_tools = list(ceiling)
    return AgentProfile(
        id=row.id,
        workspace_id=row.workspace_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        role_key=role_key,
        display_name=row.display_name,
        description=row.description,
        model_id=cast(MetaModelId, row.model_id),
        escalation_model_id=(
            cast(MetaModelId, row.escalation_model_id)
            if row.escalation_model_id is not None
            else None
        ),
        reasoning_effort=cast(ReasoningEffortLevel, row.reasoning_effort),
        allowed_tools=filtered_tools,
        immutable_role_tool_ceiling=ceiling,
        max_steps=row.max_steps,
        max_tool_calls_per_step=row.max_tool_calls_per_step,
        max_schema_repair_retries=row.max_schema_repair_retries,
        arbitrary_prompt_override_allowed=False,
        enabled=row.enabled,
        updated_by_user_id=row.updated_by_user_id,
    )


def _check_read_access(access: WorkspaceAccessContext) -> None:
    if (
        access.membership is None or access.membership.role not in ALL_WORKSPACE_ROLES
    ) and access.break_glass_grant is None:
        raise ForbiddenError(
            code="insufficient_role",
            detail="Workspace membership is required to inspect agent profiles.",
        )


def _check_admin_access(access: WorkspaceAccessContext) -> None:
    if access.membership is None or access.membership.role not in ADMIN_ONLY_ROLES:
        raise ForbiddenError(
            code="insufficient_role",
            detail="Workspace admin role is required to mutate agent profiles.",
        )


class AgentProfileService:
    """Workspace-scoped `A-20` agent profile registry and bounded configuration service."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        iam_service: IamService,
        meta_inference_service: MetaMuseInferenceService,
    ) -> None:
        self._session_factory = session_factory
        self._iam = iam_service
        self._meta = meta_inference_service

    async def ensure_default_profiles_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        now: datetime,
    ) -> list[WorkspaceAgentProfileModel]:
        rows = list(
            (
                await db.scalars(
                    select(WorkspaceAgentProfileModel)
                    .where(WorkspaceAgentProfileModel.workspace_id == workspace_id)
                    .order_by(WorkspaceAgentProfileModel.role_key.asc())
                )
            ).all()
        )
        by_role = {r.role_key: r for r in rows}

        defaults: tuple[
            tuple[AgentProfileRoleKey, str, str, str | None, str, tuple[str, ...], int],
            ...,
        ] = (
            (
                "triage_diagnosis",
                "Triage & Diagnosis Agent",
                (
                    "Classifies failed CI runs, abstains on unsupported/infra/auth/flaky classes, "
                    "cites immutable log evidence, and proposes Sandbox A reproduction profiles."
                ),
                None,
                "medium",
                DIAGNOSIS_ALLOWED_TOOLS,
                8,
            ),
            (
                "bounded_patch",
                "Bounded Patch Agent",
                (
                    "Proposes minimal root-cause candidate diffs only after ADR-031 Sandbox A "
                    "repro_confirmed, bounded by REP-03 path rules and NFR-06 attempt caps."
                ),
                ESCALATION_META_MODEL_ID,
                "high",
                PATCH_ALLOWED_TOOLS,
                10,
            ),
        )
        created_any = False
        for role_key, name, desc, esc_model, effort, tools, max_steps in defaults:
            if role_key not in by_role:
                new_row = WorkspaceAgentProfileModel(
                    id=new_uuid7(now=now),
                    workspace_id=workspace_id,
                    role_key=role_key,
                    display_name=name,
                    description=desc,
                    model_id=PRIMARY_META_MODEL_ID,
                    escalation_model_id=esc_model,
                    reasoning_effort=effort,
                    allowed_tools_json=list(tools),
                    max_steps=max_steps,
                    max_tool_calls_per_step=4,
                    max_schema_repair_retries=DEFAULT_MAX_SCHEMA_REPAIR_RETRIES,
                    enabled=True,
                    updated_by_user_id=None,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
                db.add(new_row)
                by_role[role_key] = new_row
                created_any = True
        if created_any:
            await db.flush()
        return [by_role["triage_diagnosis"], by_role["bounded_patch"]]

    async def get_profile_for_role(
        self,
        *,
        workspace_id: str,
        role_key: AgentProfileRoleKey,
    ) -> AgentProfile:
        """Load the active `AgentProfile` for internal orchestrator/agent execution."""
        now = self._iam.now()
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            rows = await self.ensure_default_profiles_in_tx(db, workspace_id=workspace_id, now=now)
            for row in rows:
                if row.role_key == role_key:
                    return _row_to_agent_profile_dto(row)
        raise NotFoundError(
            code="agent_profile_not_found",
            detail=f"Agent profile for role {role_key!r} not found.",
        )

    async def _build_profiles_response_in_tx(
        self,
        db: AsyncSession,
        *,
        access: WorkspaceAccessContext,
        now: datetime,
    ) -> WorkspaceAgentProfilesResponse:
        ws_id = access.workspace.id
        rows = await self.ensure_default_profiles_in_tx(db, workspace_id=ws_id, now=now)
        step_rows = list(
            (
                await db.scalars(
                    select(AgentStepModel)
                    .where(AgentStepModel.workspace_id == ws_id)
                    .order_by(AgentStepModel.created_at.desc(), AgentStepModel.id.desc())
                    .limit(30)
                )
            ).all()
        )
        models_state = await self._meta.get_workspace_models(access=access)
        return WorkspaceAgentProfilesResponse(
            workspace_id=ws_id,
            profiles=[_row_to_agent_profile_dto(r) for r in rows],
            tool_matrix=build_immutable_tool_matrix(),
            prohibited_capabilities=list(FORBIDDEN_AGENT_CAPABILITIES),
            recent_steps=[to_agent_step_dto(s) for s in step_rows],
            ready_for_repair_inference=models_state.ready_for_repair_inference,
            suspension_reason=models_state.suspension_reason,
        )

    async def list_workspace_agent_profiles(
        self,
        *,
        access: WorkspaceAccessContext,
    ) -> WorkspaceAgentProfilesResponse:
        _check_read_access(access)
        now = self._iam.now()
        ws_id = access.workspace.id
        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            return await self._build_profiles_response_in_tx(db, access=access, now=now)

    async def get_workspace_agent_profile(
        self,
        *,
        access: WorkspaceAccessContext,
        profile_id: str,
    ) -> AgentProfile:
        _check_read_access(access)
        now = self._iam.now()
        ws_id = access.workspace.id
        target = profile_id.strip()
        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            rows = await self.ensure_default_profiles_in_tx(db, workspace_id=ws_id, now=now)
            for r in rows:
                if r.id == target or r.role_key == target:
                    return _row_to_agent_profile_dto(r)
        raise NotFoundError(
            code="agent_profile_not_found",
            detail=f"Agent profile {target!r} not found in workspace.",
        )

    async def update_workspace_agent_profile(
        self,
        *,
        access: WorkspaceAccessContext,
        profile_id: str,
        payload: AgentProfileUpdateRequest,
        idempotency_key: str,
        if_match: str | None,
        correlation_id: str,
        client_ip: str | None = None,
    ) -> AgentProfileUpdateResponse:
        _check_admin_access(access)
        if (if_match is None or not if_match.strip()) and payload.expected_version is None:
            raise PreconditionFailedError(
                code="missing_if_match",
                detail="PATCH /agent-profiles/{profile_id} requires If-Match or expected_version.",
            )

        now = self._iam.now()
        ws_id = access.workspace.id
        principal_id = access.auth.user.id
        target = profile_id.strip()
        op_name = f"agent_profiles.update:{target}"
        req_dict = payload.model_dump(mode="json")

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            rows = await self.ensure_default_profiles_in_tx(db, workspace_id=ws_id, now=now)
            match_row: WorkspaceAgentProfileModel | None = None
            for candidate in rows:
                if candidate.id == target or candidate.role_key == target:
                    match_row = candidate
                    break
            if match_row is None:
                raise NotFoundError(
                    code="agent_profile_not_found",
                    detail=f"Agent profile {target!r} not found in workspace.",
                )

            logical_effect_key = f"{op_name}:{ws_id}:{idempotency_key}"
            claim = await claim_idempotent_operation(
                db,
                workspace_id=ws_id,
                principal_id=principal_id,
                operation=op_name,
                idempotency_key=idempotency_key,
                request_payload=req_dict,
                logical_effect_key=logical_effect_key,
                resource_id=match_row.id,
                correlation_id=correlation_id,
                now=now,
            )
            if not claim.is_new_claim and claim.cached_response is not None:
                return AgentProfileUpdateResponse.model_validate(claim.cached_response)

            locked = (
                await db.execute(
                    select(WorkspaceAgentProfileModel)
                    .where(
                        WorkspaceAgentProfileModel.workspace_id == ws_id,
                        WorkspaceAgentProfileModel.id == match_row.id,
                    )
                    .with_for_update()
                )
            ).scalar_one()

            enforce_optimistic_version(
                current_version=locked.version,
                if_match_header=if_match,
                expected_version=payload.expected_version,
            )

            role_key = cast(AgentProfileRoleKey, locked.role_key)
            ceiling = (
                set(DIAGNOSIS_ALLOWED_TOOLS)
                if role_key == "triage_diagnosis"
                else set(PATCH_ALLOWED_TOOLS)
            )

            if payload.allowed_tools is not None:
                disallowed = [t for t in payload.allowed_tools if t not in ceiling]
                if disallowed:
                    raise UnprocessableEntityError(
                        code="tool_role_forbidden",
                        detail=(
                            f"Tools {disallowed!r} exceed the immutable ceiling for role "
                            f"{role_key!r} (SEC-028)."
                        ),
                    )
                locked.allowed_tools_json = list(payload.allowed_tools)

            if payload.model_id is not None:
                resolved_model = validate_supported_meta_model_id(payload.model_id)
                if resolved_model == ESCALATION_META_MODEL_ID:
                    latest_wonder = (
                        await db.scalars(
                            select(ModelCapabilitySnapshotModel)
                            .where(
                                ModelCapabilitySnapshotModel.workspace_id == ws_id,
                                ModelCapabilitySnapshotModel.model_id == ESCALATION_META_MODEL_ID,
                            )
                            .order_by(
                                ModelCapabilitySnapshotModel.probed_at.desc(),
                                ModelCapabilitySnapshotModel.id.desc(),
                            )
                            .limit(1)
                        )
                    ).first()
                    if latest_wonder is None or latest_wonder.status != "available":
                        raise ConflictError(
                            code="model_not_probed_available",
                            detail=(
                                "muse-wonder-1.0 cannot be selected until a consented capability "
                                "probe confirms status='available' (ADR-008 / ADR-020)."
                            ),
                        )
                locked.model_id = resolved_model

            if payload.clear_escalation_model:
                locked.escalation_model_id = None
            elif payload.escalation_model_id is not None:
                locked.escalation_model_id = validate_supported_meta_model_id(
                    payload.escalation_model_id
                )

            if payload.reasoning_effort is not None:
                locked.reasoning_effort = payload.reasoning_effort
            if payload.max_steps is not None:
                locked.max_steps = payload.max_steps
            if payload.max_tool_calls_per_step is not None:
                locked.max_tool_calls_per_step = payload.max_tool_calls_per_step
            if payload.max_schema_repair_retries is not None:
                locked.max_schema_repair_retries = payload.max_schema_repair_retries
            if payload.enabled is not None:
                locked.enabled = payload.enabled

            locked.updated_by_user_id = principal_id
            locked.version += 1
            locked.updated_at = now
            await db.flush()

            op_id = claim.receipt.operation_id
            status_url = claim.receipt.status_url or f"/api/v1/operations/{op_id}"
            receipt = await upsert_operation_receipt(
                db,
                operation_id=op_id,
                scope="workspace",
                workspace_id=ws_id,
                principal_id=principal_id,
                required_role="admin",
                operation_kind=op_name,
                resource_id=locked.id,
                state="succeeded",
                correlation_id=correlation_id,
                status_url=status_url,
                logical_effect_key=logical_effect_key,
                result_id=locked.id,
                now=now,
            )
            await append_audit_entry(
                db,
                workspace_id=ws_id,
                actor_type="user",
                actor_id=principal_id,
                action="agent.profile.updated",
                target=f"{locked.role_key}:{locked.id}",
                decision="allow",
                reason_code="profile_updated",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={
                    "role_key": locked.role_key,
                    "model_id": locked.model_id,
                    "max_steps": locked.max_steps,
                    "max_schema_repair_retries": locked.max_schema_repair_retries,
                    "allowed_tools": locked.allowed_tools_json,
                    "enabled": locked.enabled,
                },
                occurred_at=now,
            )

            profile_dto = _row_to_agent_profile_dto(locked)
            full_state = await self._build_profiles_response_in_tx(db, access=access, now=now)
            out = AgentProfileUpdateResponse(
                receipt=receipt,
                profile=profile_dto,
                profiles_state=full_state,
            )
            await complete_idempotent_operation(
                db,
                workspace_id=ws_id,
                operation_id=op_id,
                state="succeeded",
                status_code=200,
                result_id=locked.id,
                response_payload=out.model_dump(mode="json"),
                now=now,
            )
            return out
