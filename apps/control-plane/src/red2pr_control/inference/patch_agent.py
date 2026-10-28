"""Bounded Patch Agent with Non-Waivable ADR-031 Baseline Gate & S-20 Tool Broker (`U17`).

Implements `AGT-02`, `S-11`, `S-12`, `S-19`, `S-20`, `S-22`, `W-05`, `ADR-031`, `ADR-038`,
`SEC-005`, `SEC-007`, `SEC-009`, `SEC-012`, `SEC-028`, and `SEC-032`:
- Enforces double-locked `ADR-031` baseline verification (`RepairSessionModel.state` in
  `{'repro_confirmed', 'verifying'}` with `proof_grade >= 'baseline_confirmed'` AND
  `ReproductionOrchestrator.enforce_adr031_baseline_gate`) before any model invocation or patch
  attempt allocation.
- Mediates all 8 `S-20` tools through `AgentToolBroker` (`agent_role='patch'`), wrapping all
  repository files, diffs, and logs in `UNTRUSTED DATA` boundary blocks (`SEC-005`).
- Caps structured JSON / diff repair retries at `<= 2` within the same `AtomicBudgetLedger`
  session account before abstaining fail-closed to `needs_human` (`SEC-012`).
- Deterministically validates candidate unified diffs against the pinned `base_sha` snapshot,
  `effective_policy.max_diff_lines`, and `evaluate_path_policy` (`HARD_DENIED_PATH_GLOBS`,
  `file_denylist`, `file_allowlist`, `allow_test_edits=False`, `allow_config_edits=False`),
  blocking unauthorized edits with `security.policy.denied` (`SEC-007`, `SEC-028`).
- Stores accepted candidate diffs in `ArtifactStore`, records `PatchAttemptModel` with `S-22`
  `ModelToolProvenance`, transitions `patching -> verifying` while keeping
  `proof_grade == 'baseline_confirmed'` (never self-certifying `locally_verified`), and emits
  `repair.patch.proposed`.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, cast

from pydantic import Field, StrictStr, ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.events import (
    EventEnvelope,
    RepairPhaseEventPayload,
    SecurityIdentityEventPayload,
)
from py_contracts.evidence import ModelToolProvenance
from py_contracts.integrations import EffectiveRepositoryPolicy, RepositoryPolicy
from py_contracts.models import (
    ESCALATION_META_MODEL_ID,
    MetaChatCompletionRequest,
    MetaChatMessage,
    MetaJsonSchemaSpec,
    MetaModelId,
    MetaResponseFormat,
    PatchAttemptRecord,
)
from py_contracts.primitives import (
    BoundedName,
    BoundedText,
    StrictContractModel,
    new_uuid7,
)
from py_contracts.repairs import ContextManifestEntry, Repair
from py_contracts.tools import PATCH_ALLOWED_TOOLS, PatchIntegrityOutcome
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    ConflictError,
    DependencyUnavailableError,
    NotFoundError,
    RateLimitedError,
    UnprocessableEntityError,
)
from red2pr_control.core.redaction import DEFAULT_REDACTOR, REDACTION_VERSION, Redactor
from red2pr_control.db.base import (
    AgentStepModel,
    ArtifactModel,
    DiagnosticModel,
    PatchAttemptModel,
    RepairSessionModel,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.inference.agent_profiles import AgentProfileService
from red2pr_control.inference.budgets import AtomicBudgetLedger, BudgetExceededError
from red2pr_control.inference.meta_client import MetaMuseInferenceService
from red2pr_control.inference.tool_broker import (
    UNTRUSTED_SYSTEM_PREAMBLE,
    AgentToolBroker,
    ExecutionResultLookupCallback,
    ParsedUnifiedDiff,
    RepoSnapshotError,
    RepoSnapshotProvider,
    TargetedTestCallback,
    ToolBrokerSessionContext,
    parse_and_validate_unified_diff,
    persist_context_manifest_in_tx,
    sanitize_and_redact_text,
    wrap_untrusted_repo_data,
)
from red2pr_control.orchestrator.reproducer import (
    ReproductionOrchestrator,
    RunnerProfileRegistry,
)
from red2pr_control.orchestrator.state_machine import (
    PROOF_GRADE_ORDER,
    RepairSessionStateMachine,
    to_repair_dto,
)
from red2pr_control.repositories.glob_guard import (
    PathCanonicalizationError,
    canonicalize_repo_path,
)
from red2pr_control.repositories.policy_engine import (
    PolicyHierarchyContext,
    evaluate_path_policy,
)
from red2pr_control.triage_evidence.artifact_store import (
    ArtifactStoreProtocol,
    persist_encrypted_artifact,
    read_artifact_for_authorized_caller,
)


class _ModelPatchProposalPayload(StrictContractModel):
    """Strict non-recursive structured candidate patch output from Meta Muse."""

    unified_diff: Annotated[StrictStr, Field(min_length=1, max_length=131_072)]
    claimed_root_cause: BoundedText
    changed_paths: Annotated[list[BoundedText], Field(min_length=1, max_length=32)]
    target_test_selection_id: BoundedName | None = None
    uncertainties: Annotated[list[BoundedText], Field(max_length=16)] = Field(default_factory=list)


_PATCH_PROPOSAL_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "unified_diff",
        "claimed_root_cause",
        "changed_paths",
        "target_test_selection_id",
        "uncertainties",
    ],
    "properties": {
        "unified_diff": {"type": "string", "minLength": 1, "maxLength": 131072},
        "claimed_root_cause": {"type": "string", "minLength": 1, "maxLength": 2000},
        "changed_paths": {
            "type": "array",
            "minItems": 1,
            "maxItems": 32,
            "items": {"type": "string"},
        },
        "target_test_selection_id": {"type": ["string", "null"]},
        "uncertainties": {
            "type": "array",
            "maxItems": 16,
            "items": {"type": "string"},
        },
    },
}


@dataclass(frozen=True, slots=True)
class PatchGenerationOutcome:
    """Returned result of invoking `BoundedPatchAgentService.generate_candidate_patch`."""

    repair: Repair
    patch_attempt: PatchAttemptRecord | None


def to_patch_attempt_dto(row: PatchAttemptModel) -> PatchAttemptRecord:
    return PatchAttemptRecord(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        repair_id=row.repair_id,
        attempt=row.attempt_number,
        base_sha=row.base_sha,
        patch_digest=row.patch_digest,
        diff_artifact_id=row.diff_artifact_id,
        changed_paths=list(row.changed_paths_json),
        diff_lines_added=row.diff_lines_added,
        diff_lines_removed=row.diff_lines_removed,
        claimed_root_cause=row.claimed_root_cause,
        target_test_selection_id=row.target_test_selection_id,
        integrity_outcome=cast(PatchIntegrityOutcome, row.integrity_outcome),
        sandbox_reproduction_id=row.sandbox_reproduction_id,
        provenance=[ModelToolProvenance.model_validate(item) for item in row.provenance_json],
    )


class BoundedPatchAgentService:
    """Orchestrates `AGT-02` bounded candidate patch synthesis behind `ADR-031` & `S-20`."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        state_machine: RepairSessionStateMachine,
        reproduction_orchestrator: ReproductionOrchestrator,
        meta_inference_service: MetaMuseInferenceService,
        budget_ledger: AtomicBudgetLedger,
        agent_profile_service: AgentProfileService,
        artifact_store: ArtifactStoreProtocol,
        profile_registry: RunnerProfileRegistry | None = None,
        redactor: Redactor = DEFAULT_REDACTOR,
    ) -> None:
        self._session_factory = session_factory
        self._state_machine = state_machine
        self._reproducer = reproduction_orchestrator
        self._meta = meta_inference_service
        self._budgets = budget_ledger
        self._profiles = agent_profile_service
        self._artifact_store = artifact_store
        self._profile_registry = profile_registry or RunnerProfileRegistry()
        self._redactor = redactor

    async def _record_patch_policy_denial_and_block_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        repository_id: str,
        repair_id: str,
        attempt_number: int,
        step_number: int,
        context_digest: str,
        reason_code: str,
        detail: str,
        model_id: str | None,
        provider_request_id: str | None,
        correlation_id: str,
    ) -> RepairSessionModel:
        now = datetime.now(tz=UTC)
        safe_detail = sanitize_and_redact_text(detail, redactor=self._redactor, max_chars=950)
        db.add(
            AgentStepModel(
                id=new_uuid7(now=now),
                workspace_id=workspace_id,
                repository_id=repository_id,
                repair_id=repair_id,
                agent_role="patch",
                attempt_number=attempt_number,
                step_number=step_number,
                step_kind="policy_denial",
                status="denied",
                context_digest=context_digest,
                deny_reason_code=reason_code[:120],
                deny_explanation=safe_detail,
                model_id=model_id,
                provider_request_id=provider_request_id,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
        await db.flush()

        await enqueue_outbox_event(
            db,
            EventEnvelope(
                event_id=new_uuid7(now=now),
                type="security.policy.denied",
                occurred_at=now,
                workspace_id=workspace_id,
                repository_id=repository_id,
                session_id=repair_id,
                aggregate_id=repair_id,
                aggregate_version=1,
                correlation_id=correlation_id,
                payload=SecurityIdentityEventPayload(
                    target_id=repair_id,
                    reason_code=reason_code[:120],
                ),
            ),
            now=now,
        )
        await append_audit_entry(
            db,
            workspace_id=workspace_id,
            repository_id=repository_id,
            actor_type="service",
            actor_id="agent:patch",
            action="repair.patch.denied",
            target=repair_id,
            decision="deny",
            reason_code=reason_code[:120],
            correlation_id=correlation_id,
            metadata={"attempt_number": attempt_number, "detail": safe_detail},
            occurred_at=now,
            redactor=self._redactor,
        )

        return await self._state_machine.transition_in_tx(
            db,
            workspace_id=workspace_id,
            repair_id=repair_id,
            target_state="blocked",
            reason_code=reason_code[:120],
            status_detail=safe_detail,
            actor="service:patch_agent",
            correlation_id=correlation_id,
        )

    async def generate_candidate_patch(
        self,
        *,
        workspace_id: str,
        repair_id: str,
        snapshot: RepoSnapshotProvider,
        repo_policy: RepositoryPolicy,
        effective_policy: EffectiveRepositoryPolicy,
        policy_ctx: PolicyHierarchyContext,
        correlation_id: str,
        targeted_test_callback: TargetedTestCallback | None = None,
        execution_result_callback: ExecutionResultLookupCallback | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> PatchGenerationOutcome:
        """Synthesize a bounded, policy-verified candidate unified diff (`W-05`, `AGT-02`)."""
        # 1. Pre-flight session state & proof-grade check before any model call or attempt debit
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            repair_row = (
                await db.execute(
                    select(RepairSessionModel)
                    .where(
                        RepairSessionModel.workspace_id == workspace_id,
                        RepairSessionModel.id == repair_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if repair_row is None:
                raise NotFoundError(
                    code="repair_not_found",
                    detail=f"Repair session {repair_id} not found.",
                )

            cur_proof_rank = PROOF_GRADE_ORDER.get(cast(Any, repair_row.proof_grade), 0)
            if (
                repair_row.state not in {"repro_confirmed", "verifying"}
                or cur_proof_rank < PROOF_GRADE_ORDER["baseline_confirmed"]
            ):
                raise ConflictError(
                    code="adr031_baseline_unconfirmed",
                    detail=(
                        f"ADR-031 prohibits candidate patch generation from state "
                        f"{repair_row.state!r} with proof_grade={repair_row.proof_grade!r}."
                    ),
                )

            repository_id = repair_row.repository_id
            ci_run_id = repair_row.ci_run_id
            base_sha = repair_row.base_sha
            policy_revision = repair_row.policy_revision
            budget_account_id = repair_row.budget_account_id
            active_repro_id = repair_row.active_reproduction_id
            latest_diag_id = repair_row.latest_diagnosis_id

            existing_attempts = int(
                await db.scalar(
                    select(func.count(PatchAttemptModel.id)).where(
                        PatchAttemptModel.workspace_id == workspace_id,
                        PatchAttemptModel.repair_id == repair_id,
                    )
                )
                or 0
            )
            attempt_number = existing_attempts + 1

        # 2. Non-waivable ADR-031 Sandbox A baseline reproduction gate (double-lock)
        baseline_repro = await self._reproducer.enforce_adr031_baseline_gate(
            workspace_id=workspace_id,
            repair_id=repair_id,
            correlation_id=correlation_id,
            baseline_reproduction_id=active_repro_id,
            attempted_stage="patch_generation",
        )

        # 3. Check bounded_patch agent profile & max_attempts / AtomicBudgetLedger attempt cap
        profile = await self._profiles.get_profile_for_role(
            workspace_id=workspace_id,
            role_key="bounded_patch",
        )
        if not profile.enabled:
            updated = await self._state_machine.transition_session(
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state="needs_human",
                reason_code="bounded_patch_profile_disabled",
                status_detail=(
                    "Workspace bounded_patch agent profile is disabled; escalating to human review."
                ),
                actor="service:patch_agent",
                correlation_id=correlation_id,
            )
            return PatchGenerationOutcome(repair=updated, patch_attempt=None)

        if attempt_number > effective_policy.max_attempts:
            updated = await self._state_machine.transition_session(
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state="needs_human",
                reason_code="max_patch_attempts_exceeded",
                status_detail=(
                    f"Patch attempt {attempt_number} exceeds effective repository "
                    f"max_attempts={effective_policy.max_attempts}."
                ),
                actor="service:patch_agent",
                correlation_id=correlation_id,
            )
            return PatchGenerationOutcome(repair=updated, patch_attempt=None)

        if budget_account_id is not None:
            try:
                await self._budgets.record_patch_attempt(
                    workspace_id=workspace_id,
                    account_id=budget_account_id,
                    correlation_id=correlation_id,
                    actor_id="agent:patch",
                )
            except BudgetExceededError as exc:
                updated = await self._state_machine.transition_session(
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state="blocked",
                    reason_code="patch_attempt_cap_exceeded",
                    status_detail=sanitize_and_redact_text(
                        exc.detail, redactor=self._redactor, max_chars=950
                    ),
                    actor="service:patch_agent",
                    correlation_id=correlation_id,
                )
                return PatchGenerationOutcome(repair=updated, patch_attempt=None)

        # 4. Transition to `patching` & prepare scrubbed UNTRUSTED DATA context manifest
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            await self._state_machine.transition_in_tx(
                db,
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state="patching",
                reason_code=f"patch_attempt_{attempt_number}_started",
                actor="service:patch_agent",
                correlation_id=correlation_id,
                emit_phase_event=False,
            )

            diag_summary = "Baseline reproduction confirmed."
            if latest_diag_id is not None:
                diag_row = (
                    await db.execute(
                        select(DiagnosticModel).where(
                            DiagnosticModel.workspace_id == workspace_id,
                            DiagnosticModel.id == latest_diag_id,
                        )
                    )
                ).scalar_one_or_none()
                if diag_row is not None:
                    diag_summary = diag_row.summary

            art_rows = list(
                (
                    await db.scalars(
                        select(ArtifactModel)
                        .where(
                            ArtifactModel.workspace_id == workspace_id,
                            ArtifactModel.repository_id == repository_id,
                            ArtifactModel.run_id == ci_run_id,
                            ArtifactModel.lifecycle_state == "finalized",
                        )
                        .order_by(ArtifactModel.created_at.asc(), ArtifactModel.id.asc())
                    )
                ).all()
            )
            session_art_ids = {art.id for art in art_rows}
            now = datetime.now(tz=UTC)
            primary_excerpt = ""
            manifest_entries: list[ContextManifestEntry] = []

            for art in art_rows:
                raw_bytes = await read_artifact_for_authorized_caller(
                    db,
                    store=self._artifact_store,
                    artifact_row=art,
                    now=now,
                )
                decoded = raw_bytes.decode("utf-8", errors="replace")
                scrubbed = sanitize_and_redact_text(
                    decoded, redactor=self._redactor, max_chars=32_000
                )
                if not primary_excerpt:
                    primary_excerpt = scrubbed[:12_000]
                manifest_entries.append(
                    ContextManifestEntry(
                        kind="ci_log",
                        ref_id=art.id,
                        digest=hashlib.sha256(scrubbed.encode("utf-8")).hexdigest(),
                        byte_length=len(scrubbed.encode("utf-8")),
                        truncated=len(decoded) > 32_000,
                    )
                )

            manifest_row = await persist_context_manifest_in_tx(
                db,
                workspace_id=workspace_id,
                repository_id=repository_id,
                repair_id=repair_id,
                base_sha=base_sha,
                policy_revision=policy_revision,
                entries=manifest_entries,
                truncated=any(e.truncated for e in manifest_entries),
                redaction_version=REDACTION_VERSION,
            )
            context_digest = manifest_row.context_digest
            max_existing_step = await db.scalar(
                select(func.max(AgentStepModel.step_number)).where(
                    AgentStepModel.workspace_id == workspace_id,
                    AgentStepModel.repair_id == repair_id,
                )
            )
            initial_step_number = int(max_existing_step or 0) + 1

        # 5. Select primary model (`muse-spark-1.3`) or verified escalation (`muse-wonder-1.0`)
        selected_model: MetaModelId = profile.model_id
        if attempt_number >= 2 and selected_model != ESCALATION_META_MODEL_ID:
            escalated = await self._meta.select_model_for_attempt(
                workspace_id=workspace_id,
                failed_attempts=attempt_number - 1,
            )
            if (
                escalated == ESCALATION_META_MODEL_ID
                and profile.escalation_model_id == ESCALATION_META_MODEL_ID
            ):
                selected_model = ESCALATION_META_MODEL_ID

        wrapped_log_ctx, _ = wrap_untrusted_repo_data(
            primary_excerpt or diag_summary,
            kind="baseline_failure_excerpt",
            source_ref=baseline_repro.id,
            redactor=self._redactor,
        )

        broker_ctx = ToolBrokerSessionContext(
            workspace_id=workspace_id,
            repository_id=repository_id,
            repair_id=repair_id,
            ci_run_id=ci_run_id,
            base_sha=base_sha,
            agent_role="patch",
            attempt_number=attempt_number,
            allowed_tools=frozenset(profile.allowed_tools) & frozenset(PATCH_ALLOWED_TOOLS),
            context_digest=context_digest,
            repo_policy=repo_policy,
            effective_policy=effective_policy,
            policy_ctx=policy_ctx,
            snapshot=snapshot,
            artifact_store=self._artifact_store,
            profile_registry=self._profile_registry,
            correlation_id=correlation_id,
            redactor=self._redactor,
            session_artifact_ids=set(session_art_ids),
            targeted_test_callback=targeted_test_callback,
            execution_result_callback=execution_result_callback,
            next_step_number=initial_step_number,
        )
        tool_broker = AgentToolBroker(ctx=broker_ctx)
        meta_tools = tool_broker.build_meta_tools()
        response_format = MetaResponseFormat(
            type="json_schema",
            json_schema=MetaJsonSchemaSpec.model_validate(
                {
                    "name": "red2pr_patch_proposal_v1",
                    "strict": True,
                    "schema": _PATCH_PROPOSAL_JSON_SCHEMA,
                }
            ),
        )

        messages: list[MetaChatMessage] = [
            MetaChatMessage(
                role="system",
                content=(
                    f"{UNTRUSTED_SYSTEM_PREAMBLE}\n"
                    "You are the Red2PR Bounded Patch Agent. Produce the minimal, root-cause "
                    "unified diff against the pinned base_sha that fixes the reproduced failure "
                    "without weakening or deleting tests, bypassing policy, or exceeding "
                    f"max_diff_lines={effective_policy.max_diff_lines} "
                    f"(allow_test_edits={repo_policy.allow_test_edits}, "
                    f"allow_config_edits={repo_policy.allow_config_edits}). "
                    "Output strict JSON matching red2pr_patch_proposal_v1."
                ),
            ),
            MetaChatMessage(
                role="user",
                content=(
                    f"Repair session: {repair_id} (attempt {attempt_number})\n"
                    f"Pinned base_sha: {base_sha}\n"
                    f"Worktree digest: {snapshot.worktree_digest()}\n"
                    f"Baseline Sandbox A reproduction ID: {baseline_repro.id} "
                    f"(profile={baseline_repro.profile_id}, status={baseline_repro.status})\n"
                    f"Diagnosis summary: {diag_summary}\n\n"
                    f"{wrapped_log_ctx}"
                ),
            ),
        ]

        max_schema_retries = min(2, profile.max_schema_repair_retries)
        schema_retries_used = 0
        steps_used = 0
        provenance_entries: list[ModelToolProvenance] = []
        validated_proposal: _ModelPatchProposalPayload | None = None
        validated_diff: ParsedUnifiedDiff | None = None
        last_model_id: str | None = None
        last_provider_req_id: str | None = None
        security_block_reason: tuple[str, str] | None = None
        budget_exhausted_detail: str | None = None
        abstain_reason_code: str | None = None
        abstain_detail: str | None = None

        while steps_used < profile.max_steps:
            steps_used += 1
            try:
                completion = await self._meta.complete_chat(
                    MetaChatCompletionRequest(
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        repair_id=repair_id,
                        session_budget_account_id=budget_account_id,
                        model_id=selected_model,
                        messages=messages,
                        tools=meta_tools if meta_tools else None,
                        response_format=response_format,
                        max_completion_tokens=2048,
                        reasoning_effort=profile.reasoning_effort,
                        correlation_id=correlation_id,
                    ),
                    cancel_check=cancel_check,
                )
            except (DependencyUnavailableError, RateLimitedError) as exc:
                await self._state_machine.suspend_session(
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    reason="model_unavailable",
                    requested_by="service:patch_agent",
                    correlation_id=correlation_id,
                )
                raise exc
            except BudgetExceededError as exc:
                budget_exhausted_detail = exc.detail
                break
            except UnprocessableEntityError as exc:
                async with workspace_rls_session(
                    self._session_factory, workspace_id=workspace_id
                ) as step_db:
                    now_step = datetime.now(tz=UTC)
                    step_db.add(
                        AgentStepModel(
                            id=new_uuid7(now=now_step),
                            workspace_id=workspace_id,
                            repository_id=repository_id,
                            repair_id=repair_id,
                            agent_role="patch",
                            attempt_number=attempt_number,
                            step_number=broker_ctx.allocate_step_number(),
                            step_kind="schema_repair",
                            status="failed",
                            context_digest=context_digest,
                            deny_reason_code=exc.code[:120],
                            deny_explanation=sanitize_and_redact_text(
                                exc.detail, redactor=self._redactor, max_chars=900
                            ),
                            model_id=selected_model,
                            version=1,
                            created_at=now_step,
                            updated_at=now_step,
                        )
                    )
                    await step_db.flush()

                if schema_retries_used >= max_schema_retries:
                    abstain_reason_code = "sec012_schema_repair_exhausted"
                    abstain_detail = (
                        f"Patch agent output failed strict JSON schema validation after "
                        f"{schema_retries_used} repair retries (SEC-012); escalating to human."
                    )
                    break
                schema_retries_used += 1
                messages.append(
                    MetaChatMessage(
                        role="user",
                        content=(
                            f"SCHEMA_REPAIR_RETRY ({schema_retries_used}/{max_schema_retries}): "
                            f"Your response violated red2pr_patch_proposal_v1 ({exc.code}). "
                            "Return ONLY a valid JSON object with the exact required keys."
                        ),
                    )
                )
                continue

            last_model_id = completion.model_id
            last_provider_req_id = completion.provider_request_id
            provenance_entries.append(completion.provenance)

            async with workspace_rls_session(
                self._session_factory, workspace_id=workspace_id
            ) as step_db:
                now_step = datetime.now(tz=UTC)
                step_db.add(
                    AgentStepModel(
                        id=new_uuid7(now=now_step),
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        repair_id=repair_id,
                        agent_role="patch",
                        attempt_number=attempt_number,
                        step_number=broker_ctx.allocate_step_number(),
                        step_kind="model_call",
                        status="ok",
                        context_digest=context_digest,
                        model_id=completion.model_id,
                        provider_request_id=completion.provider_request_id,
                        usage_record_id=completion.usage_record.id,
                        version=1,
                        created_at=now_step,
                        updated_at=now_step,
                    )
                )
                await step_db.flush()

                if completion.tool_calls:
                    messages.append(
                        MetaChatMessage(
                            role="assistant",
                            content=completion.content,
                            tool_calls=completion.tool_calls[: profile.max_tool_calls_per_step],
                        )
                    )
                    for tc in completion.tool_calls[: profile.max_tool_calls_per_step]:
                        _, serialized_tool_out = await tool_broker.dispatch_meta_tool_call_in_tx(
                            step_db,
                            raw_tool_call=tc,
                        )
                        messages.append(
                            MetaChatMessage(
                                role="tool",
                                tool_call_id=tc.id,
                                name=tc.function.name[:120],
                                content=serialized_tool_out[:65536],
                            )
                        )
                    continue

            # Parse & validate candidate patch payload + unified diff against pinned base_sha
            raw_struct = completion.parsed_structured_output
            if raw_struct is None and completion.content:
                try:
                    loaded_obj = json.loads(completion.content)
                    if isinstance(loaded_obj, dict):
                        raw_struct = loaded_obj
                except json.JSONDecodeError:
                    raw_struct = None

            try:
                if raw_struct is None:
                    raise ValueError("Missing structured JSON object in patch proposal response")
                candidate = _ModelPatchProposalPayload.model_validate(raw_struct)
                parsed_diff = parse_and_validate_unified_diff(
                    candidate.unified_diff,
                    snapshot=snapshot,
                )
            except RepoSnapshotError as exc:
                if exc.security_violation:
                    security_block_reason = (exc.code, exc.detail)
                    break
                # Non-security hunk/context syntax error -> bounded SEC-012 repair retry
                async with workspace_rls_session(
                    self._session_factory, workspace_id=workspace_id
                ) as step_db:
                    now_step = datetime.now(tz=UTC)
                    step_db.add(
                        AgentStepModel(
                            id=new_uuid7(now=now_step),
                            workspace_id=workspace_id,
                            repository_id=repository_id,
                            repair_id=repair_id,
                            agent_role="patch",
                            attempt_number=attempt_number,
                            step_number=broker_ctx.allocate_step_number(),
                            step_kind="schema_repair",
                            status="failed",
                            context_digest=context_digest,
                            deny_reason_code=exc.code[:120],
                            deny_explanation=sanitize_and_redact_text(
                                exc.detail, redactor=self._redactor, max_chars=900
                            ),
                            model_id=completion.model_id,
                            provider_request_id=completion.provider_request_id,
                            usage_record_id=completion.usage_record.id,
                            version=1,
                            created_at=now_step,
                            updated_at=now_step,
                        )
                    )
                    await step_db.flush()

                if schema_retries_used >= max_schema_retries:
                    abstain_reason_code = "sec012_diff_repair_exhausted"
                    abstain_detail = (
                        f"Unified diff failed hunk/context verification ({exc.code}) after "
                        f"{schema_retries_used} repair retries; escalating to human review."
                    )
                    break
                schema_retries_used += 1
                messages.append(
                    MetaChatMessage(role="assistant", content=completion.content or "{}")
                )
                messages.append(
                    MetaChatMessage(
                        role="user",
                        content=(
                            f"SCHEMA_REPAIR_RETRY ({schema_retries_used}/{max_schema_retries}): "
                            f"Unified diff failed validation ({exc.code}: {exc.detail[:240]}). "
                            "Read the exact file lines via read_file and return a valid JSON "
                            "patch proposal."
                        ),
                    )
                )
                continue
            except (ValidationError, ValueError) as exc:
                async with workspace_rls_session(
                    self._session_factory, workspace_id=workspace_id
                ) as step_db:
                    now_step = datetime.now(tz=UTC)
                    step_db.add(
                        AgentStepModel(
                            id=new_uuid7(now=now_step),
                            workspace_id=workspace_id,
                            repository_id=repository_id,
                            repair_id=repair_id,
                            agent_role="patch",
                            attempt_number=attempt_number,
                            step_number=broker_ctx.allocate_step_number(),
                            step_kind="schema_repair",
                            status="failed",
                            context_digest=context_digest,
                            deny_reason_code="patch_proposal_schema_invalid",
                            deny_explanation=sanitize_and_redact_text(
                                str(exc), redactor=self._redactor, max_chars=900
                            ),
                            model_id=completion.model_id,
                            provider_request_id=completion.provider_request_id,
                            usage_record_id=completion.usage_record.id,
                            version=1,
                            created_at=now_step,
                            updated_at=now_step,
                        )
                    )
                    await step_db.flush()

                if schema_retries_used >= max_schema_retries:
                    abstain_reason_code = "sec012_schema_repair_exhausted"
                    abstain_detail = (
                        f"Patch proposal failed schema validation after "
                        f"{schema_retries_used} repair retries (SEC-012); escalating to human."
                    )
                    break
                schema_retries_used += 1
                messages.append(
                    MetaChatMessage(role="assistant", content=completion.content or "{}")
                )
                messages.append(
                    MetaChatMessage(
                        role="user",
                        content=(
                            f"SCHEMA_REPAIR_RETRY ({schema_retries_used}/{max_schema_retries}): "
                            f"Validation error: {str(exc)[:240]}. Return ONLY valid JSON matching "
                            "red2pr_patch_proposal_v1."
                        ),
                    )
                )
                continue

            validated_proposal = candidate
            validated_diff = parsed_diff
            break

        # 6. Deterministic policy enforcement, artifact persistence & state transition
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            if budget_exhausted_detail is not None:
                blocked_row = await self._state_machine.transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state="blocked",
                    reason_code="budget_exhausted_during_patching",
                    status_detail=sanitize_and_redact_text(
                        budget_exhausted_detail, redactor=self._redactor, max_chars=950
                    ),
                    actor="service:patch_agent",
                    correlation_id=correlation_id,
                )
                return PatchGenerationOutcome(repair=to_repair_dto(blocked_row), patch_attempt=None)

            if security_block_reason is not None:
                sec_code, sec_detail = security_block_reason
                blocked_row = await self._record_patch_policy_denial_and_block_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    attempt_number=attempt_number,
                    step_number=broker_ctx.allocate_step_number(),
                    context_digest=context_digest,
                    reason_code=sec_code,
                    detail=sec_detail,
                    model_id=last_model_id,
                    provider_request_id=last_provider_req_id,
                    correlation_id=correlation_id,
                )
                return PatchGenerationOutcome(repair=to_repair_dto(blocked_row), patch_attempt=None)

            if validated_proposal is None or validated_diff is None:
                eff_code = abstain_reason_code or "patch_max_steps_exhausted"
                eff_detail = abstain_detail or (
                    f"Patch agent reached max_steps={profile.max_steps} without producing a "
                    "valid candidate unified diff; escalating to human review."
                )
                now_abs = datetime.now(tz=UTC)
                db.add(
                    AgentStepModel(
                        id=new_uuid7(now=now_abs),
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        repair_id=repair_id,
                        agent_role="patch",
                        attempt_number=attempt_number,
                        step_number=broker_ctx.allocate_step_number(),
                        step_kind="abstention",
                        status="ok",
                        context_digest=context_digest,
                        deny_reason_code=eff_code[:120],
                        deny_explanation=sanitize_and_redact_text(
                            eff_detail, redactor=self._redactor, max_chars=950
                        ),
                        model_id=last_model_id,
                        provider_request_id=last_provider_req_id,
                        version=1,
                        created_at=now_abs,
                        updated_at=now_abs,
                    )
                )
                await db.flush()
                human_row = await self._state_machine.transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state="needs_human",
                    reason_code=eff_code[:120],
                    status_detail=sanitize_and_redact_text(
                        eff_detail, redactor=self._redactor, max_chars=950
                    ),
                    actor="service:patch_agent",
                    correlation_id=correlation_id,
                )
                return PatchGenerationOutcome(repair=to_repair_dto(human_row), patch_attempt=None)

            # Verify declared changed_paths match actual unified_diff changed_paths (SEC-028)
            try:
                declared_canon = {
                    canonicalize_repo_path(p) for p in validated_proposal.changed_paths
                }
            except PathCanonicalizationError as exc:
                blocked_row = await self._record_patch_policy_denial_and_block_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    attempt_number=attempt_number,
                    step_number=broker_ctx.allocate_step_number(),
                    context_digest=context_digest,
                    reason_code=exc.code,
                    detail=exc.detail,
                    model_id=last_model_id,
                    provider_request_id=last_provider_req_id,
                    correlation_id=correlation_id,
                )
                return PatchGenerationOutcome(repair=to_repair_dto(blocked_row), patch_attempt=None)

            actual_canon = set(validated_diff.changed_paths)
            if declared_canon != actual_canon:
                blocked_row = await self._record_patch_policy_denial_and_block_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    attempt_number=attempt_number,
                    step_number=broker_ctx.allocate_step_number(),
                    context_digest=context_digest,
                    reason_code="undeclared_diff_path_mismatch",
                    detail=(
                        f"Declared changed_paths {sorted(declared_canon)} did not match actual "
                        f"unified diff paths {sorted(actual_canon)} (SEC-028)."
                    ),
                    model_id=last_model_id,
                    provider_request_id=last_provider_req_id,
                    correlation_id=correlation_id,
                )
                return PatchGenerationOutcome(repair=to_repair_dto(blocked_row), patch_attempt=None)

            # Enforce max_diff_lines ceiling
            total_changed_lines = validated_diff.lines_added + validated_diff.lines_removed
            if total_changed_lines > effective_policy.max_diff_lines:
                blocked_row = await self._record_patch_policy_denial_and_block_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    attempt_number=attempt_number,
                    step_number=broker_ctx.allocate_step_number(),
                    context_digest=context_digest,
                    reason_code="max_diff_lines_exceeded",
                    detail=(
                        f"Candidate patch modifies {total_changed_lines} lines, exceeding "
                        f"effective max_diff_lines={effective_policy.max_diff_lines}."
                    ),
                    model_id=last_model_id,
                    provider_request_id=last_provider_req_id,
                    correlation_id=correlation_id,
                )
                return PatchGenerationOutcome(repair=to_repair_dto(blocked_row), patch_attempt=None)

            # Enforce 4-layer file policy (hard-deny, denylist, allowlist, test/config toggles)
            for changed_path in validated_diff.changed_paths:
                path_eval = evaluate_path_policy(
                    changed_path,
                    repo_policy=repo_policy,
                    effective_policy=effective_policy,
                    ctx=policy_ctx,
                )
                if path_eval.verdict == "deny":
                    blocked_row = await self._record_patch_policy_denial_and_block_in_tx(
                        db,
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        repair_id=repair_id,
                        attempt_number=attempt_number,
                        step_number=broker_ctx.allocate_step_number(),
                        context_digest=context_digest,
                        reason_code=f"patch_path_{path_eval.category}",
                        detail=path_eval.reason,
                        model_id=last_model_id,
                        provider_request_id=last_provider_req_id,
                        correlation_id=correlation_id,
                    )
                    return PatchGenerationOutcome(
                        repair=to_repair_dto(blocked_row), patch_attempt=None
                    )

            # Persist encrypted candidate diff artifact & PatchAttemptModel
            now_commit = datetime.now(tz=UTC)
            diff_bytes = validated_diff.normalized_diff.encode("utf-8")
            diff_art = await persist_encrypted_artifact(
                db,
                store=self._artifact_store,
                workspace_id=workspace_id,
                repository_id=repository_id,
                run_id=ci_run_id,
                name=f"candidate-patch-attempt-{attempt_number}.diff",
                kind="candidate_patch",
                mime="text/x-diff",
                plaintext=diff_bytes,
                expected_digest=validated_diff.patch_digest,
                redaction_version=REDACTION_VERSION,
                now=now_commit,
            )

            safe_root_cause = sanitize_and_redact_text(
                validated_proposal.claimed_root_cause,
                redactor=self._redactor,
                max_chars=3800,
            )
            attempt_id = new_uuid7(now=now_commit)
            attempt_row = PatchAttemptModel(
                id=attempt_id,
                workspace_id=workspace_id,
                repository_id=repository_id,
                repair_id=repair_id,
                attempt_number=attempt_number,
                base_sha=base_sha,
                patch_digest=validated_diff.patch_digest,
                diff_artifact_id=diff_art.id,
                changed_paths_json=list(validated_diff.changed_paths),
                diff_lines_added=validated_diff.lines_added,
                diff_lines_removed=validated_diff.lines_removed,
                claimed_root_cause=safe_root_cause,
                target_test_selection_id=validated_proposal.target_test_selection_id,
                integrity_outcome="accepted",
                sandbox_reproduction_id=None,
                provenance_json=[p.model_dump(mode="json") for p in provenance_entries],
                version=1,
                created_at=now_commit,
                updated_at=now_commit,
            )
            db.add(attempt_row)
            await db.flush()

            # Transition patching -> verifying WITHOUT promoting proof_grade (AGENTS.md #1)
            verifying_row = await self._state_machine.transition_in_tx(
                db,
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state="verifying",
                patch_attempts_count=attempt_number,
                reason_code=f"candidate_patch_attempt_{attempt_number}_proposed",
                status_detail=safe_root_cause[:950],
                actor="service:patch_agent",
                correlation_id=correlation_id,
                emit_phase_event=False,
            )

            await enqueue_outbox_event(
                db,
                EventEnvelope(
                    event_id=new_uuid7(now=now_commit),
                    type="repair.patch.proposed",
                    occurred_at=now_commit,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    session_id=repair_id,
                    aggregate_id=repair_id,
                    aggregate_version=verifying_row.version,
                    correlation_id=correlation_id,
                    payload=RepairPhaseEventPayload(
                        repair_id=repair_id,
                        state=verifying_row.state,
                        reason_code=f"candidate_patch_attempt_{attempt_number}_proposed",
                    ),
                ),
                now=now_commit,
            )
            await append_audit_entry(
                db,
                workspace_id=workspace_id,
                repository_id=repository_id,
                actor_type="service",
                actor_id="agent:patch",
                action="repair.patch.proposed",
                target=f"{repair_id}:{attempt_id}",
                decision="allow",
                reason_code=f"candidate_patch_attempt_{attempt_number}_proposed",
                correlation_id=correlation_id,
                metadata={
                    "attempt_number": attempt_number,
                    "patch_digest": validated_diff.patch_digest,
                    "changed_paths": list(validated_diff.changed_paths),
                    "diff_lines_added": validated_diff.lines_added,
                    "diff_lines_removed": validated_diff.lines_removed,
                    "model_id": last_model_id,
                    "schema_repair_retries_used": schema_retries_used,
                },
                occurred_at=now_commit,
                redactor=self._redactor,
            )

            return PatchGenerationOutcome(
                repair=to_repair_dto(verifying_row),
                patch_attempt=to_patch_attempt_dto(attempt_row),
            )


__all__ = [
    "BoundedPatchAgentService",
    "PatchGenerationOutcome",
    "to_patch_attempt_dto",
]
