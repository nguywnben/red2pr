"""Hybrid Deterministic + Meta Muse Classification, Abstention & Diagnosis Agent (`U17`).

Implements `TRI-02`, `AGT-02`, `S-11`, `S-19`, `S-20`, `W-04`, `ADR-018`, `ADR-031`,
`ADR-038`, `SEC-005`, `SEC-012`, `SEC-024`, `SEC-028`, and `SEC-032`:
- Stage 1 (Deterministic Triage & Abstention): evaluates repository mode (`monitor` / paused),
  `TRI-03` flaky test classification, deterministic CI log signatures (`auth`, `network`,
  `infra`), and `ADR-018` runner profile eligibility (`FX_UNSUPPORTED` on macOS, Windows,
  GPU/CUDA, `docker:dind`, undeclared secret services, or unsupported ecosystems), abstaining
  with immutable session `evidence_refs` + `EvidenceLineCitation` line bounds and `0` patch
  attempts (`SEC-024`).
- Stage 2 (Bounded Meta Muse `muse-spark-1.3` Diagnosis Loop): mediates all read/propose tool
  calls through `AgentToolBroker` (`S-20`, never granting `apply_patch` or `run_targeted_test`),
  wraps CI logs and repo files in `UNTRUSTED DATA` boundary blocks (`SEC-005`), validates strict
  structured JSON output + session-verified citations, and caps schema-repair retries at `<= 2`
  within the same `AtomicBudgetLedger` session account before abstaining fail-closed to
  `needs_human` (`SEC-012`).
- Coordinates `reproducing -> repro_confirmed` (`proof_grade='baseline_confirmed'`) vs terminal
  `repro_unconfirmed` (`0` patches) per `ADR-031`.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import Field, ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.events import EventEnvelope, RepairPhaseEventPayload
from py_contracts.integrations import EffectiveRepositoryPolicy, RepositoryPolicy
from py_contracts.models import (
    MetaChatCompletionRequest,
    MetaChatMessage,
    MetaJsonSchemaSpec,
    MetaResponseFormat,
)
from py_contracts.primitives import (
    BoundedName,
    BoundedText,
    InternalId,
    StrictContractModel,
    new_uuid7,
)
from py_contracts.repairs import (
    ContextManifest,
    ContextManifestEntry,
    Diagnosis,
    DiagnosisClass,
    DiagnosisDecision,
    DiagnosisHypothesis,
    EvidenceLineCitation,
    HypothesisConfidence,
    Repair,
    RepairState,
)
from py_contracts.tools import DIAGNOSIS_ALLOWED_TOOLS
from py_contracts.worker import ReproductionRunRecord
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
    CiJobModel,
    CiRunModel,
    DiagnosticModel,
    RepairSessionModel,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.inference.agent_profiles import AgentProfileService
from red2pr_control.inference.budgets import BudgetExceededError
from red2pr_control.inference.meta_client import MetaMuseInferenceService
from red2pr_control.inference.tool_broker import (
    UNTRUSTED_SYSTEM_PREAMBLE,
    AgentToolBroker,
    RepoSnapshotProvider,
    ToolBrokerSessionContext,
    persist_context_manifest_in_tx,
    sanitize_and_redact_text,
    to_context_manifest_dto,
    wrap_untrusted_repo_data,
)
from red2pr_control.orchestrator.reproducer import (
    RunnerProfileRegistry,
    select_profile_for_ci_job,
)
from red2pr_control.orchestrator.state_machine import (
    RepairSessionStateMachine,
    to_repair_dto,
)
from red2pr_control.repositories.policy_engine import PolicyHierarchyContext
from red2pr_control.triage_evidence.artifact_store import (
    ArtifactStoreProtocol,
    read_artifact_for_authorized_caller,
)
from red2pr_control.triage_evidence.flaky import extract_failure_signature

_ABSTAIN_MANDATORY_CLASSES: frozenset[DiagnosisClass] = frozenset(
    {"flaky", "infra", "network", "auth", "unsupported", "unknown"}
)

_AUTH_SIGNATURE_RE = re.compile(
    r"("
    r"missing required secret|secret [a-z0-9_.-]+ (?:is )?not (?:set|found|configured)|"
    r"http[ /]1\.[01][\" ]+401\b|401 unauthorized|403 forbidden|bad credentials|"
    r"permission denied \(publickey\)|could not request id-token|oidc token"
    r")",
    re.IGNORECASE,
)

_NETWORK_SIGNATURE_RE = re.compile(
    r"("
    r"enotfound|econnrefused|econnreset|etimedout|"
    r"temporary failure in name resolution|could not resolve host|"
    r"tls handshake timeout|502 bad gateway|503 service unavailable|504 gateway timeout"
    r")",
    re.IGNORECASE,
)

_INFRA_SIGNATURE_RE = re.compile(
    r"("
    r"no space left on device|runner lost communication|"
    r"the runner has received a shutdown signal|"
    r"toomanyrequests: you have reached your pull rate limit|"
    r"docker daemon is not running|pod evicted"
    r")",
    re.IGNORECASE,
)


class _ModelDiagnosisPayload(StrictContractModel):
    """Strict non-recursive structured output contract expected from `muse-spark-1.3`."""

    failure_class: DiagnosisClass
    decision: DiagnosisDecision
    summary: BoundedText
    evidence_artifact_ids: Annotated[list[InternalId], Field(min_length=1, max_length=16)]
    hypothesis_statement: BoundedText
    hypothesis_confidence: HypothesisConfidence
    suspected_paths: Annotated[list[BoundedText], Field(max_length=16)] = Field(
        default_factory=list
    )
    uncertainties: Annotated[list[BoundedText], Field(max_length=16)] = Field(default_factory=list)
    proposed_profile: BoundedName | None = None
    proposed_command_ids: Annotated[list[BoundedName], Field(max_length=8)] = Field(
        default_factory=list
    )


_DIAGNOSIS_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "failure_class",
        "decision",
        "summary",
        "evidence_artifact_ids",
        "hypothesis_statement",
        "hypothesis_confidence",
        "suspected_paths",
        "uncertainties",
        "proposed_profile",
        "proposed_command_ids",
    ],
    "properties": {
        "failure_class": {
            "type": "string",
            "enum": [
                "code_regression",
                "test_defect",
                "config",
                "dependency",
                "flaky",
                "infra",
                "network",
                "auth",
                "unsupported",
                "unknown",
            ],
        },
        "decision": {
            "type": "string",
            "enum": ["continue", "abstain", "human"],
        },
        "summary": {"type": "string", "minLength": 1, "maxLength": 2000},
        "evidence_artifact_ids": {
            "type": "array",
            "minItems": 1,
            "maxItems": 16,
            "items": {"type": "string"},
        },
        "hypothesis_statement": {"type": "string", "minLength": 1, "maxLength": 2000},
        "hypothesis_confidence": {
            "type": "string",
            "enum": ["high", "medium", "low"],
        },
        "suspected_paths": {
            "type": "array",
            "maxItems": 16,
            "items": {"type": "string"},
        },
        "uncertainties": {
            "type": "array",
            "maxItems": 16,
            "items": {"type": "string"},
        },
        "proposed_profile": {"type": ["string", "null"]},
        "proposed_command_ids": {
            "type": "array",
            "maxItems": 8,
            "items": {"type": "string"},
        },
    },
}


@dataclass(frozen=True, slots=True)
class DiagnosisOutcome:
    """Returned result of running hybrid triage & diagnosis on a repair session."""

    repair: Repair
    diagnosis: Diagnosis
    context_manifest: ContextManifest


def to_diagnosis_dto(row: DiagnosticModel) -> Diagnosis:
    return Diagnosis.model_validate(
        {
            "id": row.id,
            "workspace_id": row.workspace_id,
            "repository_id": row.repository_id,
            "version": row.version,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
            "repair_id": row.repair_id,
            "class": row.failure_class,
            "summary": row.summary,
            "evidence_refs": list(row.evidence_refs_json),
            "uncertainties": list(row.uncertainties_json),
            "proposed_profile": row.proposed_profile,
            "proposed_command_ids": list(row.proposed_command_ids_json),
            "hypotheses": [DiagnosisHypothesis.model_validate(h) for h in row.hypotheses_json],
            "evidence_citations": [
                EvidenceLineCitation.model_validate(c) for c in row.evidence_citations_json
            ],
            "fingerprint_hash": row.fingerprint_hash,
            "model_id": row.model_id,
            "schema_repair_retries_used": row.schema_repair_retries_used,
            "deterministic_rule_id": row.deterministic_rule_id,
            "decision": row.decision,
        }
    )


def _locate_citation_in_log(
    *,
    artifact_id: str,
    scrubbed_text: str,
    pattern: re.Pattern[str] | None = None,
) -> EvidenceLineCitation:
    lines = scrubbed_text.splitlines() or [""]
    matched_idx = 0
    if pattern is not None:
        for idx, line in enumerate(lines):
            if pattern.search(line):
                matched_idx = idx
                break
    else:
        for idx, line in enumerate(lines):
            lowered = line.lower()
            if any(tok in lowered for tok in ("fail", "error", "assert", "traceback", "exception")):
                matched_idx = idx
                break
    start_idx = max(0, matched_idx - 1)
    end_idx = min(len(lines), matched_idx + 3)
    excerpt = "\n".join(lines[start_idx:end_idx])
    digest = hashlib.sha256(excerpt.encode("utf-8")).hexdigest()
    return EvidenceLineCitation(
        artifact_id=artifact_id,
        start_line=start_idx + 1,
        end_line=max(start_idx + 1, end_idx),
        excerpt_digest=digest,
    )


def _classify_deterministic_log_failure(
    scrubbed_log: str,
) -> tuple[DiagnosisClass, str, str, re.Pattern[str]] | None:
    if _AUTH_SIGNATURE_RE.search(scrubbed_log):
        return (
            "auth",
            "det_auth_or_missing_secret",
            "CI failure stems from missing credentials, unauthorized registry/API access, "
            "or secret configuration; autonomous code patching cannot resolve credential issues.",
            _AUTH_SIGNATURE_RE,
        )
    if _INFRA_SIGNATURE_RE.search(scrubbed_log):
        return (
            "infra",
            "det_runner_infra_failure",
            "CI failure stems from runner/host infrastructure exhaustion, rate limits, or "
            "daemon interruption; abstaining with zero code patches.",
            _INFRA_SIGNATURE_RE,
        )
    if _NETWORK_SIGNATURE_RE.search(scrubbed_log):
        return (
            "network",
            "det_network_or_registry_outage",
            "CI failure stems from transient DNS, TLS, or upstream package mirror outage; "
            "abstaining with zero code patches.",
            _NETWORK_SIGNATURE_RE,
        )
    return None


class DiagnosisAgentService:
    """Orchestrates `TRI-02` deterministic triage/abstention + `AGT-02` Muse diagnosis."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        state_machine: RepairSessionStateMachine,
        meta_inference_service: MetaMuseInferenceService,
        agent_profile_service: AgentProfileService,
        artifact_store: ArtifactStoreProtocol,
        profile_registry: RunnerProfileRegistry | None = None,
        redactor: Redactor = DEFAULT_REDACTOR,
    ) -> None:
        self._session_factory = session_factory
        self._state_machine = state_machine
        self._meta = meta_inference_service
        self._profiles = agent_profile_service
        self._artifact_store = artifact_store
        self._profile_registry = profile_registry or RunnerProfileRegistry()
        self._redactor = redactor

    async def _advance_to_triaging_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        repair_row: RepairSessionModel,
        correlation_id: str,
    ) -> RepairSessionModel:
        current = repair_row
        if current.state == "received":
            current = await self._state_machine.transition_in_tx(
                db,
                workspace_id=workspace_id,
                repair_id=current.id,
                target_state="authorized",
                reason_code="policy_authorized",
                correlation_id=correlation_id,
                emit_phase_event=False,
            )
        if current.state == "authorized":
            current = await self._state_machine.transition_in_tx(
                db,
                workspace_id=workspace_id,
                repair_id=current.id,
                target_state="collecting",
                reason_code="collecting_evidence",
                correlation_id=correlation_id,
                emit_phase_event=False,
            )
        if current.state == "collecting":
            current = await self._state_machine.transition_in_tx(
                db,
                workspace_id=workspace_id,
                repair_id=current.id,
                target_state="triaging",
                reason_code="triage_started",
                correlation_id=correlation_id,
                emit_phase_event=False,
            )
        if current.state != "triaging":
            raise ConflictError(
                code="invalid_diagnosis_entry_state",
                detail=(
                    f"DiagnosisAgentService requires session in received..triaging, "
                    f"got {current.state!r}."
                ),
            )
        return current

    async def _persist_diagnosis_and_transition_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        repository_id: str,
        repair_id: str,
        failure_class: DiagnosisClass,
        decision: DiagnosisDecision,
        target_state: RepairState,
        summary: str,
        evidence_refs: list[str],
        evidence_citations: list[EvidenceLineCitation],
        hypotheses: list[DiagnosisHypothesis],
        uncertainties: list[str],
        proposed_profile: str | None,
        proposed_command_ids: list[str],
        fingerprint_hash: str | None,
        model_id: str | None,
        provider_request_id: str | None,
        schema_repair_retries_used: int,
        deterministic_rule_id: str | None,
        context_digest: str,
        step_number: int,
        correlation_id: str,
    ) -> tuple[RepairSessionModel, DiagnosticModel]:
        now = datetime.now(tz=UTC)
        safe_summary = sanitize_and_redact_text(summary, redactor=self._redactor, max_chars=3800)
        diag_id = new_uuid7(now=now)
        diag_row = DiagnosticModel(
            id=diag_id,
            workspace_id=workspace_id,
            repository_id=repository_id,
            repair_id=repair_id,
            failure_class=failure_class,
            decision=decision,
            summary=safe_summary,
            evidence_refs_json=list(dict.fromkeys(evidence_refs)),
            evidence_citations_json=[c.model_dump(mode="json") for c in evidence_citations],
            hypotheses_json=[h.model_dump(mode="json") for h in hypotheses],
            uncertainties_json=[
                sanitize_and_redact_text(u, redactor=self._redactor, max_chars=500)
                for u in uncertainties
            ],
            proposed_profile=proposed_profile,
            proposed_command_ids_json=list(proposed_command_ids),
            fingerprint_hash=fingerprint_hash,
            model_id=model_id,
            provider_request_id=provider_request_id,
            schema_repair_retries_used=schema_repair_retries_used,
            deterministic_rule_id=deterministic_rule_id,
            version=1,
            created_at=now,
            updated_at=now,
        )
        db.add(diag_row)
        await db.flush()

        if decision in ("abstain", "human"):
            db.add(
                AgentStepModel(
                    id=new_uuid7(now=now),
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    agent_role="diagnosis",
                    attempt_number=0,
                    step_number=step_number,
                    step_kind="abstention",
                    status="ok",
                    context_digest=context_digest,
                    deny_reason_code=deterministic_rule_id or failure_class,
                    deny_explanation=safe_summary[:1000],
                    model_id=model_id,
                    provider_request_id=provider_request_id,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            await db.flush()

        updated_repair = await self._state_machine.transition_in_tx(
            db,
            workspace_id=workspace_id,
            repair_id=repair_id,
            target_state=target_state,
            reason_code=deterministic_rule_id or f"diagnosed_{failure_class}",
            status_detail=safe_summary[:950],
            latest_diagnosis_id=diag_id,
            actor="service:diagnosis_agent",
            correlation_id=correlation_id,
            emit_phase_event=False,
        )

        await enqueue_outbox_event(
            db,
            EventEnvelope(
                event_id=new_uuid7(now=now),
                type="repair.diagnosed",
                occurred_at=now,
                workspace_id=workspace_id,
                repository_id=repository_id,
                session_id=repair_id,
                aggregate_id=repair_id,
                aggregate_version=updated_repair.version,
                correlation_id=correlation_id,
                payload=RepairPhaseEventPayload(
                    repair_id=repair_id,
                    state=updated_repair.state,
                    reason_code=(deterministic_rule_id or failure_class)[:120],
                ),
            ),
            now=now,
        )
        await append_audit_entry(
            db,
            workspace_id=workspace_id,
            repository_id=repository_id,
            actor_type="service",
            actor_id="agent:diagnosis",
            action="repair.diagnosed",
            target=f"{repair_id}:{diag_id}",
            decision="allow",
            reason_code=(deterministic_rule_id or failure_class)[:120],
            correlation_id=correlation_id,
            metadata={
                "failure_class": failure_class,
                "decision": decision,
                "target_state": target_state,
                "evidence_refs": evidence_refs,
                "schema_repair_retries_used": schema_repair_retries_used,
            },
            occurred_at=now,
            redactor=self._redactor,
        )
        return updated_repair, diag_row

    async def run_triage_and_diagnosis(
        self,
        *,
        workspace_id: str,
        repair_id: str,
        snapshot: RepoSnapshotProvider,
        repo_policy: RepositoryPolicy,
        effective_policy: EffectiveRepositoryPolicy,
        policy_ctx: PolicyHierarchyContext,
        declared_capabilities: Sequence[str] = (),
        custom_profile_admin_opt_in: bool = False,
        correlation_id: str,
        cancel_check: Callable[[], bool] | None = None,
    ) -> DiagnosisOutcome:
        """Execute Stage 1 deterministic triage + Stage 2 bounded Meta Muse diagnosis."""
        profile = await self._profiles.get_profile_for_role(
            workspace_id=workspace_id,
            role_key="triage_diagnosis",
        )

        # Load run, jobs, and log artifacts inside workspace RLS
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

            repair_row = await self._advance_to_triaging_in_tx(
                db,
                workspace_id=workspace_id,
                repair_row=repair_row,
                correlation_id=correlation_id,
            )
            repository_id = repair_row.repository_id
            ci_run_id = repair_row.ci_run_id
            base_sha = repair_row.base_sha
            policy_revision = repair_row.policy_revision
            budget_account_id = repair_row.budget_account_id
            max_existing_step = await db.scalar(
                select(func.max(AgentStepModel.step_number)).where(
                    AgentStepModel.workspace_id == workspace_id,
                    AgentStepModel.repair_id == repair_id,
                )
            )
            initial_step_number = int(max_existing_step or 0) + 1

            run_row = (
                await db.execute(
                    select(CiRunModel).where(
                        CiRunModel.workspace_id == workspace_id,
                        CiRunModel.id == ci_run_id,
                    )
                )
            ).scalar_one_or_none()
            if run_row is None:
                raise NotFoundError(
                    code="ci_run_not_found",
                    detail=f"CI run {ci_run_id} not found.",
                )

            job_rows = list(
                (
                    await db.scalars(
                        select(CiJobModel)
                        .where(
                            CiJobModel.workspace_id == workspace_id,
                            CiJobModel.run_id == ci_run_id,
                        )
                        .order_by(CiJobModel.created_at.asc(), CiJobModel.id.asc())
                    )
                ).all()
            )
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

            now = datetime.now(tz=UTC)
            manifest_entries: list[ContextManifestEntry] = []
            log_texts_by_artifact: dict[str, str] = {}
            combined_scrubbed_logs: list[str] = []

            for art in art_rows:
                raw_bytes = await read_artifact_for_authorized_caller(
                    db,
                    store=self._artifact_store,
                    artifact_row=art,
                    now=now,
                )
                decoded = raw_bytes.decode("utf-8", errors="replace")
                scrubbed = sanitize_and_redact_text(
                    decoded, redactor=self._redactor, max_chars=48_000
                )
                log_texts_by_artifact[art.id] = scrubbed
                combined_scrubbed_logs.append(scrubbed)
                manifest_entries.append(
                    ContextManifestEntry(
                        kind="ci_log",
                        ref_id=art.id,
                        digest=hashlib.sha256(scrubbed.encode("utf-8")).hexdigest(),
                        byte_length=len(scrubbed.encode("utf-8")),
                        truncated=len(decoded) > 48_000,
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
            manifest_dto = to_context_manifest_dto(manifest_row)

            # Session must have at least one verified CI artifact to cite evidence (AGENTS.md #1)
            if not art_rows:
                updated_rep, diag_row = await self._persist_diagnosis_and_transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    failure_class="unknown",
                    decision="human",
                    target_state="needs_human",
                    summary=(
                        "No finalized CI log artifacts were available for evidence-backed "
                        "diagnosis; escalating to human review without patching."
                    ),
                    evidence_refs=[],
                    evidence_citations=[],
                    hypotheses=[],
                    uncertainties=["CI log artifacts were missing or unavailable."],
                    proposed_profile=None,
                    proposed_command_ids=[],
                    fingerprint_hash=None,
                    model_id=None,
                    provider_request_id=None,
                    schema_repair_retries_used=0,
                    deterministic_rule_id="missing_ci_log_evidence",
                    context_digest=manifest_row.context_digest,
                    step_number=initial_step_number,
                    correlation_id=correlation_id,
                )
                return DiagnosisOutcome(
                    repair=to_repair_dto(updated_rep),
                    diagnosis=to_diagnosis_dto(diag_row),
                    context_manifest=manifest_dto,
                )

            primary_art_id = art_rows[0].id
            full_log_text = "\n".join(combined_scrubbed_logs)
            failed_job = next(
                (
                    j
                    for j in job_rows
                    if j.conclusion in ("failure", "timed_out", "action_required")
                ),
                job_rows[0] if job_rows else None,
            )
            job_name = failed_job.name if failed_job is not None else "ci-job"
            extracted_sig = extract_failure_signature(
                full_log_text,
                job_name=job_name,
                redactor=self._redactor,
            )
            fp_hash = extracted_sig.fingerprint_hash if extracted_sig is not None else None

            # 1a. Monitor-only or paused repository mode -> deterministic abstain (0 model calls)
            if effective_policy.effective_mode == "monitor" or effective_policy.effective_paused:
                citation = _locate_citation_in_log(
                    artifact_id=primary_art_id,
                    scrubbed_text=log_texts_by_artifact[primary_art_id],
                )
                rule_id = (
                    "policy_paused_abstain"
                    if effective_policy.effective_paused
                    else "policy_monitor_mode"
                )
                updated_rep, diag_row = await self._persist_diagnosis_and_transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    failure_class="code_regression",
                    decision="abstain",
                    target_state="diagnosed_only",
                    summary=(
                        "Repository policy is in monitor/paused mode; recorded deterministic "
                        "triage summary and abstained with zero sandbox or patch execution."
                    ),
                    evidence_refs=[primary_art_id],
                    evidence_citations=[citation],
                    hypotheses=[],
                    uncertainties=[],
                    proposed_profile=None,
                    proposed_command_ids=[],
                    fingerprint_hash=fp_hash,
                    model_id=None,
                    provider_request_id=None,
                    schema_repair_retries_used=0,
                    deterministic_rule_id=rule_id,
                    context_digest=manifest_row.context_digest,
                    step_number=initial_step_number,
                    correlation_id=correlation_id,
                )
                return DiagnosisOutcome(
                    repair=to_repair_dto(updated_rep),
                    diagnosis=to_diagnosis_dto(diag_row),
                    context_manifest=manifest_dto,
                )

            # 1b. TRI-03 Flaky failure classification -> deterministic abstain (0 patch attempts)
            job_flaky = any(j.flaky_classification == "flaky" for j in job_rows)
            if run_row.flaky_classification == "flaky" or job_flaky:
                citation = _locate_citation_in_log(
                    artifact_id=primary_art_id,
                    scrubbed_text=log_texts_by_artifact[primary_art_id],
                )
                updated_rep, diag_row = await self._persist_diagnosis_and_transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    failure_class="flaky",
                    decision="abstain",
                    target_state="diagnosed_only",
                    summary=(
                        "Failure signature matches historical flaky pass/fail oscillation on "
                        "identical commit SHAs (TRI-03); abstaining with zero code patches."
                    ),
                    evidence_refs=[primary_art_id],
                    evidence_citations=[citation],
                    hypotheses=[],
                    uncertainties=["Non-deterministic test oscillation observed across reruns."],
                    proposed_profile=None,
                    proposed_command_ids=[],
                    fingerprint_hash=fp_hash,
                    model_id=None,
                    provider_request_id=None,
                    schema_repair_retries_used=0,
                    deterministic_rule_id="tri03_flaky_history",
                    context_digest=manifest_row.context_digest,
                    step_number=initial_step_number,
                    correlation_id=correlation_id,
                )
                return DiagnosisOutcome(
                    repair=to_repair_dto(updated_rep),
                    diagnosis=to_diagnosis_dto(diag_row),
                    context_manifest=manifest_dto,
                )

            # 1c. Deterministic auth / infra / network log signatures (SEC-024)
            det_match = _classify_deterministic_log_failure(full_log_text)
            if det_match is not None:
                det_class, det_rule, det_summary, det_regex = det_match
                citation = _locate_citation_in_log(
                    artifact_id=primary_art_id,
                    scrubbed_text=log_texts_by_artifact[primary_art_id],
                    pattern=det_regex,
                )
                updated_rep, diag_row = await self._persist_diagnosis_and_transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    failure_class=det_class,
                    decision="abstain",
                    target_state="diagnosed_only",
                    summary=det_summary,
                    evidence_refs=[primary_art_id],
                    evidence_citations=[citation],
                    hypotheses=[],
                    uncertainties=[],
                    proposed_profile=None,
                    proposed_command_ids=[],
                    fingerprint_hash=fp_hash,
                    model_id=None,
                    provider_request_id=None,
                    schema_repair_retries_used=0,
                    deterministic_rule_id=det_rule,
                    context_digest=manifest_row.context_digest,
                    step_number=initial_step_number,
                    correlation_id=correlation_id,
                )
                return DiagnosisOutcome(
                    repair=to_repair_dto(updated_rep),
                    diagnosis=to_diagnosis_dto(diag_row),
                    context_manifest=manifest_dto,
                )

            # 1d. ADR-018 Runner profile eligibility check (unsupported OS/GPU/DinD/ecosystem)
            job_stage = failed_job.stage if failed_job is not None else None
            job_matrix: dict[str, str] = {}
            if failed_job is not None and isinstance(failed_job.matrix_dimensions_json, dict):
                job_matrix = {str(k): str(v) for k, v in failed_job.matrix_dimensions_json.items()}

            profile_decision = select_profile_for_ci_job(
                ci_job_name=job_name,
                ci_job_stage=job_stage,
                matrix_dimensions=job_matrix,
                repo_files=snapshot.list_files(),
                declared_capabilities=declared_capabilities,
                policy_runtime_profile_id=(
                    repo_policy.runtime_profile_id
                    if repo_policy.runtime_profile_id != "default-isolated"
                    else None
                ),
                custom_profile_admin_opt_in=custom_profile_admin_opt_in,
                registry=self._profile_registry,
            )
            if (
                not profile_decision.supported
                or profile_decision.fidelity_grade == "FX_UNSUPPORTED"
            ):
                citation = _locate_citation_in_log(
                    artifact_id=primary_art_id,
                    scrubbed_text=log_texts_by_artifact[primary_art_id],
                )
                diff_note = (
                    "; ".join(profile_decision.fidelity_differences) or profile_decision.reason_code
                )
                updated_rep, diag_row = await self._persist_diagnosis_and_transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    failure_class="unsupported",
                    decision="abstain",
                    target_state="unsupported",
                    summary=(
                        f"CI job '{job_name}' requires an unsupported execution environment "
                        f"({diff_note}); abstaining per ADR-018 with zero sandbox or patch runs."
                    ),
                    evidence_refs=[primary_art_id],
                    evidence_citations=[citation],
                    hypotheses=[],
                    uncertainties=list(profile_decision.fidelity_differences),
                    proposed_profile=None,
                    proposed_command_ids=[],
                    fingerprint_hash=fp_hash,
                    model_id=None,
                    provider_request_id=None,
                    schema_repair_retries_used=0,
                    deterministic_rule_id=f"adr018_{profile_decision.reason_code}"[:120],
                    context_digest=manifest_row.context_digest,
                    step_number=initial_step_number,
                    correlation_id=correlation_id,
                )
                return DiagnosisOutcome(
                    repair=to_repair_dto(updated_rep),
                    diagnosis=to_diagnosis_dto(diag_row),
                    context_manifest=manifest_dto,
                )

            if not profile.enabled:
                citation = _locate_citation_in_log(
                    artifact_id=primary_art_id,
                    scrubbed_text=log_texts_by_artifact[primary_art_id],
                )
                updated_rep, diag_row = await self._persist_diagnosis_and_transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    failure_class="unknown",
                    decision="human",
                    target_state="needs_human",
                    summary=(
                        "Workspace triage_diagnosis agent profile is disabled by administrator; "
                        "escalating to human review."
                    ),
                    evidence_refs=[primary_art_id],
                    evidence_citations=[citation],
                    hypotheses=[],
                    uncertainties=["triage_diagnosis profile disabled"],
                    proposed_profile=profile_decision.profile_id,
                    proposed_command_ids=list(profile_decision.repro_command_ids),
                    fingerprint_hash=fp_hash,
                    model_id=None,
                    provider_request_id=None,
                    schema_repair_retries_used=0,
                    deterministic_rule_id="agent_profile_disabled",
                    context_digest=manifest_row.context_digest,
                    step_number=initial_step_number,
                    correlation_id=correlation_id,
                )
                return DiagnosisOutcome(
                    repair=to_repair_dto(updated_rep),
                    diagnosis=to_diagnosis_dto(diag_row),
                    context_manifest=manifest_dto,
                )

            session_art_ids = {art.id for art in art_rows}
            initial_log_wrapped, _ = wrap_untrusted_repo_data(
                log_texts_by_artifact[primary_art_id][:16_000],
                kind="ci_log",
                source_ref=primary_art_id,
                redactor=self._redactor,
            )

        # Stage 2: Bounded Meta Muse diagnosis loop + S-20 tool broker + <= 2 schema retries
        broker_ctx = ToolBrokerSessionContext(
            workspace_id=workspace_id,
            repository_id=repository_id,
            repair_id=repair_id,
            ci_run_id=ci_run_id,
            base_sha=base_sha,
            agent_role="diagnosis",
            attempt_number=0,
            allowed_tools=frozenset(profile.allowed_tools) & frozenset(DIAGNOSIS_ALLOWED_TOOLS),
            context_digest=manifest_row.context_digest,
            repo_policy=repo_policy,
            effective_policy=effective_policy,
            policy_ctx=policy_ctx,
            snapshot=snapshot,
            artifact_store=self._artifact_store,
            profile_registry=self._profile_registry,
            correlation_id=correlation_id,
            redactor=self._redactor,
            session_artifact_ids=set(session_art_ids),
            next_step_number=initial_step_number,
        )
        tool_broker = AgentToolBroker(ctx=broker_ctx)
        meta_tools = tool_broker.build_meta_tools()
        response_format = MetaResponseFormat(
            type="json_schema",
            json_schema=MetaJsonSchemaSpec.model_validate(
                {
                    "name": "red2pr_diagnosis_v1",
                    "strict": True,
                    "schema": _DIAGNOSIS_JSON_SCHEMA,
                }
            ),
        )

        messages: list[MetaChatMessage] = [
            MetaChatMessage(
                role="system",
                content=(
                    f"{UNTRUSTED_SYSTEM_PREAMBLE}\n"
                    "You are the Red2PR Triage & Diagnosis Agent. Inspect the failing CI log "
                    "and repository files using ONLY your allowlisted S-20 read/propose tools. "
                    "Cite exact session evidence_artifact_ids and output strict JSON matching "
                    "red2pr_diagnosis_v1."
                ),
            ),
            MetaChatMessage(
                role="user",
                content=(
                    f"Repair session: {repair_id}\n"
                    f"Pinned base_sha: {base_sha}\n"
                    f"Candidate runner profile: {profile_decision.profile_id}\n"
                    f"Available session CI log artifact IDs: {sorted(session_art_ids)}\n\n"
                    f"{initial_log_wrapped}"
                ),
            ),
        ]

        max_schema_retries = min(2, profile.max_schema_repair_retries)
        schema_retries_used = 0
        steps_used = 0
        validated_payload: _ModelDiagnosisPayload | None = None
        last_provider_req_id: str | None = None
        last_model_id: str | None = None
        abstain_reason_code: str | None = None
        abstain_summary: str | None = None

        while steps_used < profile.max_steps:
            steps_used += 1
            try:
                completion = await self._meta.complete_chat(
                    MetaChatCompletionRequest(
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        repair_id=repair_id,
                        session_budget_account_id=budget_account_id,
                        model_id=profile.model_id,
                        messages=messages,
                        tools=meta_tools if meta_tools else None,
                        response_format=response_format,
                        max_completion_tokens=1536,
                        reasoning_effort=profile.reasoning_effort,
                        correlation_id=correlation_id,
                    ),
                    cancel_check=cancel_check,
                )
            except (DependencyUnavailableError, RateLimitedError) as exc:
                # Suspend session cleanly without inventing a WAITING_MODEL state (SEC-023)
                await self._state_machine.suspend_session(
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    reason="model_unavailable",
                    requested_by="service:diagnosis_agent",
                    correlation_id=correlation_id,
                )
                raise exc
            except BudgetExceededError:
                abstain_reason_code = "budget_exhausted_during_diagnosis"
                abstain_summary = (
                    "Session or workspace Meta inference budget was exhausted during diagnosis; "
                    "escalating to human review without patching."
                )
                break
            except UnprocessableEntityError as exc:
                # Malformed JSON / extra keys returned by Meta model (SEC-012)
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
                            agent_role="diagnosis",
                            attempt_number=0,
                            step_number=broker_ctx.allocate_step_number(),
                            step_kind="schema_repair",
                            status="failed",
                            context_digest=manifest_row.context_digest,
                            deny_reason_code=exc.code[:120],
                            deny_explanation=sanitize_and_redact_text(
                                exc.detail, redactor=self._redactor, max_chars=900
                            ),
                            model_id=profile.model_id,
                            version=1,
                            created_at=now_step,
                            updated_at=now_step,
                        )
                    )
                    await step_db.flush()

                if schema_retries_used >= max_schema_retries:
                    abstain_reason_code = "sec012_schema_repair_exhausted"
                    abstain_summary = (
                        f"Meta model output failed strict schema validation after "
                        f"{schema_retries_used} repair retries (SEC-012); abstaining to human "
                        "review with zero patch attempts."
                    )
                    break
                schema_retries_used += 1
                messages.append(
                    MetaChatMessage(
                        role="user",
                        content=(
                            f"SCHEMA_REPAIR_RETRY ({schema_retries_used}/{max_schema_retries}): "
                            f"Your previous response violated red2pr_diagnosis_v1 ({exc.code}). "
                            "Return ONLY a valid JSON object matching the exact required keys "
                            "and citing valid session evidence_artifact_ids."
                        ),
                    )
                )
                continue

            last_provider_req_id = completion.provider_request_id
            last_model_id = completion.model_id

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
                        agent_role="diagnosis",
                        attempt_number=0,
                        step_number=broker_ctx.allocate_step_number(),
                        step_kind="model_call",
                        status="ok",
                        context_digest=manifest_row.context_digest,
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

            # Final structured output validation + session citation verification (SEC-012)
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
                    raise ValueError("Missing structured JSON object in diagnosis response")
                candidate_diag = _ModelDiagnosisPayload.model_validate(raw_struct)
                invalid_refs = [
                    aid
                    for aid in candidate_diag.evidence_artifact_ids
                    if aid not in broker_ctx.session_artifact_ids
                ]
                if invalid_refs:
                    raise ValueError(
                        f"Uncited or cross-session evidence_artifact_ids: {invalid_refs!r}"
                    )
                validated_payload = candidate_diag
                break
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
                            agent_role="diagnosis",
                            attempt_number=0,
                            step_number=broker_ctx.allocate_step_number(),
                            step_kind="schema_repair",
                            status="failed",
                            context_digest=manifest_row.context_digest,
                            deny_reason_code="diagnosis_schema_or_citation_invalid",
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
                    abstain_summary = (
                        f"Diagnosis output failed schema/citation validation after "
                        f"{schema_retries_used} repair retries (SEC-012); abstaining to human "
                        "review with zero patch attempts."
                    )
                    break
                schema_retries_used += 1
                messages.append(
                    MetaChatMessage(
                        role="assistant",
                        content=completion.content or "{}",
                    )
                )
                messages.append(
                    MetaChatMessage(
                        role="user",
                        content=(
                            f"SCHEMA_REPAIR_RETRY ({schema_retries_used}/{max_schema_retries}): "
                            f"Validation error: {str(exc)[:300]}. Return ONLY valid JSON matching "
                            f"red2pr_diagnosis_v1 and citing session artifact IDs from "
                            f"{sorted(broker_ctx.session_artifact_ids)}."
                        ),
                    )
                )

        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            citation = _locate_citation_in_log(
                artifact_id=primary_art_id,
                scrubbed_text=log_texts_by_artifact[primary_art_id],
            )
            if validated_payload is None:
                eff_rule = abstain_reason_code or "diagnosis_max_steps_exhausted"
                eff_summary = abstain_summary or (
                    f"Diagnosis agent reached max_steps={profile.max_steps} without producing a "
                    "valid structured diagnosis; escalating to human review."
                )
                updated_rep, diag_row = await self._persist_diagnosis_and_transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    repair_id=repair_id,
                    failure_class="unknown",
                    decision="human",
                    target_state="needs_human",
                    summary=eff_summary,
                    evidence_refs=[primary_art_id],
                    evidence_citations=[citation],
                    hypotheses=[],
                    uncertainties=[eff_rule],
                    proposed_profile=profile_decision.profile_id,
                    proposed_command_ids=list(profile_decision.repro_command_ids),
                    fingerprint_hash=fp_hash,
                    model_id=last_model_id,
                    provider_request_id=last_provider_req_id,
                    schema_repair_retries_used=schema_retries_used,
                    deterministic_rule_id=eff_rule,
                    context_digest=manifest_row.context_digest,
                    step_number=broker_ctx.allocate_step_number(),
                    correlation_id=correlation_id,
                )
                return DiagnosisOutcome(
                    repair=to_repair_dto(updated_rep),
                    diagnosis=to_diagnosis_dto(diag_row),
                    context_manifest=manifest_dto,
                )

            # Enforce deterministic orchestrator guardrails over model decision (SEC-024)
            f_class = validated_payload.failure_class
            m_decision = validated_payload.decision
            rule_override: str | None = None

            if f_class == "unsupported":
                eff_decision: DiagnosisDecision = "abstain"
                target_state: RepairState = "unsupported"
                rule_override = "model_classified_unsupported"
            elif f_class in _ABSTAIN_MANDATORY_CLASSES:
                if f_class == "unknown":
                    eff_decision = "human"
                    target_state = "needs_human"
                    rule_override = "unknown_class_requires_human"
                else:
                    eff_decision = "abstain"
                    target_state = "diagnosed_only"
                    rule_override = f"sec024_abstain_{f_class}"
            elif m_decision == "abstain":
                eff_decision = "abstain"
                target_state = "diagnosed_only"
            elif m_decision == "human":
                eff_decision = "human"
                target_state = "needs_human"
            else:
                eff_decision = "continue"
                target_state = "reproducing"

            # Resolve proposed profile strictly within reviewed RunnerProfileRegistry
            chosen_profile = profile_decision.profile_id
            if validated_payload.proposed_profile is not None:
                try:
                    self._profile_registry.get_manifest(validated_payload.proposed_profile)
                    chosen_profile = validated_payload.proposed_profile
                except NotFoundError:
                    pass
            elif broker_ctx.reproduction_proposals:
                chosen_profile = broker_ctx.reproduction_proposals[-1].profile_id

            declared_cmds: set[str] = set()
            if chosen_profile is not None:
                try:
                    chosen_manifest = self._profile_registry.get_manifest(chosen_profile)
                    declared_cmds = {c.command_id for c in chosen_manifest.commands}
                except NotFoundError:
                    declared_cmds = set()
            chosen_cmds = [
                cid for cid in validated_payload.proposed_command_ids if cid in declared_cmds
            ]
            if not chosen_cmds:
                chosen_cmds = list(profile_decision.repro_command_ids)

            citations = [
                _locate_citation_in_log(
                    artifact_id=aid,
                    scrubbed_text=log_texts_by_artifact.get(
                        aid, log_texts_by_artifact[primary_art_id]
                    ),
                )
                for aid in validated_payload.evidence_artifact_ids
                if aid in log_texts_by_artifact
            ] or [citation]

            hypotheses = [
                DiagnosisHypothesis(
                    id="hyp-1",
                    statement=validated_payload.hypothesis_statement,
                    confidence=validated_payload.hypothesis_confidence,
                    suspected_paths=validated_payload.suspected_paths,
                )
            ]

            updated_rep, diag_row = await self._persist_diagnosis_and_transition_in_tx(
                db,
                workspace_id=workspace_id,
                repository_id=repository_id,
                repair_id=repair_id,
                failure_class=f_class,
                decision=eff_decision,
                target_state=target_state,
                summary=validated_payload.summary,
                evidence_refs=list(validated_payload.evidence_artifact_ids),
                evidence_citations=citations,
                hypotheses=hypotheses,
                uncertainties=list(validated_payload.uncertainties),
                proposed_profile=chosen_profile if eff_decision == "continue" else None,
                proposed_command_ids=chosen_cmds if eff_decision == "continue" else [],
                fingerprint_hash=fp_hash,
                model_id=last_model_id,
                provider_request_id=last_provider_req_id,
                schema_repair_retries_used=schema_retries_used,
                deterministic_rule_id=rule_override,
                context_digest=manifest_row.context_digest,
                step_number=broker_ctx.allocate_step_number(),
                correlation_id=correlation_id,
            )
            return DiagnosisOutcome(
                repair=to_repair_dto(updated_rep),
                diagnosis=to_diagnosis_dto(diag_row),
                context_manifest=manifest_dto,
            )

    async def apply_baseline_reproduction_verdict(
        self,
        *,
        workspace_id: str,
        repair_id: str,
        reproduction_run: ReproductionRunRecord,
        correlation_id: str,
    ) -> Repair:
        """Advance `reproducing` session to `repro_confirmed` or terminal `repro_unconfirmed`."""
        if reproduction_run.repair_id != repair_id:
            raise ConflictError(
                code="reproduction_session_mismatch",
                detail=(
                    f"ReproductionRun {reproduction_run.id} belongs to repair "
                    f"{reproduction_run.repair_id}, not {repair_id}."
                ),
            )
        if reproduction_run.phase != "baseline_a":
            raise ConflictError(
                code="expected_baseline_a_reproduction",
                detail="Only Sandbox A (baseline_a) runs can confirm baseline reproduction.",
            )

        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            if reproduction_run.status == "repro_confirmed" and reproduction_run.allow_patching:
                row = await self._state_machine.transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state="repro_confirmed",
                    target_proof_grade="baseline_confirmed",
                    active_reproduction_id=reproduction_run.id,
                    reason_code="sandbox_a_repro_confirmed",
                    status_detail="Unpatched Sandbox A reproduced expected CI failure.",
                    actor="service:reproduction_orchestrator",
                    correlation_id=correlation_id,
                )
                return to_repair_dto(row)

            if reproduction_run.status == "unsupported":
                row = await self._state_machine.transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state="unsupported",
                    active_reproduction_id=reproduction_run.id,
                    reason_code=reproduction_run.failure_reason_code or "fx_unsupported",
                    status_detail=reproduction_run.failure_detail,
                    actor="service:reproduction_orchestrator",
                    correlation_id=correlation_id,
                )
                return to_repair_dto(row)

            # Non-waivable ADR-031 stop: seal terminal repro_unconfirmed (0 patches possible)
            row = await self._state_machine.transition_in_tx(
                db,
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state="repro_unconfirmed",
                active_reproduction_id=reproduction_run.id,
                reason_code=reproduction_run.failure_reason_code or "adr031_repro_unconfirmed",
                status_detail=(
                    reproduction_run.failure_detail
                    or "Baseline Sandbox A did not reproduce CI failure; stopping per ADR-031."
                ),
                actor="service:reproduction_orchestrator",
                correlation_id=correlation_id,
            )
            return to_repair_dto(row)
