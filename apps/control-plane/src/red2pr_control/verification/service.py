"""Transactional V-01..V-07 persistence and non-waivable human handoff (U18)."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import cast

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.crypto import KeyRing, sha256_canonical_json
from py_contracts.events import EventEnvelope, ReproVerificationEventPayload
from py_contracts.evidence import EvidenceManifestV1
from py_contracts.primitives import new_uuid7
from py_contracts.repairs import ProofGrade, RepairState
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.approvals.service import create_approval_for_verified_patch
from red2pr_control.core.errors import ConflictError, NotFoundError
from red2pr_control.db.base import (
    EvidenceManifestModel,
    PatchAttemptModel,
    RepairSessionModel,
    VerificationRunModel,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.orchestrator.state_machine import RepairSessionStateMachine
from red2pr_control.verification.diff_integrity import IntegrityDisposition
from red2pr_control.verification.verifier import (
    DeterministicVerifier,
    VerificationDecision,
    VerificationFacts,
    verify_evidence_manifest,
)


@dataclass(frozen=True, slots=True)
class VerificationReceipt:
    verification_id: str
    status: str
    proof_grade: str
    manifest_id: str | None
    idempotent_replay: bool
    decision: VerificationDecision | None


class VerificationService:
    """Persist one immutable attempt and atomically promote or stop its repair session."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        verifier: DeterministicVerifier,
        state_machine: RepairSessionStateMachine,
        manifest_keyring: KeyRing,
        evidence_trust_domain: str,
    ) -> None:
        self._session_factory = session_factory
        self._verifier = verifier
        self._state_machine = state_machine
        self._manifest_keyring = manifest_keyring
        self._evidence_trust_domain = evidence_trust_domain

    async def verify(
        self,
        *,
        workspace_id: str,
        repair_id: str,
        verification_id: str,
        idempotency_key: str,
        facts: VerificationFacts,
        signed_manifest: EvidenceManifestV1 | None,
        evidence_blobs: dict[str, bytes],
        correlation_id: str,
        now: datetime | None = None,
    ) -> VerificationReceipt:
        if not idempotency_key or len(idempotency_key) > 120:
            raise ValueError("idempotency_key must contain 1..120 characters")
        ref_now = now.astimezone(UTC) if now else datetime.now(tz=UTC)
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            existing = await db.scalar(
                select(VerificationRunModel).where(
                    VerificationRunModel.workspace_id == workspace_id,
                    VerificationRunModel.idempotency_key == idempotency_key,
                )
            )
            if existing is not None:
                if existing.repair_id != repair_id or existing.patch_digest != facts.diff_digest:
                    raise ConflictError(
                        code="idempotency_key_reused",
                        detail="Idempotency key is already bound to a different repair or patch.",
                    )
                existing_manifest = await db.scalar(
                    select(EvidenceManifestModel.id).where(
                        EvidenceManifestModel.workspace_id == workspace_id,
                        EvidenceManifestModel.verification_run_id == existing.id,
                    )
                )
                return VerificationReceipt(
                    verification_id=existing.id,
                    status=existing.status,
                    proof_grade=existing.proof_grade,
                    manifest_id=existing_manifest,
                    idempotent_replay=True,
                    decision=None,
                )

            repair = await db.scalar(
                select(RepairSessionModel)
                .where(
                    RepairSessionModel.workspace_id == workspace_id,
                    RepairSessionModel.id == repair_id,
                )
                .with_for_update()
            )
            if repair is None:
                raise NotFoundError(code="repair_not_found", detail="Repair session was not found.")
            if repair.state not in {"verifying", "cancel_requested"}:
                raise ConflictError(
                    code="repair_not_verifying",
                    detail="Verification can only record a verifying or cancelling session.",
                )
            facts = replace(facts, cancelled=facts.cancelled or repair.state == "cancel_requested")
            decision = self._verifier.evaluate(facts)
            verified = decision.publication_eligible
            if verified:
                self._validate_manifest_binding(
                    signed_manifest=signed_manifest,
                    workspace_id=workspace_id,
                    repository_id=repair.repository_id,
                    repair_id=repair_id,
                    diff_digest=facts.diff_digest,
                    decision=decision,
                )
                assert signed_manifest is not None
                verify_evidence_manifest(
                    signed_manifest,
                    keyring=self._manifest_keyring,
                    artifact_blobs=evidence_blobs,
                    expected_signer_trust_domain=self._evidence_trust_domain,
                    now=ref_now,
                )
            elif signed_manifest is not None:
                raise ConflictError(
                    code="manifest_without_verified_proof",
                    detail=(
                        "A failed or incomplete V-01..V-07 result cannot carry "
                        "a verification manifest."
                    ),
                )
            gates_json = [gate.model_dump(mode="json") for gate in decision.gates]
            status = self._status_for(decision, cancelled=facts.cancelled)
            proof_grade = "locally_verified" if verified else repair.proof_grade
            manifest_id = signed_manifest.manifest_id if signed_manifest else None
            if signed_manifest is not None and (
                signed_manifest.repository_id != repair.repository_id
                or signed_manifest.base_sha != repair.base_sha
            ):
                raise ConflictError(
                    code="manifest_scope_mismatch",
                    detail="Manifest repository or base revision differs from the repair session.",
                )
            if facts.cancelled or repair.state == "cancel_requested":
                status = "cancelled"
                proof_grade = repair.proof_grade
                manifest_id = None
            db.add(
                VerificationRunModel(
                    id=verification_id,
                    workspace_id=workspace_id,
                    repository_id=repair.repository_id,
                    repair_id=repair_id,
                    idempotency_key=idempotency_key,
                    patch_digest=facts.diff_digest,
                    status=status,
                    proof_grade=proof_grade,
                    gates_json=gates_json,
                    baseline_result_digest=decision.baseline_result_digest,
                    patched_result_digest=decision.patched_result_digest,
                    correlation_id=correlation_id,
                    created_at=ref_now,
                )
            )
            try:
                # The manifest has a same-workspace FK to this row; persist its parent first.
                await db.flush()
            except IntegrityError as exc:
                if getattr(exc.orig, "sqlstate", None) == "23505":
                    raise ConflictError(
                        code="verification_idempotency_conflict",
                        detail=(
                            "Verification already exists; retry with its original idempotency key."
                        ),
                    ) from exc
                raise

            if signed_manifest is not None and manifest_id is not None:
                payload = signed_manifest.model_dump(mode="json", by_alias=True)
                db.add(
                    EvidenceManifestModel(
                        id=manifest_id,
                        workspace_id=workspace_id,
                        repository_id=repair.repository_id,
                        repair_id=repair_id,
                        verification_run_id=verification_id,
                        schema_version=1,
                        payload_json=payload,
                        manifest_digest=sha256_canonical_json(payload),
                        signer_key_id=signed_manifest.signer_key_id,
                        created_at=ref_now,
                    )
                )
                await db.flush()

            if verified:
                verified_patch = await db.scalar(
                    select(PatchAttemptModel)
                    .where(
                        PatchAttemptModel.workspace_id == workspace_id,
                        PatchAttemptModel.repair_id == repair_id,
                        PatchAttemptModel.patch_digest == facts.diff_digest,
                    )
                    .order_by(PatchAttemptModel.attempt_number.desc())
                    .limit(1)
                )
                if verified_patch is not None:
                    await create_approval_for_verified_patch(
                        db,
                        repair=repair,
                        patch=verified_patch,
                        actor_id=None,
                        correlation_id=correlation_id,
                        now=ref_now,
                    )

            if repair.state == "verifying" and status != "cancelled":
                target_state: RepairState
                target_proof_grade: ProofGrade
                if verified:
                    target_state = "policy_gate"
                    target_proof_grade = "locally_verified"
                elif decision.integrity.disposition is IntegrityDisposition.REJECT:
                    target_state = "rejected"
                    target_proof_grade = cast(ProofGrade, repair.proof_grade)
                elif "v_01_fail" in decision.reason_codes or (
                    decision.integrity.disposition is IntegrityDisposition.HUMAN_REVIEW
                ):
                    target_state = "needs_human"
                    target_proof_grade = cast(ProofGrade, repair.proof_grade)
                else:
                    target_state = "blocked"
                    target_proof_grade = cast(ProofGrade, repair.proof_grade)
                await self._state_machine.transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state=target_state,
                    target_proof_grade=target_proof_grade,
                    reason_code="verification_passed" if verified else status,
                    status_detail=",".join(decision.reason_codes)[:1000] or None,
                    actor="system:deterministic_verifier",
                    correlation_id=correlation_id,
                )
            current = await db.scalar(
                select(RepairSessionModel).where(
                    RepairSessionModel.workspace_id == workspace_id,
                    RepairSessionModel.id == repair_id,
                )
            )
            aggregate_version = current.version if current is not None else repair.version
            await enqueue_outbox_event(
                db,
                EventEnvelope(
                    event_id=new_uuid7(now=ref_now),
                    type="repair.verification.completed",
                    occurred_at=ref_now,
                    workspace_id=workspace_id,
                    repository_id=repair.repository_id,
                    session_id=repair_id,
                    aggregate_id=repair_id,
                    aggregate_version=aggregate_version,
                    correlation_id=correlation_id,
                    payload=ReproVerificationEventPayload(
                        repair_id=repair_id,
                        outcome=status,
                        manifest_id=manifest_id,
                    ),
                ),
                now=ref_now,
            )
            await append_audit_entry(
                db,
                workspace_id=workspace_id,
                repository_id=repair.repository_id,
                actor_type="system",
                actor_id="deterministic_verifier",
                action="repair.verification.completed",
                target=verification_id,
                decision="allow" if verified else "deny",
                reason_code="verification_passed" if verified else status,
                correlation_id=correlation_id,
                metadata={
                    "repair_id": repair_id,
                    "patch_digest": facts.diff_digest,
                    "status": status,
                    "proof_grade": proof_grade,
                    "gate_outcomes": {gate.id: gate.outcome for gate in decision.gates},
                },
                occurred_at=ref_now,
            )
            return VerificationReceipt(
                verification_id=verification_id,
                status=status,
                proof_grade=proof_grade,
                manifest_id=manifest_id,
                idempotent_replay=False,
                decision=decision,
            )

    @staticmethod
    def _status_for(decision: VerificationDecision, *, cancelled: bool) -> str:
        if cancelled:
            return "cancelled"
        if decision.publication_eligible:
            return "verified"
        if "v_01_fail" in decision.reason_codes:
            return "human_review"
        if decision.integrity.disposition is IntegrityDisposition.HUMAN_REVIEW:
            return "human_review"
        if decision.integrity.disposition is IntegrityDisposition.REJECT:
            return "failed"
        return "blocked"

    @staticmethod
    def _validate_manifest_binding(
        *,
        signed_manifest: EvidenceManifestV1 | None,
        workspace_id: str,
        repository_id: str,
        repair_id: str,
        diff_digest: str,
        decision: VerificationDecision,
    ) -> None:
        if signed_manifest is None:
            raise ConflictError(
                code="verified_manifest_required",
                detail="All V-01..V-07 gates need a matching signed EvidenceManifestV1.",
            )
        binding_ok = all(
            (
                signed_manifest.workspace_id == workspace_id,
                signed_manifest.repository_id == repository_id,
                signed_manifest.repair_id == repair_id,
                signed_manifest.diff_digest == diff_digest,
                signed_manifest.baseline_result_digest == decision.baseline_result_digest,
                signed_manifest.patched_result_digest == decision.patched_result_digest,
                signed_manifest.integrity_outcome == "pass",
                signed_manifest.security_outcome == "pass",
                signed_manifest.policy_outcome == "pass",
                signed_manifest.regression.failed_count == 0,
                signed_manifest.regression.passed_count > 0,
            )
        )
        if not binding_ok:
            raise ConflictError(
                code="manifest_verification_mismatch",
                detail="Signed manifest is not bound to the exact successful V-01..V-07 result.",
            )
