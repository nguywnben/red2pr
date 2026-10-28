"""Canonical 25-state CI repair state machine & suspension/cancel coordinator (`W-04`, `W-05`).

Implements `docs/08_EVENTS_STATE_MACHINES.md`, `docs/36_CANONICAL_CONTRACTS.md` (`S-11`, `S-19`),
`ADR-031`, and `ADR-038` strictly inside Zone `Z1` (`red2pr_control.orchestrator` — zero imports
from `Z2` secret, publisher, or inference packages):
- Enforces the exact 25 `lower_snake_case` `RepairState` literals (`received` .. `cancelled`),
  including `ADR-038` transitions (`triaging -> needs_human` and `policy_gate -> needs_human`).
- Prohibits every non-allowlisted transition, self-transition, terminal-to-active resurrection,
  and monotonic `proof_grade` (`none < baseline_confirmed < locally_verified < remotely_verified`)
  regression.
- Enforces the non-waivable `ADR-031` proof lattice gate (`proof_grade >= baseline_confirmed`
  before `repro_confirmed` / `patching`, `>= locally_verified` before `policy_gate` /
  `awaiting_approval` / `publishing`, and `== remotely_verified` before `remote_verified`).
- Supports `RepairSuspension` pause/resume overlays on non-terminal sessions without inventing
  non-canonical states (`WAITING_MODEL`, `DEGRADED`, etc. are structurally rejected).
- Preserves existing `proof_grade` and `remote_status` across `cancel_requested -> cancelled`
  and spawns child retry sessions via `parent_id` only after parent termination.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Final, cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.events import EventEnvelope, RepairPhaseEventPayload
from py_contracts.primitives import new_uuid7
from py_contracts.repairs import (
    ProofGrade,
    RemoteStatus,
    Repair,
    RepairState,
    RepairSuspension,
    SuspensionReason,
)
from red2pr_control.analytics_audit.audit_chain import AuditActorType, append_audit_entry
from red2pr_control.core.errors import ConflictError, NotFoundError, UnprocessableEntityError
from red2pr_control.db.base import RepairSessionModel
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import workspace_rls_session

ALL_REPAIR_STATES: Final[tuple[RepairState, ...]] = (
    "received",
    "authorized",
    "collecting",
    "triaging",
    "diagnosed_only",
    "unsupported",
    "reproducing",
    "repro_confirmed",
    "repro_unconfirmed",
    "blocked",
    "patching",
    "verifying",
    "rejected",
    "policy_gate",
    "awaiting_approval",
    "expired",
    "publishing",
    "publish_reconcile",
    "needs_human",
    "remote_validating",
    "remote_verified",
    "remote_failed",
    "remote_unknown",
    "cancel_requested",
    "cancelled",
)

TERMINAL_REPAIR_STATES: Final[frozenset[RepairState]] = frozenset(
    {
        "diagnosed_only",
        "unsupported",
        "repro_unconfirmed",
        "blocked",
        "rejected",
        "expired",
        "needs_human",
        "remote_verified",
        "remote_failed",
        "remote_unknown",
        "cancelled",
    }
)

NON_TERMINAL_REPAIR_STATES: Final[frozenset[RepairState]] = frozenset(
    state for state in ALL_REPAIR_STATES if state not in TERMINAL_REPAIR_STATES
)

PROOF_GRADE_ORDER: Final[dict[ProofGrade, int]] = {
    "none": 0,
    "baseline_confirmed": 1,
    "locally_verified": 2,
    "remotely_verified": 3,
}

VALID_REMOTE_STATUSES: Final[frozenset[RemoteStatus]] = frozenset(
    {"not_published", "pending", "passed", "failed", "unknown"}
)

STATES_REQUIRING_BASELINE_PROOF: Final[frozenset[RepairState]] = frozenset(
    {
        "repro_confirmed",
        "patching",
        "verifying",
        "policy_gate",
        "awaiting_approval",
        "publishing",
        "publish_reconcile",
        "remote_validating",
        "remote_verified",
        "remote_failed",
        "remote_unknown",
    }
)

STATES_REQUIRING_LOCAL_VERIFICATION: Final[frozenset[RepairState]] = frozenset(
    {
        "policy_gate",
        "awaiting_approval",
        "publishing",
        "publish_reconcile",
        "remote_validating",
        "remote_verified",
        "remote_failed",
        "remote_unknown",
    }
)

ALLOWED_REPAIR_TRANSITIONS: Final[dict[RepairState, frozenset[RepairState]]] = {
    "received": frozenset({"authorized", "blocked", "cancel_requested", "cancelled"}),
    "authorized": frozenset({"collecting", "blocked", "cancel_requested", "cancelled"}),
    "collecting": frozenset(
        {"triaging", "blocked", "needs_human", "cancel_requested", "cancelled"}
    ),
    "triaging": frozenset(
        {
            "diagnosed_only",
            "unsupported",
            "needs_human",
            "reproducing",
            "blocked",
            "cancel_requested",
            "cancelled",
        }
    ),
    "reproducing": frozenset(
        {
            "repro_confirmed",
            "repro_unconfirmed",
            "unsupported",
            "blocked",
            "needs_human",
            "cancel_requested",
            "cancelled",
        }
    ),
    "repro_confirmed": frozenset(
        {"patching", "blocked", "needs_human", "cancel_requested", "cancelled"}
    ),
    "patching": frozenset({"verifying", "blocked", "needs_human", "cancel_requested", "cancelled"}),
    "verifying": frozenset(
        {
            "patching",
            "rejected",
            "policy_gate",
            "blocked",
            "needs_human",
            "cancel_requested",
            "cancelled",
        }
    ),
    "policy_gate": frozenset(
        {
            "blocked",
            "needs_human",
            "awaiting_approval",
            "publishing",
            "cancel_requested",
            "cancelled",
        }
    ),
    "awaiting_approval": frozenset(
        {"rejected", "publishing", "expired", "blocked", "cancel_requested", "cancelled"}
    ),
    "publishing": frozenset(
        {"remote_validating", "publish_reconcile", "blocked", "needs_human", "cancel_requested"}
    ),
    "publish_reconcile": frozenset(
        {"remote_validating", "needs_human", "blocked", "cancel_requested", "cancelled"}
    ),
    "remote_validating": frozenset(
        {"remote_verified", "remote_failed", "remote_unknown", "cancel_requested", "cancelled"}
    ),
    "cancel_requested": frozenset({"cancelled"}),
    # Terminal states never transition back to active within the same session (docs/08)
    "diagnosed_only": frozenset(),
    "unsupported": frozenset(),
    "repro_unconfirmed": frozenset(),
    "blocked": frozenset(),
    "rejected": frozenset(),
    "expired": frozenset(),
    "needs_human": frozenset(),
    "remote_verified": frozenset(),
    "remote_failed": frozenset(),
    "remote_unknown": frozenset(),
    "cancelled": frozenset(),
}

_UNSET: Final[object] = object()


def _split_actor(actor: str) -> tuple[AuditActorType, str]:
    raw = actor.strip()
    if raw.startswith("user:"):
        return "user", raw[len("user:") :] or "unknown"
    if raw.startswith("service:"):
        return "service", raw[len("service:") :] or "service"
    if raw.startswith("system:"):
        return "system", raw[len("system:") :] or "orchestrator"
    return "system", raw or "orchestrator"


def validate_repair_transition(
    *,
    current_state: str,
    target_state: str,
    current_proof_grade: str,
    target_proof_grade: str | None = None,
) -> tuple[RepairState, ProofGrade]:
    """Deterministically validate a repair state + monotonic proof-grade transition."""
    if current_state not in ALLOWED_REPAIR_TRANSITIONS:
        raise UnprocessableEntityError(
            code="invalid_repair_state",
            detail=f"Unknown current repair state {current_state!r}",
        )
    if target_state not in ALLOWED_REPAIR_TRANSITIONS:
        raise UnprocessableEntityError(
            code="invalid_repair_state",
            detail=f"Unknown target repair state {target_state!r}",
        )
    if current_proof_grade not in PROOF_GRADE_ORDER:
        raise UnprocessableEntityError(
            code="invalid_proof_grade",
            detail=f"Unknown current proof_grade {current_proof_grade!r}",
        )

    cur_state: RepairState = current_state
    nxt_state: RepairState = target_state
    cur_proof: ProofGrade = current_proof_grade

    resolved_proof_raw = current_proof_grade if target_proof_grade is None else target_proof_grade
    if resolved_proof_raw not in PROOF_GRADE_ORDER:
        raise UnprocessableEntityError(
            code="invalid_proof_grade",
            detail=f"Unknown target proof_grade {resolved_proof_raw!r}",
        )
    nxt_proof: ProofGrade = resolved_proof_raw

    if cur_state in TERMINAL_REPAIR_STATES:
        raise ConflictError(
            code="terminal_state_immutable",
            detail=(
                f"Terminal repair session in state {cur_state!r} cannot transition to "
                f"{nxt_state!r}; create a new retry session linked via parent_id."
            ),
        )

    allowed_targets = ALLOWED_REPAIR_TRANSITIONS[cur_state]
    if nxt_state not in allowed_targets:
        if cur_state == "repro_unconfirmed" or (
            nxt_state == "patching" and cur_state not in {"repro_confirmed", "verifying"}
        ):
            raise ConflictError(
                code="illegal_state_transition",
                detail=(
                    f"Illegal repair transition {cur_state!r} -> {nxt_state!r}: "
                    "ADR-031 prohibits patching without repro_confirmed."
                ),
            )
        raise ConflictError(
            code="illegal_state_transition",
            detail=f"Illegal repair transition {cur_state!r} -> {nxt_state!r}.",
        )

    if PROOF_GRADE_ORDER[nxt_proof] < PROOF_GRADE_ORDER[cur_proof]:
        raise ConflictError(
            code="proof_grade_regression",
            detail=(
                f"proof_grade is monotonic and cannot regress from {cur_proof!r} to {nxt_proof!r}."
            ),
        )

    if (
        nxt_state in STATES_REQUIRING_BASELINE_PROOF
        and PROOF_GRADE_ORDER[nxt_proof] < PROOF_GRADE_ORDER["baseline_confirmed"]
    ):
        raise ConflictError(
            code="adr031_baseline_unconfirmed",
            detail=(
                f"ADR-031 gate: state {nxt_state!r} requires proof_grade >= "
                f"'baseline_confirmed' (got {nxt_proof!r})."
            ),
        )

    if (
        nxt_state in STATES_REQUIRING_LOCAL_VERIFICATION
        and PROOF_GRADE_ORDER[nxt_proof] < PROOF_GRADE_ORDER["locally_verified"]
    ):
        raise ConflictError(
            code="proof_grade_insufficient",
            detail=(
                f"State {nxt_state!r} requires deterministic local verification "
                f"(proof_grade >= 'locally_verified', got {nxt_proof!r})."
            ),
        )

    if nxt_state == "remote_verified" and nxt_proof != "remotely_verified":
        raise ConflictError(
            code="proof_grade_insufficient",
            detail="State 'remote_verified' requires proof_grade == 'remotely_verified'.",
        )

    return nxt_state, nxt_proof


def to_repair_dto(row: RepairSessionModel) -> Repair:
    """Project `RepairSessionModel` to canonical `S-11` `Repair` wire contract."""
    suspension = (
        RepairSuspension.model_validate(row.suspension_json)
        if row.suspension_json is not None
        else None
    )
    return Repair(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        run_id=row.ci_run_id,
        state=cast(RepairState, row.state),
        proof_grade=cast(ProofGrade, row.proof_grade),
        remote_status=cast(RemoteStatus, row.remote_status),
        policy_revision=row.policy_revision,
        base_sha=row.base_sha,
        parent_id=row.parent_id,
        suspension=suspension,
        budget_id=row.budget_account_id,
    )


class RepairSessionStateMachine:
    """Row-locked transactional `S-11` repair session coordinator (`docs/08`, `ADR-038`)."""

    def __init__(self, *, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create_or_get_session_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        repository_id: str,
        ci_run_id: str,
        semantic_trigger_key: str,
        base_sha: str,
        target_ref: str,
        policy_revision: int,
        budget_account_id: str,
        correlation_id: str,
        parent_id: str | None = None,
        supersedes_id: str | None = None,
        causation_event_id: str | None = None,
        actor: str = "system:orchestrator",
    ) -> tuple[RepairSessionModel, bool]:
        """Idempotently create or return an existing repair session for a semantic trigger."""
        existing = (
            await db.execute(
                select(RepairSessionModel)
                .where(
                    RepairSessionModel.workspace_id == workspace_id,
                    RepairSessionModel.repository_id == repository_id,
                    RepairSessionModel.semantic_trigger_key == semantic_trigger_key,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing, False

        if parent_id is not None:
            parent_row = (
                await db.execute(
                    select(RepairSessionModel)
                    .where(
                        RepairSessionModel.workspace_id == workspace_id,
                        RepairSessionModel.id == parent_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if parent_row is None:
                raise NotFoundError(
                    code="repair_not_found",
                    detail=f"Parent repair session {parent_id} not found.",
                )
            if parent_row.state not in TERMINAL_REPAIR_STATES:
                raise ConflictError(
                    code="retry_requires_terminal_parent",
                    detail=(
                        f"Parent repair session {parent_id} is still active "
                        f"({parent_row.state!r}); retry requires a terminal parent session."
                    ),
                )

        now = datetime.now(tz=UTC)
        repair_id = new_uuid7(now=now)
        row = RepairSessionModel(
            id=repair_id,
            workspace_id=workspace_id,
            repository_id=repository_id,
            ci_run_id=ci_run_id,
            parent_id=parent_id,
            supersedes_id=supersedes_id,
            semantic_trigger_key=semantic_trigger_key,
            base_sha=base_sha,
            target_ref=target_ref,
            policy_revision=policy_revision,
            state="received",
            proof_grade="none",
            remote_status="not_published",
            suspension_json=None,
            budget_account_id=budget_account_id,
            active_reproduction_id=None,
            latest_diagnosis_id=None,
            patch_attempts_count=0,
            reason_code=None,
            status_detail=None,
            correlation_id=correlation_id,
            causation_event_id=causation_event_id,
            version=1,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        await db.flush()

        await enqueue_outbox_event(
            db,
            EventEnvelope(
                event_id=new_uuid7(now=now),
                type="repair.session.created",
                occurred_at=now,
                workspace_id=workspace_id,
                repository_id=repository_id,
                session_id=repair_id,
                aggregate_id=repair_id,
                aggregate_version=row.version,
                correlation_id=correlation_id,
                causation_id=causation_event_id,
                payload=RepairPhaseEventPayload(
                    repair_id=repair_id,
                    state="received",
                    reason_code="session_created",
                ),
            ),
            now=now,
        )
        actor_type, actor_id = _split_actor(actor)
        await append_audit_entry(
            db,
            workspace_id=workspace_id,
            repository_id=repository_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action="repair.session.created",
            target=repair_id,
            decision="allow",
            reason_code="session_created",
            correlation_id=correlation_id,
            occurred_at=now,
        )
        return row, True

    async def create_or_get_session(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        ci_run_id: str,
        semantic_trigger_key: str,
        base_sha: str,
        target_ref: str,
        policy_revision: int,
        budget_account_id: str,
        correlation_id: str,
        parent_id: str | None = None,
        supersedes_id: str | None = None,
        causation_event_id: str | None = None,
        actor: str = "system:orchestrator",
    ) -> tuple[Repair, bool]:
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            row, created = await self.create_or_get_session_in_tx(
                db,
                workspace_id=workspace_id,
                repository_id=repository_id,
                ci_run_id=ci_run_id,
                semantic_trigger_key=semantic_trigger_key,
                base_sha=base_sha,
                target_ref=target_ref,
                policy_revision=policy_revision,
                budget_account_id=budget_account_id,
                correlation_id=correlation_id,
                parent_id=parent_id,
                supersedes_id=supersedes_id,
                causation_event_id=causation_event_id,
                actor=actor,
            )
            return to_repair_dto(row), created

    async def transition_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        repair_id: str,
        target_state: RepairState,
        expected_version: int | None = None,
        target_proof_grade: ProofGrade | None = None,
        remote_status: RemoteStatus | None = None,
        reason_code: str | None = None,
        status_detail: str | None = None,
        active_reproduction_id: str | object | None = _UNSET,
        latest_diagnosis_id: str | object | None = _UNSET,
        patch_attempts_count: int | None = None,
        actor: str = "system:orchestrator",
        correlation_id: str | None = None,
        emit_phase_event: bool = True,
    ) -> RepairSessionModel:
        """Atomically transition a row-locked repair session with CAS & outbox/audit records."""
        row = (
            await db.execute(
                select(RepairSessionModel)
                .where(
                    RepairSessionModel.workspace_id == workspace_id,
                    RepairSessionModel.id == repair_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if row is None:
            raise NotFoundError(
                code="repair_not_found",
                detail=f"Repair session {repair_id} not found.",
            )

        if expected_version is not None and row.version != expected_version:
            raise ConflictError(
                code="version_conflict",
                detail=(
                    f"Repair session {repair_id} version {row.version} != "
                    f"expected {expected_version}."
                ),
            )

        if row.suspension_json is not None and target_state not in {
            "cancel_requested",
            "cancelled",
            "blocked",
            "needs_human",
        }:
            raise ConflictError(
                code="repair_session_suspended",
                detail=(
                    f"Repair session {repair_id} is suspended and must be resumed before "
                    f"transitioning to {target_state!r}."
                ),
            )

        nxt_state, nxt_proof = validate_repair_transition(
            current_state=row.state,
            target_state=target_state,
            current_proof_grade=row.proof_grade,
            target_proof_grade=target_proof_grade,
        )

        if remote_status is not None:
            if remote_status not in VALID_REMOTE_STATUSES:
                raise UnprocessableEntityError(
                    code="invalid_remote_status",
                    detail=f"Invalid remote_status {remote_status!r}",
                )
            row.remote_status = remote_status

        now = datetime.now(tz=UTC)
        prev_state = row.state
        row.state = nxt_state
        row.proof_grade = nxt_proof
        if nxt_state in TERMINAL_REPAIR_STATES:
            row.suspension_json = None
        if reason_code is not None:
            row.reason_code = reason_code[:120]
        if status_detail is not None:
            row.status_detail = status_detail[:1000]
        if active_reproduction_id is not _UNSET:
            row.active_reproduction_id = cast(str | None, active_reproduction_id)
        if latest_diagnosis_id is not _UNSET:
            row.latest_diagnosis_id = cast(str | None, latest_diagnosis_id)
        if patch_attempts_count is not None:
            row.patch_attempts_count = patch_attempts_count
        row.version += 1
        row.updated_at = now
        await db.flush()

        corr = correlation_id or row.correlation_id
        if emit_phase_event:
            event_type: str | None = None
            if nxt_state == "blocked":
                event_type = "repair.blocked"
            elif nxt_state == "cancelled":
                event_type = "repair.cancelled"
            elif nxt_state in {"diagnosed_only", "unsupported"}:
                event_type = "repair.diagnosed"

            if event_type is not None:
                await enqueue_outbox_event(
                    db,
                    EventEnvelope(
                        event_id=new_uuid7(now=now),
                        type=cast(Any, event_type),
                        occurred_at=now,
                        workspace_id=workspace_id,
                        repository_id=row.repository_id,
                        session_id=row.id,
                        aggregate_id=row.id,
                        aggregate_version=row.version,
                        correlation_id=corr,
                        payload=RepairPhaseEventPayload(
                            repair_id=row.id,
                            state=nxt_state,
                            reason_code=(reason_code or nxt_state)[:120],
                        ),
                    ),
                    now=now,
                )

        actor_type, actor_id = _split_actor(actor)
        await append_audit_entry(
            db,
            workspace_id=workspace_id,
            repository_id=row.repository_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action="repair.state.transition",
            target=f"{row.id}:{prev_state}->{nxt_state}",
            decision="allow",
            reason_code=(reason_code or nxt_state)[:120],
            correlation_id=corr,
            metadata={
                "from_state": prev_state,
                "to_state": nxt_state,
                "proof_grade": nxt_proof,
            },
            occurred_at=now,
        )
        return row

    async def transition_session(
        self,
        *,
        workspace_id: str,
        repair_id: str,
        target_state: RepairState,
        expected_version: int | None = None,
        target_proof_grade: ProofGrade | None = None,
        remote_status: RemoteStatus | None = None,
        reason_code: str | None = None,
        status_detail: str | None = None,
        actor: str = "system:orchestrator",
        correlation_id: str | None = None,
        emit_phase_event: bool = True,
    ) -> Repair:
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            row = await self.transition_in_tx(
                db,
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state=target_state,
                expected_version=expected_version,
                target_proof_grade=target_proof_grade,
                remote_status=remote_status,
                reason_code=reason_code,
                status_detail=status_detail,
                actor=actor,
                correlation_id=correlation_id,
                emit_phase_event=emit_phase_event,
            )
            return to_repair_dto(row)

    async def suspend_session(
        self,
        *,
        workspace_id: str,
        repair_id: str,
        reason: SuspensionReason,
        requested_by: str,
        correlation_id: str,
    ) -> Repair:
        """Pause a non-terminal repair session via `RepairSuspension` without mutating state."""
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            row = (
                await db.execute(
                    select(RepairSessionModel)
                    .where(
                        RepairSessionModel.workspace_id == workspace_id,
                        RepairSessionModel.id == repair_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if row is None:
                raise NotFoundError(
                    code="repair_not_found",
                    detail=f"Repair session {repair_id} not found.",
                )
            if row.state in TERMINAL_REPAIR_STATES:
                raise ConflictError(
                    code="terminal_state_immutable",
                    detail=f"Cannot suspend terminal repair session in state {row.state!r}.",
                )
            now = datetime.now(tz=UTC)
            suspension = RepairSuspension(
                reason=reason,
                checkpoint_state=cast(RepairState, row.state),
                requested_by=requested_by[:120],
                at=now,
            )
            row.suspension_json = suspension.model_dump(mode="json")
            row.version += 1
            row.updated_at = now
            await db.flush()
            actor_type, actor_id = _split_actor(requested_by)
            await append_audit_entry(
                db,
                workspace_id=workspace_id,
                repository_id=row.repository_id,
                actor_type=actor_type,
                actor_id=actor_id,
                action="repair.session.suspended",
                target=row.id,
                decision="allow",
                reason_code=reason,
                correlation_id=correlation_id,
                occurred_at=now,
            )
            return to_repair_dto(row)

    async def resume_session(
        self,
        *,
        workspace_id: str,
        repair_id: str,
        requested_by: str,
        correlation_id: str,
    ) -> Repair:
        """Resume a suspended non-terminal repair session from its checkpoint state."""
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            row = (
                await db.execute(
                    select(RepairSessionModel)
                    .where(
                        RepairSessionModel.workspace_id == workspace_id,
                        RepairSessionModel.id == repair_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if row is None:
                raise NotFoundError(
                    code="repair_not_found",
                    detail=f"Repair session {repair_id} not found.",
                )
            if row.suspension_json is None:
                return to_repair_dto(row)
            suspension = RepairSuspension.model_validate(row.suspension_json)
            if suspension.checkpoint_state != row.state:
                raise ConflictError(
                    code="suspension_checkpoint_mismatch",
                    detail=(
                        f"Checkpoint mismatch: suspension recorded "
                        f"{suspension.checkpoint_state!r} but session is in {row.state!r}."
                    ),
                )
            now = datetime.now(tz=UTC)
            row.suspension_json = None
            row.version += 1
            row.updated_at = now
            await db.flush()
            actor_type, actor_id = _split_actor(requested_by)
            await append_audit_entry(
                db,
                workspace_id=workspace_id,
                repository_id=row.repository_id,
                actor_type=actor_type,
                actor_id=actor_id,
                action="repair.session.resumed",
                target=row.id,
                decision="allow",
                reason_code="session_resumed",
                correlation_id=correlation_id,
                occurred_at=now,
            )
            return to_repair_dto(row)

    async def request_cancel(
        self,
        *,
        workspace_id: str,
        repair_id: str,
        requested_by: str,
        reason_code: str = "operator_cancelled",
        immediate: bool = False,
        correlation_id: str,
    ) -> Repair:
        """Request or finalize cancellation while preserving `proof_grade` & `remote_status`."""
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            row = (
                await db.execute(
                    select(RepairSessionModel)
                    .where(
                        RepairSessionModel.workspace_id == workspace_id,
                        RepairSessionModel.id == repair_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if row is None:
                raise NotFoundError(
                    code="repair_not_found",
                    detail=f"Repair session {repair_id} not found.",
                )
            if row.state == "cancelled":
                return to_repair_dto(row)
            if row.state == "cancel_requested" and not immediate:
                return to_repair_dto(row)
            if row.state in TERMINAL_REPAIR_STATES:
                raise ConflictError(
                    code="terminal_state_immutable",
                    detail=f"Cannot cancel terminal repair session in state {row.state!r}.",
                )

            if row.state == "cancel_requested":
                row = await self.transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state="cancelled",
                    reason_code=reason_code,
                    actor=requested_by[:120],
                    correlation_id=correlation_id,
                )
                return to_repair_dto(row)

            # Publishing in-flight writes MUST pass through cancel_requested first (docs/08)
            if immediate and row.state != "publishing":
                row = await self.transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state="cancelled",
                    reason_code=reason_code,
                    actor=requested_by[:120],
                    correlation_id=correlation_id,
                )
                return to_repair_dto(row)

            row = await self.transition_in_tx(
                db,
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state="cancel_requested",
                reason_code=reason_code,
                actor=requested_by[:120],
                correlation_id=correlation_id,
            )
            return to_repair_dto(row)
