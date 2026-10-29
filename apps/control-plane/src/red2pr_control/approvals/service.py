"""Transactional approval creation and decision logic (U19 / A-11 / APP-02)."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.crypto import sha256_canonical_json
from py_contracts.events import ApprovalEventPayload, EventEnvelope
from py_contracts.primitives import new_uuid7
from py_contracts.repairs import Approval
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import ConflictError, GoneError, NotFoundError
from red2pr_control.db.base import (
    ApprovalRequestModel,
    ApprovalVoteModel,
    AuditLogModel,
    PatchAttemptModel,
    RepairSessionModel,
    RepositoryPolicyModel,
    VerificationRunModel,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import workspace_rls_session

APPROVAL_TTL = timedelta(hours=24)
_TEST_CONFIG_PATHS = (
    ".github/workflows/",
    ".gitlab-ci",
    "test",
    "tests/",
    "pytest.ini",
    "tox.ini",
    "pyproject.toml",
    "package.json",
    "Dockerfile",
    ".yaml",
    ".yml",
)


def approval_dto(row: ApprovalRequestModel) -> Approval:
    return Approval(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        repair_id=row.repair_id,
        intent_type=row.intent_type,  # type: ignore[arg-type]
        patch_digest=row.patch_digest,
        base_sha=row.base_sha,
        target_ref=row.target_ref,
        policy_revision=row.policy_revision,
        expires_at=row.expires_at,
        status=row.status,  # type: ignore[arg-type]
        decision_actor=row.decision_actor,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.decided_at or row.created_at,
    )


async def create_approval_for_verified_patch(
    db: AsyncSession,
    *,
    repair: RepairSessionModel,
    patch: PatchAttemptModel,
    actor_id: str | None,
    correlation_id: str,
    now: datetime,
) -> ApprovalRequestModel | None:
    """Create one pending request after local verification for approval-mode repos."""
    policy = await db.scalar(
        select(RepositoryPolicyModel).where(
            RepositoryPolicyModel.workspace_id == repair.workspace_id,
            RepositoryPolicyModel.repository_id == repair.repository_id,
            RepositoryPolicyModel.revision == repair.policy_revision,
        )
    )
    if policy is None or policy.mode != "approval":
        return None
    verification = await db.scalar(
        select(VerificationRunModel)
        .where(
            VerificationRunModel.workspace_id == repair.workspace_id,
            VerificationRunModel.repair_id == repair.id,
            VerificationRunModel.patch_digest == patch.patch_digest,
            VerificationRunModel.status == "verified",
            VerificationRunModel.proof_grade == "locally_verified",
        )
        .order_by(VerificationRunModel.created_at.desc())
    )
    if verification is None:
        return None
    existing = await db.scalar(
        select(ApprovalRequestModel)
        .where(
            ApprovalRequestModel.workspace_id == repair.workspace_id,
            ApprovalRequestModel.repair_id == repair.id,
            ApprovalRequestModel.patch_digest == patch.patch_digest,
            ApprovalRequestModel.policy_revision == repair.policy_revision,
            ApprovalRequestModel.status == "pending",
        )
        .with_for_update()
    )
    if existing is not None:
        return existing
    lowered_paths = [path.lower() for path in patch.changed_paths_json]
    sensitive = any(any(token in path for token in _TEST_CONFIG_PATHS) for path in lowered_paths)
    intent = (
        "test_modification"
        if any("test" in path for path in lowered_paths)
        else ("sensitive_path_change" if sensitive else "publish_draft_pr")
    )
    requester_id = await db.scalar(
        select(AuditLogModel.actor_id)
        .where(
            AuditLogModel.workspace_id == repair.workspace_id,
            AuditLogModel.target == repair.id,
            AuditLogModel.action == "repair.session.created",
            AuditLogModel.actor_type == "user",
        )
        .order_by(AuditLogModel.occurred_at.asc())
        .limit(1)
    )
    row = ApprovalRequestModel(
        id=new_uuid7(now=now),
        workspace_id=repair.workspace_id,
        repository_id=repair.repository_id,
        repair_id=repair.id,
        intent_type=intent,
        patch_digest=patch.patch_digest,
        base_sha=patch.base_sha,
        target_ref=repair.target_ref,
        policy_revision=repair.policy_revision,
        requested_by=requester_id,
        risk_level="sensitive" if sensitive else "review",
        scope_description=(
            f"Review verified patch attempt {patch.attempt_number} "
            f"({len(patch.changed_paths_json)} changed paths)."
        ),
        sensitive_change=sensitive,
        expires_at=now + APPROVAL_TTL,
        status="pending",
        correlation_id=correlation_id,
        created_at=now,
    )
    db.add(row)
    await db.flush()
    await enqueue_outbox_event(
        db,
        EventEnvelope(
            event_id=new_uuid7(now=now),
            type="repair.approval.requested",
            occurred_at=now,
            workspace_id=repair.workspace_id,
            repository_id=repair.repository_id,
            session_id=repair.id,
            aggregate_id=row.id,
            aggregate_version=1,
            correlation_id=correlation_id,
            payload=ApprovalEventPayload(
                approval_id=row.id,
                status="pending",
                expires_at=now + APPROVAL_TTL,
            ),
        ),
        now=now,
    )
    await append_audit_entry(
        db,
        workspace_id=repair.workspace_id,
        repository_id=repair.repository_id,
        actor_type="user" if actor_id else "system",
        actor_id=actor_id or "deterministic-verifier",
        action="repair.approval.requested",
        target=row.id,
        decision="allow",
        reason_code="locally_verified_patch_requires_review",
        correlation_id=correlation_id,
        occurred_at=now,
        metadata={
            "repair_id": repair.id,
            "patch_digest": patch.patch_digest,
            "policy_revision": repair.policy_revision,
        },
    )
    return row


class ApprovalService:
    def __init__(self, *, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def decide(
        self,
        *,
        workspace_id: str,
        approval_id: str,
        actor_id: str,
        decision: str,
        reason: str | None,
        expected_patch_digest: str,
        expected_policy_revision: int,
        idempotency_key: str,
        correlation_id: str,
        now: datetime,
    ) -> ApprovalRequestModel:
        if len(idempotency_key) > 120 or not idempotency_key:
            raise ConflictError(
                code="idempotency_key_invalid", detail="A bounded Idempotency-Key is required."
            )
        request_hash = sha256_canonical_json(
            {
                "approval_id": approval_id,
                "decision": decision,
                "reason": reason,
                "expected_patch_digest": expected_patch_digest,
                "expected_policy_revision": expected_policy_revision,
            }
        )
        deferred_error: Exception | None = None
        result: ApprovalRequestModel | None = None
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            prior = await db.scalar(
                select(ApprovalVoteModel).where(
                    ApprovalVoteModel.workspace_id == workspace_id,
                    ApprovalVoteModel.idempotency_key == idempotency_key,
                )
            )
            if prior is not None:
                if prior.request_digest != request_hash or prior.user_id != actor_id:
                    raise ConflictError(
                        code="idempotency_key_reused",
                        detail="Idempotency key is already bound to another approval decision.",
                    )
                return await self._get_request(db, workspace_id, approval_id)
            row = await self._get_request(db, workspace_id, approval_id, lock=True)
            if row.expires_at <= now:
                if row.status == "pending":
                    row.status = "expired"
                    row.version += 1
                    await db.flush()
                deferred_error = GoneError(
                    code="approval_expired", detail="Approval request has expired."
                )
            elif row.status != "pending":
                raise ConflictError(
                    code="approval_not_pending", detail="Approval request is no longer pending."
                )
            elif (
                row.patch_digest != expected_patch_digest
                or row.policy_revision != expected_policy_revision
            ):
                deferred_error = ConflictError(
                    code="approval_binding_stale",
                    detail="Patch or policy binding does not match the current approval request.",
                )
            if deferred_error is not None:
                result = row
            else:
                repair = await db.scalar(
                    select(RepairSessionModel)
                    .where(
                        RepairSessionModel.workspace_id == workspace_id,
                        RepairSessionModel.id == row.repair_id,
                    )
                    .with_for_update()
                )
                patch = await db.scalar(
                    select(PatchAttemptModel)
                    .where(
                        PatchAttemptModel.workspace_id == workspace_id,
                        PatchAttemptModel.repair_id == row.repair_id,
                    )
                    .order_by(PatchAttemptModel.attempt_number.desc())
                    .limit(1)
                )
                policy = await db.scalar(
                    select(RepositoryPolicyModel)
                    .where(
                        RepositoryPolicyModel.workspace_id == workspace_id,
                        RepositoryPolicyModel.repository_id == row.repository_id,
                    )
                    .order_by(RepositoryPolicyModel.revision.desc())
                    .limit(1)
                )
            if deferred_error is None and (repair is None or patch is None or policy is None):
                raise NotFoundError(
                    code="approval_not_found", detail="Approval request was not found."
                )
            if (
                deferred_error is None
                and repair is not None
                and patch is not None
                and policy is not None
                and (
                    patch.patch_digest != row.patch_digest
                    or repair.base_sha != row.base_sha
                    or repair.target_ref != row.target_ref
                    or policy.revision != row.policy_revision
                )
            ):
                row.status = "revoked"
                row.version += 1
                await db.flush()
                deferred_error = ConflictError(
                    code="approval_binding_stale",
                    detail="Current patch, target, or policy changed; request was revoked.",
                )
            if deferred_error is None and row.sensitive_change and row.requested_by == actor_id:
                raise ConflictError(
                    code="separation_of_duties",
                    detail=(
                        "A requester cannot approve their own sensitive test or "
                        "configuration change."
                    ),
                )
            if deferred_error is not None:
                result = row
            else:
                vote = ApprovalVoteModel(
                    id=new_uuid7(now=now),
                    workspace_id=workspace_id,
                    approval_request_id=row.id,
                    user_id=actor_id,
                    decision=decision,
                    reason=reason,
                    idempotency_key=idempotency_key,
                    request_digest=request_hash,
                    correlation_id=correlation_id,
                    created_at=now,
                )
                db.add(vote)
                row.status = "approved" if decision == "approve" else "rejected"
                row.version += 1
                row.decision = decision
                row.decision_actor = actor_id
                row.decided_at = now
                row.reason = reason
                await db.flush()
                await enqueue_outbox_event(
                    db,
                    EventEnvelope(
                        event_id=new_uuid7(now=now),
                        type="repair.approval.decided",
                        occurred_at=now,
                        workspace_id=workspace_id,
                        repository_id=row.repository_id,
                        session_id=row.repair_id,
                        aggregate_id=row.id,
                        aggregate_version=2,
                        correlation_id=correlation_id,
                        payload=ApprovalEventPayload(
                            approval_id=row.id, status=row.status, expires_at=row.expires_at
                        ),
                    ),
                    now=now,
                )
                await append_audit_entry(
                    db,
                    workspace_id=workspace_id,
                    repository_id=row.repository_id,
                    actor_type="user",
                    actor_id=actor_id,
                    action="repair.approval.decided",
                    target=row.id,
                    decision="allow",
                    reason_code=decision,
                    correlation_id=correlation_id,
                    occurred_at=now,
                    metadata={
                        "patch_digest": row.patch_digest,
                        "policy_revision": row.policy_revision,
                    },
                )
                result = row
        if deferred_error is not None:
            raise deferred_error
        assert result is not None
        return result

    @staticmethod
    async def _get_request(
        db: AsyncSession, workspace_id: str, approval_id: str, *, lock: bool = False
    ) -> ApprovalRequestModel:
        stmt = select(ApprovalRequestModel).where(
            ApprovalRequestModel.workspace_id == workspace_id,
            ApprovalRequestModel.id == approval_id,
        )
        if lock:
            stmt = stmt.with_for_update()
        row = await db.scalar(stmt)
        if row is None:
            raise NotFoundError(code="approval_not_found", detail="Approval request was not found.")
        return row
