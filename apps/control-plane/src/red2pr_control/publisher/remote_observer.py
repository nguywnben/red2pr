"""Exact-SHA remote CI verdict derivation for FIX-03 / V-08."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.crypto import sha256_canonical_json
from py_contracts.events import EventEnvelope, RemoteCiEventPayload
from py_contracts.primitives import new_uuid7
from red2pr_control.core.errors import ConflictError, NotFoundError
from red2pr_control.db.base import (
    PublicationRecordModel,
    RemoteCiCheckModel,
    RepairSessionModel,
    RequiredCheckSetModel,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.integrations.base import ProviderRemoteCheckRecord
from red2pr_control.integrations.github_app import GitHubIntegrationService
from red2pr_control.orchestrator.state_machine import RepairSessionStateMachine

RemoteOutcome = Literal["pending", "passed", "failed", "unknown"]


@dataclass(frozen=True, slots=True)
class RemoteVerdict:
    outcome: RemoteOutcome
    observations: tuple[dict[str, str | None], ...]
    missing_required: tuple[str, ...]
    wrong_sha_required: tuple[str, ...]


def evaluate_required_checks(
    *,
    expected_sha: str,
    required_names: Sequence[str],
    checks: Sequence[ProviderRemoteCheckRecord],
) -> RemoteVerdict:
    """Return green only when each required context completed successfully on exact SHA.

    Provider check lists are untrusted and may include stale or duplicate observations. Unknown,
    skipped, neutral and wrong-SHA observations can never satisfy a required check.
    """
    required = tuple(sorted({name.strip() for name in required_names if name.strip()}))
    normalized = tuple(
        {
            "check_name": check.name[:120],
            "external_id": check.external_check_id[:128],
            "head_sha": check.head_sha.lower()[:64],
            "status": check.status.lower()[:32],
            "conclusion": check.conclusion.lower()[:32] if check.conclusion else None,
        }
        for check in checks
    )
    exact = [check for check in checks if check.head_sha.lower() == expected_sha.lower()]
    missing: list[str] = []
    wrong_sha: list[str] = []
    pending = False
    failed = False
    for name in required:
        candidates = [item for item in exact if item.name == name]
        if not candidates:
            if any(item.name == name for item in checks):
                wrong_sha.append(name)
            else:
                missing.append(name)
            pending = True
            continue
        if any(
            item.status in {"queued", "in_progress", "pending", "running"} for item in candidates
        ):
            pending = True
        terminal = [
            item
            for item in candidates
            if item.status not in {"queued", "in_progress", "pending", "running"}
        ]
        if terminal and any(
            item.status not in {"completed", "success"} or item.conclusion != "success"
            for item in terminal
        ):
            # A terminal failure or skipped/neutral/cancelled result is never a pass.
            failed = True
    outcome: RemoteOutcome
    if failed:
        outcome = "failed"
    elif pending:
        outcome = "pending"
    elif required:
        outcome = "passed"
    else:
        # An empty/misconfigured set is never proof of remote success.
        outcome = "unknown"
    return RemoteVerdict(outcome, normalized, tuple(missing), tuple(wrong_sha))


class RemoteCiObserver:
    """Authenticated provider polling and transactional V-08 state promotion."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        integrations: GitHubIntegrationService,
        state_machine: RepairSessionStateMachine,
    ) -> None:
        self._session_factory = session_factory
        self._integrations = integrations
        self._state_machine = state_machine

    async def reconcile(
        self,
        *,
        workspace_id: str,
        publication_id: str,
        correlation_id: str,
        now: datetime | None = None,
    ) -> tuple[PublicationRecordModel, RemoteCiCheckModel]:
        ref_now = (now or datetime.now(tz=UTC)).astimezone(UTC)
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            publication = await db.scalar(
                select(PublicationRecordModel).where(
                    PublicationRecordModel.workspace_id == workspace_id,
                    PublicationRecordModel.id == publication_id,
                )
            )
            if publication is None:
                raise NotFoundError(
                    code="publication_not_found", detail="Publication was not found."
                )
            if publication.status != "published" or not publication.expected_commit_sha:
                raise ConflictError(
                    code="publication_not_ready_for_ci",
                    detail=(
                        "Remote CI can only be reconciled after the draft head SHA is confirmed."
                    ),
                )
            required = await db.scalar(
                select(RequiredCheckSetModel).where(
                    RequiredCheckSetModel.workspace_id == workspace_id,
                    RequiredCheckSetModel.repository_id == publication.repository_id,
                    RequiredCheckSetModel.policy_revision == publication.policy_revision,
                )
            )
            required_names = list(required.names_json) if required is not None else []
            set_digest = (
                required.digest
                if required is not None
                and publication.required_check_set_digest == required.digest
                and sha256_canonical_json(required_names) == required.digest
                else sha256_canonical_json([])
            )
            if required is not None and set_digest != required.digest:
                required_names = []
        adapter, ctx, repo_full_name = await self._integrations.resolve_publisher_target(
            workspace_id=workspace_id,
            repository_id=publication.repository_id,
        )
        if ctx.provider != publication.provider:
            raise ConflictError(
                code="publication_provider_changed",
                detail="Provider connection no longer matches the published draft.",
            )
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            checks = await adapter.get_remote_checks(
                db,
                ctx,
                repo_full_name=repo_full_name,
                head_sha=publication.expected_commit_sha,
                now=ref_now,
            )
        verdict = evaluate_required_checks(
            expected_sha=publication.expected_commit_sha,
            required_names=required_names,
            checks=checks,
        )
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            current = await db.scalar(
                select(PublicationRecordModel)
                .where(
                    PublicationRecordModel.workspace_id == workspace_id,
                    PublicationRecordModel.id == publication_id,
                )
                .with_for_update()
            )
            if current is None:
                raise NotFoundError(
                    code="publication_not_found", detail="Publication was not found."
                )
            if current.expected_commit_sha != publication.expected_commit_sha:
                raise ConflictError(
                    code="stale_remote_ci_observation",
                    detail="Published head changed while remote CI was being reconciled.",
                )
            remote = await db.scalar(
                select(RemoteCiCheckModel)
                .where(
                    RemoteCiCheckModel.workspace_id == workspace_id,
                    RemoteCiCheckModel.publication_id == publication_id,
                )
                .with_for_update()
            )
            if remote is None:
                remote = RemoteCiCheckModel(
                    id=str(new_uuid7(now=ref_now)),
                    workspace_id=workspace_id,
                    publication_id=publication_id,
                    head_sha=publication.expected_commit_sha,
                    expected_check_set_digest=set_digest,
                    observations_json=[],
                    outcome=verdict.outcome,
                    observed_at=ref_now,
                )
                db.add(remote)
            prior_outcome = remote.outcome
            remote.head_sha = publication.expected_commit_sha
            remote.expected_check_set_digest = set_digest
            remote.observations_json = list(verdict.observations)
            remote.outcome = verdict.outcome
            remote.observed_at = ref_now
            repair = await db.scalar(
                select(RepairSessionModel)
                .where(
                    RepairSessionModel.workspace_id == workspace_id,
                    RepairSessionModel.id == publication.repair_id,
                )
                .with_for_update()
            )
            if repair is None:
                raise NotFoundError(code="repair_not_found", detail="Repair session was not found.")
            if repair.state == "remote_validating":
                if verdict.outcome == "passed":
                    await self._state_machine.transition_in_tx(
                        db,
                        workspace_id=workspace_id,
                        repair_id=repair.id,
                        target_state="remote_verified",
                        target_proof_grade="remotely_verified",
                        remote_status="passed",
                        reason_code="all_required_remote_checks_passed_exact_sha",
                        actor="service:remote_ci_observer",
                        correlation_id=correlation_id,
                    )
                elif verdict.outcome in {"failed", "unknown"}:
                    await self._state_machine.transition_in_tx(
                        db,
                        workspace_id=workspace_id,
                        repair_id=repair.id,
                        target_state=(
                            "remote_failed" if verdict.outcome == "failed" else "remote_unknown"
                        ),
                        remote_status=("failed" if verdict.outcome == "failed" else "unknown"),
                        reason_code=f"remote_ci_{verdict.outcome}",
                        actor="service:remote_ci_observer",
                        correlation_id=correlation_id,
                    )
                else:
                    repair.remote_status = "pending"
                    repair.version += 1
                    repair.updated_at = ref_now
            if prior_outcome != verdict.outcome:
                await enqueue_outbox_event(
                    db,
                    EventEnvelope(
                        event_id=str(new_uuid7(now=ref_now)),
                        type="repair.remote_ci.completed",
                        occurred_at=ref_now,
                        workspace_id=workspace_id,
                        repository_id=publication.repository_id,
                        session_id=repair.id,
                        aggregate_id=repair.id,
                        aggregate_version=repair.version,
                        correlation_id=correlation_id,
                        payload=RemoteCiEventPayload(
                            publication_id=publication.id,
                            head_sha=publication.expected_commit_sha,
                            outcome=verdict.outcome,
                        ),
                    ),
                    now=ref_now,
                )
            await db.flush()
            return current, remote
