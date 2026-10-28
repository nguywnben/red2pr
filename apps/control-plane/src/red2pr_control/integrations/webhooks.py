"""Authenticated raw-body webhook ingress & semantic run-attempt trigger normalizer (`U11`).

Implements `SRC-03`, `A-22` (GitHub/GitLab slice), `S-10`, `S-19`, `W-03`, `NFR-01`, `NFR-03`,
`SEC-001`, `SEC-002`, `SEC-003`, `SEC-011`, `SEC-027`, and `SEC-032`:
- Raw-byte cryptographic signature/token verification BEFORE JSON parsing (`GitHubAppAdapter`
  `X-Hub-Signature-256` and `GitLabAdapter` pinned `gitlab_signed_v19` vs `gitlab_legacy_token`
  with zero silent downgrade).
- Browser `Cookie` authentication rejection on `/api/v1/hooks/*` (`A-22`).
- Durable `webhook_inbox` persistence (`UNIQUE (connection_id, provider_delivery_id)`) returning
  `202 Accepted` (or `200 OK` on identical duplicate delivery, `409 Conflict` on mutated digest)
  strictly AFTER PostgreSQL `fsync` transaction commit; any DB persistence failure returns `503`.
- Race-safe semantic run-attempt deduplication (`uq_ci_run_triggers_semantic`) across concurrent
  duplicate/reordered webhooks (`workflow_job` + `workflow_run` / `Job Hook` + `Pipeline Hook`)
  and overlapping local polling, backed by `90d` `effect_tombstones` anti-replay protection and
  bot-authored `red2pr/` repair-branch loop suppression.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, Depends, Path, Request
from fastapi.responses import JSONResponse
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.crypto import verify_hmac_sha256_hex
from py_contracts.events import EventEnvelope, RunEventPayload
from py_contracts.integrations import (
    ProviderKind,
    WebhookInboxStatus,
    WebhookIngressDisposition,
    WebhookIngressReceipt,
)
from py_contracts.primitives import MAX_JSON_BODY_BYTES, InternalId, Problem, new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    PROBLEM_JSON_MEDIA_TYPE,
    BadRequestError,
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    PayloadTooLargeError,
    Red2PrError,
    UnauthorizedError,
)
from red2pr_control.core.logging import current_correlation_id, get_structured_logger
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.db.base import (
    CiRunTriggerModel,
    EffectTombstoneModel,
    ProviderConnectionModel,
    RepositoryModel,
    RepositoryPolicyModel,
    TaskJobModel,
    WebhookInboxModel,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.sessions import extract_client_ip
from red2pr_control.integrations.base import (
    ProviderConnectionContext,
    ProviderError,
)
from red2pr_control.integrations.github_app import (
    GitHubAppAdapter,
    GitHubIntegrationService,
    WorkflowHazardScanner,
    _to_connection_context,
)
from red2pr_control.integrations.gitlab_client import (
    GitLabAdapter,
    _map_gitlab_pipeline_status,
)
from red2pr_control.repositories.glob_guard import (
    canonicalize_branch_ref,
    first_matching_glob,
)

WEBHOOK_INBOX_RETENTION = timedelta(days=90)
TOMBSTONE_RETENTION = timedelta(days=90)
DEFAULT_STALE_REPLAY_THRESHOLD = timedelta(hours=6)
FAILURE_CONCLUSIONS: frozenset[str] = frozenset({"failure", "timed_out", "action_required"})

_UUID_ADAPTER: TypeAdapter[str] = TypeAdapter(InternalId)
_LOGGER = get_structured_logger("red2pr_control.integrations.webhooks")

_SENSITIVE_WEBHOOK_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-gitlab-token",
        "private-token",
        "job-token",
        "x-hub-signature",
        "x-hub-signature-256",
        "webhook-signature",
        "x-csrf-token",
    }
)


@dataclass(frozen=True, slots=True)
class NormalizedRunCandidate:
    """Provider-neutral run/pipeline candidate extracted from webhook or polling."""

    provider: ProviderKind
    external_repo_id: str | None
    repo_full_name: str | None
    provider_run_id: str
    attempt_key: str
    head_sha: str
    ref: str
    event_type: str
    status: str
    conclusion: str | None
    jobs_complete: bool
    raw_vendor_status: str | None = None
    untrusted_fork: bool = False
    commit_message: str | None = None
    actor_login: str | None = None
    event_timestamp: datetime | None = None
    explicit_rerun: bool = False
    needs_live_run_lookup: bool = False


@dataclass(frozen=True, slots=True)
class TriggerResolution:
    """Outcome of processing a `NormalizedRunCandidate` inside a workspace RLS transaction."""

    inbox_status: WebhookInboxStatus
    disposition: WebhookIngressDisposition
    reason_code: str
    trigger_id: str | None = None
    job_id: str | None = None
    created: bool = False


def _parse_iso_utc(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    cleaned = raw.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def sanitize_webhook_headers(
    headers: Mapping[str, str],
    *,
    redactor: Redactor,
) -> dict[str, str]:
    """Produce a safe redacted header dictionary stripping signatures, tokens & cookies."""
    sanitized: dict[str, str] = {}
    for raw_k, raw_v in headers.items():
        clean_k = raw_k.strip().lower()[:80]
        if not clean_k:
            continue
        if clean_k in _SENSITIVE_WEBHOOK_HEADERS or clean_k.endswith(
            ("-token", "-secret", "-key", "-signature")
        ):
            sanitized[clean_k] = "[REDACTED]"
        else:
            sanitized[clean_k] = redactor.redact_text(str(raw_v).strip())[:256]
    return sanitized


def is_bot_authored_repair_loop(
    *,
    ref: str,
    commit_message: str | None = None,
    actor_login: str | None = None,
    connection_account_login: str | None = None,
) -> bool:
    """Return `True` if event originates from a Red2PR repair branch or bot marker (`W-03`)."""
    clean_ref = ref.strip().removeprefix("refs/heads/").removeprefix("refs/tags/")
    if clean_ref.startswith("red2pr/"):
        return True
    if commit_message:
        lowered_msg = commit_message.lower()
        if "[red2pr-bot]" in lowered_msg or "<!-- red2pr:" in lowered_msg:
            return True
    if actor_login:
        clean_actor = actor_login.strip().lower()
        if clean_actor in {"red2pr[bot]", "red2pr-bot"}:
            return True
        if (
            connection_account_login
            and clean_ref.startswith("red2pr")
            and clean_actor
            in {
                connection_account_login.strip().lower(),
                f"{connection_account_login.strip().lower()}[bot]",
            }
        ):
            return True
    return False


async def resolve_tracked_repository(
    db: AsyncSession,
    *,
    workspace_id: str,
    connection_id: str,
    external_repo_id: str | None,
    repo_full_name: str | None,
) -> RepositoryModel | None:
    """Locate an active workspace repository bound to `(workspace_id, connection_id)`."""
    if external_repo_id:
        row = await db.scalar(
            select(RepositoryModel).where(
                RepositoryModel.workspace_id == workspace_id,
                RepositoryModel.provider_connection_id == connection_id,
                RepositoryModel.external_repo_id == external_repo_id,
                RepositoryModel.active.is_(True),
            )
        )
        if row is not None:
            return row
    if repo_full_name:
        cleaned_name = repo_full_name.strip()[:120]
        by_name: RepositoryModel | None = await db.scalar(
            select(RepositoryModel).where(
                RepositoryModel.workspace_id == workspace_id,
                RepositoryModel.provider_connection_id == connection_id,
                RepositoryModel.name == cleaned_name,
                RepositoryModel.active.is_(True),
            )
        )
        if by_name is not None:
            return by_name
    return None


async def record_normalized_run_failure_trigger(
    db: AsyncSession,
    *,
    workspace_id: str,
    conn_row: ProviderConnectionModel,
    repo_row: RepositoryModel,
    candidate: NormalizedRunCandidate,
    source: Literal["webhook", "poll", "reconcile"],
    inbox_id: str | None,
    correlation_id: str,
    redactor: Redactor,
    now: datetime,
) -> TriggerResolution:
    """Atomically deduplicate & record a CI run-attempt failure trigger (`SEC-002`, `W-03`).

    Guarantees via PostgreSQL `ON CONFLICT ON CONSTRAINT uq_ci_run_triggers_semantic DO NOTHING`
    and `90d` `effect_tombstones` that concurrent duplicate/reordered webhooks + overlapping
    polling create at most ONE trigger, ONE `S-19` outbox event, and ONE `task_jobs` item per
    `(workspace_id, repository_id, provider_run_id, attempt_key)`.
    """
    if is_bot_authored_repair_loop(
        ref=candidate.ref,
        commit_message=candidate.commit_message,
        actor_login=candidate.actor_login,
        connection_account_login=conn_row.account_login,
    ):
        return TriggerResolution(
            inbox_status="ignored",
            disposition="ignored_bot_loop",
            reason_code="bot_repair_branch_ignored",
        )

    if not candidate.jobs_complete or candidate.conclusion not in FAILURE_CONCLUSIONS:
        return TriggerResolution(
            inbox_status="ignored",
            disposition="ignored_non_failure",
            reason_code="non_failing_or_incomplete_run",
        )

    if repo_row.paused:
        await append_audit_entry(
            db,
            workspace_id=workspace_id,
            repository_id=repo_row.id,
            actor_type="system",
            actor_id=f"ingestor:{source}",
            action="integration.run_trigger.skipped_paused",
            target=f"repository:{repo_row.id}:run:{candidate.attempt_key[:80]}",
            decision="deny",
            reason_code="repository_paused",
            correlation_id=correlation_id,
            client_ip=None,
            metadata={
                "provider": candidate.provider,
                "provider_run_id": candidate.provider_run_id[:80],
                "attempt_key": candidate.attempt_key[:80],
                "source": source,
            },
            occurred_at=now,
        )
        return TriggerResolution(
            inbox_status="ignored",
            disposition="ignored_repository_paused",
            reason_code="repository_paused",
        )

    clean_run_id = candidate.provider_run_id.strip()[:128]
    clean_attempt_key = candidate.attempt_key.strip()[:128]
    clean_sha = (candidate.head_sha.strip() or "unknown")[:64]
    clean_ref = (candidate.ref.strip() or repo_row.default_branch)[:120]
    clean_event = (candidate.event_type.strip() or "unknown")[:120]
    clean_status = (
        candidate.status
        if candidate.status in {"queued", "in_progress", "completed", "unknown"}
        else "completed"
    )
    clean_conclusion = candidate.conclusion

    logical_effect_key = (f"ci_run_trigger:{repo_row.id}:{clean_run_id}:{clean_attempt_key}")[:256]
    tombstone_op = "provider.ci_run.trigger"

    # 1. Check >=90d anti-replay tombstone before claiming (`NFR-07`, `T-SRC-03-N`)
    existing_tombstone = await db.scalar(
        select(EffectTombstoneModel).where(
            EffectTombstoneModel.workspace_id == workspace_id,
            EffectTombstoneModel.operation == tombstone_op,
            EffectTombstoneModel.logical_effect_key == logical_effect_key,
            EffectTombstoneModel.retained_until > now,
        )
    )
    if existing_tombstone is not None:
        existing_trigger = await db.scalar(
            select(CiRunTriggerModel).where(
                CiRunTriggerModel.workspace_id == workspace_id,
                CiRunTriggerModel.repository_id == repo_row.id,
                CiRunTriggerModel.provider_run_id == clean_run_id,
                CiRunTriggerModel.attempt_key == clean_attempt_key,
            )
        )
        if existing_trigger is not None:
            return TriggerResolution(
                inbox_status="duplicate_semantic",
                disposition="duplicate_semantic",
                reason_code="semantic_run_attempt_already_triggered",
                trigger_id=existing_trigger.id,
                job_id=existing_trigger.job_id,
                created=False,
            )
        return TriggerResolution(
            inbox_status="ignored",
            disposition="ignored_stale_replay",
            reason_code="tombstone_replay_blocked",
            created=False,
        )

    # 2. Check whether a prior attempt for the same run (or prior pipeline on same SHA) exists
    prior_same_run = await db.scalar(
        select(CiRunTriggerModel.id)
        .where(
            CiRunTriggerModel.workspace_id == workspace_id,
            CiRunTriggerModel.repository_id == repo_row.id,
            CiRunTriggerModel.provider_run_id == clean_run_id,
            CiRunTriggerModel.attempt_key != clean_attempt_key,
        )
        .limit(1)
    )
    is_rerun = bool(prior_same_run is not None or candidate.explicit_rerun)

    # 3. Race-safe PostgreSQL atomic semantic claim (`uq_ci_run_triggers_semantic`)
    candidate_trigger_id = new_uuid7(now=now)
    insert_trigger_stmt = (
        pg_insert(CiRunTriggerModel)
        .values(
            id=candidate_trigger_id,
            workspace_id=workspace_id,
            connection_id=conn_row.id,
            repository_id=repo_row.id,
            provider=candidate.provider,
            provider_run_id=clean_run_id,
            attempt_key=clean_attempt_key,
            head_sha=clean_sha,
            ref=clean_ref,
            event_type=clean_event,
            status=clean_status,
            conclusion=clean_conclusion,
            jobs_complete=True,
            raw_vendor_status=(
                redactor.redact_text(candidate.raw_vendor_status)[:120]
                if candidate.raw_vendor_status
                else None
            ),
            is_rerun=is_rerun,
            untrusted_fork=candidate.untrusted_fork,
            first_source=source,
            first_inbox_id=inbox_id,
            job_id=None,
            correlation_id=correlation_id,
            triggered_at=now,
            version=1,
            created_at=now,
            updated_at=now,
        )
        .on_conflict_do_nothing(constraint="uq_ci_run_triggers_semantic")
        .returning(CiRunTriggerModel.id)
    )
    inserted_trigger_id = await db.scalar(insert_trigger_stmt)

    if inserted_trigger_id is None:
        winner = await db.scalar(
            select(CiRunTriggerModel).where(
                CiRunTriggerModel.workspace_id == workspace_id,
                CiRunTriggerModel.repository_id == repo_row.id,
                CiRunTriggerModel.provider_run_id == clean_run_id,
                CiRunTriggerModel.attempt_key == clean_attempt_key,
            )
        )
        return TriggerResolution(
            inbox_status="duplicate_semantic",
            disposition="duplicate_semantic",
            reason_code="concurrent_semantic_duplicate_suppressed",
            trigger_id=winner.id if winner is not None else None,
            job_id=winner.job_id if winner is not None else None,
            created=False,
        )

    # 4. Winning transaction: record 90d tombstone, S-19 outbox event, triage job & audit entry
    req_hash = hashlib.sha256(logical_effect_key.encode("utf-8")).hexdigest()
    await db.execute(
        pg_insert(EffectTombstoneModel)
        .values(
            id=new_uuid7(now=now),
            workspace_id=workspace_id,
            logical_effect_key=logical_effect_key,
            operation=tombstone_op,
            origin_operation_id=inserted_trigger_id,
            idempotency_key=inserted_trigger_id,
            request_hash=req_hash,
            resource_id=inserted_trigger_id,
            retained_until=now + TOMBSTONE_RETENTION,
            created_at=now,
        )
        .on_conflict_do_nothing(constraint="uq_effect_tombstones_logical_effect")
    )

    outbox_event_type: Literal["provider.run.failed", "provider.run.retried"] = (
        "provider.run.retried" if is_rerun else "provider.run.failed"
    )
    await enqueue_outbox_event(
        db,
        EventEnvelope(
            event_id=new_uuid7(now=now),
            type=outbox_event_type,
            occurred_at=now,
            workspace_id=workspace_id,
            repository_id=repo_row.id,
            aggregate_id=inserted_trigger_id,
            aggregate_version=1,
            correlation_id=correlation_id,
            payload=RunEventPayload(
                run_id=inserted_trigger_id,
                attempt_key=clean_attempt_key,
                head_sha=clean_sha[:120],
            ),
        ),
        now=now,
    )

    pol_row = await db.scalar(
        select(RepositoryPolicyModel).where(
            RepositoryPolicyModel.workspace_id == workspace_id,
            RepositoryPolicyModel.repository_id == repo_row.id,
            RepositoryPolicyModel.revision == repo_row.policy_revision,
        )
    )
    branch_allowed = True
    if pol_row is not None:
        try:
            canon_branch = canonicalize_branch_ref(clean_ref)
            if first_matching_glob(pol_row.branch_denylist_json, canon_branch) is not None or (
                pol_row.branch_allowlist_json
                and first_matching_glob(pol_row.branch_allowlist_json, canon_branch) is None
            ):
                branch_allowed = False
        except Exception:
            branch_allowed = False

    allow_sandbox_execution = bool(
        repo_row.mode in ("approval", "auto_repair")
        and not repo_row.paused
        and not candidate.untrusted_fork
        and branch_allowed
    )

    dedup_key = f"ci_run.triage:{repo_row.id}:{clean_run_id}:{clean_attempt_key}"[:256]
    job_id = new_uuid7(now=now)
    job_row = TaskJobModel(
        id=job_id,
        workspace_id=workspace_id,
        repository_id=repo_row.id,
        repair_id=None,
        kind="ci_run.triage",
        is_repair_job=False,
        resource_id=inserted_trigger_id,
        state="queued",
        priority=100,
        dedup_key=dedup_key,
        logical_effect_key=logical_effect_key,
        budget_key=f"triage:{repo_row.id}",
        correlation_id=correlation_id,
        payload_json={
            "trigger_id": inserted_trigger_id,
            "connection_id": conn_row.id,
            "repository_id": repo_row.id,
            "repository_name": repo_row.name,
            "repository_mode": repo_row.mode,
            "policy_revision": repo_row.policy_revision,
            "allow_sandbox_execution": allow_sandbox_execution,
            "provider": candidate.provider,
            "provider_run_id": clean_run_id,
            "attempt_key": clean_attempt_key,
            "head_sha": clean_sha,
            "ref": clean_ref,
            "conclusion": clean_conclusion,
            "is_rerun": is_rerun,
            "untrusted_fork": candidate.untrusted_fork,
            "source": source,
        },
        attempt=1,
        max_attempts=3,
        lease_epoch=0,
        not_before=now,
        deadline=now + timedelta(minutes=30),
        recoverable=True,
        reconcile_required=False,
        version=1,
        created_at=now,
        updated_at=now,
    )
    db.add(job_row)
    await db.flush()

    trigger_row = await db.scalar(
        select(CiRunTriggerModel).where(
            CiRunTriggerModel.workspace_id == workspace_id,
            CiRunTriggerModel.id == inserted_trigger_id,
        )
    )
    if trigger_row is not None:
        trigger_row.job_id = job_id
        await db.flush()

    await append_audit_entry(
        db,
        workspace_id=workspace_id,
        repository_id=repo_row.id,
        actor_type="system",
        actor_id=f"ingestor:{source}",
        action="integration.run_trigger.recorded",
        target=f"ci_run_trigger:{inserted_trigger_id}",
        decision="allow",
        reason_code="run_attempt_retriggered" if is_rerun else "run_failure_detected",
        correlation_id=correlation_id,
        client_ip=None,
        metadata={
            "provider": candidate.provider,
            "provider_run_id": clean_run_id,
            "attempt_key": clean_attempt_key,
            "head_sha": clean_sha,
            "is_rerun": is_rerun,
            "untrusted_fork": candidate.untrusted_fork,
            "job_id": job_id,
            "source": source,
        },
        occurred_at=now,
    )
    return TriggerResolution(
        inbox_status="normalized",
        disposition="accepted_trigger",
        reason_code="run_attempt_retriggered" if is_rerun else "run_failure_detected",
        trigger_id=inserted_trigger_id,
        job_id=job_id,
        created=True,
    )


def _extract_github_candidate(
    event_name: str,
    payload: Mapping[str, Any],
) -> NormalizedRunCandidate | None:
    repo_obj = payload.get("repository")
    ext_repo_id = (
        str(repo_obj.get("id"))
        if isinstance(repo_obj, Mapping) and repo_obj.get("id") is not None
        else None
    )
    repo_full_name = (
        str(repo_obj.get("full_name"))
        if isinstance(repo_obj, Mapping) and isinstance(repo_obj.get("full_name"), str)
        else None
    )
    sender_obj = payload.get("sender")
    actor_login = (
        str(sender_obj.get("login"))
        if isinstance(sender_obj, Mapping) and isinstance(sender_obj.get("login"), str)
        else None
    )

    if event_name == "workflow_run":
        wf_run = payload.get("workflow_run")
        if not isinstance(wf_run, Mapping) or wf_run.get("id") is None:
            return None
        run_id = str(wf_run["id"])
        attempt_str = str(wf_run.get("run_attempt") or "1")
        action = str(payload.get("action") or "")
        raw_status = str(wf_run.get("status") or ("completed" if action == "completed" else ""))
        conclusion = str(wf_run["conclusion"]) if wf_run.get("conclusion") is not None else None
        head_commit = wf_run.get("head_commit")
        commit_msg = (
            str(head_commit.get("message"))
            if isinstance(head_commit, Mapping) and isinstance(head_commit.get("message"), str)
            else None
        )
        head_repo = wf_run.get("head_repository")
        head_repo_id = (
            str(head_repo.get("id"))
            if isinstance(head_repo, Mapping) and head_repo.get("id") is not None
            else ext_repo_id
        )
        head_fork = bool(head_repo.get("fork")) if isinstance(head_repo, Mapping) else False
        trust = (
            WorkflowHazardScanner.classify_pull_request_trust(
                base_repo_id=ext_repo_id,
                head_repo_id=head_repo_id,
                head_repo_fork=head_fork,
            )
            if ext_repo_id
            else None
        )
        evt_ts = _parse_iso_utc(wf_run.get("updated_at")) or _parse_iso_utc(
            wf_run.get("created_at")
        )
        explicit_rerun = False
        if attempt_str.isdigit() and int(attempt_str) > 1:
            explicit_rerun = True

        return NormalizedRunCandidate(
            provider="github",
            external_repo_id=ext_repo_id,
            repo_full_name=repo_full_name,
            provider_run_id=run_id,
            attempt_key=f"{run_id}:{attempt_str}",
            head_sha=str(wf_run.get("head_sha") or ""),
            ref=str(wf_run.get("head_branch") or "HEAD"),
            event_type=str(wf_run.get("event") or "workflow_run"),
            status=(
                raw_status if raw_status in {"queued", "in_progress", "completed"} else "unknown"
            ),
            conclusion=conclusion,
            jobs_complete=(action == "completed" and raw_status == "completed"),
            raw_vendor_status=raw_status or action,
            untrusted_fork=bool(trust.untrusted_fork) if trust is not None else head_fork,
            commit_message=commit_msg,
            actor_login=actor_login,
            event_timestamp=evt_ts,
            explicit_rerun=explicit_rerun,
            needs_live_run_lookup=False,
        )

    if event_name == "workflow_job":
        wf_job = payload.get("workflow_job")
        if not isinstance(wf_job, Mapping) or wf_job.get("run_id") is None:
            return None
        action = str(payload.get("action") or "")
        conclusion = str(wf_job["conclusion"]) if wf_job.get("conclusion") is not None else None
        run_id = str(wf_job["run_id"])
        attempt_str = str(wf_job.get("run_attempt") or "1")
        if action != "completed" or conclusion not in FAILURE_CONCLUSIONS:
            return NormalizedRunCandidate(
                provider="github",
                external_repo_id=ext_repo_id,
                repo_full_name=repo_full_name,
                provider_run_id=run_id,
                attempt_key=f"{run_id}:{attempt_str}",
                head_sha=str(wf_job.get("head_sha") or ""),
                ref=str(wf_job.get("head_branch") or "HEAD"),
                event_type="workflow_job",
                status="in_progress",
                conclusion=conclusion,
                jobs_complete=False,
                raw_vendor_status=str(wf_job.get("status") or action),
                actor_login=actor_login,
                event_timestamp=_parse_iso_utc(wf_job.get("completed_at")),
                needs_live_run_lookup=False,
            )
        return NormalizedRunCandidate(
            provider="github",
            external_repo_id=ext_repo_id,
            repo_full_name=repo_full_name,
            provider_run_id=run_id,
            attempt_key=f"{run_id}:{attempt_str}",
            head_sha=str(wf_job.get("head_sha") or ""),
            ref=str(wf_job.get("head_branch") or "HEAD"),
            event_type="workflow_job",
            status="completed",
            conclusion=conclusion,
            jobs_complete=False,
            raw_vendor_status=str(wf_job.get("status") or action),
            actor_login=actor_login,
            event_timestamp=_parse_iso_utc(wf_job.get("completed_at")),
            explicit_rerun=(attempt_str.isdigit() and int(attempt_str) > 1),
            needs_live_run_lookup=True,
        )

    return None


def _extract_gitlab_candidate(
    event_name: str,
    payload: Mapping[str, Any],
) -> NormalizedRunCandidate | None:
    proj_obj = payload.get("project")
    ext_repo_id = (
        str(proj_obj.get("id"))
        if isinstance(proj_obj, Mapping) and proj_obj.get("id") is not None
        else (str(payload["project_id"]) if payload.get("project_id") is not None else None)
    )
    repo_full_name = (
        str(proj_obj.get("path_with_namespace"))
        if isinstance(proj_obj, Mapping) and isinstance(proj_obj.get("path_with_namespace"), str)
        else None
    )
    user_obj = payload.get("user")
    actor_login = (
        str(user_obj.get("username"))
        if isinstance(user_obj, Mapping) and isinstance(user_obj.get("username"), str)
        else None
    )
    commit_obj = payload.get("commit")
    commit_msg = (
        str(commit_obj.get("message"))
        if isinstance(commit_obj, Mapping) and isinstance(commit_obj.get("message"), str)
        else None
    )

    obj_kind = str(payload.get("object_kind") or "").lower()
    lowered_evt = event_name.strip().lower()

    if obj_kind == "pipeline" or lowered_evt == "pipeline hook":
        attrs = payload.get("object_attributes")
        if not isinstance(attrs, Mapping) or attrs.get("id") is None:
            return None
        pipe_id = str(attrs["id"])
        raw_status = str(attrs.get("status") or "unknown")
        norm_status, conclusion, jobs_complete = _map_gitlab_pipeline_status(raw_status)

        builds = payload.get("builds")
        retried_count = 0
        if isinstance(builds, list):
            retried_count = sum(
                1 for b in builds if isinstance(b, Mapping) and b.get("retried") is True
            )
        attempt_key = (
            f"pipeline:{pipe_id}:retry-{retried_count}"
            if retried_count > 0
            else f"pipeline:{pipe_id}"
        )

        mr_obj = payload.get("merge_request")
        untrusted_fork = False
        if isinstance(mr_obj, Mapping):
            src_proj = mr_obj.get("source_project_id")
            tgt_proj = mr_obj.get("target_project_id")
            if src_proj is not None and tgt_proj is not None and str(src_proj) != str(tgt_proj):
                untrusted_fork = True

        evt_ts = _parse_iso_utc(attrs.get("finished_at")) or _parse_iso_utc(attrs.get("created_at"))
        return NormalizedRunCandidate(
            provider="gitlab",
            external_repo_id=ext_repo_id,
            repo_full_name=repo_full_name,
            provider_run_id=pipe_id,
            attempt_key=attempt_key,
            head_sha=str(attrs.get("sha") or ""),
            ref=str(attrs.get("ref") or "HEAD"),
            event_type=str(attrs.get("source") or "pipeline"),
            status=norm_status,
            conclusion=conclusion,
            jobs_complete=jobs_complete,
            raw_vendor_status=raw_status,
            untrusted_fork=untrusted_fork,
            commit_message=commit_msg,
            actor_login=actor_login,
            event_timestamp=evt_ts,
            explicit_rerun=retried_count > 0,
            needs_live_run_lookup=False,
        )

    if obj_kind == "build" or lowered_evt in {"job hook", "build hook"}:
        pipe_id_raw = payload.get("pipeline_id")
        if pipe_id_raw is None:
            return None
        pipe_id = str(pipe_id_raw)
        raw_build_status = str(payload.get("build_status") or "unknown")
        norm_status, conclusion, _ = _map_gitlab_pipeline_status(raw_build_status)
        if conclusion not in FAILURE_CONCLUSIONS:
            return NormalizedRunCandidate(
                provider="gitlab",
                external_repo_id=ext_repo_id,
                repo_full_name=repo_full_name,
                provider_run_id=pipe_id,
                attempt_key=f"pipeline:{pipe_id}",
                head_sha=str(payload.get("sha") or ""),
                ref=str(payload.get("ref") or "HEAD"),
                event_type="job_hook",
                status=norm_status,
                conclusion=conclusion,
                jobs_complete=False,
                raw_vendor_status=raw_build_status,
                commit_message=commit_msg,
                actor_login=actor_login,
                needs_live_run_lookup=False,
            )
        return NormalizedRunCandidate(
            provider="gitlab",
            external_repo_id=ext_repo_id,
            repo_full_name=repo_full_name,
            provider_run_id=pipe_id,
            attempt_key=f"pipeline:{pipe_id}",
            head_sha=str(payload.get("sha") or ""),
            ref=str(payload.get("ref") or "HEAD"),
            event_type="job_hook",
            status="completed",
            conclusion=conclusion,
            jobs_complete=False,
            raw_vendor_status=raw_build_status,
            commit_message=commit_msg,
            actor_login=actor_login,
            explicit_rerun=int(payload.get("retries_count") or 0) > 0,
            needs_live_run_lookup=True,
        )

    return None


class WebhookIngestService:
    """Authenticated raw-body `A-22` webhook ingress & durable `webhook_inbox` processor."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        github_adapter: GitHubAppAdapter,
        gitlab_adapter: GitLabAdapter,
        integration_service: GitHubIntegrationService | None = None,
        redactor: Redactor | None = None,
        clock: Callable[[], datetime] | None = None,
        stale_replay_threshold: timedelta = DEFAULT_STALE_REPLAY_THRESHOLD,
    ) -> None:
        self._session_factory = session_factory
        self._github = github_adapter
        self._gitlab = gitlab_adapter
        self._integration_service = integration_service
        self._redactor = redactor or DEFAULT_REDACTOR
        self._clock = clock or (lambda: datetime.now(tz=UTC))
        self._stale_replay_threshold = stale_replay_threshold

    def now(self) -> datetime:
        return self._clock().astimezone(UTC)

    def _adapter_for(self, provider: ProviderKind) -> GitHubAppAdapter | GitLabAdapter:
        if provider == "github":
            return self._github
        return self._gitlab

    @staticmethod
    def _dummy_constant_time_check(raw_body: bytes, headers: Mapping[str, str]) -> None:
        sig = ""
        for k, v in headers.items():
            if k.strip().lower() in {"x-hub-signature-256", "webhook-signature", "x-gitlab-token"}:
                sig = v
                break
        verify_hmac_sha256_hex(
            b"__red2pr_dummy_unknown_connection_secret__",
            raw_body,
            sig if sig.startswith("sha256=") else f"sha256={'0' * 64}",
        )

    @staticmethod
    def _extract_event_and_delivery_id(
        *,
        provider: ProviderKind,
        auth_mode: str,
        headers: Mapping[str, str],
        payload_digest: str,
    ) -> tuple[str, str]:
        lowered = {k.strip().lower(): v.strip() for k, v in headers.items()}
        if provider == "github":
            event_type = lowered.get("x-github-event", "")
            delivery_id = lowered.get("x-github-delivery", "")
            if not event_type or not delivery_id:
                raise BadRequestError(
                    code="malformed_webhook_headers",
                    detail=(
                        "GitHub webhook requires non-empty X-GitHub-Event and "
                        "X-GitHub-Delivery headers."
                    ),
                )
            return (event_type[:120], delivery_id[:256])

        event_type = lowered.get("x-gitlab-event", "")
        if not event_type:
            raise BadRequestError(
                code="malformed_webhook_headers",
                detail="GitLab webhook requires a non-empty X-Gitlab-Event header.",
            )
        if auth_mode in {"gitlab_signed_v19", "signed_webhook"}:
            webhook_id = lowered.get("webhook-id", "")
            if not webhook_id:
                raise BadRequestError(
                    code="malformed_webhook_headers",
                    detail="Signed GitLab v19 webhook requires a non-empty webhook-id header.",
                )
            return (event_type[:120], webhook_id[:256])

        # Legacy GitLab token mode (`docs/12`: prefer Idempotency-Key 17.4+, else UUID+digest)
        idem_key = lowered.get("idempotency-key") or lowered.get("webhook-id")
        if idem_key:
            return (event_type[:120], idem_key[:256])
        event_uuid = lowered.get("x-gitlab-event-uuid")
        if event_uuid:
            return (event_type[:120], f"gl-uuid:{event_uuid[:120]}:{payload_digest[:24]}"[:256])
        return (event_type[:120], f"gl-sha256:{payload_digest[:48]}")

    async def _resolve_live_run_candidate(
        self,
        db: AsyncSession,
        *,
        provider: ProviderKind,
        adapter: GitHubAppAdapter | GitLabAdapter,
        conn_row: ProviderConnectionModel,
        conn_ctx: ProviderConnectionContext,
        repo_row: RepositoryModel,
        candidate: NormalizedRunCandidate,
        is_stale_timestamp: bool,
        correlation_id: str,
        client_ip: str | None,
        ref_now: datetime,
    ) -> tuple[
        NormalizedRunCandidate | None,
        WebhookInboxStatus,
        WebhookIngressDisposition,
        str,
    ]:
        try:
            live_run = await adapter.get_run(
                db,
                conn_ctx,
                repo_full_name=repo_row.name,
                external_run_id=candidate.provider_run_id,
                now=ref_now,
            )
            if is_stale_timestamp and (
                live_run.attempt_key != candidate.attempt_key
                or not live_run.jobs_complete
                or live_run.conclusion not in FAILURE_CONCLUSIONS
            ):
                return (
                    None,
                    "ignored",
                    "ignored_stale_replay",
                    "stale_webhook_superseded_by_live_state",
                )
            if candidate.needs_live_run_lookup and not live_run.jobs_complete:
                return (
                    None,
                    "reconcile_pending",
                    "reconcile_scheduled",
                    "parent_run_still_in_progress",
                )
            return (
                NormalizedRunCandidate(
                    provider=candidate.provider,
                    external_repo_id=repo_row.external_repo_id,
                    repo_full_name=repo_row.name,
                    provider_run_id=live_run.external_run_id,
                    attempt_key=live_run.attempt_key,
                    head_sha=live_run.head_sha or candidate.head_sha,
                    ref=live_run.ref or candidate.ref,
                    event_type=live_run.event_type or candidate.event_type,
                    status=live_run.status,
                    conclusion=live_run.conclusion,
                    jobs_complete=live_run.jobs_complete,
                    raw_vendor_status=live_run.raw_vendor_status,
                    untrusted_fork=candidate.untrusted_fork or live_run.head_repo_fork,
                    commit_message=candidate.commit_message,
                    actor_login=candidate.actor_login,
                    event_timestamp=candidate.event_timestamp,
                    explicit_rerun=candidate.explicit_rerun,
                    needs_live_run_lookup=False,
                ),
                "ignored",
                "ignored_non_failure",
                "unsupported_or_non_failure_event",
            )
        except ProviderError as exc:
            if exc.code == "REVOKED" and self._integration_service is not None:
                await self._integration_service._suspend_connection_work_and_mark_revoked(
                    db,
                    conn_row=conn_row,
                    actor_type="system",
                    actor_id=f"webhook:{provider}",
                    reason_code="provider_credentials_revoked",
                    detail=exc.detail,
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    revoke_stored_secrets=False,
                    now=ref_now,
                )
                return (
                    None,
                    "reconcile_pending",
                    "reconcile_scheduled",
                    "provider_credentials_revoked",
                )
            if exc.code == "NOT_FOUND" and is_stale_timestamp:
                return (
                    None,
                    "ignored",
                    "ignored_stale_replay",
                    "stale_webhook_run_not_found",
                )
            return (
                None,
                "reconcile_pending",
                "reconcile_scheduled",
                f"live_lookup_deferred_{exc.code.lower()}",
            )

    async def ingest_webhook(
        self,
        *,
        provider: ProviderKind,
        connection_id: str,
        headers: Mapping[str, str],
        raw_body: bytes,
        client_ip: str | None,
        correlation_id: str,
        now: datetime | None = None,
    ) -> tuple[int, WebhookIngressReceipt]:
        """Verify raw bytes, persist `webhook_inbox` with `fsync`, normalize & ack (`A-22`)."""
        started_monotonic = time.monotonic()
        ref_now = now.astimezone(UTC) if now is not None else self.now()

        # 1. Forbid browser Cookie authentication on webhook ingress (`A-22` / `SEC-001`)
        for h_key, h_val in headers.items():
            if h_key.strip().lower() == "cookie" and h_val.strip():
                raise BadRequestError(
                    code="cookie_auth_forbidden_on_webhook",
                    detail="Webhook ingress endpoints reject browser Cookie authentication.",
                )

        if not raw_body:
            raise BadRequestError(
                code="empty_webhook_body",
                detail="Webhook request body must not be empty.",
            )
        if len(raw_body) > MAX_JSON_BODY_BYTES:
            raise PayloadTooLargeError(
                detail=f"Webhook payload exceeds maximum {MAX_JSON_BODY_BYTES} bytes."
            )

        try:
            clean_conn_id = _UUID_ADAPTER.validate_python(connection_id.strip())
        except ValidationError as exc:
            self._dummy_constant_time_check(raw_body, headers)
            raise UnauthorizedError(
                code="invalid_webhook_auth",
                detail="Webhook authentication failed.",
            ) from exc

        try:
            # 2. Narrow instance lookup to resolve connection's tenant workspace_id (`SEC-032`)
            async with instance_rls_session(self._session_factory, mode="instance_admin") as lookup:
                conn_meta = (
                    await lookup.execute(
                        select(
                            ProviderConnectionModel.workspace_id,
                            ProviderConnectionModel.provider,
                        ).where(ProviderConnectionModel.id == clean_conn_id)
                    )
                ).one_or_none()

            if conn_meta is None or conn_meta[1] != provider:
                self._dummy_constant_time_check(raw_body, headers)
                raise UnauthorizedError(
                    code="invalid_webhook_auth",
                    detail="Webhook authentication failed.",
                )

            ws_id = str(conn_meta[0])

            # 3. Execute all verification, inbox writes, triggers & audit under tenant RLS.
            # Exiting `workspace_rls_session` cleanly executes the authoritative PostgreSQL
            # `fsync` transaction commit BEFORE any HTTP response or rejection is returned.
            deferred_error: Red2PrError | None = None
            result_pair: tuple[int, WebhookIngressReceipt] | None = None

            async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
                conn_row = await db.scalar(
                    select(ProviderConnectionModel).where(
                        ProviderConnectionModel.workspace_id == ws_id,
                        ProviderConnectionModel.id == clean_conn_id,
                    )
                )
                if conn_row is None:
                    self._dummy_constant_time_check(raw_body, headers)
                    raise UnauthorizedError(
                        code="invalid_webhook_auth",
                        detail="Webhook authentication failed.",
                    )

                if conn_row.status == "revoked":
                    await append_audit_entry(
                        db,
                        workspace_id=ws_id,
                        actor_type="anonymous",
                        actor_id=f"webhook:{provider}",
                        action="integration.webhook.rejected",
                        target=f"provider_connection:{conn_row.id}",
                        decision="deny",
                        reason_code="connection_revoked",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        metadata={"provider": provider},
                        occurred_at=ref_now,
                    )
                    deferred_error = UnauthorizedError(
                        code="webhook_connection_revoked",
                        detail="Provider connection has been revoked.",
                    )
                else:
                    conn_ctx: ProviderConnectionContext = _to_connection_context(conn_row)
                    adapter = self._adapter_for(provider)

                    # 4. Verify raw bytes BEFORE any JSON parsing (`SEC-001`, `SEC-003`, `SEC-027`)
                    sig_valid = await adapter.verify_webhook(
                        db,
                        conn_ctx,
                        headers=headers,
                        raw_body=raw_body,
                        now=ref_now,
                    )
                    if not sig_valid:
                        await append_audit_entry(
                            db,
                            workspace_id=ws_id,
                            actor_type="anonymous",
                            actor_id=f"webhook:{provider}",
                            action="integration.webhook.rejected",
                            target=f"provider_connection:{conn_row.id}",
                            decision="deny",
                            reason_code="invalid_webhook_signature",
                            correlation_id=correlation_id,
                            client_ip=client_ip,
                            metadata={
                                "provider": provider,
                                "pinned_auth_mode": conn_row.auth_mode,
                            },
                            occurred_at=ref_now,
                        )
                        deferred_error = UnauthorizedError(
                            code="invalid_webhook_auth",
                            detail="Webhook cryptographic signature or token verification failed.",
                        )

                if deferred_error is None:
                    payload_digest = hashlib.sha256(raw_body).hexdigest()
                    event_type, delivery_id = self._extract_event_and_delivery_id(
                        provider=provider,
                        auth_mode=conn_row.auth_mode,
                        headers=headers,
                        payload_digest=payload_digest,
                    )

                    try:
                        parsed_json = json.loads(raw_body.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise BadRequestError(
                            code="malformed_webhook_json",
                            detail="Verified webhook body is not valid UTF-8 JSON.",
                        ) from exc

                    if not isinstance(parsed_json, Mapping):
                        raise BadRequestError(
                            code="malformed_webhook_json",
                            detail="Webhook JSON root must be an object.",
                        )

                    # 5. Enforce GitHub App installation binding (`SEC-001`)
                    if provider == "github" and conn_row.external_installation_id:
                        inst_obj = parsed_json.get("installation")
                        if isinstance(inst_obj, Mapping) and inst_obj.get("id") is not None:
                            incoming_inst_id = str(inst_obj["id"]).strip()
                            if incoming_inst_id != conn_row.external_installation_id:
                                await append_audit_entry(
                                    db,
                                    workspace_id=ws_id,
                                    actor_type="anonymous",
                                    actor_id="webhook:github",
                                    action="integration.webhook.rejected",
                                    target=f"provider_connection:{conn_row.id}",
                                    decision="deny",
                                    reason_code="webhook_installation_mismatch",
                                    correlation_id=correlation_id,
                                    client_ip=client_ip,
                                    metadata={
                                        "expected_installation_id": (
                                            conn_row.external_installation_id
                                        ),
                                        "incoming_installation_id": incoming_inst_id[:64],
                                    },
                                    occurred_at=ref_now,
                                )
                                deferred_error = ForbiddenError(
                                    code="webhook_installation_mismatch",
                                    detail=(
                                        "GitHub webhook installation ID does not match the "
                                        "installation bound to this connection."
                                    ),
                                )

                if deferred_error is None:
                    sanitized_headers = sanitize_webhook_headers(headers, redactor=self._redactor)

                    # 6. Atomic delivery deduplication (`uq_webhook_inbox_conn_delivery`)
                    candidate_inbox_id = new_uuid7(now=ref_now)
                    inserted_inbox_id = await db.scalar(
                        pg_insert(WebhookInboxModel)
                        .values(
                            id=candidate_inbox_id,
                            workspace_id=ws_id,
                            connection_id=conn_row.id,
                            repository_id=None,
                            provider=provider,
                            source="webhook",
                            event_type=event_type,
                            provider_delivery_id=delivery_id,
                            payload_digest=payload_digest,
                            signature_valid=True,
                            status="received",
                            sanitized_headers_json=sanitized_headers,
                            normalized_summary_json={"event_type": event_type},
                            correlation_id=correlation_id,
                            received_at=ref_now,
                            processed_at=None,
                            retention_until=ref_now + WEBHOOK_INBOX_RETENTION,
                            version=1,
                            created_at=ref_now,
                            updated_at=ref_now,
                        )
                        .on_conflict_do_nothing(constraint="uq_webhook_inbox_conn_delivery")
                        .returning(WebhookInboxModel.id)
                    )

                    if inserted_inbox_id is None:
                        existing_inbox = await db.scalar(
                            select(WebhookInboxModel).where(
                                WebhookInboxModel.workspace_id == ws_id,
                                WebhookInboxModel.connection_id == conn_row.id,
                                WebhookInboxModel.provider_delivery_id == delivery_id,
                            )
                        )
                        if existing_inbox is None:
                            raise DependencyUnavailableError(
                                code="webhook_persistence_unavailable",
                                detail="Concurrent webhook inbox lookup failed; retry delivery.",
                            )
                        if not hmac.compare_digest(existing_inbox.payload_digest, payload_digest):
                            await append_audit_entry(
                                db,
                                workspace_id=ws_id,
                                actor_type="anonymous",
                                actor_id=f"webhook:{provider}",
                                action="integration.webhook.rejected",
                                target=f"webhook_inbox:{existing_inbox.id}",
                                decision="deny",
                                reason_code="webhook_delivery_digest_mismatch",
                                correlation_id=correlation_id,
                                client_ip=client_ip,
                                metadata={"delivery_id": delivery_id[:120]},
                                occurred_at=ref_now,
                            )
                            deferred_error = ConflictError(
                                code="webhook_delivery_digest_mismatch",
                                detail=(
                                    "Duplicate provider delivery ID arrived with a different "
                                    "payload digest."
                                ),
                            )
                        else:
                            existing_job_id: str | None = None
                            if existing_inbox.trigger_id is not None:
                                existing_job_id = await db.scalar(
                                    select(CiRunTriggerModel.job_id).where(
                                        CiRunTriggerModel.workspace_id == ws_id,
                                        CiRunTriggerModel.id == existing_inbox.trigger_id,
                                    )
                                )
                            result_pair = (
                                200,
                                WebhookIngressReceipt(
                                    inbox_id=existing_inbox.id,
                                    connection_id=conn_row.id,
                                    provider=provider,
                                    delivery_id=delivery_id[:128],
                                    status=cast(WebhookInboxStatus, existing_inbox.status),
                                    disposition="duplicate_delivery",
                                    duplicate=True,
                                    trigger_id=existing_inbox.trigger_id,
                                    job_id=existing_job_id,
                                    correlation_id=correlation_id,
                                    received_at=existing_inbox.received_at,
                                ),
                            )
                    else:
                        inbox_row = await db.scalar(
                            select(WebhookInboxModel).where(
                                WebhookInboxModel.workspace_id == ws_id,
                                WebhookInboxModel.id == inserted_inbox_id,
                            )
                        )
                        assert inbox_row is not None

                        # 7. Handle GitHub installation revocation/suspension webhook (`SEC-011`)
                        if (
                            provider == "github"
                            and event_type == "installation"
                            and str(parsed_json.get("action") or "") in {"deleted", "suspend"}
                            and self._integration_service is not None
                        ):
                            action_str = str(parsed_json.get("action"))
                            await (
                                self._integration_service._suspend_connection_work_and_mark_revoked(
                                    db,
                                    conn_row=conn_row,
                                    actor_type="system",
                                    actor_id="webhook:github",
                                    reason_code=f"github_installation_{action_str}",
                                    detail=(
                                        f"GitHub App installation reported '{action_str}' "
                                        "via verified webhook."
                                    ),
                                    correlation_id=correlation_id,
                                    client_ip=client_ip,
                                    revoke_stored_secrets=(action_str == "deleted"),
                                    now=ref_now,
                                )
                            )
                            inbox_row.status = "normalized"
                            inbox_row.disposition_reason = f"github_installation_{action_str}"
                            inbox_row.processed_at = ref_now
                            inbox_row.updated_at = ref_now
                            result_pair = (
                                202,
                                WebhookIngressReceipt(
                                    inbox_id=inbox_row.id,
                                    connection_id=conn_row.id,
                                    provider=provider,
                                    delivery_id=delivery_id[:128],
                                    status="normalized",
                                    disposition="installation_revoked",
                                    duplicate=False,
                                    correlation_id=correlation_id,
                                    received_at=ref_now,
                                ),
                            )
                        else:
                            candidate = (
                                _extract_github_candidate(event_type, parsed_json)
                                if provider == "github"
                                else _extract_gitlab_candidate(event_type, parsed_json)
                            )

                            final_status: WebhookInboxStatus = "ignored"
                            final_disposition: WebhookIngressDisposition = "ignored_non_failure"
                            reason_code = "unsupported_or_non_failure_event"
                            trigger_id: str | None = None
                            job_id: str | None = None

                            if candidate is not None:
                                inbox_row.provider_run_id = candidate.provider_run_id[:128]
                                inbox_row.attempt_key = candidate.attempt_key[:128]
                                inbox_row.head_sha = (
                                    candidate.head_sha[:64] if candidate.head_sha else None
                                )
                                inbox_row.normalized_summary_json = {
                                    "event_type": event_type,
                                    "external_repo_id": candidate.external_repo_id,
                                    "repo_full_name": (
                                        self._redactor.redact_text(candidate.repo_full_name)[:120]
                                        if candidate.repo_full_name
                                        else None
                                    ),
                                    "provider_run_id": candidate.provider_run_id[:128],
                                    "attempt_key": candidate.attempt_key[:128],
                                    "head_sha": candidate.head_sha[:64],
                                    "ref": self._redactor.redact_text(candidate.ref)[:120],
                                    "conclusion": candidate.conclusion,
                                    "untrusted_fork": candidate.untrusted_fork,
                                }

                                repo_row = await resolve_tracked_repository(
                                    db,
                                    workspace_id=ws_id,
                                    connection_id=conn_row.id,
                                    external_repo_id=candidate.external_repo_id,
                                    repo_full_name=candidate.repo_full_name,
                                )
                                if repo_row is None:
                                    final_status = "ignored"
                                    final_disposition = "ignored_untracked_repo"
                                    reason_code = "repository_not_tracked_or_inactive"
                                else:
                                    inbox_row.repository_id = repo_row.id
                                    is_stale_timestamp = (
                                        candidate.event_timestamp is not None
                                        and (ref_now - candidate.event_timestamp)
                                        > self._stale_replay_threshold
                                    )

                                    resolved_candidate: NormalizedRunCandidate | None = candidate
                                    if candidate.needs_live_run_lookup or (
                                        is_stale_timestamp
                                        and candidate.jobs_complete
                                        and candidate.conclusion in FAILURE_CONCLUSIONS
                                    ):
                                        (
                                            resolved_candidate,
                                            final_status,
                                            final_disposition,
                                            reason_code,
                                        ) = await self._resolve_live_run_candidate(
                                            db,
                                            provider=provider,
                                            adapter=adapter,
                                            conn_row=conn_row,
                                            conn_ctx=conn_ctx,
                                            repo_row=repo_row,
                                            candidate=candidate,
                                            is_stale_timestamp=is_stale_timestamp,
                                            correlation_id=correlation_id,
                                            client_ip=client_ip,
                                            ref_now=ref_now,
                                        )

                                    if resolved_candidate is not None:
                                        resolution = await record_normalized_run_failure_trigger(
                                            db,
                                            workspace_id=ws_id,
                                            conn_row=conn_row,
                                            repo_row=repo_row,
                                            candidate=resolved_candidate,
                                            source="webhook",
                                            inbox_id=inbox_row.id,
                                            correlation_id=correlation_id,
                                            redactor=self._redactor,
                                            now=ref_now,
                                        )
                                        final_status = resolution.inbox_status
                                        final_disposition = resolution.disposition
                                        reason_code = resolution.reason_code
                                        trigger_id = resolution.trigger_id
                                        job_id = resolution.job_id

                            inbox_row.status = final_status
                            inbox_row.disposition_reason = reason_code[:120]
                            inbox_row.trigger_id = trigger_id
                            inbox_row.processed_at = (
                                ref_now if final_status != "reconcile_pending" else None
                            )
                            inbox_row.updated_at = ref_now

                            await append_audit_entry(
                                db,
                                workspace_id=ws_id,
                                repository_id=inbox_row.repository_id,
                                actor_type="service",
                                actor_id=f"webhook:{provider}",
                                action="integration.webhook.ingested",
                                target=f"webhook_inbox:{inbox_row.id}",
                                decision="allow",
                                reason_code=reason_code[:120],
                                correlation_id=correlation_id,
                                client_ip=client_ip,
                                metadata={
                                    "provider": provider,
                                    "event_type": event_type,
                                    "delivery_id": delivery_id[:120],
                                    "status": final_status,
                                    "disposition": final_disposition,
                                },
                                occurred_at=ref_now,
                            )
                            await db.flush()
                            result_pair = (
                                202,
                                WebhookIngressReceipt(
                                    inbox_id=inserted_inbox_id,
                                    connection_id=clean_conn_id,
                                    provider=provider,
                                    delivery_id=delivery_id[:128],
                                    status=final_status,
                                    disposition=final_disposition,
                                    duplicate=False,
                                    trigger_id=trigger_id,
                                    job_id=job_id,
                                    correlation_id=correlation_id,
                                    received_at=ref_now,
                                ),
                            )

            # `workspace_rls_session` has now committed with PostgreSQL fsync!
            if deferred_error is not None:
                raise deferred_error
            assert result_pair is not None
            status_out, receipt_out = result_pair
            if status_out == 202:
                elapsed_ms = round((time.monotonic() - started_monotonic) * 1000.0, 2)
                _LOGGER.info(
                    "Durable webhook delivery committed",
                    extra={
                        "event": "integration.webhook.committed",
                        "duration_ms": elapsed_ms,
                        "attributes": {
                            "provider": provider,
                            "connection_id": clean_conn_id,
                            "inbox_id": receipt_out.inbox_id,
                            "status": receipt_out.status,
                            "disposition": receipt_out.disposition,
                        },
                    },
                )
            return result_pair
        except Red2PrError:
            raise
        except (SQLAlchemyError, OSError) as exc:
            _LOGGER.error(
                "Webhook inbox persistence failed; returning 503 for provider retry",
                extra={
                    "event": "integration.webhook.persistence_failed",
                    "error_code": "webhook_persistence_unavailable",
                    "attributes": {
                        "provider": provider,
                        "connection_id": clean_conn_id,
                        "error_type": type(exc).__name__,
                    },
                },
            )
            raise DependencyUnavailableError(
                code="webhook_persistence_unavailable",
                detail=(
                    "Durable webhook inbox persistence is temporarily unavailable; "
                    "provider should retry delivery."
                ),
            ) from exc


def _resolve_webhook_ingest_service(request: Request) -> WebhookIngestService:
    svc = getattr(request.app.state, "webhook_ingest_service", None)
    if not isinstance(svc, WebhookIngestService):
        raise DependencyUnavailableError(
            code="webhook_ingress_unconfigured",
            detail="Webhook ingress service is not configured on this control-plane instance.",
        )
    return svc


def _req_corr_id(request: Request) -> str:
    state_corr = getattr(request.state, "correlation_id", None)
    if isinstance(state_corr, str) and state_corr:
        return state_corr
    return current_correlation_id()


_WEBHOOK_PROBLEM_RESPONSES: dict[int | str, dict[str, object]] = {
    200: {"model": WebhookIngressReceipt},
    400: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    401: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    403: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    409: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    413: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    429: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    503: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
}


def build_webhooks_router() -> APIRouter:
    """Build `/api/v1/hooks` router for `A-22` GitHub & GitLab authenticated webhooks."""
    router = APIRouter(prefix="/api/v1/hooks", tags=["webhooks"])

    @router.post(
        "/github/{connection}",
        operation_id="ingestGitHubWebhook",
        status_code=202,
        response_model=WebhookIngressReceipt,
        summary="Verify raw GitHub HMAC-SHA256 webhook & commit durable inbox receipt (A-22)",
        responses=_WEBHOOK_PROBLEM_RESPONSES,
    )
    async def ingest_github_webhook(
        connection: Annotated[str, Path(min_length=1, max_length=64)],
        request: Request,
        svc: Annotated[WebhookIngestService, Depends(_resolve_webhook_ingest_service)],
    ) -> JSONResponse:
        raw_body = await request.body()
        status_code, receipt = await svc.ingest_webhook(
            provider="github",
            connection_id=connection,
            headers=dict(request.headers.items()),
            raw_body=raw_body,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
        )
        return JSONResponse(
            status_code=status_code,
            content=receipt.model_dump(mode="json"),
        )

    @router.post(
        "/gitlab/{connection}",
        operation_id="ingestGitLabWebhook",
        status_code=202,
        response_model=WebhookIngressReceipt,
        summary="Verify pinned GitLab webhook & commit durable inbox receipt (A-22)",
        responses=_WEBHOOK_PROBLEM_RESPONSES,
    )
    async def ingest_gitlab_webhook(
        connection: Annotated[str, Path(min_length=1, max_length=64)],
        request: Request,
        svc: Annotated[WebhookIngestService, Depends(_resolve_webhook_ingest_service)],
    ) -> JSONResponse:
        raw_body = await request.body()
        status_code, receipt = await svc.ingest_webhook(
            provider="gitlab",
            connection_id=connection,
            headers=dict(request.headers.items()),
            raw_body=raw_body,
            client_ip=extract_client_ip(request),
            correlation_id=_req_corr_id(request),
        )
        return JSONResponse(
            status_code=status_code,
            content=receipt.model_dump(mode="json"),
        )

    return router
