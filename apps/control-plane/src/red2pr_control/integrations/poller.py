"""Resumable local/NAT CI run polling service with 5m overlap, ETag & 429 backoff (`U11`).

Implements `SRC-04`, `NFR-04`, `S-10`, `S-19`, `W-03`, `SEC-002`, `SEC-011`, and `SEC-032`:
- Default `60s` polling interval + bounded deterministic jitter (`0..9s`) for NAT/firewalled
  self-hosted deployments where inbound webhooks are unreachable or delayed.
- `5m` (`300s`) overlap window (`high_water_mark_at - overlap_seconds`) with conditional
  `If-None-Match` (`ETag`) `304 Not Modified` handling.
- Durable cursor advancement (`high_water_mark_at`, `etag`, `last_seen_run_id`, `last_stable_page`)
  committed strictly inside the SAME PostgreSQL transaction as `webhook_inbox` + `ci_run_triggers`;
  any persistence failure rolls back the cursor so the next poll replays without data loss.
- Strict `429 Retry-After` rate-limit backoff honoring provider reset windows without storming.
- Honest offline `>TTL` and pagination history-gap detection (`last_status='gap_detected'`,
  `history_gap_detected=True`), never falsely claiming complete recovery (`T-SRC-04-N`).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.integrations import ProviderKind, ProviderSyncCursor
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.logging import bind_telemetry_context, get_structured_logger
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.db.base import (
    ProviderConnectionModel,
    ProviderSyncCursorModel,
    RepositoryModel,
    WebhookInboxModel,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.integrations.base import (
    ProviderConnectionContext,
    ProviderError,
    ProviderPollItem,
)
from red2pr_control.integrations.github_app import (
    GitHubAppAdapter,
    GitHubIntegrationService,
    WorkflowHazardScanner,
    _to_connection_context,
    _to_sync_cursor_dto,
)
from red2pr_control.integrations.gitlab_client import GitLabAdapter
from red2pr_control.integrations.webhooks import (
    FAILURE_CONCLUSIONS,
    WEBHOOK_INBOX_RETENTION,
    NormalizedRunCandidate,
    record_normalized_run_failure_trigger,
)

DEFAULT_POLL_INTERVAL_SECONDS = 60
DEFAULT_POLL_JITTER_MAX_SECONDS = 9
DEFAULT_OVERLAP_SECONDS = 300
DEFAULT_PROVIDER_HISTORY_TTL = timedelta(days=90)
DEFAULT_MAX_CATCHUP_PAGES = 5
DEFAULT_PER_PAGE = 50

_LOGGER = get_structured_logger("red2pr_control.integrations.poller")


@dataclass(frozen=True, slots=True)
class RepoPollOutcome:
    """Result of polling a single repository under workspace RLS."""

    repository_id: str
    cursor: ProviderSyncCursor
    polled: bool
    skipped_not_due: bool = False
    rate_limited: bool = False
    history_gap_detected: bool = False
    triggers_created: int = 0
    runs_inspected: int = 0


@dataclass(frozen=True, slots=True)
class ConnectionPollSummary:
    """Aggregated outcome of polling due repositories for one provider connection."""

    connection_id: str
    workspace_id: str
    outcomes: tuple[RepoPollOutcome, ...]
    polled_repository_count: int
    rate_limited_count: int
    history_gap_count: int
    triggers_created_count: int


def compute_poll_jitter_seconds(
    repository_id: str,
    *,
    now: datetime,
    max_jitter_seconds: int = DEFAULT_POLL_JITTER_MAX_SECONDS,
) -> int:
    """Compute bounded `0..max_jitter_seconds` jitter spreading multi-repo poll bursts."""
    if max_jitter_seconds <= 0:
        return 0
    minute_bucket = int(now.astimezone(UTC).timestamp()) // 60
    digest = hashlib.sha256(f"{repository_id}:{minute_bucket}".encode()).digest()
    return int.from_bytes(digest[:2], "big") % (max_jitter_seconds + 1)


class LocalPollingService:
    """Resumable `SRC-04` local/NAT CI run poller across GitHub & GitLab connections."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        github_adapter: GitHubAppAdapter,
        gitlab_adapter: GitLabAdapter,
        integration_service: GitHubIntegrationService | None = None,
        redactor: Redactor | None = None,
        clock: Callable[[], datetime] | None = None,
        poll_interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS,
        overlap_seconds: int = DEFAULT_OVERLAP_SECONDS,
        max_jitter_seconds: int = DEFAULT_POLL_JITTER_MAX_SECONDS,
        provider_history_ttl: timedelta = DEFAULT_PROVIDER_HISTORY_TTL,
        max_catchup_pages: int = DEFAULT_MAX_CATCHUP_PAGES,
        per_page: int = DEFAULT_PER_PAGE,
    ) -> None:
        self._session_factory = session_factory
        self._github = github_adapter
        self._gitlab = gitlab_adapter
        self._integration_service = integration_service
        self._redactor = redactor or DEFAULT_REDACTOR
        self._clock = clock or (lambda: datetime.now(tz=UTC))
        self._poll_interval_seconds = max(10, min(poll_interval_seconds, 3600))
        self._overlap_seconds = max(0, min(overlap_seconds, 3600))
        self._max_jitter_seconds = max(0, min(max_jitter_seconds, 30))
        self._provider_history_ttl = provider_history_ttl
        self._max_catchup_pages = max(1, min(max_catchup_pages, 20))
        self._per_page = max(1, min(per_page, 100))

    def now(self) -> datetime:
        return self._clock().astimezone(UTC)

    def _adapter_for(self, provider: ProviderKind) -> GitHubAppAdapter | GitLabAdapter:
        if provider == "github":
            return self._github
        return self._gitlab

    async def _ensure_cursor_row(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        conn_row: ProviderConnectionModel,
        repo_row: RepositoryModel,
        now: datetime,
    ) -> ProviderSyncCursorModel:
        await db.execute(
            pg_insert(ProviderSyncCursorModel)
            .values(
                id=new_uuid7(now=now),
                workspace_id=workspace_id,
                connection_id=conn_row.id,
                repository_id=repo_row.id,
                provider=conn_row.provider,
                etag=None,
                high_water_mark_at=None,
                last_seen_run_id=None,
                last_stable_page=1,
                overlap_seconds=self._overlap_seconds,
                poll_interval_seconds=self._poll_interval_seconds,
                last_polled_at=None,
                last_success_at=None,
                next_poll_after=None,
                rate_limit_remaining=None,
                rate_limit_reset_at=None,
                consecutive_failures=0,
                last_status="idle",
                history_gap_detected=False,
                version=1,
                created_at=now,
                updated_at=now,
            )
            .on_conflict_do_nothing(constraint="uq_provider_sync_cursors_ws_conn_repo")
        )
        cursor_row = await db.scalar(
            select(ProviderSyncCursorModel)
            .where(
                ProviderSyncCursorModel.workspace_id == workspace_id,
                ProviderSyncCursorModel.connection_id == conn_row.id,
                ProviderSyncCursorModel.repository_id == repo_row.id,
            )
            .with_for_update()
        )
        assert cursor_row is not None
        return cursor_row

    async def acknowledge_connection_history_gaps(
        self,
        *,
        workspace_id: str,
        connection_id: str,
        repository_ids: list[str] | None,
        actor_user_id: str,
        correlation_id: str,
        client_ip: str | None,
        now: datetime | None = None,
    ) -> int:
        """Explicitly acknowledge offline history-TTL gap warnings before resyncing."""
        ref_now = now.astimezone(UTC) if now is not None else self.now()
        cleared = 0
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            stmt = (
                select(ProviderSyncCursorModel)
                .where(
                    ProviderSyncCursorModel.workspace_id == workspace_id,
                    ProviderSyncCursorModel.connection_id == connection_id,
                    ProviderSyncCursorModel.history_gap_detected.is_(True),
                )
                .with_for_update()
            )
            if repository_ids:
                stmt = stmt.where(ProviderSyncCursorModel.repository_id.in_(repository_ids))
            rows = list((await db.scalars(stmt)).all())
            for row in rows:
                row.history_gap_detected = False
                row.history_gap_since = None
                row.history_gap_until = None
                row.history_gap_detail = None
                if row.last_status == "gap_detected":
                    row.last_status = "idle"
                row.version += 1
                row.updated_at = ref_now
                cleared += 1
            if cleared > 0:
                await append_audit_entry(
                    db,
                    workspace_id=workspace_id,
                    actor_type="user",
                    actor_id=actor_user_id,
                    action="integration.poll.history_gap_acknowledged",
                    target=f"provider_connection:{connection_id}",
                    decision="reconcile",
                    reason_code="operator_acknowledged_history_gap",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={"cleared_cursor_count": cleared},
                    occurred_at=ref_now,
                )
            await db.flush()
        return cleared

    async def poll_repository(
        self,
        *,
        workspace_id: str,
        connection_id: str,
        repository_id: str,
        correlation_id: str,
        force_poll: bool = False,
        now: datetime | None = None,
    ) -> RepoPollOutcome | None:
        """Poll a single repository and commit cursor advancement atomically with inbox/triggers."""
        ref_now = now.astimezone(UTC) if now is not None else self.now()
        outcome: RepoPollOutcome | None = None

        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            conn_row = await db.scalar(
                select(ProviderConnectionModel).where(
                    ProviderConnectionModel.workspace_id == workspace_id,
                    ProviderConnectionModel.id == connection_id,
                )
            )
            repo_row = await db.scalar(
                select(RepositoryModel).where(
                    RepositoryModel.workspace_id == workspace_id,
                    RepositoryModel.provider_connection_id == connection_id,
                    RepositoryModel.id == repository_id,
                    RepositoryModel.active.is_(True),
                )
            )
            if conn_row is None or repo_row is None:
                return None

            cursor_row = await self._ensure_cursor_row(
                db,
                workspace_id=workspace_id,
                conn_row=conn_row,
                repo_row=repo_row,
                now=ref_now,
            )

            if conn_row.status == "revoked":
                cursor_row.last_status = "revoked"
                cursor_row.next_poll_after = None
                cursor_row.updated_at = ref_now
                await db.flush()
                outcome = RepoPollOutcome(
                    repository_id=repo_row.id,
                    cursor=_to_sync_cursor_dto(cursor_row),
                    polled=False,
                    skipped_not_due=True,
                    history_gap_detected=cursor_row.history_gap_detected,
                )
            elif (
                cursor_row.last_status == "rate_limited"
                and cursor_row.next_poll_after is not None
                and ref_now < cursor_row.next_poll_after
            ):
                # Respect active 429 rate-limit window ALWAYS (even when force_poll=True)
                await db.flush()
                outcome = RepoPollOutcome(
                    repository_id=repo_row.id,
                    cursor=_to_sync_cursor_dto(cursor_row),
                    polled=False,
                    skipped_not_due=True,
                    rate_limited=True,
                    history_gap_detected=cursor_row.history_gap_detected,
                )
            elif (
                not force_poll
                and cursor_row.next_poll_after is not None
                and ref_now < cursor_row.next_poll_after
            ):
                # Respect normal poll schedule unless force_poll=True
                await db.flush()
                outcome = RepoPollOutcome(
                    repository_id=repo_row.id,
                    cursor=_to_sync_cursor_dto(cursor_row),
                    polled=False,
                    skipped_not_due=True,
                    history_gap_detected=cursor_row.history_gap_detected,
                )

            if outcome is not None:
                pass
            else:
                outcome = await self._execute_repo_poll_in_tx(
                    db,
                    workspace_id=workspace_id,
                    conn_row=conn_row,
                    repo_row=repo_row,
                    cursor_row=cursor_row,
                    correlation_id=correlation_id,
                    ref_now=ref_now,
                )

        return outcome

    async def _execute_repo_poll_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        conn_row: ProviderConnectionModel,
        repo_row: RepositoryModel,
        cursor_row: ProviderSyncCursorModel,
        correlation_id: str,
        ref_now: datetime,
    ) -> RepoPollOutcome:
        if True:
            provider = cast(ProviderKind, conn_row.provider)
            adapter = self._adapter_for(provider)
            conn_ctx: ProviderConnectionContext = _to_connection_context(conn_row)

            prior_checkpoint = cursor_row.last_success_at or cursor_row.high_water_mark_at
            offline_exceeded_ttl = (
                prior_checkpoint is not None
                and (ref_now - prior_checkpoint) > self._provider_history_ttl
            )

            effective_since: datetime | None = None
            since_iso: str | None = None
            if cursor_row.high_water_mark_at is not None and not offline_exceeded_ttl:
                hwm_floor = ref_now - self._provider_history_ttl
                bounded_hwm = max(cursor_row.high_water_mark_at, hwm_floor)
                effective_since = bounded_hwm - timedelta(seconds=cursor_row.overlap_seconds)
                since_iso = effective_since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

            collected_items: list[ProviderPollItem] = []
            not_modified = False
            retention_expired = False
            new_etag: str | None = cursor_row.etag
            rl_remaining: int | None = cursor_row.rate_limit_remaining
            rl_reset_at: datetime | None = cursor_row.rate_limit_reset_at
            oldest_observed: datetime | None = None
            newest_observed: datetime | None = None
            unbridged_pagination_gap = False
            pages_fetched = 0

            try:
                current_page = 1
                while pages_fetched < self._max_catchup_pages:
                    pages_fetched += 1
                    page_res = await adapter.poll_runs(
                        db,
                        conn_ctx,
                        repo_full_name=repo_row.name,
                        since_cursor=since_iso,
                        etag=cursor_row.etag
                        if (current_page == 1 and not offline_exceeded_ttl)
                        else None,
                        page=current_page,
                        per_page=self._per_page,
                        now=ref_now,
                    )
                    if page_res.rate_limit_remaining is not None:
                        rl_remaining = page_res.rate_limit_remaining
                    if page_res.rate_limit_reset_at is not None:
                        rl_reset_at = page_res.rate_limit_reset_at

                    if page_res.not_modified and current_page == 1:
                        not_modified = True
                        if page_res.etag:
                            new_etag = page_res.etag
                        break

                    if page_res.retention_expired:
                        retention_expired = True
                        break

                    if current_page == 1 and page_res.etag is not None:
                        new_etag = page_res.etag

                    collected_items.extend(page_res.items)
                    if page_res.oldest_observed_at is not None and (
                        oldest_observed is None or page_res.oldest_observed_at < oldest_observed
                    ):
                        oldest_observed = page_res.oldest_observed_at
                    if page_res.newest_observed_at is not None and (
                        newest_observed is None or page_res.newest_observed_at > newest_observed
                    ):
                        newest_observed = page_res.newest_observed_at

                    if effective_since is None or not page_res.has_next_page:
                        break
                    if (
                        page_res.oldest_observed_at is not None
                        and page_res.oldest_observed_at <= effective_since
                    ):
                        break
                    if pages_fetched >= self._max_catchup_pages:
                        unbridged_pagination_gap = True
                        break
                    current_page = page_res.next_page or (current_page + 1)

            except ProviderError as exc:
                if exc.code == "RATE_LIMIT":
                    backoff_secs = max(1, exc.retry_after_seconds or 60)
                    backoff_until = ref_now + timedelta(seconds=backoff_secs)
                    cursor_row.last_polled_at = ref_now
                    cursor_row.next_poll_after = backoff_until
                    cursor_row.rate_limit_remaining = 0
                    cursor_row.rate_limit_reset_at = backoff_until
                    cursor_row.consecutive_failures += 1
                    cursor_row.last_status = "rate_limited"
                    cursor_row.last_error_code = "provider_rate_limited"
                    cursor_row.last_error_detail = self._redactor.redact_text(exc.detail)[:950]
                    cursor_row.version += 1
                    cursor_row.updated_at = ref_now
                    await append_audit_entry(
                        db,
                        workspace_id=workspace_id,
                        repository_id=repo_row.id,
                        actor_type="system",
                        actor_id=f"poller:{provider}",
                        action="integration.poll.rate_limited",
                        target=f"provider_sync_cursor:{cursor_row.id}",
                        decision="deny",
                        reason_code="provider_rate_limited",
                        correlation_id=correlation_id,
                        client_ip=None,
                        metadata={
                            "retry_after_seconds": backoff_secs,
                            "next_poll_after": backoff_until.isoformat(),
                        },
                        occurred_at=ref_now,
                    )
                    await db.flush()
                    return RepoPollOutcome(
                        repository_id=repo_row.id,
                        cursor=_to_sync_cursor_dto(cursor_row),
                        polled=True,
                        rate_limited=True,
                        history_gap_detected=cursor_row.history_gap_detected,
                    )

                if exc.code == "REVOKED" and self._integration_service is not None:
                    await self._integration_service._suspend_connection_work_and_mark_revoked(
                        db,
                        conn_row=conn_row,
                        actor_type="system",
                        actor_id=f"poller:{provider}",
                        reason_code="provider_credentials_revoked",
                        detail=exc.detail,
                        correlation_id=correlation_id,
                        client_ip=None,
                        revoke_stored_secrets=False,
                        now=ref_now,
                    )
                    await db.refresh(cursor_row)
                    await db.flush()
                    return RepoPollOutcome(
                        repository_id=repo_row.id,
                        cursor=_to_sync_cursor_dto(cursor_row),
                        polled=True,
                        history_gap_detected=cursor_row.history_gap_detected,
                    )

                jitter = compute_poll_jitter_seconds(
                    repo_row.id,
                    now=ref_now,
                    max_jitter_seconds=self._max_jitter_seconds,
                )
                err_backoff = min(
                    300,
                    cursor_row.poll_interval_seconds
                    * (2 ** min(cursor_row.consecutive_failures, 3))
                    + jitter,
                )
                cursor_row.last_polled_at = ref_now
                cursor_row.next_poll_after = ref_now + timedelta(seconds=err_backoff)
                cursor_row.consecutive_failures += 1
                cursor_row.last_status = "error"
                cursor_row.last_error_code = f"provider_{exc.code.lower()}"
                cursor_row.last_error_detail = self._redactor.redact_text(exc.detail)[:950]
                cursor_row.version += 1
                cursor_row.updated_at = ref_now
                await db.flush()
                return RepoPollOutcome(
                    repository_id=repo_row.id,
                    cursor=_to_sync_cursor_dto(cursor_row),
                    polled=True,
                    history_gap_detected=cursor_row.history_gap_detected,
                )

            jitter_secs = compute_poll_jitter_seconds(
                repo_row.id,
                now=ref_now,
                max_jitter_seconds=self._max_jitter_seconds,
            )
            next_due = ref_now + timedelta(seconds=cursor_row.poll_interval_seconds + jitter_secs)

            # Process collected runs oldest-first so triggers record in chronological order
            triggers_created = 0
            last_seen_run_id = cursor_row.last_seen_run_id
            if not not_modified and collected_items:
                last_seen_run_id = collected_items[0].run.external_run_id[:128]
                for poll_item in reversed(collected_items):
                    run = poll_item.run
                    if not run.jobs_complete or run.conclusion not in FAILURE_CONCLUSIONS:
                        continue

                    untrusted_fork = run.head_repo_fork
                    if provider == "github" and run.head_repo_id:
                        verdict = WorkflowHazardScanner.classify_pull_request_trust(
                            base_repo_id=repo_row.external_repo_id,
                            head_repo_id=run.head_repo_id,
                            head_repo_fork=run.head_repo_fork,
                        )
                        untrusted_fork = verdict.untrusted_fork

                    explicit_rerun = False
                    if provider == "github" and ":" in run.attempt_key:
                        att_part = run.attempt_key.rsplit(":", 1)[-1]
                        explicit_rerun = att_part.isdigit() and int(att_part) > 1

                    synth_delivery_id = f"poll:{repo_row.id}:{run.attempt_key}"[:256]
                    synth_summary = {
                        "source": "poll",
                        "repository_id": repo_row.id,
                        "provider_run_id": run.external_run_id[:128],
                        "attempt_key": run.attempt_key[:128],
                        "head_sha": run.head_sha[:64],
                        "ref": self._redactor.redact_text(run.ref)[:120],
                        "conclusion": run.conclusion,
                    }
                    synth_digest = hashlib.sha256(
                        json.dumps(synth_summary, sort_keys=True).encode("utf-8")
                    ).hexdigest()

                    candidate_inbox_id = new_uuid7(now=ref_now)
                    inserted_inbox_id = await db.scalar(
                        pg_insert(WebhookInboxModel)
                        .values(
                            id=candidate_inbox_id,
                            workspace_id=workspace_id,
                            connection_id=conn_row.id,
                            repository_id=repo_row.id,
                            provider=provider,
                            source="poll",
                            event_type=run.event_type[:120] or "poll_sync",
                            provider_delivery_id=synth_delivery_id,
                            payload_digest=synth_digest,
                            signature_valid=True,
                            provider_run_id=run.external_run_id[:128],
                            attempt_key=run.attempt_key[:128],
                            head_sha=run.head_sha[:64] if run.head_sha else None,
                            status="received",
                            sanitized_headers_json={"x-red2pr-source": "local_poller"},
                            normalized_summary_json=synth_summary,
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

                    candidate = NormalizedRunCandidate(
                        provider=provider,
                        external_repo_id=repo_row.external_repo_id,
                        repo_full_name=repo_row.name,
                        provider_run_id=run.external_run_id,
                        attempt_key=run.attempt_key,
                        head_sha=run.head_sha,
                        ref=run.ref,
                        event_type=run.event_type,
                        status=run.status,
                        conclusion=run.conclusion,
                        jobs_complete=run.jobs_complete,
                        raw_vendor_status=run.raw_vendor_status,
                        untrusted_fork=untrusted_fork,
                        event_timestamp=poll_item.observed_at,
                        explicit_rerun=explicit_rerun,
                    )
                    resolution = await record_normalized_run_failure_trigger(
                        db,
                        workspace_id=workspace_id,
                        conn_row=conn_row,
                        repo_row=repo_row,
                        candidate=candidate,
                        source="poll",
                        inbox_id=inserted_inbox_id,
                        correlation_id=correlation_id,
                        redactor=self._redactor,
                        now=ref_now,
                    )
                    if resolution.created:
                        triggers_created += 1

                    if inserted_inbox_id is not None:
                        inbox_row = await db.scalar(
                            select(WebhookInboxModel).where(
                                WebhookInboxModel.workspace_id == workspace_id,
                                WebhookInboxModel.id == inserted_inbox_id,
                            )
                        )
                        if inbox_row is not None:
                            inbox_row.status = resolution.inbox_status
                            inbox_row.disposition_reason = resolution.reason_code[:120]
                            inbox_row.trigger_id = resolution.trigger_id
                            inbox_row.processed_at = ref_now
                            inbox_row.updated_at = ref_now

            # Detect new offline history-TTL or pagination gaps (`T-SRC-04-N`)
            newly_detected_gap = (
                offline_exceeded_ttl or retention_expired or unbridged_pagination_gap
            )
            if newly_detected_gap:
                gap_since = (
                    prior_checkpoint
                    if offline_exceeded_ttl
                    else (effective_since or prior_checkpoint or ref_now)
                )
                gap_until = oldest_observed or ref_now
                if offline_exceeded_ttl and prior_checkpoint is not None:
                    offline_days = max(
                        1, int((ref_now - prior_checkpoint).total_seconds() // 86400)
                    )
                    ttl_days = max(1, int(self._provider_history_ttl.total_seconds() // 86400))
                    gap_detail = (
                        f"Offline duration ({offline_days}d) exceeded provider run history "
                        f"retention ({ttl_days}d); missed runs in gap window cannot be recovered."
                    )
                    gap_reason = "offline_duration_exceeded_provider_ttl"
                elif retention_expired:
                    gap_detail = (
                        "Provider reported history retention expiration (HTTP 410); "
                        "missed runs prior to checkpoint cannot be recovered."
                    )
                    gap_reason = "provider_history_retention_expired"
                else:
                    gap_detail = (
                        f"Missed run volume exceeded bounded catch-up window "
                        f"({self._max_catchup_pages} pages); intermediate history gap recorded."
                    )
                    gap_reason = "catchup_pagination_window_exceeded"

                cursor_row.history_gap_detected = True
                if cursor_row.history_gap_since is None:
                    cursor_row.history_gap_since = gap_since
                cursor_row.history_gap_until = gap_until
                cursor_row.history_gap_detail = gap_detail[:950]
                cursor_row.last_error_code = gap_reason
                cursor_row.last_error_detail = gap_detail[:950]

                await append_audit_entry(
                    db,
                    workspace_id=workspace_id,
                    repository_id=repo_row.id,
                    actor_type="system",
                    actor_id=f"poller:{provider}",
                    action="integration.poll.history_gap_detected",
                    target=f"provider_sync_cursor:{cursor_row.id}",
                    decision="reconcile",
                    reason_code=gap_reason,
                    correlation_id=correlation_id,
                    client_ip=None,
                    metadata={
                        "gap_since": gap_since.isoformat() if gap_since else None,
                        "gap_until": gap_until.isoformat(),
                        "pages_fetched": pages_fetched,
                    },
                    occurred_at=ref_now,
                )

            # Advance durable checkpoint ONLY inside this transaction commit (`SRC-04`)
            if not not_modified:
                candidate_hwm = newest_observed or ref_now
                if (
                    cursor_row.high_water_mark_at is None
                    or candidate_hwm > cursor_row.high_water_mark_at
                ):
                    cursor_row.high_water_mark_at = candidate_hwm
                cursor_row.last_seen_run_id = last_seen_run_id
                cursor_row.last_stable_page = max(1, pages_fetched)

            cursor_row.etag = new_etag
            cursor_row.last_polled_at = ref_now
            cursor_row.last_success_at = ref_now
            cursor_row.next_poll_after = next_due
            cursor_row.rate_limit_remaining = rl_remaining
            cursor_row.rate_limit_reset_at = rl_reset_at
            cursor_row.consecutive_failures = 0
            if cursor_row.history_gap_detected:
                cursor_row.last_status = "gap_detected"
            elif not_modified:
                cursor_row.last_status = "not_modified"
                cursor_row.last_error_code = None
                cursor_row.last_error_detail = None
            else:
                cursor_row.last_status = "ok"
                cursor_row.last_error_code = None
                cursor_row.last_error_detail = None
            cursor_row.version += 1
            cursor_row.updated_at = ref_now

            await db.flush()
            return RepoPollOutcome(
                repository_id=repo_row.id,
                cursor=_to_sync_cursor_dto(cursor_row),
                polled=True,
                rate_limited=False,
                history_gap_detected=cursor_row.history_gap_detected,
                triggers_created=triggers_created,
                runs_inspected=len(collected_items),
            )

    async def poll_connection(
        self,
        *,
        workspace_id: str,
        connection_id: str,
        repository_ids: list[str] | None = None,
        force_poll: bool = False,
        correlation_id: str | None = None,
        now: datetime | None = None,
    ) -> ConnectionPollSummary:
        """Poll all active (or specified) repositories for a connection under workspace RLS."""
        ref_now = now.astimezone(UTC) if now is not None else self.now()
        corr_id = correlation_id or new_uuid7(now=ref_now)

        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            stmt = (
                select(RepositoryModel.id)
                .where(
                    RepositoryModel.workspace_id == workspace_id,
                    RepositoryModel.provider_connection_id == connection_id,
                    RepositoryModel.active.is_(True),
                )
                .order_by(RepositoryModel.name.asc())
            )
            if repository_ids is not None:
                stmt = stmt.where(RepositoryModel.id.in_(repository_ids))
            target_repo_ids = list((await db.scalars(stmt)).all())

        outcomes: list[RepoPollOutcome] = []
        for repo_id in target_repo_ids:
            outcome = await self.poll_repository(
                workspace_id=workspace_id,
                connection_id=connection_id,
                repository_id=repo_id,
                correlation_id=corr_id,
                force_poll=force_poll,
                now=ref_now,
            )
            if outcome is not None:
                outcomes.append(outcome)

        return ConnectionPollSummary(
            connection_id=connection_id,
            workspace_id=workspace_id,
            outcomes=tuple(outcomes),
            polled_repository_count=sum(1 for o in outcomes if o.polled),
            rate_limited_count=sum(1 for o in outcomes if o.rate_limited),
            history_gap_count=sum(1 for o in outcomes if o.history_gap_detected),
            triggers_created_count=sum(o.triggers_created for o in outcomes),
        )

    async def poll_all_due_connections(
        self,
        *,
        now: datetime | None = None,
    ) -> tuple[ConnectionPollSummary, ...]:
        """Sweep all active `ready`/`degraded` connections across workspaces (`NFR-04`)."""
        ref_now = now.astimezone(UTC) if now is not None else self.now()
        async with instance_rls_session(self._session_factory, mode="instance_admin") as lookup:
            pairs = list(
                (
                    await lookup.execute(
                        select(
                            ProviderConnectionModel.workspace_id,
                            ProviderConnectionModel.id,
                        )
                        .where(ProviderConnectionModel.status.in_(("ready", "degraded")))
                        .order_by(ProviderConnectionModel.created_at.asc())
                    )
                ).all()
            )

        summaries: list[ConnectionPollSummary] = []
        for ws_id, conn_id in pairs:
            corr_id = new_uuid7(now=ref_now)
            with bind_telemetry_context(
                correlation_id=corr_id,
                workspace_id=str(ws_id),
                entry_point="scheduler",
            ):
                summary = await self.poll_connection(
                    workspace_id=str(ws_id),
                    connection_id=str(conn_id),
                    force_poll=False,
                    correlation_id=corr_id,
                    now=ref_now,
                )
                summaries.append(summary)
        return tuple(summaries)

    async def run_loop(
        self,
        stop_event: asyncio.Event,
        *,
        tick_seconds: float = 15.0,
    ) -> None:
        """Cancellable background polling loop checking due cursors every `tick_seconds`."""
        bounded_tick = max(1.0, tick_seconds)
        while not stop_event.is_set():
            try:
                await self.poll_all_due_connections()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                _LOGGER.error(
                    "Background polling sweep encountered an error",
                    extra={
                        "event": "integration.poller.sweep_error",
                        "error_code": type(exc).__name__,
                    },
                )
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=bounded_tick)
            except TimeoutError:
                continue
