"""Attempt-pinned CI run, matrix job, log & bomb-safe artifact collector (`U13`, `TRI-01`).

Implements `TRI-01`, `TRI-03`, `W-03`, `W-04`, `NFR-14`, `SEC-007`, `SEC-016`, `SEC-017`,
`SEC-024`, `SEC-025`, `SEC-032`, `SEC-033`, and `SEC-036`:
- Collects attempt-specific jobs (`attempt_number` for GitHub, `pipeline:<id>` + downstream
  child bridge pipelines for GitLab) so rerun attempts never mix jobs or logs.
- Verifies live provider `head_sha` against the pinned trigger `head_sha` (`SEC-016`): stale or
  force-pushed mismatches mark `head_sha_verified=False`, `ingestion_state='stale_sha'`.
- Enforces `NFR-14` (`<= 20 MiB` per-log cap with explicit tail preservation & truncation marker;
  `<= 100 MiB` compressed, `<= 500 MiB` expanded, `<= 10,000` files via `archive_guard.py`).
- Never treats `410` expired or missing logs/artifacts as passing (`T-TRI-01-N`).
- Redacts secrets via `Redactor` (`SEC-017`) BEFORE storing logs in `ArtifactStore` or indexing
  failure excerpts and `TRI-03` fingerprints.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.events import EventEnvelope, SecurityIdentityEventPayload
from py_contracts.evidence import ArtifactAccessClass
from py_contracts.integrations import (
    CiConclusion,
    CiJob,
    CiRun,
    CiRunIngestionState,
    CiRunStatus,
    ConnectionAuthMode,
    FlakyClassification,
    JobLogStatus,
    ProviderKind,
)
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import ConflictError, DependencyUnavailableError, NotFoundError
from red2pr_control.core.redaction import DEFAULT_REDACTOR, REDACTION_VERSION, Redactor
from red2pr_control.db.base import (
    ArtifactModel,
    CiJobModel,
    CiRunModel,
    CiRunTriggerModel,
    ProviderConnectionModel,
    RepositoryModel,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.integrations.base import (
    ProviderConnectionContext,
    ProviderError,
    ProviderJobRecord,
)
from red2pr_control.integrations.github_app import GitHubAppAdapter
from red2pr_control.integrations.gitlab_client import GitLabAdapter
from red2pr_control.orchestrator.queue import DurableTaskQueueService
from red2pr_control.triage_evidence.archive_guard import (
    MAX_ARCHIVE_COMPRESSED_BYTES,
    MAX_ARCHIVE_EXPANDED_BYTES,
    MAX_ARCHIVE_FILES,
    ArchiveHazardError,
    inspect_and_extract_archive,
)
from red2pr_control.triage_evidence.artifact_store import (
    ArtifactStoreProtocol,
    persist_encrypted_artifact,
)
from red2pr_control.triage_evidence.flaky import (
    FAILURE_CONCLUSIONS,
    record_and_classify_job_observation,
    summarize_run_flaky_classification,
)

MAX_CI_LOG_BYTES = 20 * 1024 * 1024  # 20 MiB (`NFR-14`)
TRUNCATION_BANNER = "[RED2PR TRUNCATED: upstream CI log exceeded max_bytes cap; tail preserved]\n"


def _default_utc_clock() -> datetime:
    return datetime.now(tz=UTC)


def parse_attempt_number(attempt_key: str) -> int:
    """Extract numeric attempt index from `<run_id>:<n>` or `attempt:<n>` (`1` for `pipeline:`)."""
    clean = attempt_key.strip()
    if clean.startswith("pipeline:"):
        return 1
    if ":" in clean:
        suffix = clean.rsplit(":", 1)[1].strip()
        if suffix.isdigit():
            return max(1, int(suffix))
    return 1


def _build_connection_context(conn: ProviderConnectionModel) -> ProviderConnectionContext:
    return ProviderConnectionContext(
        workspace_id=conn.workspace_id,
        connection_id=conn.id,
        provider=cast(ProviderKind, conn.provider),
        base_url=conn.base_url,
        app_id=conn.app_id,
        client_id=conn.client_id,
        installation_id=conn.external_installation_id,
        credential_secret_ref=conn.credential_secret_ref,
        webhook_secret_ref=conn.webhook_secret_ref,
        auth_mode=cast(ConnectionAuthMode, conn.auth_mode),
        vendor_version=conn.vendor_version,
    )


def ci_run_model_to_dto(
    row: CiRunModel,
    *,
    repository_name: str | None = None,
) -> CiRun:
    """Project `CiRunModel` to `S-10` `CiRun` canonical DTO."""
    return CiRun(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        external_id=row.external_id,
        attempt_key=row.attempt_key,
        head_sha=row.head_sha,
        ref=row.ref,
        event_type=row.event_type,
        status=cast(CiRunStatus, row.status),
        conclusion=cast(CiConclusion | None, row.conclusion),
        jobs_complete=row.jobs_complete,
        raw_vendor_status=row.raw_vendor_status,
        provider=cast(ProviderKind, row.provider),
        repository_name=repository_name,
        attempt_number=row.attempt_number,
        is_rerun=row.is_rerun,
        untrusted_fork=row.untrusted_fork,
        head_sha_verified=row.head_sha_verified,
        observed_head_sha=row.observed_head_sha,
        ingestion_state=cast(CiRunIngestionState, row.ingestion_state),
        incomplete_reason=row.incomplete_reason,
        failed_job_count=row.failed_job_count,
        total_job_count=row.total_job_count,
        artifact_count=row.artifact_count,
        flaky_classification=cast(FlakyClassification, row.flaky_classification),
        child_pipeline_ids=list(row.child_pipeline_ids_json or []),
        started_at=row.started_at,
        completed_at=row.completed_at,
    )


def ci_job_model_to_dto(row: CiJobModel) -> CiJob:
    """Project `CiJobModel` to `S-10` `CiJob` canonical DTO."""
    return CiJob(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        external_id=row.external_id,
        run_id=row.run_id,
        name=row.name,
        matrix_dimensions=dict(row.matrix_dimensions_json or {}),
        retry_of_id=row.retry_of_id,
        started_at=row.started_at,
        completed_at=row.completed_at,
        conclusion=cast(CiConclusion | None, row.conclusion),
        status=cast(CiRunStatus, row.status),
        stage=row.stage,
        is_child_pipeline_job=row.is_child_pipeline_job,
        child_pipeline_id=row.child_pipeline_id,
        log_artifact_id=row.log_artifact_id,
        log_status=cast(JobLogStatus, row.log_status),
        log_size_bytes=row.log_size_bytes,
        log_truncated=row.log_truncated,
        failure_excerpt=row.failure_excerpt,
        failure_fingerprint_id=row.failure_fingerprint_id,
        failure_fingerprint_hash=row.failure_fingerprint_hash,
        flaky_classification=cast(FlakyClassification, row.flaky_classification),
    )


@dataclass(frozen=True, slots=True)
class _CollectedJobCandidate:
    record: ProviderJobRecord
    is_child_pipeline_job: bool
    child_pipeline_id: str | None


class CiRunCollectorService:
    """Idempotent `TRI-01` CI run, matrix job, redacted log & encrypted artifact collector."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        artifact_store: ArtifactStoreProtocol,
        github_adapter: GitHubAppAdapter | None = None,
        gitlab_adapter: GitLabAdapter | None = None,
        redactor: Redactor = DEFAULT_REDACTOR,
        max_log_bytes: int = MAX_CI_LOG_BYTES,
        max_archive_compressed_bytes: int = MAX_ARCHIVE_COMPRESSED_BYTES,
        max_archive_expanded_bytes: int = MAX_ARCHIVE_EXPANDED_BYTES,
        max_archive_files: int = MAX_ARCHIVE_FILES,
        log_retention_delta: timedelta = timedelta(days=7),
        artifact_retention_delta: timedelta = timedelta(days=30),
        clock: Callable[[], datetime] = _default_utc_clock,
    ) -> None:
        self._session_factory = session_factory
        self._artifact_store = artifact_store
        self._github_adapter = github_adapter
        self._gitlab_adapter = gitlab_adapter
        self._redactor = redactor
        self._max_log_bytes = max_log_bytes
        self._max_archive_compressed_bytes = max_archive_compressed_bytes
        self._max_archive_expanded_bytes = max_archive_expanded_bytes
        self._max_archive_files = max_archive_files
        self._log_retention_delta = log_retention_delta
        self._artifact_retention_delta = artifact_retention_delta
        self._clock = clock

    @property
    def artifact_store(self) -> ArtifactStoreProtocol:
        return self._artifact_store

    def _resolve_adapter(self, provider: str) -> GitHubAppAdapter | GitLabAdapter:
        if provider == "github" and self._github_adapter is not None:
            return self._github_adapter
        if provider == "gitlab" and self._gitlab_adapter is not None:
            return self._gitlab_adapter
        raise DependencyUnavailableError(
            code="provider_adapter_unconfigured",
            detail=f"Source provider adapter '{provider}' is not configured on this instance.",
        )

    async def collect_from_trigger(
        self,
        *,
        workspace_id: str,
        trigger_id: str,
        correlation_id: str | None = None,
        now: datetime | None = None,
    ) -> CiRun:
        """Ingest a `CiRunTriggerModel` into `ci_runs`, `ci_jobs`, `artifacts` & fingerprints."""
        ref_now = now.astimezone(UTC) if now is not None else self._clock().astimezone(UTC)
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            trig = await db.scalar(
                select(CiRunTriggerModel).where(
                    CiRunTriggerModel.workspace_id == workspace_id,
                    CiRunTriggerModel.id == trigger_id,
                )
            )
            if trig is None:
                raise NotFoundError(
                    code="ci_run_trigger_not_found",
                    detail="CI run trigger was not found in this workspace.",
                )

        return await self.collect_run_attempt(
            workspace_id=workspace_id,
            repository_id=trig.repository_id,
            external_run_id=trig.provider_run_id,
            attempt_key=trig.attempt_key,
            expected_head_sha=trig.head_sha,
            fallback_ref=trig.ref,
            fallback_event_type=trig.event_type,
            is_rerun=trig.is_rerun,
            untrusted_fork=trig.untrusted_fork,
            trigger_id=trig.id,
            correlation_id=correlation_id or trig.correlation_id,
            now=ref_now,
        )

    async def collect_run_attempt(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        external_run_id: str,
        attempt_key: str,
        expected_head_sha: str,
        fallback_ref: str = "HEAD",
        fallback_event_type: str = "push",
        is_rerun: bool = False,
        untrusted_fork: bool = False,
        trigger_id: str | None = None,
        correlation_id: str | None = None,
        now: datetime | None = None,
    ) -> CiRun:
        """Idempotently ingest or refresh an attempt-pinned CI run (`TRI-01`, `TRI-03`)."""
        ref_now = now.astimezone(UTC) if now is not None else self._clock().astimezone(UTC)
        corr_id = (correlation_id or new_uuid7(now=ref_now))[:120]
        attempt_number = parse_attempt_number(attempt_key)

        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            repo_row = await db.scalar(
                select(RepositoryModel).where(
                    RepositoryModel.workspace_id == workspace_id,
                    RepositoryModel.id == repository_id,
                )
            )
            if repo_row is None:
                raise NotFoundError(
                    code="repository_not_found",
                    detail="Repository not found in workspace.",
                )
            conn_row = await db.scalar(
                select(ProviderConnectionModel).where(
                    ProviderConnectionModel.workspace_id == workspace_id,
                    ProviderConnectionModel.id == repo_row.provider_connection_id,
                )
            )
            if conn_row is None:
                raise NotFoundError(
                    code="connection_not_found",
                    detail="Provider connection not found for repository.",
                )
            if conn_row.status == "revoked":
                raise ConflictError(
                    code="connection_revoked",
                    detail="Cannot collect CI runs from a revoked provider connection.",
                )

            adapter = self._resolve_adapter(conn_row.provider)
            conn_ctx = _build_connection_context(conn_row)

            # 1. Fetch authoritative run metadata from provider
            live_run = await adapter.get_run(
                db,
                conn_ctx,
                repo_full_name=repo_row.name,
                external_run_id=external_run_id,
                now=ref_now,
            )

            incomplete_reasons: list[str] = []
            observed_sha = live_run.head_sha.strip().lower()
            expected_sha = expected_head_sha.strip().lower()
            head_sha_verified = bool(observed_sha) and (observed_sha == expected_sha)
            if not head_sha_verified:
                incomplete_reasons.append("head_sha_mismatch")

            if not live_run.jobs_complete:
                incomplete_reasons.append("jobs_incomplete")

            # Upsert CiRunModel first so composite FKs from artifacts and ci_jobs succeed
            run_row = await db.scalar(
                select(CiRunModel)
                .where(
                    CiRunModel.workspace_id == workspace_id,
                    CiRunModel.repository_id == repository_id,
                    CiRunModel.external_id == external_run_id,
                    CiRunModel.attempt_key == attempt_key,
                )
                .with_for_update()
            )
            if run_row is None:
                run_row = CiRunModel(
                    id=new_uuid7(now=ref_now),
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    connection_id=conn_row.id,
                    trigger_id=trigger_id,
                    provider=conn_row.provider,
                    external_id=external_run_id,
                    attempt_key=attempt_key,
                    attempt_number=attempt_number,
                    head_sha=expected_sha,
                    observed_head_sha=observed_sha[:64] if observed_sha else None,
                    head_sha_verified=head_sha_verified,
                    ref=(live_run.ref or fallback_ref)[:120],
                    event_type=(live_run.event_type or fallback_event_type)[:120],
                    status=live_run.status,
                    conclusion=live_run.conclusion,
                    jobs_complete=live_run.jobs_complete,
                    raw_vendor_status=(
                        live_run.raw_vendor_status[:120] if live_run.raw_vendor_status else None
                    ),
                    is_rerun=is_rerun or attempt_number > 1,
                    untrusted_fork=untrusted_fork or live_run.head_repo_fork,
                    ingestion_state="collecting",
                    incomplete_reason=None,
                    failed_job_count=0,
                    total_job_count=0,
                    artifact_count=0,
                    flaky_classification="unknown",
                    child_pipeline_ids_json=[],
                    started_at=None,
                    completed_at=None,
                    version=1,
                    created_at=ref_now,
                    updated_at=ref_now,
                )
                db.add(run_row)
            else:
                run_row.observed_head_sha = observed_sha[:64] if observed_sha else None
                run_row.head_sha_verified = head_sha_verified
                run_row.ref = (live_run.ref or fallback_ref)[:120]
                run_row.event_type = (live_run.event_type or fallback_event_type)[:120]
                run_row.status = live_run.status
                run_row.conclusion = live_run.conclusion
                run_row.jobs_complete = live_run.jobs_complete
                run_row.raw_vendor_status = (
                    live_run.raw_vendor_status[:120] if live_run.raw_vendor_status else None
                )
                run_row.untrusted_fork = untrusted_fork or live_run.head_repo_fork
                run_row.version += 1
                run_row.updated_at = ref_now
            await db.flush()

            if not head_sha_verified:
                await append_audit_entry(
                    db,
                    workspace_id=workspace_id,
                    actor_type="service",
                    actor_id="ci_collector",
                    action="security.ci_run.stale_sha",
                    target=f"ci_run:{run_row.id}",
                    decision="deny",
                    reason_code="head_sha_mismatch",
                    correlation_id=corr_id,
                    metadata={
                        "expected_head_sha": expected_sha,
                        "observed_head_sha": observed_sha,
                        "external_run_id": external_run_id,
                        "attempt_key": attempt_key,
                    },
                    occurred_at=ref_now,
                )
                await enqueue_outbox_event(
                    db,
                    EventEnvelope(
                        event_id=new_uuid7(now=ref_now),
                        type="security.policy.denied",
                        occurred_at=ref_now,
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        aggregate_id=run_row.id,
                        aggregate_version=run_row.version,
                        correlation_id=corr_id,
                        payload=SecurityIdentityEventPayload(
                            target_id=run_row.id,
                            reason_code="head_sha_mismatch",
                        ),
                    ),
                    now=ref_now,
                )

            # 2. Fetch attempt-specific jobs (+ GitLab downstream child pipeline jobs)
            primary_jobs = await adapter.list_jobs(
                db,
                conn_ctx,
                repo_full_name=repo_row.name,
                external_run_id=external_run_id,
                attempt_number=attempt_number if conn_row.provider == "github" else None,
                now=ref_now,
            )
            collected_jobs: list[_CollectedJobCandidate] = [
                _CollectedJobCandidate(
                    record=j,
                    is_child_pipeline_job=False,
                    child_pipeline_id=None,
                )
                for j in primary_jobs
            ]

            child_pipeline_ids: list[str] = []
            if conn_row.provider == "gitlab" and isinstance(adapter, GitLabAdapter):
                children = await adapter.list_child_pipelines(
                    db,
                    conn_ctx,
                    repo_full_name=repo_row.name,
                    external_run_id=external_run_id,
                )
                for child in children:
                    child_pipeline_ids.append(child.downstream_pipeline_id)
                    try:
                        child_jobs = await adapter.list_jobs(
                            db,
                            conn_ctx,
                            repo_full_name=repo_row.name,
                            external_run_id=child.downstream_pipeline_id,
                            now=ref_now,
                        )
                        for cj in child_jobs:
                            collected_jobs.append(
                                _CollectedJobCandidate(
                                    record=cj,
                                    is_child_pipeline_job=True,
                                    child_pipeline_id=child.downstream_pipeline_id,
                                )
                            )
                    except ProviderError as exc:
                        if exc.code in ("TRANSIENT", "RATE_LIMIT"):
                            raise
                        incomplete_reasons.append(
                            f"child_pipeline_jobs_unavailable:{child.downstream_pipeline_id}"
                        )

            # 3. Collect, cap (`<=20 MiB`), redact, encrypt & fingerprint each job log
            failed_job_count = 0
            job_flaky_verdicts: list[FlakyClassification] = []
            earliest_start: datetime | None = None
            latest_end: datetime | None = None

            for candidate in collected_jobs:
                j_rec = candidate.record
                ext_job_id = (
                    f"child:{candidate.child_pipeline_id}:{j_rec.external_job_id}"
                    if candidate.is_child_pipeline_job and candidate.child_pipeline_id
                    else j_rec.external_job_id
                )
                if j_rec.started_at is not None and (
                    earliest_start is None or j_rec.started_at < earliest_start
                ):
                    earliest_start = j_rec.started_at
                if j_rec.completed_at is not None and (
                    latest_end is None or j_rec.completed_at > latest_end
                ):
                    latest_end = j_rec.completed_at

                if (j_rec.conclusion or "") in FAILURE_CONCLUSIONS:
                    failed_job_count += 1

                log_status: JobLogStatus = "unavailable"
                log_truncated = False
                log_size_bytes = 0
                log_art_id: str | None = None
                redacted_log_text: str | None = None

                if j_rec.status in ("queued", "in_progress"):
                    log_status = "pending"
                    incomplete_reasons.append(f"job_running:{j_rec.external_job_id}")
                else:
                    try:
                        raw_log_bytes = await adapter.get_job_log(
                            db,
                            conn_ctx,
                            repo_full_name=repo_row.name,
                            external_job_id=j_rec.external_job_id,
                            max_bytes=self._max_log_bytes + 1,
                            now=ref_now,
                        )
                        if len(raw_log_bytes) > self._max_log_bytes:
                            log_truncated = True
                            banner_bytes = TRUNCATION_BANNER.encode("utf-8")
                            tail_budget = max(0, self._max_log_bytes - len(banner_bytes))
                            capped_bytes = banner_bytes + raw_log_bytes[-tail_budget:]
                        else:
                            capped_bytes = raw_log_bytes

                        decoded_text = capped_bytes.decode("utf-8", errors="replace")
                        redacted_log_text = self._redactor.redact_text(decoded_text)
                        redacted_bytes = redacted_log_text.encode("utf-8")
                        if len(redacted_bytes) > self._max_log_bytes:
                            redacted_bytes = redacted_bytes[: self._max_log_bytes]
                            redacted_log_text = redacted_bytes.decode("utf-8", errors="ignore")
                            log_truncated = True

                        log_size_bytes = len(redacted_bytes)
                        log_status = "truncated" if log_truncated else "available"

                        log_art = await persist_encrypted_artifact(
                            db,
                            store=self._artifact_store,
                            workspace_id=workspace_id,
                            repository_id=repository_id,
                            name=f"job-{j_rec.external_job_id}.log"[:120],
                            kind="ci_job_log",
                            mime="text/plain; charset=utf-8",
                            plaintext=redacted_bytes,
                            redaction_version=REDACTION_VERSION,
                            access_class="workspace_internal",
                            retention_delta=self._log_retention_delta,
                            run_id=run_row.id,
                            now=ref_now,
                        )
                        log_art_id = log_art.id
                    except ProviderError as exc:
                        if exc.code in ("TRANSIENT", "RATE_LIMIT", "REVOKED"):
                            raise
                        if exc.status_code == 410:
                            log_status = "expired"
                            incomplete_reasons.append(f"log_expired:{j_rec.external_job_id}")
                        else:
                            log_status = "unavailable"
                            incomplete_reasons.append(f"log_unavailable:{j_rec.external_job_id}")

                # Only record fingerprint history when head_sha is verified (`SEC-016`)
                fp_row = None
                flaky_verdict: FlakyClassification = "unknown"
                failure_excerpt: str | None = None
                if head_sha_verified:
                    (
                        fp_row,
                        flaky_verdict,
                        failure_excerpt,
                    ) = await record_and_classify_job_observation(
                        db,
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        run_id=run_row.id,
                        attempt_key=attempt_key,
                        head_sha=expected_sha,
                        job_name=j_rec.name,
                        conclusion=j_rec.conclusion,
                        log_text=redacted_log_text,
                        log_status=log_status,
                        redactor=self._redactor,
                        now=ref_now,
                    )
                if (j_rec.conclusion or "") in FAILURE_CONCLUSIONS or flaky_verdict != "unknown":
                    job_flaky_verdicts.append(flaky_verdict)

                stage_val = j_rec.matrix_dimensions.get("stage")
                clean_dims = {
                    k[:120]: self._redactor.redact_text(v)[:256]
                    for k, v in j_rec.matrix_dimensions.items()
                    if k != "stage"
                }

                job_row = await db.scalar(
                    select(CiJobModel).where(
                        CiJobModel.workspace_id == workspace_id,
                        CiJobModel.run_id == run_row.id,
                        CiJobModel.external_id == ext_job_id[:128],
                    )
                )
                if job_row is None:
                    job_row = CiJobModel(
                        id=new_uuid7(now=ref_now),
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        run_id=run_row.id,
                        external_id=ext_job_id[:128],
                        name=self._redactor.redact_text(j_rec.name)[:120] or "job",
                        stage=stage_val[:120] if stage_val else None,
                        matrix_dimensions_json=clean_dims,
                        retry_of_id=j_rec.retry_of_id[:128] if j_rec.retry_of_id else None,
                        is_child_pipeline_job=candidate.is_child_pipeline_job,
                        child_pipeline_id=(
                            candidate.child_pipeline_id[:128]
                            if candidate.child_pipeline_id
                            else None
                        ),
                        status=j_rec.status,
                        conclusion=j_rec.conclusion,
                        started_at=j_rec.started_at,
                        completed_at=j_rec.completed_at,
                        log_artifact_id=log_art_id,
                        log_status=log_status,
                        log_size_bytes=log_size_bytes,
                        log_truncated=log_truncated,
                        failure_excerpt=failure_excerpt,
                        failure_fingerprint_id=fp_row.id if fp_row is not None else None,
                        failure_fingerprint_hash=(
                            fp_row.fingerprint_hash if fp_row is not None else None
                        ),
                        flaky_classification=flaky_verdict,
                        version=1,
                        created_at=ref_now,
                        updated_at=ref_now,
                    )
                    db.add(job_row)
                else:
                    job_row.status = j_rec.status
                    job_row.conclusion = j_rec.conclusion
                    job_row.started_at = j_rec.started_at
                    job_row.completed_at = j_rec.completed_at
                    job_row.matrix_dimensions_json = clean_dims
                    job_row.retry_of_id = j_rec.retry_of_id[:128] if j_rec.retry_of_id else None
                    job_row.log_artifact_id = log_art_id
                    job_row.log_status = log_status
                    job_row.log_size_bytes = log_size_bytes
                    job_row.log_truncated = log_truncated
                    job_row.failure_excerpt = failure_excerpt
                    job_row.failure_fingerprint_id = fp_row.id if fp_row is not None else None
                    job_row.failure_fingerprint_hash = (
                        fp_row.fingerprint_hash if fp_row is not None else None
                    )
                    job_row.flaky_classification = flaky_verdict
                    job_row.version += 1
                    job_row.updated_at = ref_now
                await db.flush()

                if log_art_id is not None:
                    art_to_bind = await db.scalar(
                        select(ArtifactModel).where(
                            ArtifactModel.workspace_id == workspace_id,
                            ArtifactModel.id == log_art_id,
                        )
                    )
                    if art_to_bind is not None and art_to_bind.job_id is None:
                        art_to_bind.job_id = job_row.id
                        await db.flush()

            # 4. Collect & inspect run artifact archives (`NFR-14`, `SEC-007`, `SEC-036`)
            stored_archive_count = 0
            try:
                provider_artifacts = await adapter.get_artifact_metadata(
                    db,
                    conn_ctx,
                    repo_full_name=repo_row.name,
                    external_run_id=external_run_id,
                    now=ref_now,
                )
            except ProviderError as exc:
                if exc.code in ("TRANSIENT", "RATE_LIMIT", "REVOKED"):
                    raise
                provider_artifacts = ()
                incomplete_reasons.append("artifact_metadata_unavailable")

            archive_access: ArtifactAccessClass = (
                "restricted"
                if repo_row.visibility in ("private", "internal", "unknown")
                else "workspace_internal"
            )

            for p_art in provider_artifacts:
                existing_art = await db.scalar(
                    select(ArtifactModel).where(
                        ArtifactModel.workspace_id == workspace_id,
                        ArtifactModel.run_id == run_row.id,
                        ArtifactModel.external_artifact_id == p_art.external_artifact_id[:128],
                        ArtifactModel.lifecycle_state == "finalized",
                    )
                )
                if existing_art is not None:
                    stored_archive_count += 1
                    continue

                if p_art.expired or (p_art.expires_at is not None and p_art.expires_at <= ref_now):
                    incomplete_reasons.append(f"artifact_expired:{p_art.name[:64]}")
                    continue

                if p_art.size_bytes > self._max_archive_compressed_bytes:
                    incomplete_reasons.append(
                        f"artifact_rejected:archive_compressed_size_exceeded:{p_art.name[:48]}"
                    )
                    await self._record_archive_rejection(
                        db,
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        run_row=run_row,
                        artifact_name=p_art.name,
                        reason_code="archive_compressed_size_exceeded",
                        detail=f"Metadata size {p_art.size_bytes} exceeds cap.",
                        correlation_id=corr_id,
                        now=ref_now,
                    )
                    continue

                try:
                    raw_archive = await adapter.download_artifact_archive(
                        db,
                        conn_ctx,
                        repo_full_name=repo_row.name,
                        external_artifact_id=p_art.external_artifact_id,
                        max_bytes=self._max_archive_compressed_bytes + 1,
                        now=ref_now,
                    )
                except ProviderError as exc:
                    if exc.code in ("TRANSIENT", "RATE_LIMIT", "REVOKED"):
                        raise
                    if exc.status_code == 410:
                        incomplete_reasons.append(f"artifact_expired:{p_art.name[:64]}")
                    else:
                        incomplete_reasons.append(f"artifact_unavailable:{p_art.name[:64]}")
                    continue

                scratch_root = Path(tempfile.mkdtemp(prefix="red2pr_art_inspect_"))
                try:
                    inspection = inspect_and_extract_archive(
                        raw_archive,
                        filename=p_art.name,
                        dest_dir=scratch_root,
                        max_compressed_bytes=self._max_archive_compressed_bytes,
                        max_expanded_bytes=self._max_archive_expanded_bytes,
                        max_files=self._max_archive_files,
                    )
                except ArchiveHazardError as hazard:
                    incomplete_reasons.append(f"artifact_rejected:{hazard.code}:{p_art.name[:48]}")
                    await self._record_archive_rejection(
                        db,
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        run_row=run_row,
                        artifact_name=p_art.name,
                        reason_code=hazard.code,
                        detail=hazard.detail,
                        correlation_id=corr_id,
                        now=ref_now,
                    )
                    continue
                finally:
                    shutil.rmtree(scratch_root, ignore_errors=True)

                mime_type = (
                    "application/zip" if inspection.archive_format == "zip" else "application/x-tar"
                )
                retention_delta = self._artifact_retention_delta
                if p_art.expires_at is not None and p_art.expires_at > ref_now:
                    provider_rem = p_art.expires_at - ref_now
                    if provider_rem < retention_delta:
                        retention_delta = provider_rem

                await persist_encrypted_artifact(
                    db,
                    store=self._artifact_store,
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    name=self._redactor.redact_text(p_art.name)[:120] or "artifact.zip",
                    kind="ci_artifact_archive",
                    mime=mime_type,
                    plaintext=raw_archive,
                    redaction_version=REDACTION_VERSION,
                    access_class=archive_access,
                    retention_delta=retention_delta,
                    run_id=run_row.id,
                    external_artifact_id=p_art.external_artifact_id[:128],
                    extracted_file_count=inspection.extracted_file_count,
                    now=ref_now,
                )
                stored_archive_count += 1

            # 5. Finalize CiRunModel summary & propagate updated flaky classifications to siblings
            run_flaky = summarize_run_flaky_classification(job_flaky_verdicts)
            if not head_sha_verified:
                final_state: CiRunIngestionState = "stale_sha"
            elif incomplete_reasons:
                final_state = "incomplete"
            else:
                final_state = "ingested"

            if live_run.attempt_key != attempt_key and collected_jobs:
                any_running = any(
                    c.record.status in ("queued", "in_progress") for c in collected_jobs
                )
                run_row.status = "in_progress" if any_running else "completed"
                run_row.jobs_complete = not any_running
                if any_running:
                    run_row.conclusion = None
                elif failed_job_count > 0:
                    run_row.conclusion = "failure"
                else:
                    run_row.conclusion = "success"

            run_row.total_job_count = len(collected_jobs)
            run_row.failed_job_count = failed_job_count
            run_row.artifact_count = stored_archive_count
            run_row.child_pipeline_ids_json = child_pipeline_ids
            run_row.flaky_classification = run_flaky
            run_row.ingestion_state = final_state
            run_row.incomplete_reason = (
                "; ".join(incomplete_reasons)[:980] if incomplete_reasons else None
            )
            run_row.started_at = earliest_start
            run_row.completed_at = latest_end
            run_row.updated_at = ref_now

            # Refresh sibling attempts on the same `(repository_id, head_sha)` when a green rerun
            # updates shared fingerprint classifications (e.g. `single_pass_unproven` or `flaky`)
            sibling_runs = list(
                (
                    await db.scalars(
                        select(CiRunModel).where(
                            CiRunModel.workspace_id == workspace_id,
                            CiRunModel.repository_id == repository_id,
                            CiRunModel.head_sha == expected_sha,
                            CiRunModel.id != run_row.id,
                        )
                    )
                ).all()
            )
            for sib in sibling_runs:
                sib_job_classes = [
                    cast(FlakyClassification, c)
                    for c in (
                        await db.scalars(
                            select(CiJobModel.flaky_classification).where(
                                CiJobModel.workspace_id == workspace_id,
                                CiJobModel.run_id == sib.id,
                                CiJobModel.flaky_classification != "unknown",
                            )
                        )
                    ).all()
                ]
                if sib_job_classes:
                    sib.flaky_classification = summarize_run_flaky_classification(sib_job_classes)
                    sib.updated_at = ref_now

            await append_audit_entry(
                db,
                workspace_id=workspace_id,
                actor_type="service",
                actor_id="ci_collector",
                action="ci_run.ingested",
                target=f"ci_run:{run_row.id}",
                decision="allow",
                reason_code=final_state,
                correlation_id=corr_id,
                metadata={
                    "repository_id": repository_id,
                    "repository_mode": repo_row.mode,
                    "external_run_id": external_run_id,
                    "attempt_key": attempt_key,
                    "head_sha": expected_sha,
                    "head_sha_verified": head_sha_verified,
                    "total_job_count": len(collected_jobs),
                    "failed_job_count": failed_job_count,
                    "artifact_count": stored_archive_count,
                    "flaky_classification": run_flaky,
                },
                occurred_at=ref_now,
            )
            await db.flush()
            return ci_run_model_to_dto(run_row, repository_name=repo_row.name)

    async def _record_archive_rejection(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        repository_id: str,
        run_row: CiRunModel,
        artifact_name: str,
        reason_code: str,
        detail: str,
        correlation_id: str,
        now: datetime,
    ) -> None:
        await append_audit_entry(
            db,
            workspace_id=workspace_id,
            actor_type="service",
            actor_id="ci_collector",
            action="security.artifact_archive.rejected",
            target=f"ci_run:{run_row.id}",
            decision="deny",
            reason_code=reason_code[:120],
            correlation_id=correlation_id,
            metadata={
                "artifact_name": self._redactor.redact_text(artifact_name)[:120],
                "detail": self._redactor.redact_text(detail)[:300],
            },
            occurred_at=now,
        )
        await enqueue_outbox_event(
            db,
            EventEnvelope(
                event_id=new_uuid7(now=now),
                type="security.policy.denied",
                occurred_at=now,
                workspace_id=workspace_id,
                repository_id=repository_id,
                aggregate_id=run_row.id,
                aggregate_version=run_row.version,
                correlation_id=correlation_id,
                payload=SecurityIdentityEventPayload(
                    target_id=run_row.id,
                    reason_code=reason_code[:120],
                ),
            ),
            now=now,
        )

    async def process_next_triage_job(
        self,
        *,
        task_queue: DurableTaskQueueService,
        worker_id: str,
        now: datetime | None = None,
    ) -> CiRun | None:
        """Lease & execute the next queued `ci_run.triage` job (`IG-03` end-to-end Wave 2 loop).

        Respects `ADR-033`: repositories in `monitor` mode complete triage/evidence ingestion
        cleanly with zero sandbox execution jobs dispatched.
        """
        ref_now = now.astimezone(UTC) if now is not None else self._clock().astimezone(UTC)
        leased = await task_queue.acquire_next_lease(
            worker_id=worker_id,
            now=ref_now,
            allowed_kinds={"ci_run.triage"},
        )
        if leased is None:
            return None

        job_id = leased.job.id
        lease_epoch = leased.job.lease_epoch
        await task_queue.mark_lease_running(
            job_id=job_id,
            worker_id=worker_id,
            lease_epoch=lease_epoch,
            now=ref_now,
        )

        trigger_id = str(leased.payload.get("trigger_id") or leased.job.resource_id)
        try:
            ingested_run = await self.collect_from_trigger(
                workspace_id=leased.job.workspace_id,
                trigger_id=trigger_id,
                correlation_id=leased.job.correlation_id,
                now=ref_now,
            )
        except ProviderError as exc:
            recoverable = exc.code in ("TRANSIENT", "RATE_LIMIT")
            await task_queue.fail_lease(
                job_id=job_id,
                worker_id=worker_id,
                lease_epoch=lease_epoch,
                error_code=f"provider_{exc.code.lower()}",
                error_detail=exc.detail,
                recoverable=recoverable,
                now=ref_now,
            )
            return None
        except Exception as exc:
            await task_queue.fail_lease(
                job_id=job_id,
                worker_id=worker_id,
                lease_epoch=lease_epoch,
                error_code="ci_triage_failed",
                error_detail=str(exc),
                recoverable=False,
                now=ref_now,
            )
            raise

        await task_queue.complete_lease(
            job_id=job_id,
            worker_id=worker_id,
            lease_epoch=lease_epoch,
            now=ref_now,
        )
        return ingested_run
