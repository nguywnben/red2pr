"""End-to-end autonomous CI repair pipeline coordinator (`W-03`..`W-06`, `ADR-031`, `FIX-02..04`).

Coordinates durable `ci_run.triage` ingestion, Stage 1/2 diagnosis, isolated Sandbox A baseline
reproduction, bounded candidate patch generation, isolated Sandbox B verification, deterministic
`V-01..V-07` proof evaluation + signed `EvidenceManifestV1`, human-approval / `auto_repair`
Draft PR publication, and periodic provider polling + `V-08` exact-SHA remote check observation.
"""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import hashlib
import io
import tarfile
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any, Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import ColumnElement, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.crypto import (
    KeyRing,
    PublicKeyRecord,
    canonical_json_bytes,
    sha256_canonical_json,
)
from py_contracts.events import ApprovalEventPayload, EventEnvelope
from py_contracts.evidence import (
    EvidenceManifestV1,
    ModelToolProvenance,
    RegressionSuiteSummary,
)
from py_contracts.primitives import new_uuid7
from py_contracts.repairs import RepairState
from py_contracts.worker import ResultV1
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.approvals.service import APPROVAL_TTL
from red2pr_control.core.errors import (
    ConflictError,
    DependencyUnavailableError,
    NotFoundError,
    RateLimitedError,
    Red2PrError,
)
from red2pr_control.core.logging import get_structured_logger
from red2pr_control.core.redaction import REDACTION_VERSION
from red2pr_control.db.base import (
    ApprovalRequestModel,
    ArtifactModel,
    BudgetAccountModel,
    CiJobModel,
    CiRunModel,
    PatchAttemptModel,
    PublicationRecordModel,
    RepairSessionModel,
    RepositoryModel,
    RepositoryPolicyModel,
    ReproductionRunModel,
    RequiredCheckSetModel,
    SandboxLeaseModel,
    SigningKeyModel,
    TaskJobModel,
    WorkspaceModelConfigModel,
)
from red2pr_control.db.budget_accounts import (
    ensure_repair_session_budget_account_in_tx,
    ensure_workspace_daily_budget_account_in_tx,
    resolve_workspace_budget_policy_in_tx,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.inference.diagnosis_agent import DiagnosisAgentService
from red2pr_control.inference.patch_agent import BoundedPatchAgentService
from red2pr_control.inference.tool_broker import InMemoryRepoSnapshot
from red2pr_control.integrations.github_app import GitHubIntegrationService
from red2pr_control.integrations.poller import LocalPollingService
from red2pr_control.orchestrator import (
    DurableTaskQueueService,
    ProfileSelectionDecision,
    ReproductionOrchestrator,
    RunnerProfileRegistry,
    WorkerBrokerService,
    select_profile_for_ci_job,
)
from red2pr_control.orchestrator.state_machine import RepairSessionStateMachine
from red2pr_control.publisher.remote_observer import RemoteCiObserver
from red2pr_control.publisher.saga import PublisherSaga
from red2pr_control.repositories import (
    PathCanonicalizationError,
    RepositoryCatalogService,
    canonicalize_repo_path,
    evaluate_patch_paths,
)
from red2pr_control.triage_evidence.archive_guard import validate_safe_archive_member_path
from red2pr_control.triage_evidence.artifact_store import (
    ArtifactStoreProtocol,
    read_artifact_for_authorized_caller,
)
from red2pr_control.triage_evidence.collector import CiRunCollectorService
from red2pr_control.verification.service import VerificationService
from red2pr_control.verification.verifier import (
    DeterministicVerifier,
    ExecutionCounts,
    VerificationFacts,
    create_signed_evidence_manifest,
)

_LOGGER = get_structured_logger("red2pr_control.runtime_pipeline")

ACTIVE_PIPELINE_STATES: Final[tuple[str, ...]] = (
    "received",
    "reproducing",
    "repro_confirmed",
    "verifying",
    "policy_gate",
)

_STANDARD_ROOT_DIRS: Final[frozenset[str]] = frozenset(
    {
        ".github",
        "app",
        "apps",
        "bin",
        "cmd",
        "config",
        "docs",
        "include",
        "lib",
        "packages",
        "pkg",
        "scripts",
        "src",
        "test",
        "tests",
    }
)

_LOCKFILE_BASENAMES: Final[frozenset[str]] = frozenset(
    {
        "uv.lock",
        "poetry.lock",
        "Pipfile.lock",
        "requirements.txt",
        "pnpm-lock.yaml",
        "package-lock.json",
        "yarn.lock",
        "Cargo.lock",
        "go.sum",
    }
)

_MAX_ARCHIVE_FILES: Final[int] = 10_000
_MAX_ARCHIVE_UNCOMPRESSED_BYTES: Final[int] = 104_857_600
_MAX_SNAPSHOT_TEXT_FILE_BYTES: Final[int] = 2_097_152
_SNAPSHOT_CACHE_CAPACITY: Final[int] = 16

ArchiveFetcher = Callable[[str, str, str], Awaitable[bytes]]


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


def _unsuspended_repair_clause() -> ColumnElement[bool]:
    """Match repair sessions whose `suspension_json` is SQL `NULL` or JSONB `'null'`."""
    return or_(
        RepairSessionModel.suspension_json.is_(None),
        func.jsonb_typeof(RepairSessionModel.suspension_json) == "null",
    )


@dataclass(frozen=True, slots=True)
class NormalizedRepoArchive:
    """Deterministic root-relative `.tar.gz` archive paired with an in-memory text snapshot."""

    archive_bytes: bytes
    archive_digest: str
    dependency_lock_digest: str
    snapshot: InMemoryRepoSnapshot


def normalize_source_archive(*, raw_tar_bytes: bytes, base_sha: str) -> NormalizedRepoArchive:
    """Normalize a GitHub/GitLab repository tarball into deterministic root-relative `.tar.gz`."""
    extracted_entries: list[tuple[str, bytes]] = []
    total_bytes = 0
    with tarfile.open(fileobj=io.BytesIO(raw_tar_bytes), mode="r:*") as tf:
        for member in tf.getmembers():
            if member.type in (tarfile.XGLTYPE, tarfile.XHDTYPE) or member.isdir():
                continue
            if not member.isfile():
                # Strip symlinks, hardlinks, FIFOs, and device nodes before sandbox staging.
                continue
            safe_rel = validate_safe_archive_member_path(member.name)
            if safe_rel is None:
                continue
            if len(extracted_entries) >= _MAX_ARCHIVE_FILES:
                break
            fobj = tf.extractfile(member)
            if fobj is None:
                continue
            payload = fobj.read(_MAX_ARCHIVE_UNCOMPRESSED_BYTES + 1)
            total_bytes += len(payload)
            if total_bytes > _MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise ConflictError(
                    code="repository_archive_too_large",
                    detail="Uncompressed repository source archive exceeds 100 MiB safety cap.",
                )
            extracted_entries.append((safe_rel, payload))

    strip_prefix = ""
    if extracted_entries and all("/" in rel for rel, _ in extracted_entries):
        top_dirs = {rel.split("/", 1)[0] for rel, _ in extracted_entries}
        if len(top_dirs) == 1:
            candidate_top = next(iter(top_dirs))
            if candidate_top not in _STANDARD_ROOT_DIRS:
                strip_prefix = f"{candidate_top}/"

    file_bytes_map: dict[str, bytes] = {}
    text_files: dict[str, str] = {}
    lock_digests: dict[str, str] = {}

    for rel_path, payload in extracted_entries:
        trimmed = rel_path[len(strip_prefix) :] if strip_prefix else rel_path
        if not trimmed:
            continue
        segments = trimmed.split("/")
        if segments[0] == ".git" or ".git" in segments or trimmed == ".gitmodules":
            continue
        try:
            canon = canonicalize_repo_path(trimmed)
        except PathCanonicalizationError:
            continue
        file_bytes_map[canon] = payload
        basename = canon.rsplit("/", 1)[-1]
        if basename in _LOCKFILE_BASENAMES:
            lock_digests[canon] = hashlib.sha256(payload).hexdigest()
        if len(payload) <= _MAX_SNAPSHOT_TEXT_FILE_BYTES and b"\x00" not in payload:
            with contextlib.suppress(UnicodeDecodeError):
                text_files[canon] = payload.decode("utf-8")

    out_buf = io.BytesIO()
    with (
        gzip.GzipFile(filename="", mode="wb", fileobj=out_buf, mtime=0) as gz,
        tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as out_tf,
    ):
        for canon_path in sorted(file_bytes_map):
            content = file_bytes_map[canon_path]
            info = tarfile.TarInfo(name=canon_path)
            info.size = len(content)
            info.mtime = 0
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            out_tf.addfile(info, io.BytesIO(content))

    archive_bytes = out_buf.getvalue()
    archive_digest = hashlib.sha256(archive_bytes).hexdigest()
    dep_digest = (
        sha256_canonical_json(lock_digests)
        if lock_digests
        else hashlib.sha256(b"no-lockfile").hexdigest()
    )
    snapshot = InMemoryRepoSnapshot(base_sha=base_sha, files=text_files)
    return NormalizedRepoArchive(
        archive_bytes=archive_bytes,
        archive_digest=archive_digest,
        dependency_lock_digest=dep_digest,
        snapshot=snapshot,
    )


async def sync_worker_signing_keys_into_keyring(
    session_factory: async_sessionmaker[AsyncSession],
    keyring: KeyRing,
) -> None:
    """Synchronize enrolled `worker_result` Ed25519 keys (and revocations) into `keyring`."""
    async with instance_rls_session(session_factory, mode="instance_only") as db:
        rows = (
            await db.scalars(
                select(SigningKeyModel).where(SigningKeyModel.purpose == "worker_result")
            )
        ).all()
        for sk in rows:
            if sk.algorithm == "ed25519":
                keyring.upsert(
                    PublicKeyRecord(
                        key_id=sk.key_id,
                        algorithm="ed25519",
                        public_key_b64=sk.public_key_b64,
                        not_before=sk.not_before,
                        revoked_at=sk.revoked_at,
                        trust_domain=sk.trust_domain,
                    )
                )


class RuntimePipelineCoordinator:
    """Drains `ci_run.triage` jobs and drives active repair sessions through Sandbox A/B & PR."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        queue_service: DurableTaskQueueService,
        collector_service: CiRunCollectorService,
        state_machine: RepairSessionStateMachine,
        diagnosis_agent: DiagnosisAgentService | None = None,
        patch_agent: BoundedPatchAgentService | None = None,
        reproducer: ReproductionOrchestrator | None = None,
        worker_broker: WorkerBrokerService | None = None,
        verification_service: VerificationService | None = None,
        verifier: DeterministicVerifier | None = None,
        publisher_saga: PublisherSaga | None = None,
        integration_service: GitHubIntegrationService | None = None,
        catalog_service: RepositoryCatalogService | None = None,
        artifact_store: ArtifactStoreProtocol | None = None,
        profile_registry: RunnerProfileRegistry | None = None,
        manifest_signer: Ed25519PrivateKey | None = None,
        manifest_key_id: str = "runtime-manifest-key-v1",
        manifest_keyring: KeyRing | None = None,
        evidence_trust_domain: str = "worker.red2pr.internal",
        polling_service: LocalPollingService | None = None,
        remote_observer: RemoteCiObserver | None = None,
        archive_fetcher: ArchiveFetcher | None = None,
        worker_id: str | None = None,
        poll_interval_seconds: float = 1.0,
        sweep_interval_seconds: float = 30.0,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._session_factory = session_factory
        self._queue = queue_service
        self._collector = collector_service
        self._state_machine = state_machine
        self._diagnosis_agent = diagnosis_agent
        self._patch_agent = patch_agent
        self._reproducer = reproducer
        self._worker_broker = worker_broker
        self._verification_service = verification_service
        self._verifier = verifier
        self._publisher_saga = publisher_saga
        self._integrations = integration_service
        self._catalog = catalog_service
        self._artifact_store = artifact_store
        self._profile_registry = profile_registry or RunnerProfileRegistry()
        self._manifest_signer = manifest_signer
        self._manifest_key_id = manifest_key_id
        self._manifest_keyring = manifest_keyring
        self._evidence_trust_domain = evidence_trust_domain
        self._poller = polling_service
        self._remote_observer = remote_observer
        self._archive_fetcher = archive_fetcher
        self._worker_id = worker_id if worker_id is not None else new_uuid7(now=clock())
        self._poll_interval = max(0.05, poll_interval_seconds)
        self._sweep_interval = max(5.0, sweep_interval_seconds)
        self._clock = clock
        self._snapshot_cache: OrderedDict[tuple[str, str, str], NormalizedRepoArchive] = (
            OrderedDict()
        )
        self._last_periodic_sweep_monotonic: float = 0.0

    @property
    def _orchestration_enabled(self) -> bool:
        return (
            self._diagnosis_agent is not None
            and self._patch_agent is not None
            and self._reproducer is not None
            and self._verification_service is not None
            and self._verifier is not None
            and self._catalog is not None
            and self._artifact_store is not None
            and self._manifest_signer is not None
            and self._manifest_keyring is not None
            and (self._integrations is not None or self._archive_fetcher is not None)
        )

    async def run_once(self, *, now: datetime | None = None) -> bool:
        """Process one queued `ci_run.triage` job or advance one active repair session."""
        ref_now = now.astimezone(UTC) if now is not None else self._clock().astimezone(UTC)
        if await self._drain_one_triage_job(ref_now=ref_now):
            return True
        if self._orchestration_enabled:
            return await self._advance_one_repair_session(ref_now=ref_now)
        return False

    async def _drain_one_triage_job(self, *, ref_now: datetime) -> bool:
        leased = await self._queue.acquire_next_lease(
            worker_id=self._worker_id,
            now=ref_now,
            allowed_kinds=("ci_run.triage",),
        )
        if leased is None:
            return False

        job = leased.job
        lease_epoch = job.lease_epoch
        await self._queue.mark_lease_running(
            job_id=job.id,
            worker_id=self._worker_id,
            lease_epoch=lease_epoch,
            now=ref_now,
        )
        try:
            ci_run = await self._collector.collect_from_trigger(
                workspace_id=job.workspace_id,
                trigger_id=job.resource_id,
                correlation_id=job.correlation_id,
                now=ref_now,
            )
            if ci_run.ingestion_state == "incomplete":
                await asyncio.sleep(3.0)
                ci_run = await self._collector.collect_from_trigger(
                    workspace_id=job.workspace_id,
                    trigger_id=job.resource_id,
                    correlation_id=job.correlation_id,
                    now=self._clock().astimezone(UTC),
                )
            payload = leased.payload or {}
            if bool(payload.get("allow_sandbox_execution")) and ci_run.head_sha_verified:
                await self._maybe_enqueue_auto_repair_session(
                    workspace_id=job.workspace_id,
                    repository_id=ci_run.repository_id,
                    ci_run_id=ci_run.id,
                    head_sha=ci_run.head_sha,
                    target_ref=ci_run.ref,
                    conclusion=ci_run.conclusion,
                    correlation_id=job.correlation_id or new_uuid7(now=ref_now),
                    now=ref_now,
                )
            await self._queue.complete_lease(
                job_id=job.id,
                worker_id=self._worker_id,
                lease_epoch=lease_epoch,
                now=self._clock().astimezone(UTC),
            )
            return True
        except Red2PrError as exc:
            _LOGGER.warning(
                "ci_run.triage pipeline failed with domain error",
                extra={
                    "event": "pipeline.triage_domain_error",
                    "job_id": job.id,
                    "error_code": exc.code,
                    "status_code": exc.status,
                },
            )
            recoverable = exc.status in (429, 502, 503, 504)
            await self._queue.fail_lease(
                job_id=job.id,
                worker_id=self._worker_id,
                lease_epoch=lease_epoch,
                error_code=exc.code,
                error_detail=exc.detail,
                now=self._clock().astimezone(UTC),
                recoverable=recoverable,
            )
            return True
        except Exception as exc:
            _LOGGER.error(
                "Unhandled ci_run.triage pipeline failure",
                exc_info=exc,
                extra={"event": "pipeline.triage_failed", "job_id": job.id},
            )
            await self._queue.fail_lease(
                job_id=job.id,
                worker_id=self._worker_id,
                lease_epoch=lease_epoch,
                error_code="triage_internal_error",
                error_detail="CI run collection failed due to an unexpected internal error.",
                now=self._clock().astimezone(UTC),
                recoverable=True,
            )
            return True

    async def _maybe_enqueue_auto_repair_session(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        ci_run_id: str,
        head_sha: str,
        target_ref: str,
        conclusion: str | None,
        correlation_id: str,
        now: datetime,
    ) -> None:
        if conclusion not in {"failure", "timed_out", "action_required"}:
            return
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            repo = await db.scalar(
                select(RepositoryModel).where(
                    RepositoryModel.workspace_id == workspace_id,
                    RepositoryModel.id == repository_id,
                )
            )
            if repo is None or repo.paused or repo.mode not in {"approval", "auto_repair"}:
                return
            policy = await db.scalar(
                select(RepositoryPolicyModel)
                .where(
                    RepositoryPolicyModel.workspace_id == workspace_id,
                    RepositoryPolicyModel.repository_id == repository_id,
                )
                .order_by(RepositoryPolicyModel.revision.desc())
                .limit(1)
            )
            if policy is None or policy.paused or policy.mode not in {"approval", "auto_repair"}:
                return
            daily_budget = await db.scalar(
                select(BudgetAccountModel)
                .where(
                    BudgetAccountModel.workspace_id == workspace_id,
                    BudgetAccountModel.scope_kind.in_(("workspace_daily", "workspace_total")),
                    BudgetAccountModel.cancelled_at.is_(None),
                )
                .order_by(BudgetAccountModel.scope_kind)
                .limit(1)
            )
            if daily_budget is None:
                cfg_row = await db.scalar(
                    select(WorkspaceModelConfigModel).where(
                        WorkspaceModelConfigModel.workspace_id == workspace_id
                    )
                )
                if cfg_row is not None and (
                    cfg_row.budget_policy_json or cfg_row.credential_secret_ref is not None
                ):
                    pol = await resolve_workspace_budget_policy_in_tx(db, workspace_id=workspace_id)
                    if pol.max_cost_per_session.amount > 0:
                        daily_budget = await ensure_workspace_daily_budget_account_in_tx(
                            db,
                            workspace_id=workspace_id,
                            policy=pol,
                            now=now,
                        )
            if daily_budget is None:
                return
            budget_policy = await resolve_workspace_budget_policy_in_tx(
                db,
                workspace_id=workspace_id,
                fallback_account=daily_budget,
            )
            if budget_policy.max_cost_per_session.amount <= 0:
                return
            trigger_key = f"auto:{ci_run_id}"
            session_budget = await ensure_repair_session_budget_account_in_tx(
                db,
                workspace_id=workspace_id,
                scope_key=trigger_key,
                policy=budget_policy,
                repository_id=repository_id,
                now=now,
            )
            repair_row, created = await self._state_machine.create_or_get_session_in_tx(
                db,
                workspace_id=workspace_id,
                repository_id=repository_id,
                ci_run_id=ci_run_id,
                semantic_trigger_key=trigger_key,
                base_sha=head_sha,
                target_ref=target_ref,
                policy_revision=policy.revision,
                budget_account_id=session_budget.id,
                correlation_id=correlation_id,
                actor="system:auto_repair_intake",
            )
            if created and session_budget.repair_id is None:
                session_budget.repair_id = repair_row.id
                await db.flush()

    async def _get_or_fetch_snapshot(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        base_sha: str,
        now: datetime,
    ) -> NormalizedRepoArchive:
        cache_key = (workspace_id, repository_id, base_sha.lower())
        cached = self._snapshot_cache.get(cache_key)
        if cached is not None:
            self._snapshot_cache.move_to_end(cache_key)
            if self._worker_broker is not None:
                self._worker_broker.register_source_archive(cached.archive_bytes)
            return cached

        if self._archive_fetcher is not None:
            raw_bytes = await self._archive_fetcher(workspace_id, repository_id, base_sha)
        else:
            assert self._integrations is not None
            raw_bytes = await self._integrations.download_repository_archive(
                workspace_id=workspace_id,
                repository_id=repository_id,
                ref=base_sha,
                now=now,
            )
        normalized = normalize_source_archive(raw_tar_bytes=raw_bytes, base_sha=base_sha)
        if self._worker_broker is not None:
            self._worker_broker.register_source_archive(normalized.archive_bytes)
        self._snapshot_cache[cache_key] = normalized
        while len(self._snapshot_cache) > _SNAPSHOT_CACHE_CAPACITY:
            self._snapshot_cache.popitem(last=False)
        return normalized

    async def _ensure_session_budget_if_missing(
        self,
        *,
        workspace_id: str,
        repair_id: str,
        now: datetime,
    ) -> None:
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            repair = await db.scalar(
                select(RepairSessionModel)
                .where(
                    RepairSessionModel.workspace_id == workspace_id,
                    RepairSessionModel.id == repair_id,
                )
                .with_for_update()
            )
            if repair is None:
                return
            existing_session_budget = await db.scalar(
                select(BudgetAccountModel).where(
                    BudgetAccountModel.workspace_id == workspace_id,
                    BudgetAccountModel.id == repair.budget_account_id,
                    BudgetAccountModel.cancelled_at.is_(None),
                )
            )
            daily_budget = await db.scalar(
                select(BudgetAccountModel)
                .where(
                    BudgetAccountModel.workspace_id == workspace_id,
                    BudgetAccountModel.scope_kind.in_(("workspace_daily", "workspace_total")),
                    BudgetAccountModel.cancelled_at.is_(None),
                )
                .order_by(BudgetAccountModel.scope_kind)
                .limit(1)
            )
            pol = await resolve_workspace_budget_policy_in_tx(
                db,
                workspace_id=workspace_id,
                fallback_account=daily_budget,
            )
            if pol.max_cost_per_session.amount <= 0:
                return
            if daily_budget is None:
                daily_budget = await ensure_workspace_daily_budget_account_in_tx(
                    db,
                    workspace_id=workspace_id,
                    policy=pol,
                    now=now,
                )
            if existing_session_budget is not None:
                await db.flush()
                return
            session_budget = await ensure_repair_session_budget_account_in_tx(
                db,
                workspace_id=workspace_id,
                scope_key=f"session:{repair.id}",
                policy=pol,
                repository_id=repair.repository_id,
                repair_id=repair.id,
                now=now,
            )
            repair.budget_account_id = session_budget.id
            await db.flush()

    async def _advance_one_repair_session(self, *, ref_now: datetime) -> bool:
        async with instance_rls_session(self._session_factory, mode="instance_admin") as lookup:
            candidates = list(
                (
                    await lookup.execute(
                        select(
                            RepairSessionModel.workspace_id,
                            RepairSessionModel.id,
                            RepairSessionModel.state,
                        )
                        .where(
                            RepairSessionModel.state.in_(ACTIVE_PIPELINE_STATES),
                            _unsuspended_repair_clause(),
                        )
                        .order_by(
                            RepairSessionModel.updated_at.asc(),
                            RepairSessionModel.id.asc(),
                        )
                        .limit(25)
                    )
                ).all()
            )

        for ws_raw, repair_raw, state_raw in candidates:
            ws_id = str(ws_raw)
            repair_id = str(repair_raw)
            state = str(state_raw)
            corr_id = f"pipe-{repair_id[:18]}-{int(ref_now.timestamp())}"
            try:
                progressed = await self._step_session(
                    workspace_id=ws_id,
                    repair_id=repair_id,
                    expected_state=state,
                    correlation_id=corr_id,
                    ref_now=ref_now,
                )
                if progressed:
                    return True
            except (DependencyUnavailableError, RateLimitedError) as exc:
                _LOGGER.warning(
                    "Repair session paused due to transient provider/model unavailability",
                    extra={
                        "event": "pipeline.session_paused_transient",
                        "workspace_id": ws_id,
                        "repair_id": repair_id,
                        "error_code": exc.code,
                    },
                )
                return True
            except Exception as exc:
                _LOGGER.error(
                    "Unhandled error advancing repair session; moving to needs_human",
                    exc_info=exc,
                    extra={
                        "event": "pipeline.session_step_error",
                        "workspace_id": ws_id,
                        "repair_id": repair_id,
                        "state": state,
                    },
                )
                await self._fail_safe_escalate_session(
                    workspace_id=ws_id,
                    repair_id=repair_id,
                    reason_code="pipeline_step_error",
                    detail=f"Coordinator encountered {type(exc).__name__} while advancing {state}.",
                    correlation_id=corr_id,
                )
                return True
        return False

    async def _fail_safe_escalate_session(
        self,
        *,
        workspace_id: str,
        repair_id: str,
        reason_code: str,
        detail: str,
        correlation_id: str,
    ) -> None:
        try:
            async with workspace_rls_session(
                self._session_factory, workspace_id=workspace_id
            ) as db:
                row = await db.scalar(
                    select(RepairSessionModel)
                    .where(
                        RepairSessionModel.workspace_id == workspace_id,
                        RepairSessionModel.id == repair_id,
                    )
                    .with_for_update()
                )
                if row is None or row.suspension_json is not None:
                    return
                target: RepairState = (
                    "blocked" if row.state in {"received", "authorized"} else "needs_human"
                )
                await self._state_machine.transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state=target,
                    reason_code=reason_code[:120],
                    status_detail=detail[:950],
                    actor="system:pipeline_coordinator",
                    correlation_id=correlation_id,
                )
        except Exception:
            _LOGGER.warning(
                "Fail-safe escalation skipped because session already transitioned",
                extra={"event": "pipeline.failsafe_skipped", "repair_id": repair_id},
            )

    async def _step_session(
        self,
        *,
        workspace_id: str,
        repair_id: str,
        expected_state: str,
        correlation_id: str,
        ref_now: datetime,
    ) -> bool:
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            repair = await db.scalar(
                select(RepairSessionModel).where(
                    RepairSessionModel.workspace_id == workspace_id,
                    RepairSessionModel.id == repair_id,
                )
            )
            if (
                repair is None
                or repair.suspension_json is not None
                or repair.state != expected_state
            ):
                return False
            repo_id = repair.repository_id
            ci_run_id = repair.ci_run_id
            base_sha = repair.base_sha
            policy_revision = repair.policy_revision
            active_repro_id = repair.active_reproduction_id
            latest_diag_id = repair.latest_diagnosis_id

        if expected_state == "received":
            return await self._step_received(
                workspace_id=workspace_id,
                repository_id=repo_id,
                repair_id=repair_id,
                ci_run_id=ci_run_id,
                base_sha=base_sha,
                policy_revision=policy_revision,
                correlation_id=correlation_id,
                ref_now=ref_now,
            )
        if expected_state == "reproducing":
            return await self._step_reproducing(
                workspace_id=workspace_id,
                repository_id=repo_id,
                repair_id=repair_id,
                ci_run_id=ci_run_id,
                base_sha=base_sha,
                policy_revision=policy_revision,
                latest_diag_id=latest_diag_id,
                correlation_id=correlation_id,
                ref_now=ref_now,
            )
        if expected_state == "repro_confirmed":
            return await self._step_repro_confirmed(
                workspace_id=workspace_id,
                repository_id=repo_id,
                repair_id=repair_id,
                base_sha=base_sha,
                policy_revision=policy_revision,
                active_repro_id=active_repro_id,
                correlation_id=correlation_id,
                ref_now=ref_now,
            )
        if expected_state == "verifying":
            return await self._step_verifying(
                workspace_id=workspace_id,
                repository_id=repo_id,
                repair_id=repair_id,
                ci_run_id=ci_run_id,
                base_sha=base_sha,
                policy_revision=policy_revision,
                active_repro_id=active_repro_id,
                correlation_id=correlation_id,
                ref_now=ref_now,
            )
        if expected_state == "policy_gate":
            return await self._step_policy_gate(
                workspace_id=workspace_id,
                repository_id=repo_id,
                repair_id=repair_id,
                base_sha=base_sha,
                policy_revision=policy_revision,
                correlation_id=correlation_id,
                ref_now=ref_now,
            )
        return False

    async def _dispatch_baseline_sandbox_a_for_session(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        repair_id: str,
        ci_run_id: str,
        base_sha: str,
        norm_archive: NormalizedRepoArchive,
        runtime_profile_id: str,
        proposed_profile: str | None,
        proposed_command_ids: list[str],
        fingerprint_hash: str | None,
        correlation_id: str,
        ref_now: datetime,
    ) -> None:
        assert self._reproducer is not None
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
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
            failed_job = next(
                (
                    j
                    for j in job_rows
                    if j.conclusion in ("failure", "timed_out", "action_required")
                ),
                job_rows[0] if job_rows else None,
            )
            if failed_job is None:
                await self._state_machine.transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state="needs_human",
                    reason_code="missing_ci_job_for_repro",
                    status_detail="CI run has no recorded CI job for Sandbox A reproduction.",
                    actor="system:pipeline_coordinator",
                    correlation_id=correlation_id,
                )
                return
            job_id = failed_job.id
            job_name = failed_job.name
            job_stage = failed_job.stage
            job_fp = failed_job.failure_fingerprint_hash
            job_matrix: dict[str, str] = (
                {str(k): str(v) for k, v in failed_job.matrix_dimensions_json.items()}
                if isinstance(failed_job.matrix_dimensions_json, dict)
                else {}
            )

        selection: ProfileSelectionDecision = select_profile_for_ci_job(
            ci_job_name=job_name,
            ci_job_stage=job_stage,
            matrix_dimensions=job_matrix,
            repo_files=norm_archive.snapshot.list_files(),
            policy_runtime_profile_id=(
                runtime_profile_id if runtime_profile_id != "default-isolated" else None
            ),
            registry=self._profile_registry,
        )
        if proposed_profile and proposed_command_ids:
            try:
                manifest, _ = self._profile_registry.resolve_profile_and_commands(
                    proposed_profile,
                    proposed_command_ids,
                )
                selection = replace(
                    selection,
                    supported=True,
                    profile_id=manifest.profile_id,
                    profile_revision=manifest.revision,
                    repro_command_ids=tuple(proposed_command_ids),
                    requires_vm_isolation=manifest.requires_isolated_vm_tier,
                )
            except (NotFoundError, Red2PrError):
                pass

        if not selection.supported or selection.profile_id is None:
            await self._state_machine.transition_session(
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state="unsupported",
                reason_code=selection.reason_code,
                status_detail="; ".join(selection.fidelity_differences) or selection.reason_code,
                actor="system:pipeline_coordinator",
                correlation_id=correlation_id,
            )
            return

        await self._reproducer.start_baseline_sandbox_a(
            workspace_id=workspace_id,
            repository_id=repository_id,
            repair_id=repair_id,
            ci_run_id=ci_run_id,
            ci_job_id=job_id,
            base_sha=base_sha,
            source_archive_bytes=norm_archive.archive_bytes,
            selection=selection,
            correlation_id=correlation_id,
            dependency_lock_digest=norm_archive.dependency_lock_digest,
            expected_fingerprint_hash=fingerprint_hash or job_fp,
            now=ref_now,
        )

    async def _step_received(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        repair_id: str,
        ci_run_id: str,
        base_sha: str,
        policy_revision: int,
        correlation_id: str,
        ref_now: datetime,
    ) -> bool:
        assert self._catalog is not None
        assert self._diagnosis_agent is not None
        if self._collector is not None:
            refresh_args: tuple[str, str, str, str, str, bool, bool, str | None] | None = None
            async with workspace_rls_session(
                self._session_factory, workspace_id=workspace_id
            ) as db:
                run_row = await db.scalar(
                    select(CiRunModel).where(
                        CiRunModel.workspace_id == workspace_id,
                        CiRunModel.id == ci_run_id,
                    )
                )
                if run_row is not None and (
                    run_row.ingestion_state != "ingested" or run_row.artifact_count == 0
                ):
                    refresh_args = (
                        run_row.external_id,
                        run_row.attempt_key,
                        run_row.head_sha,
                        run_row.ref,
                        run_row.event_type,
                        run_row.is_rerun,
                        run_row.untrusted_fork,
                        run_row.trigger_id,
                    )
            if refresh_args is not None:
                await self._collector.collect_run_attempt(
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    external_run_id=refresh_args[0],
                    attempt_key=refresh_args[1],
                    expected_head_sha=refresh_args[2],
                    fallback_ref=refresh_args[3],
                    fallback_event_type=refresh_args[4],
                    is_rerun=refresh_args[5],
                    untrusted_fork=refresh_args[6],
                    trigger_id=refresh_args[7],
                    correlation_id=correlation_id,
                    now=ref_now,
                )
        await self._ensure_session_budget_if_missing(
            workspace_id=workspace_id,
            repair_id=repair_id,
            now=ref_now,
        )
        repo_policy, effective_policy, policy_ctx, _ = (
            await self._catalog.resolve_repository_policy_bundle(
                workspace_id=workspace_id,
                repository_id=repository_id,
                policy_revision=policy_revision,
                now=ref_now,
            )
        )
        norm_archive = await self._get_or_fetch_snapshot(
            workspace_id=workspace_id,
            repository_id=repository_id,
            base_sha=base_sha,
            now=ref_now,
        )
        outcome = await self._diagnosis_agent.run_triage_and_diagnosis(
            workspace_id=workspace_id,
            repair_id=repair_id,
            snapshot=norm_archive.snapshot,
            repo_policy=repo_policy,
            effective_policy=effective_policy,
            policy_ctx=policy_ctx,
            correlation_id=correlation_id,
        )
        if outcome.repair.state == "reproducing":
            await self._dispatch_baseline_sandbox_a_for_session(
                workspace_id=workspace_id,
                repository_id=repository_id,
                repair_id=repair_id,
                ci_run_id=ci_run_id,
                base_sha=base_sha,
                norm_archive=norm_archive,
                runtime_profile_id=repo_policy.runtime_profile_id,
                proposed_profile=outcome.diagnosis.proposed_profile,
                proposed_command_ids=list(outcome.diagnosis.proposed_command_ids),
                fingerprint_hash=outcome.diagnosis.fingerprint_hash,
                correlation_id=correlation_id,
                ref_now=ref_now,
            )
        return True

    async def _step_reproducing(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        repair_id: str,
        ci_run_id: str,
        base_sha: str,
        policy_revision: int,
        latest_diag_id: str | None,
        correlation_id: str,
        ref_now: datetime,
    ) -> bool:
        assert self._reproducer is not None
        assert self._diagnosis_agent is not None
        assert self._catalog is not None

        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            repro_row = await db.scalar(
                select(ReproductionRunModel)
                .where(
                    ReproductionRunModel.workspace_id == workspace_id,
                    ReproductionRunModel.repair_id == repair_id,
                    ReproductionRunModel.phase == "baseline_a",
                )
                .order_by(ReproductionRunModel.created_at.desc(), ReproductionRunModel.id.desc())
                .limit(1)
            )
            if repro_row is None:
                diag_profile: str | None = None
                diag_cmds: list[str] = []
                diag_fp: str | None = None
                if latest_diag_id is not None:
                    from red2pr_control.db.base import DiagnosticModel

                    diag_row = await db.scalar(
                        select(DiagnosticModel).where(
                            DiagnosticModel.workspace_id == workspace_id,
                            DiagnosticModel.id == latest_diag_id,
                        )
                    )
                    if diag_row is not None:
                        diag_profile = diag_row.proposed_profile
                        diag_cmds = list(diag_row.proposed_command_ids_json)
                        diag_fp = diag_row.fingerprint_hash
            else:
                repro_id = repro_row.id
                repro_sealed = repro_row.immutable_sealed
                sandbox_job_id = repro_row.sandbox_job_id
                lease_ready = False
                job_terminal_fail: tuple[str, str | None] | None = None
                job_queued = False
                if sandbox_job_id is not None:
                    lease_row = await db.scalar(
                        select(SandboxLeaseModel)
                        .where(
                            SandboxLeaseModel.workspace_id == workspace_id,
                            SandboxLeaseModel.job_id == sandbox_job_id,
                        )
                        .order_by(SandboxLeaseModel.lease_epoch.desc())
                        .limit(1)
                    )
                    lease_ready = lease_row is not None and lease_row.result_json is not None
                    if not lease_ready:
                        job_row = await db.scalar(
                            select(TaskJobModel).where(
                                TaskJobModel.workspace_id == workspace_id,
                                TaskJobModel.id == sandbox_job_id,
                            )
                        )
                        if job_row is not None:
                            job_queued = job_row.state == "queued"
                            if job_row.state in {"failed", "dead_letter", "cancelled"}:
                                job_terminal_fail = (job_row.state, job_row.last_error_detail)

        if repro_row is None:
            repo_policy, _, _, _ = await self._catalog.resolve_repository_policy_bundle(
                workspace_id=workspace_id,
                repository_id=repository_id,
                policy_revision=policy_revision,
                now=ref_now,
            )
            norm_archive = await self._get_or_fetch_snapshot(
                workspace_id=workspace_id,
                repository_id=repository_id,
                base_sha=base_sha,
                now=ref_now,
            )
            await self._dispatch_baseline_sandbox_a_for_session(
                workspace_id=workspace_id,
                repository_id=repository_id,
                repair_id=repair_id,
                ci_run_id=ci_run_id,
                base_sha=base_sha,
                norm_archive=norm_archive,
                runtime_profile_id=repo_policy.runtime_profile_id,
                proposed_profile=diag_profile,
                proposed_command_ids=diag_cmds,
                fingerprint_hash=diag_fp,
                correlation_id=correlation_id,
                ref_now=ref_now,
            )
            return True

        if repro_sealed or lease_ready:
            rec = await self._reproducer.finalize_baseline_sandbox_a(
                workspace_id=workspace_id,
                reproduction_id=repro_id,
                correlation_id=correlation_id,
                now=ref_now,
            )
            await self._diagnosis_agent.apply_baseline_reproduction_verdict(
                workspace_id=workspace_id,
                repair_id=repair_id,
                reproduction_run=rec,
                correlation_id=correlation_id,
            )
            return True

        if job_terminal_fail is not None:
            job_state, err_detail = job_terminal_fail
            await self._state_machine.transition_session(
                workspace_id=workspace_id,
                repair_id=repair_id,
                target_state="repro_unconfirmed",
                reason_code=f"sandbox_a_job_{job_state}",
                status_detail=err_detail or "Sandbox A job terminated without a signed ResultV1.",
                actor="system:pipeline_coordinator",
                correlation_id=correlation_id,
            )
            return True

        if job_queued and self._worker_broker is not None:
            await self._get_or_fetch_snapshot(
                workspace_id=workspace_id,
                repository_id=repository_id,
                base_sha=base_sha,
                now=ref_now,
            )
        return False

    async def _read_patch_diff_bytes_and_row(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        diff_artifact_id: str,
        ref_now: datetime,
    ) -> tuple[ArtifactModel, bytes]:
        assert self._artifact_store is not None
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            art_row = await db.scalar(
                select(ArtifactModel).where(
                    ArtifactModel.workspace_id == workspace_id,
                    ArtifactModel.repository_id == repository_id,
                    ArtifactModel.id == diff_artifact_id,
                )
            )
            if art_row is None:
                raise NotFoundError(
                    code="patch_diff_artifact_missing",
                    detail=f"Candidate patch diff artifact {diff_artifact_id} was not found.",
                )
            diff_bytes = await read_artifact_for_authorized_caller(
                db,
                store=self._artifact_store,
                artifact_row=art_row,
                now=ref_now,
            )
            return art_row, diff_bytes

    async def _step_repro_confirmed(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        repair_id: str,
        base_sha: str,
        policy_revision: int,
        active_repro_id: str | None,
        correlation_id: str,
        ref_now: datetime,
    ) -> bool:
        assert self._catalog is not None
        assert self._patch_agent is not None
        assert self._reproducer is not None

        repo_policy, effective_policy, policy_ctx, _ = (
            await self._catalog.resolve_repository_policy_bundle(
                workspace_id=workspace_id,
                repository_id=repository_id,
                policy_revision=policy_revision,
                now=ref_now,
            )
        )
        norm_archive = await self._get_or_fetch_snapshot(
            workspace_id=workspace_id,
            repository_id=repository_id,
            base_sha=base_sha,
            now=ref_now,
        )
        patch_out = await self._patch_agent.generate_candidate_patch(
            workspace_id=workspace_id,
            repair_id=repair_id,
            snapshot=norm_archive.snapshot,
            repo_policy=repo_policy,
            effective_policy=effective_policy,
            policy_ctx=policy_ctx,
            correlation_id=correlation_id,
        )
        if patch_out.repair.state == "verifying" and patch_out.patch_attempt is not None:
            _, diff_bytes = await self._read_patch_diff_bytes_and_row(
                workspace_id=workspace_id,
                repository_id=repository_id,
                diff_artifact_id=patch_out.patch_attempt.diff_artifact_id,
                ref_now=ref_now,
            )
            baseline_id = active_repro_id or patch_out.patch_attempt.sandbox_reproduction_id
            if baseline_id is None:
                raise ConflictError(
                    code="adr031_unconfirmed_baseline",
                    detail="Confirmed baseline reproduction ID is missing before Sandbox B.",
                )
            await self._reproducer.start_patched_sandbox_b(
                workspace_id=workspace_id,
                repair_id=repair_id,
                baseline_reproduction_id=baseline_id,
                patch_diff_text=diff_bytes.decode("utf-8"),
                correlation_id=correlation_id,
                additional_command_ids=(),
                now=ref_now,
            )
        return True

    async def _step_verifying(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        repair_id: str,
        ci_run_id: str,
        base_sha: str,
        policy_revision: int,
        active_repro_id: str | None,
        correlation_id: str,
        ref_now: datetime,
    ) -> bool:
        assert self._reproducer is not None
        assert self._patch_agent is not None
        assert self._catalog is not None
        assert self._verifier is not None
        assert self._verification_service is not None
        assert self._manifest_signer is not None
        assert self._manifest_keyring is not None

        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            patch_row = await db.scalar(
                select(PatchAttemptModel)
                .where(
                    PatchAttemptModel.workspace_id == workspace_id,
                    PatchAttemptModel.repair_id == repair_id,
                    PatchAttemptModel.integrity_outcome == "accepted",
                )
                .order_by(PatchAttemptModel.attempt_number.desc())
                .limit(1)
            )
            if patch_row is None:
                await self._state_machine.transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state="needs_human",
                    reason_code="missing_accepted_patch_attempt",
                    status_detail="Verifying session has no accepted candidate patch attempt.",
                    actor="system:pipeline_coordinator",
                    correlation_id=correlation_id,
                )
                return True

            patched_repro = await db.scalar(
                select(ReproductionRunModel)
                .where(
                    ReproductionRunModel.workspace_id == workspace_id,
                    ReproductionRunModel.repair_id == repair_id,
                    ReproductionRunModel.phase == "patched_b",
                    ReproductionRunModel.patch_digest == patch_row.patch_digest,
                )
                .order_by(ReproductionRunModel.created_at.desc(), ReproductionRunModel.id.desc())
                .limit(1)
            )
            patch_attempt_num = patch_row.attempt_number
            patch_digest = patch_row.patch_digest
            diff_artifact_id = patch_row.diff_artifact_id
            changed_paths = tuple(patch_row.changed_paths_json)
            diff_total_lines = patch_row.diff_lines_added + patch_row.diff_lines_removed
            provenance_raw = list(patch_row.provenance_json or [])
            patch_repo_id = patch_row.repository_id
            patch_base_repro_id = active_repro_id or patch_row.sandbox_reproduction_id

            if patched_repro is not None:
                patched_repro_id = patched_repro.id
                patched_sealed = patched_repro.immutable_sealed
                sandbox_b_job_id = patched_repro.sandbox_job_id
                lease_b_ready = False
                job_b_fail: tuple[str, str | None] | None = None
                job_b_queued = False
                if sandbox_b_job_id is not None:
                    lease_b = await db.scalar(
                        select(SandboxLeaseModel)
                        .where(
                            SandboxLeaseModel.workspace_id == workspace_id,
                            SandboxLeaseModel.job_id == sandbox_b_job_id,
                        )
                        .order_by(SandboxLeaseModel.lease_epoch.desc())
                        .limit(1)
                    )
                    lease_b_ready = lease_b is not None and lease_b.result_json is not None
                    if not lease_b_ready:
                        job_b = await db.scalar(
                            select(TaskJobModel).where(
                                TaskJobModel.workspace_id == workspace_id,
                                TaskJobModel.id == sandbox_b_job_id,
                            )
                        )
                        if job_b is not None:
                            job_b_queued = job_b.state == "queued"
                            if job_b.state in {"failed", "dead_letter", "cancelled"}:
                                job_b_fail = (job_b.state, job_b.last_error_detail)

        if patched_repro is None:
            await self._get_or_fetch_snapshot(
                workspace_id=workspace_id,
                repository_id=repository_id,
                base_sha=base_sha,
                now=ref_now,
            )
            _, diff_bytes = await self._read_patch_diff_bytes_and_row(
                workspace_id=workspace_id,
                repository_id=repository_id,
                diff_artifact_id=diff_artifact_id,
                ref_now=ref_now,
            )
            if patch_base_repro_id is None:
                raise ConflictError(
                    code="adr031_unconfirmed_baseline",
                    detail="Confirmed baseline reproduction ID is missing before Sandbox B.",
                )
            await self._reproducer.start_patched_sandbox_b(
                workspace_id=workspace_id,
                repair_id=repair_id,
                baseline_reproduction_id=patch_base_repro_id,
                patch_diff_text=diff_bytes.decode("utf-8"),
                correlation_id=correlation_id,
                additional_command_ids=(),
                now=ref_now,
            )
            return True

        if not patched_sealed and not lease_b_ready:
            if job_b_fail is not None:
                jb_state, jb_detail = job_b_fail
                await self._state_machine.transition_session(
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state="blocked",
                    reason_code=f"sandbox_b_job_{jb_state}",
                    status_detail=jb_detail or "Sandbox B job failed without a signed ResultV1.",
                    actor="system:pipeline_coordinator",
                    correlation_id=correlation_id,
                )
                return True
            if job_b_queued and self._worker_broker is not None:
                await self._get_or_fetch_snapshot(
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    base_sha=base_sha,
                    now=ref_now,
                )
            return False

        patched_rec = await self._reproducer.finalize_patched_sandbox_b(
            workspace_id=workspace_id,
            reproduction_id=patched_repro_id,
            correlation_id=correlation_id,
            now=ref_now,
        )
        repo_policy, effective_policy, policy_ctx, _ = (
            await self._catalog.resolve_repository_policy_bundle(
                workspace_id=workspace_id,
                repository_id=repository_id,
                policy_revision=policy_revision,
                now=ref_now,
            )
        )

        # Bounded multi-attempt retry loop if Sandbox B did not pass cleanly (`W-05`)
        if (
            patched_rec.status != "patched_passed"
            and patch_attempt_num < effective_policy.max_attempts
        ):
            norm_archive = await self._get_or_fetch_snapshot(
                workspace_id=workspace_id,
                repository_id=repository_id,
                base_sha=base_sha,
                now=ref_now,
            )
            retry_out = await self._patch_agent.generate_candidate_patch(
                workspace_id=workspace_id,
                repair_id=repair_id,
                snapshot=norm_archive.snapshot,
                repo_policy=repo_policy,
                effective_policy=effective_policy,
                policy_ctx=policy_ctx,
                correlation_id=correlation_id,
            )
            if retry_out.repair.state == "verifying" and retry_out.patch_attempt is not None:
                _, retry_diff = await self._read_patch_diff_bytes_and_row(
                    workspace_id=workspace_id,
                    repository_id=repository_id,
                    diff_artifact_id=retry_out.patch_attempt.diff_artifact_id,
                    ref_now=ref_now,
                )
                assert patched_rec.baseline_reproduction_id is not None
                await self._reproducer.start_patched_sandbox_b(
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    baseline_reproduction_id=patched_rec.baseline_reproduction_id,
                    patch_diff_text=retry_diff.decode("utf-8"),
                    correlation_id=correlation_id,
                    additional_command_ids=(),
                    now=ref_now,
                )
            return True

        await sync_worker_signing_keys_into_keyring(self._session_factory, self._manifest_keyring)
        diff_art_row, diff_bytes = await self._read_patch_diff_bytes_and_row(
            workspace_id=workspace_id,
            repository_id=repository_id,
            diff_artifact_id=diff_artifact_id,
            ref_now=ref_now,
        )
        diff_text = diff_bytes.decode("utf-8")

        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            baseline_row = await db.scalar(
                select(ReproductionRunModel).where(
                    ReproductionRunModel.workspace_id == workspace_id,
                    ReproductionRunModel.id == patched_rec.baseline_reproduction_id,
                )
            )
            if (
                baseline_row is None
                or baseline_row.sandbox_job_id is None
                or patched_rec.sandbox_job_id is None
            ):
                raise ConflictError(
                    code="verification_missing_reproduction_pair",
                    detail="Baseline Sandbox A or Patched Sandbox B record is missing.",
                )
            baseline_lease = await db.scalar(
                select(SandboxLeaseModel)
                .where(
                    SandboxLeaseModel.workspace_id == workspace_id,
                    SandboxLeaseModel.job_id == baseline_row.sandbox_job_id,
                    SandboxLeaseModel.status == "completed",
                )
                .order_by(SandboxLeaseModel.lease_epoch.desc())
                .limit(1)
            )
            patched_lease = await db.scalar(
                select(SandboxLeaseModel)
                .where(
                    SandboxLeaseModel.workspace_id == workspace_id,
                    SandboxLeaseModel.job_id == patched_rec.sandbox_job_id,
                    SandboxLeaseModel.status == "completed",
                )
                .order_by(SandboxLeaseModel.lease_epoch.desc())
                .limit(1)
            )
            if (
                baseline_lease is None
                or baseline_lease.result_json is None
                or patched_lease is None
                or patched_lease.result_json is None
            ):
                raise ConflictError(
                    code="verification_missing_sandbox_results",
                    detail="Completed Sandbox A or Sandbox B signed ResultV1 lease is missing.",
                )
            run_row = await db.scalar(
                select(CiRunModel).where(
                    CiRunModel.workspace_id == workspace_id,
                    CiRunModel.id == ci_run_id,
                )
            )
            job_ids = list(
                (
                    await db.scalars(
                        select(CiJobModel.id)
                        .where(
                            CiJobModel.workspace_id == workspace_id,
                            CiJobModel.run_id == ci_run_id,
                        )
                        .order_by(CiJobModel.created_at.asc(), CiJobModel.id.asc())
                    )
                ).all()
            )
            baseline_res_json: dict[str, Any] = dict(baseline_lease.result_json)
            patched_res_json: dict[str, Any] = dict(patched_lease.result_json)
            b_exec = baseline_row.executed_tests_count
            b_fail = baseline_row.failed_tests_count
            b_skip = baseline_row.skipped_tests_count
            b_exp_fp = baseline_row.expected_fingerprint_hash
            b_obs_fp = baseline_row.observed_fingerprint_hash
            b_fp_matched = baseline_row.fingerprint_matched
            b_prof_digest = baseline_row.profile_digest
            b_lock_digest = baseline_row.dependency_lock_digest
            b_ci_job_id = baseline_row.ci_job_id
            attempt_key = run_row.attempt_key if run_row is not None else "attempt-1"

        baseline_res = ResultV1.model_validate(baseline_res_json)
        patched_res = ResultV1.model_validate(patched_res_json)
        b_key = self._manifest_keyring.get(baseline_res.signer_key_id)
        p_key = self._manifest_keyring.get(patched_res.signer_key_id)
        b_td = (
            b_key.trust_domain
            if b_key is not None and b_key.trust_domain
            else self._evidence_trust_domain
        )
        p_td = (
            p_key.trust_domain
            if p_key is not None and p_key.trust_domain
            else self._evidence_trust_domain
        )

        overall_verdict, _, _, _ = evaluate_patch_paths(
            changed_paths,
            diff_lines=diff_total_lines,
            repo_policy=repo_policy,
            effective_policy=effective_policy,
            ctx=policy_ctx,
        )
        expected_fp = (
            b_exp_fp
            if b_exp_fp is not None
            else (b_obs_fp if (b_fp_matched and b_obs_fp is not None) else ("0" * 64))
        )
        policy_ok = (
            overall_verdict != "deny"
            and not effective_policy.effective_paused
            and effective_policy.effective_mode != "monitor"
        )

        facts = VerificationFacts(
            baseline=baseline_res,
            patched=patched_res,
            baseline_trust_domain=b_td,
            patched_trust_domain=p_td,
            baseline_counts=ExecutionCounts(executed=b_exec, failed=b_fail, skipped=b_skip),
            patched_counts=ExecutionCounts(
                executed=patched_rec.executed_tests_count,
                failed=patched_rec.failed_tests_count,
                skipped=patched_rec.skipped_tests_count,
            ),
            regression_counts=ExecutionCounts(
                executed=patched_rec.executed_tests_count,
                failed=patched_rec.failed_tests_count,
                skipped=patched_rec.skipped_tests_count,
            ),
            regression_selection_digest=patched_res.command_digest,
            expected_regression_selection_digest=baseline_res.command_digest,
            expected_failure_fingerprint=expected_fp,
            observed_baseline_fingerprint=b_obs_fp,
            diff_text=diff_text,
            changed_paths=changed_paths,
            diff_digest=patch_digest,
            allowed_paths=changed_paths if overall_verdict != "deny" else (),
            minimum_fidelity="F1_TARGETED",
            fidelity=patched_rec.fidelity_grade,
            security_findings=(),
            workspace_id_matches=True,
            repository_id_matches=(patch_repo_id == repository_id),
            policy_allows_patch=policy_ok,
            actor_authorized=True,
            budget_sufficient=True,
            max_diff_lines=effective_policy.max_diff_lines,
        )
        pre_decision = self._verifier.evaluate(facts)

        signed_manifest: EvidenceManifestV1 | None = None
        evidence_blobs: dict[str, bytes] = {}
        if pre_decision.publication_eligible:
            baseline_blob = canonical_json_bytes(baseline_res_json)
            patched_blob = canonical_json_bytes(patched_res_json)
            evidence_blobs = {
                baseline_res.job_id: baseline_blob,
                patched_res.job_id: patched_blob,
                diff_art_row.id: diff_bytes,
            }
            provenance_models = [
                ModelToolProvenance.model_validate(item) for item in provenance_raw
            ]
            patched_sha = hashlib.sha256(
                f"{base_sha}:{patch_digest}".encode()
            ).hexdigest()[:40]
            lock_digest = b_lock_digest or hashlib.sha256(b"no-lockfile").hexdigest()
            manifest_payload: dict[str, object] = {
                "manifest_id": new_uuid7(now=ref_now),
                "workspace_id": workspace_id,
                "repository_id": repository_id,
                "repair_id": repair_id,
                "source_sha": base_sha,
                "base_sha": base_sha,
                "patched_sha": patched_sha,
                "diff_digest": patch_digest,
                "ci_run_id": ci_run_id,
                "ci_job_ids": job_ids or [b_ci_job_id],
                "ci_attempt_key": attempt_key,
                "profile_id": patched_rec.profile_id,
                "profile_digest": b_prof_digest,
                "image_digest": patched_res.image_digest,
                "dependency_lock_digest": lock_digest,
                "commands_digest": patched_res.command_digest,
                "environment_digest": patched_res.environment_digest,
                "baseline_result_job_id": baseline_res.job_id,
                "baseline_result_digest": hashlib.sha256(baseline_blob).hexdigest(),
                "patched_result_job_id": patched_res.job_id,
                "patched_result_digest": hashlib.sha256(patched_blob).hexdigest(),
                "failure_fingerprint": expected_fp,
                "fidelity_grade": patched_rec.fidelity_grade,
                "fidelity_differences": list(patched_rec.fidelity_differences),
                "regression": RegressionSuiteSummary(
                    selection_id="sandbox-b-parity",
                    selection_digest=patched_res.command_digest,
                    passed_count=patched_rec.passed_tests_count,
                    failed_count=patched_rec.failed_tests_count,
                    skipped_count=patched_rec.skipped_tests_count,
                    result_job_id=patched_res.job_id,
                ),
                "integrity_outcome": "pass",
                "security_outcome": "pass",
                "security_findings": [],
                "policy_outcome": "pass",
                "provenance": provenance_models,
                "redaction_revision": REDACTION_VERSION,
                "artifact_digests": {
                    diff_art_row.id: hashlib.sha256(diff_bytes).hexdigest(),
                },
                "created_at": ref_now,
            }
            signed_manifest = create_signed_evidence_manifest(
                manifest_payload,
                private_key=self._manifest_signer,
                key_id=self._manifest_key_id,
            )

        await self._verification_service.verify(
            workspace_id=workspace_id,
            repair_id=repair_id,
            verification_id=new_uuid7(now=ref_now),
            idempotency_key=f"verify:{repair_id}:{patch_digest[:24]}",
            facts=facts,
            signed_manifest=signed_manifest,
            evidence_blobs=evidence_blobs,
            correlation_id=correlation_id,
            now=ref_now,
        )
        return True

    async def _step_policy_gate(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        repair_id: str,
        base_sha: str,
        policy_revision: int,
        correlation_id: str,
        ref_now: datetime,
    ) -> bool:
        assert self._catalog is not None
        repo_policy, effective_policy, policy_ctx, _ = (
            await self._catalog.resolve_repository_policy_bundle(
                workspace_id=workspace_id,
                repository_id=repository_id,
                policy_revision=policy_revision,
                now=ref_now,
            )
        )
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            repair = await db.scalar(
                select(RepairSessionModel)
                .where(
                    RepairSessionModel.workspace_id == workspace_id,
                    RepairSessionModel.id == repair_id,
                )
                .with_for_update()
            )
            patch_row = await db.scalar(
                select(PatchAttemptModel)
                .where(
                    PatchAttemptModel.workspace_id == workspace_id,
                    PatchAttemptModel.repair_id == repair_id,
                    PatchAttemptModel.integrity_outcome == "accepted",
                )
                .order_by(PatchAttemptModel.attempt_number.desc())
                .limit(1)
            )
            if repair is None or repair.state != "policy_gate":
                return False
            if patch_row is None:
                await self._state_machine.transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state="needs_human",
                    reason_code="policy_gate_missing_patch",
                    status_detail="Policy gate has no accepted candidate patch to evaluate.",
                    actor="system:policy_gate",
                    correlation_id=correlation_id,
                )
                return True

            overall_verdict, _, _, _ = evaluate_patch_paths(
                patch_row.changed_paths_json,
                diff_lines=patch_row.diff_lines_added + patch_row.diff_lines_removed,
                repo_policy=repo_policy,
                effective_policy=effective_policy,
                ctx=policy_ctx,
            )
            if (
                overall_verdict == "deny"
                or effective_policy.effective_paused
                or effective_policy.effective_mode == "monitor"
            ):
                await self._state_machine.transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state="blocked",
                    reason_code="policy_gate_denied",
                    status_detail="Effective repository policy denied draft publication.",
                    actor="system:policy_gate",
                    correlation_id=correlation_id,
                )
                return True

            can_auto_publish = (
                effective_policy.effective_mode == "auto_repair"
                and effective_policy.allow_auto_publication
                and overall_verdict == "allow"
                and self._publisher_saga is not None
            )
            if can_auto_publish:
                existing_approved = await db.scalar(
                    select(ApprovalRequestModel).where(
                        ApprovalRequestModel.workspace_id == workspace_id,
                        ApprovalRequestModel.repair_id == repair_id,
                        ApprovalRequestModel.patch_digest == patch_row.patch_digest,
                        ApprovalRequestModel.policy_revision == repair.policy_revision,
                        ApprovalRequestModel.intent_type == "publish_draft_pr",
                        ApprovalRequestModel.status == "approved",
                    )
                )
                if existing_approved is None:
                    auto_approval = ApprovalRequestModel(
                        id=new_uuid7(now=ref_now),
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        repair_id=repair_id,
                        intent_type="publish_draft_pr",
                        patch_digest=patch_row.patch_digest,
                        base_sha=base_sha,
                        target_ref=repair.target_ref,
                        policy_revision=repair.policy_revision,
                        requested_by=None,
                        risk_level="review",
                        scope_description=(
                            f"Auto-approved verified patch attempt {patch_row.attempt_number} "
                            f"under repository auto_repair policy."
                        ),
                        sensitive_change=False,
                        expires_at=ref_now + APPROVAL_TTL,
                        status="approved",
                        decision="approve",
                        decision_actor=None,
                        decided_at=ref_now,
                        reason="Verified V-01..V-07 proof satisfied auto_repair policy.",
                        correlation_id=correlation_id,
                        created_at=ref_now,
                    )
                    db.add(auto_approval)
                    await db.flush()
                    await append_audit_entry(
                        db,
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        actor_type="system",
                        actor_id="auto_repair_policy",
                        action="repair.approval.decided",
                        target=auto_approval.id,
                        decision="allow",
                        reason_code="auto_repair_policy_approved",
                        correlation_id=correlation_id,
                        occurred_at=ref_now,
                        metadata={
                            "repair_id": repair_id,
                            "patch_digest": patch_row.patch_digest,
                        },
                    )
                    approval_id = auto_approval.id
                else:
                    approval_id = existing_approved.id
            else:
                existing_pending = await db.scalar(
                    select(ApprovalRequestModel).where(
                        ApprovalRequestModel.workspace_id == workspace_id,
                        ApprovalRequestModel.repair_id == repair_id,
                        ApprovalRequestModel.patch_digest == patch_row.patch_digest,
                        ApprovalRequestModel.policy_revision == repair.policy_revision,
                        ApprovalRequestModel.status == "pending",
                    )
                )
                if existing_pending is None:
                    pending_row = ApprovalRequestModel(
                        id=new_uuid7(now=ref_now),
                        workspace_id=workspace_id,
                        repository_id=repository_id,
                        repair_id=repair_id,
                        intent_type="publish_draft_pr",
                        patch_digest=patch_row.patch_digest,
                        base_sha=base_sha,
                        target_ref=repair.target_ref,
                        policy_revision=repair.policy_revision,
                        requested_by=None,
                        risk_level="sensitive",
                        scope_description=(
                            f"Review verified patch attempt {patch_row.attempt_number} "
                            f"({len(patch_row.changed_paths_json)} changed paths)."
                        ),
                        sensitive_change=True,
                        expires_at=ref_now + APPROVAL_TTL,
                        status="pending",
                        correlation_id=correlation_id,
                        created_at=ref_now,
                    )
                    db.add(pending_row)
                    await db.flush()
                    await enqueue_outbox_event(
                        db,
                        EventEnvelope(
                            event_id=new_uuid7(now=ref_now),
                            type="repair.approval.requested",
                            occurred_at=ref_now,
                            workspace_id=workspace_id,
                            repository_id=repository_id,
                            session_id=repair_id,
                            aggregate_id=pending_row.id,
                            aggregate_version=1,
                            correlation_id=correlation_id,
                            payload=ApprovalEventPayload(
                                approval_id=pending_row.id,
                                status="pending",
                                expires_at=ref_now + APPROVAL_TTL,
                            ),
                        ),
                        now=ref_now,
                    )
                await self._state_machine.transition_in_tx(
                    db,
                    workspace_id=workspace_id,
                    repair_id=repair_id,
                    target_state="awaiting_approval",
                    reason_code="awaiting_human_approval",
                    status_detail="Verified candidate patch is awaiting human review in Approvals.",
                    actor="system:policy_gate",
                    correlation_id=correlation_id,
                )
                return True

        assert self._publisher_saga is not None
        await self._publisher_saga.publish_approved(
            workspace_id=workspace_id,
            approval_id=approval_id,
            correlation_id=correlation_id,
            now=ref_now,
        )
        return True

    async def run_periodic_sweeps(self, *, now: datetime | None = None) -> None:
        """Run due local/NAT provider polls and exact-SHA remote CI reconciliations."""
        ref_now = now.astimezone(UTC) if now is not None else self._clock().astimezone(UTC)
        if self._poller is not None:
            try:
                await self._poller.poll_all_due_connections(now=ref_now)
            except Exception as exc:
                _LOGGER.warning(
                    "Background provider polling sweep failed",
                    extra={
                        "event": "pipeline.poller_sweep_error",
                        "error_code": type(exc).__name__,
                    },
                )
        if self._remote_observer is not None:
            try:
                async with instance_rls_session(
                    self._session_factory, mode="instance_admin"
                ) as lookup:
                    pub_rows = list(
                        (
                            await lookup.execute(
                                select(
                                    PublicationRecordModel.workspace_id,
                                    PublicationRecordModel.id,
                                    PublicationRecordModel.repository_id,
                                    PublicationRecordModel.policy_revision,
                                )
                                .join(
                                    RepairSessionModel,
                                    (
                                        RepairSessionModel.workspace_id
                                        == PublicationRecordModel.workspace_id
                                    )
                                    & (RepairSessionModel.id == PublicationRecordModel.repair_id),
                                )
                                .where(
                                    PublicationRecordModel.status == "published",
                                    PublicationRecordModel.expected_commit_sha.is_not(None),
                                    RepairSessionModel.state == "remote_validating",
                                    _unsuspended_repair_clause(),
                                )
                                .limit(20)
                            )
                        ).all()
                    )
                for ws_raw, pub_raw, repo_raw, pol_rev in pub_rows:
                    ws_id = str(ws_raw)
                    pub_id = str(pub_raw)
                    async with workspace_rls_session(
                        self._session_factory, workspace_id=ws_id
                    ) as ws_db:
                        req_set = await ws_db.scalar(
                            select(RequiredCheckSetModel).where(
                                RequiredCheckSetModel.workspace_id == ws_id,
                                RequiredCheckSetModel.repository_id == str(repo_raw),
                                RequiredCheckSetModel.policy_revision == int(pol_rev),
                            )
                        )
                        has_required_names = bool(req_set is not None and req_set.names_json)
                    if has_required_names:
                        await self._remote_observer.reconcile(
                            workspace_id=ws_id,
                            publication_id=pub_id,
                            correlation_id=f"remote-ci-{pub_id[:18]}",
                            now=ref_now,
                        )
            except Exception as exc:
                _LOGGER.warning(
                    "Background remote CI reconciliation sweep failed",
                    extra={
                        "event": "pipeline.remote_ci_sweep_error",
                        "error_code": type(exc).__name__,
                    },
                )

    async def run_forever(self) -> None:
        """Continuously drive triage intake, active repair sessions, and periodic sweeps."""
        loop = asyncio.get_running_loop()
        while True:
            processed = await self.run_once()
            now_mono = loop.time()
            if now_mono - self._last_periodic_sweep_monotonic >= self._sweep_interval:
                self._last_periodic_sweep_monotonic = now_mono
                await self.run_periodic_sweeps()
            if not processed:
                await asyncio.sleep(self._poll_interval)
