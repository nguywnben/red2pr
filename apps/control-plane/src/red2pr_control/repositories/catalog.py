"""Workspace-scoped repository catalog, versioned policy CRUD & dry-run service (`U12`).

Implements `REP-01`, `REP-02`, `REP-03`, `A-07`, `S-04`, `S-09`, `W-02`, `W-04`, `W-05`, `W-06`,
`UX-02`, `UX-REPO-001`, `UX-POLICY-001`, `SEC-007`, `SEC-009`, `SEC-010`, `SEC-022`,
`SEC-031`, and `SEC-032`:
- Deny-by-default repository visibility (`admin` or active `break_glass_grant` sees workspace
  catalog; `maintainer`/`reviewer`/`viewer`/`auditor` sees strictly `repo_grants`).
- Zero-leakage tag, organization, and count facets (`UX-02`): unauthorized repositories never
  leak names, tags, or totals.
- Live in-transaction role & `repo_grant` re-verification on every mutation (`SEC-022`),
  `ETag`/`If-Match` (`412`) + `expected_version`/`expected_revision` (`409`) concurrency guards,
  and `5m` MFA `step_up` enforcement on privilege-expanding mode/policy changes.
- Immutable `repository_policies` append-only snapshot persistence, structured policy audit
  diffs, `security.policy.denied` domain events, and concrete `SetupStepRegistry` `repo_policy`
  probe wiring.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Literal, cast

from pydantic import TypeAdapter, ValidationError
from sqlalchemy import and_, desc, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.events import EventEnvelope, SecurityIdentityEventPayload
from py_contracts.iam import WorkspaceRole
from py_contracts.integrations import (
    AffectedInFlightItem,
    BulkRepositoryPreviewItem,
    BulkRepositoryPreviewRequest,
    BulkRepositoryPreviewResponse,
    BulkRepositoryUpdateRequest,
    BulkRepositoryUpdateResponse,
    CiConclusion,
    CiRunStatus,
    ConnectionStatus,
    ProviderKind,
    ProviderSyncCursor,
    Repository,
    RepositoryAccessGrantSummary,
    RepositoryCatalogPage,
    RepositoryDetailResponse,
    RepositoryFacetSummary,
    RepositoryHistoryEntry,
    RepositoryMode,
    RepositoryPolicy,
    RepositoryPolicyPreviewRequest,
    RepositoryPolicyPreviewResponse,
    RepositoryPolicyRevision,
    RepositoryPolicyStateResponse,
    RepositoryPolicyUpdateRequest,
    RepositoryRunTriggerSummary,
    RepositoryUpdateRequest,
    RepositoryVisibility,
    SyncCursorStatus,
    WorkflowHazardFinding,
    WorkflowHazardStatus,
)
from py_contracts.primitives import InternalId, Money, new_uuid7
from py_contracts.repairs import SetupWizardPhase
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.config import Red2PrConfig, load_config
from red2pr_control.core.errors import (
    BadRequestError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    UnprocessableEntityError,
)
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.db.base import (
    AuditLogModel,
    CiRunTriggerModel,
    ConsentModel,
    MembershipModel,
    ProviderConnectionModel,
    ProviderSyncCursorModel,
    RepoGrantModel,
    RepositoryModel,
    RepositoryPolicyModel,
    SetupCheckpointModel,
    TaskJobModel,
    UserModel,
    WorkspaceModel,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.rbac import (
    WorkspaceAccessContext,
    compute_query_filter_hash,
    decode_signed_cursor,
    encode_signed_cursor,
    enforce_optimistic_version,
)
from red2pr_control.iam.sessions import is_step_up_fresh
from red2pr_control.operations.setup_wizard import SetupStepProbeResult, SetupStepRegistry
from red2pr_control.repositories.glob_guard import (
    PathCanonicalizationError,
    canonicalize_glob_pattern,
)
from red2pr_control.repositories.policy_engine import (
    HistoricalTriggerInput,
    PolicyHierarchyContext,
    WorkspacePolicyLayer,
    build_default_repository_policy,
    compute_policy_rule_changes,
    evaluate_readiness_gates,
    resolve_effective_policy,
    simulate_policy_preview,
    validate_policy_against_hierarchy,
)

_UUID_ADAPTER: TypeAdapter[str] = TypeAdapter(InternalId)
_MUTATION_ROLES: frozenset[WorkspaceRole] = frozenset({"admin", "maintainer"})


def _default_utc_clock() -> datetime:
    return datetime.now(tz=UTC)


def _extract_org_name(repo_full_name: str) -> str | None:
    if "/" not in repo_full_name:
        return None
    org = repo_full_name.split("/", 1)[0].strip()
    return org[:120] if org else None


def _normalize_tags(raw_tags: Sequence[str], *, redactor: Redactor) -> list[str]:
    cleaned: list[str] = []
    for raw in raw_tags:
        scrubbed = redactor.redact_text(raw.strip())[:120].strip()
        if not scrubbed:
            continue
        cleaned.append(scrubbed)
    return list(dict.fromkeys(cleaned))[:32]


def _to_sync_cursor_dto(row: ProviderSyncCursorModel) -> ProviderSyncCursor:
    return ProviderSyncCursor(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        connection_id=row.connection_id,
        provider=cast(ProviderKind, row.provider),
        etag=row.etag,
        high_water_mark_at=row.high_water_mark_at,
        last_seen_run_id=row.last_seen_run_id,
        last_stable_page=row.last_stable_page,
        overlap_seconds=row.overlap_seconds,
        poll_interval_seconds=row.poll_interval_seconds,
        last_polled_at=row.last_polled_at,
        last_success_at=row.last_success_at,
        next_poll_after=row.next_poll_after,
        rate_limit_remaining=row.rate_limit_remaining,
        rate_limit_reset_at=row.rate_limit_reset_at,
        consecutive_failures=row.consecutive_failures,
        last_status=cast(SyncCursorStatus, row.last_status),
        last_error_code=row.last_error_code,
        last_error_detail=row.last_error_detail,
        history_gap_detected=row.history_gap_detected,
        history_gap_since=row.history_gap_since,
        history_gap_until=row.history_gap_until,
        history_gap_detail=row.history_gap_detail,
    )


def _policy_model_to_contract(row: RepositoryPolicyModel) -> RepositoryPolicy:
    cost_obj: Money | None = None
    if row.max_cost_per_session_amount is not None and row.max_cost_currency is not None:
        cost_obj = Money(
            amount=row.max_cost_per_session_amount,
            currency=row.max_cost_currency,
        )
    return RepositoryPolicy(
        branch_allowlist=list(row.branch_allowlist_json),
        branch_denylist=list(row.branch_denylist_json),
        file_allowlist=list(row.file_allowlist_json),
        file_denylist=list(row.file_denylist_json),
        sensitive_rules=list(row.sensitive_rules_json),
        allow_test_edits=row.allow_test_edits,
        allow_config_edits=row.allow_config_edits,
        max_attempts=row.max_attempts,
        max_diff_lines=row.max_diff_lines,
        max_calls_per_session=row.max_calls_per_session,
        max_tokens_per_session=row.max_tokens_per_session,
        max_wall_seconds=row.max_wall_seconds,
        max_cost_per_session=cost_obj,
        require_baseline=True,
        inference_consent_id=row.inference_consent_id,
        runtime_profile_id=row.runtime_profile_id,
    )


def _policy_model_to_revision_dto(row: RepositoryPolicyModel) -> RepositoryPolicyRevision:
    return RepositoryPolicyRevision(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        revision=row.revision,
        mode=cast(RepositoryMode, row.mode),
        paused=row.paused,
        policy=_policy_model_to_contract(row),
        change_reason=row.change_reason,
        created_by_user_id=row.created_by_user_id,
    )


def _to_catalog_repository_dto(
    row: RepositoryModel,
    *,
    conn_row: ProviderConnectionModel | None = None,
    cursor_row: ProviderSyncCursorModel | None = None,
    latest_trigger: CiRunTriggerModel | None = None,
) -> Repository:
    hazards = [WorkflowHazardFinding.model_validate(item) for item in row.workflow_hazards_json]
    grant_review = row.grant_review_required or (
        conn_row.grant_review_required if conn_row is not None else False
    )
    return Repository(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=row.id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        external_id=row.external_repo_id,
        connection_id=row.provider_connection_id,
        name=row.name,
        default_branch=row.default_branch,
        visibility=cast(RepositoryVisibility, row.visibility),
        mode=cast(RepositoryMode, row.mode),
        paused=row.paused,
        policy_revision=row.policy_revision,
        tags=list(row.tags_json),
        archived=row.archived,
        is_fork=row.is_fork,
        workflow_hazard_status=cast(WorkflowHazardStatus, row.workflow_hazard_status),
        workflow_hazards=hazards,
        auto_repair_blocked=row.auto_repair_blocked,
        provider=cast(ProviderKind, conn_row.provider) if conn_row is not None else None,
        organization=_extract_org_name(row.name),
        active=row.active,
        grant_review_required=grant_review,
        sync_status=(
            cast(SyncCursorStatus, cursor_row.last_status) if cursor_row is not None else None
        ),
        last_synced_at=row.last_synced_at,
        last_ci_conclusion=(
            cast(CiConclusion, latest_trigger.conclusion) if latest_trigger is not None else None
        ),
        last_ci_at=latest_trigger.triggered_at if latest_trigger is not None else None,
    )


def _validate_uuid_or_404(raw_id: str, *, code: str, detail: str) -> str:
    try:
        return _UUID_ADAPTER.validate_python(raw_id.strip())
    except ValidationError as exc:
        raise NotFoundError(code=code, detail=detail) from exc


class RepositoryCatalogService:
    """Authoritative `U12` repository catalog, versioned policy CRUD & dry-run simulator."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        signing_key: bytes,
        instance_config: Red2PrConfig | None = None,
        redactor: Redactor | None = None,
        clock: Callable[[], datetime] = _default_utc_clock,
    ) -> None:
        self._session_factory = session_factory
        self._signing_key = signing_key
        self._instance_config = instance_config if instance_config is not None else load_config()
        self._redactor = redactor if redactor is not None else DEFAULT_REDACTOR
        self._clock = clock

    def register_setup_probe(self, registry: SetupStepRegistry) -> None:
        """Wire concrete `repo_policy` validation probe into `SetupStepRegistry` (`U12`)."""
        registry.register_probe("repo_policy", self._probe_setup_repo_policy)

    async def _probe_setup_repo_policy(
        self,
        phase: SetupWizardPhase,
        draft: Mapping[str, Any],
    ) -> SetupStepProbeResult:
        del phase
        raw_branches = draft.get("protected_branches")
        if isinstance(raw_branches, Sequence) and not isinstance(raw_branches, (str, bytes)):
            for pat in raw_branches:
                if not isinstance(pat, str):
                    return SetupStepProbeResult(
                        probe_status="failed",
                        detail="All protected_branches entries must be canonical glob strings.",
                        blocking_reasons=("invalid_protected_branch_glob",),
                    )
                try:
                    canonicalize_glob_pattern(pat)
                except PathCanonicalizationError as exc:
                    return SetupStepProbeResult(
                        probe_status="failed",
                        detail=f"Invalid protected_branches glob '{pat[:80]}': {exc.detail}",
                        blocking_reasons=(exc.code,),
                    )

        max_attempts = draft.get("max_attempts", 2)
        if (
            not isinstance(max_attempts, int)
            or isinstance(max_attempts, bool)
            or not (1 <= max_attempts <= self._instance_config.repository_defaults.max_attempts)
        ):
            return SetupStepProbeResult(
                probe_status="blocked",
                detail=(
                    f"max_attempts ({max_attempts}) exceeds instance ceiling "
                    f"({self._instance_config.repository_defaults.max_attempts})."
                ),
                blocking_reasons=("max_attempts_exceeds_instance_ceiling",),
            )

        max_diff_lines = draft.get("max_diff_lines", 500)
        if (
            not isinstance(max_diff_lines, int)
            or isinstance(max_diff_lines, bool)
            or not (1 <= max_diff_lines <= self._instance_config.repository_defaults.max_diff_lines)
        ):
            return SetupStepProbeResult(
                probe_status="blocked",
                detail=(
                    f"max_diff_lines ({max_diff_lines}) exceeds instance ceiling "
                    f"({self._instance_config.repository_defaults.max_diff_lines})."
                ),
                blocking_reasons=("max_diff_lines_exceeds_instance_ceiling",),
            )

        mode = str(draft.get("default_repo_mode") or "monitor")
        return SetupStepProbeResult(
            probe_status="passed",
            detail=(
                f"Default repository mode '{mode}' validated by policy engine with "
                "require_baseline=true and auto_merge=false."
            ),
        )

    async def _ensure_current_policy_snapshot_in_tx(
        self,
        db: AsyncSession,
        *,
        repo_row: RepositoryModel,
        now: datetime,
    ) -> RepositoryPolicyModel:
        """Load current `RepositoryPolicyModel`, seeding initial snapshot if created directly."""
        current = await db.scalar(
            select(RepositoryPolicyModel).where(
                RepositoryPolicyModel.workspace_id == repo_row.workspace_id,
                RepositoryPolicyModel.repository_id == repo_row.id,
                RepositoryPolicyModel.revision == repo_row.policy_revision,
            )
        )
        if current is not None:
            return current

        latest = await db.scalar(
            select(RepositoryPolicyModel)
            .where(
                RepositoryPolicyModel.workspace_id == repo_row.workspace_id,
                RepositoryPolicyModel.repository_id == repo_row.id,
            )
            .order_by(RepositoryPolicyModel.revision.desc())
            .limit(1)
        )
        base_policy = (
            _policy_model_to_contract(latest)
            if latest is not None
            else build_default_repository_policy(instance_config=self._instance_config)
        )
        seeded = RepositoryPolicyModel(
            id=new_uuid7(now=now),
            workspace_id=repo_row.workspace_id,
            repository_id=repo_row.id,
            revision=repo_row.policy_revision,
            mode=repo_row.mode,
            paused=repo_row.paused,
            branch_allowlist_json=list(base_policy.branch_allowlist),
            branch_denylist_json=list(base_policy.branch_denylist),
            file_allowlist_json=list(base_policy.file_allowlist),
            file_denylist_json=list(base_policy.file_denylist),
            sensitive_rules_json=list(base_policy.sensitive_rules),
            allow_test_edits=base_policy.allow_test_edits,
            allow_config_edits=base_policy.allow_config_edits,
            max_attempts=base_policy.max_attempts,
            max_diff_lines=base_policy.max_diff_lines,
            max_calls_per_session=base_policy.max_calls_per_session,
            max_tokens_per_session=base_policy.max_tokens_per_session,
            max_wall_seconds=base_policy.max_wall_seconds,
            max_cost_per_session_amount=(
                base_policy.max_cost_per_session.amount
                if base_policy.max_cost_per_session is not None
                else None
            ),
            max_cost_currency=(
                base_policy.max_cost_per_session.currency
                if base_policy.max_cost_per_session is not None
                else None
            ),
            require_baseline=True,
            inference_consent_id=base_policy.inference_consent_id,
            runtime_profile_id=base_policy.runtime_profile_id,
            change_reason="Initial repository policy snapshot.",
            created_by_user_id=None,
            version=1,
            created_at=repo_row.created_at,
            updated_at=repo_row.created_at,
        )
        db.add(seeded)
        await db.flush()
        return seeded

    async def _load_instance_readiness_and_consents(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        repo_visibility: str,
        explicit_consent_id: str | None,
    ) -> tuple[bool, bool, bool]:
        """Inspect instance worker readiness & active outbound inference consents."""
        async with instance_rls_session(self._session_factory, mode="instance_admin") as inst_db:
            worker_ckpt = await inst_db.scalar(
                select(SetupCheckpointModel).where(SetupCheckpointModel.phase == "worker_readiness")
            )
            worker_ready = bool(
                worker_ckpt is not None
                and worker_ckpt.status == "completed"
                and worker_ckpt.probe_status == "passed"
            )

            data_policy = self._instance_config.security.inference_data_policy
            if data_policy == "disabled":
                return False, worker_ready, False
            if data_policy == "public_only" and repo_visibility != "public":
                return False, worker_ready, False

            consent_stmt = select(ConsentModel).where(
                ConsentModel.purpose == "inference",
                ConsentModel.revoked_at.is_(None),
                or_(
                    ConsentModel.scope == "instance",
                    ConsentModel.workspace_id == workspace_id,
                ),
            )
            if explicit_consent_id is not None:
                consent_stmt = consent_stmt.where(ConsentModel.id == explicit_consent_id)

            active_consents = list((await inst_db.scalars(consent_stmt)).all())

        consent_ready = False
        needs_non_public_class = repo_visibility != "public"
        for c_row in active_consents:
            scope_matches = (
                c_row.scope == "instance"
                or (c_row.scope == "workspace" and c_row.workspace_id == workspace_id)
                or (
                    c_row.scope == "repository"
                    and c_row.workspace_id == workspace_id
                    and c_row.repository_id == repository_id
                )
            )
            if not scope_matches:
                continue
            classes = set(c_row.data_classes_json or [])
            if needs_non_public_class:
                if classes & {"workspace_internal", "restricted"}:
                    consent_ready = True
                    break
            elif classes & {"public", "workspace_internal", "restricted"}:
                consent_ready = True
                break

        return False, worker_ready, consent_ready

    async def _build_hierarchy_context(
        self,
        *,
        ws_row: WorkspaceModel,
        conn_row: ProviderConnectionModel | None,
        repo_row: RepositoryModel,
        explicit_consent_id: str | None,
    ) -> PolicyHierarchyContext:
        inst_paused, worker_ready, consent_ready = await self._load_instance_readiness_and_consents(
            workspace_id=ws_row.id,
            repository_id=repo_row.id,
            repo_visibility=repo_row.visibility,
            explicit_consent_id=explicit_consent_id,
        )
        raw_ws_policy = (
            ws_row.retention_policy.get("repository_policy_defaults")
            if isinstance(ws_row.retention_policy, Mapping)
            else None
        )
        ws_layer = WorkspacePolicyLayer.from_mapping(
            raw_ws_policy if isinstance(raw_ws_policy, Mapping) else None,
            workspace_paused=ws_row.paused or ws_row.status == "suspended",
        )
        grant_review = repo_row.grant_review_required or (
            conn_row.grant_review_required if conn_row is not None else False
        )
        return PolicyHierarchyContext(
            instance_config=self._instance_config,
            instance_paused=inst_paused,
            workspace_layer=ws_layer,
            worker_isolation_ready=worker_ready,
            inference_consent_ready=consent_ready,
            workflow_hazard_blocked=repo_row.auto_repair_blocked,
            grant_review_required=grant_review,
        )

    async def _reverify_live_mutation_grant_in_tx(
        self,
        db: AsyncSession,
        *,
        access: WorkspaceAccessContext,
        repository_id: str,
        action: str,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> tuple[WorkspaceRole | None, Exception | None]:
        """Re-check live DB membership & `repo_grants` inside the write transaction (`SEC-022`)."""
        ws_id = access.workspace_id
        actor_id = access.auth.user.id

        membership_row = await db.scalar(
            select(MembershipModel)
            .where(
                MembershipModel.workspace_id == ws_id,
                MembershipModel.user_id == actor_id,
            )
            .with_for_update(read=True)
        )
        if membership_row is None:
            reason = (
                "break_glass_read_only"
                if access.break_glass_grant is not None
                else "workspace_access_denied"
            )
            await append_audit_entry(
                db,
                workspace_id=ws_id,
                repository_id=repository_id,
                actor_type="user",
                actor_id=actor_id,
                action=action,
                target=f"repository:{repository_id}",
                decision="deny",
                reason_code=reason,
                correlation_id=correlation_id,
                client_ip=client_ip,
                occurred_at=now,
            )
            if reason == "break_glass_read_only":
                return None, ForbiddenError(
                    code=reason,
                    detail="Break-glass grants provide audited read-only visibility only.",
                )
            return None, NotFoundError(code="repository_not_found", detail="Repository not found.")

        live_role = cast(WorkspaceRole, membership_row.role)
        has_repo_access = live_role == "admin"
        if not has_repo_access:
            grant_exists = await db.scalar(
                select(RepoGrantModel.repository_id)
                .where(
                    RepoGrantModel.workspace_id == ws_id,
                    RepoGrantModel.membership_id == membership_row.id,
                    RepoGrantModel.repository_id == repository_id,
                )
                .limit(1)
            )
            has_repo_access = grant_exists is not None

        if not has_repo_access:
            await append_audit_entry(
                db,
                workspace_id=ws_id,
                repository_id=repository_id,
                actor_type="user",
                actor_id=actor_id,
                action=action,
                target=f"repository:{repository_id}",
                decision="deny",
                reason_code="repository_not_found",
                correlation_id=correlation_id,
                client_ip=client_ip,
                occurred_at=now,
            )
            return None, NotFoundError(code="repository_not_found", detail="Repository not found.")

        if live_role not in _MUTATION_ROLES:
            await append_audit_entry(
                db,
                workspace_id=ws_id,
                repository_id=repository_id,
                actor_type="user",
                actor_id=actor_id,
                action=action,
                target=f"repository:{repository_id}",
                decision="deny",
                reason_code="insufficient_role",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={"live_role": live_role},
                occurred_at=now,
            )
            await enqueue_outbox_event(
                db,
                EventEnvelope(
                    event_id=new_uuid7(now=now),
                    type="security.policy.denied",
                    occurred_at=now,
                    workspace_id=ws_id,
                    repository_id=repository_id,
                    aggregate_id=actor_id,
                    aggregate_version=access.auth.user.version,
                    correlation_id=correlation_id,
                    payload=SecurityIdentityEventPayload(
                        target_id=repository_id,
                        reason_code="insufficient_role",
                    ),
                ),
                now=now,
            )
            return None, ForbiddenError(
                code="insufficient_role",
                detail="Only a workspace admin or granted maintainer may modify repository policy.",
            )

        return live_role, None

    async def _drain_repair_jobs_on_pause_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        repository_id: str,
        actor_user_id: str,
        now: datetime,
    ) -> int:
        """Cancel queued repair jobs and request cancellation on running repair jobs when paused."""
        queued_result = await db.execute(
            update(TaskJobModel)
            .where(
                TaskJobModel.workspace_id == workspace_id,
                TaskJobModel.repository_id == repository_id,
                TaskJobModel.is_repair_job.is_(True),
                TaskJobModel.state == "queued",
            )
            .values(
                state="cancelled",
                cancel_reason="repository_paused",
                cancelled_by_user_id=actor_user_id,
                version=TaskJobModel.version + 1,
                updated_at=now,
            )
        )
        running_result = await db.execute(
            update(TaskJobModel)
            .where(
                TaskJobModel.workspace_id == workspace_id,
                TaskJobModel.repository_id == repository_id,
                TaskJobModel.is_repair_job.is_(True),
                TaskJobModel.state.in_(("leased", "running")),
            )
            .values(
                state="cancel_requested",
                cancel_reason="repository_paused",
                cancelled_by_user_id=actor_user_id,
                version=TaskJobModel.version + 1,
                updated_at=now,
            )
        )
        q_count = int(getattr(queued_result, "rowcount", 0) or 0)
        r_count = int(getattr(running_result, "rowcount", 0) or 0)
        return q_count + r_count

    async def _load_affected_in_flight_jobs_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        repository_id: str,
        fallback_revision: int,
    ) -> list[AffectedInFlightItem]:
        active_rows = list(
            (
                await db.scalars(
                    select(TaskJobModel)
                    .where(
                        TaskJobModel.workspace_id == workspace_id,
                        TaskJobModel.repository_id == repository_id,
                        TaskJobModel.state.in_(("queued", "leased", "running", "cancel_requested")),
                    )
                    .order_by(TaskJobModel.created_at.desc(), TaskJobModel.id.desc())
                    .limit(25)
                )
            ).all()
        )
        items: list[AffectedInFlightItem] = []
        for j_row in active_rows:
            raw_rev = j_row.payload_json.get("policy_revision")
            pinned_rev = (
                raw_rev
                if isinstance(raw_rev, int) and not isinstance(raw_rev, bool) and raw_rev >= 1
                else fallback_revision
            )
            items.append(
                AffectedInFlightItem(
                    job_id=j_row.id,
                    repair_id=j_row.repair_id,
                    kind=j_row.kind,
                    state=j_row.state,
                    pinned_policy_revision=pinned_rev,
                    impact_summary=(
                        f"In-flight job remains pinned to policy revision v{pinned_rev}; "
                        "subsequent runs will bind the new revision."
                    ),
                    created_at=j_row.created_at,
                )
            )
        return items

    async def list_repositories(
        self,
        access: WorkspaceAccessContext,
        *,
        cursor: str | None = None,
        limit: int = 25,
        q: str | None = None,
        connection_id: str | None = None,
        provider: ProviderKind | None = None,
        mode: RepositoryMode | None = None,
        paused: bool | None = None,
        hazard_status: WorkflowHazardStatus | None = None,
        tag: str | None = None,
        include_inactive: bool = False,
    ) -> RepositoryCatalogPage:
        """List workspace repositories intersected with caller's `repo_grants` (`UX-02`)."""
        ref_now = self._clock().astimezone(UTC)
        ws_id = access.workspace_id

        clean_q = q.strip()[:256] if q and q.strip() else None
        clean_tag = tag.strip()[:120] if tag and tag.strip() else None
        clean_conn_id: str | None = None
        if connection_id is not None and connection_id.strip():
            try:
                clean_conn_id = _UUID_ADAPTER.validate_python(connection_id.strip())
            except ValidationError as exc:
                raise BadRequestError(
                    code="invalid_connection_id",
                    detail="connection_id query filter must be a canonical UUID.",
                ) from exc

        q_hash = compute_query_filter_hash(
            {
                "connection_id": clean_conn_id,
                "endpoint": "repositories.list",
                "hazard_status": hazard_status,
                "include_inactive": include_inactive,
                "mode": mode,
                "paused": paused,
                "provider": provider,
                "q": clean_q,
                "tag": clean_tag,
            }
        )
        decoded_cursor = (
            decode_signed_cursor(
                cursor,
                signing_key=self._signing_key,
                expected_workspace_scope=ws_id,
                expected_principal_id=access.auth.user.id,
                current_grant_epoch=access.auth.user.grant_epoch,
                expected_query_hash=q_hash,
                now=ref_now,
            )
            if cursor is not None
            else None
        )

        # Deny-by-default: non-admin without repo_grants sees 0 items and 0 facets (`UX-02`)
        if not access.has_workspace_wide_repo_read and not access.repository_grants:
            return RepositoryCatalogPage(
                items=[],
                next_cursor=None,
                snapshot_at=ref_now,
                facets=RepositoryFacetSummary(),
            )

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            # 1. Load all authorized repos in workspace to compute strictly scoped facets (`UX-02`)
            scoped_base_stmt = select(RepositoryModel).where(RepositoryModel.workspace_id == ws_id)
            if not include_inactive:
                scoped_base_stmt = scoped_base_stmt.where(RepositoryModel.active.is_(True))
            if not access.has_workspace_wide_repo_read:
                scoped_base_stmt = scoped_base_stmt.where(
                    RepositoryModel.id.in_(access.repository_grants)
                )

            authorized_rows = list((await db.scalars(scoped_base_stmt)).all())
            conn_ids = {r.provider_connection_id for r in authorized_rows}
            conns_by_id: dict[str, ProviderConnectionModel] = {}
            if conn_ids:
                conn_rows = (
                    await db.scalars(
                        select(ProviderConnectionModel).where(
                            ProviderConnectionModel.workspace_id == ws_id,
                            ProviderConnectionModel.id.in_(conn_ids),
                        )
                    )
                ).all()
                conns_by_id = {c.id: c for c in conn_rows}

            scoped_tags: set[str] = set()
            scoped_orgs: set[str] = set()
            mode_counts: dict[str, int] = {"monitor": 0, "approval": 0, "auto_repair": 0}
            paused_count = 0
            hazard_count = 0
            partial_sync_conns: set[str] = set()

            for r_row in authorized_rows:
                for t_val in r_row.tags_json:
                    if isinstance(t_val, str) and t_val:
                        scoped_tags.add(t_val)
                org_val = _extract_org_name(r_row.name)
                if org_val:
                    scoped_orgs.add(org_val)
                mode_counts[r_row.mode] = mode_counts.get(r_row.mode, 0) + 1
                if r_row.paused:
                    paused_count += 1
                if r_row.workflow_hazard_status == "flagged":
                    hazard_count += 1
                c_obj = conns_by_id.get(r_row.provider_connection_id)
                if c_obj is not None and c_obj.status == "degraded":
                    partial_sync_conns.add(c_obj.id)

            facets = RepositoryFacetSummary(
                tags=sorted(scoped_tags),
                organizations=sorted(scoped_orgs),
                mode_counts=mode_counts,
                paused_count=paused_count,
                hazard_flagged_count=hazard_count,
                partial_sync_connection_ids=sorted(partial_sync_conns),
            )

            # 2. Apply query filters & signed S-04 keyset pagination
            page_stmt = select(RepositoryModel).where(RepositoryModel.workspace_id == ws_id)
            if not include_inactive:
                page_stmt = page_stmt.where(RepositoryModel.active.is_(True))
            if not access.has_workspace_wide_repo_read:
                page_stmt = page_stmt.where(RepositoryModel.id.in_(access.repository_grants))
            if clean_conn_id is not None:
                page_stmt = page_stmt.where(RepositoryModel.provider_connection_id == clean_conn_id)
            if provider is not None:
                matching_prov_ids = [
                    cid for cid, c_row in conns_by_id.items() if c_row.provider == provider
                ]
                if not matching_prov_ids:
                    return RepositoryCatalogPage(
                        items=[],
                        next_cursor=None,
                        snapshot_at=ref_now,
                        facets=facets,
                    )
                page_stmt = page_stmt.where(
                    RepositoryModel.provider_connection_id.in_(matching_prov_ids)
                )
            if mode is not None:
                page_stmt = page_stmt.where(RepositoryModel.mode == mode)
            if paused is not None:
                page_stmt = page_stmt.where(RepositoryModel.paused.is_(paused))
            if hazard_status is not None:
                page_stmt = page_stmt.where(RepositoryModel.workflow_hazard_status == hazard_status)
            if clean_tag is not None:
                page_stmt = page_stmt.where(RepositoryModel.tags_json.contains([clean_tag]))
            if clean_q is not None:
                escaped_like = clean_q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                page_stmt = page_stmt.where(
                    RepositoryModel.name.ilike(f"%{escaped_like}%", escape="\\")
                )
            if decoded_cursor is not None:
                page_stmt = page_stmt.where(
                    or_(
                        RepositoryModel.created_at < decoded_cursor.created_at,
                        and_(
                            RepositoryModel.created_at == decoded_cursor.created_at,
                            RepositoryModel.id < decoded_cursor.item_id,
                        ),
                    )
                )

            page_stmt = page_stmt.order_by(
                RepositoryModel.created_at.desc(),
                RepositoryModel.id.desc(),
            ).limit(limit + 1)

            raw_rows = list((await db.scalars(page_stmt)).all())
            has_more = len(raw_rows) > limit
            page_rows = raw_rows[:limit]

            # 3. Batch-enrich sync cursors & latest CI conclusions (zero N+1 queries)
            cursors_by_repo: dict[str, ProviderSyncCursorModel] = {}
            latest_triggers_by_repo: dict[str, CiRunTriggerModel] = {}
            if page_rows:
                page_repo_ids = [r.id for r in page_rows]
                cursor_rows = (
                    await db.scalars(
                        select(ProviderSyncCursorModel).where(
                            ProviderSyncCursorModel.workspace_id == ws_id,
                            ProviderSyncCursorModel.repository_id.in_(page_repo_ids),
                        )
                    )
                ).all()
                cursors_by_repo = {c.repository_id: c for c in cursor_rows}

                trig_rows = (
                    await db.scalars(
                        select(CiRunTriggerModel)
                        .where(
                            CiRunTriggerModel.workspace_id == ws_id,
                            CiRunTriggerModel.repository_id.in_(page_repo_ids),
                        )
                        .order_by(
                            CiRunTriggerModel.triggered_at.desc(),
                            CiRunTriggerModel.id.desc(),
                        )
                    )
                ).all()
                for t_row in trig_rows:
                    latest_triggers_by_repo.setdefault(t_row.repository_id, t_row)

            items = [
                _to_catalog_repository_dto(
                    r_row,
                    conn_row=conns_by_id.get(r_row.provider_connection_id),
                    cursor_row=cursors_by_repo.get(r_row.id),
                    latest_trigger=latest_triggers_by_repo.get(r_row.id),
                )
                for r_row in page_rows
            ]

        next_cursor: str | None = None
        if has_more and page_rows:
            last_row = page_rows[-1]
            next_cursor = encode_signed_cursor(
                signing_key=self._signing_key,
                workspace_scope=ws_id,
                principal_id=access.auth.user.id,
                grant_epoch=access.auth.user.grant_epoch,
                query_hash=q_hash,
                created_at=last_row.created_at,
                item_id=last_row.id,
                now=ref_now,
            )

        return RepositoryCatalogPage(
            items=items,
            next_cursor=next_cursor,
            snapshot_at=ref_now,
            facets=facets,
        )

    async def get_repository(
        self,
        access: WorkspaceAccessContext,
        *,
        repository_id: str,
        client_ip: str,
        correlation_id: str,
    ) -> tuple[RepositoryDetailResponse, int]:
        """Return detailed repository state, effective policy, runs, access & history (`UI-S05`)."""
        ref_now = self._clock().astimezone(UTC)
        ws_id = access.workspace_id
        clean_repo_id = _validate_uuid_or_404(
            repository_id,
            code="repository_not_found",
            detail="Repository not found.",
        )

        if not access.can_read_repository(clean_repo_id):
            async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    repository_id=clean_repo_id,
                    actor_type="user",
                    actor_id=access.auth.user.id,
                    action="repositories.read",
                    target=f"repository:{clean_repo_id}",
                    decision="deny",
                    reason_code="repository_not_found",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
            raise NotFoundError(code="repository_not_found", detail="Repository not found.")

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            repo_row = await db.scalar(
                select(RepositoryModel).where(
                    RepositoryModel.workspace_id == ws_id,
                    RepositoryModel.id == clean_repo_id,
                )
            )
            if repo_row is None:
                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    repository_id=clean_repo_id,
                    actor_type="user",
                    actor_id=access.auth.user.id,
                    action="repositories.read",
                    target=f"repository:{clean_repo_id}",
                    decision="deny",
                    reason_code="repository_not_found",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                raise NotFoundError(code="repository_not_found", detail="Repository not found.")

            ws_row = await db.scalar(select(WorkspaceModel).where(WorkspaceModel.id == ws_id))
            assert ws_row is not None
            conn_row = await db.scalar(
                select(ProviderConnectionModel).where(
                    ProviderConnectionModel.workspace_id == ws_id,
                    ProviderConnectionModel.id == repo_row.provider_connection_id,
                )
            )
            current_policy_row = await self._ensure_current_policy_snapshot_in_tx(
                db, repo_row=repo_row, now=ref_now
            )
            policy_dto = _policy_model_to_contract(current_policy_row)

            revision_rows = list(
                (
                    await db.scalars(
                        select(RepositoryPolicyModel)
                        .where(
                            RepositoryPolicyModel.workspace_id == ws_id,
                            RepositoryPolicyModel.repository_id == clean_repo_id,
                        )
                        .order_by(RepositoryPolicyModel.revision.desc())
                        .limit(25)
                    )
                ).all()
            )
            revisions_dto = [_policy_model_to_revision_dto(r) for r in revision_rows]

            cursor_row = await db.scalar(
                select(ProviderSyncCursorModel).where(
                    ProviderSyncCursorModel.workspace_id == ws_id,
                    ProviderSyncCursorModel.repository_id == clean_repo_id,
                )
            )

            trigger_rows = list(
                (
                    await db.scalars(
                        select(CiRunTriggerModel)
                        .where(
                            CiRunTriggerModel.workspace_id == ws_id,
                            CiRunTriggerModel.repository_id == clean_repo_id,
                        )
                        .order_by(
                            CiRunTriggerModel.triggered_at.desc(),
                            CiRunTriggerModel.id.desc(),
                        )
                        .limit(25)
                    )
                ).all()
            )
            recent_runs = [
                RepositoryRunTriggerSummary(
                    id=t.id,
                    provider=cast(ProviderKind, t.provider),
                    provider_run_id=t.provider_run_id,
                    attempt_key=t.attempt_key,
                    head_sha=t.head_sha,
                    ref=t.ref,
                    event_type=t.event_type,
                    status=cast(CiRunStatus, t.status),
                    conclusion=cast(CiConclusion, t.conclusion),
                    is_rerun=t.is_rerun,
                    untrusted_fork=t.untrusted_fork,
                    first_source=cast(Literal["webhook", "poll", "reconcile"], t.first_source),
                    job_id=t.job_id,
                    triggered_at=t.triggered_at,
                )
                for t in trigger_rows
            ]

            active_jobs = await self._load_affected_in_flight_jobs_in_tx(
                db,
                workspace_id=ws_id,
                repository_id=clean_repo_id,
                fallback_revision=repo_row.policy_revision,
            )

            # Scoped access grants summary (admins/auditors/maintainers see repo grant list;
            # viewers/reviewers see only their own membership entry to avoid member enumeration)
            can_inspect_all_grants = access.effective_role in {
                "admin",
                "auditor",
                "maintainer",
                "break_glass",
            }
            grant_membership_rows = list(
                (
                    await db.scalars(
                        select(MembershipModel).where(
                            MembershipModel.workspace_id == ws_id,
                            or_(
                                MembershipModel.role == "admin",
                                MembershipModel.id.in_(
                                    select(RepoGrantModel.membership_id).where(
                                        RepoGrantModel.workspace_id == ws_id,
                                        RepoGrantModel.repository_id == clean_repo_id,
                                    )
                                ),
                            ),
                        )
                    )
                ).all()
            )
            if not can_inspect_all_grants:
                grant_membership_rows = [
                    m for m in grant_membership_rows if m.user_id == access.auth.user.id
                ]

            audit_rows = list(
                (
                    await db.scalars(
                        select(AuditLogModel)
                        .where(
                            AuditLogModel.workspace_id == ws_id,
                            AuditLogModel.repository_id == clean_repo_id,
                        )
                        .order_by(desc(AuditLogModel.seq))
                        .limit(30)
                    )
                ).all()
            )

            repo_dto = _to_catalog_repository_dto(
                repo_row,
                conn_row=conn_row,
                cursor_row=cursor_row,
                latest_trigger=trigger_rows[0] if trigger_rows else None,
            )
            repo_version = repo_row.version
            repo_policy_rev = repo_row.policy_revision
            repo_mode = cast(RepositoryMode, repo_row.mode)
            repo_paused = repo_row.paused
            conn_name = conn_row.display_name if conn_row is not None else None
            conn_status = (
                cast(ConnectionStatus, conn_row.status)
                if conn_row is not None
                else "not_configured"
            )
            cursor_dto = _to_sync_cursor_dto(cursor_row) if cursor_row is not None else None

            db.expunge(ws_row)
            if conn_row is not None:
                db.expunge(conn_row)
            db.expunge(repo_row)

        # Resolve user display names for authorized grant entries under `instance_only`
        users_by_id: dict[str, UserModel] = {}
        if grant_membership_rows:
            u_ids = {m.user_id for m in grant_membership_rows}
            async with instance_rls_session(self._session_factory, mode="instance_only") as inst_db:
                u_rows = (
                    await inst_db.scalars(select(UserModel).where(UserModel.id.in_(u_ids)))
                ).all()
                users_by_id = {u.id: u for u in u_rows}

        access_grants: list[RepositoryAccessGrantSummary] = []
        for m_row in sorted(
            grant_membership_rows,
            key=lambda m: (0 if m.role == "admin" else 1, m.created_at, m.id),
        ):
            u_obj = users_by_id.get(m_row.user_id)
            access_grants.append(
                RepositoryAccessGrantSummary(
                    membership_id=m_row.id,
                    user_id=m_row.user_id,
                    display_name=u_obj.display_name if u_obj is not None else m_row.user_id,
                    email=(u_obj.email or "") if u_obj is not None else "",
                    role=cast(WorkspaceRole, m_row.role),
                    grant_origin=(
                        "workspace_admin" if m_row.role == "admin" else "explicit_repo_grant"
                    ),
                )
            )

        recent_history: list[RepositoryHistoryEntry] = []
        for a_row in audit_rows:
            meta = a_row.metadata_json if isinstance(a_row.metadata_json, Mapping) else {}
            raw_rev = meta.get("new_policy_revision") or meta.get("policy_revision")
            pol_rev = (
                raw_rev
                if isinstance(raw_rev, int) and not isinstance(raw_rev, bool) and raw_rev >= 1
                else None
            )
            reason_note = str(meta.get("reason") or a_row.reason_code or a_row.action)[:500]
            recent_history.append(
                RepositoryHistoryEntry(
                    id=a_row.id,
                    occurred_at=a_row.occurred_at,
                    actor_type=a_row.actor_type[:120],
                    actor_id=a_row.actor_id[:120],
                    action=a_row.action[:120],
                    decision=a_row.decision[:120],
                    reason_code=a_row.reason_code[:120] if a_row.reason_code else None,
                    policy_revision=pol_rev,
                    summary=self._redactor.redact_text(reason_note)[:1000] or a_row.action,
                )
            )

        ctx = await self._build_hierarchy_context(
            ws_row=ws_row,
            conn_row=conn_row,
            repo_row=repo_row,
            explicit_consent_id=policy_dto.inference_consent_id,
        )
        effective_policy = resolve_effective_policy(
            repo_mode=repo_mode,
            repo_paused=repo_paused,
            repo_policy=policy_dto,
            ctx=ctx,
        )
        readiness_gates = evaluate_readiness_gates(ctx, target_mode=repo_mode)

        return (
            RepositoryDetailResponse(
                repository=repo_dto,
                connection_display_name=conn_name,
                connection_status=conn_status,
                current_policy_revision=repo_policy_rev,
                policy=policy_dto,
                effective_policy=effective_policy,
                readiness_gates=readiness_gates,
                sync_cursor=cursor_dto,
                recent_runs=recent_runs,
                active_jobs=active_jobs,
                access_grants=access_grants,
                recent_history=recent_history,
                policy_revisions=revisions_dto,
            ),
            repo_version,
        )

    async def update_repository(
        self,
        access: WorkspaceAccessContext,
        *,
        repository_id: str,
        payload: RepositoryUpdateRequest,
        if_match_header: str | None,
        client_ip: str,
        correlation_id: str,
    ) -> tuple[Repository, int]:
        """Update repository `mode`, `paused`, `tags`, or `W-02` review gate (`A-07`, `S-02`)."""
        ref_now = self._clock().astimezone(UTC)
        ws_id = access.workspace_id
        clean_repo_id = _validate_uuid_or_404(
            repository_id,
            code="repository_not_found",
            detail="Repository not found.",
        )

        raised_exc: Exception | None = None
        result_dto: Repository | None = None
        result_version = 1

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            live_role, grant_exc = await self._reverify_live_mutation_grant_in_tx(
                db,
                access=access,
                repository_id=clean_repo_id,
                action="repositories.update",
                client_ip=client_ip,
                correlation_id=correlation_id,
                now=ref_now,
            )
            if grant_exc is not None:
                raised_exc = grant_exc
            else:
                assert live_role is not None
                result_dto, result_version, raised_exc = await self._apply_repo_update_in_tx(
                    db,
                    access=access,
                    live_role=live_role,
                    repository_id=clean_repo_id,
                    payload=payload,
                    if_match_header=if_match_header,
                    client_ip=client_ip,
                    correlation_id=correlation_id,
                    ref_now=ref_now,
                )

        if raised_exc is not None:
            raise raised_exc
        assert result_dto is not None
        return result_dto, result_version

    async def _apply_repo_update_in_tx(
        self,
        db: AsyncSession,
        *,
        access: WorkspaceAccessContext,
        live_role: WorkspaceRole,
        repository_id: str,
        payload: RepositoryUpdateRequest,
        if_match_header: str | None,
        client_ip: str,
        correlation_id: str,
        ref_now: datetime,
    ) -> tuple[Repository | None, int, Exception | None]:
        ws_id = access.workspace_id
        clean_repo_id = repository_id
        raised_exc: Exception | None = None
        result_dto: Repository | None = None
        result_version = 1

        if True:
            repo_row = await db.scalar(
                select(RepositoryModel)
                .where(
                    RepositoryModel.workspace_id == ws_id,
                    RepositoryModel.id == clean_repo_id,
                )
                .with_for_update()
            )
            if repo_row is None:
                raise NotFoundError(code="repository_not_found", detail="Repository not found.")

            enforce_optimistic_version(
                current_version=repo_row.version,
                if_match_header=if_match_header,
                expected_version=payload.expected_version,
            )

            ws_row = await db.scalar(select(WorkspaceModel).where(WorkspaceModel.id == ws_id))
            assert ws_row is not None
            conn_row = await db.scalar(
                select(ProviderConnectionModel)
                .where(
                    ProviderConnectionModel.workspace_id == ws_id,
                    ProviderConnectionModel.id == repo_row.provider_connection_id,
                )
                .with_for_update()
            )
            current_policy_row = await self._ensure_current_policy_snapshot_in_tx(
                db, repo_row=repo_row, now=ref_now
            )
            current_policy = _policy_model_to_contract(current_policy_row)

            if payload.acknowledge_grant_review and live_role != "admin":
                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    repository_id=clean_repo_id,
                    actor_type="user",
                    actor_id=access.auth.user.id,
                    action="repositories.acknowledge_grant_review",
                    target=f"repository:{clean_repo_id}",
                    decision="deny",
                    reason_code="admin_required_for_grant_review",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                raised_exc = ForbiddenError(
                    code="admin_required_for_grant_review",
                    detail=(
                        "Only a workspace admin may clear a post-revocation W-02 connection "
                        "grant review hold."
                    ),
                )
            else:
                target_mode = (
                    payload.mode
                    if payload.mode is not None
                    else cast(RepositoryMode, repo_row.mode)
                )
                target_paused = payload.paused if payload.paused is not None else repo_row.paused
                _, policy_needs_step_up = compute_policy_rule_changes(
                    current_mode=cast(RepositoryMode, repo_row.mode),
                    current_paused=repo_row.paused,
                    current_policy=current_policy,
                    target_mode=target_mode,
                    target_paused=target_paused,
                    target_policy=current_policy,
                )
                needs_step_up = policy_needs_step_up or payload.acknowledge_grant_review
                if needs_step_up and not is_step_up_fresh(access.auth.session, now=ref_now):
                    await append_audit_entry(
                        db,
                        workspace_id=ws_id,
                        repository_id=clean_repo_id,
                        actor_type="user",
                        actor_id=access.auth.user.id,
                        action="repositories.update",
                        target=f"repository:{clean_repo_id}",
                        decision="deny",
                        reason_code="step_up_required",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        metadata={"target_mode": target_mode},
                        occurred_at=ref_now,
                    )
                    raised_exc = ForbiddenError(
                        code="step_up_required",
                        detail=(
                            "Enabling auto_repair or clearing W-02 grant review requires fresh "
                            "5-minute MFA step-up verification."
                        ),
                    )
                else:
                    ctx = await self._build_hierarchy_context(
                        ws_row=ws_row,
                        conn_row=conn_row,
                        repo_row=repo_row,
                        explicit_consent_id=current_policy.inference_consent_id,
                    )
                    denials = validate_policy_against_hierarchy(
                        target_mode=target_mode,
                        target_policy=current_policy,
                        ctx=ctx,
                        acknowledge_grant_review=payload.acknowledge_grant_review,
                    )
                    blocking = [d for d in denials if d.blocking_save]
                    if blocking:
                        first_block = blocking[0]
                        await append_audit_entry(
                            db,
                            workspace_id=ws_id,
                            repository_id=clean_repo_id,
                            actor_type="user",
                            actor_id=access.auth.user.id,
                            action="repositories.update",
                            target=f"repository:{clean_repo_id}",
                            decision="deny",
                            reason_code=first_block.code,
                            correlation_id=correlation_id,
                            client_ip=client_ip,
                            metadata={"target_mode": target_mode, "detail": first_block.detail},
                            occurred_at=ref_now,
                        )
                        await enqueue_outbox_event(
                            db,
                            EventEnvelope(
                                event_id=new_uuid7(now=ref_now),
                                type="security.policy.denied",
                                occurred_at=ref_now,
                                workspace_id=ws_id,
                                repository_id=clean_repo_id,
                                aggregate_id=clean_repo_id,
                                aggregate_version=repo_row.version,
                                correlation_id=correlation_id,
                                payload=SecurityIdentityEventPayload(
                                    target_id=clean_repo_id,
                                    reason_code=first_block.code,
                                ),
                            ),
                            now=ref_now,
                        )
                        raised_exc = ConflictError(
                            code=first_block.code,
                            detail=first_block.detail,
                        )
                    else:
                        old_mode = repo_row.mode
                        old_paused = repo_row.paused
                        old_tags = list(repo_row.tags_json)
                        old_policy_rev = repo_row.policy_revision
                        clean_reason = (
                            self._redactor.redact_text(payload.reason.strip())[:1000]
                            if payload.reason and payload.reason.strip()
                            else None
                        )

                        if payload.acknowledge_grant_review:
                            repo_row.grant_review_required = False
                            if conn_row is not None and conn_row.grant_review_required:
                                other_pending = await db.scalar(
                                    select(RepositoryModel.id)
                                    .where(
                                        RepositoryModel.workspace_id == ws_id,
                                        RepositoryModel.provider_connection_id == conn_row.id,
                                        RepositoryModel.id != clean_repo_id,
                                        RepositoryModel.grant_review_required.is_(True),
                                    )
                                    .limit(1)
                                )
                                if other_pending is None:
                                    conn_row.grant_review_required = False
                                    conn_row.version += 1
                                    conn_row.updated_at = ref_now

                        if payload.tags is not None:
                            repo_row.tags_json = _normalize_tags(
                                payload.tags, redactor=self._redactor
                            )

                        mode_or_pause_changed = (
                            target_mode != old_mode or target_paused != old_paused
                        )
                        repo_row.mode = target_mode
                        repo_row.paused = target_paused
                        drained_jobs = 0
                        if target_paused and not old_paused:
                            drained_jobs = await self._drain_repair_jobs_on_pause_in_tx(
                                db,
                                workspace_id=ws_id,
                                repository_id=clean_repo_id,
                                actor_user_id=access.auth.user.id,
                                now=ref_now,
                            )

                        if mode_or_pause_changed:
                            new_rev = old_policy_rev + 1
                            repo_row.policy_revision = new_rev
                            db.add(
                                RepositoryPolicyModel(
                                    id=new_uuid7(now=ref_now),
                                    workspace_id=ws_id,
                                    repository_id=clean_repo_id,
                                    revision=new_rev,
                                    mode=target_mode,
                                    paused=target_paused,
                                    branch_allowlist_json=list(current_policy.branch_allowlist),
                                    branch_denylist_json=list(current_policy.branch_denylist),
                                    file_allowlist_json=list(current_policy.file_allowlist),
                                    file_denylist_json=list(current_policy.file_denylist),
                                    sensitive_rules_json=list(current_policy.sensitive_rules),
                                    allow_test_edits=current_policy.allow_test_edits,
                                    allow_config_edits=current_policy.allow_config_edits,
                                    max_attempts=current_policy.max_attempts,
                                    max_diff_lines=current_policy.max_diff_lines,
                                    max_calls_per_session=current_policy.max_calls_per_session,
                                    max_tokens_per_session=current_policy.max_tokens_per_session,
                                    max_wall_seconds=current_policy.max_wall_seconds,
                                    max_cost_per_session_amount=(
                                        current_policy.max_cost_per_session.amount
                                        if current_policy.max_cost_per_session is not None
                                        else None
                                    ),
                                    max_cost_currency=(
                                        current_policy.max_cost_per_session.currency
                                        if current_policy.max_cost_per_session is not None
                                        else None
                                    ),
                                    require_baseline=True,
                                    inference_consent_id=current_policy.inference_consent_id,
                                    runtime_profile_id=current_policy.runtime_profile_id,
                                    change_reason=(
                                        clean_reason
                                        or (
                                            f"Repository updated: mode={target_mode}, "
                                            f"paused={target_paused}."
                                        )
                                    ),
                                    created_by_user_id=access.auth.user.id,
                                    version=1,
                                    created_at=ref_now,
                                    updated_at=ref_now,
                                )
                            )

                        repo_row.version += 1
                        repo_row.updated_at = ref_now
                        await db.flush()

                        await append_audit_entry(
                            db,
                            workspace_id=ws_id,
                            repository_id=clean_repo_id,
                            actor_type="user",
                            actor_id=access.auth.user.id,
                            action="repositories.updated",
                            target=f"repository:{clean_repo_id}",
                            decision="allow",
                            reason_code="repository_settings_updated",
                            correlation_id=correlation_id,
                            client_ip=client_ip,
                            metadata={
                                "old_mode": old_mode,
                                "new_mode": target_mode,
                                "old_paused": old_paused,
                                "new_paused": target_paused,
                                "old_tags": old_tags,
                                "new_tags": list(repo_row.tags_json),
                                "old_policy_revision": old_policy_rev,
                                "new_policy_revision": repo_row.policy_revision,
                                "drained_repair_jobs": drained_jobs,
                                "acknowledge_grant_review": payload.acknowledge_grant_review,
                                "reason": clean_reason,
                            },
                            occurred_at=ref_now,
                        )

                        cursor_row = await db.scalar(
                            select(ProviderSyncCursorModel).where(
                                ProviderSyncCursorModel.workspace_id == ws_id,
                                ProviderSyncCursorModel.repository_id == clean_repo_id,
                            )
                        )
                        latest_trig = await db.scalar(
                            select(CiRunTriggerModel)
                            .where(
                                CiRunTriggerModel.workspace_id == ws_id,
                                CiRunTriggerModel.repository_id == clean_repo_id,
                            )
                            .order_by(
                                CiRunTriggerModel.triggered_at.desc(),
                                CiRunTriggerModel.id.desc(),
                            )
                            .limit(1)
                        )
                        result_dto = _to_catalog_repository_dto(
                            repo_row,
                            conn_row=conn_row,
                            cursor_row=cursor_row,
                            latest_trigger=latest_trig,
                        )
                        result_version = repo_row.version

        return result_dto, result_version, raised_exc

    async def get_repository_policy(
        self,
        access: WorkspaceAccessContext,
        *,
        repository_id: str,
        client_ip: str,
        correlation_id: str,
    ) -> tuple[RepositoryPolicyStateResponse, int]:
        """Return current immutable `repository_policies` snapshot, effective merge & history."""
        ref_now = self._clock().astimezone(UTC)
        ws_id = access.workspace_id
        clean_repo_id = _validate_uuid_or_404(
            repository_id,
            code="repository_not_found",
            detail="Repository not found.",
        )

        if not access.can_read_repository(clean_repo_id):
            async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    repository_id=clean_repo_id,
                    actor_type="user",
                    actor_id=access.auth.user.id,
                    action="repositories.policy.read",
                    target=f"repository:{clean_repo_id}:policy",
                    decision="deny",
                    reason_code="repository_not_found",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
            raise NotFoundError(code="repository_not_found", detail="Repository not found.")

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            repo_row = await db.scalar(
                select(RepositoryModel).where(
                    RepositoryModel.workspace_id == ws_id,
                    RepositoryModel.id == clean_repo_id,
                )
            )
            if repo_row is None:
                raise NotFoundError(code="repository_not_found", detail="Repository not found.")

            ws_row = await db.scalar(select(WorkspaceModel).where(WorkspaceModel.id == ws_id))
            assert ws_row is not None
            conn_row = await db.scalar(
                select(ProviderConnectionModel).where(
                    ProviderConnectionModel.workspace_id == ws_id,
                    ProviderConnectionModel.id == repo_row.provider_connection_id,
                )
            )
            current_row = await self._ensure_current_policy_snapshot_in_tx(
                db, repo_row=repo_row, now=ref_now
            )
            policy_dto = _policy_model_to_contract(current_row)
            revision_rows = list(
                (
                    await db.scalars(
                        select(RepositoryPolicyModel)
                        .where(
                            RepositoryPolicyModel.workspace_id == ws_id,
                            RepositoryPolicyModel.repository_id == clean_repo_id,
                        )
                        .order_by(RepositoryPolicyModel.revision.desc())
                        .limit(50)
                    )
                ).all()
            )
            revisions_dto = [_policy_model_to_revision_dto(r) for r in revision_rows]
            cur_rev = repo_row.policy_revision
            cur_mode = cast(RepositoryMode, repo_row.mode)
            cur_paused = repo_row.paused
            db.expunge(ws_row)
            if conn_row is not None:
                db.expunge(conn_row)
            db.expunge(repo_row)

        ctx = await self._build_hierarchy_context(
            ws_row=ws_row,
            conn_row=conn_row,
            repo_row=repo_row,
            explicit_consent_id=policy_dto.inference_consent_id,
        )
        effective_policy = resolve_effective_policy(
            repo_mode=cur_mode,
            repo_paused=cur_paused,
            repo_policy=policy_dto,
            ctx=ctx,
        )
        gates = evaluate_readiness_gates(ctx, target_mode=cur_mode)

        return (
            RepositoryPolicyStateResponse(
                repository_id=clean_repo_id,
                workspace_id=ws_id,
                current_revision=cur_rev,
                mode=cur_mode,
                paused=cur_paused,
                policy=policy_dto,
                effective_policy=effective_policy,
                readiness_gates=gates,
                revisions=revisions_dto,
            ),
            cur_rev,
        )

    async def update_repository_policy(
        self,
        access: WorkspaceAccessContext,
        *,
        repository_id: str,
        payload: RepositoryPolicyUpdateRequest,
        if_match_header: str | None,
        client_ip: str,
        correlation_id: str,
    ) -> tuple[RepositoryPolicyStateResponse, int]:
        """Create an immutable `repository_policies` revision with optimistic locking (`A-07`)."""
        ref_now = self._clock().astimezone(UTC)
        ws_id = access.workspace_id
        clean_repo_id = _validate_uuid_or_404(
            repository_id,
            code="repository_not_found",
            detail="Repository not found.",
        )

        raised_exc: Exception | None = None

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            _, grant_exc = await self._reverify_live_mutation_grant_in_tx(
                db,
                access=access,
                repository_id=clean_repo_id,
                action="repositories.policy.update",
                client_ip=client_ip,
                correlation_id=correlation_id,
                now=ref_now,
            )
            if grant_exc is not None:
                raised_exc = grant_exc
            else:
                raised_exc = await self._apply_policy_update_in_tx(
                    db,
                    access=access,
                    repository_id=clean_repo_id,
                    payload=payload,
                    if_match_header=if_match_header,
                    client_ip=client_ip,
                    correlation_id=correlation_id,
                    ref_now=ref_now,
                )

        if raised_exc is not None:
            raise raised_exc

        return await self.get_repository_policy(
            access,
            repository_id=clean_repo_id,
            client_ip=client_ip,
            correlation_id=correlation_id,
        )

    async def _apply_policy_update_in_tx(
        self,
        db: AsyncSession,
        *,
        access: WorkspaceAccessContext,
        repository_id: str,
        payload: RepositoryPolicyUpdateRequest,
        if_match_header: str | None,
        client_ip: str,
        correlation_id: str,
        ref_now: datetime,
    ) -> Exception | None:
        ws_id = access.workspace_id
        clean_repo_id = repository_id
        raised_exc: Exception | None = None

        if True:
            repo_row = await db.scalar(
                select(RepositoryModel)
                .where(
                    RepositoryModel.workspace_id == ws_id,
                    RepositoryModel.id == clean_repo_id,
                )
                .with_for_update()
            )
            if repo_row is None:
                raise NotFoundError(code="repository_not_found", detail="Repository not found.")

            enforce_optimistic_version(
                current_version=repo_row.policy_revision,
                if_match_header=if_match_header,
                expected_version=payload.expected_revision,
            )

            ws_row = await db.scalar(select(WorkspaceModel).where(WorkspaceModel.id == ws_id))
            assert ws_row is not None
            conn_row = await db.scalar(
                select(ProviderConnectionModel).where(
                    ProviderConnectionModel.workspace_id == ws_id,
                    ProviderConnectionModel.id == repo_row.provider_connection_id,
                )
            )
            current_row = await self._ensure_current_policy_snapshot_in_tx(
                db, repo_row=repo_row, now=ref_now
            )
            current_policy = _policy_model_to_contract(current_row)

            target_mode = (
                payload.mode if payload.mode is not None else cast(RepositoryMode, repo_row.mode)
            )
            target_paused = payload.paused if payload.paused is not None else repo_row.paused
            target_policy = payload.policy

            rule_changes, needs_step_up = compute_policy_rule_changes(
                current_mode=cast(RepositoryMode, repo_row.mode),
                current_paused=repo_row.paused,
                current_policy=current_policy,
                target_mode=target_mode,
                target_paused=target_paused,
                target_policy=target_policy,
            )
            if needs_step_up and not is_step_up_fresh(access.auth.session, now=ref_now):
                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    repository_id=clean_repo_id,
                    actor_type="user",
                    actor_id=access.auth.user.id,
                    action="repositories.policy.update",
                    target=f"repository:{clean_repo_id}:policy",
                    decision="deny",
                    reason_code="step_up_required",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={"target_mode": target_mode},
                    occurred_at=ref_now,
                )
                raised_exc = ForbiddenError(
                    code="step_up_required",
                    detail=(
                        "Relaxing sensitive/denylist guardrails, enabling test/config edits, or "
                        "promoting to auto_repair requires fresh 5-minute MFA step-up."
                    ),
                )
            else:
                ctx = await self._build_hierarchy_context(
                    ws_row=ws_row,
                    conn_row=conn_row,
                    repo_row=repo_row,
                    explicit_consent_id=target_policy.inference_consent_id,
                )
                denials = validate_policy_against_hierarchy(
                    target_mode=target_mode,
                    target_policy=target_policy,
                    ctx=ctx,
                )
                blocking = [d for d in denials if d.blocking_save]
                if blocking:
                    first_block = blocking[0]
                    await append_audit_entry(
                        db,
                        workspace_id=ws_id,
                        repository_id=clean_repo_id,
                        actor_type="user",
                        actor_id=access.auth.user.id,
                        action="repositories.policy.update",
                        target=f"repository:{clean_repo_id}:policy",
                        decision="deny",
                        reason_code=first_block.code,
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        metadata={"detail": first_block.detail},
                        occurred_at=ref_now,
                    )
                    await enqueue_outbox_event(
                        db,
                        EventEnvelope(
                            event_id=new_uuid7(now=ref_now),
                            type="security.policy.denied",
                            occurred_at=ref_now,
                            workspace_id=ws_id,
                            repository_id=clean_repo_id,
                            aggregate_id=clean_repo_id,
                            aggregate_version=repo_row.version,
                            correlation_id=correlation_id,
                            payload=SecurityIdentityEventPayload(
                                target_id=clean_repo_id,
                                reason_code=first_block.code,
                            ),
                        ),
                        now=ref_now,
                    )
                    if first_block.code.endswith("_exceeds_ceiling") or first_block.code in {
                        "budget_currency_mismatch",
                        "zero_budget_blocks_repair",
                    }:
                        raised_exc = UnprocessableEntityError(
                            code=first_block.code,
                            detail=first_block.detail,
                        )
                    else:
                        raised_exc = ConflictError(
                            code=first_block.code,
                            detail=first_block.detail,
                        )
                else:
                    old_rev = repo_row.policy_revision
                    new_rev = old_rev + 1
                    clean_reason = (
                        self._redactor.redact_text(payload.reason.strip())[:1000]
                        if payload.reason and payload.reason.strip()
                        else f"Policy updated to revision v{new_rev}."
                    )

                    drained_jobs = 0
                    if target_paused and not repo_row.paused:
                        drained_jobs = await self._drain_repair_jobs_on_pause_in_tx(
                            db,
                            workspace_id=ws_id,
                            repository_id=clean_repo_id,
                            actor_user_id=access.auth.user.id,
                            now=ref_now,
                        )

                    new_snapshot = RepositoryPolicyModel(
                        id=new_uuid7(now=ref_now),
                        workspace_id=ws_id,
                        repository_id=clean_repo_id,
                        revision=new_rev,
                        mode=target_mode,
                        paused=target_paused,
                        branch_allowlist_json=list(target_policy.branch_allowlist),
                        branch_denylist_json=list(target_policy.branch_denylist),
                        file_allowlist_json=list(target_policy.file_allowlist),
                        file_denylist_json=list(target_policy.file_denylist),
                        sensitive_rules_json=list(target_policy.sensitive_rules),
                        allow_test_edits=target_policy.allow_test_edits,
                        allow_config_edits=target_policy.allow_config_edits,
                        max_attempts=target_policy.max_attempts,
                        max_diff_lines=target_policy.max_diff_lines,
                        max_calls_per_session=target_policy.max_calls_per_session,
                        max_tokens_per_session=target_policy.max_tokens_per_session,
                        max_wall_seconds=target_policy.max_wall_seconds,
                        max_cost_per_session_amount=(
                            target_policy.max_cost_per_session.amount
                            if target_policy.max_cost_per_session is not None
                            else None
                        ),
                        max_cost_currency=(
                            target_policy.max_cost_per_session.currency
                            if target_policy.max_cost_per_session is not None
                            else None
                        ),
                        require_baseline=True,
                        inference_consent_id=target_policy.inference_consent_id,
                        runtime_profile_id=target_policy.runtime_profile_id,
                        change_reason=clean_reason,
                        created_by_user_id=access.auth.user.id,
                        version=1,
                        created_at=ref_now,
                        updated_at=ref_now,
                    )
                    db.add(new_snapshot)

                    repo_row.mode = target_mode
                    repo_row.paused = target_paused
                    repo_row.policy_revision = new_rev
                    repo_row.version += 1
                    repo_row.updated_at = ref_now
                    await db.flush()

                    await append_audit_entry(
                        db,
                        workspace_id=ws_id,
                        repository_id=clean_repo_id,
                        actor_type="user",
                        actor_id=access.auth.user.id,
                        action="repositories.policy.updated",
                        target=f"repository:{clean_repo_id}:policy:v{new_rev}",
                        decision="allow",
                        reason_code="policy_revision_created",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        metadata={
                            "old_policy_revision": old_rev,
                            "new_policy_revision": new_rev,
                            "changed_fields": [c.field for c in rule_changes],
                            "rule_changes": [c.model_dump(mode="json") for c in rule_changes],
                            "drained_repair_jobs": drained_jobs,
                            "reason": clean_reason,
                        },
                        occurred_at=ref_now,
                    )

        return raised_exc

    async def preview_repository_policy(
        self,
        access: WorkspaceAccessContext,
        *,
        repository_id: str,
        payload: RepositoryPolicyPreviewRequest,
        client_ip: str,
        correlation_id: str,
    ) -> RepositoryPolicyPreviewResponse:
        """Run a zero-mutation dry-run simulation against historical runs & in-flight jobs."""
        ref_now = self._clock().astimezone(UTC)
        ws_id = access.workspace_id
        clean_repo_id = _validate_uuid_or_404(
            repository_id,
            code="repository_not_found",
            detail="Repository not found.",
        )

        if not access.can_read_repository(clean_repo_id):
            async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    repository_id=clean_repo_id,
                    actor_type="user",
                    actor_id=access.auth.user.id,
                    action="repositories.policy.preview",
                    target=f"repository:{clean_repo_id}:policy",
                    decision="deny",
                    reason_code="repository_not_found",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
            raise NotFoundError(code="repository_not_found", detail="Repository not found.")

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            repo_row = await db.scalar(
                select(RepositoryModel).where(
                    RepositoryModel.workspace_id == ws_id,
                    RepositoryModel.id == clean_repo_id,
                )
            )
            if repo_row is None:
                raise NotFoundError(code="repository_not_found", detail="Repository not found.")

            ws_row = await db.scalar(select(WorkspaceModel).where(WorkspaceModel.id == ws_id))
            assert ws_row is not None
            conn_row = await db.scalar(
                select(ProviderConnectionModel).where(
                    ProviderConnectionModel.workspace_id == ws_id,
                    ProviderConnectionModel.id == repo_row.provider_connection_id,
                )
            )
            existing_policy_row = await db.scalar(
                select(RepositoryPolicyModel)
                .where(
                    RepositoryPolicyModel.workspace_id == ws_id,
                    RepositoryPolicyModel.repository_id == clean_repo_id,
                )
                .order_by(RepositoryPolicyModel.revision.desc())
                .limit(1)
            )
            current_policy = (
                _policy_model_to_contract(existing_policy_row)
                if existing_policy_row is not None
                else build_default_repository_policy(instance_config=self._instance_config)
            )

            trig_rows = list(
                (
                    await db.scalars(
                        select(CiRunTriggerModel)
                        .where(
                            CiRunTriggerModel.workspace_id == ws_id,
                            CiRunTriggerModel.repository_id == clean_repo_id,
                        )
                        .order_by(
                            CiRunTriggerModel.triggered_at.desc(),
                            CiRunTriggerModel.id.desc(),
                        )
                        .limit(20)
                    )
                ).all()
            )
            historical_inputs = [
                HistoricalTriggerInput(
                    trigger_id=t.id,
                    provider_run_id=t.provider_run_id,
                    attempt_key=t.attempt_key,
                    ref=t.ref,
                    head_sha=t.head_sha,
                    conclusion=cast(CiConclusion, t.conclusion),
                    untrusted_fork=t.untrusted_fork,
                    triggered_at=t.triggered_at,
                )
                for t in trig_rows
            ]
            affected_jobs = await self._load_affected_in_flight_jobs_in_tx(
                db,
                workspace_id=ws_id,
                repository_id=clean_repo_id,
                fallback_revision=repo_row.policy_revision,
            )

            cur_rev = repo_row.policy_revision
            cur_mode = cast(RepositoryMode, repo_row.mode)
            cur_paused = repo_row.paused
            default_branch = repo_row.default_branch
            db.expunge(ws_row)
            if conn_row is not None:
                db.expunge(conn_row)
            db.expunge(repo_row)

        target_mode = payload.mode if payload.mode is not None else cur_mode
        target_paused = payload.paused if payload.paused is not None else cur_paused
        target_policy = payload.policy if payload.policy is not None else current_policy

        ctx = await self._build_hierarchy_context(
            ws_row=ws_row,
            conn_row=conn_row,
            repo_row=repo_row,
            explicit_consent_id=target_policy.inference_consent_id,
        )
        sample_branches = (
            list(payload.sample_branches)
            if payload.sample_branches
            else [default_branch, "feature/example", "red2pr/bot-check"]
        )
        return simulate_policy_preview(
            repository_id=clean_repo_id,
            current_revision=cur_rev,
            current_mode=cur_mode,
            current_paused=cur_paused,
            current_policy=current_policy,
            target_mode=target_mode,
            target_paused=target_paused,
            target_policy=target_policy,
            ctx=ctx,
            sample_branches=sample_branches,
            sample_paths=payload.sample_paths,
            sample_diff_lines=payload.sample_diff_lines,
            historical_triggers=historical_inputs,
            affected_in_flight=affected_jobs,
        )

    async def preview_bulk_repositories(
        self,
        access: WorkspaceAccessContext,
        *,
        payload: BulkRepositoryPreviewRequest,
        client_ip: str,
        correlation_id: str,
    ) -> BulkRepositoryPreviewResponse:
        """Zero-mutation bulk policy/mode preview for `UI-S04` multi-repo selection."""
        ref_now = self._clock().astimezone(UTC)
        ws_id = access.workspace_id
        deduped_ids = list(dict.fromkeys(payload.repository_ids))

        for repo_id in deduped_ids:
            if not access.can_read_repository(repo_id):
                async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
                    await append_audit_entry(
                        db,
                        workspace_id=ws_id,
                        repository_id=repo_id,
                        actor_type="user",
                        actor_id=access.auth.user.id,
                        action="repositories.bulk_preview",
                        target=f"repository:{repo_id}",
                        decision="deny",
                        reason_code="repository_not_found",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        occurred_at=ref_now,
                    )
                raise NotFoundError(code="repository_not_found", detail="Repository not found.")

        items: list[BulkRepositoryPreviewItem] = []
        any_step_up = False
        all_ok = True

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            ws_row = await db.scalar(select(WorkspaceModel).where(WorkspaceModel.id == ws_id))
            assert ws_row is not None
            repo_rows = {
                r.id: r
                for r in (
                    await db.scalars(
                        select(RepositoryModel).where(
                            RepositoryModel.workspace_id == ws_id,
                            RepositoryModel.id.in_(deduped_ids),
                        )
                    )
                ).all()
            }
            if len(repo_rows) != len(deduped_ids):
                raise NotFoundError(code="repository_not_found", detail="Repository not found.")

            conn_ids = {r.provider_connection_id for r in repo_rows.values()}
            conns_by_id = {
                c.id: c
                for c in (
                    await db.scalars(
                        select(ProviderConnectionModel).where(
                            ProviderConnectionModel.workspace_id == ws_id,
                            ProviderConnectionModel.id.in_(conn_ids),
                        )
                    )
                ).all()
            }

            policies_by_repo: dict[str, RepositoryPolicy] = {}
            active_counts: dict[str, int] = {}
            for repo_id, r_row in repo_rows.items():
                latest_pol = await db.scalar(
                    select(RepositoryPolicyModel)
                    .where(
                        RepositoryPolicyModel.workspace_id == ws_id,
                        RepositoryPolicyModel.repository_id == repo_id,
                    )
                    .order_by(RepositoryPolicyModel.revision.desc())
                    .limit(1)
                )
                policies_by_repo[repo_id] = (
                    _policy_model_to_contract(latest_pol)
                    if latest_pol is not None
                    else build_default_repository_policy(instance_config=self._instance_config)
                )
                active_jobs = await self._load_affected_in_flight_jobs_in_tx(
                    db,
                    workspace_id=ws_id,
                    repository_id=repo_id,
                    fallback_revision=r_row.policy_revision,
                )
                active_counts[repo_id] = len(active_jobs)
                db.expunge(r_row)

            db.expunge(ws_row)
            for c_obj in conns_by_id.values():
                db.expunge(c_obj)

        for repo_id in deduped_ids:
            r_row = repo_rows[repo_id]
            c_row = conns_by_id.get(r_row.provider_connection_id)
            pol = policies_by_repo[repo_id]
            cur_mode = cast(RepositoryMode, r_row.mode)
            tgt_mode = payload.mode if payload.mode is not None else cur_mode
            tgt_paused = payload.paused if payload.paused is not None else r_row.paused
            ctx = await self._build_hierarchy_context(
                ws_row=ws_row,
                conn_row=c_row,
                repo_row=r_row,
                explicit_consent_id=pol.inference_consent_id,
            )
            denials = validate_policy_against_hierarchy(
                target_mode=tgt_mode,
                target_policy=pol,
                ctx=ctx,
            )
            _, needs_step_up = compute_policy_rule_changes(
                current_mode=cur_mode,
                current_paused=r_row.paused,
                current_policy=pol,
                target_mode=tgt_mode,
                target_paused=tgt_paused,
                target_policy=pol,
            )
            can_apply = not any(d.blocking_save for d in denials)
            if not can_apply:
                all_ok = False
            if needs_step_up:
                any_step_up = True
            items.append(
                BulkRepositoryPreviewItem(
                    repository_id=repo_id,
                    repository_name=r_row.name,
                    current_version=r_row.version,
                    current_mode=cur_mode,
                    target_mode=tgt_mode,
                    current_paused=r_row.paused,
                    target_paused=tgt_paused,
                    can_apply=can_apply,
                    requires_step_up=needs_step_up,
                    active_job_count=active_counts[repo_id],
                    denials=denials,
                )
            )

        return BulkRepositoryPreviewResponse(
            can_apply_all=all_ok,
            requires_step_up=any_step_up,
            items=items,
        )

    async def bulk_update_repositories(
        self,
        access: WorkspaceAccessContext,
        *,
        payload: BulkRepositoryUpdateRequest,
        client_ip: str,
        correlation_id: str,
    ) -> BulkRepositoryUpdateResponse:
        """Apply an all-or-nothing version-checked bulk repository update (`UI-S04`)."""
        ref_now = self._clock().astimezone(UTC)
        ws_id = access.workspace_id
        deduped_ids = list(dict.fromkeys(payload.repository_ids))

        for repo_id in deduped_ids:
            if payload.expected_versions.get(repo_id) is None:
                raise BadRequestError(
                    code="missing_expected_version",
                    detail=f"expected_versions must include repository '{repo_id}'.",
                )

        # 1. Zero-mutation preflight across every target repository before any write commits
        preview = await self.preview_bulk_repositories(
            access,
            payload=BulkRepositoryPreviewRequest(
                repository_ids=deduped_ids,
                mode=payload.mode,
                paused=payload.paused,
                add_tags=payload.add_tags,
                remove_tags=payload.remove_tags,
            ),
            client_ip=client_ip,
            correlation_id=correlation_id,
        )

        raised_exc: Exception | None = None
        updated: list[Repository] = []

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            live_roles: dict[str, WorkspaceRole] = {}
            for repo_id in deduped_ids:
                live_role, grant_exc = await self._reverify_live_mutation_grant_in_tx(
                    db,
                    access=access,
                    repository_id=repo_id,
                    action="repositories.bulk_update",
                    client_ip=client_ip,
                    correlation_id=correlation_id,
                    now=ref_now,
                )
                if grant_exc is not None:
                    raised_exc = grant_exc
                    break
                assert live_role is not None
                live_roles[repo_id] = live_role

            if raised_exc is None:
                locked_rows = {
                    r.id: r
                    for r in (
                        await db.scalars(
                            select(RepositoryModel)
                            .where(
                                RepositoryModel.workspace_id == ws_id,
                                RepositoryModel.id.in_(deduped_ids),
                            )
                            .order_by(RepositoryModel.id.asc())
                            .with_for_update()
                        )
                    ).all()
                }
                for repo_id in deduped_ids:
                    row = locked_rows.get(repo_id)
                    if row is None:
                        raise NotFoundError(
                            code="repository_not_found", detail="Repository not found."
                        )
                    enforce_optimistic_version(
                        current_version=row.version,
                        expected_version=payload.expected_versions[repo_id],
                    )

                if preview.requires_step_up and not is_step_up_fresh(
                    access.auth.session, now=ref_now
                ):
                    raise ForbiddenError(
                        code="step_up_required",
                        detail=(
                            "Bulk promotion to auto_repair requires fresh 5-minute MFA step-up "
                            "verification."
                        ),
                    )
                if not preview.can_apply_all:
                    for item in preview.items:
                        blocking = [d for d in item.denials if d.blocking_save]
                        if blocking:
                            raise ConflictError(code=blocking[0].code, detail=blocking[0].detail)

                # Apply every repository update inside this single atomic transaction.
                for repo_id in deduped_ids:
                    row = locked_rows[repo_id]
                    expected_ver = payload.expected_versions[repo_id]
                    merged_tags: list[str] | None = None
                    if payload.add_tags or payload.remove_tags:
                        remove_set = set(payload.remove_tags)
                        merged_tags = [t for t in row.tags_json if t not in remove_set] + list(
                            payload.add_tags
                        )

                    dto, _, repo_exc = await self._apply_repo_update_in_tx(
                        db,
                        access=access,
                        live_role=live_roles[repo_id],
                        repository_id=repo_id,
                        payload=RepositoryUpdateRequest(
                            expected_version=expected_ver,
                            mode=payload.mode,
                            paused=payload.paused,
                            tags=merged_tags,
                            reason=payload.reason,
                        ),
                        if_match_header=None,
                        client_ip=client_ip,
                        correlation_id=correlation_id,
                        ref_now=ref_now,
                    )
                    if repo_exc is not None:
                        # Raise inside `workspace_rls_session` so any earlier repo writes roll back!
                        raise repo_exc
                    assert dto is not None
                    updated.append(dto)

        if raised_exc is not None:
            raise raised_exc

        return BulkRepositoryUpdateResponse(updated_repositories=updated)
