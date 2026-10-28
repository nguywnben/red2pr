"""Resumable 10-phase Setup Wizard (`INS-02`), outbound `consents` ledger, and `ADR-037` endpoints.

Implements Unit U07 (`INS-02`, `A-01`, `S-18`, `UI-S01`, `W-01`, `ADR-037`,
`SEC-014`, `SEC-018`, `SEC-032`, `SEC-033`):
- `GET    /api/v1/setup` (`getSetupState`)
- `POST   /api/v1/setup/steps/{phase}` (`submitSetupStep`)
- `GET    /api/v1/setup/consents` (`listSetupConsents`)
- `POST   /api/v1/setup/consents` (`grantSetupConsent`)
- `DELETE /api/v1/setup/consents/{consent_id}` (`revokeSetupConsent`)
- `GET    /api/v1/setup/endpoints` (`listEndpointRegistrations`)
- `POST   /api/v1/setup/endpoints` (`registerPrivateEndpoint`, step-up gated)
- `DELETE /api/v1/setup/endpoints/{endpoint_id}` (`revokePrivateEndpoint`, step-up gated)
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, cast
from urllib.parse import urlparse

from fastapi import APIRouter, Body, Depends, Path, Query, Request, Response, status
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.integrations import (
    ConsentCreateRequest,
    ConsentDataClass,
    ConsentPurpose,
    ConsentRecord,
    ConsentRecordPage,
    ConsentRevokeRequest,
    ConsentScope,
    EgressAdapterKind,
    EndpointRegistration,
    EndpointRegistrationCreateRequest,
    EndpointRegistrationPage,
    EndpointScheme,
)
from py_contracts.primitives import InternalId, Problem, new_uuid7
from py_contracts.repairs import (
    OPTIONAL_SETUP_PHASES,
    SETUP_WIZARD_PHASES,
    PrerequisiteStatus,
    SetupPrerequisite,
    SetupReadiness,
    SetupState,
    SetupStepStatus,
    SetupStepSubmitRequest,
    SetupStepSummary,
    SetupWizardPhase,
)
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.egress import (
    EndpointAllowlistProviderProtocol,
    RegisteredEndpointRule,
)
from red2pr_control.core.errors import (
    PROBLEM_JSON_MEDIA_TYPE,
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    NotFoundError,
    UnprocessableEntityError,
)
from red2pr_control.core.logging import current_correlation_id
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.db.base import (
    ConsentModel,
    EndpointRegistrationModel,
    InstanceModel,
    MembershipModel,
    SetupCheckpointModel,
    UserModel,
    WorkspaceModel,
)
from red2pr_control.db.rls import instance_rls_session
from red2pr_control.iam.csrf import set_csrf_cookie
from red2pr_control.iam.router import get_iam_service
from red2pr_control.iam.sessions import (
    AuthenticatedContext,
    IamService,
    assert_no_secret_in_query_url,
    extract_client_ip,
    is_step_up_fresh,
)
from red2pr_control.iam.workspaces import slugify_workspace_name

_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost"})

_PROBLEM_RESPONSES: dict[int | str, dict[str, object]] = {
    400: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    401: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    403: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    404: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    409: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    410: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    422: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    429: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    503: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
}

_EMPTY_REVOKE_CONSENT = ConsentRevokeRequest()


@dataclass(frozen=True, slots=True)
class SetupStepProbeResult:
    """Authoritative result returned by a registered setup-phase readiness probe."""

    probe_status: PrerequisiteStatus
    detail: str
    blocking_reasons: tuple[str, ...] = ()


SetupStepProbeCallable = Callable[
    [SetupWizardPhase, Mapping[str, Any]],
    Awaitable[SetupStepProbeResult],
]


PROBEABLE_SETUP_PHASES: frozenset[SetupWizardPhase] = OPTIONAL_SETUP_PHASES | frozenset(
    {"repo_policy"}
)


class SetupStepRegistry:
    """Typed registry allowing downstream adapters (`U09`..`U28`) to plug real readiness probes."""

    def __init__(self) -> None:
        self._probes: dict[SetupWizardPhase, SetupStepProbeCallable] = {}

    def register_probe(
        self,
        phase: SetupWizardPhase,
        probe: SetupStepProbeCallable,
    ) -> None:
        if phase not in PROBEABLE_SETUP_PHASES:
            raise ValueError(
                f"Only adapter/runtime phases {sorted(PROBEABLE_SETUP_PHASES)} accept probes"
            )
        self._probes[phase] = probe

    def get_probe(self, phase: SetupWizardPhase) -> SetupStepProbeCallable | None:
        return self._probes.get(phase)


class DbEndpointAllowlistProvider(EndpointAllowlistProviderProtocol):
    """PostgreSQL-backed lookup of active `endpoint_registrations` under RLS (`instance_only`)."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def find_active_rule(
        self,
        *,
        adapter: EgressAdapterKind,
        scheme: EndpointScheme,
        host: str,
        port: int,
    ) -> RegisteredEndpointRule | None:
        normalized_host = host.strip().lower().rstrip(".")
        if normalized_host.startswith("[") and normalized_host.endswith("]"):
            normalized_host = normalized_host[1:-1]
        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            row = await db.scalar(
                select(EndpointRegistrationModel).where(
                    EndpointRegistrationModel.adapter == adapter,
                    EndpointRegistrationModel.scheme == scheme,
                    EndpointRegistrationModel.host == normalized_host,
                    EndpointRegistrationModel.port == port,
                    EndpointRegistrationModel.revoked_at.is_(None),
                )
            )
            if row is None:
                return None
            return RegisteredEndpointRule.from_values(
                endpoint_id=row.id,
                adapter=cast(EgressAdapterKind, row.adapter),
                scheme=cast(EndpointScheme, row.scheme),
                host=row.host,
                port=row.port,
                cidrs=row.cidrs_json,
                ca_ref=row.ca_ref,
            )


def _mint_checkpoint_token(now: datetime) -> str:
    return f"ckpt_{new_uuid7(now=now)}"


def _phase_index(phase: SetupWizardPhase) -> int:
    return SETUP_WIZARD_PHASES.index(phase)


def _next_phase(phase: SetupWizardPhase) -> SetupWizardPhase:
    idx = _phase_index(phase)
    if idx + 1 < len(SETUP_WIZARD_PHASES):
        return SETUP_WIZARD_PHASES[idx + 1]
    return phase


def _to_consent_dto(row: ConsentModel) -> ConsentRecord:
    return ConsentRecord(
        id=row.id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        purpose=cast(ConsentPurpose, row.purpose),
        scope=cast(ConsentScope, row.scope),
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        destination=row.destination,
        data_classes=[cast(ConsentDataClass, item) for item in row.data_classes_json],
        granted_by_user_id=row.granted_by_user_id,
        policy_revision=row.policy_version,
        status="revoked" if row.revoked_at is not None else "active",
        revoked_at=row.revoked_at,
        revoke_reason=row.revoke_reason,
    )


def _to_endpoint_dto(row: EndpointRegistrationModel) -> EndpointRegistration:
    return EndpointRegistration(
        id=row.id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        owner_user_id=row.created_by_user_id,
        adapter=cast(EgressAdapterKind, row.adapter),
        scheme=cast(EndpointScheme, row.scheme),
        host=row.host,
        port=row.port,
        cidrs=list(row.cidrs_json),
        ca_ref=row.ca_ref,
        description=row.description,
        status="revoked" if row.revoked_at is not None else "active",
        revoked_at=row.revoked_at,
    )


def _scrub_draft_dict(raw: dict[str, Any], *, redactor: Redactor) -> dict[str, Any]:
    scrubbed = redactor.redact_value(raw)
    if isinstance(scrubbed, Mapping):
        return {str(k): v for k, v in scrubbed.items()}
    return {}


class SetupWizardService:
    """Durable 10-phase onboarding state machine, readiness calculator & consent/egress service."""

    def __init__(
        self,
        *,
        iam_service: IamService,
        step_registry: SetupStepRegistry | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        self._iam = iam_service
        self._registry = step_registry if step_registry is not None else SetupStepRegistry()
        self._redactor = redactor if redactor is not None else DEFAULT_REDACTOR

    @property
    def step_registry(self) -> SetupStepRegistry:
        return self._registry

    async def _require_instance_owner(
        self,
        request: Request,
        *,
        require_csrf: bool,
        action: str,
        correlation_id: str,
    ) -> AuthenticatedContext:
        auth = await self._iam.authenticate_request(
            request,
            require_csrf=require_csrf,
            correlation_id=correlation_id,
        )
        if not auth.user.is_instance_owner:
            ref_now = self._iam.now()
            client_ip = extract_client_ip(request)
            async with instance_rls_session(self._iam.session_factory, mode="instance_only") as db:
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action=action,
                    target=request.url.path,
                    decision="deny",
                    reason_code="instance_owner_required",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
            raise ForbiddenError(
                code="instance_owner_required",
                detail=(
                    "Only an authenticated instance_owner may access setup, consent, or "
                    "endpoint registration APIs."
                ),
            )
        return auth

    async def _require_owner_with_step_up(
        self,
        request: Request,
        *,
        action: str,
        correlation_id: str,
    ) -> AuthenticatedContext:
        auth = await self._require_instance_owner(
            request,
            require_csrf=True,
            action=action,
            correlation_id=correlation_id,
        )
        ref_now = self._iam.now()
        if not is_step_up_fresh(auth.session, now=ref_now):
            client_ip = extract_client_ip(request)
            async with instance_rls_session(self._iam.session_factory, mode="instance_only") as db:
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action=action,
                    target=request.url.path,
                    decision="deny",
                    reason_code="step_up_required",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
            raise ForbiddenError(
                code="step_up_required",
                detail=(
                    "Registering or revoking private egress endpoints requires fresh "
                    "5-minute step-up verification."
                ),
            )
        return auth

    async def _ensure_checkpoints_initialized(
        self,
        db: AsyncSession,
        *,
        instance_row: InstanceModel,
        owner_user_id: str,
        now: datetime,
    ) -> dict[SetupWizardPhase, SetupCheckpointModel]:
        existing_rows = (
            await db.scalars(
                select(SetupCheckpointModel)
                .where(SetupCheckpointModel.instance_id == instance_row.id)
                .order_by(SetupCheckpointModel.phase_order.asc())
                .with_for_update()
            )
        ).all()
        by_phase: dict[SetupWizardPhase, SetupCheckpointModel] = {
            cast(SetupWizardPhase, r.phase): r for r in existing_rows
        }

        if not by_phase:
            active_token = _mint_checkpoint_token(now)
            for idx, phase_name in enumerate(SETUP_WIZARD_PHASES, start=1):
                is_claim = phase_name == "owner_claim"
                is_second = phase_name == "topology_tls"
                row = SetupCheckpointModel(
                    id=new_uuid7(now=now),
                    instance_id=instance_row.id,
                    phase=phase_name,
                    phase_order=idx,
                    status="completed" if is_claim else "pending",
                    is_current_phase=is_second,
                    checkpoint_token=active_token,
                    draft_payload_json={"claimed": True} if is_claim else {},
                    probe_status="passed" if is_claim else None,
                    probe_detail=(
                        "Initial instance_owner bootstrap claim verified." if is_claim else None
                    ),
                    blocking_reasons_json=[],
                    completed_by_user_id=owner_user_id if is_claim else None,
                    completed_at=now if is_claim else None,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
                db.add(row)
                by_phase[phase_name] = row
            await db.flush()
            return by_phase

        claim_row = by_phase["owner_claim"]
        if claim_row.status != "completed":
            claim_row.status = "completed"
            claim_row.probe_status = "passed"
            claim_row.probe_detail = "Initial instance_owner bootstrap claim verified."
            claim_row.completed_by_user_id = owner_user_id
            claim_row.completed_at = now
            claim_row.updated_at = now
            if claim_row.is_current_phase:
                claim_row.is_current_phase = False
                await db.flush()
                topo_row = by_phase["topology_tls"]
                topo_row.is_current_phase = True
                topo_row.checkpoint_token = _mint_checkpoint_token(now)
                topo_row.updated_at = now
            await db.flush()

        return by_phase

    async def _evaluate_readiness(
        self,
        db: AsyncSession,
        *,
        by_phase: Mapping[SetupWizardPhase, SetupCheckpointModel],
    ) -> tuple[bool, bool, SetupReadiness, list[SetupPrerequisite]]:
        prereqs: list[SetupPrerequisite] = []

        # 1. Core control-plane foundation phases (1..4)
        foundation_phases: tuple[SetupWizardPhase, ...] = (
            "owner_claim",
            "topology_tls",
            "storage_keys",
            "workspace_admin",
        )
        foundation_ok = all(by_phase[p].status == "completed" for p in foundation_phases)
        prereqs.append(
            SetupPrerequisite(
                id="foundation_topology_storage_workspace",
                status="passed" if foundation_ok else "not_configured",
                remediation=(
                    "Owner claim, TLS topology, key custody, and initial workspace are configured."
                    if foundation_ok
                    else "Complete Phases 1-4 (Owner Claim, Topology/TLS, Storage/Keys, Workspace)."
                ),
            )
        )

        # 2. Provider connection probe (Phase 5) -> required for ready_monitor
        prov_row = by_phase["provider_connect"]
        provider_ok = prov_row.status == "completed" and prov_row.probe_status == "passed"
        prov_status: PrerequisiteStatus = (
            cast(PrerequisiteStatus, prov_row.probe_status)
            if prov_row.probe_status is not None
            else "not_configured"
        )
        prereqs.append(
            SetupPrerequisite(
                id="provider_connectivity",
                status="passed" if provider_ok else prov_status,
                remediation=(
                    prov_row.probe_detail or "Provider connectivity verified."
                    if provider_ok
                    else (
                        prov_row.probe_detail
                        or (
                            "Configure and verify a GitHub or GitLab connection to enable "
                            "monitoring."
                        )
                    )
                ),
            )
        )

        ready_monitor = foundation_ok and provider_ok

        # 3. Explicit outbound inference consent (S-18 / SEC-018)
        active_inference_consents = int(
            (
                await db.scalar(
                    select(func.count())
                    .select_from(ConsentModel)
                    .where(
                        ConsentModel.purpose == "inference",
                        ConsentModel.revoked_at.is_(None),
                    )
                )
            )
            or 0
        )
        consent_ok = active_inference_consents > 0
        prereqs.append(
            SetupPrerequisite(
                id="outbound_inference_consent",
                status="passed" if consent_ok else "blocked",
                remediation=(
                    "Active outbound inference data-sharing consent recorded."
                    if consent_ok
                    else (
                        "Grant explicit outbound inference consent before autonomous repair "
                        "can run."
                    )
                ),
            )
        )

        # 4. Model probe & positive budget ceiling (Phase 6)
        model_row = by_phase["model_consent"]
        raw_budget_str = str(
            model_row.draft_payload_json.get("max_cost_per_session_amount", "0") or "0"
        )
        budget_amount = Decimal(raw_budget_str)
        model_probe_passed = model_row.status == "completed" and model_row.probe_status == "passed"
        budget_ok = budget_amount > Decimal("0")
        model_ok = model_probe_passed and budget_ok
        if not budget_ok and model_row.status == "completed":
            model_prereq_status: PrerequisiteStatus = "blocked"
            model_remediation = (
                "Per-session model cost cap is $0.00; configure a positive budget ceiling."
            )
        elif model_ok:
            model_prereq_status = "passed"
            model_remediation = model_row.probe_detail or "Model endpoint and budget verified."
        else:
            model_prereq_status = (
                cast(PrerequisiteStatus, model_row.probe_status)
                if model_row.probe_status is not None
                else "not_configured"
            )
            model_remediation = (
                model_row.probe_detail
                or "Verify model connectivity and configure a non-zero session cost cap."
            )
        prereqs.append(
            SetupPrerequisite(
                id="model_inference_and_budget",
                status=model_prereq_status,
                remediation=model_remediation,
            )
        )

        # 5. Isolated Z3 sandbox worker self-test (Phase 7)
        worker_row = by_phase["worker_readiness"]
        worker_ok = worker_row.status == "completed" and worker_row.probe_status == "passed"
        worker_prereq_status: PrerequisiteStatus = (
            "passed"
            if worker_ok
            else (
                cast(PrerequisiteStatus, worker_row.probe_status)
                if worker_row.probe_status is not None
                else "not_configured"
            )
        )
        prereqs.append(
            SetupPrerequisite(
                id="isolated_worker_sandbox",
                status=worker_prereq_status,
                remediation=(
                    worker_row.probe_detail or "Isolated Z3 worker self-test verified."
                    if worker_ok
                    else (
                        worker_row.probe_detail
                        or "Verify an isolated Z3 sandbox worker before enabling repair execution."
                    )
                ),
            )
        )

        # 6. Repository safety policy guardrails (Phase 8)
        policy_row = by_phase["repo_policy"]
        policy_ok = policy_row.status == "completed"
        prereqs.append(
            SetupPrerequisite(
                id="repository_safety_policy",
                status="passed" if policy_ok else "not_configured",
                remediation=(
                    "Baseline proof requirement and no-auto-merge guardrails confirmed."
                    if policy_ok
                    else "Confirm repository baseline proof and no-auto-merge policy in Phase 8."
                ),
            )
        )

        ready_repair = ready_monitor and consent_ok and model_ok and worker_ok and policy_ok
        readiness: SetupReadiness = (
            "ready_repair" if ready_repair else ("ready_monitor" if ready_monitor else "not_ready")
        )
        return ready_monitor, ready_repair, readiness, prereqs

    async def _build_setup_state_dto(
        self,
        db: AsyncSession,
        *,
        instance_row: InstanceModel,
        by_phase: Mapping[SetupWizardPhase, SetupCheckpointModel],
    ) -> SetupState:
        current_row = next(
            (r for r in by_phase.values() if r.is_current_phase),
            by_phase["readiness_review"],
        )
        ready_monitor, ready_repair, readiness, prereqs = await self._evaluate_readiness(
            db, by_phase=by_phase
        )
        ws_draft = by_phase["workspace_admin"].draft_payload_json
        default_ws_id = cast(str | None, ws_draft.get("workspace_id"))
        default_ws_slug = cast(str | None, ws_draft.get("workspace_slug"))

        review_row = by_phase["readiness_review"]
        steps = [
            SetupStepSummary(
                phase=phase_name,
                status=cast(SetupStepStatus, by_phase[phase_name].status),
                optional=phase_name in OPTIONAL_SETUP_PHASES,
                redacted_draft=dict(by_phase[phase_name].draft_payload_json),
                probe_status=cast(PrerequisiteStatus | None, by_phase[phase_name].probe_status),
                probe_detail=by_phase[phase_name].probe_detail,
                updated_at=by_phase[phase_name].updated_at,
            )
            for phase_name in SETUP_WIZARD_PHASES
        ]
        max_updated = max(r.updated_at for r in by_phase.values())
        total_version = sum(r.version for r in by_phase.values())
        return SetupState(
            id=instance_row.id,
            version=max(1, total_version),
            created_at=instance_row.created_at,
            updated_at=max_updated,
            phase=cast(SetupWizardPhase, current_row.phase),
            checkpoint=current_row.checkpoint_token,
            owner_claimed=True,
            prerequisites=prereqs,
            readiness=readiness,
            ready_monitor=ready_monitor,
            ready_repair=ready_repair,
            completed_at=review_row.completed_at,
            default_workspace_id=default_ws_id,
            default_workspace_slug=default_ws_slug,
            steps=steps,
        )

    async def get_setup_state(
        self,
        request: Request,
        *,
        correlation_id: str,
    ) -> tuple[SetupState, AuthenticatedContext | None]:
        """Return unclaimed `owner_claim` state pre-bootstrap, or owner-gated `SetupState`."""
        assert_no_secret_in_query_url(request)
        ref_now = self._iam.now()

        async with instance_rls_session(self._iam.session_factory, mode="instance_only") as db:
            inst = await db.scalar(select(InstanceModel))
            owner_count = int(
                (
                    await db.scalar(
                        select(func.count())
                        .select_from(UserModel)
                        .where(UserModel.is_instance_owner.is_(True))
                    )
                )
                or 0
            )
            unclaimed = (inst is None or inst.initialized_at is None) and owner_count == 0
            if unclaimed:
                inst_id = inst.id if inst is not None else "00000000-0000-7000-8000-000000000000"
                created = inst.created_at if inst is not None else ref_now
                steps = [
                    SetupStepSummary(
                        phase=p,
                        status="pending",
                        optional=p in OPTIONAL_SETUP_PHASES,
                        redacted_draft={},
                        probe_status=None,
                        probe_detail=None,
                        updated_at=None,
                    )
                    for p in SETUP_WIZARD_PHASES
                ]
                return (
                    SetupState(
                        id=inst_id,
                        version=1,
                        created_at=created,
                        updated_at=ref_now,
                        phase="owner_claim",
                        checkpoint="ckpt_unclaimed",
                        owner_claimed=False,
                        prerequisites=[
                            SetupPrerequisite(
                                id="owner_bootstrap_claim",
                                status="needs_admin",
                                remediation=(
                                    "Claim the initial instance_owner account with the "
                                    "one-time CLI bootstrap token."
                                ),
                            )
                        ],
                        readiness="not_ready",
                        ready_monitor=False,
                        ready_repair=False,
                        completed_at=None,
                        default_workspace_id=None,
                        default_workspace_slug=None,
                        steps=steps,
                    ),
                    None,
                )

        auth = await self._require_instance_owner(
            request,
            require_csrf=False,
            action="setup.state_read",
            correlation_id=correlation_id,
        )
        async with instance_rls_session(self._iam.session_factory, mode="instance_admin") as db:
            instance_row = await db.scalar(select(InstanceModel).with_for_update())
            if instance_row is None:
                raise DependencyUnavailableError(
                    code="instance_uninitialized",
                    detail="Singleton instance record is missing.",
                )
            by_phase = await self._ensure_checkpoints_initialized(
                db,
                instance_row=instance_row,
                owner_user_id=auth.user.id,
                now=ref_now,
            )
            dto = await self._build_setup_state_dto(
                db, instance_row=instance_row, by_phase=by_phase
            )
            return dto, auth

    async def _set_current_phase(
        self,
        db: AsyncSession,
        *,
        instance_id: str,
        by_phase: Mapping[SetupWizardPhase, SetupCheckpointModel],
        target_phase: SetupWizardPhase,
        new_checkpoint: str,
        now: datetime,
    ) -> None:
        await db.execute(
            update(SetupCheckpointModel)
            .where(
                SetupCheckpointModel.instance_id == instance_id,
                SetupCheckpointModel.is_current_phase.is_(True),
            )
            .values(is_current_phase=False)
        )
        await db.flush()
        for row in by_phase.values():
            row.is_current_phase = False
        target_row = by_phase[target_phase]
        target_row.is_current_phase = True
        target_row.checkpoint_token = new_checkpoint
        target_row.version += 1
        target_row.updated_at = now
        await db.flush()

    async def _run_optional_phase_probe(
        self,
        phase: SetupWizardPhase,
        draft: Mapping[str, Any],
        *,
        default_unprobed_detail: str,
    ) -> tuple[SetupStepStatus, PrerequisiteStatus, str, list[str]]:
        probe = self._registry.get_probe(phase)
        if probe is None:
            return (
                "not_configured",
                "not_configured",
                default_unprobed_detail,
                [f"{phase}_probe_unregistered"],
            )
        verdict = await probe(phase, draft)
        clean_detail = self._redactor.redact_text(verdict.detail)[:500]
        if verdict.probe_status == "passed":
            return ("completed", "passed", clean_detail, [])
        if verdict.probe_status == "not_configured":
            return (
                "not_configured",
                "not_configured",
                clean_detail,
                list(verdict.blocking_reasons),
            )
        return (
            "blocked",
            verdict.probe_status,
            clean_detail,
            list(verdict.blocking_reasons) or [f"{phase}_{verdict.probe_status}"],
        )

    async def submit_step(
        self,
        phase: SetupWizardPhase,
        payload: SetupStepSubmitRequest,
        request: Request,
        *,
        correlation_id: str,
    ) -> tuple[SetupState, AuthenticatedContext]:
        """Validate `expected_checkpoint`, persist redacted phase state, and recompute readiness."""
        assert_no_secret_in_query_url(request)
        auth = await self._require_instance_owner(
            request,
            require_csrf=True,
            action=f"setup.step.{phase}",
            correlation_id=correlation_id,
        )
        ref_now = self._iam.now()
        client_ip = extract_client_ip(request)

        async with instance_rls_session(self._iam.session_factory, mode="instance_admin") as db:
            instance_row = await db.scalar(select(InstanceModel).with_for_update())
            if instance_row is None or instance_row.initialized_at is None:
                raise ConflictError(
                    code="owner_claim_required",
                    detail="Initial instance_owner bootstrap claim must be completed first.",
                )

            by_phase = await self._ensure_checkpoints_initialized(
                db,
                instance_row=instance_row,
                owner_user_id=auth.user.id,
                now=ref_now,
            )
            current_row = next(
                (r for r in by_phase.values() if r.is_current_phase),
                by_phase["readiness_review"],
            )

            if payload.expected_checkpoint != current_row.checkpoint_token:
                raise ConflictError(
                    code="checkpoint_conflict",
                    detail=(
                        f"Expected setup checkpoint '{payload.expected_checkpoint}' is stale; "
                        "reload setup state and retry."
                    ),
                )

            new_ckpt = _mint_checkpoint_token(ref_now)
            step_row = by_phase[phase]

            if payload.action == "back":
                nav_target: SetupWizardPhase = "topology_tls" if phase == "owner_claim" else phase
                await self._set_current_phase(
                    db,
                    instance_id=instance_row.id,
                    by_phase=by_phase,
                    target_phase=nav_target,
                    new_checkpoint=new_ckpt,
                    now=ref_now,
                )
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="setup.step_revisited",
                    target=f"setup_phase:{nav_target}",
                    decision="allow",
                    reason_code="wizard_back_navigation",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                return (
                    await self._build_setup_state_dto(
                        db, instance_row=instance_row, by_phase=by_phase
                    ),
                    auth,
                )

            if payload.action == "skip":
                if phase not in OPTIONAL_SETUP_PHASES:
                    raise UnprocessableEntityError(
                        code="mandatory_phase_cannot_skip",
                        detail=f"Setup phase '{phase}' is mandatory and cannot be skipped.",
                    )
                step_row.status = "not_configured"
                step_row.probe_status = "not_configured"
                step_row.probe_detail = (
                    "Skipped by instance owner; capability remains not_configured."
                )
                step_row.blocking_reasons_json = [f"{phase}_skipped"]
                if payload.draft_notes:
                    step_row.draft_payload_json = _scrub_draft_dict(
                        {"skipped": True, "draft_notes": dict(payload.draft_notes)},
                        redactor=self._redactor,
                    )
                else:
                    step_row.draft_payload_json = {"skipped": True}
                step_row.completed_by_user_id = auth.user.id
                step_row.completed_at = None
                step_row.version += 1
                step_row.updated_at = ref_now

                next_target = _next_phase(phase)
                await self._set_current_phase(
                    db,
                    instance_id=instance_row.id,
                    by_phase=by_phase,
                    target_phase=next_target,
                    new_checkpoint=new_ckpt,
                    now=ref_now,
                )
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="setup.step_skipped",
                    target=f"setup_phase:{phase}",
                    decision="allow",
                    reason_code="optional_phase_not_configured",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={"next_phase": next_target},
                    occurred_at=ref_now,
                )
                return (
                    await self._build_setup_state_dto(
                        db, instance_row=instance_row, by_phase=by_phase
                    ),
                    auth,
                )

            # action == "save"
            advance_on_save = True

            if phase == "owner_claim":
                step_row.status = "completed"
                step_row.probe_status = "passed"
                step_row.probe_detail = "Initial instance_owner bootstrap claim verified."
                step_row.completed_by_user_id = auth.user.id
                step_row.completed_at = step_row.completed_at or ref_now

            elif phase == "topology_tls":
                dep_mode = payload.deployment_mode or cast(Any, instance_row.deployment_mode)
                base_url = (payload.public_base_url or instance_row.public_base_url).strip()
                parsed_url = urlparse(base_url)
                scheme_lower = parsed_url.scheme.lower()
                host_lower = (parsed_url.hostname or "").lower()
                tls_mode = payload.tls_mode or (
                    "loopback_http" if scheme_lower == "http" else "reverse_proxy_https"
                )

                is_loopback = host_lower in _LOOPBACK_HOSTS
                if dep_mode != "local" or not is_loopback:
                    if scheme_lower != "https" or tls_mode == "loopback_http":
                        raise UnprocessableEntityError(
                            code="tls_required_for_remote_topology",
                            detail=(
                                "Non-loopback or server/distributed deployments must use "
                                "an https:// public_base_url with TLS termination."
                            ),
                        )
                elif scheme_lower not in ("http", "https"):
                    raise UnprocessableEntityError(
                        code="invalid_public_base_url",
                        detail="public_base_url must use http:// (loopback only) or https://.",
                    )

                instance_row.deployment_mode = dep_mode
                instance_row.public_base_url = base_url
                instance_row.config_revision += 1
                instance_row.version += 1
                instance_row.updated_at = ref_now

                step_row.draft_payload_json = _scrub_draft_dict(
                    {
                        "deployment_mode": dep_mode,
                        "public_base_url": base_url,
                        "tls_mode": tls_mode,
                        **(
                            {"draft_notes": dict(payload.draft_notes)}
                            if payload.draft_notes
                            else {}
                        ),
                    },
                    redactor=self._redactor,
                )
                step_row.status = "completed"
                step_row.probe_status = "passed"
                step_row.probe_detail = f"Topology '{dep_mode}' and origin '{base_url}' validated."
                step_row.blocking_reasons_json = []
                step_row.completed_by_user_id = auth.user.id
                step_row.completed_at = ref_now

            elif phase == "storage_keys":
                if payload.master_key_custody_confirmed is not True:
                    raise UnprocessableEntityError(
                        code="kek_custody_confirmation_required",
                        detail=(
                            "Confirm master encryption key (KEK) backup custody before "
                            "advancing storage setup."
                        ),
                    )
                storage_backend = payload.storage_backend or "local"
                retention_days = (
                    payload.backup_retention_days
                    if payload.backup_retention_days is not None
                    else 30
                )
                if storage_backend == "s3_compatible" and payload.artifact_endpoint_id is not None:
                    ep = await db.scalar(
                        select(EndpointRegistrationModel).where(
                            EndpointRegistrationModel.id == payload.artifact_endpoint_id,
                            EndpointRegistrationModel.adapter == "s3_artifacts",
                            EndpointRegistrationModel.revoked_at.is_(None),
                        )
                    )
                    if ep is None:
                        raise NotFoundError(
                            code="endpoint_not_found",
                            detail=(
                                "Referenced s3_artifacts endpoint registration was not found "
                                "or is revoked."
                            ),
                        )
                step_row.draft_payload_json = _scrub_draft_dict(
                    {
                        "storage_backend": storage_backend,
                        "master_key_custody_confirmed": True,
                        "backup_retention_days": retention_days,
                        "artifact_endpoint_id": payload.artifact_endpoint_id,
                        "secret_configured": payload.secret_ref is not None,
                        **(
                            {"draft_notes": dict(payload.draft_notes)}
                            if payload.draft_notes
                            else {}
                        ),
                    },
                    redactor=self._redactor,
                )
                step_row.status = "completed"
                step_row.probe_status = "passed"
                step_row.probe_detail = (
                    f"PostgreSQL 16 durability and '{storage_backend}' artifact custody confirmed."
                )
                step_row.blocking_reasons_json = []
                step_row.completed_by_user_id = auth.user.id
                step_row.completed_at = ref_now

            elif phase == "workspace_admin":
                existing_ws_id = cast(str | None, step_row.draft_payload_json.get("workspace_id"))
                ws_row: WorkspaceModel | None = None
                if existing_ws_id is not None:
                    ws_row = await db.scalar(
                        select(WorkspaceModel).where(
                            WorkspaceModel.id == existing_ws_id,
                            WorkspaceModel.status != "deleting",
                        )
                    )
                if ws_row is None:
                    ws_name = (payload.workspace_name or "").strip()
                    if not ws_name:
                        raise UnprocessableEntityError(
                            code="workspace_name_required",
                            detail="workspace_name is required to provision the initial workspace.",
                        )
                    desired_slug = (
                        payload.workspace_slug
                        if payload.workspace_slug is not None
                        else slugify_workspace_name(ws_name)
                    )
                    existing_by_slug = await db.scalar(
                        select(WorkspaceModel).where(WorkspaceModel.slug == desired_slug)
                    )
                    if existing_by_slug is not None:
                        ws_row = existing_by_slug
                    else:
                        ws_row = WorkspaceModel(
                            id=new_uuid7(now=ref_now),
                            name=ws_name,
                            slug=desired_slug,
                            owner_user_id=auth.user.id,
                            status="active",
                            paused=False,
                            retention_policy={},
                            last_event_seq=0,
                            version=1,
                            created_at=ref_now,
                            updated_at=ref_now,
                            deleted_at=None,
                        )
                        db.add(ws_row)
                        await db.flush()

                    existing_member = await db.scalar(
                        select(MembershipModel).where(
                            MembershipModel.workspace_id == ws_row.id,
                            MembershipModel.user_id == auth.user.id,
                        )
                    )
                    if existing_member is None:
                        db.add(
                            MembershipModel(
                                id=new_uuid7(now=ref_now),
                                workspace_id=ws_row.id,
                                user_id=auth.user.id,
                                role="admin",
                                invited_by_user_id=auth.user.id,
                                version=1,
                                created_at=ref_now,
                                updated_at=ref_now,
                            )
                        )
                        await db.flush()
                elif payload.workspace_name is not None:
                    ws_row.name = payload.workspace_name.strip()
                    ws_row.version += 1
                    ws_row.updated_at = ref_now
                    await db.flush()

                step_row.draft_payload_json = _scrub_draft_dict(
                    {
                        "workspace_id": ws_row.id,
                        "workspace_name": ws_row.name,
                        "workspace_slug": ws_row.slug,
                        **(
                            {"draft_notes": dict(payload.draft_notes)}
                            if payload.draft_notes
                            else {}
                        ),
                    },
                    redactor=self._redactor,
                )
                step_row.status = "completed"
                step_row.probe_status = "passed"
                step_row.probe_detail = (
                    f"Initial workspace '{ws_row.slug}' provisioned with admin membership."
                )
                step_row.blocking_reasons_json = []
                step_row.completed_by_user_id = auth.user.id
                step_row.completed_at = ref_now

            elif phase == "provider_connect":
                if (
                    payload.provider is None
                    or payload.provider_base_url is None
                    or payload.auth_mode is None
                ):
                    raise UnprocessableEntityError(
                        code="provider_fields_required",
                        detail=(
                            "provider, provider_base_url, and auth_mode are required "
                            "(or use action='skip')."
                        ),
                    )
                parsed_prov = urlparse(payload.provider_base_url)
                prov_scheme = parsed_prov.scheme.lower()
                if prov_scheme == "http":
                    if payload.endpoint_registration_id is None:
                        raise UnprocessableEntityError(
                            code="provider_https_required",
                            detail=(
                                "Cleartext http:// provider_base_url requires an explicit "
                                "owner-registered private endpoint_registration_id."
                            ),
                        )
                    ep_row = await db.scalar(
                        select(EndpointRegistrationModel).where(
                            EndpointRegistrationModel.id == payload.endpoint_registration_id,
                            EndpointRegistrationModel.adapter == payload.provider,
                            EndpointRegistrationModel.scheme == "http",
                            EndpointRegistrationModel.revoked_at.is_(None),
                        )
                    )
                    if ep_row is None:
                        raise ForbiddenError(
                            code="egress_cleartext_http_denied",
                            detail="No active HTTP endpoint registration matches this provider.",
                        )
                elif prov_scheme != "https":
                    raise UnprocessableEntityError(
                        code="provider_https_required",
                        detail="provider_base_url must use https://.",
                    )

                prov_draft = _scrub_draft_dict(
                    {
                        "provider": payload.provider,
                        "provider_base_url": payload.provider_base_url,
                        "auth_mode": payload.auth_mode,
                        "endpoint_registration_id": payload.endpoint_registration_id,
                        "provider_consent_id": payload.provider_consent_id,
                        "secret_configured": payload.secret_ref is not None,
                        **(
                            {"draft_notes": dict(payload.draft_notes)}
                            if payload.draft_notes
                            else {}
                        ),
                    },
                    redactor=self._redactor,
                )
                st, pr_status, pr_detail, blockers = await self._run_optional_phase_probe(
                    "provider_connect",
                    prov_draft,
                    default_unprobed_detail=(
                        "Provider settings saved; live webhook/API capability probe is "
                        "not_configured."
                    ),
                )
                step_row.draft_payload_json = prov_draft
                step_row.status = st
                step_row.probe_status = pr_status
                step_row.probe_detail = pr_detail
                step_row.blocking_reasons_json = blockers
                step_row.completed_by_user_id = auth.user.id
                step_row.completed_at = ref_now if st == "completed" else None
                advance_on_save = st in ("completed", "not_configured")

            elif phase == "model_consent":
                if payload.primary_model is None or payload.max_cost_per_session is None:
                    raise UnprocessableEntityError(
                        code="model_fields_required",
                        detail=(
                            "primary_model and max_cost_per_session are required "
                            "(or use action='skip')."
                        ),
                    )
                if payload.inference_consent_id is not None:
                    consent_row = await db.scalar(
                        select(ConsentModel).where(
                            ConsentModel.id == payload.inference_consent_id,
                            ConsentModel.purpose == "inference",
                            ConsentModel.revoked_at.is_(None),
                        )
                    )
                    if consent_row is None:
                        raise ConflictError(
                            code="inference_consent_missing",
                            detail=(
                                "Referenced inference_consent_id does not exist or has been "
                                "revoked."
                            ),
                        )

                budget_amount = payload.max_cost_per_session.amount
                model_draft = _scrub_draft_dict(
                    {
                        "primary_model": payload.primary_model,
                        "escalation_model": payload.escalation_model,
                        "inference_consent_id": payload.inference_consent_id,
                        "max_cost_per_session_currency": payload.max_cost_per_session.currency,
                        "max_cost_per_session_amount": format(budget_amount, "f"),
                        "max_tokens_per_session": payload.max_tokens_per_session or 64_000,
                        "max_calls_per_session": payload.max_calls_per_session or 12,
                        "secret_configured": payload.secret_ref is not None,
                        **(
                            {"draft_notes": dict(payload.draft_notes)}
                            if payload.draft_notes
                            else {}
                        ),
                    },
                    redactor=self._redactor,
                )
                st, pr_status, pr_detail, blockers = await self._run_optional_phase_probe(
                    "model_consent",
                    model_draft,
                    default_unprobed_detail=(
                        "Model settings saved; live Meta inference probe is not_configured."
                    ),
                )
                if budget_amount <= Decimal("0"):
                    blockers = [*blockers, "model_budget_zero"]
                    pr_detail = (
                        "Model budget is set to $0.00; autonomous repair remains blocked "
                        "until a positive per-session cost ceiling is configured."
                    )
                step_row.draft_payload_json = model_draft
                step_row.status = st
                step_row.probe_status = pr_status
                step_row.probe_detail = pr_detail
                step_row.blocking_reasons_json = blockers
                step_row.completed_by_user_id = auth.user.id
                step_row.completed_at = ref_now if st == "completed" else None
                advance_on_save = st in ("completed", "not_configured")

            elif phase == "worker_readiness":
                if payload.sandbox_backend is None or payload.runtime_profile_id is None:
                    raise UnprocessableEntityError(
                        code="worker_fields_required",
                        detail=(
                            "sandbox_backend and runtime_profile_id are required "
                            "(or use action='skip')."
                        ),
                    )
                if payload.host_escape_risk_acknowledged is not True:
                    raise UnprocessableEntityError(
                        code="worker_isolation_acknowledgement_required",
                        detail=(
                            "Confirm isolated non-privileged sandbox constraints "
                            "(host_escape_risk_acknowledged=true) before saving."
                        ),
                    )
                worker_draft = _scrub_draft_dict(
                    {
                        "sandbox_backend": payload.sandbox_backend,
                        "runtime_profile_id": payload.runtime_profile_id,
                        "host_escape_risk_acknowledged": True,
                        "run_self_test": bool(payload.run_self_test),
                        **(
                            {"draft_notes": dict(payload.draft_notes)}
                            if payload.draft_notes
                            else {}
                        ),
                    },
                    redactor=self._redactor,
                )
                st, pr_status, pr_detail, blockers = await self._run_optional_phase_probe(
                    "worker_readiness",
                    worker_draft,
                    default_unprobed_detail=(
                        "Sandbox profile saved; isolated Z3 worker self-test is not_configured."
                    ),
                )
                step_row.draft_payload_json = worker_draft
                step_row.status = st
                step_row.probe_status = pr_status
                step_row.probe_detail = pr_detail
                step_row.blocking_reasons_json = blockers
                step_row.completed_by_user_id = auth.user.id
                step_row.completed_at = ref_now if st == "completed" else None
                advance_on_save = st in ("completed", "not_configured")

            elif phase == "repo_policy":
                if payload.require_baseline is False:
                    raise UnprocessableEntityError(
                        code="baseline_proof_mandatory",
                        detail=(
                            "require_baseline must remain true "
                            "(ADR-031 deterministic proof invariant)."
                        ),
                    )
                if payload.auto_merge is True:
                    raise UnprocessableEntityError(
                        code="auto_merge_forbidden",
                        detail=(
                            "Autonomous PR/MR auto-merge is permanently forbidden by Red2PR policy."
                        ),
                    )
                repo_mode = payload.default_repo_mode or "monitor"
                if repo_mode == "auto_repair":
                    # Pre-verify repair gates before allowing default auto_repair mode!
                    _, candidate_repair_ready, _, _ = await self._evaluate_readiness(
                        db,
                        by_phase={
                            **by_phase,
                            "repo_policy": SetupCheckpointModel(
                                id=step_row.id,
                                instance_id=instance_row.id,
                                phase="repo_policy",
                                phase_order=8,
                                status="completed",
                                is_current_phase=True,
                                checkpoint_token=step_row.checkpoint_token,
                                draft_payload_json={},
                                probe_status="passed",
                            ),
                        },
                    )
                    if not candidate_repair_ready:
                        raise ConflictError(
                            code="readiness_gate_unmet",
                            detail=(
                                "default_repo_mode='auto_repair' cannot be enabled until "
                                "provider connectivity, outbound inference consent, positive "
                                "model budget, and isolated worker self-test have all passed."
                            ),
                        )

                policy_draft = _scrub_draft_dict(
                    {
                        "default_repo_mode": repo_mode,
                        "require_baseline": True,
                        "auto_merge": False,
                        "max_attempts": payload.max_attempts or 2,
                        "max_diff_lines": payload.max_diff_lines or 500,
                        "protected_branches": list(
                            payload.protected_branches or ["main", "release/*"]
                        ),
                        **(
                            {"draft_notes": dict(payload.draft_notes)}
                            if payload.draft_notes
                            else {}
                        ),
                    },
                    redactor=self._redactor,
                )
                if self._registry.get_probe("repo_policy") is None:
                    step_row.draft_payload_json = policy_draft
                    step_row.status = "completed"
                    step_row.probe_status = "passed"
                    step_row.probe_detail = (
                        f"Default repository mode '{repo_mode}' saved with require_baseline=true "
                        "and auto_merge=false."
                    )
                    step_row.blocking_reasons_json = []
                    step_row.completed_by_user_id = auth.user.id
                    step_row.completed_at = ref_now
                else:
                    st, pr_status, pr_detail, blockers = await self._run_optional_phase_probe(
                        "repo_policy",
                        policy_draft,
                        default_unprobed_detail=(f"Default repository mode '{repo_mode}' saved."),
                    )
                    step_row.draft_payload_json = policy_draft
                    step_row.status = st
                    step_row.probe_status = pr_status
                    step_row.probe_detail = pr_detail
                    step_row.blocking_reasons_json = blockers
                    step_row.completed_by_user_id = auth.user.id
                    step_row.completed_at = ref_now if st == "completed" else None
                    advance_on_save = st == "completed"

            elif phase == "notifications":
                notif_channel = payload.channel or "in_app"
                telem_mode = payload.telemetry_mode or "local_only"

                if notif_channel != "in_app" and payload.notification_consent_id is not None:
                    notif_consent = await db.scalar(
                        select(ConsentModel).where(
                            ConsentModel.id == payload.notification_consent_id,
                            ConsentModel.purpose == "notification",
                            ConsentModel.revoked_at.is_(None),
                        )
                    )
                    if notif_consent is None:
                        raise ConflictError(
                            code="notification_consent_missing",
                            detail=(
                                "Referenced notification_consent_id does not exist or is revoked."
                            ),
                        )

                if telem_mode == "consented_export":
                    active_telem = int(
                        (
                            await db.scalar(
                                select(func.count())
                                .select_from(ConsentModel)
                                .where(
                                    ConsentModel.purpose == "telemetry",
                                    ConsentModel.revoked_at.is_(None),
                                )
                            )
                        )
                        or 0
                    )
                    if active_telem == 0:
                        raise ConflictError(
                            code="telemetry_consent_required",
                            detail=(
                                "telemetry_mode='consented_export' requires an active "
                                "purpose='telemetry' consent grant."
                            ),
                        )

                notif_draft = _scrub_draft_dict(
                    {
                        "channel": notif_channel,
                        "notification_consent_id": payload.notification_consent_id,
                        "telemetry_mode": telem_mode,
                        "telemetry_consent_id": payload.telemetry_consent_id,
                        "secret_configured": payload.secret_ref is not None,
                        **(
                            {"draft_notes": dict(payload.draft_notes)}
                            if payload.draft_notes
                            else {}
                        ),
                    },
                    redactor=self._redactor,
                )
                if notif_channel == "in_app" and self._registry.get_probe("notifications") is None:
                    step_row.draft_payload_json = notif_draft
                    step_row.status = "completed"
                    step_row.probe_status = "passed"
                    step_row.probe_detail = "In-app operator notifications enabled (local-only)."
                    step_row.blocking_reasons_json = []
                    step_row.completed_by_user_id = auth.user.id
                    step_row.completed_at = ref_now
                else:
                    st, pr_status, pr_detail, blockers = await self._run_optional_phase_probe(
                        "notifications",
                        notif_draft,
                        default_unprobed_detail=(
                            f"External channel '{notif_channel}' saved; "
                            "delivery probe is not_configured."
                        ),
                    )
                    step_row.draft_payload_json = notif_draft
                    step_row.status = st
                    step_row.probe_status = pr_status
                    step_row.probe_detail = pr_detail
                    step_row.blocking_reasons_json = blockers
                    step_row.completed_by_user_id = auth.user.id
                    step_row.completed_at = ref_now if st == "completed" else None
                    advance_on_save = st in ("completed", "not_configured")

            elif phase == "readiness_review":
                (
                    ready_monitor,
                    ready_repair,
                    computed_readiness,
                    prereqs,
                ) = await self._evaluate_readiness(db, by_phase=by_phase)
                requested = payload.target_readiness
                if requested == "ready_repair" and not ready_repair:
                    unmet = [p.id for p in prereqs if p.status != "passed"]
                    raise ConflictError(
                        code="readiness_gate_unmet",
                        detail=(
                            "Cannot certify instance as ready_repair while prerequisites "
                            f"remain unmet: {', '.join(unmet)}."
                        ),
                    )
                if requested == "ready_monitor" and not ready_monitor:
                    unmet = [
                        p.id
                        for p in prereqs
                        if p.id
                        in ("foundation_topology_storage_workspace", "provider_connectivity")
                        and p.status != "passed"
                    ]
                    raise ConflictError(
                        code="readiness_gate_unmet",
                        detail=(
                            "Cannot certify instance as ready_monitor while prerequisites "
                            f"remain unmet: {', '.join(unmet)}."
                        ),
                    )
                step_row.draft_payload_json = _scrub_draft_dict(
                    {
                        "certified_readiness": computed_readiness,
                        "notes": payload.notes or "",
                    },
                    redactor=self._redactor,
                )
                step_row.status = "completed"
                step_row.probe_status = "passed"
                step_row.probe_detail = (
                    f"Setup wizard completed with verified readiness='{computed_readiness}'."
                )
                step_row.blocking_reasons_json = []
                step_row.completed_by_user_id = auth.user.id
                step_row.completed_at = ref_now
                advance_on_save = False

            target_next = _next_phase(phase) if advance_on_save else phase
            await self._set_current_phase(
                db,
                instance_id=instance_row.id,
                by_phase=by_phase,
                target_phase=target_next,
                new_checkpoint=new_ckpt,
                now=ref_now,
            )
            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=auth.user.id,
                action="setup.step_saved",
                target=f"setup_phase:{phase}",
                decision="allow",
                reason_code=f"status_{step_row.status}",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={
                    "phase": phase,
                    "status": step_row.status,
                    "probe_status": step_row.probe_status,
                    "next_phase": target_next,
                },
                occurred_at=ref_now,
            )
            return (
                await self._build_setup_state_dto(db, instance_row=instance_row, by_phase=by_phase),
                auth,
            )

    async def list_consents(
        self,
        request: Request,
        *,
        purpose: ConsentPurpose | None,
        include_revoked: bool,
        correlation_id: str,
    ) -> tuple[ConsentRecordPage, AuthenticatedContext]:
        assert_no_secret_in_query_url(request)
        auth = await self._require_instance_owner(
            request,
            require_csrf=False,
            action="setup.consents_list",
            correlation_id=correlation_id,
        )
        ref_now = self._iam.now()
        async with instance_rls_session(self._iam.session_factory, mode="instance_admin") as db:
            stmt = select(ConsentModel)
            if purpose is not None:
                stmt = stmt.where(ConsentModel.purpose == purpose)
            if not include_revoked:
                stmt = stmt.where(ConsentModel.revoked_at.is_(None))
            stmt = stmt.order_by(ConsentModel.created_at.desc(), ConsentModel.id.desc()).limit(100)
            rows = (await db.scalars(stmt)).all()
            return (
                ConsentRecordPage(
                    items=[_to_consent_dto(r) for r in rows],
                    next_cursor=None,
                    snapshot_at=ref_now,
                ),
                auth,
            )

    async def grant_consent(
        self,
        payload: ConsentCreateRequest,
        request: Request,
        *,
        correlation_id: str,
    ) -> tuple[ConsentRecord, AuthenticatedContext]:
        assert_no_secret_in_query_url(request)
        auth = await self._require_instance_owner(
            request,
            require_csrf=True,
            action="setup.consent_grant",
            correlation_id=correlation_id,
        )
        ref_now = self._iam.now()
        client_ip = extract_client_ip(request)

        async with instance_rls_session(self._iam.session_factory, mode="instance_admin") as db:
            if payload.workspace_id is not None:
                ws = await db.scalar(
                    select(WorkspaceModel.id).where(
                        WorkspaceModel.id == payload.workspace_id,
                        WorkspaceModel.status != "deleting",
                    )
                )
                if ws is None:
                    raise NotFoundError(
                        code="workspace_not_found",
                        detail="Target workspace for consent grant does not exist.",
                    )

            row = ConsentModel(
                id=new_uuid7(now=ref_now),
                purpose=payload.purpose,
                scope=payload.scope,
                workspace_id=payload.workspace_id,
                repository_id=payload.repository_id,
                destination=payload.destination,
                data_classes_json=list(payload.data_classes),
                granted_by_user_id=auth.user.id,
                granted_at=ref_now,
                revoked_by_user_id=None,
                revoked_at=None,
                revoke_reason=None,
                policy_version=1,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(row)
            await db.flush()
            await append_audit_entry(
                db,
                workspace_id=payload.workspace_id,
                repository_id=payload.repository_id,
                actor_type="user",
                actor_id=auth.user.id,
                action="setup.consent_granted",
                target=f"consent:{row.id}",
                decision="allow",
                reason_code=f"purpose_{payload.purpose}",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={
                    "purpose": payload.purpose,
                    "scope": payload.scope,
                    "destination": payload.destination,
                    "data_classes": list(payload.data_classes),
                },
                occurred_at=ref_now,
            )
            return _to_consent_dto(row), auth

    async def revoke_consent(
        self,
        consent_id: str,
        payload: ConsentRevokeRequest,
        request: Request,
        *,
        correlation_id: str,
    ) -> tuple[ConsentRecord, AuthenticatedContext]:
        assert_no_secret_in_query_url(request)
        auth = await self._require_instance_owner(
            request,
            require_csrf=True,
            action="setup.consent_revoke",
            correlation_id=correlation_id,
        )
        ref_now = self._iam.now()
        client_ip = extract_client_ip(request)

        async with instance_rls_session(self._iam.session_factory, mode="instance_admin") as db:
            row = await db.scalar(
                select(ConsentModel).where(ConsentModel.id == consent_id).with_for_update()
            )
            if row is None:
                raise NotFoundError(
                    code="consent_not_found",
                    detail="Consent record not found.",
                )
            if row.revoked_at is None:
                row.revoked_at = ref_now
                row.revoked_by_user_id = auth.user.id
                row.revoke_reason = (
                    self._redactor.redact_text(payload.reason)[:500]
                    if payload.reason
                    else "Revoked by instance owner"
                )
                row.version += 1
                row.updated_at = ref_now
                await db.flush()
                await append_audit_entry(
                    db,
                    workspace_id=row.workspace_id,
                    repository_id=row.repository_id,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="setup.consent_revoked",
                    target=f"consent:{row.id}",
                    decision="allow",
                    reason_code=f"purpose_{row.purpose}_revoked",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={"purpose": row.purpose, "scope": row.scope},
                    occurred_at=ref_now,
                )
            return _to_consent_dto(row), auth

    async def list_endpoints(
        self,
        request: Request,
        *,
        adapter: EgressAdapterKind | None,
        include_revoked: bool,
        correlation_id: str,
    ) -> tuple[EndpointRegistrationPage, AuthenticatedContext]:
        assert_no_secret_in_query_url(request)
        auth = await self._require_instance_owner(
            request,
            require_csrf=False,
            action="security.endpoints_list",
            correlation_id=correlation_id,
        )
        ref_now = self._iam.now()
        async with instance_rls_session(self._iam.session_factory, mode="instance_admin") as db:
            stmt = select(EndpointRegistrationModel)
            if adapter is not None:
                stmt = stmt.where(EndpointRegistrationModel.adapter == adapter)
            if not include_revoked:
                stmt = stmt.where(EndpointRegistrationModel.revoked_at.is_(None))
            stmt = stmt.order_by(
                EndpointRegistrationModel.created_at.desc(),
                EndpointRegistrationModel.id.desc(),
            ).limit(100)
            rows = (await db.scalars(stmt)).all()
            return (
                EndpointRegistrationPage(
                    items=[_to_endpoint_dto(r) for r in rows],
                    next_cursor=None,
                    snapshot_at=ref_now,
                ),
                auth,
            )

    async def register_endpoint(
        self,
        payload: EndpointRegistrationCreateRequest,
        request: Request,
        *,
        correlation_id: str,
    ) -> tuple[EndpointRegistration, AuthenticatedContext]:
        assert_no_secret_in_query_url(request)
        auth = await self._require_owner_with_step_up(
            request,
            action="security.endpoint_register",
            correlation_id=correlation_id,
        )
        ref_now = self._iam.now()
        client_ip = extract_client_ip(request)

        async with instance_rls_session(self._iam.session_factory, mode="instance_admin") as db:
            row = EndpointRegistrationModel(
                id=new_uuid7(now=ref_now),
                adapter=payload.adapter,
                scheme=payload.scheme,
                host=payload.host,
                port=payload.port,
                cidrs_json=list(payload.cidrs),
                ca_ref=payload.ca_ref,
                description=(
                    self._redactor.redact_text(payload.description)[:500]
                    if payload.description
                    else None
                ),
                created_by_user_id=auth.user.id,
                revoked_by_user_id=None,
                revoked_at=None,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(row)
            try:
                await db.flush()
            except IntegrityError as exc:
                raise ConflictError(
                    code="endpoint_already_registered",
                    detail=(
                        f"An active endpoint registration already exists for "
                        f"({payload.adapter}, {payload.scheme}://{payload.host}:{payload.port})."
                    ),
                ) from exc

            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=auth.user.id,
                action="security.endpoint_registered",
                target=f"endpoint_registration:{row.id}",
                decision="allow",
                reason_code="owner_step_up_verified",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={
                    "adapter": payload.adapter,
                    "scheme": payload.scheme,
                    "host": payload.host,
                    "port": payload.port,
                    "cidrs": list(payload.cidrs),
                    "has_ca_ref": payload.ca_ref is not None,
                },
                occurred_at=ref_now,
            )
            return _to_endpoint_dto(row), auth

    async def revoke_endpoint(
        self,
        endpoint_id: str,
        request: Request,
        *,
        correlation_id: str,
    ) -> tuple[EndpointRegistration, AuthenticatedContext]:
        assert_no_secret_in_query_url(request)
        auth = await self._require_owner_with_step_up(
            request,
            action="security.endpoint_revoke",
            correlation_id=correlation_id,
        )
        ref_now = self._iam.now()
        client_ip = extract_client_ip(request)

        async with instance_rls_session(self._iam.session_factory, mode="instance_admin") as db:
            row = await db.scalar(
                select(EndpointRegistrationModel)
                .where(EndpointRegistrationModel.id == endpoint_id)
                .with_for_update()
            )
            if row is None:
                raise NotFoundError(
                    code="endpoint_not_found",
                    detail="Endpoint registration not found.",
                )
            if row.revoked_at is None:
                row.revoked_at = ref_now
                row.revoked_by_user_id = auth.user.id
                row.version += 1
                row.updated_at = ref_now
                await db.flush()
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="security.endpoint_revoked",
                    target=f"endpoint_registration:{row.id}",
                    decision="allow",
                    reason_code="owner_step_up_verified",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={
                        "adapter": row.adapter,
                        "scheme": row.scheme,
                        "host": row.host,
                        "port": row.port,
                    },
                    occurred_at=ref_now,
                )
            return _to_endpoint_dto(row), auth


def _correlation_id(request: Request) -> str:
    state_corr = getattr(request.state, "correlation_id", None)
    if isinstance(state_corr, str) and state_corr:
        return state_corr
    return current_correlation_id()


def _apply_no_store_headers(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _maybe_refresh_csrf(
    response: Response,
    *,
    auth: AuthenticatedContext | None,
    iam: IamService,
) -> None:
    if auth is not None and auth.csrf_cookie_refreshed:
        set_csrf_cookie(response, csrf_token=auth.csrf_token, secure=iam.secure_cookies)


def get_setup_wizard_service(
    request: Request,
    iam: Annotated[IamService, Depends(get_iam_service)],
) -> SetupWizardService:
    """Resolve `SetupWizardService` from `app.state` or construct on `IamService`."""
    existing = getattr(request.app.state, "setup_wizard_service", None)
    if isinstance(existing, SetupWizardService):
        return existing
    registry = getattr(request.app.state, "setup_step_registry", None)
    svc = SetupWizardService(
        iam_service=iam,
        step_registry=registry if isinstance(registry, SetupStepRegistry) else None,
    )
    request.app.state.setup_wizard_service = svc
    return svc


def build_setup_router() -> APIRouter:
    """Create the `/api/v1/setup` onboarding, consent ledger & private endpoint registry router."""
    router = APIRouter(prefix="/api/v1/setup", tags=["setup"])

    @router.get(
        "",
        operation_id="getSetupState",
        response_model=SetupState,
        summary="Read durable 10-phase setup wizard checkpoint and readiness state (A-01, INS-02)",
        responses=_PROBLEM_RESPONSES,
    )
    async def get_setup_state(
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        svc: Annotated[SetupWizardService, Depends(get_setup_wizard_service)],
    ) -> SetupState:
        _apply_no_store_headers(response)
        dto, auth = await svc.get_setup_state(
            request,
            correlation_id=_correlation_id(request),
        )
        _maybe_refresh_csrf(response, auth=auth, iam=iam)
        return dto

    @router.post(
        "/steps/{phase}",
        operation_id="submitSetupStep",
        response_model=SetupState,
        summary="Save, skip, or revisit a 10-phase setup step with checkpoint locking (A-01)",
        responses=_PROBLEM_RESPONSES,
    )
    async def submit_setup_step(
        phase: SetupWizardPhase,
        payload: SetupStepSubmitRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        svc: Annotated[SetupWizardService, Depends(get_setup_wizard_service)],
    ) -> SetupState:
        _apply_no_store_headers(response)
        dto, auth = await svc.submit_step(
            phase,
            payload,
            request,
            correlation_id=_correlation_id(request),
        )
        _maybe_refresh_csrf(response, auth=auth, iam=iam)
        return dto

    @router.get(
        "/consents",
        operation_id="listSetupConsents",
        response_model=ConsentRecordPage,
        summary="List explicit outbound data-sharing consent records by purpose (S-18, SEC-018)",
        responses=_PROBLEM_RESPONSES,
    )
    async def list_setup_consents(
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        svc: Annotated[SetupWizardService, Depends(get_setup_wizard_service)],
        purpose: Annotated[ConsentPurpose | None, Query()] = None,
        include_revoked: Annotated[bool, Query()] = False,
    ) -> ConsentRecordPage:
        _apply_no_store_headers(response)
        page, auth = await svc.list_consents(
            request,
            purpose=purpose,
            include_revoked=include_revoked,
            correlation_id=_correlation_id(request),
        )
        _maybe_refresh_csrf(response, auth=auth, iam=iam)
        return page

    @router.post(
        "/consents",
        operation_id="grantSetupConsent",
        status_code=status.HTTP_201_CREATED,
        response_model=ConsentRecord,
        summary="Grant explicit per-purpose outbound data-sharing consent (S-18, SEC-018)",
        responses=_PROBLEM_RESPONSES,
    )
    async def grant_setup_consent(
        payload: ConsentCreateRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        svc: Annotated[SetupWizardService, Depends(get_setup_wizard_service)],
    ) -> ConsentRecord:
        _apply_no_store_headers(response)
        dto, auth = await svc.grant_consent(
            payload,
            request,
            correlation_id=_correlation_id(request),
        )
        _maybe_refresh_csrf(response, auth=auth, iam=iam)
        return dto

    @router.delete(
        "/consents/{consent_id}",
        operation_id="revokeSetupConsent",
        response_model=ConsentRecord,
        summary="Revoke an outbound data-sharing consent record and recompute readiness (S-18)",
        responses=_PROBLEM_RESPONSES,
    )
    async def revoke_setup_consent(
        consent_id: Annotated[InternalId, Path()],
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        svc: Annotated[SetupWizardService, Depends(get_setup_wizard_service)],
        payload: Annotated[ConsentRevokeRequest, Body()] = _EMPTY_REVOKE_CONSENT,
    ) -> ConsentRecord:
        _apply_no_store_headers(response)
        dto, auth = await svc.revoke_consent(
            consent_id,
            payload,
            request,
            correlation_id=_correlation_id(request),
        )
        _maybe_refresh_csrf(response, auth=auth, iam=iam)
        return dto

    @router.get(
        "/endpoints",
        operation_id="listEndpointRegistrations",
        response_model=EndpointRegistrationPage,
        summary="List owner-registered private egress endpoints (ADR-037)",
        responses=_PROBLEM_RESPONSES,
    )
    async def list_endpoint_registrations(
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        svc: Annotated[SetupWizardService, Depends(get_setup_wizard_service)],
        adapter: Annotated[EgressAdapterKind | None, Query()] = None,
        include_revoked: Annotated[bool, Query()] = False,
    ) -> EndpointRegistrationPage:
        _apply_no_store_headers(response)
        page, auth = await svc.list_endpoints(
            request,
            adapter=adapter,
            include_revoked=include_revoked,
            correlation_id=_correlation_id(request),
        )
        _maybe_refresh_csrf(response, auth=auth, iam=iam)
        return page

    @router.post(
        "/endpoints",
        operation_id="registerPrivateEndpoint",
        status_code=status.HTTP_201_CREATED,
        response_model=EndpointRegistration,
        summary="Register a private service endpoint allowlist entry (owner + 5m step-up, ADR-037)",
        responses=_PROBLEM_RESPONSES,
    )
    async def register_private_endpoint(
        payload: EndpointRegistrationCreateRequest,
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        svc: Annotated[SetupWizardService, Depends(get_setup_wizard_service)],
    ) -> EndpointRegistration:
        _apply_no_store_headers(response)
        dto, auth = await svc.register_endpoint(
            payload,
            request,
            correlation_id=_correlation_id(request),
        )
        _maybe_refresh_csrf(response, auth=auth, iam=iam)
        return dto

    @router.delete(
        "/endpoints/{endpoint_id}",
        operation_id="revokePrivateEndpoint",
        response_model=EndpointRegistration,
        summary="Revoke a private service endpoint allowlist entry (owner + 5m step-up, ADR-037)",
        responses=_PROBLEM_RESPONSES,
    )
    async def revoke_private_endpoint(
        endpoint_id: Annotated[InternalId, Path()],
        request: Request,
        response: Response,
        iam: Annotated[IamService, Depends(get_iam_service)],
        svc: Annotated[SetupWizardService, Depends(get_setup_wizard_service)],
    ) -> EndpointRegistration:
        _apply_no_store_headers(response)
        dto, auth = await svc.revoke_endpoint(
            endpoint_id,
            request,
            correlation_id=_correlation_id(request),
        )
        _maybe_refresh_csrf(response, auth=auth, iam=iam)
        return dto

    return router
