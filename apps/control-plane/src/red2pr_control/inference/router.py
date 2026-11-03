"""FastAPI `/api/v1` router for `A-20` workspace Meta models, probes & agent profiles (`U17`)."""

from __future__ import annotations

import hashlib
import os
from typing import Annotated, cast

from fastapi import APIRouter, Body, Depends, Header, Path, Request, Response
from sqlalchemy import select

from py_contracts.crypto import MasterKeyRing
from py_contracts.extensions import ModelFallbackPolicyRequest, ModelFallbackPolicyResponse
from py_contracts.integrations import ConsentRecord, ConsentRevokeRequest
from py_contracts.models import (
    AgentProfile,
    AgentProfileUpdateRequest,
    AgentProfileUpdateResponse,
    ModelProbeRequest,
    ModelProbeResponse,
    WorkspaceAgentProfilesResponse,
    WorkspaceInferenceConsentCreateRequest,
    WorkspaceModelsConfigUpdateRequest,
    WorkspaceModelsConfigUpdateResponse,
    WorkspaceModelsResponse,
    validate_supported_meta_model_id,
)
from py_contracts.primitives import Problem, new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    PROBLEM_JSON_MEDIA_TYPE,
    BadRequestError,
    DependencyUnavailableError,
    ForbiddenError,
    NotFoundError,
    PreconditionFailedError,
    UnprocessableEntityError,
)
from red2pr_control.core.keyring import load_master_key_ring_from_file
from red2pr_control.core.logging import current_correlation_id
from red2pr_control.db.base import (
    ModelCapabilitySnapshotModel,
    ModelFallbackPolicyModel,
    RepositoryModel,
    WorkspaceAgentProfileModel,
)
from red2pr_control.db.idempotency import (
    claim_idempotent_operation,
    complete_idempotent_operation,
)
from red2pr_control.db.rls import workspace_rls_session
from red2pr_control.extensions.model_fallback import FallbackReason
from red2pr_control.iam.csrf import set_csrf_cookie
from red2pr_control.iam.rbac import (
    ADMIN_ONLY_ROLES,
    ALL_WORKSPACE_ROLES,
    WorkspaceAccessContext,
    format_version_etag,
    make_workspace_rbac_dependency,
    parse_if_match_version,
)
from red2pr_control.iam.sessions import IamService, extract_client_ip, is_step_up_fresh
from red2pr_control.inference.agent_profiles import AgentProfileService
from red2pr_control.inference.meta_client import MetaMuseInferenceService
from red2pr_control.secrets.broker import SecretBroker

_COMMON_PROBLEM_RESPONSES: dict[int | str, dict[str, object]] = {
    400: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    401: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    403: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    404: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    409: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    410: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    412: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    422: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    429: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
    503: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
}

_EMPTY_CONSENT_REVOKE = ConsentRevokeRequest()


def _req_corr_id(request: Request) -> str:
    state_corr = getattr(request.state, "correlation_id", None)
    if isinstance(state_corr, str) and state_corr:
        return state_corr
    return current_correlation_id()


def _resolve_iam(request: Request) -> IamService:
    svc = getattr(request.app.state, "iam_service", None)
    if not isinstance(svc, IamService):
        raise DependencyUnavailableError(
            code="iam_unconfigured",
            detail="IAM persistence service is not configured on this control-plane instance.",
        )
    return svc


def _resolve_meta_inference_service(request: Request) -> MetaMuseInferenceService:
    svc = getattr(request.app.state, "meta_inference_service", None)
    if isinstance(svc, MetaMuseInferenceService):
        return svc
    iam = _resolve_iam(request)
    broker = getattr(request.app.state, "notification_secret_broker", None)
    if not isinstance(broker, SecretBroker):
        if os.environ.get("RED2PR_MASTER_KEY_FILE", "").strip():
            key_ring = load_master_key_ring_from_file()
        else:
            derived_kek = hashlib.sha256(
                b"red2pr:default_secret_kek:v1:" + iam.csrf_signing_key
            ).digest()
            key_ring = MasterKeyRing(active_version=1, keys={1: derived_kek})
        broker = SecretBroker(key_ring=key_ring)
        request.app.state.notification_secret_broker = broker
    created = MetaMuseInferenceService(
        iam_service=iam,
        secret_broker=broker,
    )
    registry = getattr(request.app.state, "setup_step_registry", None)
    if registry is not None:
        created.register_setup_probe(registry)
    request.app.state.meta_inference_service = created
    return created


def _resolve_agent_profile_service(request: Request) -> AgentProfileService:
    svc = getattr(request.app.state, "agent_profile_service", None)
    if isinstance(svc, AgentProfileService):
        return svc
    iam = _resolve_iam(request)
    meta = _resolve_meta_inference_service(request)
    created = AgentProfileService(
        session_factory=iam.session_factory,
        iam_service=iam,
        meta_inference_service=meta,
    )
    request.app.state.agent_profile_service = created
    return created


def _maybe_refresh_csrf(
    response: Response,
    ws_ctx: WorkspaceAccessContext,
    iam: IamService,
) -> None:
    if ws_ctx.auth.csrf_cookie_refreshed:
        set_csrf_cookie(response, csrf_token=ws_ctx.auth.csrf_token, secure=iam.secure_cookies)


def _require_idempotency_key(raw_key: str | None, *, endpoint_label: str) -> str:
    if not raw_key or not raw_key.strip():
        raise BadRequestError(
            code="missing_idempotency_key",
            detail=f"{endpoint_label} requires an S-05 Idempotency-Key UUIDv7 header.",
        )
    return raw_key.strip()


_require_models_read = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="models.read",
)

_require_models_admin = make_workspace_rbac_dependency(
    allowed_roles=ADMIN_ONLY_ROLES,
    require_csrf=True,
    allow_break_glass=False,
    action="models.mutate",
)

_require_agent_profiles_read = make_workspace_rbac_dependency(
    allowed_roles=ALL_WORKSPACE_ROLES,
    require_csrf=False,
    allow_break_glass=True,
    action="agent_profiles.read",
)

_require_agent_profiles_admin = make_workspace_rbac_dependency(
    allowed_roles=ADMIN_ONLY_ROLES,
    require_csrf=True,
    allow_break_glass=False,
    action="agent_profiles.mutate",
)


def build_inference_router() -> APIRouter:
    """Build `/api/v1` router exposing `A-20` workspace Meta models, probes & agent profiles."""
    router = APIRouter(prefix="/api/v1")

    @router.get(
        "/workspaces/{ws}/repositories/{repository_id}/model-fallback",
        operation_id="getRepositoryModelFallbackPolicy",
        tags=["models"],
        response_model=ModelFallbackPolicyResponse | None,
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def get_repository_model_fallback_policy(
        repository_id: Annotated[str, Path(min_length=36, max_length=36)],
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_models_read)],
        response: Response,
        iam: Annotated[IamService, Depends(_resolve_iam)],
    ) -> ModelFallbackPolicyResponse | None:
        if not ws_ctx.can_read_repository(repository_id):
            raise NotFoundError(code="repository_not_found", detail="Repository was not found.")
        async with workspace_rls_session(
            iam.session_factory, workspace_id=ws_ctx.workspace.id
        ) as db:
            row = await db.scalar(
                select(ModelFallbackPolicyModel).where(
                    ModelFallbackPolicyModel.workspace_id == ws_ctx.workspace.id,
                    ModelFallbackPolicyModel.repository_id == repository_id,
                )
            )
            if row is None:
                return None
            response.headers["ETag"] = format_version_etag(row.version)
            return ModelFallbackPolicyResponse(
                id=row.id,
                version=row.version,
                workspace_id=row.workspace_id,
                repository_id=row.repository_id,
                primary_model_profile_id=row.primary_model_profile_id,
                secondary_model_profile_id=row.secondary_model_profile_id,
                consent_id=row.consent_id,
                enabled=row.enabled,
                last_fallback_at=row.last_fallback_at,
                last_fallback_reason=cast(FallbackReason | None, row.last_fallback_reason),
            )

    @router.put(
        "/workspaces/{ws}/repositories/{repository_id}/model-fallback",
        operation_id="putRepositoryModelFallbackPolicy",
        tags=["models"],
        response_model=ModelFallbackPolicyResponse,
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def put_repository_model_fallback_policy(
        repository_id: Annotated[str, Path(min_length=36, max_length=36)],
        payload: ModelFallbackPolicyRequest,
        request: Request,
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_models_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[MetaMuseInferenceService, Depends(_resolve_meta_inference_service)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
        if_match: Annotated[str | None, Header(alias="If-Match", max_length=64)] = None,
    ) -> ModelFallbackPolicyResponse:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label=(
                "PUT /api/v1/workspaces/{ws}/repositories/{repository_id}/model-fallback"
            ),
        )
        if not ws_ctx.can_act_on_repository(repository_id, allowed_roles={"admin"}):
            raise NotFoundError(code="repository_not_found", detail="Repository was not found.")
        if not is_step_up_fresh(ws_ctx.auth.session, now=iam.now()):
            raise ForbiddenError(
                code="step_up_required", detail="Fresh 5-minute step-up is required."
            )
        async with workspace_rls_session(
            iam.session_factory, workspace_id=ws_ctx.workspace.id
        ) as db:
            repo = await db.scalar(
                select(RepositoryModel).where(
                    RepositoryModel.workspace_id == ws_ctx.workspace.id,
                    RepositoryModel.id == repository_id,
                )
            )
            if repo is None:
                raise NotFoundError(code="repository_not_found", detail="Repository was not found.")
            consent, consent_error = await svc._verify_active_inference_consent_in_tx(
                db,
                workspace_id=ws_ctx.workspace.id,
                consent_id=payload.consent_id,
                endpoint_base_url=(
                    await svc._ensure_workspace_config_in_tx(
                        db, workspace_id=ws_ctx.workspace.id, now=iam.now()
                    )
                ).endpoint_base_url,
                repository_id=repository_id,
            )
            if consent_error is not None or consent is None:
                raise ForbiddenError(
                    code="repository_inference_consent_required",
                    detail="An active inference consent scoped to this repository is required.",
                )
            profiles = list(
                (
                    await db.scalars(
                        select(WorkspaceAgentProfileModel).where(
                            WorkspaceAgentProfileModel.workspace_id == ws_ctx.workspace.id,
                            WorkspaceAgentProfileModel.id.in_(
                                {
                                    payload.primary_model_profile_id,
                                    payload.secondary_model_profile_id,
                                }
                            ),
                        )
                    )
                ).all()
            )
            profiles_by_id = {profile.id: profile for profile in profiles}
            primary_profile = profiles_by_id.get(payload.primary_model_profile_id)
            secondary_profile = profiles_by_id.get(payload.secondary_model_profile_id)
            if primary_profile is None or secondary_profile is None:
                raise NotFoundError(
                    code="model_profile_not_found",
                    detail="Both model profiles must belong to this workspace.",
                )
            if not primary_profile.enabled or not secondary_profile.enabled:
                raise UnprocessableEntityError(
                    code="model_profile_disabled",
                    detail="Fallback policies require two enabled model profiles.",
                )
            primary_model_id = validate_supported_meta_model_id(primary_profile.model_id)
            secondary_model_id = validate_supported_meta_model_id(secondary_profile.model_id)
            if primary_model_id == secondary_model_id:
                raise UnprocessableEntityError(
                    code="fallback_profiles_same_model",
                    detail="Primary and secondary model profiles must use different models.",
                )
            if payload.enabled:
                snapshot = await db.scalar(
                    select(ModelCapabilitySnapshotModel)
                    .where(
                        ModelCapabilitySnapshotModel.workspace_id == ws_ctx.workspace.id,
                        ModelCapabilitySnapshotModel.model_id == secondary_model_id,
                        ModelCapabilitySnapshotModel.status == "available",
                    )
                    .order_by(
                        ModelCapabilitySnapshotModel.probed_at.desc(),
                        ModelCapabilitySnapshotModel.id.desc(),
                    )
                    .limit(1)
                )
                if snapshot is None:
                    raise ForbiddenError(
                        code="fallback_model_not_probed",
                        detail="The secondary model must have a successful capability probe.",
                    )
            row = await db.scalar(
                select(ModelFallbackPolicyModel)
                .where(
                    ModelFallbackPolicyModel.workspace_id == ws_ctx.workspace.id,
                    ModelFallbackPolicyModel.repository_id == repository_id,
                )
                .with_for_update()
            )
            resource_id = row.id if row is not None else new_uuid7(now=iam.now())
            current_version = row.version if row is not None else 0
            claim = await claim_idempotent_operation(
                db,
                workspace_id=ws_ctx.workspace.id,
                principal_id=ws_ctx.auth.user.id,
                operation="extension.agt04.model_fallback.configure",
                idempotency_key=idem,
                request_payload={
                    "payload": payload.model_dump(mode="json"),
                    "if_match": if_match,
                },
                logical_effect_key=(f"model-fallback:{repository_id}:version:{current_version}"),
                resource_id=resource_id,
                correlation_id=_req_corr_id(request),
                now=iam.now(),
            )
            if not claim.is_new_claim and claim.cached_response is not None:
                replay = ModelFallbackPolicyResponse.model_validate(claim.cached_response)
                response.headers["ETag"] = format_version_etag(replay.version)
                return replay
            if row is None:
                if payload.expected_version is not None or if_match is not None:
                    raise PreconditionFailedError(
                        code="stale_policy_version",
                        detail="No policy exists for the supplied ETag.",
                    )
                row = ModelFallbackPolicyModel(
                    id=resource_id,
                    workspace_id=ws_ctx.workspace.id,
                    repository_id=repository_id,
                    primary_model_profile_id=payload.primary_model_profile_id,
                    secondary_model_profile_id=payload.secondary_model_profile_id,
                    trigger_conditions_json=["429", "503", "capability_unavailable"],
                    consent_id=consent.id,
                    enabled=payload.enabled,
                    updated_by_user_id=ws_ctx.auth.user.id,
                    version=1,
                    created_at=iam.now(),
                    updated_at=iam.now(),
                )
                db.add(row)
            else:
                supplied = payload.expected_version
                if if_match is not None:
                    supplied = parse_if_match_version(if_match)
                if supplied is None or supplied != row.version:
                    raise PreconditionFailedError(
                        code="stale_policy_version", detail="Reload the latest fallback policy."
                    )
                row.primary_model_profile_id = payload.primary_model_profile_id
                row.secondary_model_profile_id = payload.secondary_model_profile_id
                row.consent_id = consent.id
                row.enabled = payload.enabled
                row.updated_by_user_id = ws_ctx.auth.user.id
                row.version += 1
                row.updated_at = iam.now()
            await db.flush()
            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=ws_ctx.auth.user.id,
                action="extension.agt04.model_fallback.configure",
                target=f"repository:{repository_id}",
                decision="allow",
                reason_code="repository_fallback_policy_configured",
                correlation_id=_req_corr_id(request),
                workspace_id=ws_ctx.workspace.id,
                repository_id=repository_id,
                client_ip=extract_client_ip(request),
                metadata={
                    "enabled": row.enabled,
                    "primary_model_profile_id": row.primary_model_profile_id,
                    "secondary_model_profile_id": row.secondary_model_profile_id,
                    "version": row.version,
                },
                occurred_at=iam.now(),
            )
            result = ModelFallbackPolicyResponse(
                id=row.id,
                version=row.version,
                workspace_id=row.workspace_id,
                repository_id=row.repository_id,
                primary_model_profile_id=row.primary_model_profile_id,
                secondary_model_profile_id=row.secondary_model_profile_id,
                consent_id=row.consent_id,
                enabled=row.enabled,
                last_fallback_at=row.last_fallback_at,
                last_fallback_reason=cast(FallbackReason | None, row.last_fallback_reason),
            )
            await complete_idempotent_operation(
                db,
                workspace_id=ws_ctx.workspace.id,
                operation_id=claim.receipt.operation_id,
                state="succeeded",
                status_code=200,
                result_id=result.id,
                response_payload=result.model_dump(mode="json"),
                now=iam.now(),
            )
        response.headers["ETag"] = format_version_etag(result.version)
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return result

    @router.get(
        "/workspaces/{ws}/models",
        operation_id="listWorkspaceModels",
        tags=["models"],
        response_model=WorkspaceModelsResponse,
        summary="Get workspace Meta model registry, masked key presence, budgets & usage (A-20)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def list_workspace_models(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_models_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[MetaMuseInferenceService, Depends(_resolve_meta_inference_service)],
        response: Response,
    ) -> WorkspaceModelsResponse:
        dto = await svc.get_workspace_models(access=ws_ctx)
        response.headers["ETag"] = format_version_etag(dto.version)
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return dto

    @router.patch(
        "/workspaces/{ws}/models/config",
        operation_id="updateWorkspaceModelsConfig",
        tags=["models"],
        response_model=WorkspaceModelsConfigUpdateResponse,
        summary="Update workspace Meta API key, pricing, NFR-06 budgets & escalation policy (A-20)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def update_workspace_models_config(
        payload: WorkspaceModelsConfigUpdateRequest,
        request: Request,
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_models_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[MetaMuseInferenceService, Depends(_resolve_meta_inference_service)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
        if_match: Annotated[
            str | None,
            Header(alias="If-Match", max_length=64),
        ] = None,
    ) -> WorkspaceModelsConfigUpdateResponse:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label="PATCH /api/v1/workspaces/{ws}/models/config",
        )
        updated = await svc.update_workspace_models_config(
            access=ws_ctx,
            payload=payload,
            idempotency_key=idem,
            if_match_header=if_match,
            correlation_id=_req_corr_id(request),
            client_ip=extract_client_ip(request),
        )
        response.headers["ETag"] = format_version_etag(updated.models_state.version)
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return updated

    @router.post(
        "/workspaces/{ws}/models/consents",
        operation_id="grantWorkspaceInferenceConsent",
        tags=["models"],
        status_code=201,
        response_model=ConsentRecord,
        summary="Grant explicit workspace-scoped outbound Meta inference consent (SEC-018)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def grant_workspace_inference_consent(
        payload: WorkspaceInferenceConsentCreateRequest,
        request: Request,
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_models_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[MetaMuseInferenceService, Depends(_resolve_meta_inference_service)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
    ) -> ConsentRecord:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label="POST /api/v1/workspaces/{ws}/models/consents",
        )
        consent = await svc.grant_workspace_inference_consent(
            access=ws_ctx,
            payload=payload,
            idempotency_key=idem,
            correlation_id=_req_corr_id(request),
            client_ip=extract_client_ip(request),
        )
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return consent

    @router.delete(
        "/workspaces/{ws}/models/consents/{consent_id}",
        operation_id="revokeWorkspaceInferenceConsent",
        tags=["models"],
        response_model=ConsentRecord,
        summary="Revoke workspace-scoped outbound Meta inference consent (SEC-018)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def revoke_workspace_inference_consent(
        request: Request,
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_models_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[MetaMuseInferenceService, Depends(_resolve_meta_inference_service)],
        consent_id: Annotated[str, Path(min_length=1, max_length=64)],
        payload: Annotated[ConsentRevokeRequest, Body()] = _EMPTY_CONSENT_REVOKE,
    ) -> ConsentRecord:
        revoked = await svc.revoke_workspace_inference_consent(
            access=ws_ctx,
            consent_id=consent_id,
            reason=payload.reason,
            correlation_id=_req_corr_id(request),
            client_ip=extract_client_ip(request),
        )
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return revoked

    @router.post(
        "/workspaces/{ws}/model-probes",
        operation_id="createWorkspaceModelProbe",
        tags=["models"],
        response_model=ModelProbeResponse,
        summary="Run consented, budget-capped Meta Model API capability probe (A-20)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def create_workspace_model_probe(
        payload: ModelProbeRequest,
        request: Request,
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_models_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[MetaMuseInferenceService, Depends(_resolve_meta_inference_service)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
    ) -> ModelProbeResponse:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label="POST /api/v1/workspaces/{ws}/model-probes",
        )
        probe_res = await svc.probe_model(
            access=ws_ctx,
            payload=payload,
            idempotency_key=idem,
            correlation_id=_req_corr_id(request),
            client_ip=extract_client_ip(request),
        )
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return probe_res

    @router.get(
        "/workspaces/{ws}/agent-profiles",
        operation_id="listWorkspaceAgentProfiles",
        tags=["agents"],
        response_model=WorkspaceAgentProfilesResponse,
        summary="List bounded workspace agent profiles, S-20 tool matrix & recent steps (A-20)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def list_workspace_agent_profiles(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_agent_profiles_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[AgentProfileService, Depends(_resolve_agent_profile_service)],
        response: Response,
    ) -> WorkspaceAgentProfilesResponse:
        dto = await svc.list_workspace_agent_profiles(access=ws_ctx)
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return dto

    @router.get(
        "/workspaces/{ws}/agent-profiles/{profile_id}",
        operation_id="getWorkspaceAgentProfile",
        tags=["agents"],
        response_model=AgentProfile,
        summary="Get a workspace agent profile by ID or role_key (A-20)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def get_workspace_agent_profile(
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_agent_profiles_read)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[AgentProfileService, Depends(_resolve_agent_profile_service)],
        response: Response,
        profile_id: Annotated[str, Path(min_length=1, max_length=64)],
    ) -> AgentProfile:
        dto = await svc.get_workspace_agent_profile(access=ws_ctx, profile_id=profile_id)
        response.headers["ETag"] = format_version_etag(dto.version)
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return dto

    @router.patch(
        "/workspaces/{ws}/agent-profiles/{profile_id}",
        operation_id="updateWorkspaceAgentProfile",
        tags=["agents"],
        response_model=AgentProfileUpdateResponse,
        summary="Update bounded workspace agent profile within immutable S-20 ceilings (A-20)",
        responses=_COMMON_PROBLEM_RESPONSES,
    )
    async def update_workspace_agent_profile(
        payload: AgentProfileUpdateRequest,
        request: Request,
        response: Response,
        ws_ctx: Annotated[WorkspaceAccessContext, Depends(_require_agent_profiles_admin)],
        iam: Annotated[IamService, Depends(_resolve_iam)],
        svc: Annotated[AgentProfileService, Depends(_resolve_agent_profile_service)],
        profile_id: Annotated[str, Path(min_length=1, max_length=64)],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key", max_length=128),
        ] = None,
        if_match: Annotated[
            str | None,
            Header(alias="If-Match", max_length=64),
        ] = None,
    ) -> AgentProfileUpdateResponse:
        idem = _require_idempotency_key(
            idempotency_key,
            endpoint_label="PATCH /api/v1/workspaces/{ws}/agent-profiles/{profile_id}",
        )
        updated = await svc.update_workspace_agent_profile(
            access=ws_ctx,
            profile_id=profile_id,
            payload=payload,
            idempotency_key=idem,
            if_match=if_match,
            correlation_id=_req_corr_id(request),
            client_ip=extract_client_ip(request),
        )
        response.headers["ETag"] = format_version_etag(updated.profile.version)
        _maybe_refresh_csrf(response, ws_ctx, iam)
        return updated

    return router


__all__ = ["build_inference_router"]
