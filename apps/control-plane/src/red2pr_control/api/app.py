"""FastAPI /api/v1 application shell, S-03 Problem handlers, and OpenAPI v1 exporter (U02..U14).

Provides:
- Public minimal liveness route GET /api/v1/system/health (A-18).
- ASGI request correlation ID binding (X-Correlation-Id), 1 MiB JSON body ceiling (S-01),
  and 100 MiB worker artifact upload ceiling on `/internal/v1/jobs/{job_id}/upload` (NFR-14).
- Consistent S-03 application/problem+json handlers across 400..503 without traceback leaks.
- Deterministic OpenAPI 3.1 contract export registering all canonical S-01..S-22 DTO schemas.
"""

from __future__ import annotations

import json
import pathlib
import re
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from pydantic.json_schema import GenerateJsonSchema, models_json_schema
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from py_contracts import (
    MAX_JSON_BODY_BYTES,
    ActionReceipt,
    AffectedInFlightItem,
    Approval,
    Artifact,
    AuditRecord,
    BranchPolicyEvaluation,
    BreakGlassCreateRequest,
    BreakGlassGrant,
    BreakGlassGrantPage,
    BudgetAccountSummary,
    BudgetPolicyDefaults,
    BudgetReservationRecord,
    BulkRepositoryPreviewItem,
    BulkRepositoryPreviewRequest,
    BulkRepositoryPreviewResponse,
    BulkRepositoryUpdateRequest,
    BulkRepositoryUpdateResponse,
    CapabilitySnapshot,
    CiJob,
    CiJobListResponse,
    CiRun,
    CiRunDetailResponse,
    CiRunPage,
    Connection,
    ConnectionDetailResponse,
    ConnectionPage,
    ConnectionPatchRequest,
    ConnectionProbeResponse,
    ConnectionReconcileRequest,
    ConnectionReconcileResponse,
    ConnectionSyncResponse,
    ConnectionWrite,
    ConsentCreateRequest,
    ConsentRecord,
    ConsentRecordPage,
    ConsentRevokeRequest,
    CsrfBootstrapResponse,
    DeadLetterJobSummary,
    Diagnosis,
    EffectiveRepositoryPolicy,
    EndpointRegistration,
    EndpointRegistrationCreateRequest,
    EndpointRegistrationPage,
    EscalationPolicy,
    EventEnvelope,
    EvidenceManifestV1,
    FailureFingerprintObservation,
    FailureFingerprintSummary,
    GitHubCallbackResponse,
    GitHubInstallationConfirmRequest,
    GitHubInstallationConfirmResponse,
    GitHubInstallStateCreateRequest,
    GitHubInstallStateResponse,
    HistoricalRunSimulation,
    Invite,
    InviteAcceptRequest,
    InviteCreateRequest,
    InviteCreateResponse,
    InvitePage,
    JobLogChunkResponse,
    LifecycleOperation,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    Membership,
    MembershipPage,
    MemberUpdateRequest,
    MeResponse,
    MfaDeleteRequest,
    MfaEnrollRequest,
    MfaEnrollResponse,
    ModelCapabilityFlags,
    ModelCapabilitySnapshot,
    ModelPricingRate,
    ModelProbeRequest,
    ModelProbeResponse,
    ModelUsageRecord,
    Money,
    NotificationDelivery,
    NotificationDestination,
    NotificationPreference,
    PageParams,
    Patch,
    PathPolicyEvaluation,
    PolicyDenialItem,
    PolicyReadinessGates,
    PolicyRuleChange,
    Problem,
    ProblemFieldError,
    ProviderSyncCursor,
    Publication,
    RecoveryRequest,
    RecoveryResponse,
    RemoteCheck,
    Repair,
    ReportExportRequest,
    Repository,
    RepositoryAccessGrantSummary,
    RepositoryCatalogPage,
    RepositoryDetailResponse,
    RepositoryFacetSummary,
    RepositoryHistoryEntry,
    RepositoryPolicy,
    RepositoryPolicyPreviewRequest,
    RepositoryPolicyPreviewResponse,
    RepositoryPolicyRevision,
    RepositoryPolicyStateResponse,
    RepositoryPolicyUpdateRequest,
    RepositoryRunTriggerSummary,
    RepositoryUpdateRequest,
    ReproductionRunRecord,
    ResultV1,
    RunnerProfileCommandSpec,
    RunnerProfileManifest,
    SandboxJobV1,
    SecretPresence,
    Session,
    SessionListItem,
    SessionPage,
    SetupClaimRequest,
    SetupClaimResponse,
    SetupPrerequisite,
    SetupState,
    SetupStepSubmitRequest,
    SetupStepSummary,
    StepUpRequest,
    StepUpResponse,
    StrictContractModel,
    SystemHealthResponse,
    TaskAttemptSummary,
    TaskJob,
    TaskJobActionRequest,
    TaskJobDetail,
    TaskJobPage,
    TelegramLinkSummary,
    ToolCallRequest,
    ToolCallResponse,
    User,
    Verification,
    WebhookIngressReceipt,
    Worker,
    WorkerActionRequest,
    WorkerEnrollmentCreateRequest,
    WorkerEnrollmentCreateResponse,
    WorkerFleetSummary,
    WorkerPage,
    WorkerSelfTestResponse,
    WorkflowHazardFinding,
    Workspace,
    WorkspaceCreateRequest,
    WorkspaceDeleteRequest,
    WorkspaceInferenceConsentCreateRequest,
    WorkspaceModelEntry,
    WorkspaceModelsConfigUpdateRequest,
    WorkspaceModelsConfigUpdateResponse,
    WorkspaceModelsResponse,
    WorkspacePage,
    WorkspaceQueueFairnessSummary,
    WorkspaceSandboxLeaseSummary,
    WorkspaceUpdateRequest,
    WorkspaceWorkerReadinessResponse,
    new_uuid7,
)
from red2pr_control.core.errors import (
    PROBLEM_JSON_MEDIA_TYPE,
    PayloadTooLargeError,
    Red2PrError,
    build_problem,
    problem_from_exception,
)
from red2pr_control.core.logging import (
    bind_telemetry_context,
    current_correlation_id,
    get_structured_logger,
)
from red2pr_control.iam.router import build_iam_router
from red2pr_control.iam.sessions import IamService
from red2pr_control.inference import (
    MetaMuseInferenceService,
    build_inference_router,
)
from red2pr_control.integrations import (
    GitHubIntegrationService,
    LocalPollingService,
    MissedEventReconciler,
    WebhookIngestService,
    build_integrations_router,
    build_webhooks_router,
)
from red2pr_control.operations.setup_wizard import (
    SetupStepRegistry,
    SetupWizardService,
    build_setup_router,
)
from red2pr_control.orchestrator import (
    MAX_SANDBOX_UPLOAD_WIRE_BYTES,
    DurableTaskQueueService,
    OperationReceiptService,
    WorkerBrokerService,
    build_internal_worker_router,
    build_orchestrator_router,
)
from red2pr_control.repositories import (
    RepositoryCatalogService,
    build_repositories_router,
)
from red2pr_control.triage_evidence import (
    ArtifactStoreProtocol,
    TriageEvidenceService,
    build_triage_evidence_router,
)

CORRELATION_HEADER = "X-Correlation-Id"
_SAFE_CORR_RE = re.compile(r"^[A-Za-z0-9._:-]{1,120}$")
_INTERNAL_UPLOAD_PATH_RE = re.compile(r"^/internal/v1/jobs/[^/]+/upload$")
_LOGGER = get_structured_logger("red2pr_control.api")

CANONICAL_OPENAPI_MODELS: tuple[type[StrictContractModel], ...] = (
    Problem,
    ProblemFieldError,
    ActionReceipt,
    PageParams,
    Money,
    User,
    Session,
    SessionListItem,
    SessionPage,
    CsrfBootstrapResponse,
    SetupClaimRequest,
    SetupClaimResponse,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    StepUpRequest,
    StepUpResponse,
    RecoveryRequest,
    RecoveryResponse,
    TelegramLinkSummary,
    MeResponse,
    MfaEnrollRequest,
    MfaEnrollResponse,
    MfaDeleteRequest,
    Workspace,
    WorkspacePage,
    WorkspaceCreateRequest,
    WorkspaceUpdateRequest,
    WorkspaceDeleteRequest,
    Membership,
    MembershipPage,
    MemberUpdateRequest,
    Invite,
    InvitePage,
    InviteCreateRequest,
    InviteCreateResponse,
    InviteAcceptRequest,
    BreakGlassGrant,
    BreakGlassGrantPage,
    BreakGlassCreateRequest,
    SecretPresence,
    Connection,
    ConnectionPage,
    ConnectionWrite,
    ConnectionPatchRequest,
    CapabilitySnapshot,
    WorkflowHazardFinding,
    ConnectionDetailResponse,
    ConnectionProbeResponse,
    ConnectionSyncResponse,
    ConnectionReconcileRequest,
    ConnectionReconcileResponse,
    ProviderSyncCursor,
    WebhookIngressReceipt,
    GitHubInstallStateCreateRequest,
    GitHubInstallStateResponse,
    GitHubCallbackResponse,
    GitHubInstallationConfirmRequest,
    GitHubInstallationConfirmResponse,
    Repository,
    RepositoryAccessGrantSummary,
    RepositoryCatalogPage,
    RepositoryDetailResponse,
    RepositoryFacetSummary,
    RepositoryHistoryEntry,
    RepositoryPolicy,
    RepositoryPolicyPreviewRequest,
    RepositoryPolicyPreviewResponse,
    RepositoryPolicyRevision,
    RepositoryPolicyStateResponse,
    RepositoryPolicyUpdateRequest,
    RepositoryRunTriggerSummary,
    RepositoryUpdateRequest,
    AffectedInFlightItem,
    BranchPolicyEvaluation,
    BulkRepositoryPreviewItem,
    BulkRepositoryPreviewRequest,
    BulkRepositoryPreviewResponse,
    BulkRepositoryUpdateRequest,
    BulkRepositoryUpdateResponse,
    EffectiveRepositoryPolicy,
    HistoricalRunSimulation,
    PathPolicyEvaluation,
    PolicyDenialItem,
    PolicyReadinessGates,
    PolicyRuleChange,
    CiRun,
    CiRunDetailResponse,
    CiRunPage,
    CiJob,
    CiJobListResponse,
    FailureFingerprintObservation,
    FailureFingerprintSummary,
    JobLogChunkResponse,
    Repair,
    Diagnosis,
    Patch,
    Verification,
    Approval,
    Publication,
    RemoteCheck,
    Artifact,
    Worker,
    WorkerFleetSummary,
    WorkerPage,
    WorkerEnrollmentCreateRequest,
    WorkerEnrollmentCreateResponse,
    WorkerActionRequest,
    WorkerSelfTestResponse,
    WorkspaceSandboxLeaseSummary,
    WorkspaceWorkerReadinessResponse,
    TaskJob,
    TaskAttemptSummary,
    DeadLetterJobSummary,
    WorkspaceQueueFairnessSummary,
    TaskJobDetail,
    TaskJobPage,
    TaskJobActionRequest,
    NotificationDestination,
    NotificationDelivery,
    NotificationPreference,
    AuditRecord,
    ModelUsageRecord,
    BudgetAccountSummary,
    BudgetPolicyDefaults,
    BudgetReservationRecord,
    EscalationPolicy,
    ModelCapabilityFlags,
    ModelCapabilitySnapshot,
    ModelPricingRate,
    ModelProbeRequest,
    ModelProbeResponse,
    WorkspaceInferenceConsentCreateRequest,
    WorkspaceModelEntry,
    WorkspaceModelsConfigUpdateRequest,
    WorkspaceModelsConfigUpdateResponse,
    WorkspaceModelsResponse,
    ReportExportRequest,
    ConsentCreateRequest,
    ConsentRevokeRequest,
    ConsentRecord,
    ConsentRecordPage,
    EndpointRegistrationCreateRequest,
    EndpointRegistration,
    EndpointRegistrationPage,
    SetupPrerequisite,
    SetupStepSummary,
    SetupStepSubmitRequest,
    SetupState,
    LifecycleOperation,
    SystemHealthResponse,
    EventEnvelope,
    ToolCallRequest,
    ToolCallResponse,
    SandboxJobV1,
    ResultV1,
    RunnerProfileCommandSpec,
    RunnerProfileManifest,
    ReproductionRunRecord,
    EvidenceManifestV1,
)


def _extract_safe_correlation_id(headers: list[tuple[bytes, bytes]]) -> str:
    for raw_name, raw_val in headers:
        if raw_name.lower() == b"x-correlation-id":
            candidate = raw_val.decode("latin1", errors="ignore").strip()
            if _SAFE_CORR_RE.fullmatch(candidate):
                return candidate
            break
    return new_uuid7()


def _problem_json_response(
    problem: Problem,
    *,
    correlation_id: str,
    extra_headers: dict[str, str] | None = None,
) -> JSONResponse:
    headers = {CORRELATION_HEADER: correlation_id}
    if extra_headers:
        headers.update(extra_headers)
    return JSONResponse(
        status_code=problem.status,
        content=problem.model_dump(mode="json", exclude_none=True),
        media_type=PROBLEM_JSON_MEDIA_TYPE,
        headers=headers,
    )


class _CorrelationAndBodyLimitMiddleware:
    """Enforces S-01 1 MiB JSON body ceiling (100 MiB on mTLS upload) and correlation ID."""

    def __init__(self, app: ASGIApp, *, max_body_bytes: int = MAX_JSON_BODY_BYTES) -> None:
        self._app = app
        self._max_body_bytes = max_body_bytes

    def _effective_limit_for_scope(self, scope: Scope) -> int:
        method = str(scope.get("method", "")).upper()
        path = str(scope.get("path", ""))
        if method == "POST" and _INTERNAL_UPLOAD_PATH_RE.fullmatch(path):
            return MAX_SANDBOX_UPLOAD_WIRE_BYTES
        return self._max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        raw_headers: list[tuple[bytes, bytes]] = list(scope.get("headers", []))
        corr_id = _extract_safe_correlation_id(raw_headers)
        scope.setdefault("state", {})["correlation_id"] = corr_id
        max_bytes = self._effective_limit_for_scope(scope)

        with bind_telemetry_context(correlation_id=corr_id, entry_point="api"):
            for h_name, h_val in raw_headers:
                if h_name.lower() == b"content-length":
                    try:
                        declared_len = int(h_val.decode("ascii").strip())
                    except ValueError:
                        prob = build_problem(
                            status=400,
                            code="invalid_content_length",
                            title="Bad request",
                            detail="Malformed Content-Length header.",
                            correlation_id=corr_id,
                        )
                        resp = _problem_json_response(prob, correlation_id=corr_id)
                        await resp(scope, receive, send)
                        return
                    if declared_len > max_bytes:
                        too_large = PayloadTooLargeError(
                            detail=f"Request body exceeds maximum {max_bytes} bytes (S-01/NFR-14)."
                        )
                        prob = problem_from_exception(too_large, correlation_id=corr_id)
                        resp = _problem_json_response(prob, correlation_id=corr_id)
                        await resp(scope, receive, send)
                        return

            chunks: list[bytes] = []
            seen_bytes = 0
            body_complete = False
            while not body_complete:
                msg = await receive()
                if msg["type"] == "http.disconnect":
                    return
                if msg["type"] == "http.request":
                    chunk: bytes = msg.get("body", b"")
                    seen_bytes += len(chunk)
                    if seen_bytes > max_bytes:
                        too_large = PayloadTooLargeError(
                            detail=f"Request body exceeds maximum {max_bytes} bytes (S-01/NFR-14)."
                        )
                        prob = problem_from_exception(too_large, correlation_id=corr_id)
                        resp = _problem_json_response(prob, correlation_id=corr_id)
                        await resp(scope, receive, send)
                        return
                    if chunk:
                        chunks.append(chunk)
                    body_complete = not bool(msg.get("more_body", False))
                else:
                    body_complete = True

            buffered_body = b"".join(chunks)
            body_delivered = False

            async def _replay_receive() -> Message:
                nonlocal body_delivered
                if not body_delivered:
                    body_delivered = True
                    return {
                        "type": "http.request",
                        "body": buffered_body,
                        "more_body": False,
                    }
                return await receive()

            async def _correlated_send(message: Message) -> None:
                if message["type"] == "http.response.start":
                    out_headers: list[tuple[bytes, bytes]] = list(message.get("headers", []))
                    if not any(k.lower() == b"x-correlation-id" for k, _ in out_headers):
                        out_headers.append((CORRELATION_HEADER.encode("ascii"), corr_id.encode()))
                    message = {**message, "headers": out_headers}
                await send(message)

            await self._app(scope, _replay_receive, _correlated_send)


def _request_correlation_id(request: Request) -> str:
    state_corr = getattr(request.state, "correlation_id", None)
    if isinstance(state_corr, str) and state_corr:
        return state_corr
    return current_correlation_id()


def create_app(
    *,
    iam_service: IamService | None = None,
    setup_wizard_service: SetupWizardService | None = None,
    setup_step_registry: SetupStepRegistry | None = None,
    task_queue_service: DurableTaskQueueService | None = None,
    operation_receipt_service: OperationReceiptService | None = None,
    worker_broker_service: WorkerBrokerService | None = None,
    github_integration_service: GitHubIntegrationService | None = None,
    webhook_ingest_service: WebhookIngestService | None = None,
    polling_service: LocalPollingService | None = None,
    reconciler_service: MissedEventReconciler | None = None,
    repository_catalog_service: RepositoryCatalogService | None = None,
    triage_evidence_service: TriageEvidenceService | None = None,
    meta_inference_service: MetaMuseInferenceService | None = None,
    artifact_store: ArtifactStoreProtocol | None = None,
) -> FastAPI:
    """Create the FastAPI /api/v1 control-plane application shell."""
    app = FastAPI(
        title="Red2PR Control Plane API",
        version="1.0.0",
        description=(
            "Canonical /api/v1 HTTP boundary for Red2PR self-hosted autonomous CI/CD repair "
            "with deterministic proof."
        ),
        openapi_url="/api/v1/openapi.json",
        docs_url=None,
        redoc_url=None,
    )
    if github_integration_service is not None and setup_step_registry is not None:
        github_integration_service.register_setup_probe(setup_step_registry)
    if repository_catalog_service is not None and setup_step_registry is not None:
        repository_catalog_service.register_setup_probe(setup_step_registry)
    if worker_broker_service is not None and setup_step_registry is not None:
        worker_broker_service.register_setup_probe(setup_step_registry)
    if meta_inference_service is not None and setup_step_registry is not None:
        meta_inference_service.register_setup_probe(setup_step_registry)
    app.state.iam_service = iam_service
    app.state.setup_wizard_service = setup_wizard_service
    app.state.setup_step_registry = setup_step_registry
    app.state.task_queue_service = task_queue_service
    app.state.operation_receipt_service = operation_receipt_service
    app.state.worker_broker_service = worker_broker_service
    app.state.github_integration_service = github_integration_service
    app.state.webhook_ingest_service = webhook_ingest_service
    app.state.polling_service = polling_service
    app.state.reconciler_service = reconciler_service
    app.state.repository_catalog_service = repository_catalog_service
    app.state.triage_evidence_service = triage_evidence_service
    app.state.meta_inference_service = meta_inference_service
    app.state.artifact_store = artifact_store

    system_router = APIRouter(prefix="/api/v1/system", tags=["system"])

    @system_router.get(
        "/health",
        operation_id="getSystemHealth",
        response_model=SystemHealthResponse,
        summary="Public minimal instance liveness probe (A-18)",
        responses={
            429: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
            503: {"model": Problem, "content": {PROBLEM_JSON_MEDIA_TYPE: {}}},
        },
    )
    async def get_system_health() -> SystemHealthResponse:
        return SystemHealthResponse(status="ok", timestamp=datetime.now(tz=UTC))

    app.include_router(system_router)
    app.include_router(build_iam_router())
    app.include_router(build_setup_router())
    app.include_router(build_orchestrator_router())
    app.include_router(build_internal_worker_router())
    app.include_router(build_integrations_router())
    app.include_router(build_webhooks_router())
    app.include_router(build_repositories_router())
    app.include_router(build_triage_evidence_router())
    app.include_router(build_inference_router())

    @app.exception_handler(Red2PrError)
    async def _handle_red2pr_error(request: Request, exc: Red2PrError) -> JSONResponse:
        corr_id = _request_correlation_id(request)
        prob = problem_from_exception(exc, correlation_id=corr_id)
        extra = (
            {"Retry-After": str(exc.retry_after_seconds)}
            if exc.retry_after_seconds is not None
            else None
        )
        return _problem_json_response(prob, correlation_id=corr_id, extra_headers=extra)

    @app.exception_handler(RequestValidationError)
    async def _handle_validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        corr_id = _request_correlation_id(request)
        raw_errors = exc.errors()
        if any(err.get("type") == "json_invalid" for err in raw_errors):
            prob = build_problem(
                status=400,
                code="malformed_json",
                title="Bad request",
                detail="Request body is not valid UTF-8 JSON.",
                correlation_id=corr_id,
            )
            return _problem_json_response(prob, correlation_id=corr_id)

        field_errors: list[ProblemFieldError] = []
        for err in raw_errors[:50]:
            loc_parts = [str(part) for part in err.get("loc", ()) if str(part) != "body"]
            field_name = (".".join(loc_parts) or "request")[:120]
            err_code = str(err.get("type") or "invalid_field")[:120]
            field_errors.append(ProblemFieldError(field=field_name, code=err_code))

        prob = build_problem(
            status=422,
            code="validation_error",
            title="Validation failed",
            detail="One or more request fields failed contract validation.",
            correlation_id=corr_id,
            errors=field_errors or None,
        )
        return _problem_json_response(prob, correlation_id=corr_id)

    @app.exception_handler(StarletteHTTPException)
    async def _handle_http_exception(
        request: Request,
        exc: StarletteHTTPException,
    ) -> JSONResponse:
        corr_id = _request_correlation_id(request)
        code_map = {
            400: "bad_request",
            401: "unauthenticated",
            403: "operation_denied",
            404: "not_found",
            405: "method_not_allowed",
            409: "conflict",
            410: "resource_expired",
            412: "precondition_failed",
            413: "payload_too_large",
            422: "validation_error",
            429: "rate_limited",
            503: "dependency_unavailable",
        }
        status = exc.status_code if 400 <= exc.status_code <= 599 else 500
        code = code_map.get(status, f"http_{status}")
        detail = str(exc.detail) if status < 500 else "Internal server error."
        prob = build_problem(
            status=status,
            code=code,
            title="Request failed",
            detail=detail,
            correlation_id=corr_id,
        )
        return _problem_json_response(prob, correlation_id=corr_id)

    @app.exception_handler(Exception)
    async def _handle_unexpected_exception(request: Request, exc: Exception) -> JSONResponse:
        corr_id = _request_correlation_id(request)
        _LOGGER.error(
            "Unhandled API exception",
            exc_info=exc,
            extra={"event": "api.unhandled_exception", "error_code": "internal_error"},
        )
        prob = problem_from_exception(exc, correlation_id=corr_id)
        return _problem_json_response(prob, correlation_id=corr_id)

    def _custom_openapi() -> dict[str, Any]:
        if app.openapi_schema is not None:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        _, top_defs = models_json_schema(
            [(model, "serialization") for model in CANONICAL_OPENAPI_MODELS],
            schema_generator=GenerateJsonSchema,
            ref_template="#/components/schemas/{model}",
        )
        components = schema.setdefault("components", {})
        existing_schemas: dict[str, Any] = dict(components.get("schemas", {}))
        for model_name, model_schema in top_defs.get("$defs", {}).items():
            existing_schemas.setdefault(model_name, model_schema)
        components["schemas"] = {k: existing_schemas[k] for k in sorted(existing_schemas)}
        app.openapi_schema = schema
        return schema

    app.openapi = _custom_openapi  # type: ignore[method-assign]
    app.add_middleware(_CorrelationAndBodyLimitMiddleware, max_body_bytes=MAX_JSON_BODY_BYTES)
    return app


def render_openapi_v1_json() -> str:
    """Render deterministic UTF-8 OpenAPI v1 contract JSON."""
    app = create_app()
    spec = app.openapi()
    return json.dumps(spec, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_openapi_v1_json(output_path: pathlib.Path) -> pathlib.Path:
    """Write deterministic OpenAPI v1 contract JSON to contracts/openapi/openapi.v1.json."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_openapi_v1_json(), encoding="utf-8", newline="\n")
    return output_path
