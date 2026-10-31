"""FastAPI /api/v1 application shell, S-03 Problem handlers, and OpenAPI v1 exporter (U02..U14).

Provides:
- Public minimal liveness route GET /api/v1/system/health (A-18).
- ASGI request correlation ID binding (X-Correlation-Id), 1 MiB JSON body ceiling (S-01),
  and 100 MiB worker artifact upload ceiling on `/internal/v1/jobs/{job_id}/upload` (NFR-14).
- Consistent S-03 application/problem+json handlers across 400..503 without traceback leaks.
- Deterministic OpenAPI 3.1 contract export registering all canonical S-01..S-22 DTO schemas.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.sdk.metrics.export import MetricReader
from opentelemetry.sdk.trace.export import SpanExporter
from pydantic.json_schema import GenerateJsonSchema, models_json_schema
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from py_contracts import (
    MAX_JSON_BODY_BYTES,
    ActionReceipt,
    AffectedInFlightItem,
    AgentProfile,
    AgentProfileUpdateRequest,
    AgentProfileUpdateResponse,
    AgentStepRecord,
    AnalyticsCostSummary,
    AnalyticsFunnelStage,
    ApiToken,
    ApiTokenCreateRequest,
    ApiTokenCreateResponse,
    Approval,
    ApprovalDecisionRequest,
    ApprovalInboxEntry,
    ApprovalPageResponse,
    Artifact,
    AuditRecord,
    BackupCreateRequest,
    BackupKeyReference,
    BackupManifestV1,
    BackupObjectEntry,
    BackupRecord,
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
    ContextManifest,
    ContextManifestEntry,
    CsrfBootstrapResponse,
    DeadLetterJobSummary,
    Diagnosis,
    DiagnosisHypothesis,
    DoctorResponse,
    EffectiveRepositoryPolicy,
    EndpointRegistration,
    EndpointRegistrationCreateRequest,
    EndpointRegistrationPage,
    EscalationPolicy,
    EventEnvelope,
    EvidenceLineCitation,
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
    MaintenanceRequest,
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
    NotificationCredentialWriteRequest,
    NotificationDelivery,
    NotificationDestination,
    NotificationPreference,
    PageParams,
    Patch,
    PatchAttemptRecord,
    PathPolicyEvaluation,
    PolicyDenialItem,
    PolicyReadinessGates,
    PolicyRuleChange,
    Problem,
    ProblemFieldError,
    ProviderSyncCursor,
    Publication,
    PublicationDetailResponse,
    PublicationPageResponse,
    PublicationReconciliationRequest,
    RecoveryRequest,
    RecoveryResponse,
    ReleaseExceptionCreateRequest,
    ReleaseExceptionList,
    ReleaseExceptionRecord,
    RemoteCheck,
    Repair,
    RepairActionRequest,
    RepairCreateRequest,
    RepairPageResponse,
    ReportExportReceipt,
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
    RestoreDryRunRequest,
    RestorePlan,
    RestoreStartRequest,
    ResultV1,
    RunnerProfileCommandSpec,
    RunnerProfileManifest,
    SandboxJobV1,
    SecretPresence,
    SecurityFindingV1,
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
    SupportBundleCreateRequest,
    SupportBundlePreview,
    SupportBundleRecord,
    SystemCheck,
    SystemHealthResponse,
    SystemStatus,
    TaskAttemptSummary,
    TaskJob,
    TaskJobActionRequest,
    TaskJobDetail,
    TaskJobPage,
    TelegramIntentConfirmationRequest,
    TelegramIntentConfirmationResponse,
    TelegramIntentResponse,
    TelegramIntentTokenRequest,
    TelegramLinkChallengeResponse,
    TelegramLinkSummary,
    ToolCallRequest,
    ToolCallResponse,
    ToolCapabilityPolicyItem,
    UpgradePreflightRequest,
    UpgradePreflightResponse,
    User,
    Verification,
    WebhookIngressReceipt,
    WebhookSigningKeyRotateResponse,
    Worker,
    WorkerActionRequest,
    WorkerEnrollmentCreateRequest,
    WorkerEnrollmentCreateResponse,
    WorkerFleetSummary,
    WorkerPage,
    WorkerSelfTestResponse,
    WorkflowHazardFinding,
    Workspace,
    WorkspaceAgentProfilesResponse,
    WorkspaceAnalyticsResponse,
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
    WorkspaceUsageResponse,
    WorkspaceWorkerReadinessResponse,
    new_uuid7,
)
from py_contracts.crypto import KeyRing
from red2pr_control.analytics_audit.audit_chain import ExternalCheckpointStore
from red2pr_control.analytics_audit.router import build_analytics_router
from red2pr_control.approvals.router import build_approvals_router
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
from red2pr_control.core.telemetry import configure_telemetry, extract_trace_context
from red2pr_control.iam.api_tokens import build_api_tokens_router
from red2pr_control.iam.router import build_iam_router
from red2pr_control.iam.sessions import IamService
from red2pr_control.inference import (
    AgentProfileService,
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
from red2pr_control.notifications import NotificationDispatcher, build_notifications_router
from red2pr_control.notifications.channels.runtime import build_external_notification_adapters
from red2pr_control.notifications.telegram.poller import TelegramBotService
from red2pr_control.notifications.telegram.router import build_telegram_router
from red2pr_control.operations.alarms import OperationalAlarmWorker
from red2pr_control.operations.backup_restore import recover_interrupted_restore
from red2pr_control.operations.retention import RetentionPurgeWorker
from red2pr_control.operations.router import build_operations_router
from red2pr_control.operations.runtime import (
    dispose_operation_lock_engine,
    shared_operation_lease,
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
from red2pr_control.orchestrator.repairs_router import build_repairs_router
from red2pr_control.publisher.remote_observer import RemoteCiObserver
from red2pr_control.publisher.router import build_publications_router
from red2pr_control.publisher.saga import PublisherSaga
from red2pr_control.repositories import (
    RepositoryCatalogService,
    build_repositories_router,
)
from red2pr_control.secrets.broker import SecretBroker
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
    AnalyticsCostSummary,
    AnalyticsFunnelStage,
    BackupCreateRequest,
    BackupKeyReference,
    BackupManifestV1,
    BackupObjectEntry,
    BackupRecord,
    DoctorResponse,
    MaintenanceRequest,
    RestoreDryRunRequest,
    RestorePlan,
    RestoreStartRequest,
    SupportBundleCreateRequest,
    SupportBundlePreview,
    SupportBundleRecord,
    SystemCheck,
    SystemStatus,
    UpgradePreflightRequest,
    UpgradePreflightResponse,
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
    RepairActionRequest,
    RepairCreateRequest,
    RepairPageResponse,
    Diagnosis,
    DiagnosisHypothesis,
    EvidenceLineCitation,
    ContextManifestEntry,
    ContextManifest,
    AgentStepRecord,
    Patch,
    PatchAttemptRecord,
    Verification,
    Approval,
    ApprovalDecisionRequest,
    ApprovalInboxEntry,
    ApprovalPageResponse,
    Publication,
    PublicationPageResponse,
    PublicationDetailResponse,
    PublicationReconciliationRequest,
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
    ApiToken,
    ApiTokenCreateRequest,
    ApiTokenCreateResponse,
    WebhookSigningKeyRotateResponse,
    NotificationCredentialWriteRequest,
    TelegramLinkSummary,
    TelegramLinkChallengeResponse,
    TelegramIntentTokenRequest,
    TelegramIntentConfirmationRequest,
    TelegramIntentResponse,
    TelegramIntentConfirmationResponse,
    AuditRecord,
    ReleaseExceptionCreateRequest,
    ReleaseExceptionList,
    ReleaseExceptionRecord,
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
    WorkspaceAnalyticsResponse,
    WorkspaceUsageResponse,
    WorkspaceModelEntry,
    WorkspaceModelsConfigUpdateRequest,
    WorkspaceModelsConfigUpdateResponse,
    WorkspaceModelsResponse,
    ToolCapabilityPolicyItem,
    AgentProfile,
    WorkspaceAgentProfilesResponse,
    AgentProfileUpdateRequest,
    AgentProfileUpdateResponse,
    ReportExportRequest,
    ReportExportReceipt,
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
    SecurityFindingV1,
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

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int = MAX_JSON_BODY_BYTES,
        tracer: Any | None = None,
        request_counter: Any | None = None,
        request_duration: Any | None = None,
    ) -> None:
        self._app = app
        self._max_body_bytes = max_body_bytes
        self._tracer = tracer or trace.get_tracer("red2pr.api")
        self._request_counter = request_counter
        self._request_duration = request_duration

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
        started_at = time.perf_counter()
        method = str(scope.get("method", "OTHER")).upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
            method = "OTHER"
        response_status = 500

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

            trace_carrier = {
                name.decode("latin-1"): value.decode("latin-1")
                for name, value in raw_headers
                if name.lower() in {b"traceparent", b"tracestate"}
            }
            parent_context = extract_trace_context(trace_carrier)
            context_token = otel_context.attach(parent_context)
            span_holder: list[Any | None] = [None]
            original_send = _correlated_send

            async def traced_send(message: Message) -> None:
                nonlocal response_status
                if message["type"] == "http.response.start" and span_holder[0] is not None:
                    response_status = int(message.get("status", 500))
                    span_holder[0].set_attribute("http.response.status_code", response_status)
                await original_send(message)

            try:
                with self._tracer.start_as_current_span("http.server") as span:
                    span_holder[0] = span
                    span.set_attribute("http.request.method", str(scope.get("method", "")))
                    await self._app(scope, _replay_receive, traced_send)
            finally:
                otel_context.detach(context_token)
                attributes = {
                    "http.request.method": method,
                    "http.response.status_class": f"{response_status // 100}xx",
                }
                if self._request_counter is not None:
                    self._request_counter.add(1, attributes)
                if self._request_duration is not None:
                    self._request_duration.record(time.perf_counter() - started_at, attributes)


class _SystemMaintenanceMiddleware(BaseHTTPMiddleware):
    """Serialize mutating HTTP requests against restore and fail closed in maintenance."""

    _RESTORE_ALLOWED = frozenset(
        {
            "/api/v1/system/maintenance",
            "/api/v1/system/restore",
            "/api/v1/system/restore/dry-run",
            "/api/v1/system/support-bundles/preview",
            "/api/v1/system/support-bundles",
        }
    )

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return await call_next(request)
        if request.url.path in self._RESTORE_ALLOWED or (
            request.url.path.startswith("/api/v1/operations/")
            and request.url.path.endswith("/cancel")
        ):
            return await call_next(request)
        iam = getattr(request.app.state, "iam_service", None)
        if iam is None:
            return await call_next(request)
        bind = iam.session_factory.kw.get("bind")
        if getattr(getattr(bind, "dialect", None), "name", None) != "postgresql":
            return await call_next(request)
        try:
            async with shared_operation_lease(iam.session_factory) as state:
                if state.enabled:
                    return JSONResponse(
                        status_code=503,
                        headers={"Retry-After": "30", "Cache-Control": "no-store"},
                        content={
                            "type": "about:blank",
                            "title": "Service unavailable",
                            "status": 503,
                            "code": "instance_maintenance",
                            "detail": "Instance writes are paused during maintenance or recovery.",
                        },
                        media_type="application/problem+json",
                    )
                return await call_next(request)
        except Exception:
            _LOGGER.error("system_write_fence_unavailable")
            return JSONResponse(
                status_code=503,
                headers={"Retry-After": "30", "Cache-Control": "no-store"},
                content={
                    "type": "about:blank",
                    "title": "Service unavailable",
                    "status": 503,
                    "code": "system_write_fence_unavailable",
                    "detail": "Instance writes are paused because recovery fencing is unavailable.",
                },
                media_type="application/problem+json",
            )


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
    agent_profile_service: AgentProfileService | None = None,
    artifact_store: ArtifactStoreProtocol | None = None,
    publisher_saga: PublisherSaga | None = None,
    remote_ci_observer: RemoteCiObserver | None = None,
    notification_dispatcher: NotificationDispatcher | None = None,
    telegram_bot_service: TelegramBotService | None = None,
    notification_secret_broker: SecretBroker | None = None,
    audit_checkpoint_store: ExternalCheckpointStore | None = None,
    audit_checkpoint_keyring: KeyRing | None = None,
    telemetry_span_exporter: SpanExporter | None = None,
    telemetry_metric_reader: MetricReader | None = None,
) -> FastAPI:
    """Create the FastAPI /api/v1 control-plane application shell."""
    if (audit_checkpoint_store is None) != (audit_checkpoint_keyring is None):
        raise ValueError(
            "Audit checkpoint store and verification keyring must be configured together."
        )
    tracer_provider, meter_provider = configure_telemetry(
        span_exporter=telemetry_span_exporter,
        metric_reader=telemetry_metric_reader,
    )
    meter = meter_provider.get_meter("red2pr.control_plane")
    request_counter = meter.create_counter(
        "red2pr.http.server.requests", description="Completed HTTP server requests"
    )
    request_duration = meter.create_histogram(
        "red2pr.http.server.duration", unit="s", description="HTTP server request duration"
    )
    if notification_dispatcher is None and iam_service is not None:
        notification_dispatcher = NotificationDispatcher(
            session_factory=iam_service.session_factory
        )
    if (
        notification_dispatcher is not None
        and iam_service is not None
        and notification_secret_broker is not None
    ):
        for channel, adapter in build_external_notification_adapters(
            session_factory=iam_service.session_factory,
            secret_broker=notification_secret_broker,
        ).items():
            notification_dispatcher.register_adapter(channel, adapter)  # type: ignore[arg-type]
    if notification_dispatcher is not None and telegram_bot_service is not None:
        notification_dispatcher.register_adapter(
            "telegram", telegram_bot_service.notification_adapter
        )
    if notification_dispatcher is not None and setup_step_registry is not None:
        notification_dispatcher.register_setup_probe(setup_step_registry)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        worker = None
        telegram_worker = None
        retention_task = None
        alarms_task = None
        admin_database_url = os.environ.get("RED2PR_ADMIN_DATABASE_URL", "").strip()
        backup_directory = os.environ.get("RED2PR_BACKUP_DIRECTORY", "").strip()
        if admin_database_url and backup_directory:
            await recover_interrupted_restore(admin_database_url, pathlib.Path(backup_directory))
        dispatcher = getattr(app.state, "notification_dispatcher", None)
        if dispatcher is not None:
            worker = asyncio.create_task(
                dispatcher.run_forever(), name="notification-outbox-dispatcher"
            )
        telegram_service = getattr(app.state, "telegram_bot_service", None)
        if telegram_service is not None:
            telegram_worker = asyncio.create_task(
                telegram_service.run_forever(), name="telegram-bot-runtime"
            )
        retention_worker = getattr(app.state, "retention_worker", None)
        if retention_worker is not None:
            retention_task = asyncio.create_task(
                retention_worker.run_forever(), name="retention-purge-worker"
            )
        alarm_worker = getattr(app.state, "operational_alarm_worker", None)
        if alarm_worker is not None:
            alarms_task = asyncio.create_task(
                alarm_worker.run_forever(), name="operational-alarm-worker"
            )
        try:
            yield
        finally:
            if worker is not None:
                worker.cancel()
                with suppress(asyncio.CancelledError):
                    await worker
            if dispatcher is not None:
                await dispatcher.aclose()
            if retention_task is not None:
                retention_task.cancel()
                with suppress(asyncio.CancelledError):
                    await retention_task
            if alarms_task is not None:
                alarms_task.cancel()
                with suppress(asyncio.CancelledError):
                    await alarms_task
            if telegram_worker is not None:
                telegram_worker.cancel()
                with suppress(asyncio.CancelledError):
                    await telegram_worker
                if telegram_service is not None:
                    await telegram_service.api.aclose()
            if iam_service is not None:
                await dispose_operation_lock_engine(iam_service.session_factory)

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
        lifespan=lifespan,
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
    app.state.agent_profile_service = (
        agent_profile_service
        if agent_profile_service is not None
        else (
            AgentProfileService(
                session_factory=iam_service.session_factory,
                iam_service=iam_service,
                meta_inference_service=meta_inference_service,
            )
            if iam_service is not None and meta_inference_service is not None
            else None
        )
    )
    app.state.artifact_store = artifact_store
    app.state.publisher_saga = publisher_saga
    app.state.remote_ci_observer = remote_ci_observer
    app.state.notification_dispatcher = notification_dispatcher
    app.state.retention_worker = (
        RetentionPurgeWorker(
            session_factory=iam_service.session_factory,
            store=artifact_store,
        )
        if iam_service is not None
        else None
    )
    app.state.operational_alarm_worker = (
        OperationalAlarmWorker(
            session_factory=iam_service.session_factory,
            artifact_store=artifact_store,
            task_queue_service=task_queue_service,
            checkpoint_store=audit_checkpoint_store,
            checkpoint_keyring=audit_checkpoint_keyring,
        )
        if iam_service is not None
        else None
    )
    app.state.notification_secret_broker = notification_secret_broker
    app.state.telegram_bot_service = telegram_bot_service
    app.state.audit_checkpoint_store = audit_checkpoint_store
    app.state.audit_checkpoint_keyring = audit_checkpoint_keyring

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
    app.include_router(build_api_tokens_router())
    app.include_router(build_setup_router())
    app.include_router(build_orchestrator_router())
    app.include_router(build_internal_worker_router())
    app.include_router(build_integrations_router())
    app.include_router(build_webhooks_router())
    app.include_router(build_repositories_router())
    app.include_router(build_triage_evidence_router())
    app.include_router(build_repairs_router())
    app.include_router(build_approvals_router())
    app.include_router(build_publications_router())
    app.include_router(build_inference_router())
    app.include_router(build_notifications_router())
    app.include_router(build_telegram_router())
    app.include_router(build_analytics_router())
    app.include_router(build_operations_router())

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
    app.add_middleware(_SystemMaintenanceMiddleware)
    app.add_middleware(
        _CorrelationAndBodyLimitMiddleware,
        max_body_bytes=MAX_JSON_BODY_BYTES,
        tracer=tracer_provider.get_tracer("red2pr.api"),
        request_counter=request_counter,
        request_duration=request_duration,
    )
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
