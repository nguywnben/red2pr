import createClient, { type Client, type ClientOptions, type Middleware } from "openapi-fetch";
import type { components, operations, paths } from "./schema.js";

export type SchemaName = keyof components["schemas"];
export type SchemaOf<K extends SchemaName> = components["schemas"][K];

// Canonical S-01..S-22 & A-01..A-05 TypeScript aliases strictly derived from openapi.v1.json
export type Problem = SchemaOf<"Problem">;
export type ProblemFieldError = SchemaOf<"ProblemFieldError">;
export type ActionReceipt = SchemaOf<"ActionReceipt">;
export type PageParams = SchemaOf<"PageParams">;
export type Money = SchemaOf<"Money">;
export type User = SchemaOf<"User">;
export type Session = SchemaOf<"Session">;
export type SessionListItem = SchemaOf<"SessionListItem">;
export type SessionPage = SchemaOf<"Page_SessionListItem_">;
export type CsrfBootstrapResponse = SchemaOf<"CsrfBootstrapResponse">;
export type SetupClaimRequest = SchemaOf<"SetupClaimRequest">;
export type SetupClaimResponse = SchemaOf<"SetupClaimResponse">;
export type LoginRequest = SchemaOf<"LoginRequest">;
export type LoginResponse = SchemaOf<"LoginResponse">;
export type LogoutRequest = SchemaOf<"LogoutRequest">;
export type StepUpRequest = SchemaOf<"StepUpRequest">;
export type StepUpResponse = SchemaOf<"StepUpResponse">;
export type RecoveryRequest = SchemaOf<"RecoveryRequest">;
export type RecoveryResponse = SchemaOf<"RecoveryResponse">;
export type TelegramLinkSummary = SchemaOf<"TelegramLinkSummary">;
export type TelegramLinkChallengeResponse = SchemaOf<"TelegramLinkChallengeResponse">;
export type TelegramIntentTokenRequest = SchemaOf<"TelegramIntentTokenRequest">;
export type TelegramIntentConfirmationRequest = SchemaOf<"TelegramIntentConfirmationRequest">;
export type TelegramIntentResponse = SchemaOf<"TelegramIntentResponse">;
export type TelegramIntentConfirmationResponse = SchemaOf<"TelegramIntentConfirmationResponse">;
export type MeResponse = SchemaOf<"MeResponse">;
export type MfaEnrollRequest = SchemaOf<"MfaEnrollRequest">;
export type MfaEnrollResponse = SchemaOf<"MfaEnrollResponse">;
export type MfaDeleteRequest = SchemaOf<"MfaDeleteRequest">;
export type Workspace = SchemaOf<"Workspace">;
export type WorkspacePage = SchemaOf<"Page_Workspace_">;
export type WorkspaceCreateRequest = SchemaOf<"WorkspaceCreateRequest">;
export type WorkspaceUpdateRequest = SchemaOf<"WorkspaceUpdateRequest">;
export type WorkspaceDeleteRequest = SchemaOf<"WorkspaceDeleteRequest">;
export type WorkspaceRole = Membership["role"];
export type Membership = SchemaOf<"Membership">;
export type MembershipPage = SchemaOf<"Page_Membership_">;
export type MemberUpdateRequest = SchemaOf<"MemberUpdateRequest">;
export type Invite = SchemaOf<"Invite">;
export type InviteStatus = Invite["status"];
export type InvitePage = SchemaOf<"Page_Invite_">;
export type InviteCreateRequest = SchemaOf<"InviteCreateRequest">;
export type InviteCreateResponse = SchemaOf<"InviteCreateResponse">;
export type InviteAcceptRequest = SchemaOf<"InviteAcceptRequest">;
export type BreakGlassGrant = SchemaOf<"BreakGlassGrant">;
export type BreakGlassGrantPage = SchemaOf<"Page_BreakGlassGrant_">;
export type BreakGlassCreateRequest = SchemaOf<"BreakGlassCreateRequest">;
export type SecretPresence = SchemaOf<"SecretPresence">;
export type Connection = SchemaOf<"Connection">;
export type ConnectionPage = SchemaOf<"Page_Connection_">;
export type ProviderKind = Connection["provider"];
export type ConnectionAuthMode = Connection["auth_mode"];
export type ConnectionStatus = Connection["status"];
export type CapabilityAvailability = NonNullable<Connection["capabilities"]>[string];
export type ConnectionWrite = SchemaOf<"ConnectionWrite">;
export type ConnectionPatchRequest = SchemaOf<"ConnectionPatchRequest">;
export type CapabilitySnapshot = SchemaOf<"CapabilitySnapshot">;
export type WorkflowHazardFinding = SchemaOf<"WorkflowHazardFinding">;
export type WorkflowHazardCode = WorkflowHazardFinding["code"];
export type WorkflowHazardSeverity = WorkflowHazardFinding["severity"];
export type Repository = SchemaOf<"Repository">;
export type RepositoryVisibility = Repository["visibility"];
export type RepositoryMode = Repository["mode"];
export type WorkflowHazardStatus = NonNullable<Repository["workflow_hazard_status"]>;
export type RepositoryPolicy = SchemaOf<"RepositoryPolicy">;
export type RepositoryFacetSummary = SchemaOf<"RepositoryFacetSummary">;
export type RepositoryCatalogPage = SchemaOf<"RepositoryCatalogPage">;
export type RepositoryUpdateRequest = SchemaOf<"RepositoryUpdateRequest">;
export type PolicyReadinessGates = SchemaOf<"PolicyReadinessGates">;
export type EffectiveRepositoryPolicy = SchemaOf<"EffectiveRepositoryPolicy">;
export type RepositoryPolicyRevision = SchemaOf<"RepositoryPolicyRevision">;
export type RepositoryPolicyStateResponse = SchemaOf<"RepositoryPolicyStateResponse">;
export type RepositoryPolicyUpdateRequest = SchemaOf<"RepositoryPolicyUpdateRequest">;
export type PolicyRuleChange = SchemaOf<"PolicyRuleChange">;
export type PolicyDenialItem = SchemaOf<"PolicyDenialItem">;
export type PolicyScopeLayer = PolicyDenialItem["source_layer"];
export type BranchPolicyEvaluation = SchemaOf<"BranchPolicyEvaluation">;
export type PolicyEvaluationVerdict = BranchPolicyEvaluation["verdict"];
export type PathPolicyEvaluation = SchemaOf<"PathPolicyEvaluation">;
export type HistoricalRunSimulation = SchemaOf<"HistoricalRunSimulation">;
export type RunEligibilityDisposition = HistoricalRunSimulation["disposition"];
export type AffectedInFlightItem = SchemaOf<"AffectedInFlightItem">;
export type RepositoryPolicyPreviewRequest = SchemaOf<"RepositoryPolicyPreviewRequest">;
export type RepositoryPolicyPreviewResponse = SchemaOf<"RepositoryPolicyPreviewResponse">;
export type BulkRepositoryPreviewItem = SchemaOf<"BulkRepositoryPreviewItem">;
export type BulkRepositoryPreviewRequest = SchemaOf<"BulkRepositoryPreviewRequest">;
export type BulkRepositoryPreviewResponse = SchemaOf<"BulkRepositoryPreviewResponse">;
export type BulkRepositoryUpdateRequest = SchemaOf<"BulkRepositoryUpdateRequest">;
export type BulkRepositoryUpdateResponse = SchemaOf<"BulkRepositoryUpdateResponse">;
export type RepositoryRunTriggerSummary = SchemaOf<"RepositoryRunTriggerSummary">;
export type RepositoryAccessGrantSummary = SchemaOf<"RepositoryAccessGrantSummary">;
export type RepositoryHistoryEntry = SchemaOf<"RepositoryHistoryEntry">;
export type RepositoryDetailResponse = SchemaOf<"RepositoryDetailResponse">;
export type ConnectionDetailResponse = SchemaOf<"ConnectionDetailResponse">;
export type ConnectionProbeResponse = SchemaOf<"ConnectionProbeResponse">;
export type ConnectionSyncResponse = SchemaOf<"ConnectionSyncResponse">;
export type WebhookIngressReceipt = SchemaOf<"WebhookIngressReceipt">;
export type WebhookInboxStatus = WebhookIngressReceipt["status"];
export type WebhookIngressDisposition = WebhookIngressReceipt["disposition"];
export type ProviderSyncCursor = SchemaOf<"ProviderSyncCursor">;
export type SyncCursorStatus = NonNullable<ProviderSyncCursor["last_status"]>;
export type ConnectionReconcileRequest = SchemaOf<"ConnectionReconcileRequest">;
export type ConnectionReconcileResponse = SchemaOf<"ConnectionReconcileResponse">;
export type GitHubInstallStateCreateRequest = SchemaOf<"GitHubInstallStateCreateRequest">;
export type GitHubInstallStateResponse = SchemaOf<"GitHubInstallStateResponse">;
export type GitHubCallbackResponse = SchemaOf<"GitHubCallbackResponse">;
export type GitHubInstallationConfirmRequest = SchemaOf<"GitHubInstallationConfirmRequest">;
export type GitHubInstallationConfirmResponse = SchemaOf<"GitHubInstallationConfirmResponse">;
export type CiRun = SchemaOf<"CiRun">;
export type CiJob = SchemaOf<"CiJob">;
export type CiRunStatus = CiRun["status"];
export type CiConclusion = NonNullable<CiRun["conclusion"]>;
export type CiRunIngestionState = NonNullable<CiRun["ingestion_state"]>;
export type FlakyClassification = NonNullable<CiRun["flaky_classification"]>;
export type JobLogStatus = NonNullable<CiJob["log_status"]>;
export type CiRunPage = SchemaOf<"Page_CiRun_">;
export type CiJobListResponse = SchemaOf<"CiJobListResponse">;
export type JobLogChunkResponse = SchemaOf<"JobLogChunkResponse">;
export type FailureFingerprintObservation = SchemaOf<"FailureFingerprintObservation">;
export type FailureFingerprintSummary = SchemaOf<"FailureFingerprintSummary">;
export type CiRunDetailResponse = SchemaOf<"CiRunDetailResponse">;
export type Repair = SchemaOf<"Repair">;
export type Diagnosis = SchemaOf<"Diagnosis">;
export type Patch = SchemaOf<"Patch">;
export type Verification = SchemaOf<"Verification">;
export type Approval = SchemaOf<"Approval">;
export type RepairCreateRequest = SchemaOf<"RepairCreateRequest">;
export type RepairActionRequest = SchemaOf<"RepairActionRequest">;
export type ApprovalDecisionRequest = SchemaOf<"ApprovalDecisionRequest">;
export type RepairPageResponse = SchemaOf<"RepairPageResponse">;
export type ApprovalPageResponse = SchemaOf<"ApprovalPageResponse">;
export type ApprovalInboxEntry = SchemaOf<"ApprovalInboxEntry">;
export type Publication = SchemaOf<"Publication">;
export type RemoteCheck = SchemaOf<"RemoteCheck">;
export type PublicationPageResponse = SchemaOf<"PublicationPageResponse">;
export type PublicationDetailResponse = SchemaOf<"PublicationDetailResponse">;
export type PublicationReconciliationRequest = SchemaOf<"PublicationReconciliationRequest">;
export type Artifact = SchemaOf<"Artifact">;
export type Worker = SchemaOf<"Worker">;
export type WorkerStatus = Worker["status"];
export type WorkerIsolationMode = NonNullable<Worker["isolation_mode"]>;
export type WorkerFleetSummary = SchemaOf<"WorkerFleetSummary">;
export type WorkerPage = SchemaOf<"WorkerPage">;
export type WorkerEnrollmentCreateRequest = SchemaOf<"WorkerEnrollmentCreateRequest">;
export type WorkerEnrollmentCreateResponse = SchemaOf<"WorkerEnrollmentCreateResponse">;
export type WorkerActionRequest = SchemaOf<"WorkerActionRequest">;
export type WorkerAction = WorkerActionRequest["action"];
export type WorkerSelfTestResponse = SchemaOf<"WorkerSelfTestResponse">;
export type IsolationCheckResult = SchemaOf<"IsolationCheckResult">;
export type WorkspaceSandboxLeaseSummary = SchemaOf<"WorkspaceSandboxLeaseSummary">;
export type SandboxLeaseStatus = WorkspaceSandboxLeaseSummary["status"];
export type WorkspaceWorkerReadinessResponse = SchemaOf<"WorkspaceWorkerReadinessResponse">;
export type TaskJob = SchemaOf<"TaskJob">;
export type TaskJobState = TaskJob["state"];
export type TaskAttemptSummary = SchemaOf<"TaskAttemptSummary">;
export type TaskAttemptState = TaskAttemptSummary["state"];
export type DeadLetterJobSummary = SchemaOf<"DeadLetterJobSummary">;
export type DeadLetterStatus = DeadLetterJobSummary["status"];
export type WorkspaceQueueFairnessSummary = SchemaOf<"WorkspaceQueueFairnessSummary">;
export type QueueTransportStatus = WorkspaceQueueFairnessSummary["transport_status"];
export type TaskJobDetail = SchemaOf<"TaskJobDetail">;
export type TaskJobPage = SchemaOf<"TaskJobPage">;
export type TaskJobActionRequest = SchemaOf<"TaskJobActionRequest">;
export type TaskJobAction = TaskJobActionRequest["action"];
export type TaskJobReconcileOutcome = NonNullable<TaskJobActionRequest["reconciled_outcome"]>;
export type NotificationDestination = SchemaOf<"NotificationDestination">;
export type NotificationChannel = NotificationDestination["channel"];
export type NotificationDestinationCreateRequest = SchemaOf<"NotificationDestinationCreateRequest">;
export type NotificationDestinationPatchRequest = SchemaOf<"NotificationDestinationPatchRequest">;
export type NotificationDelivery = SchemaOf<"NotificationDelivery">;
export type NotificationPreference = SchemaOf<"NotificationPreference">;
export type NotificationInboxItem = SchemaOf<"NotificationInboxItem">;
export type NotificationInboxPage = SchemaOf<"Page_NotificationInboxItem_">;
export type NotificationDestinationPage = SchemaOf<"Page_NotificationDestination_">;
export type NotificationDeliveryPage = SchemaOf<"Page_NotificationDelivery_">;
export type NotificationReadPatchRequest = SchemaOf<"NotificationReadPatchRequest">;
export type NotificationPreferencesPatchRequest = SchemaOf<"NotificationPreferencesPatchRequest">;
export type NotificationPreferencesState = SchemaOf<"NotificationPreferencesState">;
export type NotificationTestRequest = SchemaOf<"NotificationTestRequest">;
export type AuditRecord = SchemaOf<"AuditRecord">;
export type ModelUsageRecord = SchemaOf<"ModelUsageRecord">;
export type ReportExportRequest = SchemaOf<"ReportExportRequest">;
export type ConsentCreateRequest = SchemaOf<"ConsentCreateRequest">;
export type ConsentRevokeRequest = SchemaOf<"ConsentRevokeRequest">;
export type ConsentRecord = SchemaOf<"ConsentRecord">;
export type ConsentPurpose = ConsentRecord["purpose"];
export type ConsentScope = ConsentRecord["scope"];
export type ConsentDataClass = ConsentRecord["data_classes"][number];
export type ConsentRecordPage = SchemaOf<"Page_ConsentRecord_">;
export type EndpointRegistrationCreateRequest = SchemaOf<"EndpointRegistrationCreateRequest">;
export type EndpointRegistration = SchemaOf<"EndpointRegistration">;
export type EgressAdapterKind = EndpointRegistration["adapter"];
export type EndpointScheme = EndpointRegistration["scheme"];
export type EndpointRegistrationPage = SchemaOf<"Page_EndpointRegistration_">;
export type SetupPrerequisite = SchemaOf<"SetupPrerequisite">;
export type SetupStepSummary = SchemaOf<"SetupStepSummary">;
export type SetupStepStatus = SetupStepSummary["status"];
export type SetupStepSubmitRequest = SchemaOf<"SetupStepSubmitRequest">;
export type SetupStepAction = NonNullable<SetupStepSubmitRequest["action"]>;
export type SetupState = SchemaOf<"SetupState">;
export type SetupWizardPhase = SetupState["phase"];
export type SetupReadiness = SetupState["readiness"];
export type LifecycleOperation = SchemaOf<"LifecycleOperation">;
export type SystemHealthResponse = SchemaOf<"SystemHealthResponse">;
export type EventEnvelope = SchemaOf<"EventEnvelope">;
export type ToolCallRequest = SchemaOf<"ToolCallRequest">;
export type ToolCallResponse = SchemaOf<"ToolCallResponse">;
export type SandboxJobV1 = SchemaOf<"SandboxJobV1">;
export type ResultV1 = SchemaOf<"ResultV1">;
export type RunnerProfileCommandSpec = SchemaOf<"RunnerProfileCommandSpec">;
export type RunnerProfileManifest = SchemaOf<"RunnerProfileManifest">;
export type ReproductionRunRecord = SchemaOf<"ReproductionRunRecord">;
export type ReproductionPhase = ReproductionRunRecord["phase"];
export type ReproductionStatus = ReproductionRunRecord["status"];
export type FidelityGrade = ReproductionRunRecord["fidelity_grade"];
export type EvidenceManifestV1 = SchemaOf<"EvidenceManifestV1">;
export type ModelToolProvenance = SchemaOf<"ModelToolProvenance">;
export type ModelCapabilityFlags = SchemaOf<"ModelCapabilityFlags">;
export type ModelCapabilitySnapshot = SchemaOf<"ModelCapabilitySnapshot">;
export type MetaModelId = ModelCapabilitySnapshot["model_id"];
export type ModelTierRole = ModelCapabilitySnapshot["tier_role"];
export type ModelAvailabilityStatus = ModelCapabilitySnapshot["status"];
export type SuspensionReason = NonNullable<ModelCapabilitySnapshot["suspension_reason"]>;
export type ModelPricingRate = SchemaOf<"ModelPricingRate">;
export type BudgetPolicyDefaults = SchemaOf<"BudgetPolicyDefaults">;
export type EscalationPolicy = SchemaOf<"EscalationPolicy">;
export type BudgetAccountSummary = SchemaOf<"BudgetAccountSummary">;
export type BudgetScopeKind = BudgetAccountSummary["scope_kind"];
export type BudgetReservationRecord = SchemaOf<"BudgetReservationRecord">;
export type BudgetReservationStatus = BudgetReservationRecord["status"];
export type WorkspaceModelEntry = SchemaOf<"WorkspaceModelEntry">;
export type WorkspaceModelsResponse = SchemaOf<"WorkspaceModelsResponse">;
export type WorkspaceModelsConfigUpdateRequest = SchemaOf<"WorkspaceModelsConfigUpdateRequest">;
export type WorkspaceModelsConfigUpdateResponse = SchemaOf<"WorkspaceModelsConfigUpdateResponse">;
export type WorkspaceInferenceConsentCreateRequest =
  SchemaOf<"WorkspaceInferenceConsentCreateRequest">;
export type ModelProbeRequest = SchemaOf<"ModelProbeRequest">;
export type ModelProbeResponse = SchemaOf<"ModelProbeResponse">;
export type AgentToolName = ToolCallRequest["tool_name"];
export type AgentProfile = SchemaOf<"AgentProfile">;
export type AgentProfileRoleKey = AgentProfile["role_key"];
export type ReasoningEffortLevel = AgentProfile["reasoning_effort"];
export type ToolCapabilityPolicyItem = SchemaOf<"ToolCapabilityPolicyItem">;
export type WorkspaceAgentProfilesResponse = SchemaOf<"WorkspaceAgentProfilesResponse">;
export type AgentProfileUpdateRequest = SchemaOf<"AgentProfileUpdateRequest">;
export type AgentProfileUpdateResponse = SchemaOf<"AgentProfileUpdateResponse">;
export type AgentStepRecord = SchemaOf<"AgentStepRecord">;
export type ContextManifestEntry = SchemaOf<"ContextManifestEntry">;
export type ContextManifest = SchemaOf<"ContextManifest">;
export type PatchAttemptRecord = SchemaOf<"PatchAttemptRecord">;
export type DiagnosisHypothesis = SchemaOf<"DiagnosisHypothesis">;
export type EvidenceLineCitation = SchemaOf<"EvidenceLineCitation">;

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const CSRF_COOKIE_NAME = "red2pr_csrf";

export interface RequestCallOptions {
  readonly correlationId?: string;
  readonly signal?: AbortSignal;
}

export interface OptimisticMutationOptions extends RequestCallOptions {
  readonly ifMatch?: string;
}

export interface RequiredOptimisticMutationOptions extends RequestCallOptions {
  readonly ifMatch: string;
}

export interface IdempotentMutationOptions extends RequestCallOptions {
  readonly idempotencyKey: string;
}

export interface IdempotentOptimisticMutationOptions extends IdempotentMutationOptions {
  readonly ifMatch?: string;
}

export interface OptionalIdempotentMutationOptions extends RequestCallOptions {
  readonly idempotencyKey?: string;
}

export interface ListWorkspacesQuery {
  readonly cursor?: string | null;
  readonly limit?: number;
}

export interface ListWorkspaceMembersQuery {
  readonly cursor?: string | null;
  readonly limit?: number;
  readonly role?: WorkspaceRole | null;
}

export interface ListWorkspaceInvitationsQuery {
  readonly cursor?: string | null;
  readonly limit?: number;
  readonly status?: InviteStatus | null;
}

export interface ListSetupConsentsQuery {
  readonly purpose?: ConsentPurpose | null;
  readonly include_revoked?: boolean;
}

export interface ListEndpointRegistrationsQuery {
  readonly adapter?: EgressAdapterKind | null;
  readonly include_revoked?: boolean;
}

export interface ListWorkspaceTaskJobsQuery {
  readonly state?: TaskJobState | null;
  readonly kind?: string | null;
  readonly repository_id?: string | null;
  readonly cursor?: string | null;
  readonly limit?: number;
}

export interface ListSystemWorkersQuery {
  readonly status?: WorkerStatus | null;
  readonly isolation_mode?: WorkerIsolationMode | null;
  readonly cursor?: string | null;
  readonly limit?: number;
}

export interface ListConnectionsQuery {
  readonly provider?: ProviderKind | null;
  readonly cursor?: string | null;
  readonly limit?: number;
}

export interface ListRepositoriesQuery {
  readonly cursor?: string | null;
  readonly limit?: number;
  readonly q?: string | null;
  readonly connection_id?: string | null;
  readonly provider?: ProviderKind | null;
  readonly mode?: RepositoryMode | null;
  readonly paused?: boolean | null;
  readonly hazard_status?: WorkflowHazardStatus | null;
  readonly tag?: string | null;
  readonly include_inactive?: boolean;
}

export interface ListRunsQuery {
  readonly cursor?: string | null;
  readonly limit?: number;
  readonly repository_id?: string | null;
  readonly status?: CiRunStatus | null;
  readonly conclusion?: CiConclusion | null;
  readonly ingestion_state?: CiRunIngestionState | null;
  readonly flaky_classification?: FlakyClassification | null;
  readonly head_sha?: string | null;
  readonly flaky_only?: boolean;
}

export interface GetJobLogQuery {
  readonly start_offset?: number;
  readonly max_bytes?: number;
}

export interface DownloadedArtifactPayload {
  readonly bytes: ArrayBuffer;
  readonly contentType: string;
  readonly filename: string | null;
}

export interface GitHubCallbackQuery {
  readonly state?: string | null;
  readonly installation_id?: string | null;
  readonly setup_action?: string | null;
}

export interface ApiEnvelope<TData> {
  readonly data: TData;
  readonly correlationId: string | null;
  readonly etag?: string | null;
}

export class Red2PrApiError extends Error {
  public readonly status: number;
  public readonly problem: Problem;
  public readonly retryAfterSeconds: number | null;

  public constructor(problem: Problem, retryAfterSeconds: number | null = null) {
    super(problem.detail);
    this.name = "Red2PrApiError";
    this.status = problem.status;
    this.problem = problem;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export interface Red2PrClientOptions extends ClientOptions {
  readonly getCsrfToken?: () => string | null | undefined;
}

export interface Red2PrClient {
  readonly raw: Client<paths>;
  setCsrfToken(token: string | null): void;
  getSystemHealth(options?: RequestCallOptions): Promise<ApiEnvelope<SystemHealthResponse>>;
  getAuthCsrf(options?: RequestCallOptions): Promise<ApiEnvelope<CsrfBootstrapResponse>>;
  claimInstanceOwner(
    body: SetupClaimRequest,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<SetupClaimResponse>>;
  getSetupState(options?: RequestCallOptions): Promise<ApiEnvelope<SetupState>>;
  submitSetupStep(
    phase: SetupWizardPhase,
    body: SetupStepSubmitRequest,
    options?: OptionalIdempotentMutationOptions,
  ): Promise<ApiEnvelope<SetupState>>;
  listSetupConsents(
    query?: ListSetupConsentsQuery,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<ConsentRecordPage>>;
  grantSetupConsent(
    body: ConsentCreateRequest,
    options?: OptionalIdempotentMutationOptions,
  ): Promise<ApiEnvelope<ConsentRecord>>;
  revokeSetupConsent(
    consentId: string,
    body?: ConsentRevokeRequest,
    options?: OptionalIdempotentMutationOptions,
  ): Promise<ApiEnvelope<ConsentRecord>>;
  listEndpointRegistrations(
    query?: ListEndpointRegistrationsQuery,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<EndpointRegistrationPage>>;
  registerPrivateEndpoint(
    body: EndpointRegistrationCreateRequest,
    options?: OptionalIdempotentMutationOptions,
  ): Promise<ApiEnvelope<EndpointRegistration>>;
  revokePrivateEndpoint(
    endpointId: string,
    options?: OptionalIdempotentMutationOptions,
  ): Promise<ApiEnvelope<EndpointRegistration>>;
  login(body: LoginRequest, options?: RequestCallOptions): Promise<ApiEnvelope<LoginResponse>>;
  logout(options?: RequestCallOptions): Promise<{ correlationId: string | null }>;
  stepUp(body: StepUpRequest, options?: RequestCallOptions): Promise<ApiEnvelope<StepUpResponse>>;
  recoverAccount(
    body: RecoveryRequest,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<RecoveryResponse>>;
  getMe(options?: RequestCallOptions): Promise<ApiEnvelope<MeResponse>>;
  createMyTelegramLinkChallenge(options?: RequestCallOptions): Promise<ApiEnvelope<TelegramLinkChallengeResponse>>;
  deleteMyTelegramLink(options?: RequestCallOptions): Promise<{ correlationId: string | null }>;
  previewTelegramIntent(body: TelegramIntentTokenRequest, options?: RequestCallOptions): Promise<ApiEnvelope<TelegramIntentResponse>>;
  confirmTelegramIntent(body: TelegramIntentConfirmationRequest, options: IdempotentMutationOptions): Promise<ApiEnvelope<TelegramIntentConfirmationResponse>>;
  listMySessions(options?: RequestCallOptions): Promise<ApiEnvelope<SessionPage>>;
  revokeMySession(
    sessionId: string,
    options?: RequestCallOptions,
  ): Promise<{ correlationId: string | null }>;
  enrollMyMfa(
    body?: MfaEnrollRequest,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<MfaEnrollResponse>>;
  deleteMyMfa(
    body: MfaDeleteRequest,
    options?: RequestCallOptions,
  ): Promise<{ correlationId: string | null }>;
  listWorkspaces(
    query?: ListWorkspacesQuery,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<WorkspacePage>>;
  createWorkspace(
    body: WorkspaceCreateRequest,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<Workspace>>;
  getWorkspace(ws: string, options?: RequestCallOptions): Promise<ApiEnvelope<Workspace>>;
  updateWorkspace(
    ws: string,
    body: WorkspaceUpdateRequest,
    options?: OptimisticMutationOptions,
  ): Promise<ApiEnvelope<Workspace>>;
  deleteWorkspace(
    ws: string,
    body: WorkspaceDeleteRequest,
    options: IdempotentMutationOptions,
  ): Promise<ApiEnvelope<ActionReceipt>>;
  listBreakGlassGrants(
    ws: string,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<BreakGlassGrantPage>>;
  createBreakGlassGrant(
    ws: string,
    body: BreakGlassCreateRequest,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<BreakGlassGrant>>;
  revokeBreakGlassGrant(
    ws: string,
    grantId: string,
    options?: RequestCallOptions,
  ): Promise<{ correlationId: string | null }>;
  listWorkspaceMembers(
    ws: string,
    query?: ListWorkspaceMembersQuery,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<MembershipPage>>;
  updateWorkspaceMember(
    ws: string,
    memberId: string,
    body: MemberUpdateRequest,
    options?: OptimisticMutationOptions,
  ): Promise<ApiEnvelope<Membership>>;
  removeWorkspaceMember(
    ws: string,
    memberId: string,
    options?: RequestCallOptions,
  ): Promise<{ correlationId: string | null }>;
  listWorkspaceInvitations(
    ws: string,
    query?: ListWorkspaceInvitationsQuery,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<InvitePage>>;
  createWorkspaceInvitation(
    ws: string,
    body: InviteCreateRequest,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<InviteCreateResponse>>;
  revokeWorkspaceInvitation(
    ws: string,
    inviteId: string,
    options?: RequestCallOptions,
  ): Promise<{ correlationId: string | null }>;
  acceptWorkspaceInvitation(
    body: InviteAcceptRequest,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<Membership>>;
  listTaskJobs(
    ws: string,
    query?: ListWorkspaceTaskJobsQuery,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<TaskJobPage>>;
  getTaskJob(
    ws: string,
    jobId: string,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<TaskJobDetail>>;
  performTaskJobAction(
    ws: string,
    jobId: string,
    body: TaskJobActionRequest,
    options: IdempotentOptimisticMutationOptions,
  ): Promise<ApiEnvelope<ActionReceipt>>;
  getOperationReceipt(
    operationId: string,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<ActionReceipt>>;
  listConnections(
    ws: string,
    query?: ListConnectionsQuery,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<ConnectionPage>>;
  createConnection(
    ws: string,
    body: ConnectionWrite,
    options: IdempotentMutationOptions,
  ): Promise<ApiEnvelope<Connection>>;
  getConnection(
    ws: string,
    connectionId: string,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<ConnectionDetailResponse>>;
  updateConnection(
    ws: string,
    connectionId: string,
    body: ConnectionPatchRequest,
    options: IdempotentOptimisticMutationOptions,
  ): Promise<ApiEnvelope<Connection>>;
  deleteConnection(
    ws: string,
    connectionId: string,
    options: IdempotentMutationOptions,
  ): Promise<ApiEnvelope<ActionReceipt>>;
  probeConnection(
    ws: string,
    connectionId: string,
    options: IdempotentMutationOptions,
  ): Promise<ApiEnvelope<ConnectionProbeResponse>>;
  syncConnection(
    ws: string,
    connectionId: string,
    options: IdempotentMutationOptions,
  ): Promise<ApiEnvelope<ConnectionSyncResponse>>;
  reconcileConnectionRuns(
    ws: string,
    connectionId: string,
    body: Partial<ConnectionReconcileRequest> | null,
    options: IdempotentMutationOptions,
  ): Promise<ApiEnvelope<ConnectionReconcileResponse>>;
  mintGitHubInstallState(
    ws: string,
    connectionId: string,
    body: GitHubInstallStateCreateRequest | null,
    options: IdempotentMutationOptions,
  ): Promise<ApiEnvelope<GitHubInstallStateResponse>>;
  handleGitHubCallback(
    query: GitHubCallbackQuery,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<GitHubCallbackResponse>>;
  confirmGitHubInstallation(
    ws: string,
    connectionId: string,
    body: GitHubInstallationConfirmRequest,
    options: IdempotentMutationOptions,
  ): Promise<ApiEnvelope<GitHubInstallationConfirmResponse>>;
  listRepositories(
    ws: string,
    query?: ListRepositoriesQuery,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<RepositoryCatalogPage>>;
  getRepository(
    ws: string,
    repositoryId: string,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<RepositoryDetailResponse>>;
  updateRepository(
    ws: string,
    repositoryId: string,
    body: RepositoryUpdateRequest,
    options?: OptimisticMutationOptions,
  ): Promise<ApiEnvelope<Repository>>;
  getRepositoryPolicy(
    ws: string,
    repositoryId: string,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<RepositoryPolicyStateResponse>>;
  updateRepositoryPolicy(
    ws: string,
    repositoryId: string,
    body: RepositoryPolicyUpdateRequest,
    options?: OptimisticMutationOptions,
  ): Promise<ApiEnvelope<RepositoryPolicyStateResponse>>;
  previewRepositoryPolicy(
    ws: string,
    repositoryId: string,
    body: RepositoryPolicyPreviewRequest,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<RepositoryPolicyPreviewResponse>>;
  previewBulkRepositoryPolicies(
    ws: string,
    body: BulkRepositoryPreviewRequest,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<BulkRepositoryPreviewResponse>>;
  bulkUpdateRepositories(
    ws: string,
    body: BulkRepositoryUpdateRequest,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<BulkRepositoryUpdateResponse>>;
  listRuns(
    ws: string,
    query?: ListRunsQuery,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<CiRunPage>>;
  getRun(
    ws: string,
    runId: string,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<CiRunDetailResponse>>;
  listRunJobs(
    ws: string,
    runId: string,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<CiJobListResponse>>;
  getJobLog(
    ws: string,
    jobId: string,
    query?: GetJobLogQuery,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<JobLogChunkResponse>>;
  downloadArtifact(
    ws: string,
    artifactId: string,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<DownloadedArtifactPayload>>;
  listSystemWorkers(
    query?: ListSystemWorkersQuery,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<WorkerPage>>;
  createWorkerEnrollment(
    body: WorkerEnrollmentCreateRequest,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<WorkerEnrollmentCreateResponse>>;
  performWorkerAction(
    workerId: string,
    body: WorkerActionRequest,
    options: IdempotentOptimisticMutationOptions,
  ): Promise<ApiEnvelope<ActionReceipt>>;
  runWorkerSelfTest(
    workerId: string,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<WorkerSelfTestResponse>>;
  getWorkspaceWorkerReadiness(
    ws: string,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<WorkspaceWorkerReadinessResponse>>;
  listWorkspaceModels(
    ws: string,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<WorkspaceModelsResponse>>;
  updateWorkspaceModelsConfig(
    ws: string,
    body: WorkspaceModelsConfigUpdateRequest,
    options: IdempotentOptimisticMutationOptions,
  ): Promise<ApiEnvelope<WorkspaceModelsConfigUpdateResponse>>;
  grantWorkspaceInferenceConsent(
    ws: string,
    body: WorkspaceInferenceConsentCreateRequest,
    options: IdempotentMutationOptions,
  ): Promise<ApiEnvelope<ConsentRecord>>;
  revokeWorkspaceInferenceConsent(
    ws: string,
    consentId: string,
    body?: ConsentRevokeRequest,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<ConsentRecord>>;
  createWorkspaceModelProbe(
    ws: string,
    body: ModelProbeRequest,
    options: IdempotentMutationOptions,
  ): Promise<ApiEnvelope<ModelProbeResponse>>;
  listWorkspaceAgentProfiles(
    ws: string,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<WorkspaceAgentProfilesResponse>>;
  getWorkspaceAgentProfile(
    ws: string,
    profileId: string,
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<AgentProfile>>;
  updateWorkspaceAgentProfile(
    ws: string,
    profileId: string,
    body: AgentProfileUpdateRequest,
    options: IdempotentOptimisticMutationOptions,
  ): Promise<ApiEnvelope<AgentProfileUpdateResponse>>;
  listWorkspaceRepairs(
    ws: string,
    query?: { readonly state?: string; readonly proof_grade?: string; readonly remote_status?: string; readonly limit?: number; readonly cursor?: string },
    options?: RequestCallOptions,
  ): Promise<ApiEnvelope<RepairPageResponse>>;
  createWorkspaceRepair(ws: string, body: RepairCreateRequest, options: IdempotentMutationOptions): Promise<ApiEnvelope<ActionReceipt>>;
  getWorkspaceRepair(ws: string, repairId: string, options?: RequestCallOptions): Promise<ApiEnvelope<Repair>>;
  getWorkspaceRepairEvidence(ws: string, repairId: string, kind: "diagnosis" | "patches" | "verification", options?: RequestCallOptions): Promise<ApiEnvelope<{ readonly items: readonly Record<string, unknown>[]; readonly reproductions?: readonly Record<string, unknown>[]; readonly next_cursor: string | null; readonly snapshot_at: string }>>;
  getWorkspaceRepairTimeline(ws: string, repairId: string, options?: RequestCallOptions): Promise<ApiEnvelope<{ readonly items: readonly Record<string, unknown>[]; readonly next_cursor: string | null; readonly snapshot_at: string }>>;
  performRepairAction(ws: string, repairId: string, body: RepairActionRequest, options: IdempotentMutationOptions): Promise<ApiEnvelope<ActionReceipt>>;
  listWorkspaceApprovals(ws: string, query?: { readonly status?: string; readonly repository_id?: string; readonly limit?: number; readonly cursor?: string }, options?: RequestCallOptions): Promise<ApiEnvelope<ApprovalPageResponse>>;
  listWorkspaceNotifications(ws: string, query?: { readonly unread?: boolean; readonly severity?: string; readonly limit?: number; readonly cursor?: string }, options?: RequestCallOptions): Promise<ApiEnvelope<NotificationInboxPage>>;
  getWorkspaceNotification(ws: string, notificationId: string, options?: RequestCallOptions): Promise<ApiEnvelope<NotificationInboxItem>>;
  updateWorkspaceNotificationReadState(ws: string, notificationId: string, body: NotificationReadPatchRequest, options?: RequestCallOptions): Promise<ApiEnvelope<NotificationInboxItem>>;
  listNotificationDestinations(ws: string, query?: { readonly limit?: number; readonly cursor?: string }, options?: RequestCallOptions): Promise<ApiEnvelope<NotificationDestinationPage>>;
  createNotificationDestination(ws: string, body: NotificationDestinationCreateRequest, options?: IdempotentMutationOptions): Promise<ApiEnvelope<NotificationDestination>>;
  patchNotificationDestination(ws: string, destinationId: string, body: NotificationDestinationPatchRequest, options: RequiredOptimisticMutationOptions): Promise<ApiEnvelope<NotificationDestination>>;
  deleteNotificationDestination(ws: string, destinationId: string, options?: RequestCallOptions): Promise<{ correlationId: string | null }>;
  testNotificationDestination(ws: string, destinationId: string, body: NotificationTestRequest, options?: RequestCallOptions): Promise<{ correlationId: string | null }>;
  listNotificationDeliveries(ws: string, query?: { readonly destination_id?: string; readonly state?: string; readonly limit?: number; readonly cursor?: string }, options?: RequestCallOptions): Promise<ApiEnvelope<NotificationDeliveryPage>>;
  getNotificationPreferences(workspaceId?: string, options?: RequestCallOptions): Promise<ApiEnvelope<NotificationPreferencesState>>;
  patchNotificationPreferences(body: NotificationPreferencesPatchRequest, options?: RequestCallOptions): Promise<ApiEnvelope<NotificationPreferencesState>>;
  getWorkspaceApproval(ws: string, approvalId: string, options?: RequestCallOptions): Promise<ApiEnvelope<Approval>>;
  decideWorkspaceApproval(ws: string, approvalId: string, body: ApprovalDecisionRequest, options: IdempotentMutationOptions): Promise<ApiEnvelope<Approval>>;
  listWorkspacePublications(ws: string, options?: RequestCallOptions): Promise<ApiEnvelope<PublicationPageResponse>>;
  getWorkspacePublication(ws: string, publicationId: string, options?: RequestCallOptions): Promise<ApiEnvelope<PublicationDetailResponse>>;
  reconcileWorkspacePublication(ws: string, publicationId: string, body: PublicationReconciliationRequest, options: IdempotentMutationOptions): Promise<ApiEnvelope<ActionReceipt>>;
}

function readCookieFromDocument(cookieName: string): string | null {
  if (typeof document === "undefined" || typeof document.cookie !== "string") {
    return null;
  }
  const prefix = `${cookieName}=`;
  for (const part of document.cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) {
      return decodeURIComponent(trimmed.slice(prefix.length));
    }
  }
  return null;
}

function parseRetryAfter(response: Response): number | null {
  const raw = response.headers.get("Retry-After");
  if (raw === null) {
    return null;
  }
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function coerceProblem(errorBody: unknown, response: Response): Problem {
  if (
    typeof errorBody === "object" &&
    errorBody !== null &&
    "code" in errorBody &&
    "detail" in errorBody &&
    "title" in errorBody &&
    typeof errorBody.code === "string" &&
    typeof errorBody.detail === "string" &&
    typeof errorBody.title === "string"
  ) {
    return errorBody as Problem;
  }
  const corr = response.headers.get("X-Correlation-Id") ?? "unassigned";
  return {
    type: "https://red2pr.local/problems/unexpected_response",
    title: "Request failed",
    status: response.status,
    code: "unexpected_response",
    detail: `HTTP ${String(response.status)} response did not include canonical Problem+JSON body.`,
    correlation_id: corr,
    errors: null,
  };
}

function buildOptionalHeaders(
  reqOptions?: RequestCallOptions & {
    readonly ifMatch?: string;
    readonly idempotencyKey?: string;
  },
): Record<string, string> {
  const headers: Record<string, string> = {};
  if (reqOptions?.correlationId !== undefined) {
    headers["X-Correlation-Id"] = reqOptions.correlationId;
  }
  if (reqOptions?.ifMatch !== undefined) {
    headers["If-Match"] = reqOptions.ifMatch;
  }
  if (reqOptions?.idempotencyKey !== undefined) {
    headers["Idempotency-Key"] = reqOptions.idempotencyKey;
  }
  return headers;
}

function parseAttachmentFilename(response: Response): string | null {
  const disp = response.headers.get("Content-Disposition");
  if (disp === null) {
    return null;
  }
  const match = /filename="?([^";\r\n]+)"?/i.exec(disp);
  return match?.[1] ?? null;
}

function toEnvelope<TData>(data: TData, response: Response): ApiEnvelope<TData> {
  return {
    data,
    correlationId: response.headers.get("X-Correlation-Id"),
    etag: response.headers.get("ETag"),
  };
}

function unwrapEnvelope<TData>(result: {
  readonly data?: TData;
  readonly error?: unknown;
  readonly response: Response;
}): ApiEnvelope<TData> {
  if (result.data === undefined) {
    throw new Red2PrApiError(
      coerceProblem(result.error, result.response),
      parseRetryAfter(result.response),
    );
  }
  return toEnvelope(result.data, result.response);
}

export function createRed2PrClient(options: Red2PrClientOptions = {}): Red2PrClient {
  const { getCsrfToken, ...fetchClientOptions } = options;
  // Held strictly in JS heap memory; never persisted in localStorage or sessionStorage.
  let memoryCsrfToken: string | null = null;

  const resolveActiveCsrfToken = (): string | null => {
    const external = getCsrfToken?.();
    if (typeof external === "string" && external.length > 0) {
      return external;
    }
    if (typeof memoryCsrfToken === "string" && memoryCsrfToken.length > 0) {
      return memoryCsrfToken;
    }
    return readCookieFromDocument(CSRF_COOKIE_NAME);
  };

  const raw = createClient<paths>({
    baseUrl: "",
    credentials: "same-origin",
    ...fetchClientOptions,
  });

  const headerMiddleware: Middleware = {
    async onRequest({ request }) {
      if (!request.headers.has("Accept")) {
        request.headers.set("Accept", "application/json, application/problem+json");
      }
      if (MUTATING_METHODS.has(request.method.toUpperCase())) {
        const csrfToken = resolveActiveCsrfToken();
        if (typeof csrfToken === "string" && csrfToken.length > 0) {
          request.headers.set("X-CSRF-Token", csrfToken);
        }
      }
      return request;
    },
  };

  raw.use(headerMiddleware);

  const ensurePreAuthCsrf = async (reqOptions?: RequestCallOptions): Promise<void> => {
    if (resolveActiveCsrfToken() !== null) {
      return;
    }
    const { data, error, response } = await raw.GET("/api/v1/auth/csrf", {
      headers: buildOptionalHeaders(reqOptions),
      signal: reqOptions?.signal,
    });
    if (data === undefined) {
      throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
    }
    memoryCsrfToken = data.csrf_token;
  };

  type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  type AnyCallOptions = RequestCallOptions & {
    readonly ifMatch?: string;
    readonly idempotencyKey?: string;
  };

  const callJson = async <TData>(
    method: HttpMethod,
    url: string,
    init?: {
      readonly path?: Record<string, unknown>;
      readonly query?: unknown;
      readonly body?: unknown;
      readonly options?: AnyCallOptions;
    },
  ): Promise<ApiEnvelope<TData>> => {
    const fn = raw[method] as unknown as (
      u: string,
      o: Record<string, unknown>,
    ) => Promise<{
      readonly data?: TData;
      readonly error?: unknown;
      readonly response: Response;
    }>;
    return unwrapEnvelope(
      await fn(url, {
        ...(init?.path !== undefined || init?.query !== undefined
          ? {
              params: {
                ...(init?.path !== undefined ? { path: init.path } : {}),
                ...(init?.query !== undefined ? { query: init.query } : {}),
              },
            }
          : {}),
        ...(init?.body !== undefined ? { body: init.body } : {}),
        headers: buildOptionalHeaders(init?.options),
        signal: init?.options?.signal,
      }),
    );
  };

  const callVoid = async (
    method: HttpMethod,
    url: string,
    init?: {
      readonly path?: Record<string, unknown>;
      readonly body?: unknown;
      readonly options?: AnyCallOptions;
    },
  ): Promise<{ readonly correlationId: string | null }> => {
    const fn = raw[method] as unknown as (
      u: string,
      o: Record<string, unknown>,
    ) => Promise<{
      readonly error?: unknown;
      readonly response: Response;
    }>;
    const { error, response } = await fn(url, {
      ...(init?.path !== undefined ? { params: { path: init.path } } : {}),
      ...(init?.body !== undefined ? { body: init.body } : {}),
      headers: buildOptionalHeaders(init?.options),
      signal: init?.options?.signal,
    });
    if (!response.ok) {
      throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
    }
    return { correlationId: response.headers.get("X-Correlation-Id") };
  };

  const syncCsrf = <T extends { readonly csrf_token?: string | null }>(
    env: ApiEnvelope<T>,
  ): ApiEnvelope<T> => {
    if (typeof env.data.csrf_token === "string" && env.data.csrf_token.length > 0) {
      memoryCsrfToken = env.data.csrf_token;
    }
    return env;
  };

  return {
    raw,
    setCsrfToken(token: string | null) {
      memoryCsrfToken = token;
    },
    getSystemHealth: (options) => callJson("GET", "/api/v1/system/health", { options }),
    getAuthCsrf: async (options) => syncCsrf(await callJson("GET", "/api/v1/auth/csrf", { options })),
    async claimInstanceOwner(body, options) {
      await ensurePreAuthCsrf(options);
      return syncCsrf(await callJson("POST", "/api/v1/setup/claim", { body, options }));
    },
    getSetupState: (options) => callJson("GET", "/api/v1/setup", { options }),
    submitSetupStep: (phase, body, options) =>
      callJson("POST", "/api/v1/setup/steps/{phase}", { path: { phase }, body, options }),
    listSetupConsents: (query, options) =>
      callJson("GET", "/api/v1/setup/consents", { query, options }),
    grantSetupConsent: (body, options) =>
      callJson("POST", "/api/v1/setup/consents", { body, options }),
    revokeSetupConsent: (consentId, body = {}, options) =>
      callJson("DELETE", "/api/v1/setup/consents/{consent_id}", {
        path: { consent_id: consentId },
        body,
        options,
      }),
    listEndpointRegistrations: (query, options) =>
      callJson("GET", "/api/v1/setup/endpoints", { query, options }),
    registerPrivateEndpoint: (body, options) =>
      callJson("POST", "/api/v1/setup/endpoints", { body, options }),
    revokePrivateEndpoint: (endpointId, options) =>
      callJson("DELETE", "/api/v1/setup/endpoints/{endpoint_id}", {
        path: { endpoint_id: endpointId },
        options,
      }),
    async login(body, options) {
      await ensurePreAuthCsrf(options);
      return syncCsrf(await callJson("POST", "/api/v1/auth/login", { body, options }));
    },
    async logout(options) {
      const res = await callVoid("POST", "/api/v1/auth/logout", { body: {}, options });
      memoryCsrfToken = null;
      return res;
    },
    stepUp: async (body, options) =>
      syncCsrf(await callJson("POST", "/api/v1/auth/step-up", { body, options })),
    async recoverAccount(body, options) {
      await ensurePreAuthCsrf(options);
      return syncCsrf(await callJson("POST", "/api/v1/auth/recovery", { body, options }));
    },
    getMe: async (options) => syncCsrf(await callJson("GET", "/api/v1/me", { options })),
    createMyTelegramLinkChallenge: (options) =>
      callJson("POST", "/api/v1/me/telegram-link-challenges", { options }),
    deleteMyTelegramLink: (options) =>
      callVoid("DELETE", "/api/v1/me/telegram-link", { options }),
    previewTelegramIntent: (body, options) =>
      callJson("POST", "/api/v1/me/telegram-intents/preview", { body, options }),
    confirmTelegramIntent: (body, options) =>
      callJson("POST", "/api/v1/me/telegram-intents/confirm", { body, options }),
    listMySessions: (options) => callJson("GET", "/api/v1/me/sessions", { options }),
    revokeMySession: (sessionId, options) =>
      callVoid("DELETE", "/api/v1/me/sessions/{session_id}", {
        path: { session_id: sessionId },
        options,
      }),
    enrollMyMfa: async (body = {}, options) =>
      syncCsrf(await callJson("POST", "/api/v1/me/mfa", { body, options })),
    deleteMyMfa: (body, options) => callVoid("DELETE", "/api/v1/me/mfa", { body, options }),
    listWorkspaces: (query, options) =>
      callJson("GET", "/api/v1/workspaces", { query, options }),
    createWorkspace: (body, options) =>
      callJson("POST", "/api/v1/workspaces", { body, options }),
    getWorkspace: (ws, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}", { path: { ws }, options }),
    updateWorkspace: (ws, body, options) =>
      callJson("PATCH", "/api/v1/workspaces/{ws}", { path: { ws }, body, options }),
    deleteWorkspace: (ws, body, options) =>
      callJson("DELETE", "/api/v1/workspaces/{ws}", { path: { ws }, body, options }),
    listBreakGlassGrants: (ws, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/break-glass", { path: { ws }, options }),
    createBreakGlassGrant: (ws, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/break-glass", { path: { ws }, body, options }),
    revokeBreakGlassGrant: (ws, grantId, options) =>
      callVoid("DELETE", "/api/v1/workspaces/{ws}/break-glass/{grant_id}", {
        path: { ws, grant_id: grantId },
        options,
      }),
    listWorkspaceMembers: (ws, query, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/members", { path: { ws }, query, options }),
    updateWorkspaceMember: (ws, memberId, body, options) =>
      callJson("PATCH", "/api/v1/workspaces/{ws}/members/{member_id}", {
        path: { ws, member_id: memberId },
        body,
        options,
      }),
    removeWorkspaceMember: (ws, memberId, options) =>
      callVoid("DELETE", "/api/v1/workspaces/{ws}/members/{member_id}", {
        path: { ws, member_id: memberId },
        options,
      }),
    listWorkspaceInvitations: (ws, query, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/invitations", { path: { ws }, query, options }),
    createWorkspaceInvitation: (ws, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/invitations", { path: { ws }, body, options }),
    revokeWorkspaceInvitation: (ws, inviteId, options) =>
      callVoid("DELETE", "/api/v1/workspaces/{ws}/invitations/{invite_id}", {
        path: { ws, invite_id: inviteId },
        options,
      }),
    acceptWorkspaceInvitation: (body, options) =>
      callJson("POST", "/api/v1/invitations/accept", { body, options }),
    listTaskJobs: (ws, query, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/task-jobs", { path: { ws }, query, options }),
    getTaskJob: (ws, jobId, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/task-jobs/{job_id}", {
        path: { ws, job_id: jobId },
        options,
      }),
    performTaskJobAction: (ws, jobId, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/task-jobs/{job_id}/actions", {
        path: { ws, job_id: jobId },
        body,
        options,
      }),
    getOperationReceipt: (operationId, options) =>
      callJson("GET", "/api/v1/operations/{operation_id}", {
        path: { operation_id: operationId },
        options,
      }),
    listConnections: (ws, query, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/integrations", { path: { ws }, query, options }),
    createConnection: (ws, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/integrations", { path: { ws }, body, options }),
    getConnection: (ws, connectionId, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/integrations/{connection_id}", {
        path: { ws, connection_id: connectionId },
        options,
      }),
    updateConnection: (ws, connectionId, body, options) =>
      callJson("PATCH", "/api/v1/workspaces/{ws}/integrations/{connection_id}", {
        path: { ws, connection_id: connectionId },
        body,
        options,
      }),
    deleteConnection: (ws, connectionId, options) =>
      callJson("DELETE", "/api/v1/workspaces/{ws}/integrations/{connection_id}", {
        path: { ws, connection_id: connectionId },
        options,
      }),
    probeConnection: (ws, connectionId, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/integrations/{connection_id}/probes", {
        path: { ws, connection_id: connectionId },
        options,
      }),
    syncConnection: (ws, connectionId, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/integrations/{connection_id}/sync", {
        path: { ws, connection_id: connectionId },
        options,
      }),
    reconcileConnectionRuns: (ws, connectionId, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/integrations/{connection_id}/reconcile", {
        path: { ws, connection_id: connectionId },
        body: {
          repository_ids: body?.repository_ids ?? null,
          acknowledge_history_gap: body?.acknowledge_history_gap ?? false,
          force_poll: body?.force_poll ?? false,
        },
        options,
      }),
    mintGitHubInstallState: (ws, connectionId, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/integrations/{connection_id}/installations/state", {
        path: { ws, connection_id: connectionId },
        body: body ?? {},
        options,
      }),
    handleGitHubCallback: (query, options) =>
      callJson("GET", "/api/v1/integrations/github/callback", { query, options }),
    confirmGitHubInstallation: (ws, connectionId, body, options) =>
      callJson(
        "POST",
        "/api/v1/workspaces/{ws}/integrations/{connection_id}/installations/confirm",
        { path: { ws, connection_id: connectionId }, body, options },
      ),
    listRepositories: (ws, query, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/repositories", { path: { ws }, query, options }),
    getRepository: (ws, repositoryId, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/repositories/{repository_id}", {
        path: { ws, repository_id: repositoryId },
        options,
      }),
    updateRepository: (ws, repositoryId, body, options) =>
      callJson("PATCH", "/api/v1/workspaces/{ws}/repositories/{repository_id}", {
        path: { ws, repository_id: repositoryId },
        body,
        options,
      }),
    getRepositoryPolicy: (ws, repositoryId, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/repositories/{repository_id}/policy", {
        path: { ws, repository_id: repositoryId },
        options,
      }),
    updateRepositoryPolicy: (ws, repositoryId, body, options) =>
      callJson("PATCH", "/api/v1/workspaces/{ws}/repositories/{repository_id}/policy", {
        path: { ws, repository_id: repositoryId },
        body,
        options,
      }),
    previewRepositoryPolicy: (ws, repositoryId, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/repositories/{repository_id}/policy/previews", {
        path: { ws, repository_id: repositoryId },
        body,
        options,
      }),
    previewBulkRepositoryPolicies: (ws, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/repositories/policy-previews", {
        path: { ws },
        body,
        options,
      }),
    bulkUpdateRepositories: (ws, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/repositories/bulk-update", {
        path: { ws },
        body,
        options,
      }),
    listRuns: (ws, query, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/runs", { path: { ws }, query, options }),
    getRun: (ws, runId, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/runs/{run_id}", {
        path: { ws, run_id: runId },
        options,
      }),
    listRunJobs: (ws, runId, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/runs/{run_id}/jobs", {
        path: { ws, run_id: runId },
        options,
      }),
    getJobLog: (ws, jobId, query, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/jobs/{job_id}/log", {
        path: { ws, job_id: jobId },
        query,
        options,
      }),
    async downloadArtifact(ws, artifactId, reqOptions) {
      const { data, error, response } = await raw.GET(
        "/api/v1/workspaces/{ws}/artifacts/{artifact_id}/download",
        {
          params: { path: { ws, artifact_id: artifactId } },
          parseAs: "arrayBuffer",
          headers: {
            Accept: "*/*, application/problem+json",
            ...buildOptionalHeaders(reqOptions),
          },
          signal: reqOptions?.signal,
        },
      );
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(
        {
          bytes: data,
          contentType: response.headers.get("Content-Type") ?? "application/octet-stream",
          filename: parseAttachmentFilename(response),
        },
        response,
      );
    },
    listSystemWorkers: (query, options) =>
      callJson("GET", "/api/v1/system/workers", { query, options }),
    createWorkerEnrollment: (body, options) =>
      callJson("POST", "/api/v1/system/workers/enrollments", { body, options }),
    performWorkerAction: (workerId, body, options) =>
      callJson("POST", "/api/v1/system/workers/{worker_id}/actions", {
        path: { worker_id: workerId },
        body,
        options,
      }),
    runWorkerSelfTest: (workerId, options) =>
      callJson("POST", "/api/v1/system/workers/{worker_id}/self-test", {
        path: { worker_id: workerId },
        options,
      }),
    getWorkspaceWorkerReadiness: (ws, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/workers/readiness", { path: { ws }, options }),
    listWorkspaceModels: (ws, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/models", { path: { ws }, options }),
    updateWorkspaceModelsConfig: (ws, body, options) =>
      callJson("PATCH", "/api/v1/workspaces/{ws}/models/config", { path: { ws }, body, options }),
    grantWorkspaceInferenceConsent: (ws, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/models/consents", { path: { ws }, body, options }),
    revokeWorkspaceInferenceConsent: (ws, consentId, body, options) =>
      callJson("DELETE", "/api/v1/workspaces/{ws}/models/consents/{consent_id}", {
        path: { ws, consent_id: consentId },
        body: body ?? {},
        options,
      }),
    createWorkspaceModelProbe: (ws, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/model-probes", { path: { ws }, body, options }),
    listWorkspaceAgentProfiles: (ws, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/agent-profiles", { path: { ws }, options }),
    getWorkspaceAgentProfile: (ws, profileId, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/agent-profiles/{profile_id}", {
        path: { ws, profile_id: profileId },
        options,
      }),
    updateWorkspaceAgentProfile: (ws, profileId, body, options) =>
      callJson("PATCH", "/api/v1/workspaces/{ws}/agent-profiles/{profile_id}", {
        path: { ws, profile_id: profileId },
        body,
        options,
      }),
    listWorkspaceRepairs: (ws, query, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/repairs", { path: { ws }, query, options }),
    createWorkspaceRepair: (ws, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/repairs", { path: { ws }, body, options }),
    getWorkspaceRepair: (ws, repairId, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/repairs/{repair_id}", {
        path: { ws, repair_id: repairId },
        options,
      }),
    getWorkspaceRepairEvidence: (ws, repairId, kind, options) =>
      callJson("GET", `/api/v1/workspaces/{ws}/repairs/{repair_id}/${kind}`, {
        path: { ws, repair_id: repairId },
        options,
      }),
    getWorkspaceRepairTimeline: (ws, repairId, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/repairs/{repair_id}/timeline", {
        path: { ws, repair_id: repairId },
        options,
      }),
    performRepairAction: (ws, repairId, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/repairs/{repair_id}/actions", {
        path: { ws, repair_id: repairId },
        body,
        options,
      }),
    listWorkspaceApprovals: (ws, query, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/approvals", { path: { ws }, query, options }),
    listWorkspaceNotifications: (ws, query, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/notifications", { path: { ws }, query, options }),
    getWorkspaceNotification: (ws, notificationId, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/notifications/{notification_id}", { path: { ws, notification_id: notificationId }, options }),
    updateWorkspaceNotificationReadState: (ws, notificationId, body, options) =>
      callJson("PATCH", "/api/v1/workspaces/{ws}/notifications/{notification_id}", { path: { ws, notification_id: notificationId }, body, options }),
    listNotificationDestinations: (ws, query, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/notification-destinations", { path: { ws }, query, options }),
    createNotificationDestination: (ws, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/notification-destinations", { path: { ws }, body, options }),
    patchNotificationDestination: (ws, destinationId, body, options) =>
      callJson("PATCH", "/api/v1/workspaces/{ws}/notification-destinations/{destination_id}", { path: { ws, destination_id: destinationId }, body, options }),
    deleteNotificationDestination: (ws, destinationId, options) =>
      callVoid("DELETE", "/api/v1/workspaces/{ws}/notification-destinations/{destination_id}", { path: { ws, destination_id: destinationId }, options }),
    testNotificationDestination: (ws, destinationId, body, options) =>
      callVoid("POST", "/api/v1/workspaces/{ws}/notification-destinations/{destination_id}/tests", { path: { ws, destination_id: destinationId }, body, options }),
    listNotificationDeliveries: (ws, query, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/notification-deliveries", { path: { ws }, query, options }),
    getNotificationPreferences: (workspaceId, options) =>
      callJson("GET", "/api/v1/me/notification-preferences", { query: workspaceId ? { workspace_id: workspaceId } : undefined, options }),
    patchNotificationPreferences: (body, options) =>
      callJson("PATCH", "/api/v1/me/notification-preferences", { body, options }),
    getWorkspaceApproval: (ws, approvalId, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/approvals/{approval_id}", {
        path: { ws, approval_id: approvalId },
        options,
      }),
    decideWorkspaceApproval: (ws, approvalId, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/approvals/{approval_id}/decisions", {
        path: { ws, approval_id: approvalId },
        body,
        options,
      }),
    listWorkspacePublications: (ws, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/publications", { path: { ws }, options }),
    getWorkspacePublication: (ws, publicationId, options) =>
      callJson("GET", "/api/v1/workspaces/{ws}/publications/{publication_id}", {
        path: { ws, publication_id: publicationId },
        options,
      }),
    reconcileWorkspacePublication: (ws, publicationId, body, options) =>
      callJson("POST", "/api/v1/workspaces/{ws}/publications/{publication_id}/reconciliations", {
        path: { ws, publication_id: publicationId },
        body,
        options,
      }),
  };
}

export type { components, operations, paths };
