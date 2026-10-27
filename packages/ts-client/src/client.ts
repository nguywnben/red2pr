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
export type Connection = SchemaOf<"Connection">;
export type ConnectionWrite = SchemaOf<"ConnectionWrite">;
export type Repository = SchemaOf<"Repository">;
export type RepositoryPolicy = SchemaOf<"RepositoryPolicy">;
export type CiRun = SchemaOf<"CiRun">;
export type CiJob = SchemaOf<"CiJob">;
export type Repair = SchemaOf<"Repair">;
export type Diagnosis = SchemaOf<"Diagnosis">;
export type Patch = SchemaOf<"Patch">;
export type Verification = SchemaOf<"Verification">;
export type Approval = SchemaOf<"Approval">;
export type Publication = SchemaOf<"Publication">;
export type RemoteCheck = SchemaOf<"RemoteCheck">;
export type Artifact = SchemaOf<"Artifact">;
export type Worker = SchemaOf<"Worker">;
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
export type NotificationDelivery = SchemaOf<"NotificationDelivery">;
export type NotificationPreference = SchemaOf<"NotificationPreference">;
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
export type EvidenceManifestV1 = SchemaOf<"EvidenceManifestV1">;

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const CSRF_COOKIE_NAME = "red2pr_csrf";

export interface RequestCallOptions {
  readonly correlationId?: string;
  readonly signal?: AbortSignal;
}

export interface OptimisticMutationOptions extends RequestCallOptions {
  readonly ifMatch?: string;
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

function toEnvelope<TData>(data: TData, response: Response): ApiEnvelope<TData> {
  return {
    data,
    correlationId: response.headers.get("X-Correlation-Id"),
    etag: response.headers.get("ETag"),
  };
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

  return {
    raw,
    setCsrfToken(token: string | null) {
      memoryCsrfToken = token;
    },
    async getSystemHealth(reqOptions) {
      const { data, error, response } = await raw.GET("/api/v1/system/health", {
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async getAuthCsrf(reqOptions) {
      const { data, error, response } = await raw.GET("/api/v1/auth/csrf", {
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      memoryCsrfToken = data.csrf_token;
      return toEnvelope(data, response);
    },
    async claimInstanceOwner(body, reqOptions) {
      await ensurePreAuthCsrf(reqOptions);
      const { data, error, response } = await raw.POST("/api/v1/setup/claim", {
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      memoryCsrfToken = data.csrf_token;
      return toEnvelope(data, response);
    },
    async getSetupState(reqOptions) {
      const { data, error, response } = await raw.GET("/api/v1/setup", {
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async submitSetupStep(phase, body, reqOptions) {
      const { data, error, response } = await raw.POST("/api/v1/setup/steps/{phase}", {
        params: { path: { phase } },
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async listSetupConsents(query, reqOptions) {
      const { data, error, response } = await raw.GET("/api/v1/setup/consents", {
        params: { query },
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async grantSetupConsent(body, reqOptions) {
      const { data, error, response } = await raw.POST("/api/v1/setup/consents", {
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async revokeSetupConsent(consentId, body = {}, reqOptions) {
      const { data, error, response } = await raw.DELETE("/api/v1/setup/consents/{consent_id}", {
        params: { path: { consent_id: consentId } },
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async listEndpointRegistrations(query, reqOptions) {
      const { data, error, response } = await raw.GET("/api/v1/setup/endpoints", {
        params: { query },
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async registerPrivateEndpoint(body, reqOptions) {
      const { data, error, response } = await raw.POST("/api/v1/setup/endpoints", {
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async revokePrivateEndpoint(endpointId, reqOptions) {
      const { data, error, response } = await raw.DELETE("/api/v1/setup/endpoints/{endpoint_id}", {
        params: { path: { endpoint_id: endpointId } },
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async login(body, reqOptions) {
      await ensurePreAuthCsrf(reqOptions);
      const { data, error, response } = await raw.POST("/api/v1/auth/login", {
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      if (typeof data.csrf_token === "string" && data.csrf_token.length > 0) {
        memoryCsrfToken = data.csrf_token;
      }
      return toEnvelope(data, response);
    },
    async logout(reqOptions) {
      const { error, response } = await raw.POST("/api/v1/auth/logout", {
        body: {},
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (!response.ok) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      memoryCsrfToken = null;
      return {
        correlationId: response.headers.get("X-Correlation-Id"),
      };
    },
    async stepUp(body, reqOptions) {
      const { data, error, response } = await raw.POST("/api/v1/auth/step-up", {
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      memoryCsrfToken = data.csrf_token;
      return toEnvelope(data, response);
    },
    async recoverAccount(body, reqOptions) {
      await ensurePreAuthCsrf(reqOptions);
      const { data, error, response } = await raw.POST("/api/v1/auth/recovery", {
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      memoryCsrfToken = data.csrf_token;
      return toEnvelope(data, response);
    },
    async getMe(reqOptions) {
      const { data, error, response } = await raw.GET("/api/v1/me", {
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      memoryCsrfToken = data.csrf_token;
      return toEnvelope(data, response);
    },
    async listMySessions(reqOptions) {
      const { data, error, response } = await raw.GET("/api/v1/me/sessions", {
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async revokeMySession(sessionId, reqOptions) {
      const { error, response } = await raw.DELETE("/api/v1/me/sessions/{session_id}", {
        params: { path: { session_id: sessionId } },
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (!response.ok) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return {
        correlationId: response.headers.get("X-Correlation-Id"),
      };
    },
    async enrollMyMfa(body = {}, reqOptions) {
      const { data, error, response } = await raw.POST("/api/v1/me/mfa", {
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      if (typeof data.csrf_token === "string" && data.csrf_token.length > 0) {
        memoryCsrfToken = data.csrf_token;
      }
      return toEnvelope(data, response);
    },
    async deleteMyMfa(body, reqOptions) {
      const { error, response } = await raw.DELETE("/api/v1/me/mfa", {
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (!response.ok) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return {
        correlationId: response.headers.get("X-Correlation-Id"),
      };
    },
    async listWorkspaces(query, reqOptions) {
      const { data, error, response } = await raw.GET("/api/v1/workspaces", {
        params: { query },
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async createWorkspace(body, reqOptions) {
      const { data, error, response } = await raw.POST("/api/v1/workspaces", {
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async getWorkspace(ws, reqOptions) {
      const { data, error, response } = await raw.GET("/api/v1/workspaces/{ws}", {
        params: { path: { ws } },
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async updateWorkspace(ws, body, reqOptions) {
      const { data, error, response } = await raw.PATCH("/api/v1/workspaces/{ws}", {
        params: {
          path: { ws },
          header: reqOptions?.ifMatch ? { "If-Match": reqOptions.ifMatch } : undefined,
        },
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async deleteWorkspace(ws, body, reqOptions) {
      const { data, error, response } = await raw.DELETE("/api/v1/workspaces/{ws}", {
        params: {
          path: { ws },
          header: { "Idempotency-Key": reqOptions.idempotencyKey },
        },
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async listBreakGlassGrants(ws, reqOptions) {
      const { data, error, response } = await raw.GET("/api/v1/workspaces/{ws}/break-glass", {
        params: { path: { ws } },
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async createBreakGlassGrant(ws, body, reqOptions) {
      const { data, error, response } = await raw.POST("/api/v1/workspaces/{ws}/break-glass", {
        params: { path: { ws } },
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async revokeBreakGlassGrant(ws, grantId, reqOptions) {
      const { error, response } = await raw.DELETE(
        "/api/v1/workspaces/{ws}/break-glass/{grant_id}",
        {
          params: { path: { ws, grant_id: grantId } },
          headers: buildOptionalHeaders(reqOptions),
          signal: reqOptions?.signal,
        },
      );
      if (!response.ok) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return {
        correlationId: response.headers.get("X-Correlation-Id"),
      };
    },
    async listWorkspaceMembers(ws, query, reqOptions) {
      const { data, error, response } = await raw.GET("/api/v1/workspaces/{ws}/members", {
        params: { path: { ws }, query },
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async updateWorkspaceMember(ws, memberId, body, reqOptions) {
      const { data, error, response } = await raw.PATCH(
        "/api/v1/workspaces/{ws}/members/{member_id}",
        {
          params: {
            path: { ws, member_id: memberId },
            header: reqOptions?.ifMatch ? { "If-Match": reqOptions.ifMatch } : undefined,
          },
          body,
          headers: buildOptionalHeaders(reqOptions),
          signal: reqOptions?.signal,
        },
      );
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async removeWorkspaceMember(ws, memberId, reqOptions) {
      const { error, response } = await raw.DELETE("/api/v1/workspaces/{ws}/members/{member_id}", {
        params: { path: { ws, member_id: memberId } },
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (!response.ok) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return {
        correlationId: response.headers.get("X-Correlation-Id"),
      };
    },
    async listWorkspaceInvitations(ws, query, reqOptions) {
      const { data, error, response } = await raw.GET("/api/v1/workspaces/{ws}/invitations", {
        params: { path: { ws }, query },
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async createWorkspaceInvitation(ws, body, reqOptions) {
      const { data, error, response } = await raw.POST("/api/v1/workspaces/{ws}/invitations", {
        params: { path: { ws } },
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async revokeWorkspaceInvitation(ws, inviteId, reqOptions) {
      const { error, response } = await raw.DELETE(
        "/api/v1/workspaces/{ws}/invitations/{invite_id}",
        {
          params: { path: { ws, invite_id: inviteId } },
          headers: buildOptionalHeaders(reqOptions),
          signal: reqOptions?.signal,
        },
      );
      if (!response.ok) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return {
        correlationId: response.headers.get("X-Correlation-Id"),
      };
    },
    async acceptWorkspaceInvitation(body, reqOptions) {
      const { data, error, response } = await raw.POST("/api/v1/invitations/accept", {
        body,
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async listTaskJobs(ws, query, reqOptions) {
      const { data, error, response } = await raw.GET("/api/v1/workspaces/{ws}/task-jobs", {
        params: { path: { ws }, query },
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async getTaskJob(ws, jobId, reqOptions) {
      const { data, error, response } = await raw.GET(
        "/api/v1/workspaces/{ws}/task-jobs/{job_id}",
        {
          params: { path: { ws, job_id: jobId } },
          headers: buildOptionalHeaders(reqOptions),
          signal: reqOptions?.signal,
        },
      );
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async performTaskJobAction(ws, jobId, body, reqOptions) {
      const { data, error, response } = await raw.POST(
        "/api/v1/workspaces/{ws}/task-jobs/{job_id}/actions",
        {
          params: {
            path: { ws, job_id: jobId },
            header: {
              "Idempotency-Key": reqOptions.idempotencyKey,
              ...(reqOptions.ifMatch ? { "If-Match": reqOptions.ifMatch } : {}),
            },
          },
          body,
          headers: buildOptionalHeaders(reqOptions),
          signal: reqOptions?.signal,
        },
      );
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
    async getOperationReceipt(operationId, reqOptions) {
      const { data, error, response } = await raw.GET("/api/v1/operations/{operation_id}", {
        params: { path: { operation_id: operationId } },
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return toEnvelope(data, response);
    },
  };
}

export type { components, operations, paths };
