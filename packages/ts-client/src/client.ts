import createClient, { type Client, type ClientOptions, type Middleware } from "openapi-fetch";
import type { components, operations, paths } from "./schema.js";

export type SchemaName = keyof components["schemas"];
export type SchemaOf<K extends SchemaName> = components["schemas"][K];

// Canonical S-01..S-22 & A-01..A-03 TypeScript aliases strictly derived from openapi.v1.json
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
export type Membership = SchemaOf<"Membership">;
export type Invite = SchemaOf<"Invite">;
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
export type NotificationDestination = SchemaOf<"NotificationDestination">;
export type NotificationDelivery = SchemaOf<"NotificationDelivery">;
export type NotificationPreference = SchemaOf<"NotificationPreference">;
export type AuditRecord = SchemaOf<"AuditRecord">;
export type ModelUsageRecord = SchemaOf<"ModelUsageRecord">;
export type ReportExportRequest = SchemaOf<"ReportExportRequest">;
export type SetupState = SchemaOf<"SetupState">;
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

export interface ApiEnvelope<TData> {
  readonly data: TData;
  readonly correlationId: string | null;
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

function buildOptionalHeaders(reqOptions?: RequestCallOptions): Record<string, string> {
  const headers: Record<string, string> = {};
  if (reqOptions?.correlationId !== undefined) {
    headers["X-Correlation-Id"] = reqOptions.correlationId;
  }
  return headers;
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
      return {
        data,
        correlationId: response.headers.get("X-Correlation-Id"),
      };
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
      return {
        data,
        correlationId: response.headers.get("X-Correlation-Id"),
      };
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
      return {
        data,
        correlationId: response.headers.get("X-Correlation-Id"),
      };
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
      return {
        data,
        correlationId: response.headers.get("X-Correlation-Id"),
      };
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
      return {
        data,
        correlationId: response.headers.get("X-Correlation-Id"),
      };
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
      return {
        data,
        correlationId: response.headers.get("X-Correlation-Id"),
      };
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
      return {
        data,
        correlationId: response.headers.get("X-Correlation-Id"),
      };
    },
    async listMySessions(reqOptions) {
      const { data, error, response } = await raw.GET("/api/v1/me/sessions", {
        headers: buildOptionalHeaders(reqOptions),
        signal: reqOptions?.signal,
      });
      if (data === undefined) {
        throw new Red2PrApiError(coerceProblem(error, response), parseRetryAfter(response));
      }
      return {
        data,
        correlationId: response.headers.get("X-Correlation-Id"),
      };
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
      return {
        data,
        correlationId: response.headers.get("X-Correlation-Id"),
      };
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
  };
}

export type { components, operations, paths };
