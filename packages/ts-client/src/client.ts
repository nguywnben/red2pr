import createClient, { type Client, type ClientOptions, type Middleware } from "openapi-fetch";
import type { components, operations, paths } from "./schema.js";

export type SchemaName = keyof components["schemas"];
export type SchemaOf<K extends SchemaName> = components["schemas"][K];

// Canonical S-01..S-22 TypeScript aliases strictly derived from openapi.v1.json
export type Problem = SchemaOf<"Problem">;
export type ProblemFieldError = SchemaOf<"ProblemFieldError">;
export type ActionReceipt = SchemaOf<"ActionReceipt">;
export type PageParams = SchemaOf<"PageParams">;
export type Money = SchemaOf<"Money">;
export type User = SchemaOf<"User">;
export type Session = SchemaOf<"Session">;
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
  getSystemHealth(options?: { correlationId?: string; signal?: AbortSignal }): Promise<{
    data: SystemHealthResponse;
    correlationId: string | null;
  }>;
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

export function createRed2PrClient(options: Red2PrClientOptions = {}): Red2PrClient {
  const { getCsrfToken, ...fetchClientOptions } = options;

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
      if (MUTATING_METHODS.has(request.method.toUpperCase()) && getCsrfToken !== undefined) {
        const csrfToken = getCsrfToken();
        if (typeof csrfToken === "string" && csrfToken.length > 0) {
          request.headers.set("X-CSRF-Token", csrfToken);
        }
      }
      return request;
    },
  };

  raw.use(headerMiddleware);

  return {
    raw,
    async getSystemHealth(reqOptions) {
      const headers: Record<string, string> = {};
      if (reqOptions?.correlationId !== undefined) {
        headers["X-Correlation-Id"] = reqOptions.correlationId;
      }
      const { data, error, response } = await raw.GET("/api/v1/system/health", {
        headers,
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
  };
}

export type { components, operations, paths };
