import { Red2PrApiError } from "@red2pr/ts-client";
import { sanitizeUntrustedText } from "../../shared/ui";

export interface AuthProblemSummary {
  readonly status: number | null;
  readonly code: string;
  readonly detail: string;
  readonly correlationId: string | null;
  readonly retryAfterSeconds: number | null;
}

/**
 * Resolve a safe internal post-authentication route from URL query parameters (`?next=...`).
 * Rejects scheme-qualified, protocol-relative (`//`), control-char, or `/login` loop URLs (`SEC-040`).
 */
export function resolveSafePostLoginPath(search: string, fallback = "/account"): string {
  const params = new URLSearchParams(search);
  const candidate = params.get("next");
  if (candidate === null) {
    return fallback;
  }
  const trimmed = candidate.trim();
  if (
    trimmed.length === 0 ||
    !trimmed.startsWith("/") ||
    trimmed.startsWith("//") ||
    trimmed.startsWith("/\\") ||
    trimmed === "/login" ||
    trimmed.startsWith("/login?")
  ) {
    return fallback;
  }
  for (let idx = 0; idx < trimmed.length; idx += 1) {
    const code = trimmed.charCodeAt(idx);
    if (code <= 0x1f || code === 0x7f) {
      return fallback;
    }
  }
  return trimmed;
}

/**
 * Extract safe, anti-enumeration error details + correlation ID from `Red2PrApiError` or network failures.
 */
export function extractAuthProblemSummary(
  error: unknown,
  fallbackDetail: string,
): AuthProblemSummary {
  if (error instanceof Red2PrApiError) {
    const safeDetail = sanitizeUntrustedText(error.problem.detail).text.trim();
    const safeCorr = sanitizeUntrustedText(error.problem.correlation_id).text.trim();
    return {
      status: error.status,
      code: error.problem.code,
      detail: safeDetail.length > 0 ? safeDetail : fallbackDetail,
      correlationId: safeCorr.length > 0 ? safeCorr : null,
      retryAfterSeconds: error.retryAfterSeconds,
    };
  }
  return {
    status: null,
    code: "network_or_client_error",
    detail: fallbackDetail,
    correlationId: null,
    retryAfterSeconds: null,
  };
}

export function formatUtcTimestamp(isoTimestamp: string | null | undefined): string {
  if (typeof isoTimestamp !== "string" || isoTimestamp.trim().length === 0) {
    return "—";
  }
  const parsed = new Date(isoTimestamp);
  if (Number.isNaN(parsed.getTime())) {
    return sanitizeUntrustedText(isoTimestamp).text;
  }
  return `${parsed.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

export function isStepUpValid(stepUpValidUntil: string | null | undefined): boolean {
  if (typeof stepUpValidUntil !== "string" || stepUpValidUntil.length === 0) {
    return false;
  }
  const untilMs = new Date(stepUpValidUntil).getTime();
  if (Number.isNaN(untilMs)) {
    return false;
  }
  return untilMs > Date.now() + 2_000;
}
