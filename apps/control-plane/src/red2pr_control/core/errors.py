"""Canonical Problem+JSON error builders and domain exception hierarchy (S-03)."""

from __future__ import annotations

from py_contracts.primitives import Problem, ProblemFieldError
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor

PROBLEM_JSON_MEDIA_TYPE: str = "application/problem+json"
PROBLEM_BASE_URI: str = "https://red2pr.local/problems"


class Red2PrError(Exception):
    """Structured base error with HTTP status and canonical machine-readable code."""

    def __init__(
        self,
        *,
        code: str,
        title: str,
        detail: str,
        status: int = 400,
        errors: list[ProblemFieldError] | None = None,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.title = title
        self.detail = detail
        self.status = status
        self.errors = errors
        self.retry_after_seconds = retry_after_seconds


class BadRequestError(Red2PrError):
    """400 malformed request syntax or invalid wire framing."""

    def __init__(self, *, code: str = "bad_request", detail: str) -> None:
        super().__init__(code=code, title="Bad request", detail=detail, status=400)


class UnauthorizedError(Red2PrError):
    """401 unauthenticated request."""

    def __init__(self, *, code: str = "unauthenticated", detail: str) -> None:
        super().__init__(code=code, title="Authentication required", detail=detail, status=401)


class ForbiddenError(Red2PrError):
    """403 authenticated principal lacks required permission or policy grant."""

    def __init__(self, *, code: str = "operation_denied", detail: str) -> None:
        super().__init__(code=code, title="Operation denied", detail=detail, status=403)


class NotFoundError(Red2PrError):
    """404 nonexistent or inaccessible resource (consistent anti-enumeration)."""

    def __init__(self, *, code: str = "not_found", detail: str = "Resource not found.") -> None:
        super().__init__(code=code, title="Resource not found", detail=detail, status=404)


class ConflictError(Red2PrError):
    """409 version, state-transition, or idempotency conflict."""

    def __init__(self, *, code: str = "conflict", detail: str) -> None:
        super().__init__(code=code, title="Resource conflict", detail=detail, status=409)


class GoneError(Red2PrError):
    """410 expired replay cursor, challenge, or purged artifact."""

    def __init__(self, *, code: str = "resource_expired", detail: str) -> None:
        super().__init__(code=code, title="Resource expired", detail=detail, status=410)


class PreconditionFailedError(Red2PrError):
    """412 ETag / If-Match optimistic concurrency precondition failure."""

    def __init__(self, *, code: str = "precondition_failed", detail: str) -> None:
        super().__init__(code=code, title="Precondition failed", detail=detail, status=412)


class PayloadTooLargeError(Red2PrError):
    """413 JSON request payload exceeds 1 MiB S-01 wire limit."""

    def __init__(self, *, code: str = "payload_too_large", detail: str) -> None:
        super().__init__(code=code, title="Payload too large", detail=detail, status=413)


class UnprocessableEntityError(Red2PrError):
    """422 schema or semantic validation failure."""

    def __init__(
        self,
        *,
        code: str = "validation_error",
        detail: str,
        errors: list[ProblemFieldError] | None = None,
    ) -> None:
        super().__init__(
            code=code,
            title="Validation failed",
            detail=detail,
            status=422,
            errors=errors,
        )


class RateLimitedError(Red2PrError):
    """429 rate-limit exceeded with mandatory Retry-After seconds."""

    def __init__(
        self,
        *,
        code: str = "rate_limited",
        detail: str,
        retry_after_seconds: int = 30,
    ) -> None:
        super().__init__(
            code=code,
            title="Too many requests",
            detail=detail,
            status=429,
            retry_after_seconds=max(1, retry_after_seconds),
        )


class DependencyUnavailableError(Red2PrError):
    """503 upstream provider, database, or worker dependency unavailable."""

    def __init__(self, *, code: str = "dependency_unavailable", detail: str) -> None:
        super().__init__(code=code, title="Service unavailable", detail=detail, status=503)


def build_problem(
    *,
    status: int,
    code: str,
    title: str,
    detail: str,
    correlation_id: str,
    errors: list[ProblemFieldError] | None = None,
    redactor: Redactor | None = None,
) -> Problem:
    """Construct a redacted S-03 Problem payload guaranteed free of secret leaks."""
    active_redactor = redactor if redactor is not None else DEFAULT_REDACTOR
    safe_detail = active_redactor.redact_text(detail)[:4096]
    safe_code = code.strip()[:120] or "internal_error"
    safe_title = active_redactor.redact_text(title.strip())[:120] or "Request failed"
    safe_corr = correlation_id.strip()[:120] or "unassigned"
    return Problem(
        type=f"{PROBLEM_BASE_URI}/{safe_code.lower()}",
        title=safe_title,
        status=status,
        code=safe_code,
        detail=safe_detail,
        correlation_id=safe_corr,
        errors=errors,
    )


def problem_from_exception(
    exc: BaseException,
    *,
    correlation_id: str,
    redactor: Redactor | None = None,
) -> Problem:
    """Convert an exception to S-03 Problem, stripping stack traces & host internals on 500s."""
    if isinstance(exc, Red2PrError):
        return build_problem(
            status=exc.status,
            code=exc.code,
            title=exc.title,
            detail=exc.detail,
            correlation_id=correlation_id,
            errors=exc.errors,
            redactor=redactor,
        )
    return build_problem(
        status=500,
        code="internal_error",
        title="Internal server error",
        detail="An unexpected internal error occurred. Refer to correlation_id in server logs.",
        correlation_id=correlation_id,
        redactor=redactor,
    )
