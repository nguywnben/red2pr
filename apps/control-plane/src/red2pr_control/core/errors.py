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
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.title = title
        self.detail = detail
        self.status = status
        self.errors = errors


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
    # Unhandled internal exceptions never expose Python tracebacks, SQL, or filesystem paths
    return build_problem(
        status=500,
        code="internal_error",
        title="Internal server error",
        detail="An unexpected internal error occurred. Refer to correlation_id in server logs.",
        correlation_id=correlation_id,
        redactor=redactor,
    )
