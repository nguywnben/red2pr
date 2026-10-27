"""Core configuration, redaction, error envelope, integrity and structured logging."""

from red2pr_control.core.config import (
    AiBudgetCaps,
    ConfigValidationError,
    Red2PrConfig,
    load_config,
    parse_config_yaml,
    validate_child_budget_within_parent,
)
from red2pr_control.core.errors import (
    PROBLEM_JSON_MEDIA_TYPE,
    Red2PrError,
    build_problem,
    problem_from_exception,
)
from red2pr_control.core.integrity import (
    EXPECTED_AGENTS_MD_LF_SHA256,
    IntegrityCheckError,
    verify_agents_md_integrity,
)
from red2pr_control.core.logging import (
    EntryPoint,
    RedactingSpanProcessor,
    StructuredJsonFormatter,
    bind_telemetry_context,
    current_correlation_id,
    get_structured_logger,
)
from red2pr_control.core.redaction import DEFAULT_REDACTOR, REDACTION_VERSION, Redactor

__all__ = [
    "DEFAULT_REDACTOR",
    "EXPECTED_AGENTS_MD_LF_SHA256",
    "PROBLEM_JSON_MEDIA_TYPE",
    "REDACTION_VERSION",
    "AiBudgetCaps",
    "ConfigValidationError",
    "EntryPoint",
    "IntegrityCheckError",
    "Red2PrConfig",
    "Red2PrError",
    "RedactingSpanProcessor",
    "Redactor",
    "StructuredJsonFormatter",
    "bind_telemetry_context",
    "build_problem",
    "current_correlation_id",
    "get_structured_logger",
    "load_config",
    "parse_config_yaml",
    "problem_from_exception",
    "validate_child_budget_within_parent",
    "verify_agents_md_integrity",
]
