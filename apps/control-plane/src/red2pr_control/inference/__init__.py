"""Z2 Meta Muse inference broker, S-20 tool broker & bounded repair agents (`U16`, `U17`)."""

from red2pr_control.inference.agent_profiles import (
    AgentProfileService,
    build_immutable_tool_matrix,
)
from red2pr_control.inference.budgets import (
    AtomicBudgetLedger,
    BudgetExceededError,
    SettlementOutcome,
    budget_account_row_to_dto,
    compute_exact_token_cost,
    ensure_strict_decimal,
    estimate_worst_case_input_tokens,
    reservation_row_to_dto,
    usage_row_to_dto,
)
from red2pr_control.inference.diagnosis_agent import (
    DiagnosisAgentService,
    DiagnosisOutcome,
    to_diagnosis_dto,
)
from red2pr_control.inference.meta_client import (
    DEFAULT_RATE_LIMIT_RETRY_SECONDS,
    MAX_JSON_SCHEMA_DEPTH,
    MAX_PROBE_OUTPUT_TOKENS,
    MetaMuseInferenceService,
)
from red2pr_control.inference.patch_agent import (
    BoundedPatchAgentService,
    PatchGenerationOutcome,
    to_patch_attempt_dto,
)
from red2pr_control.inference.router import build_inference_router
from red2pr_control.inference.tool_broker import (
    UNTRUSTED_SYSTEM_PREAMBLE,
    AgentToolBroker,
    FilesystemRepoSnapshot,
    InMemoryRepoSnapshot,
    ParsedUnifiedDiff,
    RepoSnapshotError,
    RepoSnapshotProvider,
    ToolBrokerSessionContext,
    compute_context_cache_key,
    parse_and_validate_unified_diff,
    persist_context_manifest_in_tx,
    sanitize_and_redact_text,
    to_agent_step_dto,
    to_context_manifest_dto,
    wrap_untrusted_repo_data,
)

__all__ = [
    "DEFAULT_RATE_LIMIT_RETRY_SECONDS",
    "MAX_JSON_SCHEMA_DEPTH",
    "MAX_PROBE_OUTPUT_TOKENS",
    "UNTRUSTED_SYSTEM_PREAMBLE",
    "AgentProfileService",
    "AgentToolBroker",
    "AtomicBudgetLedger",
    "BoundedPatchAgentService",
    "BudgetExceededError",
    "DiagnosisAgentService",
    "DiagnosisOutcome",
    "FilesystemRepoSnapshot",
    "InMemoryRepoSnapshot",
    "MetaMuseInferenceService",
    "ParsedUnifiedDiff",
    "PatchGenerationOutcome",
    "RepoSnapshotError",
    "RepoSnapshotProvider",
    "SettlementOutcome",
    "ToolBrokerSessionContext",
    "budget_account_row_to_dto",
    "build_immutable_tool_matrix",
    "build_inference_router",
    "compute_context_cache_key",
    "compute_exact_token_cost",
    "ensure_strict_decimal",
    "estimate_worst_case_input_tokens",
    "parse_and_validate_unified_diff",
    "persist_context_manifest_in_tx",
    "reservation_row_to_dto",
    "sanitize_and_redact_text",
    "to_agent_step_dto",
    "to_context_manifest_dto",
    "to_diagnosis_dto",
    "to_patch_attempt_dto",
    "usage_row_to_dto",
    "wrap_untrusted_repo_data",
]
