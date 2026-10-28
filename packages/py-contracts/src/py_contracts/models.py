"""Canonical Meta Muse model registry, capability probes, and atomic budget DTOs (A-20, S-17, U16).

Implements docs/09_AI_AGENT_ORCHESTRATION.md, docs/35_API_SPECIFICATION.md (A-20),
docs/36_CANONICAL_CONTRACTS.md (S-17), docs/37_NFR_AND_RECOVERY.md (NFR-06),
ADR-008, ADR-020, and ADR-037:
- Allowlisted Meta Muse Model API identifiers (`muse-spark-1.3` primary,
  `muse-wonder-1.0` optional escalation; non-API names such as `Wonder Full` and
  non-Meta vendors are rejected).
- Exact Decimal `Money` budgets, reservations, and `ModelUsageRecord` accounting
  (never binary floating point; `unknown` usage never coerced to `0`).
- Write-only Meta API credential rotation/revocation inputs paired with read-only
  `SecretPresence` responses.
- Consented `ModelProbeRequest` requiring explicit `max_cost` and active `inference`
  `consent_id` (`SEC-018`).
"""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, Any, Literal, Self

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator

from py_contracts.evidence import ModelToolProvenance, ModelUsageRecord
from py_contracts.integrations import (
    CapabilityAvailability,
    ConsentDataClass,
    ConsentRecord,
    OpaqueSecretRef,
    SecretPresence,
)
from py_contracts.primitives import (
    ActionReceipt,
    BoundedName,
    BoundedReason,
    BoundedText,
    CurrencyCode,
    InternalId,
    Money,
    OpaqueProviderId,
    PositiveVersion,
    Sha256Digest,
    StrictContractModel,
    UtcTimestamp,
    WorkspaceResourceBase,
)
from py_contracts.repairs import SanitizedHttpUrl, SuspensionReason

PRIMARY_META_MODEL_ID: Literal["muse-spark-1.3"] = "muse-spark-1.3"
ESCALATION_META_MODEL_ID: Literal["muse-wonder-1.0"] = "muse-wonder-1.0"
ALLOWED_META_MODEL_IDS: tuple[str, ...] = (
    PRIMARY_META_MODEL_ID,
    ESCALATION_META_MODEL_ID,
)
FORBIDDEN_META_MODEL_ALIASES: frozenset[str] = frozenset(
    {
        "wonder full",
        "wonder-full",
        "wonder_full",
        "muse-wonder-full",
        "muse_wonder_full",
    }
)

DEFAULT_META_API_BASE_URL: str = "https://api.meta.ai/v1"
META_INFERENCE_ADAPTER_VERSION: str = "meta-muse-v1"

# NFR-06 default per-session resource & spend caps
NFR06_DEFAULT_MAX_CALLS: int = 30
NFR06_DEFAULT_MAX_TOKENS: int = 120_000
NFR06_DEFAULT_MAX_PATCH_ATTEMPTS: int = 2
NFR06_DEFAULT_MAX_WALL_SECONDS: int = 1800
NFR06_DEFAULT_SESSION_COST_USD: Decimal = Decimal("5.000000")
NFR06_DEFAULT_DAILY_WORKSPACE_COST_USD: Decimal = Decimal("25.000000")

MetaModelId = Literal["muse-spark-1.3", "muse-wonder-1.0"]
ModelTierRole = Literal["primary", "escalation"]
ModelAvailabilityStatus = Literal[
    "available",
    "unavailable",
    "not_probed",
    "degraded",
    "disabled",
]
BudgetScopeKind = Literal[
    "workspace_daily",
    "workspace_total",
    "repair_session",
    "model_probe",
]
BudgetReservationStatus = Literal[
    "reserved",
    "settled",
    "released",
    "unknown_outcome",
]
ReasoningEffortLevel = Literal["low", "medium", "high"]
MetaMessageRole = Literal["system", "developer", "user", "assistant", "tool"]


def validate_supported_meta_model_id(raw_model_id: str) -> MetaModelId:
    """Validate an allowlisted Meta Model API identifier (`ADR-008`, `ADR-020`)."""
    candidate = raw_model_id.strip()
    lowered = candidate.lower()
    if lowered in FORBIDDEN_META_MODEL_ALIASES:
        raise ValueError(
            "unsupported_meta_model_id: 'Wonder Full' is not an exposed Meta Model API "
            "identifier; only 'muse-spark-1.3' and 'muse-wonder-1.0' are permitted."
        )
    if candidate == PRIMARY_META_MODEL_ID:
        return PRIMARY_META_MODEL_ID
    if candidate == ESCALATION_META_MODEL_ID:
        return ESCALATION_META_MODEL_ID
    raise ValueError(
        f"unsupported_meta_model_id: {candidate!r} is not an allowlisted Meta Muse "
        "model ('muse-spark-1.3' or 'muse-wonder-1.0')."
    )


class ModelPricingRate(StrictContractModel):
    """Exact Decimal token pricing schedule per 1,000,000 input/output tokens."""

    pricing_revision: BoundedName
    input_per_1m_tokens: Money
    output_per_1m_tokens: Money
    configured: StrictBool = True

    @model_validator(mode="after")
    def _validate_pricing_consistency(self) -> Self:
        if self.input_per_1m_tokens.currency != self.output_per_1m_tokens.currency:
            raise ValueError(
                "input_per_1m_tokens and output_per_1m_tokens must share the same currency"
            )
        if self.configured and self.pricing_revision.strip().lower() in {
            "unknown",
            "unconfigured",
            "none",
        }:
            raise ValueError("configured ModelPricingRate cannot use an unknown pricing_revision")
        return self


class ModelCapabilityFlags(StrictContractModel):
    """Observed Meta Model API capabilities recorded by a consented probe (`AGT-01`)."""

    tool_calls: CapabilityAvailability = "unknown"
    structured_output: CapabilityAvailability = "unknown"
    streaming: CapabilityAvailability = "unknown"
    context_window_tokens: Annotated[StrictInt, Field(ge=0)] | None = None
    max_output_tokens: Annotated[StrictInt, Field(ge=0)] | None = None
    rate_limit_rpm: Annotated[StrictInt, Field(ge=0)] | None = None
    rate_limit_tpm: Annotated[StrictInt, Field(ge=0)] | None = None


class ModelCapabilitySnapshot(WorkspaceResourceBase):
    """Immutable observed capability probe snapshot for a Meta model (`AGT-01`, `A-20`)."""

    model_id: MetaModelId
    tier_role: ModelTierRole
    status: ModelAvailabilityStatus
    capabilities: ModelCapabilityFlags
    provider_request_id: OpaqueProviderId | None = None
    consent_id: InternalId | None = None
    probed_at: UtcTimestamp
    status_detail: BoundedReason | None = None
    suspension_reason: SuspensionReason | None = None
    retry_after_seconds: Annotated[StrictInt, Field(ge=0)] | None = None


class BudgetPolicyDefaults(StrictContractModel):
    """Workspace & per-session token, call, attempt, walltime & cost caps (`NFR-06`, `AGT-03`)."""

    max_calls_per_session: Annotated[StrictInt, Field(ge=1, le=500)] = NFR06_DEFAULT_MAX_CALLS
    max_tokens_per_session: Annotated[StrictInt, Field(ge=256, le=2_000_000)] = (
        NFR06_DEFAULT_MAX_TOKENS
    )
    max_patch_attempts: Annotated[StrictInt, Field(ge=1, le=10)] = NFR06_DEFAULT_MAX_PATCH_ATTEMPTS
    max_wall_seconds: Annotated[StrictInt, Field(ge=60, le=14_400)] = NFR06_DEFAULT_MAX_WALL_SECONDS
    max_cost_per_session: Money
    daily_workspace_cap: Money
    alert_threshold_percent: Annotated[StrictInt, Field(ge=1, le=100)] = 80

    @model_validator(mode="after")
    def _validate_currency_and_caps(self) -> Self:
        if self.max_cost_per_session.currency != self.daily_workspace_cap.currency:
            raise ValueError(
                "max_cost_per_session and daily_workspace_cap must share the same currency"
            )
        if (
            self.daily_workspace_cap.amount > Decimal("0")
            and self.max_cost_per_session.amount > self.daily_workspace_cap.amount
        ):
            raise ValueError("max_cost_per_session cannot exceed positive daily_workspace_cap")
        return self


class EscalationPolicy(StrictContractModel):
    """Optional `muse-spark-1.3 -> muse-wonder-1.0` escalation policy (`ADR-008`, `ADR-020`)."""

    escalation_enabled: StrictBool = False
    escalation_model_id: BoundedName | None = ESCALATION_META_MODEL_ID
    escalate_after_failed_attempts: Annotated[StrictInt, Field(ge=1, le=5)] = 1
    require_probed_availability: Literal[True] = True
    allow_non_meta_fallback: Literal[False] = False

    @model_validator(mode="after")
    def _validate_escalation_model(self) -> Self:
        if self.escalation_model_id is not None:
            resolved = validate_supported_meta_model_id(self.escalation_model_id)
            if resolved != ESCALATION_META_MODEL_ID:
                raise ValueError("escalation_model_id must be 'muse-wonder-1.0' when specified")
        elif self.escalation_enabled:
            raise ValueError("escalation_model_id is required when escalation_enabled is true")
        return self


class BudgetAccountSummary(WorkspaceResourceBase):
    """Atomic row-locked budget account ledger state (`AGT-03`, `SEC-033`)."""

    scope_kind: BudgetScopeKind
    scope_key: BoundedName
    currency: CurrencyCode
    cost_cap: Money
    reserved_cost: Money
    settled_cost: Money
    unknown_cost: Money
    remaining_cost: Money
    token_cap: Annotated[StrictInt, Field(ge=0)]
    reserved_tokens: Annotated[StrictInt, Field(ge=0)]
    settled_tokens: Annotated[StrictInt, Field(ge=0)]
    unknown_tokens: Annotated[StrictInt, Field(ge=0)]
    call_cap: Annotated[StrictInt, Field(ge=0)]
    reserved_calls: Annotated[StrictInt, Field(ge=0)]
    settled_calls: Annotated[StrictInt, Field(ge=0)]
    unknown_calls: Annotated[StrictInt, Field(ge=0)]
    max_patch_attempts: Annotated[StrictInt, Field(ge=0)]
    patch_attempts_used: Annotated[StrictInt, Field(ge=0)]
    max_wall_seconds: Annotated[StrictInt, Field(ge=0)]
    window_started_at: UtcTimestamp
    window_ends_at: UtcTimestamp | None = None
    cancelled_at: UtcTimestamp | None = None


class BudgetReservationRecord(WorkspaceResourceBase):
    """Pre-call worst-case budget reservation & settlement record (`AGT-03`, `SEC-033`)."""

    budget_account_id: InternalId
    repair_id: InternalId | None = None
    model_id: MetaModelId
    pricing_revision: BoundedName
    status: BudgetReservationStatus
    estimated_input_tokens: Annotated[StrictInt, Field(ge=0)]
    max_output_tokens: Annotated[StrictInt, Field(ge=0)]
    actual_input_tokens: Annotated[StrictInt, Field(ge=0)] | None = None
    actual_output_tokens: Annotated[StrictInt, Field(ge=0)] | None = None
    reserved_cost: Money
    settled_cost: Money | None = None
    currency: CurrencyCode
    provider_request_id: OpaqueProviderId | None = None
    prompt_redacted_digest: Sha256Digest
    response_redacted_digest: Sha256Digest | None = None
    late_after_cancel: StrictBool = False
    correlation_id: BoundedName


class WorkspaceModelEntry(StrictContractModel):
    """Workspace model registry entry (`muse-spark-1.3` primary, `muse-wonder-1.0` escalation)."""

    model_id: MetaModelId
    display_name: BoundedName
    vendor: Literal["meta"] = "meta"
    tier_role: ModelTierRole
    enabled: StrictBool
    status: ModelAvailabilityStatus
    pricing: ModelPricingRate
    latest_snapshot: ModelCapabilitySnapshot | None = None


class WorkspaceModelsResponse(StrictContractModel):
    """`A-20` / `UI-S12` workspace Meta model registry, budgets, consents & usage snapshot."""

    workspace_id: InternalId
    version: PositiveVersion
    updated_at: UtcTimestamp
    endpoint_base_url: SanitizedHttpUrl
    endpoint_registration_id: InternalId | None = None
    api_key_presence: SecretPresence
    active_inference_consent_id: InternalId | None = None
    inference_consent_active: StrictBool
    available_inference_consents: list[ConsentRecord] = Field(default_factory=list)
    suspension_reason: SuspensionReason | None = None
    status_detail: BoundedReason | None = None
    retry_after_seconds: Annotated[StrictInt, Field(ge=0)] | None = None
    ready_for_repair_inference: StrictBool
    models: list[WorkspaceModelEntry]
    budget_policy: BudgetPolicyDefaults
    escalation_policy: EscalationPolicy
    workspace_budget: BudgetAccountSummary
    recent_usage: list[ModelUsageRecord] = Field(default_factory=list)


class WorkspaceModelsConfigUpdateRequest(StrictContractModel):
    """Write-only Meta credential, pricing, budget & escalation configuration update (`UI-S12`)."""

    expected_version: PositiveVersion | None = None
    endpoint_base_url: SanitizedHttpUrl | None = None
    endpoint_registration_id: InternalId | None = None
    clear_endpoint_registration: StrictBool = False
    api_key: Annotated[StrictStr, Field(min_length=12, max_length=512)] | None = None
    secret_ref: OpaqueSecretRef | None = None
    revoke_api_key: StrictBool = False
    active_inference_consent_id: InternalId | None = None
    clear_inference_consent: StrictBool = False
    pricing_updates: dict[BoundedName, ModelPricingRate] | None = None
    budget_policy: BudgetPolicyDefaults | None = None
    escalation_policy: EscalationPolicy | None = None
    clear_suspension: StrictBool = False

    @model_validator(mode="after")
    def _validate_mutually_exclusive_secret_ops(self) -> Self:
        provided_secret_inputs = sum(
            [
                self.api_key is not None,
                self.secret_ref is not None,
                bool(self.revoke_api_key),
            ]
        )
        if provided_secret_inputs > 1:
            raise ValueError(
                "Specify at most one of api_key, secret_ref, or revoke_api_key per request"
            )
        if self.endpoint_registration_id is not None and self.clear_endpoint_registration:
            raise ValueError(
                "Cannot combine endpoint_registration_id with clear_endpoint_registration=true"
            )
        if self.active_inference_consent_id is not None and self.clear_inference_consent:
            raise ValueError(
                "Cannot combine active_inference_consent_id with clear_inference_consent=true"
            )
        if self.pricing_updates is not None:
            for key in self.pricing_updates:
                validate_supported_meta_model_id(key)
        return self


class WorkspaceModelsConfigUpdateResponse(StrictContractModel):
    """Idempotent `S-05` receipt + updated workspace model registry state."""

    receipt: ActionReceipt
    models_state: WorkspaceModelsResponse


class WorkspaceInferenceConsentCreateRequest(StrictContractModel):
    """Grant a workspace-scoped `S-18` `inference` outbound data-sharing consent (`SEC-018`)."""

    destination: SanitizedHttpUrl = DEFAULT_META_API_BASE_URL
    data_classes: Annotated[list[ConsentDataClass], Field(min_length=1, max_length=8)]
    policy_version: PositiveVersion = 1


class ModelProbeRequest(StrictContractModel):
    """`A-20` consented Meta model capability probe request (`max_cost` + `consent_id`)."""

    model_id: BoundedName
    max_cost: Money
    consent_id: InternalId
    max_output_tokens: Annotated[StrictInt, Field(ge=16, le=4096)] = 64

    @model_validator(mode="after")
    def _validate_probe_request(self) -> Self:
        validate_supported_meta_model_id(self.model_id)
        if self.max_cost.amount <= Decimal("0"):
            raise ValueError("max_cost.amount must be strictly positive for a capability probe")
        return self


class ModelProbeResponse(StrictContractModel):
    """`A-20` capability probe result with `S-05` receipt, snapshot & settled usage record."""

    receipt: ActionReceipt
    snapshot: ModelCapabilitySnapshot
    usage_record: ModelUsageRecord | None = None
    models_state: WorkspaceModelsResponse


# Internal / Orchestrator-facing Meta Chat Completions contracts (consumed by U16 & U17)
class MetaToolFunctionCallPayload(StrictContractModel):
    """Function name + JSON-serialized arguments returned by a Meta model tool call."""

    name: BoundedName
    arguments: BoundedText


class MetaToolCall(StrictContractModel):
    """Assistant tool-call invocation emitted by Meta `/v1/chat/completions`."""

    id: OpaqueProviderId
    type: Literal["function"] = "function"
    function: MetaToolFunctionCallPayload


class MetaChatMessage(StrictContractModel):
    """Single message turn in a Meta Model API `/v1/chat/completions` conversation."""

    role: MetaMessageRole
    content: StrictStr | None = None
    name: BoundedName | None = None
    tool_call_id: OpaqueProviderId | None = None
    tool_calls: list[MetaToolCall] | None = None


class MetaToolFunctionDefinition(StrictContractModel):
    """Allowlisted function tool schema exposed to Meta Muse models (`S-20`)."""

    name: BoundedName
    description: BoundedReason
    parameters: dict[str, Any]
    strict: StrictBool = True


class MetaToolDefinition(StrictContractModel):
    """Wrapper for a `function` tool passed to `/v1/chat/completions`."""

    type: Literal["function"] = "function"
    function: MetaToolFunctionDefinition


class MetaJsonSchemaSpec(StrictContractModel):
    """Non-recursive strict JSON Schema output specification for Meta Muse models."""

    name: BoundedName
    strict: StrictBool = True
    schema_def: dict[str, Any] = Field(alias="schema")


class MetaResponseFormat(StrictContractModel):
    """Structured output format directive (`text` or `json_schema`)."""

    type: Literal["text", "json_schema"]
    json_schema: MetaJsonSchemaSpec | None = None

    @model_validator(mode="after")
    def _validate_json_schema_presence(self) -> Self:
        if self.type == "json_schema" and self.json_schema is None:
            raise ValueError("json_schema specification is required when type='json_schema'")
        if self.type == "text" and self.json_schema is not None:
            raise ValueError("json_schema must be omitted when type='text'")
        return self


class MetaTokenUsage(StrictContractModel):
    """Exact token counts reported by Meta `/v1/chat/completions` (`reasoning_tokens` included)."""

    prompt_tokens: Annotated[StrictInt, Field(ge=0)]
    completion_tokens: Annotated[StrictInt, Field(ge=0)]
    total_tokens: Annotated[StrictInt, Field(ge=0)]
    reasoning_tokens: Annotated[StrictInt, Field(ge=0)] = 0


class MetaChatCompletionRequest(StrictContractModel):
    """Redacted, consent-gated, budget-reserved Meta `/v1/chat/completions` invocation."""

    workspace_id: InternalId
    repository_id: InternalId | None = None
    repair_id: InternalId | None = None
    session_budget_account_id: InternalId | None = None
    consent_id: InternalId | None = None
    model_id: BoundedName = PRIMARY_META_MODEL_ID
    messages: Annotated[list[MetaChatMessage], Field(min_length=1, max_length=128)]
    tools: list[MetaToolDefinition] | None = None
    response_format: MetaResponseFormat | None = None
    max_completion_tokens: Annotated[StrictInt, Field(ge=16, le=32_768)] = 2048
    reasoning_effort: ReasoningEffortLevel | None = None
    correlation_id: BoundedName | None = None

    @model_validator(mode="after")
    def _validate_model_id(self) -> Self:
        validate_supported_meta_model_id(self.model_id)
        return self


class MetaChatCompletionResult(StrictContractModel):
    """Verified, redacted Meta inference result with `S-17` usage & `S-22` provenance."""

    provider_request_id: OpaqueProviderId
    model_id: MetaModelId
    finish_reason: BoundedName
    content: StrictStr | None = None
    parsed_structured_output: dict[str, Any] | None = None
    tool_calls: list[MetaToolCall] = Field(default_factory=list)
    usage: MetaTokenUsage
    usage_record: ModelUsageRecord
    reservation: BudgetReservationRecord
    provenance: ModelToolProvenance
    late_after_cancel: StrictBool = False
