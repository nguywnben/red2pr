"""Z2 Meta Muse Inference Broker, Model Registry, Consent Gate & Capability Probes (U16).

Implements `AGT-01`, `AGT-03`, `A-20`, `S-17`, `S-18`, `S-19`, `S-22`, `W-04`, `NFR-06`,
`ADR-008`, `ADR-020`, `ADR-037`, `SEC-012`, `SEC-013`, `SEC-017`, `SEC-018`, `SEC-023`,
`SEC-032`, and `SEC-033`:
- Connects exclusively to `https://api.meta.ai/v1` (or an active `ADR-037` owner-registered
  `meta_inference` endpoint) for `muse-spark-1.3` (primary) and `muse-wonder-1.0` (opt-in
  escalation once probed `available`), never silently switching to non-Meta providers.
- Verifies active workspace/repository/instance `inference` consent (`SEC-018`), scrubs all
  outbound messages and tool schemas via `Redactor` v1 (`SEC-017`), validates non-recursive
  JSON schemas, forbids unsupported OpenAI parameters (`stop`, `logit_bias`, `logprobs`),
  and strips any upstream chain-of-thought text while retaining numeric `reasoning_tokens`.
- Reserves worst-case token/call/cost spend via `AtomicBudgetLedger` before opening any
  network socket, settles exact `Decimal` usage on `200 OK`, retains worst-case `unknown`
  spend on post-dispatch timeouts (`SEC-033`), and records `suspension_reason="model_unavailable"`
  with `Retry-After` on `429`/outages (`SEC-023`).
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Literal, cast
from urllib.parse import urlparse

import httpcore
import httpx
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts.crypto import sha256_canonical_json
from py_contracts.events import EventEnvelope, SecurityIdentityEventPayload
from py_contracts.evidence import (
    ModelToolProvenance,
    ModelUsageRecord,
)
from py_contracts.iam import WorkspaceRole
from py_contracts.integrations import (
    ConsentDataClass,
    ConsentPurpose,
    ConsentRecord,
    ConsentScope,
    EndpointScheme,
    SecretPresence,
)
from py_contracts.models import (
    ALLOWED_META_MODEL_IDS,
    DEFAULT_META_API_BASE_URL,
    ESCALATION_META_MODEL_ID,
    META_INFERENCE_ADAPTER_VERSION,
    NFR06_DEFAULT_DAILY_WORKSPACE_COST_USD,
    NFR06_DEFAULT_SESSION_COST_USD,
    PRIMARY_META_MODEL_ID,
    BudgetPolicyDefaults,
    EscalationPolicy,
    MetaChatCompletionRequest,
    MetaChatCompletionResult,
    MetaChatMessage,
    MetaModelId,
    MetaResponseFormat,
    MetaTokenUsage,
    MetaToolCall,
    MetaToolDefinition,
    MetaToolFunctionCallPayload,
    ModelAvailabilityStatus,
    ModelCapabilityFlags,
    ModelCapabilitySnapshot,
    ModelPricingRate,
    ModelProbeRequest,
    ModelProbeResponse,
    ModelTierRole,
    WorkspaceInferenceConsentCreateRequest,
    WorkspaceModelEntry,
    WorkspaceModelsConfigUpdateRequest,
    WorkspaceModelsConfigUpdateResponse,
    WorkspaceModelsResponse,
    validate_supported_meta_model_id,
)
from py_contracts.primitives import (
    Money,
    new_uuid7,
    parse_uuid7_timestamp_ms,
    validate_idempotency_key_window,
)
from py_contracts.repairs import PrerequisiteStatus, SetupWizardPhase, SuspensionReason
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.egress import (
    CaBundleResolverProtocol,
    EgressBlockedError,
    EgressPolicyEngine,
    EgressSafeHttpClient,
)
from red2pr_control.core.errors import (
    BadRequestError,
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    NotFoundError,
    RateLimitedError,
    Red2PrError,
    UnprocessableEntityError,
    problem_from_exception,
)
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.db.base import (
    ConsentModel,
    EndpointRegistrationModel,
    IdempotencyRecordModel,
    ModelCapabilitySnapshotModel,
    SecretEntryModel,
    UsageLedgerModel,
    WorkspaceModel,
    WorkspaceModelConfigModel,
)
from red2pr_control.db.idempotency import (
    CompletedActionState,
    IdempotencyClaimOutcome,
    claim_idempotent_operation,
    complete_idempotent_operation,
    upsert_operation_receipt,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.rbac import (
    ADMIN_ONLY_ROLES,
    ALL_WORKSPACE_ROLES,
    WorkspaceAccessContext,
    enforce_optimistic_version,
)
from red2pr_control.iam.sessions import IamService, is_step_up_fresh
from red2pr_control.inference.budgets import (
    AtomicBudgetLedger,
    budget_account_row_to_dto,
    estimate_worst_case_input_tokens,
    usage_row_to_dto,
)
from red2pr_control.operations.setup_wizard import (
    DbEndpointAllowlistProvider,
    SetupStepProbeCallable,
    SetupStepProbeResult,
    SetupStepRegistry,
)
from red2pr_control.secrets.broker import (
    INFERENCE_SECRET_CAPABILITY,
    SecretBroker,
)

MAX_JSON_SCHEMA_DEPTH = 16
MAX_PROBE_OUTPUT_TOKENS = 64
DEFAULT_RATE_LIMIT_RETRY_SECONDS = 30
MAX_RETRY_AFTER_SECONDS = 3600

_FORBIDDEN_SCHEMA_KEYS: frozenset[str] = frozenset(
    {"$ref", "$defs", "definitions", "$recursiveRef", "$dynamicRef"}
)
_FORBIDDEN_WIRE_PARAMS: frozenset[str] = frozenset(
    {"stop", "logit_bias", "logprobs", "top_logprobs"}
)
_COT_FIELD_NAMES: frozenset[str] = frozenset(
    {"reasoning", "reasoning_content", "thought", "chain_of_thought"}
)

_PROBE_SYSTEM_PROMPT = (
    "You are verifying Meta Model API structured output and tool schema compatibility for Red2PR. "
    'Respond strictly with JSON matching {"probe_ok": true}.'
)
_PROBE_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["probe_ok"],
    "properties": {
        "probe_ok": {"type": "boolean"},
    },
}
_PROBE_TOOL_SPEC: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "noop_capability_check",
        "description": "Read-only capability verification stub; do not call.",
        "strict": True,
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["echo"],
            "properties": {
                "echo": {"type": "string"},
            },
        },
    },
}


def _default_budget_policy() -> BudgetPolicyDefaults:
    return BudgetPolicyDefaults(
        max_cost_per_session=Money(amount=NFR06_DEFAULT_SESSION_COST_USD, currency="USD"),
        daily_workspace_cap=Money(amount=NFR06_DEFAULT_DAILY_WORKSPACE_COST_USD, currency="USD"),
    )


def _unconfigured_pricing_rate(currency: str = "USD") -> ModelPricingRate:
    return ModelPricingRate(
        pricing_revision="unconfigured",
        input_per_1m_tokens=Money(amount=Decimal("0.000000"), currency=currency),
        output_per_1m_tokens=Money(amount=Decimal("0.000000"), currency=currency),
        configured=False,
    )


def _tier_role_for_model(model_id: MetaModelId) -> ModelTierRole:
    return "primary" if model_id == PRIMARY_META_MODEL_ID else "escalation"


def _parse_retry_after_seconds(headers: httpx.Headers, *, default_seconds: int) -> int:
    raw = headers.get("retry-after")
    if raw is not None:
        stripped = raw.strip()
        if stripped.isdigit():
            parsed = int(stripped)
            return max(1, min(MAX_RETRY_AFTER_SECONDS, parsed))
    return default_seconds


def _remaining_retry_seconds(retry_until: datetime | None, *, now: datetime) -> int | None:
    if retry_until is None or retry_until <= now:
        return None
    return max(1, int((retry_until - now).total_seconds()))


def _dep_unavailable(
    *,
    code: str,
    detail: str,
    retry_after_seconds: int | None = None,
) -> DependencyUnavailableError:
    err = DependencyUnavailableError(code=code, detail=detail)
    err.retry_after_seconds = retry_after_seconds
    return err


def _ensure_workspace_role(
    access: WorkspaceAccessContext,
    *,
    allowed_roles: Collection[WorkspaceRole],
    allow_break_glass: bool = False,
) -> None:
    role = access.effective_role
    if role == "break_glass":
        if allow_break_glass:
            return
        raise ForbiddenError(
            code="break_glass_read_only",
            detail="Break-glass grants provide audited read-only visibility only.",
        )
    if role not in allowed_roles:
        raise ForbiddenError(
            code="insufficient_role",
            detail="Authenticated workspace role lacks permission for this models operation.",
        )


async def _check_existing_idempotent_replay_in_tx(
    db: AsyncSession,
    *,
    workspace_id: str,
    principal_id: str,
    operation: str,
    idempotency_key: str,
    request_payload: Mapping[str, Any],
    correlation_id: str,
    now: datetime,
) -> IdempotencyClaimOutcome | None:
    """Return replay outcome if `idempotency_key` already exists, else validate key window."""
    try:
        parse_uuid7_timestamp_ms(idempotency_key)
    except ValueError as exc:
        raise BadRequestError(code="invalid_idempotency_key", detail=str(exc)) from exc

    existing = await db.scalar(
        select(IdempotencyRecordModel).where(
            IdempotencyRecordModel.workspace_id == workspace_id,
            IdempotencyRecordModel.principal_id == principal_id,
            IdempotencyRecordModel.operation == operation,
            IdempotencyRecordModel.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        return await claim_idempotent_operation(
            db,
            workspace_id=workspace_id,
            principal_id=principal_id,
            operation=operation,
            idempotency_key=idempotency_key,
            request_payload=request_payload,
            logical_effect_key=existing.logical_effect_key,
            resource_id=existing.resource_id,
            correlation_id=correlation_id,
            now=now,
        )

    try:
        validate_idempotency_key_window(
            idempotency_key,
            now=now,
            max_age=timedelta(days=7),
            max_future_skew=timedelta(minutes=5),
        )
    except ValueError as exc:
        msg = str(exc)
        if msg.startswith("key_expired:"):
            raise ConflictError(code="key_expired", detail=msg) from exc
        raise BadRequestError(code="invalid_idempotency_key", detail=msg) from exc
    return None


def _normalize_destination_identity(raw_url: str) -> tuple[str, str, int]:
    candidate = raw_url.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
    return (scheme, host, port)


def _validate_non_recursive_json_schema(
    node: Any,
    *,
    _depth: int = 0,
) -> None:
    if _depth > MAX_JSON_SCHEMA_DEPTH:
        raise UnprocessableEntityError(
            code="json_schema_depth_exceeded",
            detail=f"Structured output JSON Schema exceeds max depth {MAX_JSON_SCHEMA_DEPTH}.",
        )
    if isinstance(node, Mapping):
        for raw_key, raw_val in node.items():
            key_str = str(raw_key)
            if key_str in _FORBIDDEN_SCHEMA_KEYS:
                raise UnprocessableEntityError(
                    code="recursive_json_schema_unsupported",
                    detail=(
                        f"Meta Model API structured outputs forbid recursive schema keyword "
                        f"'{key_str}' (ADR-008)."
                    ),
                )
            _validate_non_recursive_json_schema(raw_val, _depth=_depth + 1)
    elif isinstance(node, Sequence) and not isinstance(node, (str, bytes, bytearray)):
        for item in node:
            _validate_non_recursive_json_schema(item, _depth=_depth + 1)


def _strip_cot_fields(value: Any) -> Any:
    """Recursively strip any hidden chain-of-thought fields from upstream payloads (SEC-017)."""
    if isinstance(value, Mapping):
        cleaned: dict[str, Any] = {}
        for raw_k, raw_v in value.items():
            key_str = str(raw_k)
            if key_str.lower() in _COT_FIELD_NAMES:
                continue
            cleaned[key_str] = _strip_cot_fields(raw_v)
        return cleaned
    if isinstance(value, list):
        return [_strip_cot_fields(item) for item in value]
    return value


def _consent_row_to_dto(row: ConsentModel) -> ConsentRecord:
    return ConsentRecord(
        id=row.id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        purpose=cast(ConsentPurpose, row.purpose),
        scope=cast(ConsentScope, row.scope),
        workspace_id=row.workspace_id,
        repository_id=row.repository_id,
        destination=row.destination,
        data_classes=[cast(ConsentDataClass, item) for item in row.data_classes_json],
        granted_by_user_id=row.granted_by_user_id,
        policy_revision=row.policy_version,
        status="revoked" if row.revoked_at is not None else "active",
        revoked_at=row.revoked_at,
        revoke_reason=row.revoke_reason,
    )


def _snapshot_row_to_dto(row: ModelCapabilitySnapshotModel) -> ModelCapabilitySnapshot:
    return ModelCapabilitySnapshot(
        id=row.id,
        workspace_id=row.workspace_id,
        repository_id=None,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        model_id=validate_supported_meta_model_id(row.model_id),
        tier_role=cast(ModelTierRole, row.tier_role),
        status=cast(ModelAvailabilityStatus, row.status),
        capabilities=ModelCapabilityFlags.model_validate(row.capabilities_json),
        provider_request_id=row.provider_request_id,
        consent_id=row.consent_id,
        probed_at=row.probed_at,
        status_detail=row.status_detail,
        suspension_reason=(
            cast(SuspensionReason, row.suspension_reason)
            if row.suspension_reason is not None
            else None
        ),
        retry_after_seconds=row.retry_after_seconds,
    )


class MetaMuseInferenceService:
    """Z2 Meta Model API adapter, capability probe service, and workspace model registry."""

    def __init__(
        self,
        *,
        iam_service: IamService,
        secret_broker: SecretBroker,
        budget_ledger: AtomicBudgetLedger | None = None,
        egress_policy: EgressPolicyEngine | None = None,
        ca_bundle_resolver: CaBundleResolverProtocol | None = None,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
        timeout_seconds: float = 15.0,
        redactor: Redactor | None = None,
    ) -> None:
        self._iam = iam_service
        self._session_factory = iam_service.session_factory
        self._secrets = secret_broker
        self._redactor = redactor if redactor is not None else DEFAULT_REDACTOR
        self._budgets = (
            budget_ledger
            if budget_ledger is not None
            else AtomicBudgetLedger(
                session_factory=self._session_factory,
                redactor=self._redactor,
                clock=self._iam.now,
            )
        )
        self._egress_policy = (
            egress_policy
            if egress_policy is not None
            else EgressPolicyEngine(
                allowlist_provider=DbEndpointAllowlistProvider(self._session_factory)
            )
        )
        self._ca_bundle_resolver = ca_bundle_resolver
        self._network_backend = network_backend
        self._timeout_seconds = timeout_seconds

    @property
    def budget_ledger(self) -> AtomicBudgetLedger:
        return self._budgets

    async def _ensure_workspace_config_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        now: datetime,
        for_update: bool = False,
    ) -> WorkspaceModelConfigModel:
        stmt = select(WorkspaceModelConfigModel).where(
            WorkspaceModelConfigModel.workspace_id == workspace_id
        )
        if for_update:
            stmt = stmt.with_for_update()
        existing = await db.scalar(stmt)
        if existing is not None:
            return existing

        default_budget = _default_budget_policy()
        default_escalation = EscalationPolicy()
        created = WorkspaceModelConfigModel(
            id=new_uuid7(now=now),
            workspace_id=workspace_id,
            endpoint_base_url=DEFAULT_META_API_BASE_URL,
            endpoint_registration_id=None,
            credential_secret_ref=None,
            credential_secret_version=None,
            active_inference_consent_id=None,
            pricing_json={},
            budget_policy_json=default_budget.model_dump(mode="json"),
            escalation_policy_json=default_escalation.model_dump(mode="json"),
            suspension_reason=None,
            status_detail=None,
            retry_after_until=None,
            updated_by_user_id=None,
            version=1,
            created_at=now,
            updated_at=now,
        )
        try:
            async with db.begin_nested():
                db.add(created)
                await db.flush()
            if for_update:
                reloaded = await db.scalar(stmt)
                assert reloaded is not None
                return reloaded
            return created
        except IntegrityError:
            winner = await db.scalar(stmt)
            if winner is None:
                raise
            return winner

    def _parse_pricing_map(
        self,
        raw_pricing: Mapping[str, Any],
    ) -> dict[MetaModelId, ModelPricingRate]:
        parsed: dict[MetaModelId, ModelPricingRate] = {}
        for raw_model_id, raw_entry in raw_pricing.items():
            if raw_model_id in ALLOWED_META_MODEL_IDS and isinstance(raw_entry, Mapping):
                model_key = validate_supported_meta_model_id(raw_model_id)
                parsed[model_key] = ModelPricingRate.model_validate(raw_entry)
        return parsed

    def _effective_budget_policy(self, raw_json: Mapping[str, Any]) -> BudgetPolicyDefaults:
        if not raw_json:
            return _default_budget_policy()
        return BudgetPolicyDefaults.model_validate(raw_json)

    def _effective_escalation_policy(self, raw_json: Mapping[str, Any]) -> EscalationPolicy:
        if not raw_json:
            return EscalationPolicy()
        return EscalationPolicy.model_validate(raw_json)

    async def _secret_presence_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        secret_ref: str | None,
        fallback_version: int | None,
    ) -> SecretPresence:
        if secret_ref is None:
            return SecretPresence(configured=False)
        row = await db.scalar(
            select(SecretEntryModel).where(
                SecretEntryModel.workspace_id == workspace_id,
                SecretEntryModel.secret_ref == secret_ref,
                SecretEntryModel.purpose == "meta_inference",
            )
        )
        if row is None or row.revoked_at is not None:
            return SecretPresence(configured=False)
        return SecretPresence(
            configured=True,
            secret_version=fallback_version or row.active_key_version,
        )

    async def _latest_snapshots_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
    ) -> dict[MetaModelId, ModelCapabilitySnapshot]:
        result: dict[MetaModelId, ModelCapabilitySnapshot] = {}
        for model_id in (PRIMARY_META_MODEL_ID, ESCALATION_META_MODEL_ID):
            typed_id: MetaModelId = model_id
            snap_row = await db.scalar(
                select(ModelCapabilitySnapshotModel)
                .where(
                    ModelCapabilitySnapshotModel.workspace_id == workspace_id,
                    ModelCapabilitySnapshotModel.model_id == model_id,
                )
                .order_by(
                    ModelCapabilitySnapshotModel.probed_at.desc(),
                    ModelCapabilitySnapshotModel.id.desc(),
                )
                .limit(1)
            )
            if snap_row is not None:
                result[typed_id] = _snapshot_row_to_dto(snap_row)
        return result

    async def _validate_meta_endpoint_in_tx(
        self,
        db: AsyncSession,
        *,
        endpoint_base_url: str,
        endpoint_registration_id: str | None,
    ) -> tuple[str, str | None, str | None]:
        """Validate `endpoint_base_url` against `api.meta.ai` or `ADR-037` allowlist."""
        parsed = urlparse(endpoint_base_url.strip())
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise UnprocessableEntityError(
                code="invalid_meta_endpoint_url",
                detail=(
                    "endpoint_base_url must not contain embedded credentials, query parameters, "
                    "or fragments."
                ),
            )
        scheme_raw = parsed.scheme.lower()
        if scheme_raw not in ("https", "http"):
            raise UnprocessableEntityError(
                code="invalid_meta_endpoint_url",
                detail="endpoint_base_url must use https:// (or registered private http://).",
            )
        scheme = cast(EndpointScheme, scheme_raw)
        host = (parsed.hostname or "").strip().lower().rstrip(".")
        if not host:
            raise UnprocessableEntityError(
                code="invalid_meta_endpoint_url",
                detail="endpoint_base_url must specify a valid hostname.",
            )
        port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
        clean_path = (parsed.path or "/v1").rstrip("/") or "/v1"
        default_port = 443 if scheme == "https" else 80
        port_part = f":{port}" if port != default_port else ""
        host_fmt = f"[{host}]" if ":" in host else host
        normalized_url = f"{scheme}://{host_fmt}{port_part}{clean_path}"

        is_canonical_meta = (
            scheme == "https" and host == "api.meta.ai" and port == 443 and clean_path == "/v1"
        )
        if is_canonical_meta and endpoint_registration_id is None:
            return (normalized_url, None, None)

        stmt = select(EndpointRegistrationModel).where(
            EndpointRegistrationModel.adapter == "meta_inference",
            EndpointRegistrationModel.scheme == scheme,
            EndpointRegistrationModel.host == host,
            EndpointRegistrationModel.port == port,
            EndpointRegistrationModel.revoked_at.is_(None),
        )
        if endpoint_registration_id is not None:
            stmt = stmt.where(EndpointRegistrationModel.id == endpoint_registration_id)

        reg_row = await db.scalar(stmt)
        if reg_row is None:
            return (normalized_url, None, "meta_endpoint_not_allowlisted")
        return (normalized_url, reg_row.id, None)

    async def _verify_active_inference_consent_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        consent_id: str | None,
        endpoint_base_url: str,
        repository_id: str | None = None,
    ) -> tuple[ConsentModel | None, str | None]:
        """Verify an active, non-revoked `inference` consent matching scope and destination."""
        if not consent_id:
            return (None, "inference_consent_missing")

        row = await db.scalar(
            select(ConsentModel).where(
                ConsentModel.id == consent_id,
                ConsentModel.purpose == "inference",
            )
        )
        if row is None:
            return (None, "inference_consent_missing")
        if row.revoked_at is not None:
            return (None, "inference_consent_revoked")

        if row.scope == "workspace":
            if row.workspace_id != workspace_id:
                return (None, "inference_consent_scope_mismatch")
        elif row.scope == "repository":
            if (
                row.workspace_id != workspace_id
                or repository_id is None
                or row.repository_id != repository_id
            ):
                return (None, "inference_consent_scope_mismatch")
        elif row.scope != "instance":
            return (None, "inference_consent_scope_mismatch")

        target_scheme, target_host, target_port = _normalize_destination_identity(endpoint_base_url)
        consent_scheme, consent_host, consent_port = _normalize_destination_identity(
            row.destination
        )
        if (consent_scheme, consent_host, consent_port) != (
            target_scheme,
            target_host,
            target_port,
        ):
            return (None, "inference_consent_destination_mismatch")

        return (row, None)

    async def _emit_policy_denial_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        actor_type: Literal["user", "system", "service"],
        actor_id: str,
        action: str,
        target: str,
        reason_code: str,
        correlation_id: str,
        client_ip: str | None,
        now: datetime,
        target_entity_id: str | None = None,
        repository_id: str | None = None,
        session_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        ws_row = await db.scalar(select(WorkspaceModel).where(WorkspaceModel.id == workspace_id))
        ws_ver = ws_row.version if ws_row is not None else 1
        resolved_target_id = target_entity_id or repository_id or workspace_id
        envelope = EventEnvelope(
            event_id=new_uuid7(now=now),
            schema_version=1,
            type="security.policy.denied",
            occurred_at=now,
            workspace_id=workspace_id,
            repository_id=repository_id,
            session_id=session_id,
            aggregate_id=workspace_id,
            aggregate_version=ws_ver,
            correlation_id=correlation_id,
            payload=SecurityIdentityEventPayload(
                target_id=resolved_target_id,
                reason_code=reason_code,
            ),
        )
        await enqueue_outbox_event(db, envelope, now=now)
        await append_audit_entry(
            db,
            workspace_id=workspace_id,
            repository_id=repository_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            target=target,
            decision="deny",
            reason_code=reason_code,
            correlation_id=correlation_id,
            client_ip=client_ip,
            metadata=dict(metadata) if metadata is not None else {},
            occurred_at=now,
            redactor=self._redactor,
        )

    async def _build_workspace_models_dto_in_tx(
        self,
        db: AsyncSession,
        *,
        workspace_id: str,
        cfg_row: WorkspaceModelConfigModel,
        now: datetime,
    ) -> WorkspaceModelsResponse:
        presence = await self._secret_presence_in_tx(
            db,
            workspace_id=workspace_id,
            secret_ref=cfg_row.credential_secret_ref,
            fallback_version=cfg_row.credential_secret_version,
        )
        budget_policy = self._effective_budget_policy(cfg_row.budget_policy_json)
        escalation_policy = self._effective_escalation_policy(cfg_row.escalation_policy_json)
        pricing_by_model = self._parse_pricing_map(cfg_row.pricing_json)
        snapshots = await self._latest_snapshots_in_tx(db, workspace_id=workspace_id)

        consent_rows = list(
            (
                await db.scalars(
                    select(ConsentModel)
                    .where(
                        ConsentModel.purpose == "inference",
                        or_(
                            ConsentModel.workspace_id.is_(None),
                            ConsentModel.workspace_id == workspace_id,
                        ),
                    )
                    .order_by(ConsentModel.created_at.desc(), ConsentModel.id.desc())
                    .limit(50)
                )
            ).all()
        )
        available_consents = [_consent_row_to_dto(r) for r in consent_rows]

        active_consent_dto: ConsentRecord | None = None
        if cfg_row.active_inference_consent_id is not None:
            verified_consent, _ = await self._verify_active_inference_consent_in_tx(
                db,
                workspace_id=workspace_id,
                consent_id=cfg_row.active_inference_consent_id,
                endpoint_base_url=cfg_row.endpoint_base_url,
            )
            if verified_consent is not None:
                active_consent_dto = _consent_row_to_dto(verified_consent)

        daily_acct = await self._budgets.ensure_workspace_daily_account_in_tx(
            db,
            workspace_id=workspace_id,
            policy=budget_policy,
            now=now,
        )
        workspace_budget = budget_account_row_to_dto(daily_acct)

        usage_rows = list(
            (
                await db.scalars(
                    select(UsageLedgerModel)
                    .where(UsageLedgerModel.workspace_id == workspace_id)
                    .order_by(UsageLedgerModel.created_at.desc(), UsageLedgerModel.id.desc())
                    .limit(25)
                )
            ).all()
        )
        recent_usage = [usage_row_to_dto(r) for r in usage_rows]

        cur = budget_policy.max_cost_per_session.currency
        spark_snap = snapshots.get(PRIMARY_META_MODEL_ID)
        wonder_snap = snapshots.get(ESCALATION_META_MODEL_ID)

        spark_status: ModelAvailabilityStatus = (
            spark_snap.status if spark_snap is not None else "not_probed"
        )
        wonder_status: ModelAvailabilityStatus = (
            wonder_snap.status if wonder_snap is not None else "not_probed"
        )
        spark_pricing = pricing_by_model.get(
            PRIMARY_META_MODEL_ID,
            _unconfigured_pricing_rate(cur),
        )
        wonder_pricing = pricing_by_model.get(
            ESCALATION_META_MODEL_ID,
            _unconfigured_pricing_rate(cur),
        )

        models_list = [
            WorkspaceModelEntry(
                model_id=PRIMARY_META_MODEL_ID,
                display_name="Muse Spark 1.3",
                vendor="meta",
                tier_role="primary",
                enabled=True,
                status=spark_status,
                pricing=spark_pricing,
                latest_snapshot=spark_snap,
            ),
            WorkspaceModelEntry(
                model_id=ESCALATION_META_MODEL_ID,
                display_name="Muse Wonder 1.0",
                vendor="meta",
                tier_role="escalation",
                enabled=bool(escalation_policy.escalation_enabled and wonder_status == "available"),
                status=wonder_status,
                pricing=wonder_pricing,
                latest_snapshot=wonder_snap,
            ),
        ]

        suspension_val = (
            cast(SuspensionReason, cfg_row.suspension_reason)
            if cfg_row.suspension_reason is not None
            else None
        )
        retry_secs = _remaining_retry_seconds(cfg_row.retry_after_until, now=now)
        budget_positive = budget_policy.max_cost_per_session.amount > Decimal(
            "0"
        ) and budget_policy.daily_workspace_cap.amount > Decimal("0")
        ready_for_repair = bool(
            presence.configured
            and active_consent_dto is not None
            and spark_pricing.configured
            and budget_positive
            and suspension_val is None
            and spark_status == "available"
        )

        return WorkspaceModelsResponse(
            workspace_id=workspace_id,
            version=cfg_row.version,
            updated_at=cfg_row.updated_at,
            endpoint_base_url=cfg_row.endpoint_base_url,
            endpoint_registration_id=cfg_row.endpoint_registration_id,
            api_key_presence=presence,
            active_inference_consent_id=(
                active_consent_dto.id if active_consent_dto is not None else None
            ),
            inference_consent_active=active_consent_dto is not None,
            available_inference_consents=available_consents,
            suspension_reason=suspension_val,
            status_detail=cfg_row.status_detail,
            retry_after_seconds=retry_secs,
            ready_for_repair_inference=ready_for_repair,
            models=models_list,
            budget_policy=budget_policy,
            escalation_policy=escalation_policy,
            workspace_budget=workspace_budget,
            recent_usage=recent_usage,
        )

    async def get_workspace_models(
        self,
        *,
        access: WorkspaceAccessContext,
    ) -> WorkspaceModelsResponse:
        """Return masked workspace Meta model registry, budgets, consents & usage."""
        _ensure_workspace_role(
            access,
            allowed_roles=ALL_WORKSPACE_ROLES,
            allow_break_glass=True,
        )
        ws_id = access.workspace.id
        ref_now = self._iam.now()
        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            cfg_row = await self._ensure_workspace_config_in_tx(
                db,
                workspace_id=ws_id,
                now=ref_now,
            )
            return await self._build_workspace_models_dto_in_tx(
                db,
                workspace_id=ws_id,
                cfg_row=cfg_row,
                now=ref_now,
            )

    async def grant_workspace_inference_consent(
        self,
        *,
        access: WorkspaceAccessContext,
        payload: WorkspaceInferenceConsentCreateRequest,
        idempotency_key: str,
        correlation_id: str,
        client_ip: str | None = None,
    ) -> ConsentRecord:
        """Record an explicit workspace-scoped outbound `inference` consent (`SEC-018`)."""
        _ensure_workspace_role(access, allowed_roles=ADMIN_ONLY_ROLES)
        ws_id = access.workspace.id
        ref_now = self._iam.now()
        principal_id = access.auth.user.id
        op_name = "models.consent.grant"
        req_body = payload.model_dump(mode="json")

        denied_exc: ForbiddenError | None = None
        dto: ConsentRecord | None = None
        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            replay = await _check_existing_idempotent_replay_in_tx(
                db,
                workspace_id=ws_id,
                principal_id=principal_id,
                operation=op_name,
                idempotency_key=idempotency_key,
                request_payload=req_body,
                correlation_id=correlation_id,
                now=ref_now,
            )
            if replay is not None and replay.cached_response is not None:
                return ConsentRecord.model_validate(replay.cached_response)

            normalized_dest, _, deny_reason = await self._validate_meta_endpoint_in_tx(
                db,
                endpoint_base_url=payload.destination,
                endpoint_registration_id=None,
            )
            if deny_reason is not None:
                await self._emit_policy_denial_in_tx(
                    db,
                    workspace_id=ws_id,
                    actor_type="user",
                    actor_id=access.auth.user.id,
                    action=op_name,
                    target=f"workspace:{ws_id}:consent",
                    reason_code=deny_reason,
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    now=ref_now,
                )
                denied_exc = ForbiddenError(
                    code="meta_endpoint_not_allowlisted",
                    detail=(
                        "Outbound inference consent destination must target https://api.meta.ai/v1 "
                        "or an active owner-registered meta_inference endpoint."
                    ),
                )
            else:
                consent_id_new = new_uuid7(now=ref_now)
                eff_key = f"{op_name}:{ws_id}:{idempotency_key}"
                claim = await claim_idempotent_operation(
                    db,
                    workspace_id=ws_id,
                    principal_id=principal_id,
                    operation=op_name,
                    idempotency_key=idempotency_key,
                    request_payload=req_body,
                    logical_effect_key=eff_key,
                    resource_id=consent_id_new,
                    correlation_id=correlation_id,
                    now=ref_now,
                )
                if not claim.is_new_claim and claim.cached_response is not None:
                    return ConsentRecord.model_validate(claim.cached_response)

                consent_row = ConsentModel(
                    id=consent_id_new,
                    workspace_id=ws_id,
                    repository_id=None,
                    purpose="inference",
                    scope="workspace",
                    destination=normalized_dest,
                    data_classes_json=[str(item) for item in payload.data_classes],
                    policy_version=payload.policy_version,
                    granted_by_user_id=access.auth.user.id,
                    granted_at=ref_now,
                    revoked_by_user_id=None,
                    revoked_at=None,
                    revoke_reason=None,
                    version=1,
                    created_at=ref_now,
                    updated_at=ref_now,
                )
                db.add(consent_row)
                await db.flush()

                cfg_row = await self._ensure_workspace_config_in_tx(
                    db,
                    workspace_id=ws_id,
                    now=ref_now,
                    for_update=True,
                )
                if cfg_row.active_inference_consent_id is None:
                    cfg_row.active_inference_consent_id = consent_row.id
                    cfg_row.updated_by_user_id = access.auth.user.id
                    cfg_row.version += 1
                    cfg_row.updated_at = ref_now
                    await db.flush()

                dto = _consent_row_to_dto(consent_row)
                serialized = dto.model_dump(mode="json")
                await upsert_operation_receipt(
                    db,
                    operation_id=claim.receipt.operation_id,
                    scope="workspace",
                    workspace_id=ws_id,
                    principal_id=principal_id,
                    required_role="admin",
                    operation_kind=op_name,
                    resource_id=consent_row.id,
                    state="succeeded",
                    correlation_id=correlation_id,
                    status_url=claim.receipt.status_url,
                    logical_effect_key=eff_key,
                    result_id=consent_row.id,
                    now=ref_now,
                )
                await complete_idempotent_operation(
                    db,
                    workspace_id=ws_id,
                    operation_id=claim.receipt.operation_id,
                    state="succeeded",
                    status_code=201,
                    result_id=consent_row.id,
                    response_payload=serialized,
                    now=ref_now,
                )
                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    actor_type="user",
                    actor_id=access.auth.user.id,
                    action=op_name,
                    target=f"consent:{consent_row.id}",
                    decision="allow",
                    reason_code="inference_consent_granted",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={
                        "destination": normalized_dest,
                        "policy_version": payload.policy_version,
                    },
                    occurred_at=ref_now,
                    redactor=self._redactor,
                )

        if denied_exc is not None:
            raise denied_exc
        assert dto is not None
        return dto

    async def revoke_workspace_inference_consent(
        self,
        *,
        access: WorkspaceAccessContext,
        consent_id: str,
        reason: str | None,
        correlation_id: str,
        client_ip: str | None = None,
    ) -> ConsentRecord:
        """Immediately revoke a workspace-scoped `inference` consent (`SEC-018`)."""
        _ensure_workspace_role(access, allowed_roles=ADMIN_ONLY_ROLES)
        ws_id = access.workspace.id
        ref_now = self._iam.now()
        clean_reason = (reason or "Revoked by workspace administrator.").strip()[:512]

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            row = await db.scalar(
                select(ConsentModel)
                .where(
                    ConsentModel.id == consent_id,
                    ConsentModel.workspace_id == ws_id,
                    ConsentModel.scope == "workspace",
                    ConsentModel.purpose == "inference",
                )
                .with_for_update()
            )
            if row is None:
                raise NotFoundError(
                    code="consent_not_found",
                    detail="Workspace inference consent was not found.",
                )
            if row.revoked_at is None:
                row.revoked_at = ref_now
                row.revoked_by_user_id = access.auth.user.id
                row.revoke_reason = clean_reason
                row.version += 1
                row.updated_at = ref_now

            cfg_row = await self._ensure_workspace_config_in_tx(
                db,
                workspace_id=ws_id,
                now=ref_now,
                for_update=True,
            )
            if cfg_row.active_inference_consent_id == row.id:
                cfg_row.active_inference_consent_id = None
                cfg_row.updated_by_user_id = access.auth.user.id
                cfg_row.version += 1
                cfg_row.updated_at = ref_now
            await db.flush()

            dto = _consent_row_to_dto(row)
            await append_audit_entry(
                db,
                workspace_id=ws_id,
                actor_type="user",
                actor_id=access.auth.user.id,
                action="models.consent.revoke",
                target=f"consent:{row.id}",
                decision="allow",
                reason_code="inference_consent_revoked",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={"reason": clean_reason},
                occurred_at=ref_now,
                redactor=self._redactor,
            )
            return dto

    async def update_workspace_models_config(
        self,
        *,
        access: WorkspaceAccessContext,
        payload: WorkspaceModelsConfigUpdateRequest,
        idempotency_key: str,
        if_match_header: str | None,
        correlation_id: str,
        client_ip: str | None = None,
    ) -> WorkspaceModelsConfigUpdateResponse:
        """Update workspace Meta API key, endpoint, pricing, budgets, consent & escalation."""
        _ensure_workspace_role(access, allowed_roles=ADMIN_ONLY_ROLES)
        ws_id = access.workspace.id
        ref_now = self._iam.now()
        principal_id = access.auth.user.id
        op_name = "models.config.update"

        redacted_req = payload.model_dump(mode="json", exclude={"api_key"})
        if payload.api_key is not None:
            secret_material = payload.api_key.strip()
            if not secret_material:
                raise UnprocessableEntityError(
                    code="empty_meta_api_key",
                    detail="api_key must not be whitespace-only.",
                )
            redacted_req["api_key_sha256"] = hashlib.sha256(
                secret_material.encode("utf-8")
            ).hexdigest()
        else:
            secret_material = None

        raised_exc: Red2PrError | None = None
        response_dto: WorkspaceModelsConfigUpdateResponse | None = None

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            replay = await _check_existing_idempotent_replay_in_tx(
                db,
                workspace_id=ws_id,
                principal_id=principal_id,
                operation=op_name,
                idempotency_key=idempotency_key,
                request_payload=redacted_req,
                correlation_id=correlation_id,
                now=ref_now,
            )
            if replay is not None and replay.cached_response is not None:
                return WorkspaceModelsConfigUpdateResponse.model_validate(replay.cached_response)

            cfg_row = await self._ensure_workspace_config_in_tx(
                db,
                workspace_id=ws_id,
                now=ref_now,
                for_update=True,
            )
            enforce_optimistic_version(
                current_version=cfg_row.version,
                if_match_header=if_match_header,
                expected_version=payload.expected_version,
            )

            current_budget = self._effective_budget_policy(cfg_row.budget_policy_json)
            target_budget = (
                payload.budget_policy if payload.budget_policy is not None else current_budget
            )

            cap_increased = (
                target_budget.max_cost_per_session.amount
                > current_budget.max_cost_per_session.amount
                or target_budget.daily_workspace_cap.amount
                > current_budget.daily_workspace_cap.amount
            )
            needs_step_up = bool(
                secret_material is not None
                or payload.secret_ref is not None
                or payload.revoke_api_key
                or cap_increased
            )
            normalized_url = cfg_row.endpoint_base_url
            validated_reg_id = cfg_row.endpoint_registration_id

            if needs_step_up and not is_step_up_fresh(access.auth.session, now=ref_now):
                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    actor_type="user",
                    actor_id=access.auth.user.id,
                    action=op_name,
                    target=f"workspace:{ws_id}:models",
                    decision="deny",
                    reason_code="step_up_required",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                    redactor=self._redactor,
                )
                raised_exc = ForbiddenError(
                    code="step_up_required",
                    detail=(
                        "Configuring, rotating, or revoking the Meta API key or raising budget "
                        "caps requires fresh 5-minute MFA step-up verification."
                    ),
                )
            else:
                target_url = (
                    payload.endpoint_base_url
                    if payload.endpoint_base_url is not None
                    else cfg_row.endpoint_base_url
                )
                if payload.clear_endpoint_registration:
                    target_reg_id: str | None = None
                elif payload.endpoint_registration_id is not None:
                    target_reg_id = payload.endpoint_registration_id
                else:
                    target_reg_id = cfg_row.endpoint_registration_id

                (
                    normalized_url,
                    validated_reg_id,
                    endpoint_denial,
                ) = await self._validate_meta_endpoint_in_tx(
                    db,
                    endpoint_base_url=target_url,
                    endpoint_registration_id=target_reg_id,
                )
                if endpoint_denial is not None:
                    await self._emit_policy_denial_in_tx(
                        db,
                        workspace_id=ws_id,
                        actor_type="user",
                        actor_id=access.auth.user.id,
                        action=op_name,
                        target=f"workspace:{ws_id}:models",
                        reason_code=endpoint_denial,
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        now=ref_now,
                        metadata={"attempted_endpoint": self._redactor.redact_text(target_url)},
                    )
                    raised_exc = ForbiddenError(
                        code="meta_endpoint_not_allowlisted",
                        detail=(
                            "Outbound inference endpoint is not allowlisted under Meta Model API "
                            "policy; silent switching to non-Meta vendors is forbidden."
                        ),
                    )

            if raised_exc is None and payload.active_inference_consent_id is not None:
                _, consent_err = await self._verify_active_inference_consent_in_tx(
                    db,
                    workspace_id=ws_id,
                    consent_id=payload.active_inference_consent_id,
                    endpoint_base_url=normalized_url,
                )
                if consent_err is not None:
                    await self._emit_policy_denial_in_tx(
                        db,
                        workspace_id=ws_id,
                        actor_type="user",
                        actor_id=access.auth.user.id,
                        action=op_name,
                        target=f"workspace:{ws_id}:models",
                        reason_code=consent_err,
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        now=ref_now,
                    )
                    raised_exc = ForbiddenError(
                        code="inference_consent_required",
                        detail=(
                            f"Selected inference consent is not valid ({consent_err}); "
                            "grant an active inference consent matching the Meta endpoint."
                        ),
                    )

            if (
                raised_exc is None
                and payload.escalation_policy is not None
                and payload.escalation_policy.escalation_enabled
            ):
                snapshots = await self._latest_snapshots_in_tx(db, workspace_id=ws_id)
                wonder_snap = snapshots.get(ESCALATION_META_MODEL_ID)
                if wonder_snap is None or wonder_snap.status != "available":
                    raised_exc = ConflictError(
                        code="escalation_model_not_verified",
                        detail=(
                            "Muse Wonder 1.0 escalation cannot be enabled until a consented "
                            "capability probe confirms status='available' on this account."
                        ),
                    )

            if raised_exc is None:
                eff_key = f"{op_name}:{ws_id}:{idempotency_key}"
                claim = await claim_idempotent_operation(
                    db,
                    workspace_id=ws_id,
                    principal_id=principal_id,
                    operation=op_name,
                    idempotency_key=idempotency_key,
                    request_payload=redacted_req,
                    logical_effect_key=eff_key,
                    resource_id=cfg_row.id,
                    correlation_id=correlation_id,
                    now=ref_now,
                )
                if not claim.is_new_claim and claim.cached_response is not None:
                    return WorkspaceModelsConfigUpdateResponse.model_validate(claim.cached_response)

                if payload.revoke_api_key:
                    if cfg_row.credential_secret_ref is not None:
                        await self._secrets.revoke_secret(
                            db,
                            secret_ref=cfg_row.credential_secret_ref,
                            workspace_id=ws_id,
                            now=ref_now,
                        )
                        cfg_row.credential_secret_ref = None
                elif secret_material is not None:
                    prev_ver = cfg_row.credential_secret_version or 0
                    if cfg_row.credential_secret_ref is not None:
                        await self._secrets.revoke_secret(
                            db,
                            secret_ref=cfg_row.credential_secret_ref,
                            workspace_id=ws_id,
                            now=ref_now,
                        )
                    meta = await self._secrets.store_secret(
                        db,
                        plaintext=secret_material.encode("utf-8"),
                        purpose="meta_inference",
                        workspace_id=ws_id,
                        now=ref_now,
                    )
                    cfg_row.credential_secret_ref = meta.secret_ref
                    cfg_row.credential_secret_version = prev_ver + 1
                    if cfg_row.suspension_reason == "model_unavailable":
                        cfg_row.suspension_reason = None
                        cfg_row.status_detail = None
                        cfg_row.retry_after_until = None
                elif payload.secret_ref is not None:
                    # Verify referenced secret exists in active workspace with meta_inference scope
                    await self._secrets.resolve_secret_bytes(
                        db,
                        secret_ref=payload.secret_ref,
                        capability=INFERENCE_SECRET_CAPABILITY,
                        workspace_id=ws_id,
                    )
                    cfg_row.credential_secret_ref = payload.secret_ref
                    cfg_row.credential_secret_version = (cfg_row.credential_secret_version or 0) + 1

                cfg_row.endpoint_base_url = normalized_url
                cfg_row.endpoint_registration_id = validated_reg_id
                if payload.clear_inference_consent:
                    cfg_row.active_inference_consent_id = None
                elif payload.active_inference_consent_id is not None:
                    cfg_row.active_inference_consent_id = payload.active_inference_consent_id

                if payload.pricing_updates is not None:
                    merged_pricing = dict(cfg_row.pricing_json)
                    for raw_key, rate in payload.pricing_updates.items():
                        canonical_model = validate_supported_meta_model_id(raw_key)
                        merged_pricing[canonical_model] = rate.model_dump(mode="json")
                    cfg_row.pricing_json = merged_pricing

                cfg_row.budget_policy_json = target_budget.model_dump(mode="json")
                if payload.escalation_policy is not None:
                    cfg_row.escalation_policy_json = payload.escalation_policy.model_dump(
                        mode="json"
                    )

                if payload.clear_suspension:
                    cfg_row.suspension_reason = None
                    cfg_row.status_detail = None
                    cfg_row.retry_after_until = None

                cfg_row.updated_by_user_id = access.auth.user.id
                cfg_row.version += 1
                cfg_row.updated_at = ref_now
                await db.flush()

                await self._budgets.ensure_workspace_daily_account_in_tx(
                    db,
                    workspace_id=ws_id,
                    policy=target_budget,
                    sync_caps=True,
                    now=ref_now,
                )

                models_dto = await self._build_workspace_models_dto_in_tx(
                    db,
                    workspace_id=ws_id,
                    cfg_row=cfg_row,
                    now=ref_now,
                )
                receipt = await upsert_operation_receipt(
                    db,
                    operation_id=claim.receipt.operation_id,
                    scope="workspace",
                    workspace_id=ws_id,
                    principal_id=principal_id,
                    required_role="admin",
                    operation_kind=op_name,
                    resource_id=cfg_row.id,
                    state="succeeded",
                    correlation_id=correlation_id,
                    status_url=claim.receipt.status_url,
                    logical_effect_key=eff_key,
                    result_id=cfg_row.id,
                    now=ref_now,
                )
                response_dto = WorkspaceModelsConfigUpdateResponse(
                    receipt=receipt,
                    models_state=models_dto,
                )
                serialized = response_dto.model_dump(mode="json")
                await complete_idempotent_operation(
                    db,
                    workspace_id=ws_id,
                    operation_id=claim.receipt.operation_id,
                    state="succeeded",
                    status_code=200,
                    result_id=cfg_row.id,
                    response_payload=serialized,
                    now=ref_now,
                )
                await append_audit_entry(
                    db,
                    workspace_id=ws_id,
                    actor_type="user",
                    actor_id=access.auth.user.id,
                    action=op_name,
                    target=f"workspace:{ws_id}:models",
                    decision="allow",
                    reason_code="models_config_updated",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={
                        "new_version": cfg_row.version,
                        "endpoint_base_url": cfg_row.endpoint_base_url,
                        "api_key_rotated": secret_material is not None,
                        "api_key_revoked": payload.revoke_api_key,
                    },
                    occurred_at=ref_now,
                    redactor=self._redactor,
                )

        if raised_exc is not None:
            raise raised_exc
        assert response_dto is not None
        return response_dto

    def _scrub_chat_messages(
        self,
        messages: Sequence[MetaChatMessage],
    ) -> list[dict[str, Any]]:
        scrubbed_list: list[dict[str, Any]] = []
        for msg in messages:
            entry: dict[str, Any] = {"role": msg.role}
            if msg.content is not None:
                entry["content"] = self._redactor.redact_text(msg.content)
            else:
                entry["content"] = None
            if msg.name is not None:
                entry["name"] = self._redactor.redact_text(msg.name)
            if msg.tool_call_id is not None:
                entry["tool_call_id"] = msg.tool_call_id
            if msg.tool_calls:
                entry["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": self._redactor.redact_text(tc.function.arguments),
                        },
                    }
                    for tc in msg.tool_calls
                ]
            scrubbed_list.append(entry)
        return scrubbed_list

    def _serialize_tools(
        self,
        tools: Sequence[MetaToolDefinition],
    ) -> list[dict[str, Any]]:
        serialized: list[dict[str, Any]] = []
        for tool_def in tools:
            _validate_non_recursive_json_schema(tool_def.function.parameters)
            serialized.append(
                {
                    "type": "function",
                    "function": {
                        "name": tool_def.function.name,
                        "description": self._redactor.redact_text(tool_def.function.description),
                        "strict": tool_def.function.strict,
                        "parameters": self._redactor.redact_value(tool_def.function.parameters),
                    },
                }
            )
        return serialized

    def _serialize_response_format(
        self,
        response_format: MetaResponseFormat | None,
    ) -> dict[str, Any] | None:
        if response_format is None or response_format.type == "text":
            return None
        assert response_format.json_schema is not None
        _validate_non_recursive_json_schema(response_format.json_schema.schema_def)
        return {
            "type": "json_schema",
            "json_schema": {
                "name": response_format.json_schema.name,
                "strict": response_format.json_schema.strict,
                "schema": response_format.json_schema.schema_def,
            },
        }

    async def _send_meta_http_post(
        self,
        *,
        endpoint_base_url: str,
        api_key_str: str,
        wire_payload: dict[str, Any],
        correlation_id: str,
    ) -> tuple[httpx.Response, int]:
        for forbidden_param in _FORBIDDEN_WIRE_PARAMS:
            if forbidden_param in wire_payload:
                raise BadRequestError(
                    code="unsupported_meta_parameter",
                    detail=(
                        f"Parameter '{forbidden_param}' is unsupported on Meta Model API (ADR-008)."
                    ),
                )

        target_url = f"{endpoint_base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key_str}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Correlation-Id": correlation_id,
        }
        started_ns = time.monotonic_ns()
        async with EgressSafeHttpClient(
            adapter="meta_inference",
            policy_engine=self._egress_policy,
            ca_bundle_resolver=self._ca_bundle_resolver,
            network_backend=self._network_backend,
            timeout_seconds=self._timeout_seconds,
            max_redirects=3,
        ) as client:
            resp = await client.request(
                "POST",
                target_url,
                headers=headers,
                json=wire_payload,
            )
        elapsed_ms = max(0, (time.monotonic_ns() - started_ns) // 1_000_000)
        return (resp, elapsed_ms)

    async def _record_workspace_suspension(
        self,
        *,
        workspace_id: str,
        reason: SuspensionReason,
        detail: str,
        retry_after_seconds: int | None,
        now: datetime,
    ) -> None:
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            cfg = await self._ensure_workspace_config_in_tx(
                db,
                workspace_id=workspace_id,
                now=now,
                for_update=True,
            )
            cfg.suspension_reason = reason
            cfg.status_detail = self._redactor.redact_text(detail)[:1000]
            cfg.retry_after_until = (
                now + timedelta(seconds=retry_after_seconds)
                if retry_after_seconds is not None and retry_after_seconds > 0
                else None
            )
            cfg.version += 1
            cfg.updated_at = now
            await db.flush()

    async def _clear_transient_suspension_if_needed(
        self,
        *,
        workspace_id: str,
        now: datetime,
    ) -> None:
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            cfg = await self._ensure_workspace_config_in_tx(
                db,
                workspace_id=workspace_id,
                now=now,
                for_update=True,
            )
            if cfg.suspension_reason == "model_unavailable":
                cfg.suspension_reason = None
                cfg.status_detail = None
                cfg.retry_after_until = None
                cfg.version += 1
                cfg.updated_at = now
                await db.flush()

    async def _persist_capability_snapshot(
        self,
        *,
        workspace_id: str,
        model_id: MetaModelId,
        status: ModelAvailabilityStatus,
        capabilities: ModelCapabilityFlags,
        consent_id: str | None,
        provider_request_id: str | None,
        status_detail: str | None,
        now: datetime,
        suspension_reason: SuspensionReason | None = None,
        retry_after_seconds: int | None = None,
        disable_wonder_escalation: bool = False,
    ) -> ModelCapabilitySnapshot:
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            snap_row = ModelCapabilitySnapshotModel(
                id=new_uuid7(now=now),
                workspace_id=workspace_id,
                model_id=model_id,
                tier_role=_tier_role_for_model(model_id),
                status=status,
                capabilities_json=capabilities.model_dump(mode="json"),
                provider_request_id=provider_request_id,
                consent_id=consent_id,
                probed_at=now,
                status_detail=(
                    self._redactor.redact_text(status_detail)[:1000] if status_detail else None
                ),
                suspension_reason=suspension_reason,
                retry_after_seconds=retry_after_seconds,
                version=1,
                created_at=now,
                updated_at=now,
            )
            db.add(snap_row)
            if disable_wonder_escalation and model_id == ESCALATION_META_MODEL_ID:
                cfg = await self._ensure_workspace_config_in_tx(
                    db,
                    workspace_id=workspace_id,
                    now=now,
                    for_update=True,
                )
                esc = self._effective_escalation_policy(cfg.escalation_policy_json)
                if esc.escalation_enabled:
                    updated_esc = esc.model_copy(update={"escalation_enabled": False})
                    cfg.escalation_policy_json = updated_esc.model_dump(mode="json")
                    cfg.version += 1
                    cfg.updated_at = now
            await db.flush()
            return _snapshot_row_to_dto(snap_row)

    async def probe_model(
        self,
        *,
        access: WorkspaceAccessContext,
        payload: ModelProbeRequest,
        idempotency_key: str,
        correlation_id: str,
        client_ip: str | None = None,
    ) -> ModelProbeResponse:
        """Execute a consented, budget-reserved Meta Model API capability probe (`A-20`)."""
        _ensure_workspace_role(access, allowed_roles=ADMIN_ONLY_ROLES)
        ws_id = access.workspace.id
        target_model = validate_supported_meta_model_id(payload.model_id)
        ref_now = self._iam.now()
        principal_id = access.auth.user.id
        op_name = "models.probe.execute"
        req_body = payload.model_dump(mode="json")

        pre_exc: Red2PrError | None = None
        endpoint_url = DEFAULT_META_API_BASE_URL
        api_key_str = ""
        pricing_rate: ModelPricingRate | None = None
        probe_acct_id = ""
        daily_acct_id = ""
        claim_op_id = ""
        claim_status_url = ""
        claim_eff_key = f"{op_name}:{ws_id}:{idempotency_key}"

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            replay = await _check_existing_idempotent_replay_in_tx(
                db,
                workspace_id=ws_id,
                principal_id=principal_id,
                operation=op_name,
                idempotency_key=idempotency_key,
                request_payload=req_body,
                correlation_id=correlation_id,
                now=ref_now,
            )
            if replay is not None and replay.cached_response is not None:
                return ModelProbeResponse.model_validate(replay.cached_response)

            cfg_row = await self._ensure_workspace_config_in_tx(
                db,
                workspace_id=ws_id,
                now=ref_now,
            )
            endpoint_url, _, endpoint_denial = await self._validate_meta_endpoint_in_tx(
                db,
                endpoint_base_url=cfg_row.endpoint_base_url,
                endpoint_registration_id=cfg_row.endpoint_registration_id,
            )
            if endpoint_denial is not None:
                await self._emit_policy_denial_in_tx(
                    db,
                    workspace_id=ws_id,
                    actor_type="user",
                    actor_id=access.auth.user.id,
                    action=op_name,
                    target=f"model:{target_model}",
                    reason_code=endpoint_denial,
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    now=ref_now,
                )
                pre_exc = ForbiddenError(
                    code="meta_endpoint_not_allowlisted",
                    detail="Configured inference endpoint is not allowlisted for Meta Model API.",
                )

            if pre_exc is None:
                _, consent_err = await self._verify_active_inference_consent_in_tx(
                    db,
                    workspace_id=ws_id,
                    consent_id=payload.consent_id,
                    endpoint_base_url=endpoint_url,
                )
                if consent_err is not None:
                    await self._emit_policy_denial_in_tx(
                        db,
                        workspace_id=ws_id,
                        actor_type="user",
                        actor_id=access.auth.user.id,
                        action=op_name,
                        target=f"model:{target_model}",
                        reason_code=consent_err,
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        now=ref_now,
                    )
                    pre_exc = ForbiddenError(
                        code="inference_consent_required",
                        detail=(
                            f"Active outbound inference consent is required before probing "
                            f"({consent_err})."
                        ),
                    )

            if pre_exc is None:
                if cfg_row.credential_secret_ref is None:
                    pre_exc = ConflictError(
                        code="meta_api_key_not_configured",
                        detail="Configure a Meta Model API key before running a capability probe.",
                    )
                else:
                    raw_key = await self._secrets.resolve_secret_bytes(
                        db,
                        secret_ref=cfg_row.credential_secret_ref,
                        capability=INFERENCE_SECRET_CAPABILITY,
                        workspace_id=ws_id,
                    )
                    api_key_str = raw_key.decode("utf-8").strip()

            if pre_exc is None:
                pricing_map = self._parse_pricing_map(cfg_row.pricing_json)
                pricing_rate = pricing_map.get(target_model)
                if pricing_rate is None or not pricing_rate.configured:
                    pre_exc = ConflictError(
                        code="unknown_model_pricing",
                        detail=(
                            f"Audited upper-bound token pricing is not configured for model "
                            f"'{target_model}'; configure pricing rates before running "
                            "paid probes."
                        ),
                    )

            if pre_exc is None:
                claim = await claim_idempotent_operation(
                    db,
                    workspace_id=ws_id,
                    principal_id=principal_id,
                    operation=op_name,
                    idempotency_key=idempotency_key,
                    request_payload=req_body,
                    logical_effect_key=claim_eff_key,
                    resource_id=cfg_row.id,
                    correlation_id=correlation_id,
                    now=ref_now,
                )
                if not claim.is_new_claim and claim.cached_response is not None:
                    return ModelProbeResponse.model_validate(claim.cached_response)
                claim_op_id = claim.receipt.operation_id
                claim_status_url = claim.receipt.status_url

                budget_policy = self._effective_budget_policy(cfg_row.budget_policy_json)
                daily_acct = await self._budgets.ensure_workspace_daily_account_in_tx(
                    db,
                    workspace_id=ws_id,
                    policy=budget_policy,
                    now=ref_now,
                )
                probe_acct = await self._budgets.create_probe_account_in_tx(
                    db,
                    workspace_id=ws_id,
                    probe_key=claim_op_id,
                    max_cost=payload.max_cost,
                    max_tokens=max(4096, payload.max_output_tokens * 8),
                    now=ref_now,
                )
                daily_acct_id = daily_acct.id
                probe_acct_id = probe_acct.id

        if pre_exc is not None:
            raise pre_exc
        assert pricing_rate is not None

        scrubbed_prompt = self._redactor.redact_text(_PROBE_SYSTEM_PROMPT)
        wire_payload: dict[str, Any] = {
            "model": target_model,
            "messages": [
                {"role": "system", "content": scrubbed_prompt},
                {"role": "user", "content": "Return probe_ok=true."},
            ],
            "max_completion_tokens": payload.max_output_tokens,
            "temperature": 0.0,
            "tools": [_PROBE_TOOL_SPEC],
            "tool_choice": "none",
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "red2pr_capability_probe",
                    "strict": True,
                    "schema": _PROBE_RESPONSE_SCHEMA,
                },
            },
        }
        prompt_digest = sha256_canonical_json(wire_payload)
        est_in = estimate_worst_case_input_tokens(
            json.dumps(wire_payload, separators=(",", ":")),
            item_count=3,
        )

        try:
            reservation = await self._budgets.reserve_for_call(
                workspace_id=ws_id,
                primary_account_id=probe_acct_id,
                secondary_account_id=daily_acct_id,
                consent_id=payload.consent_id,
                model_id=target_model,
                pricing=pricing_rate,
                estimated_input_tokens=est_in,
                max_output_tokens=payload.max_output_tokens,
                prompt_redacted_digest=prompt_digest,
                correlation_id=correlation_id,
                actor_type="user",
                actor_id=access.auth.user.id,
                now=ref_now,
            )
        except Red2PrError as exc:
            await self._fail_probe_idempotency(
                workspace_id=ws_id,
                principal_id=principal_id,
                claim_op_id=claim_op_id,
                claim_status_url=claim_status_url,
                claim_eff_key=claim_eff_key,
                resource_id=probe_acct_id,
                state="failed",
                exc=exc,
                correlation_id=correlation_id,
                now=self._iam.now(),
            )
            raise

        try:
            http_resp, _ = await self._send_meta_http_post(
                endpoint_base_url=endpoint_url,
                api_key_str=api_key_str,
                wire_payload=wire_payload,
                correlation_id=correlation_id,
            )
        except EgressBlockedError as exc:
            err_now = self._iam.now()
            await self._budgets.release_unexecuted_reservation(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code=exc.code,
                actor_type="user",
                actor_id=access.auth.user.id,
                now=err_now,
            )
            async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
                await self._emit_policy_denial_in_tx(
                    db,
                    workspace_id=ws_id,
                    actor_type="user",
                    actor_id=access.auth.user.id,
                    action=op_name,
                    target=f"model:{target_model}",
                    reason_code=exc.code,
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    now=err_now,
                )
            await self._fail_probe_idempotency(
                workspace_id=ws_id,
                principal_id=principal_id,
                claim_op_id=claim_op_id,
                claim_status_url=claim_status_url,
                claim_eff_key=claim_eff_key,
                resource_id=reservation.id,
                state="failed",
                exc=exc,
                correlation_id=correlation_id,
                now=err_now,
            )
            raise
        except httpx.ConnectError as exc:
            err_now = self._iam.now()
            await self._budgets.release_unexecuted_reservation(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code="meta_connect_failed",
                actor_type="user",
                actor_id=access.auth.user.id,
                now=err_now,
            )
            detail_msg = "Meta Model API connection failed; workspace marked model_unavailable."
            await self._record_workspace_suspension(
                workspace_id=ws_id,
                reason="model_unavailable",
                detail=detail_msg,
                retry_after_seconds=DEFAULT_RATE_LIMIT_RETRY_SECONDS,
                now=err_now,
            )
            snap_err = await self._persist_capability_snapshot(
                workspace_id=ws_id,
                model_id=target_model,
                status="degraded",
                capabilities=ModelCapabilityFlags(),
                consent_id=payload.consent_id,
                provider_request_id=None,
                status_detail=detail_msg,
                suspension_reason="model_unavailable",
                retry_after_seconds=DEFAULT_RATE_LIMIT_RETRY_SECONDS,
                now=err_now,
            )
            dep_err = _dep_unavailable(
                code="model_unavailable",
                detail="Meta Model API endpoint is unreachable; repair inference is suspended.",
                retry_after_seconds=DEFAULT_RATE_LIMIT_RETRY_SECONDS,
            )
            await self._fail_probe_idempotency(
                workspace_id=ws_id,
                principal_id=principal_id,
                claim_op_id=claim_op_id,
                claim_status_url=claim_status_url,
                claim_eff_key=claim_eff_key,
                resource_id=snap_err.id,
                state="failed",
                exc=dep_err,
                correlation_id=correlation_id,
                now=err_now,
            )
            raise dep_err from exc
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            err_now = self._iam.now()
            await self._budgets.mark_unknown_outcome(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code="meta_upstream_timeout",
                provider_request_id=None,
                actor_type="user",
                actor_id=access.auth.user.id,
                now=err_now,
            )
            detail_msg = (
                "Meta Model API timed out after dispatch; worst-case budget reservation "
                "retained as unknown outcome."
            )
            await self._record_workspace_suspension(
                workspace_id=ws_id,
                reason="model_unavailable",
                detail=detail_msg,
                retry_after_seconds=DEFAULT_RATE_LIMIT_RETRY_SECONDS,
                now=err_now,
            )
            snap_err = await self._persist_capability_snapshot(
                workspace_id=ws_id,
                model_id=target_model,
                status="degraded",
                capabilities=ModelCapabilityFlags(),
                consent_id=payload.consent_id,
                provider_request_id=None,
                status_detail=detail_msg,
                suspension_reason="model_unavailable",
                retry_after_seconds=DEFAULT_RATE_LIMIT_RETRY_SECONDS,
                now=err_now,
            )
            dep_err = _dep_unavailable(
                code="model_unavailable",
                detail=(
                    "Meta Model API timed out after dispatch; worst-case reservation retained "
                    "as unknown outcome (SEC-033)."
                ),
                retry_after_seconds=DEFAULT_RATE_LIMIT_RETRY_SECONDS,
            )
            await self._fail_probe_idempotency(
                workspace_id=ws_id,
                principal_id=principal_id,
                claim_op_id=claim_op_id,
                claim_status_url=claim_status_url,
                claim_eff_key=claim_eff_key,
                resource_id=snap_err.id,
                state="unknown",
                exc=dep_err,
                correlation_id=correlation_id,
                now=err_now,
            )
            raise dep_err from exc

        done_now = self._iam.now()
        raw_req_id = http_resp.headers.get("x-request-id") or http_resp.headers.get(
            "meta-request-id"
        )
        scrubbed_req_id = self._redactor.redact_text(raw_req_id)[:256] if raw_req_id else None
        rpm_hdr = http_resp.headers.get("x-ratelimit-limit-requests")
        tpm_hdr = http_resp.headers.get("x-ratelimit-limit-tokens")
        rate_rpm = int(rpm_hdr) if rpm_hdr and rpm_hdr.isdigit() and int(rpm_hdr) > 0 else None
        rate_tpm = int(tpm_hdr) if tpm_hdr and tpm_hdr.isdigit() and int(tpm_hdr) > 0 else None

        if http_resp.status_code == 429 or http_resp.status_code >= 500:
            retry_secs = _parse_retry_after_seconds(
                http_resp.headers,
                default_seconds=DEFAULT_RATE_LIMIT_RETRY_SECONDS,
            )
            err_code = (
                "meta_rate_limited" if http_resp.status_code == 429 else "meta_upstream_outage"
            )
            await self._budgets.release_unexecuted_reservation(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code=err_code,
                provider_request_id=scrubbed_req_id,
                actor_type="user",
                actor_id=access.auth.user.id,
                now=done_now,
            )
            detail_msg = (
                f"Meta Model API returned HTTP {http_resp.status_code}; "
                f"workspace suspended as model_unavailable (retry_after={retry_secs}s)."
            )
            await self._record_workspace_suspension(
                workspace_id=ws_id,
                reason="model_unavailable",
                detail=detail_msg,
                retry_after_seconds=retry_secs,
                now=done_now,
            )
            snap_err = await self._persist_capability_snapshot(
                workspace_id=ws_id,
                model_id=target_model,
                status="degraded",
                capabilities=ModelCapabilityFlags(
                    rate_limit_rpm=rate_rpm,
                    rate_limit_tpm=rate_tpm,
                ),
                consent_id=payload.consent_id,
                provider_request_id=scrubbed_req_id,
                status_detail=detail_msg,
                suspension_reason="model_unavailable",
                retry_after_seconds=retry_secs,
                now=done_now,
            )
            out_err: Red2PrError
            if http_resp.status_code == 429:
                out_err = RateLimitedError(
                    code="model_unavailable",
                    detail=(
                        "Meta Model API rate limit reached; workspace suspended with "
                        "reason='model_unavailable'."
                    ),
                    retry_after_seconds=retry_secs,
                )
            else:
                out_err = _dep_unavailable(
                    code="model_unavailable",
                    detail=(
                        f"Meta Model API returned upstream {http_resp.status_code}; workspace "
                        "suspended with reason='model_unavailable'."
                    ),
                    retry_after_seconds=retry_secs,
                )
            await self._fail_probe_idempotency(
                workspace_id=ws_id,
                principal_id=principal_id,
                claim_op_id=claim_op_id,
                claim_status_url=claim_status_url,
                claim_eff_key=claim_eff_key,
                resource_id=snap_err.id,
                state="failed",
                exc=out_err,
                correlation_id=correlation_id,
                now=done_now,
            )
            raise out_err

        if http_resp.status_code == 401:
            await self._budgets.release_unexecuted_reservation(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code="meta_auth_failed",
                usage_status="failed",
                provider_request_id=scrubbed_req_id,
                actor_type="user",
                actor_id=access.auth.user.id,
                now=done_now,
            )
            detail_msg = "Meta Model API rejected the configured API key (HTTP 401)."
            await self._record_workspace_suspension(
                workspace_id=ws_id,
                reason="model_unavailable",
                detail=detail_msg,
                retry_after_seconds=None,
                now=done_now,
            )
            snap_err = await self._persist_capability_snapshot(
                workspace_id=ws_id,
                model_id=target_model,
                status="unavailable",
                capabilities=ModelCapabilityFlags(),
                consent_id=payload.consent_id,
                provider_request_id=scrubbed_req_id,
                status_detail=detail_msg,
                suspension_reason="model_unavailable",
                now=done_now,
            )
            auth_err = ForbiddenError(
                code="meta_auth_failed",
                detail=detail_msg,
            )
            await self._fail_probe_idempotency(
                workspace_id=ws_id,
                principal_id=principal_id,
                claim_op_id=claim_op_id,
                claim_status_url=claim_status_url,
                claim_eff_key=claim_eff_key,
                resource_id=snap_err.id,
                state="failed",
                exc=auth_err,
                correlation_id=correlation_id,
                now=done_now,
            )
            raise auth_err

        if http_resp.status_code in (403, 404):
            upstream_err_code = "model_not_entitled"
            upstream_msg = f"Model '{target_model}' is not available on this Meta account."
            try:
                err_json = http_resp.json()
                if isinstance(err_json, Mapping):
                    err_obj = err_json.get("error")
                    if isinstance(err_obj, Mapping):
                        raw_c = err_obj.get("code")
                        raw_m = err_obj.get("message")
                        if isinstance(raw_c, str) and raw_c.strip():
                            upstream_err_code = self._redactor.redact_text(raw_c.strip())[:120]
                        if isinstance(raw_m, str) and raw_m.strip():
                            upstream_msg = self._redactor.redact_text(raw_m.strip())[:1000]
            except ValueError:
                pass

            await self._budgets.release_unexecuted_reservation(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code=upstream_err_code,
                provider_request_id=scrubbed_req_id,
                actor_type="user",
                actor_id=access.auth.user.id,
                now=done_now,
            )
            susp_for_primary: SuspensionReason | None = None
            if target_model == PRIMARY_META_MODEL_ID:
                susp_for_primary = "model_unavailable"
                await self._record_workspace_suspension(
                    workspace_id=ws_id,
                    reason="model_unavailable",
                    detail=upstream_msg,
                    retry_after_seconds=None,
                    now=done_now,
                )
            snapshot_dto = await self._persist_capability_snapshot(
                workspace_id=ws_id,
                model_id=target_model,
                status="unavailable",
                capabilities=ModelCapabilityFlags(
                    tool_calls="unavailable",
                    structured_output="unavailable",
                    streaming="unavailable",
                ),
                consent_id=payload.consent_id,
                provider_request_id=scrubbed_req_id,
                status_detail=f"{upstream_err_code}: {upstream_msg}"[:1000],
                suspension_reason=susp_for_primary,
                now=done_now,
                disable_wonder_escalation=True,
            )
            return await self._finalize_probe_idempotency(
                workspace_id=ws_id,
                principal_id=principal_id,
                claim_op_id=claim_op_id,
                claim_status_url=claim_status_url,
                claim_eff_key=claim_eff_key,
                snapshot_dto=snapshot_dto,
                usage_dto=None,
                correlation_id=correlation_id,
                actor_id=access.auth.user.id,
                client_ip=client_ip,
                now=done_now,
            )

        if http_resp.status_code != 200:
            await self._budgets.release_unexecuted_reservation(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code=f"meta_http_{http_resp.status_code}",
                provider_request_id=scrubbed_req_id,
                actor_type="user",
                actor_id=access.auth.user.id,
                now=done_now,
            )
            unexp_err = _dep_unavailable(
                code="model_unavailable",
                detail=f"Unexpected HTTP {http_resp.status_code} from Meta Model API.",
            )
            await self._fail_probe_idempotency(
                workspace_id=ws_id,
                principal_id=principal_id,
                claim_op_id=claim_op_id,
                claim_status_url=claim_status_url,
                claim_eff_key=claim_eff_key,
                resource_id=reservation.id,
                state="failed",
                exc=unexp_err,
                correlation_id=correlation_id,
                now=done_now,
            )
            raise unexp_err

        parsed_body, usage_stats, provider_req_id, response_digest = self._parse_200_chat_body(
            http_resp,
            fallback_request_id=scrubbed_req_id,
        )
        if usage_stats is None:
            unknown_outcome = await self._budgets.mark_unknown_outcome(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code="missing_usage_envelope",
                provider_request_id=provider_req_id,
                actor_type="user",
                actor_id=access.auth.user.id,
                now=done_now,
            )
            snapshot_dto = await self._persist_capability_snapshot(
                workspace_id=ws_id,
                model_id=target_model,
                status="degraded",
                capabilities=ModelCapabilityFlags(),
                consent_id=payload.consent_id,
                provider_request_id=provider_req_id,
                status_detail=(
                    "Meta response omitted token usage accounting; retained unknown spend."
                ),
                now=done_now,
            )
            return await self._finalize_probe_idempotency(
                workspace_id=ws_id,
                principal_id=principal_id,
                claim_op_id=claim_op_id,
                claim_status_url=claim_status_url,
                claim_eff_key=claim_eff_key,
                snapshot_dto=snapshot_dto,
                usage_dto=unknown_outcome.usage_record,
                correlation_id=correlation_id,
                actor_id=access.auth.user.id,
                client_ip=client_ip,
                now=done_now,
            )

        settlement = await self._budgets.settle_reservation(
            workspace_id=ws_id,
            reservation_id=reservation.id,
            pricing=pricing_rate,
            actual_input_tokens=usage_stats.prompt_tokens,
            actual_output_tokens=usage_stats.completion_tokens,
            provider_request_id=provider_req_id,
            response_redacted_digest=response_digest,
            actor_type="user",
            actor_id=access.auth.user.id,
            now=done_now,
        )

        structured_ok = False
        choices = parsed_body.get("choices")
        if isinstance(choices, list) and choices:
            first_choice = choices[0]
            if isinstance(first_choice, Mapping):
                msg_obj = first_choice.get("message")
                if isinstance(msg_obj, Mapping):
                    content_str = msg_obj.get("content")
                    if isinstance(content_str, str):
                        try:
                            probe_obj = json.loads(content_str)
                            structured_ok = (
                                isinstance(probe_obj, Mapping) and probe_obj.get("probe_ok") is True
                            )
                        except ValueError:
                            structured_ok = False

        ctx_win = 128_000
        max_out = 16_384
        raw_limits = parsed_body.get("model_limits")
        if isinstance(raw_limits, Mapping):
            cw = raw_limits.get("context_window_tokens")
            mo = raw_limits.get("max_output_tokens")
            if isinstance(cw, int) and cw > 0:
                ctx_win = cw
            if isinstance(mo, int) and mo > 0:
                max_out = mo

        caps = ModelCapabilityFlags(
            tool_calls="available",
            structured_output="available" if structured_ok else "unavailable",
            streaming="available",
            context_window_tokens=ctx_win,
            max_output_tokens=max_out,
            rate_limit_rpm=rate_rpm,
            rate_limit_tpm=rate_tpm,
        )
        snap_status: ModelAvailabilityStatus = "available" if structured_ok else "degraded"
        if snap_status == "available" and target_model == PRIMARY_META_MODEL_ID:
            await self._clear_transient_suspension_if_needed(
                workspace_id=ws_id,
                now=done_now,
            )

        snapshot_dto = await self._persist_capability_snapshot(
            workspace_id=ws_id,
            model_id=target_model,
            status=snap_status,
            capabilities=caps,
            consent_id=payload.consent_id,
            provider_request_id=provider_req_id,
            status_detail=(
                f"Verified {target_model} structured outputs & tool schema support."
                if structured_ok
                else "Model responded 200 OK but failed strict structured JSON verification."
            ),
            now=done_now,
        )
        return await self._finalize_probe_idempotency(
            workspace_id=ws_id,
            principal_id=principal_id,
            claim_op_id=claim_op_id,
            claim_status_url=claim_status_url,
            claim_eff_key=claim_eff_key,
            snapshot_dto=snapshot_dto,
            usage_dto=settlement.usage_record,
            correlation_id=correlation_id,
            actor_id=access.auth.user.id,
            client_ip=client_ip,
            now=done_now,
        )

    async def _fail_probe_idempotency(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        claim_op_id: str,
        claim_status_url: str,
        claim_eff_key: str,
        resource_id: str,
        state: CompletedActionState,
        exc: Red2PrError,
        correlation_id: str,
        now: datetime,
    ) -> None:
        if not claim_op_id:
            return
        prob = problem_from_exception(
            exc,
            correlation_id=correlation_id,
            redactor=self._redactor,
        )
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            await upsert_operation_receipt(
                db,
                operation_id=claim_op_id,
                scope="workspace",
                workspace_id=workspace_id,
                principal_id=principal_id,
                required_role="admin",
                operation_kind="models.probe.execute",
                resource_id=resource_id,
                state=state,
                correlation_id=correlation_id,
                status_url=claim_status_url,
                logical_effect_key=claim_eff_key,
                problem=prob,
                now=now,
            )
            await complete_idempotent_operation(
                db,
                workspace_id=workspace_id,
                operation_id=claim_op_id,
                state=state,
                status_code=exc.status,
                problem=prob,
                now=now,
            )

    async def _finalize_probe_idempotency(
        self,
        *,
        workspace_id: str,
        principal_id: str,
        claim_op_id: str,
        claim_status_url: str,
        claim_eff_key: str,
        snapshot_dto: ModelCapabilitySnapshot,
        usage_dto: ModelUsageRecord | None,
        correlation_id: str,
        actor_id: str,
        client_ip: str | None,
        now: datetime,
    ) -> ModelProbeResponse:
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            cfg_row = await self._ensure_workspace_config_in_tx(
                db,
                workspace_id=workspace_id,
                now=now,
            )
            models_dto = await self._build_workspace_models_dto_in_tx(
                db,
                workspace_id=workspace_id,
                cfg_row=cfg_row,
                now=now,
            )
            receipt = await upsert_operation_receipt(
                db,
                operation_id=claim_op_id,
                scope="workspace",
                workspace_id=workspace_id,
                principal_id=principal_id,
                required_role="admin",
                operation_kind="models.probe.execute",
                resource_id=snapshot_dto.id,
                state="succeeded",
                correlation_id=correlation_id,
                status_url=claim_status_url,
                logical_effect_key=claim_eff_key,
                result_id=snapshot_dto.id,
                now=now,
            )
            resp_dto = ModelProbeResponse(
                receipt=receipt,
                snapshot=snapshot_dto,
                usage_record=usage_dto,
                models_state=models_dto,
            )
            await complete_idempotent_operation(
                db,
                workspace_id=workspace_id,
                operation_id=claim_op_id,
                state="succeeded",
                status_code=200,
                result_id=snapshot_dto.id,
                response_payload=resp_dto.model_dump(mode="json"),
                now=now,
            )
            await append_audit_entry(
                db,
                workspace_id=workspace_id,
                actor_type="user",
                actor_id=actor_id,
                action="models.probe.execute",
                target=f"model:{snapshot_dto.model_id}",
                decision="allow",
                reason_code=f"probe_{snapshot_dto.status}",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={
                    "snapshot_id": snapshot_dto.id,
                    "status": snapshot_dto.status,
                    "usage_id": usage_dto.id if usage_dto is not None else None,
                },
                occurred_at=now,
                redactor=self._redactor,
            )
            return resp_dto

    def _parse_200_chat_body(
        self,
        http_resp: httpx.Response,
        *,
        fallback_request_id: str | None,
    ) -> tuple[dict[str, Any], MetaTokenUsage | None, str | None, str]:
        try:
            raw_json = http_resp.json()
        except ValueError as exc:
            raise UnprocessableEntityError(
                code="malformed_meta_response",
                detail="Meta Model API returned non-JSON body on HTTP 200.",
            ) from exc

        if not isinstance(raw_json, Mapping):
            raise UnprocessableEntityError(
                code="malformed_meta_response",
                detail="Meta Model API HTTP 200 payload must be a JSON object.",
            )

        cot_stripped = _strip_cot_fields(raw_json)
        scrubbed_body = self._redactor.redact_value(cot_stripped)
        assert isinstance(scrubbed_body, dict)
        response_digest = sha256_canonical_json(scrubbed_body)

        body_id = scrubbed_body.get("id")
        provider_req_id = (
            str(body_id)[:256]
            if isinstance(body_id, str) and body_id.strip()
            else (
                self._redactor.redact_text(fallback_request_id)[:256]
                if fallback_request_id
                else None
            )
        )

        usage_raw = scrubbed_body.get("usage")
        usage_stats: MetaTokenUsage | None = None
        if isinstance(usage_raw, Mapping):
            p_tok = usage_raw.get("prompt_tokens")
            c_tok = usage_raw.get("completion_tokens")
            t_tok = usage_raw.get("total_tokens")
            details = usage_raw.get("completion_tokens_details")
            r_tok = 0
            if isinstance(details, Mapping):
                raw_r = details.get("reasoning_tokens")
                if isinstance(raw_r, int) and not isinstance(raw_r, bool) and raw_r >= 0:
                    r_tok = raw_r
            if (
                isinstance(p_tok, int)
                and not isinstance(p_tok, bool)
                and p_tok >= 0
                and isinstance(c_tok, int)
                and not isinstance(c_tok, bool)
                and c_tok >= 0
            ):
                tot = (
                    t_tok
                    if isinstance(t_tok, int)
                    and not isinstance(t_tok, bool)
                    and t_tok >= (p_tok + c_tok)
                    else (p_tok + c_tok)
                )
                usage_stats = MetaTokenUsage(
                    prompt_tokens=p_tok,
                    completion_tokens=c_tok,
                    total_tokens=tot,
                    reasoning_tokens=r_tok,
                )

        return (scrubbed_body, usage_stats, provider_req_id, response_digest)

    async def select_model_for_attempt(
        self,
        *,
        workspace_id: str,
        failed_attempts: int = 0,
    ) -> MetaModelId:
        """Select `muse-spark-1.3` by default or `muse-wonder-1.0` when escalation is verified."""
        ref_now = self._iam.now()
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            cfg = await self._ensure_workspace_config_in_tx(
                db,
                workspace_id=workspace_id,
                now=ref_now,
            )
            esc = self._effective_escalation_policy(cfg.escalation_policy_json)
            if not esc.escalation_enabled or failed_attempts < esc.escalate_after_failed_attempts:
                return PRIMARY_META_MODEL_ID

            snapshots = await self._latest_snapshots_in_tx(db, workspace_id=workspace_id)
            wonder_snap = snapshots.get(ESCALATION_META_MODEL_ID)
            if wonder_snap is not None and wonder_snap.status == "available":
                return ESCALATION_META_MODEL_ID
            return PRIMARY_META_MODEL_ID

    async def complete_chat(
        self,
        request: MetaChatCompletionRequest,
        *,
        cancel_check: Callable[[], bool] | None = None,
    ) -> MetaChatCompletionResult:
        """Execute a consented, scrubbed, budget-governed Meta `/v1/chat/completions` call."""
        if cancel_check is not None and cancel_check():
            raise ConflictError(
                code="inference_cancelled",
                detail="Repair session was cancelled before dispatching Meta inference.",
            )

        target_model = validate_supported_meta_model_id(request.model_id)
        ws_id = request.workspace_id
        ref_now = self._iam.now()
        corr_id = request.correlation_id or new_uuid7(now=ref_now)
        scrubbed_messages = self._scrub_chat_messages(request.messages)
        serialized_tools = self._serialize_tools(request.tools) if request.tools else []
        serialized_format = self._serialize_response_format(request.response_format)

        pre_exc: Red2PrError | None = None
        endpoint_url = DEFAULT_META_API_BASE_URL
        api_key_str = ""
        pricing_rate: ModelPricingRate | None = None
        primary_acct_id = ""
        secondary_acct_id: str | None = None
        verified_consent_id = ""
        alert_pct = 80

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            cfg_row = await self._ensure_workspace_config_in_tx(
                db,
                workspace_id=ws_id,
                now=ref_now,
            )
            if cfg_row.suspension_reason is not None:
                retry_secs = _remaining_retry_seconds(cfg_row.retry_after_until, now=ref_now)
                pre_exc = _dep_unavailable(
                    code=cfg_row.suspension_reason,
                    detail=(
                        f"Workspace inference is currently suspended "
                        f"(reason='{cfg_row.suspension_reason}')."
                    ),
                    retry_after_seconds=retry_secs,
                )

            if pre_exc is None:
                endpoint_url, _, endpoint_denial = await self._validate_meta_endpoint_in_tx(
                    db,
                    endpoint_base_url=cfg_row.endpoint_base_url,
                    endpoint_registration_id=cfg_row.endpoint_registration_id,
                )
                if endpoint_denial is not None:
                    await self._emit_policy_denial_in_tx(
                        db,
                        workspace_id=ws_id,
                        actor_type="service",
                        actor_id="z2.inference",
                        action="inference.chat.complete",
                        target=f"model:{target_model}",
                        reason_code=endpoint_denial,
                        correlation_id=corr_id,
                        client_ip=None,
                        now=ref_now,
                        repository_id=request.repository_id,
                        session_id=request.repair_id,
                    )
                    pre_exc = ForbiddenError(
                        code="meta_endpoint_not_allowlisted",
                        detail="Configured inference endpoint is not allowlisted.",
                    )

            if pre_exc is None:
                eff_consent_id = request.consent_id or cfg_row.active_inference_consent_id
                verified_consent, consent_err = await self._verify_active_inference_consent_in_tx(
                    db,
                    workspace_id=ws_id,
                    consent_id=eff_consent_id,
                    endpoint_base_url=endpoint_url,
                    repository_id=request.repository_id,
                )
                if consent_err is not None or verified_consent is None:
                    await self._emit_policy_denial_in_tx(
                        db,
                        workspace_id=ws_id,
                        actor_type="service",
                        actor_id="z2.inference",
                        action="inference.chat.complete",
                        target=f"model:{target_model}",
                        reason_code=consent_err or "inference_consent_missing",
                        correlation_id=corr_id,
                        client_ip=None,
                        now=ref_now,
                        repository_id=request.repository_id,
                        session_id=request.repair_id,
                    )
                    pre_exc = ForbiddenError(
                        code="inference_consent_required",
                        detail=(
                            f"Active outbound inference consent is required before sending "
                            f"context to Meta Model API ({consent_err})."
                        ),
                    )
                else:
                    verified_consent_id = verified_consent.id

            if pre_exc is None and target_model == ESCALATION_META_MODEL_ID:
                snapshots = await self._latest_snapshots_in_tx(db, workspace_id=ws_id)
                wonder_snap = snapshots.get(ESCALATION_META_MODEL_ID)
                if wonder_snap is None or wonder_snap.status != "available":
                    pre_exc = ForbiddenError(
                        code="model_not_available",
                        detail=(
                            "Model 'muse-wonder-1.0' has not been verified available on this "
                            "account; silent fallback is disabled."
                        ),
                    )

            if pre_exc is None:
                if cfg_row.credential_secret_ref is None:
                    pre_exc = ConflictError(
                        code="meta_api_key_not_configured",
                        detail="Meta Model API key is not configured for this workspace.",
                    )
                else:
                    raw_key = await self._secrets.resolve_secret_bytes(
                        db,
                        secret_ref=cfg_row.credential_secret_ref,
                        capability=INFERENCE_SECRET_CAPABILITY,
                        workspace_id=ws_id,
                    )
                    api_key_str = raw_key.decode("utf-8").strip()

            if pre_exc is None:
                pricing_map = self._parse_pricing_map(cfg_row.pricing_json)
                pricing_rate = pricing_map.get(target_model)
                if pricing_rate is None or not pricing_rate.configured:
                    pre_exc = ConflictError(
                        code="unknown_model_pricing",
                        detail=(
                            f"Audited upper-bound token pricing is not configured for model "
                            f"'{target_model}'; cost-governed execution is blocked."
                        ),
                    )

            if pre_exc is None:
                budget_policy = self._effective_budget_policy(cfg_row.budget_policy_json)
                alert_pct = budget_policy.alert_threshold_percent
                daily_acct = await self._budgets.ensure_workspace_daily_account_in_tx(
                    db,
                    workspace_id=ws_id,
                    policy=budget_policy,
                    now=ref_now,
                )
                if request.session_budget_account_id is not None:
                    primary_acct_id = request.session_budget_account_id
                    secondary_acct_id = daily_acct.id
                else:
                    primary_acct_id = daily_acct.id
                    secondary_acct_id = None

        if pre_exc is not None:
            raise pre_exc
        assert pricing_rate is not None

        if cancel_check is not None and cancel_check():
            raise ConflictError(
                code="inference_cancelled",
                detail="Repair session was cancelled before reserving Meta budget.",
            )

        wire_payload: dict[str, Any] = {
            "model": target_model,
            "messages": scrubbed_messages,
            "max_completion_tokens": request.max_completion_tokens,
        }
        if request.reasoning_effort is not None:
            wire_payload["reasoning_effort"] = request.reasoning_effort
        if serialized_tools:
            wire_payload["tools"] = serialized_tools
        if serialized_format is not None:
            wire_payload["response_format"] = serialized_format

        prompt_digest = sha256_canonical_json(wire_payload)
        est_in = estimate_worst_case_input_tokens(
            json.dumps(wire_payload, separators=(",", ":")),
            item_count=len(scrubbed_messages) + len(serialized_tools),
        )

        reservation = await self._budgets.reserve_for_call(
            workspace_id=ws_id,
            primary_account_id=primary_acct_id,
            secondary_account_id=secondary_acct_id,
            consent_id=verified_consent_id,
            model_id=target_model,
            pricing=pricing_rate,
            estimated_input_tokens=est_in,
            max_output_tokens=request.max_completion_tokens,
            prompt_redacted_digest=prompt_digest,
            correlation_id=corr_id,
            repository_id=request.repository_id,
            repair_id=request.repair_id,
            alert_threshold_percent=alert_pct,
            now=ref_now,
        )

        if cancel_check is not None and cancel_check():
            await self._budgets.release_unexecuted_reservation(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code="cancelled_before_dispatch",
                now=self._iam.now(),
            )
            raise ConflictError(
                code="inference_cancelled",
                detail="Repair session was cancelled before opening Meta HTTP connection.",
            )

        try:
            http_resp, _ = await self._send_meta_http_post(
                endpoint_base_url=endpoint_url,
                api_key_str=api_key_str,
                wire_payload=wire_payload,
                correlation_id=corr_id,
            )
        except EgressBlockedError as exc:
            await self._budgets.release_unexecuted_reservation(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code=exc.code,
                now=self._iam.now(),
            )
            raise
        except httpx.ConnectError as exc:
            err_now = self._iam.now()
            await self._budgets.release_unexecuted_reservation(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code="meta_connect_failed",
                now=err_now,
            )
            await self._record_workspace_suspension(
                workspace_id=ws_id,
                reason="model_unavailable",
                detail="Meta Model API connection failed.",
                retry_after_seconds=DEFAULT_RATE_LIMIT_RETRY_SECONDS,
                now=err_now,
            )
            raise _dep_unavailable(
                code="model_unavailable",
                detail="Meta Model API connection failed; repair inference suspended.",
                retry_after_seconds=DEFAULT_RATE_LIMIT_RETRY_SECONDS,
            ) from exc
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            err_now = self._iam.now()
            await self._budgets.mark_unknown_outcome(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code="meta_upstream_timeout",
                provider_request_id=None,
                now=err_now,
            )
            await self._record_workspace_suspension(
                workspace_id=ws_id,
                reason="model_unavailable",
                detail="Meta Model API timed out after dispatch; unknown spend retained.",
                retry_after_seconds=DEFAULT_RATE_LIMIT_RETRY_SECONDS,
                now=err_now,
            )
            raise _dep_unavailable(
                code="model_unavailable",
                detail=(
                    "Meta Model API timed out after dispatch; worst-case reservation retained "
                    "as unknown outcome (SEC-033)."
                ),
                retry_after_seconds=DEFAULT_RATE_LIMIT_RETRY_SECONDS,
            ) from exc

        done_now = self._iam.now()
        raw_req_id = http_resp.headers.get("x-request-id") or http_resp.headers.get(
            "meta-request-id"
        )
        scrubbed_req_id = self._redactor.redact_text(raw_req_id)[:256] if raw_req_id else None

        if http_resp.status_code == 429 or http_resp.status_code >= 500:
            retry_secs = _parse_retry_after_seconds(
                http_resp.headers,
                default_seconds=DEFAULT_RATE_LIMIT_RETRY_SECONDS,
            )
            err_code = (
                "meta_rate_limited" if http_resp.status_code == 429 else "meta_upstream_outage"
            )
            await self._budgets.release_unexecuted_reservation(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code=err_code,
                provider_request_id=scrubbed_req_id,
                now=done_now,
            )
            await self._record_workspace_suspension(
                workspace_id=ws_id,
                reason="model_unavailable",
                detail=f"Meta Model API returned HTTP {http_resp.status_code} ({err_code}).",
                retry_after_seconds=retry_secs,
                now=done_now,
            )
            if http_resp.status_code == 429:
                raise RateLimitedError(
                    code="model_unavailable",
                    detail="Meta Model API rate limit reached; suspended as model_unavailable.",
                    retry_after_seconds=retry_secs,
                )
            raise _dep_unavailable(
                code="model_unavailable",
                detail=(
                    f"Meta Model API returned HTTP {http_resp.status_code}; "
                    "suspended as model_unavailable."
                ),
                retry_after_seconds=retry_secs,
            )

        if http_resp.status_code == 401:
            await self._budgets.release_unexecuted_reservation(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code="meta_auth_failed",
                usage_status="failed",
                provider_request_id=scrubbed_req_id,
                now=done_now,
            )
            await self._record_workspace_suspension(
                workspace_id=ws_id,
                reason="model_unavailable",
                detail="Meta Model API rejected configured API key (HTTP 401).",
                retry_after_seconds=None,
                now=done_now,
            )
            raise ForbiddenError(
                code="meta_auth_failed",
                detail="Meta Model API rejected the configured API key (HTTP 401).",
            )

        if http_resp.status_code in (403, 404):
            await self._budgets.release_unexecuted_reservation(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code="model_not_entitled",
                provider_request_id=scrubbed_req_id,
                now=done_now,
            )
            raise ForbiddenError(
                code="model_not_available",
                detail=(
                    f"Model '{target_model}' was rejected by Meta Model API "
                    f"(HTTP {http_resp.status_code}); silent fallback is disabled."
                ),
            )

        if http_resp.status_code != 200:
            await self._budgets.release_unexecuted_reservation(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code=f"meta_http_{http_resp.status_code}",
                provider_request_id=scrubbed_req_id,
                now=done_now,
            )
            raise DependencyUnavailableError(
                code="model_unavailable",
                detail=f"Unexpected HTTP {http_resp.status_code} from Meta Model API.",
            )

        scrubbed_body, usage_stats, provider_req_id, response_digest = self._parse_200_chat_body(
            http_resp,
            fallback_request_id=scrubbed_req_id,
        )
        if usage_stats is None:
            await self._budgets.mark_unknown_outcome(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                reason_code="missing_usage_envelope",
                provider_request_id=provider_req_id,
                now=done_now,
            )
            raise DependencyUnavailableError(
                code="model_unavailable",
                detail=(
                    "Meta Model API HTTP 200 response omitted usage accounting; worst-case "
                    "reservation retained as unknown outcome."
                ),
            )

        choices = scrubbed_body.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], Mapping):
            await self._budgets.settle_reservation(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                pricing=pricing_rate,
                actual_input_tokens=usage_stats.prompt_tokens,
                actual_output_tokens=usage_stats.completion_tokens,
                provider_request_id=provider_req_id,
                response_redacted_digest=response_digest,
                alert_threshold_percent=alert_pct,
                now=done_now,
            )
            raise UnprocessableEntityError(
                code="malformed_meta_response",
                detail="Meta Model API response did not contain any choices.",
            )
        choice0 = choices[0]
        finish_reason = str(choice0.get("finish_reason") or "unknown")[:120]
        msg_obj = choice0.get("message")
        if not isinstance(msg_obj, Mapping):
            await self._budgets.settle_reservation(
                workspace_id=ws_id,
                reservation_id=reservation.id,
                pricing=pricing_rate,
                actual_input_tokens=usage_stats.prompt_tokens,
                actual_output_tokens=usage_stats.completion_tokens,
                provider_request_id=provider_req_id,
                response_redacted_digest=response_digest,
                alert_threshold_percent=alert_pct,
                now=done_now,
            )
            raise UnprocessableEntityError(
                code="malformed_meta_response",
                detail="Meta Model API choice omitted assistant message object.",
            )

        raw_content = msg_obj.get("content")
        assistant_content = str(raw_content) if isinstance(raw_content, str) else None

        parsed_tool_calls: list[MetaToolCall] = []
        tc_digests: list[str] = []
        raw_tcs = msg_obj.get("tool_calls")
        if isinstance(raw_tcs, list):
            for idx, raw_tc in enumerate(raw_tcs):
                if not isinstance(raw_tc, Mapping):
                    continue
                fn_obj = raw_tc.get("function")
                if not isinstance(fn_obj, Mapping):
                    continue
                fn_name = fn_obj.get("name")
                fn_args = fn_obj.get("arguments")
                if not isinstance(fn_name, str) or not fn_name.strip():
                    continue
                tc_id = str(raw_tc.get("id") or f"call_{idx}")[:256]
                arg_str = (
                    str(fn_args)[:4096]
                    if isinstance(fn_args, str)
                    else json.dumps(fn_args, separators=(",", ":"))[:4096]
                )
                tc_dto = MetaToolCall(
                    id=tc_id,
                    type="function",
                    function=MetaToolFunctionCallPayload(
                        name=fn_name.strip()[:120],
                        arguments=arg_str,
                    ),
                )
                parsed_tool_calls.append(tc_dto)
                tc_digests.append(sha256_canonical_json(tc_dto.model_dump(mode="json")))

        settlement = await self._budgets.settle_reservation(
            workspace_id=ws_id,
            reservation_id=reservation.id,
            pricing=pricing_rate,
            actual_input_tokens=usage_stats.prompt_tokens,
            actual_output_tokens=usage_stats.completion_tokens,
            provider_request_id=provider_req_id,
            response_redacted_digest=response_digest,
            tool_call_digests=tc_digests,
            alert_threshold_percent=alert_pct,
            now=done_now,
        )
        late_flag = bool(
            settlement.reservation.late_after_cancel
            or (cancel_check is not None and cancel_check())
        )

        structured_output: dict[str, Any] | None = None
        if (
            request.response_format is not None
            and request.response_format.type == "json_schema"
            and not parsed_tool_calls
        ):
            if assistant_content is None:
                raise UnprocessableEntityError(
                    code="malformed_model_structured_output",
                    detail="Model response omitted structured JSON content.",
                )
            try:
                loaded = json.loads(assistant_content)
            except ValueError as exc:
                raise UnprocessableEntityError(
                    code="malformed_model_structured_output",
                    detail="Model structured output was not valid JSON.",
                ) from exc
            if not isinstance(loaded, dict):
                raise UnprocessableEntityError(
                    code="malformed_model_structured_output",
                    detail="Model structured output root must be a JSON object.",
                )
            if request.response_format.json_schema is not None:
                schema_def = request.response_format.json_schema.schema_def
                req_keys = schema_def.get("required")
                if isinstance(req_keys, list):
                    missing = [str(k) for k in req_keys if str(k) not in loaded]
                    if missing:
                        raise UnprocessableEntityError(
                            code="malformed_model_structured_output",
                            detail=(
                                f"Model structured output omitted required keys: "
                                f"{', '.join(missing[:10])}."
                            ),
                        )
                if schema_def.get("additionalProperties") is False and isinstance(
                    schema_def.get("properties"), Mapping
                ):
                    allowed_props = {str(k) for k in schema_def["properties"]}
                    extras = [k for k in loaded if k not in allowed_props]
                    if extras:
                        raise UnprocessableEntityError(
                            code="malformed_model_structured_output",
                            detail=(
                                f"Model structured output included forbidden extra keys: "
                                f"{', '.join(extras[:10])}."
                            ),
                        )
            structured_output = loaded

        eff_req_id = provider_req_id or f"meta_req_{reservation.id}"
        usage_record = settlement.usage_record
        provenance = ModelToolProvenance(
            model_id=target_model,
            adapter_version=META_INFERENCE_ADAPTER_VERSION,
            provider_request_id=eff_req_id,
            redacted_context_hashes=[prompt_digest],
            tool_call_digests=tc_digests,
            usage_record_id=usage_record.id,
        )

        return MetaChatCompletionResult(
            provider_request_id=eff_req_id,
            model_id=target_model,
            finish_reason=finish_reason,
            content=assistant_content,
            parsed_structured_output=structured_output,
            tool_calls=parsed_tool_calls,
            usage=usage_stats,
            usage_record=usage_record,
            reservation=settlement.reservation,
            provenance=provenance,
            late_after_cancel=late_flag,
        )

    def build_setup_probe(
        self,
        *,
        fallback_probe: SetupStepProbeCallable | None = None,
    ) -> SetupStepProbeCallable:
        """Build the `S-18` `model_consent` readiness probe for `SetupStepRegistry`."""

        async def _probe(
            phase: SetupWizardPhase,
            draft: Mapping[str, Any],
        ) -> SetupStepProbeResult:
            raw_primary = str(draft.get("primary_model") or PRIMARY_META_MODEL_ID).strip()
            if raw_primary not in ALLOWED_META_MODEL_IDS:
                if fallback_probe is not None:
                    return await fallback_probe(phase, draft)
                return SetupStepProbeResult(
                    probe_status="failed",
                    detail=(
                        f"Primary model '{raw_primary}' is not a supported Meta Muse model "
                        f"({sorted(ALLOWED_META_MODEL_IDS)})."
                    ),
                    blocking_reasons=("unsupported_meta_model",),
                )

            raw_budget = Decimal(str(draft.get("max_cost_per_session_amount") or "0"))
            if raw_budget <= Decimal("0"):
                return SetupStepProbeResult(
                    probe_status="needs_admin",
                    detail="Per-session model cost cap must be greater than $0.00.",
                    blocking_reasons=("model_budget_zero",),
                )

            draft_ws_id = str(draft.get("workspace_id") or "").strip()
            async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
                stmt = select(WorkspaceModelConfigModel).order_by(
                    WorkspaceModelConfigModel.updated_at.desc()
                )
                if draft_ws_id:
                    stmt = stmt.where(WorkspaceModelConfigModel.workspace_id == draft_ws_id)
                cfg_rows = list((await db.scalars(stmt)).all())
                if not cfg_rows:
                    return SetupStepProbeResult(
                        probe_status="not_configured",
                        detail=(
                            "Configure Meta API key, audited pricing rates, and run a consented "
                            "capability probe in Workspace Models."
                        ),
                        blocking_reasons=("meta_models_not_configured",),
                    )
                ws_id = cfg_rows[0].workspace_id

            async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as ws_db:
                target_cfg = await ws_db.scalar(
                    select(WorkspaceModelConfigModel).where(
                        WorkspaceModelConfigModel.workspace_id == ws_id
                    )
                )
                if target_cfg is None:
                    return SetupStepProbeResult(
                        probe_status="not_configured",
                        detail=(
                            "Configure Meta API key, audited pricing rates, and run a consented "
                            "capability probe in Workspace Models."
                        ),
                        blocking_reasons=("meta_models_not_configured",),
                    )
                presence = await self._secret_presence_in_tx(
                    ws_db,
                    workspace_id=ws_id,
                    secret_ref=target_cfg.credential_secret_ref,
                    fallback_version=target_cfg.credential_secret_version,
                )
                if not presence.configured:
                    return SetupStepProbeResult(
                        probe_status="needs_admin",
                        detail="Meta Model API key is missing or revoked in Workspace Models.",
                        blocking_reasons=("meta_api_key_missing",),
                    )

                eff_consent_id = (
                    str(draft.get("inference_consent_id") or "")
                    or target_cfg.active_inference_consent_id
                )
                _, consent_err = await self._verify_active_inference_consent_in_tx(
                    ws_db,
                    workspace_id=ws_id,
                    consent_id=eff_consent_id,
                    endpoint_base_url=target_cfg.endpoint_base_url,
                )
                if consent_err is not None:
                    return SetupStepProbeResult(
                        probe_status="needs_admin",
                        detail=f"Outbound inference consent is required ({consent_err}).",
                        blocking_reasons=(consent_err,),
                    )

                pricing_map = self._parse_pricing_map(target_cfg.pricing_json)
                spark_pricing = pricing_map.get(PRIMARY_META_MODEL_ID)
                if spark_pricing is None or not spark_pricing.configured:
                    return SetupStepProbeResult(
                        probe_status="needs_admin",
                        detail=(
                            "Configure audited upper-bound token pricing for muse-spark-1.3 "
                            "before enabling repair."
                        ),
                        blocking_reasons=("unknown_model_pricing",),
                    )

                if target_cfg.suspension_reason is not None:
                    return SetupStepProbeResult(
                        probe_status="failed",
                        detail=(
                            f"Workspace inference is suspended "
                            f"(reason='{target_cfg.suspension_reason}')."
                        ),
                        blocking_reasons=(target_cfg.suspension_reason,),
                    )

                snapshots = await self._latest_snapshots_in_tx(ws_db, workspace_id=ws_id)
                spark_snap = snapshots.get(PRIMARY_META_MODEL_ID)
                if spark_snap is None or spark_snap.status == "not_probed":
                    return SetupStepProbeResult(
                        probe_status="needs_admin",
                        detail=(
                            "Run a consented capability probe for muse-spark-1.3 in Workspace "
                            "Models to verify account access."
                        ),
                        blocking_reasons=("meta_capability_probe_required",),
                    )
                if spark_snap.status != "available":
                    err_status: PrerequisiteStatus = (
                        "failed"
                        if spark_snap.status in ("unavailable", "degraded")
                        else "needs_admin"
                    )
                    return SetupStepProbeResult(
                        probe_status=err_status,
                        detail=spark_snap.status_detail
                        or f"Muse Spark 1.3 probe status is '{spark_snap.status}'.",
                        blocking_reasons=(f"meta_spark_{spark_snap.status}",),
                    )

                return SetupStepProbeResult(
                    probe_status="passed",
                    detail=(
                        f"Meta Muse primary model '{PRIMARY_META_MODEL_ID}' capability probe, "
                        f"consent, and pricing ({spark_pricing.pricing_revision}) verified."
                    ),
                )

        return _probe

    def register_setup_probe(self, registry: SetupStepRegistry) -> None:
        """Register the concrete `model_consent` probe in `SetupStepRegistry`."""
        existing = registry.get_probe("model_consent")
        registry.register_probe(
            "model_consent",
            self.build_setup_probe(fallback_probe=existing),
        )


__all__ = [
    "DEFAULT_RATE_LIMIT_RETRY_SECONDS",
    "MAX_JSON_SCHEMA_DEPTH",
    "MAX_PROBE_OUTPUT_TOKENS",
    "MetaMuseInferenceService",
]
