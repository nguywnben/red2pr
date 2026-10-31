"""Canonical wire primitives and base envelopes (S-01..S-05).

Implements the normative wire rules from docs/36_CANONICAL_CONTRACTS.md:
- S-01: UUIDv7 internal IDs, non-coerced opaque provider IDs, RFC3339 UTC timestamps,
  lowercase SHA-256 hex digests, positive integer versions, exact Decimal Money (no float),
  nonnegative DurationMs, and bounded string scalars.
- S-02: InstanceResourceBase and WorkspaceResourceBase with extra='forbid'.
- S-03: Problem and ProblemFieldError (application/problem+json).
- S-04: Cursor-paginated Page<T> and PageParams (limit 1..100, default 25).
- S-05: ActionReceipt and UUIDv7 Idempotency-Key window validation.
"""

from __future__ import annotations

import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    StrictInt,
    StrictStr,
    StringConstraints,
)

MAX_JSON_BODY_BYTES: int = 1_048_576  # 1 MiB canonical JSON body ceiling (S-01)

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


def new_uuid7(*, now: datetime | None = None) -> str:
    """Generate a CSPRNG-backed RFC 9562 UUIDv7 lowercase canonical string."""
    ts = now if now is not None else datetime.now(tz=UTC)
    if ts.tzinfo is None or ts.utcoffset() is None:
        raise ValueError("UUIDv7 timestamp must be timezone-aware")
    unix_ts_ms = int(ts.timestamp() * 1000)
    if unix_ts_ms < 0 or unix_ts_ms >= (1 << 48):
        raise ValueError("UUIDv7 timestamp milliseconds out of 48-bit range")

    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)

    uuid_int = (unix_ts_ms << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    return str(uuid.UUID(int=uuid_int))


def parse_uuid7_timestamp_ms(value: str) -> int:
    """Validate an RFC 9562 UUIDv7 string and extract its 48-bit epoch millisecond timestamp."""
    if not isinstance(value, str) or not _UUID_RE.fullmatch(value):
        raise ValueError("invalid_idempotency_key: malformed UUID string")
    parsed = uuid.UUID(value)
    if parsed.version != 7 or parsed.variant != uuid.RFC_4122:
        raise ValueError("invalid_idempotency_key: UUID version 7 required")
    return (parsed.int >> 80) & ((1 << 48) - 1)


def validate_idempotency_key_window(
    key: str,
    *,
    now: datetime | None = None,
    max_age: timedelta = timedelta(days=7),
    max_future_skew: timedelta = timedelta(minutes=5),
) -> int:
    """Validate S-05 first-claim Idempotency-Key UUIDv7 age (<=7d) and skew (<=5m)."""
    ref_now = now if now is not None else datetime.now(tz=UTC)
    if ref_now.tzinfo is None or ref_now.utcoffset() is None:
        raise ValueError("Reference timestamp must be timezone-aware")

    key_ms = parse_uuid7_timestamp_ms(key)
    now_ms = int(ref_now.timestamp() * 1000)
    max_age_ms = int(max_age.total_seconds() * 1000)
    max_skew_ms = int(max_future_skew.total_seconds() * 1000)

    if key_ms - now_ms > max_skew_ms:
        raise ValueError("invalid_idempotency_key: embedded timestamp exceeds future skew limit")
    if now_ms - key_ms > max_age_ms:
        raise ValueError("key_expired: embedded UUIDv7 timestamp is older than claim window")
    return key_ms


def _validate_internal_id(value: Any) -> str:
    if not isinstance(value, str) or not _UUID_RE.fullmatch(value):
        raise ValueError("Internal ID must be a lowercase canonical UUID string")
    return value


def _validate_opaque_provider_id(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Provider ID must be an opaque string without numeric coercion")
    if not value or not value.strip() or len(value) > 256:
        raise ValueError("Provider ID must be a non-empty string up to 256 characters")
    if _CONTROL_CHAR_RE.search(value):
        raise ValueError("Provider ID must not contain control characters")
    return value


def _parse_utc_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamp must include an explicit timezone offset")
        return value.astimezone(UTC)
    if isinstance(value, str):
        candidate = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
        try:
            dt = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise ValueError("Invalid RFC3339 timestamp") from exc
        if dt.tzinfo is None or dt.utcoffset() is None:
            raise ValueError("Timestamp string must include Z or explicit timezone offset")
        return dt.astimezone(UTC)
    raise ValueError("Timestamp must be an RFC3339 string or timezone-aware datetime")


def _serialize_utc_timestamp(value: datetime) -> str:
    utc_dt = value.astimezone(UTC)
    return utc_dt.isoformat().replace("+00:00", "Z")


def _validate_strict_decimal(value: Any) -> Decimal:
    if isinstance(value, (bool, float)):
        raise ValueError("Binary float or boolean is forbidden for Money; use Decimal or string")
    if isinstance(value, Decimal):
        dec = value
    elif isinstance(value, int):
        dec = Decimal(value)
    elif isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            raise ValueError("Empty decimal string")
        try:
            dec = Decimal(stripped)
        except InvalidOperation as exc:
            raise ValueError("Invalid decimal amount string") from exc
    else:
        raise ValueError("Money amount must be Decimal, int, or decimal string")

    if not dec.is_finite():
        raise ValueError("Money amount must be finite")
    if dec < Decimal("0"):
        raise ValueError("Money amount must be nonnegative")
    return dec


def _serialize_decimal(value: Decimal) -> str:
    return format(value, "f")


# S-01 Annotated Wire Scalar Types
InternalId = Annotated[StrictStr, BeforeValidator(_validate_internal_id)]
OpaqueProviderId = Annotated[StrictStr, BeforeValidator(_validate_opaque_provider_id)]
UtcTimestamp = Annotated[
    datetime,
    BeforeValidator(_parse_utc_timestamp),
    PlainSerializer(_serialize_utc_timestamp, return_type=str, when_used="json"),
]
Sha256Digest = Annotated[StrictStr, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
PositiveVersion = Annotated[StrictInt, Field(ge=1)]
DurationMs = Annotated[StrictInt, Field(ge=0)]

BoundedText = Annotated[StrictStr, StringConstraints(max_length=4096)]
BoundedName = Annotated[StrictStr, StringConstraints(min_length=1, max_length=120)]
BoundedReason = Annotated[StrictStr, StringConstraints(min_length=1, max_length=1000)]
BoundedUrl = Annotated[StrictStr, StringConstraints(min_length=1, max_length=2048)]
BoundedSearchQuery = Annotated[StrictStr, StringConstraints(max_length=256)]
CurrencyCode = Annotated[StrictStr, StringConstraints(pattern=r"^[A-Z]{3}$")]
MoneyAmount = Annotated[
    Decimal,
    BeforeValidator(_validate_strict_decimal),
    PlainSerializer(_serialize_decimal, return_type=str, when_used="json"),
]


class StrictContractModel(BaseModel):
    """Base contract model forbidding undeclared properties across all Red2PR DTOs."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Money(StrictContractModel):
    """S-01 exact decimal monetary representation (never binary floating point)."""

    amount: MoneyAmount
    currency: CurrencyCode


# S-02 Resource Base Contracts
class InstanceResourceBase(StrictContractModel):
    """S-02 common fields for instance-scoped resources."""

    id: InternalId
    version: PositiveVersion
    created_at: UtcTimestamp
    updated_at: UtcTimestamp


class WorkspaceResourceBase(InstanceResourceBase):
    """S-02 common fields for workspace- and repository-scoped resources."""

    workspace_id: InternalId
    repository_id: InternalId | None = None


# S-03 Problem+JSON Envelope
class ProblemFieldError(StrictContractModel):
    """S-03 structured per-field validation failure descriptor."""

    field: BoundedName
    code: BoundedName


class Problem(StrictContractModel):
    """S-03 safe RFC 9457 / application/problem+json error envelope."""

    type: BoundedUrl
    title: BoundedName
    status: Annotated[StrictInt, Field(ge=400, le=599)]
    code: BoundedName
    detail: BoundedText
    correlation_id: BoundedName
    errors: list[ProblemFieldError] | None = None


# S-04 Cursor Pagination Envelope
class PageParams(StrictContractModel):
    """S-04 bounded cursor-pagination query parameters."""

    limit: Annotated[StrictInt, Field(ge=1, le=100)] = 25
    cursor: BoundedText | None = None
    q: BoundedSearchQuery | None = None


class Page[TItem](StrictContractModel):
    """S-04 deterministic cursor-paginated response envelope."""

    items: list[TItem]
    next_cursor: BoundedText | None = None
    snapshot_at: UtcTimestamp


# S-05 Asynchronous Action & Idempotency Receipt
ActionState = Literal["accepted", "running", "succeeded", "failed", "unknown"]


class ActionReceipt(StrictContractModel):
    """S-05 durable asynchronous operation receipt."""

    operation_id: InternalId
    resource_id: InternalId
    state: ActionState
    correlation_id: BoundedName
    status_url: BoundedUrl
    result_id: InternalId | None = None
    problem: Problem | None = None
