"""Canonical request, response and frame contracts for optional W-10 extensions."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator

from py_contracts.integrations import ProviderKind
from py_contracts.primitives import (
    BoundedName,
    InternalId,
    StrictContractModel,
    UtcTimestamp,
)


class RelayFrameV1(StrictContractModel):
    """Signed customer-relay envelope; raw provider bytes remain untouched until verification."""

    schema_version: Literal[1] = 1
    relay_seq: StrictInt = Field(ge=1)
    workspace_id: InternalId
    provider_connection_id: InternalId
    provider: ProviderKind
    raw_headers: list[tuple[StrictStr, StrictStr]] = Field(min_length=1, max_length=128)
    raw_body_b64: StrictStr = Field(min_length=1, max_length=1_500_000)
    signature_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


class RelaySubscriptionUpsertRequest(StrictContractModel):
    """Opt-in connection to a registered customer-operated relay and its frame key."""

    provider_connection_id: InternalId
    endpoint_registration_id: InternalId
    consent_id: InternalId
    relay_hmac_secret: StrictStr | None = Field(default=None, min_length=32, max_length=512)
    client_certificate_pem: StrictStr | None = Field(default=None, min_length=64, max_length=32_768)
    client_private_key_pem: StrictStr | None = Field(default=None, min_length=64, max_length=32_768)
    enabled: StrictBool = False
    expected_version: StrictInt | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _require_complete_credential_rotation(self) -> RelaySubscriptionUpsertRequest:
        supplied = (
            self.relay_hmac_secret is not None,
            self.client_certificate_pem is not None,
            self.client_private_key_pem is not None,
        )
        if any(supplied) and not all(supplied):
            raise ValueError(
                "Relay HMAC secret and both mTLS credentials must be supplied together."
            )
        return self


class RelaySubscriptionResponse(StrictContractModel):
    """Masked relay subscription status; credential material is never returned."""

    id: InternalId
    version: StrictInt = Field(ge=1)
    workspace_id: InternalId
    provider_connection_id: InternalId
    endpoint_registration_id: InternalId
    consent_id: InternalId
    enabled: StrictBool
    status: Literal["disabled", "ready", "degraded", "gap_detected"]
    last_relay_seq: StrictInt = Field(ge=0)
    last_received_at: UtcTimestamp | None = None
    status_detail: BoundedName | None = None


class RelayPullResponse(StrictContractModel):
    """One bounded relay receive result, useful for worker scheduling and health probes."""

    subscription_id: InternalId
    status: Literal["received", "idle", "gap_detected", "disabled"]
    relay_seq: StrictInt | None = Field(default=None, ge=1)
    polling_required: StrictBool = False


class ModelFallbackPolicyRequest(StrictContractModel):
    """Repository-scoped, owner-consented same-vendor model fallback policy."""

    primary_model_profile_id: InternalId
    secondary_model_profile_id: InternalId
    consent_id: InternalId
    enabled: StrictBool = False
    expected_version: StrictInt | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _require_distinct_models(self) -> ModelFallbackPolicyRequest:
        if self.primary_model_profile_id == self.secondary_model_profile_id:
            raise ValueError("Fallback model profile must differ from the primary profile.")
        return self


class ModelFallbackPolicyResponse(StrictContractModel):
    """Model fallback state without secret or raw consent content."""

    id: InternalId
    version: StrictInt = Field(ge=1)
    workspace_id: InternalId
    repository_id: InternalId
    primary_model_profile_id: InternalId
    secondary_model_profile_id: InternalId
    consent_id: InternalId
    enabled: StrictBool
    last_fallback_at: UtcTimestamp | None = None
    last_fallback_reason: Literal["429", "503", "capability_unavailable"] | None = None
