"""Write-only secret management metadata contracts (U25 / UI-S18)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, StrictBool, StrictInt

from py_contracts.primitives import InternalId, PositiveVersion, StrictContractModel, UtcTimestamp

SecretPurpose = Literal[
    "provider_read",
    "provider_write",
    "webhook_auth",
    "meta_inference",
    "notification_channel",
    "mfa_totp",
    "oidc_client",
    "storage_encryption",
]


class SecretKeyMetadata(StrictContractModel):
    """Safe metadata only; never includes secret references or encrypted values."""

    id: InternalId
    purpose: SecretPurpose
    active_key_version: PositiveVersion
    kek_version: PositiveVersion
    configured: StrictBool
    rotated_at: UtcTimestamp | None = None
    revoked_at: UtcTimestamp | None = None
    created_at: UtcTimestamp
    updated_at: UtcTimestamp


class SecretKeyMetadataPage(StrictContractModel):
    active_kek_version: PositiveVersion
    items: list[SecretKeyMetadata] = Field(max_length=5000)


class SecretKeyRotationResult(StrictContractModel):
    active_kek_version: PositiveVersion
    rotated_count: StrictInt = Field(ge=0, le=100000)
    completed_at: UtcTimestamp
