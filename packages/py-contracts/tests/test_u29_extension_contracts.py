from __future__ import annotations

import pytest
from pydantic import ValidationError

from py_contracts.extensions import (
    ModelFallbackPolicyRequest,
    RelayFrameV1,
    RelaySubscriptionUpsertRequest,
)

WORKSPACE_ID = "0196ed16-0000-7000-8000-000000000301"
CONNECTION_ID = "0196ed16-0000-7000-8000-000000000401"
CONSENT_ID = "0196ed16-0000-7000-8000-000000000601"


def test_relay_frame_contract_preserves_raw_headers_and_encoded_body() -> None:
    frame = RelayFrameV1(
        relay_seq=1,
        workspace_id=WORKSPACE_ID,
        provider_connection_id=CONNECTION_ID,
        provider="github",
        raw_headers=[("X-Hub-Signature-256", "sha256=" + "a" * 64), ("X-GitHub-Delivery", "d1")],
        raw_body_b64="eyJ4IjoxfQ==",
        signature_sha256="b" * 64,
    )

    assert frame.raw_headers[0][0] == "X-Hub-Signature-256"
    assert frame.raw_body_b64 == "eyJ4IjoxfQ=="


@pytest.mark.parametrize(
    "changes",
    [
        {"relay_seq": 0},
        {"provider": "unknown"},
        {"signature_sha256": "not-hex"},
        {"raw_headers": []},
        {"unexpected": True},
    ],
)
def test_relay_frame_contract_rejects_invalid_or_extra_fields(changes: dict[str, object]) -> None:
    payload: dict[str, object] = {
        "relay_seq": 1,
        "workspace_id": WORKSPACE_ID,
        "provider_connection_id": CONNECTION_ID,
        "provider": "github",
        "raw_headers": [("X-Hub-Signature-256", "sha256=" + "a" * 64)],
        "raw_body_b64": "e30=",
        "signature_sha256": "b" * 64,
    }
    payload.update(changes)

    with pytest.raises(ValidationError):
        RelayFrameV1.model_validate(payload)


def test_fallback_policy_contract_rejects_same_or_invalid_model_profile() -> None:
    with pytest.raises(ValidationError):
        ModelFallbackPolicyRequest(
            primary_model_profile_id="0196ed16-0000-7000-8000-000000000701",
            secondary_model_profile_id="0196ed16-0000-7000-8000-000000000701",
            consent_id=CONSENT_ID,
        )

    with pytest.raises(ValidationError):
        ModelFallbackPolicyRequest(
            primary_model_profile_id="not-a-uuid",  # type: ignore[arg-type]
            secondary_model_profile_id="0196ed16-0000-7000-8000-000000000702",
            consent_id=CONSENT_ID,
        )


def test_existing_relay_can_be_disabled_without_rotating_write_only_credentials() -> None:
    payload = RelaySubscriptionUpsertRequest(
        provider_connection_id=CONNECTION_ID,
        endpoint_registration_id="0196ed16-0000-7000-8000-000000000501",
        consent_id=CONSENT_ID,
        enabled=False,
        expected_version=2,
    )
    assert payload.relay_hmac_secret is None

    with pytest.raises(ValidationError):
        RelaySubscriptionUpsertRequest(
            provider_connection_id=CONNECTION_ID,
            endpoint_registration_id="0196ed16-0000-7000-8000-000000000501",
            consent_id=CONSENT_ID,
            relay_hmac_secret="x" * 40,
            enabled=False,
        )
