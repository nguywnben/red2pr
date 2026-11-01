"""U28 OIDC security primitives tests."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from red2pr_control.extensions.registry import list_capabilities
from red2pr_control.iam.oidc import create_pkce_pair, create_state_nonce, validate_id_token


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _token(
    *,
    nonce: str,
    issuer: str = "https://idp.test",
    audience: str = "red2pr",
    exp: int = 2_000_000_000,
    email_verified: bool = True,
):
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_numbers()
    header = {"alg": "ES256", "kid": "key-1"}
    claims = {
        "iss": issuer,
        "aud": audience,
        "exp": exp,
        "iat": 1,
        "nonce": nonce,
        "sub": "subject-1",
        "email": "person@example.test",
        "email_verified": email_verified,
    }
    head = _b64(json.dumps(header, separators=(",", ":")).encode())
    body = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signature_der = key.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature_der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    jwks = {
        "keys": [
            {
                "kid": "key-1",
                "kty": "EC",
                "crv": "P-256",
                "x": _b64(public.x.to_bytes(32, "big")),
                "y": _b64(public.y.to_bytes(32, "big")),
                "use": "sig",
                "alg": "ES256",
            }
        ]
    }
    return f"{head}.{body}.{_b64(signature)}", jwks


def test_pkce_pair_uses_s256_and_independent_state_nonce() -> None:
    verifier, challenge = create_pkce_pair()
    assert len(verifier) >= 43
    assert challenge == _b64(hashlib.sha256(verifier.encode()).digest())
    state, nonce = create_state_nonce()
    assert len(state) >= 32 and len(nonce) >= 32 and state != nonce


def test_capability_inventory_is_stable_and_closed_by_default() -> None:
    caps = list_capabilities()
    assert [(item.id, item.status) for item in caps] == [
        ("iam-03-oidc", "not_configured"),
        ("src-05-relay", "disabled"),
        ("agt-04-model-fallback", "disabled"),
        ("san-04-fleet-sandbox", "unsupported"),
        ("ext-02-mcp", "disabled"),
    ]


def test_id_token_signature_and_claims_are_verified() -> None:
    token, jwks = _token(nonce="nonce-1")
    claims = validate_id_token(
        token, jwks=jwks, issuer="https://idp.test", audience="red2pr", nonce="nonce-1", now=1
    )
    assert claims["sub"] == "subject-1"


@pytest.mark.parametrize(
    ("issuer", "audience", "nonce"),
    [
        ("https://evil.test", "red2pr", "nonce-1"),
        ("https://idp.test", "other", "nonce-1"),
        ("https://idp.test", "red2pr", "replay"),
    ],
)
def test_id_token_wrong_issuer_audience_or_nonce_is_rejected(issuer, audience, nonce) -> None:
    token, jwks = _token(nonce="nonce-1")
    with pytest.raises(ValueError):
        validate_id_token(token, jwks=jwks, issuer=issuer, audience=audience, nonce=nonce, now=1)


def test_id_token_rejects_tampered_signature() -> None:
    token, jwks = _token(nonce="nonce-1")
    parts = token.split(".")
    parts[2] = _b64(b"x" * 64)
    with pytest.raises(ValueError):
        validate_id_token(
            ".".join(parts),
            jwks=jwks,
            issuer="https://idp.test",
            audience="red2pr",
            nonce="nonce-1",
            now=1,
        )


@pytest.mark.parametrize(
    ("now", "exp", "email_verified"),
    [(2_000_000_000, 2_000_000_000, True), (1, 2_000_000_000, False)],
)
def test_id_token_rejects_expired_or_unverified_email(
    now: int, exp: int, email_verified: bool
) -> None:
    token, jwks = _token(nonce="nonce-1", exp=exp, email_verified=email_verified)
    with pytest.raises(ValueError):
        validate_id_token(
            token,
            jwks=jwks,
            issuer="https://idp.test",
            audience="red2pr",
            nonce="nonce-1",
            now=now,
        )
