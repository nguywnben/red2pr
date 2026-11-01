"""OIDC Authorization Code + PKCE primitives and strict ID-token validation (IAM-03)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any, cast
from urllib.parse import parse_qs, quote_plus, urlencode, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, TypeAdapter, ValidationError
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts.iam import NormalizedEmail, WorkspaceRole
from py_contracts.primitives import new_uuid7
from red2pr_control.core.egress import EgressPolicyEngine, EgressSafeHttpClient
from red2pr_control.core.errors import ConflictError, ForbiddenError, UnauthorizedError
from red2pr_control.core.secret_ports import OidcSecretStore
from red2pr_control.db.base import (
    ExtensionCapabilityModel,
    InstanceModel,
    MembershipModel,
    OidcAuthTransactionModel,
    OidcGroupMappingModel,
    OidcIdentityModel,
    OidcMembershipGrantModel,
    OidcProviderModel,
    SessionModel,
    UserModel,
    WorkspaceModel,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.csrf import set_csrf_cookie
from red2pr_control.iam.passwords import hash_password
from red2pr_control.iam.rbac import ADMIN_ONLY_ROLES, authorize_workspace_access
from red2pr_control.iam.sessions import (
    IamService,
    extract_client_ip,
    set_session_cookie,
    summarize_user_agent,
)

_ALLOWED_ALGORITHMS = {"RS256", "ES256"}
_WORKSPACE_ROLES = {"admin", "maintainer", "reviewer", "viewer", "auditor"}
_EMAIL_ADAPTER: TypeAdapter[Any] = TypeAdapter(NormalizedEmail)


def _workspace_role(value: str) -> WorkspaceRole:
    if value not in _WORKSPACE_ROLES:
        raise ValueError("Invalid persisted OIDC workspace role")
    return cast(WorkspaceRole, value)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_pkce_pair() -> tuple[str, str]:
    """Create a 256-bit PKCE verifier and its S256 challenge."""
    verifier = _b64url(secrets.token_bytes(32))
    return verifier, _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def create_state_nonce() -> tuple[str, str]:
    """Create independent, high-entropy OAuth state and OIDC nonce values."""
    return secrets.token_urlsafe(32), secrets.token_urlsafe(32)


def _decode_part(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _json_part(value: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("Duplicate JWT JSON member")
            result[key] = item
        return result

    parsed = json.loads(_decode_part(value), object_pairs_hook=unique_object)
    if not isinstance(parsed, dict):
        raise ValueError("JWT component must be an object")
    return parsed


def validate_id_token(
    token: str,
    *,
    jwks: Mapping[str, Any],
    issuer: str,
    audience: str,
    nonce: str,
    now: int | None = None,
) -> dict[str, Any]:
    """Verify the JWS and OIDC identity claims; reject unsupported key/algorithm modes."""
    parts = token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise ValueError("Malformed ID token")
    header = _json_part(parts[0])
    claims = _json_part(parts[1])
    algorithm = header.get("alg")
    kid = header.get("kid")
    if (
        algorithm not in _ALLOWED_ALGORITHMS
        or not isinstance(kid, str)
        or set(header) - {"alg", "kid", "typ"}
        or header.get("typ", "JWT") != "JWT"
    ):
        raise ValueError("Unsupported ID-token signing algorithm or key")
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise ValueError("Invalid JWKS")
    matches = [key for key in keys if isinstance(key, dict) and key.get("kid") == kid]
    if len(matches) != 1:
        raise ValueError("ID-token signing key is unknown or ambiguous")
    key = matches[0]
    key_ops = key.get("key_ops")
    if (
        key.get("use", "sig") != "sig"
        or key.get("alg", algorithm) != algorithm
        or (key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops))
    ):
        raise ValueError("JWKS key is not authorized for this signature")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    signature = _decode_part(parts[2])
    try:
        if algorithm == "RS256":
            if key.get("kty") != "RSA":
                raise ValueError("JWKS key type does not match algorithm")
            public_key = rsa.RSAPublicNumbers(
                int.from_bytes(_decode_part(key["e"]), "big"),
                int.from_bytes(_decode_part(key["n"]), "big"),
            ).public_key()
            if public_key.key_size < 2048:
                raise ValueError("RSA signing key is below the minimum size")
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        else:
            if key.get("kty") != "EC" or key.get("crv") != "P-256":
                raise ValueError("JWKS key type does not match algorithm")
            ec_public_key = ec.EllipticCurvePublicNumbers(
                int.from_bytes(_decode_part(key["x"]), "big"),
                int.from_bytes(_decode_part(key["y"]), "big"),
                ec.SECP256R1(),
            ).public_key()
            if len(signature) != 64:
                raise ValueError("Malformed ES256 signature")
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            ec_public_key.verify(
                encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256())
            )
    except InvalidSignature as exc:
        raise ValueError("Invalid ID-token signature") from exc
    # Signature errors deliberately normalize to the same fail-closed validation error.
    # The caller maps these errors to a generic authentication failure without token data.
    if claims.get("iss") != issuer:
        raise ValueError("Invalid ID-token issuer")
    aud = claims.get("aud")
    if aud != audience:
        raise ValueError("Invalid ID-token audience")
    current_time = int(time.time()) if now is None else now
    exp = claims.get("exp")
    if not isinstance(exp, int) or isinstance(exp, bool) or current_time >= exp:
        raise ValueError("Expired ID token")
    issued_at = claims.get("iat")
    if (
        not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or issued_at > current_time + 60
    ):
        raise ValueError("Invalid ID-token issue time")
    nbf = claims.get("nbf")
    if nbf is not None and (
        not isinstance(nbf, int) or isinstance(nbf, bool) or current_time < nbf
    ):
        raise ValueError("ID token is not yet valid")
    if not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
        raise ValueError("Invalid ID-token nonce")
    if claims.get("email_verified") is not True:
        raise ValueError("OIDC email is not verified")
    if not isinstance(claims.get("sub"), str) or not claims["sub"] or len(claims["sub"]) > 512:
        raise ValueError("OIDC subject is missing")
    return claims


class OidcProviderConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    issuer: str = Field(min_length=8, max_length=1024)
    client_id: str = Field(min_length=1, max_length=256)
    client_secret: SecretStr = Field(min_length=1, max_length=4096)


class OidcProviderSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    issuer: str
    client_id: str
    status: str
    probed_at: datetime | None


class OidcIdentityBindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    subject: str = Field(min_length=1, max_length=512)


class OidcGroupMappingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    provider_id: str = Field(min_length=1, max_length=64)
    group_name: str = Field(min_length=1, max_length=256)
    role: WorkspaceRole
    enabled: bool = True


class OidcGroupMappingSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    provider_id: str
    group_name: str
    role: WorkspaceRole
    enabled: bool


def _oidc_dependencies(request: Request) -> tuple[IamService, OidcSecretStore]:
    iam = getattr(request.app.state, "iam_service", None)
    broker = getattr(request.app.state, "oidc_secret_broker", None)
    if not isinstance(iam, IamService) or not isinstance(broker, OidcSecretStore):
        raise ForbiddenError(
            code="oidc_unconfigured",
            detail="OIDC federation is not configured on this instance.",
        )
    return iam, broker


async def _require_instance_owner(request: Request, iam: IamService) -> Any:
    from red2pr_control.iam.sessions import assert_no_secret_in_query_url

    assert_no_secret_in_query_url(request)
    auth = await iam.authenticate_request(
        request,
        require_csrf=True,
        correlation_id=str(getattr(request.state, "correlation_id", "oidc-admin")),
    )
    if not auth.user.is_instance_owner:
        raise ForbiddenError(
            code="instance_owner_required", detail="Only the instance owner may configure OIDC."
        )
    step_up_age = (
        (iam.now() - auth.session.step_up_at).total_seconds()
        if auth.session.step_up_at is not None
        else None
    )
    if step_up_age is None or step_up_age < 0 or step_up_age > 300:
        raise ForbiddenError(
            code="step_up_required", detail="Fresh local owner TOTP step-up is required."
        )
    return auth


def _http_client(request: Request) -> Any:
    factory = getattr(request.app.state, "oidc_http_client_factory", None)
    if factory is not None:
        return factory()
    return EgressSafeHttpClient(adapter="oidc", policy_engine=EgressPolicyEngine())


def _callback_uri(iam: IamService, provider_id: str) -> str:
    return f"{iam.public_base_url.rstrip('/')}/api/v1/auth/oidc/{provider_id}/callback"


def _pkce_cipher_key(iam: IamService) -> bytes:
    from red2pr_control.iam.mfa import derive_iam_subkey

    return derive_iam_subkey(iam.csrf_signing_key, context=b"red2pr:oidc:pkce-at-rest:v1")


def _browser_binding_cookie_name(state: str) -> str:
    suffix = hashlib.sha256(state.encode("ascii")).hexdigest()[:24]
    return f"red2pr_oidc_{suffix}"


async def _set_oidc_capability(
    db: AsyncSession, *, status: str, reason: str, now: datetime
) -> None:
    row = await db.get(ExtensionCapabilityModel, "iam-03-oidc")
    if row is None:
        db.add(
            ExtensionCapabilityModel(
                id="iam-03-oidc", status=status, reason=reason, probed_at=now, updated_at=now
            )
        )
    else:
        row.status = status
        row.reason = reason
        row.probed_at = now if status == "enabled" else None
        row.updated_at = now


def _seal_verifier(iam: IamService, provider_id: str, verifier: str) -> str:
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(_pkce_cipher_key(iam)).encrypt(
        nonce, verifier.encode("ascii"), provider_id.encode("ascii")
    )
    return _b64url(nonce + encrypted)


def _open_verifier(iam: IamService, provider_id: str, ciphertext: str) -> str:
    raw = _decode_part(ciphertext)
    return (
        AESGCM(_pkce_cipher_key(iam))
        .decrypt(raw[:12], raw[12:], provider_id.encode("ascii"))
        .decode("ascii")
    )


async def _sync_group_memberships(
    db: AsyncSession,
    *,
    provider_id: str,
    user: UserModel,
    claims: Mapping[str, Any],
    now: datetime,
) -> None:
    raw_groups = claims.get("groups", [])
    if (
        not isinstance(raw_groups, list)
        or len(raw_groups) > 500
        or any(not isinstance(group, str) or not group or len(group) > 256 for group in raw_groups)
    ):
        raise UnauthorizedError(
            code="oidc_groups_invalid", detail="OIDC group claims have an invalid shape."
        )
    group_names = set(raw_groups)
    mappings = (
        list(
            await db.scalars(
                select(OidcGroupMappingModel).where(
                    OidcGroupMappingModel.provider_id == provider_id,
                    OidcGroupMappingModel.enabled.is_(True),
                    OidcGroupMappingModel.group_name.in_(group_names),
                )
            )
        )
        if group_names
        else []
    )
    desired: dict[str, OidcGroupMappingModel] = {}
    for mapping in mappings:
        prior = desired.get(mapping.workspace_id)
        if prior is not None and prior.role != mapping.role:
            raise UnauthorizedError(
                code="oidc_group_mapping_conflict",
                detail="OIDC groups map to conflicting roles in one workspace.",
            )
        desired[mapping.workspace_id] = mapping
    # Keep one independently managed admin so IdP group loss can always remove an
    # OIDC-owned admin grant without violating the existing last-admin invariant.
    for workspace_id in sorted(
        workspace_id for workspace_id, mapping in desired.items() if mapping.role == "admin"
    ):
        await db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
            {"lock_key": f"ws_admin:{workspace_id}"},
        )
        if not await _has_local_admin_anchor(db, workspace_id=workspace_id):
            raise ConflictError(
                code="last_admin",
                detail=(
                    "An active locally managed workspace admin is required before OIDC "
                    "can grant admin access."
                ),
            )
    grants = list(
        await db.scalars(
            select(OidcMembershipGrantModel).where(
                OidcMembershipGrantModel.provider_id == provider_id,
                OidcMembershipGrantModel.user_id == user.id,
            )
        )
    )
    grants_by_workspace = {grant.workspace_id: grant for grant in grants}
    changed = False
    for workspace_id, grant in grants_by_workspace.items():
        current_mapping = desired.get(workspace_id)
        membership = await db.scalar(
            select(MembershipModel).where(MembershipModel.id == grant.membership_id)
        )
        if current_mapping is None:
            await db.delete(grant)
            await db.flush()
            if (
                membership is not None
                and membership.role == grant.granted_role
                and membership.version == grant.membership_version
            ):
                await db.delete(membership)
            changed = True
        elif membership is not None:
            if membership.version != grant.membership_version:
                # Any workspace-side edit transfers ownership of the membership locally.
                await db.delete(grant)
            elif membership.role != grant.granted_role and membership.role != current_mapping.role:
                # A workspace admin has taken over this membership; never rewrite it via SSO.
                await db.delete(grant)
            else:
                if membership.role != current_mapping.role:
                    membership.role = current_mapping.role
                    membership.version += 1
                    membership.updated_at = now
                    changed = True
                grant.granted_role = current_mapping.role
                grant.membership_version = membership.version
                grant.group_name = current_mapping.group_name
    for workspace_id, mapping in desired.items():
        if workspace_id in grants_by_workspace:
            continue
        membership = await db.scalar(
            select(MembershipModel).where(
                MembershipModel.workspace_id == workspace_id,
                MembershipModel.user_id == user.id,
            )
        )
        workspace = await db.scalar(
            select(WorkspaceModel).where(
                WorkspaceModel.id == workspace_id, WorkspaceModel.status == "active"
            )
        )
        # Never change or claim a locally managed membership through SSO.
        if membership is not None or workspace is None:
            continue
        membership = MembershipModel(
            id=new_uuid7(now=now),
            workspace_id=workspace_id,
            user_id=user.id,
            role=mapping.role,
            invited_by_user_id=None,
            version=1,
            created_at=now,
            updated_at=now,
        )
        db.add(membership)
        await db.flush()
        db.add(
            OidcMembershipGrantModel(
                id=new_uuid7(now=now),
                workspace_id=workspace_id,
                provider_id=provider_id,
                user_id=user.id,
                membership_id=membership.id,
                group_name=mapping.group_name,
                granted_role=mapping.role,
                membership_version=membership.version,
                created_at=now,
            )
        )
        changed = True
    if changed:
        user.grant_epoch += 1
        user.updated_at = now
        await _revoke_user_sessions(db, user_id=user.id, now=now)


async def _revoke_user_sessions(db: AsyncSession, *, user_id: str, now: datetime) -> None:
    await db.execute(
        update(SessionModel)
        .where(SessionModel.user_id == user_id, SessionModel.revoked_at.is_(None))
        .values(
            revoked_at=now,
            revoke_reason="oidc_membership_changed",
            updated_at=now,
        )
    )


async def _has_local_admin_anchor(db: AsyncSession, *, workspace_id: str) -> bool:
    oidc_admin_grant = (
        select(OidcMembershipGrantModel.id)
        .where(
            OidcMembershipGrantModel.membership_id == MembershipModel.id,
            OidcMembershipGrantModel.membership_version == MembershipModel.version,
            OidcMembershipGrantModel.granted_role == "admin",
        )
        .exists()
    )
    admin_id = await db.scalar(
        select(MembershipModel.id)
        .join(UserModel, UserModel.id == MembershipModel.user_id)
        .where(
            MembershipModel.workspace_id == workspace_id,
            MembershipModel.role == "admin",
            UserModel.status == "active",
            ~oidc_admin_grant,
        )
        .limit(1)
    )
    return admin_id is not None


def build_oidc_router() -> APIRouter:
    """Mount OIDC provider administration and the Authorization Code + PKCE flow."""
    router = APIRouter(prefix="/api/v1", tags=["auth", "system"])

    @router.put("/system/oidc/providers/{provider_id}", response_model=OidcProviderSummary)
    async def configure_provider(
        provider_id: str, body: OidcProviderConfigRequest, request: Request
    ) -> OidcProviderSummary:
        iam, broker = _oidc_dependencies(request)
        owner = await _require_instance_owner(request, iam)
        if not provider_id.isascii() or not provider_id.replace("-", "").isalnum():
            raise ForbiddenError(
                code="invalid_oidc_provider", detail="Invalid provider identifier."
            )
        issuer = body.issuer
        parsed = urlsplit(issuer)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ForbiddenError(
                code="invalid_oidc_issuer",
                detail="OIDC issuer must be an HTTPS origin without credentials.",
            )
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            existing = await db.scalar(
                select(OidcProviderModel)
                .where(OidcProviderModel.id == provider_id)
                .with_for_update()
            )
            metadata = await broker.store_client_secret(
                db,
                plaintext=body.client_secret.get_secret_value().encode(),
                secret_ref=f"oidc-client-{provider_id}-{secrets.token_hex(8)}",
                now=iam.now(),
            )
            if existing is None:
                row = OidcProviderModel(
                    id=provider_id,
                    issuer=issuer,
                    client_id=body.client_id,
                    client_secret_ref=metadata.secret_ref,
                    authorization_endpoint="",
                    token_endpoint="",
                    jwks_uri="",
                    scopes_json=["openid", "email", "profile"],
                    status="not_configured",
                    probed_at=None,
                    created_at=iam.now(),
                    updated_at=iam.now(),
                )
                db.add(row)
            else:
                await broker.revoke_client_secret(
                    db, secret_ref=existing.client_secret_ref, now=iam.now()
                )
                existing.issuer = issuer
                existing.client_id = body.client_id
                existing.client_secret_ref = metadata.secret_ref
                existing.authorization_endpoint = ""
                existing.token_endpoint = ""
                existing.jwks_uri = ""
                existing.status = "not_configured"
                existing.probed_at = None
                existing.updated_at = iam.now()
            from red2pr_control.analytics_audit.audit_chain import append_audit_entry

            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=owner.user.id,
                action="oidc.provider.configure",
                target=f"oidc-provider:{provider_id}",
                decision="allow",
                reason_code="owner_step_up",
                correlation_id=str(getattr(request.state, "correlation_id", "oidc-configure")),
                client_ip=extract_client_ip(request),
                metadata={"issuer": issuer, "client_id": body.client_id},
                occurred_at=iam.now(),
            )
            await _set_oidc_capability(
                db, status="not_configured", reason="provider_probe_required", now=iam.now()
            )
            return OidcProviderSummary(
                id=provider_id,
                issuer=issuer,
                client_id=body.client_id,
                status="not_configured",
                probed_at=None,
            )

    @router.post("/system/oidc/providers/{provider_id}/probe", response_model=OidcProviderSummary)
    async def probe_provider(provider_id: str, request: Request) -> OidcProviderSummary:
        iam, _broker = _oidc_dependencies(request)
        owner = await _require_instance_owner(request, iam)
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            provider = await db.scalar(
                select(OidcProviderModel)
                .where(OidcProviderModel.id == provider_id)
                .with_for_update()
            )
            if provider is None or not provider.client_secret_ref:
                raise ForbiddenError(
                    code="oidc_provider_not_configured", detail="OIDC provider is not configured."
                )
            issuer = provider.issuer
            provider.status = "unavailable"
            provider.probed_at = None
            provider.updated_at = iam.now()
            await _set_oidc_capability(
                db, status="disabled", reason="provider_probe_in_progress", now=iam.now()
            )
        async with _http_client(request) as client:
            try:
                response = await client.request(
                    "GET",
                    f"{issuer.rstrip('/')}/.well-known/openid-configuration",
                    headers={"Accept": "application/json"},
                )
                response.raise_for_status()
                if len(response.content) > 1_048_576:
                    raise ValueError("OIDC discovery document is too large")
                metadata = response.json()
            except Exception as exc:
                raise ForbiddenError(
                    code="oidc_probe_failed", detail="OIDC discovery probe failed."
                ) from exc
        if not isinstance(metadata, dict) or metadata.get("issuer") != issuer:
            raise ForbiddenError(
                code="oidc_issuer_mismatch",
                detail="OIDC discovery issuer did not match configuration.",
            )
        endpoints: dict[str, str] = {}
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            value = metadata.get(key)
            parsed = urlsplit(value) if isinstance(value, str) else None
            if (
                parsed is None
                or not isinstance(value, str)
                or parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
            ):
                raise ForbiddenError(
                    code="oidc_metadata_invalid", detail="OIDC discovery endpoints must use HTTPS."
                )
            endpoints[key] = value
        response_modes = metadata.get("response_modes_supported", ["query"])
        if not isinstance(response_modes, list) or "form_post" not in response_modes:
            raise ForbiddenError(
                code="oidc_metadata_invalid",
                detail="OIDC provider must advertise the form_post response mode.",
            )
        auth_methods = metadata.get(
            "token_endpoint_auth_methods_supported", ["client_secret_basic"]
        )
        if not isinstance(auth_methods, list) or "client_secret_basic" not in auth_methods:
            raise ForbiddenError(
                code="oidc_metadata_invalid",
                detail="OIDC provider must support client_secret_basic authentication.",
            )
        async with _http_client(request) as client:
            try:
                jwks_response = await client.request(
                    "GET", endpoints["jwks_uri"], headers={"Accept": "application/json"}
                )
                jwks_response.raise_for_status()
                if len(jwks_response.content) > 1_048_576:
                    raise ValueError("JWKS document is too large")
                jwks = jwks_response.json()
            except Exception as exc:
                raise ForbiddenError(
                    code="oidc_probe_failed", detail="OIDC signing-key probe failed."
                ) from exc
        if (
            not isinstance(jwks, dict)
            or not isinstance(jwks.get("keys"), list)
            or not any(
                isinstance(key, dict)
                and key.get("use", "sig") == "sig"
                and key.get("alg") in {None, *_ALLOWED_ALGORITHMS}
                and (
                    (key.get("kty") == "RSA" and (key.get("alg") in {None, "RS256"}))
                    or (
                        key.get("kty") == "EC"
                        and key.get("crv") == "P-256"
                        and key.get("alg") in {None, "ES256"}
                    )
                )
                and (not isinstance(key.get("key_ops"), list) or "verify" in key["key_ops"])
                for key in jwks["keys"]
            )
        ):
            raise ForbiddenError(
                code="oidc_metadata_invalid",
                detail="OIDC provider did not expose supported signing keys.",
            )
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            provider = await db.scalar(
                select(OidcProviderModel)
                .where(OidcProviderModel.id == provider_id)
                .with_for_update()
            )
            if provider is None:
                raise ForbiddenError(
                    code="oidc_provider_not_configured", detail="OIDC provider is not configured."
                )
            provider.authorization_endpoint = endpoints["authorization_endpoint"]
            provider.token_endpoint = endpoints["token_endpoint"]
            provider.jwks_uri = endpoints["jwks_uri"]
            provider.status = "enabled"
            provider.probed_at = iam.now()
            provider.updated_at = iam.now()
            from red2pr_control.analytics_audit.audit_chain import append_audit_entry

            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=owner.user.id,
                action="oidc.provider.probe",
                target=f"oidc-provider:{provider_id}",
                decision="allow",
                reason_code="discovery_verified",
                correlation_id=str(getattr(request.state, "correlation_id", "oidc-probe")),
                client_ip=extract_client_ip(request),
                metadata={"issuer": provider.issuer},
                occurred_at=iam.now(),
            )
            await _set_oidc_capability(
                db, status="enabled", reason="provider_probed", now=iam.now()
            )
        return OidcProviderSummary(
            id=provider.id,
            issuer=provider.issuer,
            client_id=provider.client_id,
            status="enabled",
            probed_at=provider.probed_at,
        )

    @router.post("/system/oidc/providers/{provider_id}/disable", response_model=OidcProviderSummary)
    async def disable_provider(provider_id: str, request: Request) -> OidcProviderSummary:
        iam, broker = _oidc_dependencies(request)
        owner = await _require_instance_owner(request, iam)
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            provider = await db.scalar(
                select(OidcProviderModel)
                .where(OidcProviderModel.id == provider_id)
                .with_for_update()
            )
            if provider is None:
                raise ForbiddenError(
                    code="oidc_provider_not_configured", detail="OIDC provider is not configured."
                )
            grants = list(
                await db.scalars(
                    select(OidcMembershipGrantModel).where(
                        OidcMembershipGrantModel.provider_id == provider_id
                    )
                )
            )
            for grant in grants:
                membership = await db.scalar(
                    select(MembershipModel).where(MembershipModel.id == grant.membership_id)
                )
                await db.delete(grant)
                await db.flush()
                if (
                    membership is not None
                    and membership.role == grant.granted_role
                    and membership.version == grant.membership_version
                ):
                    await db.delete(membership)
            user_ids = set(
                await db.scalars(
                    select(OidcIdentityModel.user_id).where(
                        OidcIdentityModel.provider_id == provider_id
                    )
                )
            )
            users = (
                list(await db.scalars(select(UserModel).where(UserModel.id.in_(user_ids))))
                if user_ids
                else []
            )
            for user in users:
                user.grant_epoch += 1
                user.updated_at = iam.now()
                await _revoke_user_sessions(db, user_id=user.id, now=iam.now())
            if provider.client_secret_ref:
                await broker.revoke_client_secret(
                    db, secret_ref=provider.client_secret_ref, now=iam.now()
                )
            provider.status = "disabled"
            provider.updated_at = iam.now()
            from red2pr_control.analytics_audit.audit_chain import append_audit_entry

            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=owner.user.id,
                action="oidc.provider.disable",
                target=f"oidc-provider:{provider_id}",
                decision="allow",
                reason_code="owner_step_up_deprovision",
                correlation_id=str(getattr(request.state, "correlation_id", "oidc-disable")),
                client_ip=extract_client_ip(request),
                metadata={
                    "revoked_user_count": len(users),
                    "removed_membership_count": len(grants),
                },
                occurred_at=iam.now(),
            )
            await _set_oidc_capability(
                db, status="disabled", reason="owner_disabled", now=iam.now()
            )
            summary = OidcProviderSummary(
                id=provider.id,
                issuer=provider.issuer,
                client_id=provider.client_id,
                status="disabled",
                probed_at=provider.probed_at,
            )
        return summary

    @router.get("/auth/oidc/{provider_id}/authorize")
    async def authorize(provider_id: str, request: Request) -> RedirectResponse:
        iam, _broker = _oidc_dependencies(request)
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            provider = await db.scalar(
                select(OidcProviderModel).where(
                    OidcProviderModel.id == provider_id,
                    OidcProviderModel.status == "enabled",
                    OidcProviderModel.probed_at.is_not(None),
                )
            )
            if provider is None:
                raise ForbiddenError(
                    code="oidc_provider_unavailable", detail="OIDC provider is not available."
                )
            provider_data = (provider.client_id, provider.authorization_endpoint)
            state, nonce_value = create_state_nonce()
            browser_binding = secrets.token_urlsafe(32)
            verifier, challenge = create_pkce_pair()
            now = iam.now()
            db.add(
                OidcAuthTransactionModel(
                    id=new_uuid7(now=now),
                    provider_id=provider_id,
                    state_hash=hashlib.sha256(state.encode()).hexdigest(),
                    nonce=nonce_value,
                    verifier_ciphertext=_seal_verifier(iam, provider_id, verifier),
                    browser_binding_hash=hashlib.sha256(
                        browser_binding.encode("ascii")
                    ).hexdigest(),
                    expires_at=now + timedelta(minutes=5),
                    consumed_at=None,
                    created_at=now,
                )
            )
        params = urlencode(
            {
                "response_type": "code",
                "client_id": provider_data[0],
                "redirect_uri": _callback_uri(iam, provider_id),
                "scope": "openid email profile",
                "state": state,
                "nonce": nonce_value,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "response_mode": "form_post",
            }
        )
        response = RedirectResponse(
            f"{provider_data[1]}?{params}",
            status_code=302,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
        response.set_cookie(
            key=_browser_binding_cookie_name(state),
            value=browser_binding,
            max_age=300,
            path=f"/api/v1/auth/oidc/{provider_id}/callback",
            secure=iam.secure_cookies,
            httponly=True,
            samesite="none",
        )
        return response

    @router.post("/auth/oidc/{provider_id}/callback")
    async def callback(provider_id: str, request: Request) -> Response:
        iam, broker = _oidc_dependencies(request)
        if (
            request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            != "application/x-www-form-urlencoded"
        ):
            raise ForbiddenError(
                code="oidc_callback_invalid", detail="OIDC callback must use form_post."
            )
        raw_form = await request.body()
        if len(raw_form) > 16_384:
            raise ForbiddenError(code="oidc_callback_invalid", detail="OIDC callback is too large.")
        try:
            form = parse_qs(raw_form.decode("utf-8", errors="strict"), strict_parsing=True)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ForbiddenError(
                code="oidc_callback_invalid", detail="OIDC callback is invalid."
            ) from exc
        state_values, code_values = form.get("state"), form.get("code")
        if form.get("error"):
            raise UnauthorizedError(
                code="oidc_authentication_failed", detail="OIDC authentication was not completed."
            )
        if not state_values or len(state_values) != 1 or not code_values or len(code_values) != 1:
            raise ForbiddenError(
                code="oidc_callback_invalid", detail="OIDC callback is incomplete."
            )
        state = state_values[0]
        code = code_values[0]
        if len(state) > 256 or len(code) > 4096:
            raise ForbiddenError(code="oidc_callback_invalid", detail="OIDC callback is invalid.")
        state_hash = hashlib.sha256(state.encode()).hexdigest()
        browser_binding = request.cookies.get(_browser_binding_cookie_name(state))
        if not browser_binding:
            raise UnauthorizedError(
                code="oidc_state_invalid", detail="OIDC authorization state is invalid or expired."
            )
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            txn = await db.scalar(
                select(OidcAuthTransactionModel)
                .where(
                    OidcAuthTransactionModel.provider_id == provider_id,
                    OidcAuthTransactionModel.state_hash == state_hash,
                    OidcAuthTransactionModel.browser_binding_hash
                    == hashlib.sha256(browser_binding.encode("ascii")).hexdigest(),
                    OidcAuthTransactionModel.consumed_at.is_(None),
                    OidcAuthTransactionModel.expires_at > iam.now(),
                )
                .with_for_update()
            )
            provider = await db.scalar(
                select(OidcProviderModel).where(
                    OidcProviderModel.id == provider_id, OidcProviderModel.status == "enabled"
                )
            )
            if txn is None or provider is None:
                raise UnauthorizedError(
                    code="oidc_state_invalid",
                    detail="OIDC authorization state is invalid or expired.",
                )
            verifier = _open_verifier(iam, provider_id, txn.verifier_ciphertext)
            nonce_value = txn.nonce
            provider_snapshot = (
                provider.issuer,
                provider.client_id,
                provider.client_secret_ref,
                provider.token_endpoint,
                provider.jwks_uri,
            )
            txn.consumed_at = iam.now()
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            secret = await broker.resolve_client_secret(db, secret_ref=provider_snapshot[2])
        token_url = provider_snapshot[3]
        basic = base64.b64encode(
            f"{quote_plus(provider_snapshot[1])}:{quote_plus(secret.decode())}".encode()
        ).decode()
        async with _http_client(request) as client:
            try:
                token_response = await client.request(
                    "POST",
                    token_url,
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Authorization": f"Basic {basic}",
                    },
                    content=urlencode(
                        {
                            "grant_type": "authorization_code",
                            "code": code,
                            "redirect_uri": _callback_uri(iam, provider_id),
                            "code_verifier": verifier,
                        }
                    ),
                )
                token_response.raise_for_status()
                if len(token_response.content) > 1_048_576:
                    raise ValueError("OIDC token response is too large")
                token_payload = token_response.json()
                id_token = (
                    token_payload.get("id_token") if isinstance(token_payload, dict) else None
                )
                if not isinstance(id_token, str):
                    raise ValueError("missing ID token")
                jwks_response = await client.request(
                    "GET", provider_snapshot[4], headers={"Accept": "application/json"}
                )
                jwks_response.raise_for_status()
                if len(jwks_response.content) > 1_048_576:
                    raise ValueError("OIDC JWKS is too large")
                claims = validate_id_token(
                    id_token,
                    jwks=jwks_response.json(),
                    issuer=provider_snapshot[0],
                    audience=provider_snapshot[1],
                    nonce=nonce_value,
                    now=int(iam.now().timestamp()),
                )
            except Exception as exc:
                raise UnauthorizedError(
                    code="oidc_authentication_failed", detail="OIDC authentication failed."
                ) from exc
        email = claims.get("email")
        display_name = claims.get("name") or email
        if not isinstance(email, str) or not isinstance(display_name, str):
            raise UnauthorizedError(
                code="oidc_authentication_failed", detail="OIDC profile is incomplete."
            )
        try:
            normalized_email = _EMAIL_ADAPTER.validate_python(email)
        except ValidationError as exc:
            raise UnauthorizedError(
                code="oidc_authentication_failed", detail="OIDC profile is invalid."
            ) from exc
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            user: UserModel | None
            identity = await db.scalar(
                select(OidcIdentityModel).where(
                    OidcIdentityModel.provider_id == provider_id,
                    OidcIdentityModel.subject == claims["sub"],
                )
            )
            if identity is None:
                existing_user = await db.scalar(
                    select(UserModel).where(UserModel.email == normalized_email)
                )
                if existing_user is not None:
                    raise ConflictError(
                        code="oidc_identity_link_required",
                        detail=(
                            "This email belongs to a local account; an owner must bind the "
                            "IdP subject explicitly."
                        ),
                    )
                suffix = hashlib.sha256(
                    f"{provider_snapshot[0]}\0{claims['sub']}".encode()
                ).hexdigest()[:32]
                now = iam.now()
                user = UserModel(
                    id=new_uuid7(now=now),
                    username=f"oidc_{suffix}",
                    email=normalized_email,
                    display_name=display_name[:120],
                    password_hash=hash_password(secrets.token_urlsafe(48)),
                    is_instance_owner=False,
                    status="active",
                    mfa_enabled=False,
                    grant_epoch=1,
                    disabled_at=None,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
                db.add(user)
                await db.flush()
                identity = OidcIdentityModel(
                    id=new_uuid7(now=now),
                    provider_id=provider_id,
                    subject=claims["sub"],
                    user_id=user.id,
                    created_at=now,
                )
                db.add(identity)
            else:
                user = await db.scalar(select(UserModel).where(UserModel.id == identity.user_id))
            if user is None or user.status != "active":
                raise UnauthorizedError(
                    code="oidc_authentication_failed", detail="OIDC account is unavailable."
                )
            await _sync_group_memberships(
                db,
                provider_id=provider_id,
                user=user,
                claims=claims,
                now=iam.now(),
            )
            instance = await db.scalar(select(InstanceModel))
            recovery_epoch = instance.recovery_epoch if instance is not None else 1
            _session, raw_session, csrf = await iam._mint_db_session(
                db,
                user=user,
                recovery_epoch=recovery_epoch,
                auth_strength="oidc",
                step_up_at=None,
                client_ip=extract_client_ip(request),
                user_agent=summarize_user_agent(request),
                now=iam.now(),
            )
        result = RedirectResponse(
            f"{iam.public_base_url.rstrip('/')}/auth/oidc/callback", status_code=303
        )
        set_session_cookie(result, raw_session_token=raw_session, secure=iam.secure_cookies)
        set_csrf_cookie(result, csrf_token=csrf, secure=iam.secure_cookies)
        result.headers["Cache-Control"] = "no-store"
        result.headers["Pragma"] = "no-cache"
        result.delete_cookie(
            key=_browser_binding_cookie_name(state),
            path=f"/api/v1/auth/oidc/{provider_id}/callback",
            secure=iam.secure_cookies,
            httponly=True,
            samesite="none",
        )
        return result

    @router.post(
        "/system/oidc/providers/{provider_id}/identities/{user_id}",
        status_code=204,
    )
    async def bind_identity(
        provider_id: str,
        user_id: str,
        body: OidcIdentityBindingRequest,
        request: Request,
    ) -> Response:
        iam, _broker = _oidc_dependencies(request)
        owner = await _require_instance_owner(request, iam)
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            provider = await db.scalar(
                select(OidcProviderModel).where(
                    OidcProviderModel.id == provider_id, OidcProviderModel.status == "enabled"
                )
            )
            user = await db.scalar(select(UserModel).where(UserModel.id == user_id))
            if provider is None or user is None:
                raise UnauthorizedError(
                    code="oidc_binding_target_unavailable", detail="Binding target is unavailable."
                )
            existing = await db.scalar(
                select(OidcIdentityModel).where(
                    OidcIdentityModel.provider_id == provider_id,
                    OidcIdentityModel.subject == body.subject,
                )
            )
            user_binding = await db.scalar(
                select(OidcIdentityModel).where(
                    OidcIdentityModel.provider_id == provider_id,
                    OidcIdentityModel.user_id == user_id,
                )
            )
            if existing is not None or user_binding is not None:
                raise ConflictError(
                    code="oidc_identity_already_bound", detail="Identity is already bound."
                )
            now = iam.now()
            db.add(
                OidcIdentityModel(
                    id=new_uuid7(now=now),
                    provider_id=provider_id,
                    subject=body.subject,
                    user_id=user_id,
                    created_at=now,
                )
            )
            from red2pr_control.analytics_audit.audit_chain import append_audit_entry

            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=owner.user.id,
                action="oidc.identity.bind",
                target=f"oidc-provider:{provider_id}:user:{user_id}",
                decision="allow",
                reason_code="explicit_owner_binding",
                correlation_id=str(getattr(request.state, "correlation_id", "oidc-bind")),
                client_ip=extract_client_ip(request),
                metadata={"subject_sha256": hashlib.sha256(body.subject.encode()).hexdigest()},
                occurred_at=iam.now(),
            )
        return Response(status_code=204, headers={"Cache-Control": "no-store"})

    @router.get("/workspaces/{ws}/oidc-mappings", response_model=list[OidcGroupMappingSummary])
    async def list_group_mappings(ws: str, request: Request) -> list[OidcGroupMappingSummary]:
        iam, _broker = _oidc_dependencies(request)
        correlation_id = str(getattr(request.state, "correlation_id", "oidc-mapping-list"))
        auth = await iam.authenticate_request(
            request, require_csrf=False, correlation_id=correlation_id
        )
        workspace = await authorize_workspace_access(
            iam.session_factory,
            auth=auth,
            raw_ws=ws,
            allowed_roles=ADMIN_ONLY_ROLES,
            allow_break_glass=False,
            action="workspace.oidc_mapping.read",
            client_ip=extract_client_ip(request),
            correlation_id=correlation_id,
            now=iam.now(),
        )
        async with workspace_rls_session(
            iam.session_factory, workspace_id=workspace.workspace_id
        ) as db:
            rows = list(
                await db.scalars(
                    select(OidcGroupMappingModel)
                    .where(OidcGroupMappingModel.workspace_id == workspace.workspace_id)
                    .order_by(OidcGroupMappingModel.provider_id, OidcGroupMappingModel.group_name)
                )
            )
            return [
                OidcGroupMappingSummary(
                    id=row.id,
                    provider_id=row.provider_id,
                    group_name=row.group_name,
                    role=_workspace_role(row.role),
                    enabled=row.enabled,
                )
                for row in rows
            ]

    @router.post("/workspaces/{ws}/oidc-mappings", response_model=OidcGroupMappingSummary)
    async def configure_group_mapping(
        ws: str, body: OidcGroupMappingRequest, request: Request
    ) -> OidcGroupMappingSummary:
        iam, _broker = _oidc_dependencies(request)
        correlation_id = str(getattr(request.state, "correlation_id", "oidc-mapping"))
        auth = await iam.authenticate_request(
            request, require_csrf=True, correlation_id=correlation_id
        )
        workspace = await authorize_workspace_access(
            iam.session_factory,
            auth=auth,
            raw_ws=ws,
            allowed_roles=ADMIN_ONLY_ROLES,
            allow_break_glass=False,
            action="workspace.oidc_mapping.update",
            client_ip=extract_client_ip(request),
            correlation_id=correlation_id,
            now=iam.now(),
        )
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            provider = await db.scalar(
                select(OidcProviderModel).where(
                    OidcProviderModel.id == body.provider_id,
                    OidcProviderModel.status == "enabled",
                )
            )
            if provider is None:
                raise ForbiddenError(
                    code="oidc_provider_unavailable", detail="OIDC provider is not available."
                )
        async with workspace_rls_session(
            iam.session_factory, workspace_id=workspace.workspace_id
        ) as db:
            mapping = await db.scalar(
                select(OidcGroupMappingModel)
                .where(
                    OidcGroupMappingModel.workspace_id == workspace.workspace_id,
                    OidcGroupMappingModel.provider_id == body.provider_id,
                    OidcGroupMappingModel.group_name == body.group_name,
                )
                .with_for_update()
            )
            if mapping is None:
                mapping = OidcGroupMappingModel(
                    id=new_uuid7(now=iam.now()),
                    workspace_id=workspace.workspace_id,
                    provider_id=body.provider_id,
                    group_name=body.group_name,
                    role=body.role,
                    enabled=body.enabled,
                    created_at=iam.now(),
                )
                db.add(mapping)
            else:
                mapping.role = body.role
                mapping.enabled = body.enabled
            changed_users = list(
                await db.scalars(
                    select(OidcMembershipGrantModel).where(
                        OidcMembershipGrantModel.workspace_id == workspace.workspace_id,
                        OidcMembershipGrantModel.provider_id == body.provider_id,
                        OidcMembershipGrantModel.group_name == body.group_name,
                    )
                )
            )
            for grant in changed_users:
                user = await db.scalar(select(UserModel).where(UserModel.id == grant.user_id))
                membership = await db.scalar(
                    select(MembershipModel).where(MembershipModel.id == grant.membership_id)
                )
                if not body.enabled:
                    await db.delete(grant)
                    await db.flush()
                    if (
                        membership is not None
                        and membership.role == grant.granted_role
                        and membership.version == grant.membership_version
                    ):
                        await db.delete(membership)
                    if user is not None:
                        user.grant_epoch += 1
                        user.updated_at = iam.now()
                        await _revoke_user_sessions(db, user_id=user.id, now=iam.now())
                elif membership is not None and membership.role != body.role:
                    if membership.role == grant.granted_role:
                        membership.role = body.role
                        membership.version += 1
                        membership.updated_at = iam.now()
                        grant.granted_role = body.role
                        grant.membership_version = membership.version
                        if user is not None:
                            user.grant_epoch += 1
                            user.updated_at = iam.now()
                            await _revoke_user_sessions(db, user_id=user.id, now=iam.now())
                    else:
                        await db.delete(grant)
            from red2pr_control.analytics_audit.audit_chain import append_audit_entry

            await append_audit_entry(
                db,
                workspace_id=workspace.workspace_id,
                actor_type="user",
                actor_id=auth.user.id,
                action="workspace.oidc_mapping.update",
                target=f"oidc-group:{body.group_name}",
                decision="allow",
                reason_code="explicit_group_mapping",
                correlation_id=correlation_id,
                client_ip=extract_client_ip(request),
                metadata={
                    "provider_id": body.provider_id,
                    "role": body.role,
                    "enabled": body.enabled,
                },
                occurred_at=iam.now(),
            )
        return OidcGroupMappingSummary(
            id=mapping.id,
            provider_id=mapping.provider_id,
            group_name=mapping.group_name,
            role=_workspace_role(mapping.role),
            enabled=mapping.enabled,
        )

    return router
