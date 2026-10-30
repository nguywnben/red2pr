"""IAM session lifecycle, bootstrap claim, MFA/recovery orchestration & PG rate limiter (U05).

Implements docs/14_SECURITY_IDENTITY.md, ADR-034, W-01, A-01..A-03, S-06, NFR-05, SEC-026, SEC-038:
- Atomic one-use instance-owner bootstrap claim (`409 already_claimed`, `410 bootstrap_expired`).
- 256-bit opaque cookie sessions (`__Host-red2pr_session` on HTTPS, `red2pr_session` on loopback
  HTTP), SHA-256 hashed at rest, 30m sliding idle timeout, 12h absolute ceiling, session
  rotation on login/step-up/MFA/recovery, and `grant_epoch` + `recovery_epoch` fences.
- Cookie-free MFA challenge tickets (`mfa_required` never issues a session cookie).
- 5-minute `step_up_at` privileged verification (`403 step_up_required` when missing/stale).
- Mandatory privileged MFA enforcement (`403 mfa_policy_mandatory` on owner disable attempt).
- Single-use recovery code reset revoking all sessions, bumping `grant_epoch`, resetting
  compromised MFA, and emitting high-severity audit + `identity.permission_revoked` outbox event.
- Multi-process PostgreSQL sliding-window rate limiter (`5 failed / 15m` per `account+IP`
  plus per-IP anti-spray ceiling, returning `429` + `Retry-After` without global account DoS).
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast
from urllib.parse import urlparse

from argon2 import PasswordHasher
from fastapi import Request, Response
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.events import EventEnvelope, SecurityIdentityEventPayload
from py_contracts.iam import (
    AuthStrength,
    CsrfBootstrapResponse,
    LoginRequest,
    LoginResponse,
    MeResponse,
    MfaDeleteRequest,
    MfaEnrollRequest,
    MfaEnrollResponse,
    RecoveryRequest,
    RecoveryResponse,
    Session,
    SessionListItem,
    SessionPage,
    SetupClaimRequest,
    SetupClaimResponse,
    StepUpRequest,
    StepUpResponse,
    TelegramLinkSummary,
    User,
    UserStatus,
)
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    BadRequestError,
    ConflictError,
    ForbiddenError,
    GoneError,
    NotFoundError,
    RateLimitedError,
    UnauthorizedError,
)
from red2pr_control.db.base import (
    AuthChallengeModel,
    AuthRateLimitModel,
    BootstrapTokenModel,
    InstanceModel,
    MfaCredentialModel,
    RecoveryCodeModel,
    SessionModel,
    TelegramLinkChallengeModel,
    TelegramLinkModel,
    UserModel,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import instance_rls_session
from red2pr_control.iam.csrf import (
    CSRF_COOKIE_NAME,
    hash_csrf_secret,
    mint_anonymous_csrf_token,
    mint_session_csrf_token,
    validate_double_submit_csrf,
)
from red2pr_control.iam.mfa import (
    TotpSecretVaultProtocol,
    build_otpauth_uri,
    derive_iam_subkey,
    generate_recovery_code_batch,
    generate_totp_secret,
    hash_recovery_code,
    verify_totp_code,
)
from red2pr_control.iam.passwords import (
    _DEFAULT_HASHER,
    hash_password,
    validate_new_password_policy,
    verify_dummy_password,
    verify_password_and_check_rehash,
)

HTTPS_SESSION_COOKIE_NAME: str = "__Host-red2pr_session"
HTTP_LOOPBACK_SESSION_COOKIE_NAME: str = "red2pr_session"

SESSION_IDLE_TIMEOUT: timedelta = timedelta(minutes=30)
SESSION_ABSOLUTE_LIFETIME: timedelta = timedelta(hours=12)
STEP_UP_VALIDITY_WINDOW: timedelta = timedelta(minutes=5)
MFA_LOGIN_CHALLENGE_TTL: timedelta = timedelta(minutes=5)
MFA_ENROLL_CHALLENGE_TTL: timedelta = timedelta(minutes=10)
BOOTSTRAP_DEFAULT_TTL: timedelta = timedelta(minutes=15)
BOOTSTRAP_MAX_TTL: timedelta = timedelta(minutes=15)

_FORBIDDEN_QUERY_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "bootstrap_token",
        "token",
        "secret",
        "password",
        "api_key",
        "apikey",
        "access_token",
        "client_secret",
        "private_key",
        "webhook_secret",
    }
)
_FORBIDDEN_QUERY_PARAM_SUFFIXES: tuple[str, ...] = (
    "_token",
    "_secret",
    "_password",
    "_key",
)


def assert_no_secret_in_query_url(request: Request) -> None:
    """Reject setup/auth requests carrying bootstrap tokens or credentials in query URLs."""
    for raw_key in request.query_params:
        lowered = raw_key.strip().lower()
        if lowered in _FORBIDDEN_QUERY_PARAM_NAMES or any(
            lowered.endswith(suffix) for suffix in _FORBIDDEN_QUERY_PARAM_SUFFIXES
        ):
            raise BadRequestError(
                code="secret_in_query_url",
                detail=(
                    "Bootstrap tokens and credentials must never be passed in URL query "
                    "parameters; submit them in the JSON request body or headers."
                ),
            )


RATE_LIMIT_WINDOW: timedelta = timedelta(minutes=15)
LOGIN_ACCOUNT_IP_MAX_FAILURES: int = 5
LOGIN_IP_SPRAY_MAX_FAILURES: int = 20
STEP_UP_MAX_FAILURES: int = 5
RECOVERY_MAX_FAILURES: int = 5
BOOTSTRAP_MAX_FAILURES: int = 5
MFA_VERIFY_MAX_FAILURES: int = 5

_LOOPBACK_CLIENTS: frozenset[str] = frozenset({"127.0.0.1", "::1", "localhost", "testclient"})
_CTRL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")

RateLimitAction = Literal["login", "step_up", "recovery", "bootstrap_claim", "mfa_verify"]


@dataclass(frozen=True)
class AuthenticatedContext:
    """Validated cookie or scoped API-token authentication context."""

    user: UserModel
    session: SessionModel
    csrf_token: str
    csrf_cookie_refreshed: bool
    api_token: Any | None = None


def _default_utc_clock() -> datetime:
    return datetime.now(tz=UTC)


def hash_opaque_token(raw_token: str) -> str:
    """Compute SHA-256 hex digest of an opaque bootstrap or session token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def session_cookie_name(*, secure: bool) -> str:
    """Return RFC 6265bis `__Host-` cookie name on HTTPS or loopback name on local HTTP."""
    return HTTPS_SESSION_COOKIE_NAME if secure else HTTP_LOOPBACK_SESSION_COOKIE_NAME


def extract_session_cookie(request: Request, *, secure: bool) -> str | None:
    """Extract raw opaque session cookie from incoming HTTP request."""
    primary = request.cookies.get(session_cookie_name(secure=secure))
    if primary:
        return primary
    fallback_name = HTTP_LOOPBACK_SESSION_COOKIE_NAME if secure else HTTPS_SESSION_COOKIE_NAME
    return request.cookies.get(fallback_name)


def set_session_cookie(
    response: Response,
    *,
    raw_session_token: str,
    secure: bool,
    max_age_seconds: int = int(SESSION_ABSOLUTE_LIFETIME.total_seconds()),
) -> None:
    """Attach `HttpOnly`, `SameSite=Lax`, conditionally `Secure` opaque session cookie."""
    response.set_cookie(
        key=session_cookie_name(secure=secure),
        value=raw_session_token,
        max_age=max_age_seconds,
        path="/",
        secure=secure,
        httponly=True,
        samesite="lax",
    )


def clear_session_cookie(response: Response, *, secure: bool) -> None:
    """Delete both HTTPS and loopback session cookie variants on logout/invalidation."""
    for name, sec_flag in (
        (HTTPS_SESSION_COOKIE_NAME, True),
        (HTTP_LOOPBACK_SESSION_COOKIE_NAME, False),
    ):
        if not secure and sec_flag:
            continue
        response.delete_cookie(
            key=name,
            path="/",
            secure=sec_flag,
            httponly=True,
            samesite="lax",
        )


def extract_client_ip(request: Request) -> str:
    """Extract direct peer IP address without trusting unverified X-Forwarded-For headers."""
    if request.client is not None and request.client.host:
        return request.client.host.strip()[:64]
    return "unknown"


def summarize_user_agent(request: Request) -> str | None:
    """Sanitize and bound User-Agent string for safe session list display."""
    raw = request.headers.get("user-agent")
    if not raw:
        return None
    cleaned = _CTRL_CHAR_RE.sub("", raw).strip()[:120]
    return cleaned or None


def is_step_up_fresh(session_row: SessionModel, *, now: datetime) -> bool:
    """Return True iff `session_row.step_up_at` is within the 5-minute privileged window."""
    if session_row.step_up_at is None:
        return False
    elapsed = now - session_row.step_up_at.astimezone(UTC)
    return timedelta(0) <= elapsed <= STEP_UP_VALIDITY_WINDOW


def _to_user_dto(row: UserModel) -> User:
    return User(
        id=row.id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        display_name=row.display_name,
        email=row.email,
        status=cast(UserStatus, row.status),
    )


def _to_session_dto(row: SessionModel) -> Session:
    return Session(
        id=row.id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        user_id=row.user_id,
        expires_at=row.expires_at,
        auth_strength=cast(AuthStrength, row.auth_strength),
        step_up_at=row.step_up_at,
        grant_epoch=row.grant_epoch,
    )


class IamService:
    """Authoritative U05 authentication, session, CSRF, TOTP MFA & recovery coordinator."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        totp_vault: TotpSecretVaultProtocol,
        iam_seed_key: bytes,
        public_base_url: str = "http://127.0.0.1:4280",
        deployment_mode: Literal["local", "server", "distributed"] = "local",
        clock: Callable[[], datetime] = _default_utc_clock,
        password_hasher: PasswordHasher = _DEFAULT_HASHER,
        sse_cursor_ttl: timedelta = timedelta(hours=24),
        sse_poll_interval_seconds: float = 0.20,
        sse_heartbeat_interval_seconds: float = 15.0,
    ) -> None:
        if len(iam_seed_key) < 32:
            raise ValueError("iam_seed_key must be at least 32 bytes")
        self._session_factory = session_factory
        self._totp_vault = totp_vault
        self._csrf_signing_key = derive_iam_subkey(
            iam_seed_key,
            context=b"red2pr:iam:csrf-signing:v1",
        )
        self._recovery_hmac_key = derive_iam_subkey(
            iam_seed_key,
            context=b"red2pr:iam:recovery-code:v1",
        )
        self._public_base_url = public_base_url
        self._deployment_mode = deployment_mode
        self._clock = clock
        self._password_hasher = password_hasher
        self._sse_cursor_ttl = sse_cursor_ttl
        self._sse_poll_interval_seconds = sse_poll_interval_seconds
        self._sse_heartbeat_interval_seconds = sse_heartbeat_interval_seconds
        parsed = urlparse(public_base_url)
        self._secure_cookies = parsed.scheme.lower() == "https"

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        return self._session_factory

    @property
    def public_base_url(self) -> str:
        return self._public_base_url

    @property
    def secure_cookies(self) -> bool:
        return self._secure_cookies

    @property
    def csrf_signing_key(self) -> bytes:
        return self._csrf_signing_key

    @property
    def sse_cursor_ttl(self) -> timedelta:
        return self._sse_cursor_ttl

    @property
    def sse_poll_interval_seconds(self) -> float:
        return self._sse_poll_interval_seconds

    @property
    def sse_heartbeat_interval_seconds(self) -> float:
        return self._sse_heartbeat_interval_seconds

    def now(self) -> datetime:
        return self._clock().astimezone(UTC)

    async def provision_local_user(
        self,
        *,
        display_name: str,
        email: str | None,
        password: str,
        is_instance_owner: bool = False,
        correlation_id: str = "system-provision",
    ) -> User:
        """Create a local user account with Argon2id password validation & audit record."""
        ref_now = self.now()
        clean_display = display_name.strip()
        clean_email = email.strip().lower() if email is not None else None
        disallowed = tuple(tok for tok in (clean_email, clean_display) if tok is not None and tok)
        validate_new_password_policy(
            password,
            disallowed_substrings=disallowed,
        )
        normalized_username = (clean_email or clean_display.lower())[:120]
        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            existing = await db.scalar(
                select(UserModel.id).where(
                    or_(
                        UserModel.username == normalized_username,
                        *([UserModel.email == clean_email] if clean_email is not None else []),
                    )
                )
            )
            if existing is not None:
                raise ConflictError(
                    code="user_already_exists",
                    detail="A local user with that email or username already exists.",
                )
            user_row = UserModel(
                id=new_uuid7(now=ref_now),
                username=normalized_username,
                email=clean_email,
                display_name=clean_display,
                password_hash=hash_password(password, hasher=self._password_hasher),
                is_instance_owner=is_instance_owner,
                status="active",
                mfa_enabled=False,
                grant_epoch=1,
                disabled_at=None,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(user_row)
            await db.flush()
            await append_audit_entry(
                db,
                actor_type="system",
                actor_id="system",
                action="iam.user_provisioned",
                target=f"user:{user_row.id}",
                decision="allow",
                reason_code="local_user_created",
                correlation_id=correlation_id,
                occurred_at=ref_now,
            )
            return _to_user_dto(user_row)

    async def _check_rate_limits(
        self,
        db: AsyncSession,
        *,
        checks: list[tuple[RateLimitAction, str, int]],
        now: datetime,
    ) -> int | None:
        """Return `retry_after_seconds` if any bucket has reached `max_failures` in window."""
        window_start = now - RATE_LIMIT_WINDOW
        max_retry_after: int | None = None
        for action, bucket_key, limit in checks:
            rows = (
                await db.scalars(
                    select(AuthRateLimitModel.attempted_at)
                    .where(
                        AuthRateLimitModel.action == action,
                        AuthRateLimitModel.bucket_key == bucket_key,
                        AuthRateLimitModel.attempted_at > window_start,
                        AuthRateLimitModel.expires_at > now,
                    )
                    .order_by(AuthRateLimitModel.attempted_at.asc())
                )
            ).all()
            if len(rows) >= limit:
                oldest = rows[len(rows) - limit].astimezone(UTC)
                remaining_s = max(
                    1,
                    math.ceil(((oldest + RATE_LIMIT_WINDOW) - now).total_seconds()),
                )
                if max_retry_after is None or remaining_s > max_retry_after:
                    max_retry_after = remaining_s
        return max_retry_after

    async def _record_rate_limit_failures(
        self,
        db: AsyncSession,
        *,
        buckets: list[tuple[RateLimitAction, str]],
        now: datetime,
    ) -> None:
        expires_at = now + RATE_LIMIT_WINDOW
        for action, bucket_key in buckets:
            db.add(
                AuthRateLimitModel(
                    id=new_uuid7(now=now),
                    action=action,
                    bucket_key=bucket_key,
                    attempted_at=now,
                    expires_at=expires_at,
                )
            )
        await db.flush()

    async def _mint_db_session(
        self,
        db: AsyncSession,
        *,
        user: UserModel,
        recovery_epoch: int,
        auth_strength: AuthStrength,
        step_up_at: datetime | None,
        client_ip: str | None,
        user_agent: str | None,
        now: datetime,
        absolute_expires_at: datetime | None = None,
    ) -> tuple[SessionModel, str, str]:
        raw_session_token = secrets.token_urlsafe(32)
        raw_csrf_token, csrf_hash = mint_session_csrf_token()
        abs_exp = (
            absolute_expires_at
            if absolute_expires_at is not None
            else now + SESSION_ABSOLUTE_LIFETIME
        )
        idle_exp = min(abs_exp, now + SESSION_IDLE_TIMEOUT)
        row = SessionModel(
            id=new_uuid7(now=now),
            user_id=user.id,
            token_hash=hash_opaque_token(raw_session_token),
            csrf_secret_hash=csrf_hash,
            auth_strength=auth_strength,
            step_up_at=step_up_at,
            grant_epoch=user.grant_epoch,
            recovery_epoch=recovery_epoch,
            last_seen_at=now,
            idle_expires_at=idle_exp,
            expires_at=abs_exp,
            client_ip=client_ip,
            user_agent=user_agent,
            revoked_at=None,
            revoke_reason=None,
            version=1,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        await db.flush()
        return row, raw_session_token, raw_csrf_token

    async def issue_bootstrap_token(
        self,
        *,
        ttl_seconds: int = int(BOOTSTRAP_DEFAULT_TTL.total_seconds()),
        loopback_only: bool = True,
        correlation_id: str = "bootstrap-init",
    ) -> tuple[str, datetime]:
        """Provision singleton `instances` row (if absent) and mint a one-use bootstrap token."""
        max_ttl_seconds = int(BOOTSTRAP_MAX_TTL.total_seconds())
        if ttl_seconds < 60 or ttl_seconds > max_ttl_seconds:
            raise ValueError(
                f"Bootstrap token TTL must be between 60 and {max_ttl_seconds} seconds"
            )

        ref_now = self.now()
        expires_at = ref_now + timedelta(seconds=ttl_seconds)
        raw_token = f"r2pr_boot_{secrets.token_urlsafe(32)}"
        token_hash = hash_opaque_token(raw_token)

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            instance_row = await db.scalar(select(InstanceModel).with_for_update())
            if instance_row is None:
                instance_row = InstanceModel(
                    id=new_uuid7(now=ref_now),
                    singleton_guard=True,
                    deployment_mode=self._deployment_mode,
                    public_base_url=self._public_base_url,
                    config_revision=1,
                    recovery_epoch=1,
                    initialized_at=None,
                    version=1,
                    created_at=ref_now,
                    updated_at=ref_now,
                )
                db.add(instance_row)
                await db.flush()
            elif instance_row.initialized_at is not None:
                raise ConflictError(
                    code="already_claimed",
                    detail="Instance owner has already been claimed.",
                )

            existing_owners = await db.scalar(
                select(func.count())
                .select_from(UserModel)
                .where(UserModel.is_instance_owner.is_(True))
            )
            if existing_owners and int(existing_owners) > 0:
                raise ConflictError(
                    code="already_claimed",
                    detail="Instance owner has already been claimed.",
                )

            # Revoke any previously unclaimed bootstrap tokens so at most one is valid.
            await db.execute(
                update(BootstrapTokenModel)
                .where(
                    BootstrapTokenModel.claimed_at.is_(None),
                    BootstrapTokenModel.revoked_at.is_(None),
                )
                .values(revoked_at=ref_now)
            )

            boot_row = BootstrapTokenModel(
                id=new_uuid7(now=ref_now),
                token_hash=token_hash,
                loopback_only=loopback_only,
                expires_at=expires_at,
                claimed_at=None,
                claimed_by_user_id=None,
                revoked_at=None,
                created_at=ref_now,
            )
            db.add(boot_row)
            await append_audit_entry(
                db,
                actor_type="system",
                actor_id="bootstrap-issuer",
                action="setup.bootstrap_token_issued",
                target=f"bootstrap_token:{boot_row.id}",
                decision="allow",
                reason_code="bootstrap_initialized",
                correlation_id=correlation_id,
                occurred_at=ref_now,
            )
        return raw_token, expires_at

    async def get_csrf_bootstrap(self, request: Request) -> CsrfBootstrapResponse:
        """Issue or preserve a pre-auth/session CSRF token and report unclaimed bootstrap state."""
        ref_now = self.now()
        claim_required = False
        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            inst = await db.scalar(select(InstanceModel))
            owner_count = await db.scalar(
                select(func.count())
                .select_from(UserModel)
                .where(UserModel.is_instance_owner.is_(True))
            )
            active_boot = await db.scalar(
                select(func.count())
                .select_from(BootstrapTokenModel)
                .where(
                    BootstrapTokenModel.claimed_at.is_(None),
                    BootstrapTokenModel.revoked_at.is_(None),
                    BootstrapTokenModel.expires_at > ref_now,
                )
            )
            claim_required = (
                (inst is None or inst.initialized_at is None)
                and int(owner_count or 0) == 0
                and int(active_boot or 0) > 0
            )

        existing_cookie = request.cookies.get(CSRF_COOKIE_NAME)
        if existing_cookie and existing_cookie.startswith("sess.") and len(existing_cookie) >= 24:
            return CsrfBootstrapResponse(
                csrf_token=existing_cookie,
                bootstrap_claim_required=claim_required,
            )
        anon_token = mint_anonymous_csrf_token(self._csrf_signing_key)
        return CsrfBootstrapResponse(
            csrf_token=anon_token,
            bootstrap_claim_required=claim_required,
        )

    async def record_csrf_denial(
        self,
        *,
        code: str,
        target_path: str,
        client_ip: str,
        correlation_id: str,
        actor_id: str = "anonymous",
    ) -> None:
        """Persist a hash-chained `deny` audit record for rejected CSRF/Origin requests."""
        ref_now = self.now()
        actor_type: Literal["user", "anonymous"] = (
            "anonymous" if actor_id == "anonymous" else "user"
        )
        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            await append_audit_entry(
                db,
                actor_type=actor_type,
                actor_id=actor_id,
                action="security.csrf_check",
                target=target_path,
                decision="deny",
                reason_code=code,
                correlation_id=correlation_id,
                client_ip=client_ip,
                occurred_at=ref_now,
            )

    async def claim_bootstrap_owner(
        self,
        payload: SetupClaimRequest,
        *,
        client_ip: str,
        user_agent: str | None,
        request_scheme: str,
        correlation_id: str,
    ) -> tuple[SetupClaimResponse, str]:
        """Atomically claim the initial `instance_owner` account using a one-time token (A-01)."""
        ref_now = self.now()
        ip_bucket = f"ip:{client_ip}"
        candidate_hash = hash_opaque_token(payload.bootstrap_token)

        error_to_raise: Exception | None = None

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            retry_after = await self._check_rate_limits(
                db,
                checks=[("bootstrap_claim", ip_bucket, BOOTSTRAP_MAX_FAILURES)],
                now=ref_now,
            )
            if retry_after is not None:
                await append_audit_entry(
                    db,
                    actor_type="anonymous",
                    actor_id="anonymous",
                    action="setup.owner_claim",
                    target="instance",
                    decision="deny",
                    reason_code="rate_limited",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                error_to_raise = RateLimitedError(
                    code="rate_limited",
                    detail="Too many bootstrap claim attempts. Please wait before retrying.",
                    retry_after_seconds=retry_after,
                )

            if error_to_raise is None:
                instance_row = await db.scalar(select(InstanceModel).with_for_update())
                owner_count = int(
                    (
                        await db.scalar(
                            select(func.count())
                            .select_from(UserModel)
                            .where(UserModel.is_instance_owner.is_(True))
                        )
                    )
                    or 0
                )
                token_row = await db.scalar(
                    select(BootstrapTokenModel)
                    .where(BootstrapTokenModel.token_hash == candidate_hash)
                    .with_for_update()
                )

                if (
                    (instance_row is not None and instance_row.initialized_at is not None)
                    or owner_count > 0
                    or (token_row is not None and token_row.claimed_at is not None)
                ):
                    await append_audit_entry(
                        db,
                        actor_type="anonymous",
                        actor_id="anonymous",
                        action="setup.owner_claim",
                        target="instance",
                        decision="deny",
                        reason_code="already_claimed",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        occurred_at=ref_now,
                    )
                    error_to_raise = ConflictError(
                        code="already_claimed",
                        detail="Instance owner has already been claimed.",
                    )
                elif token_row is None or token_row.revoked_at is not None:
                    await self._record_rate_limit_failures(
                        db,
                        buckets=[("bootstrap_claim", ip_bucket)],
                        now=ref_now,
                    )
                    await append_audit_entry(
                        db,
                        actor_type="anonymous",
                        actor_id="anonymous",
                        action="setup.owner_claim",
                        target="instance",
                        decision="deny",
                        reason_code="invalid_bootstrap_token",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        occurred_at=ref_now,
                    )
                    error_to_raise = UnauthorizedError(
                        code="invalid_bootstrap_token",
                        detail="Bootstrap token is invalid.",
                    )
                elif ref_now >= token_row.expires_at.astimezone(UTC):
                    await self._record_rate_limit_failures(
                        db,
                        buckets=[("bootstrap_claim", ip_bucket)],
                        now=ref_now,
                    )
                    await append_audit_entry(
                        db,
                        actor_type="anonymous",
                        actor_id="anonymous",
                        action="setup.owner_claim",
                        target=f"bootstrap_token:{token_row.id}",
                        decision="deny",
                        reason_code="bootstrap_expired",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        occurred_at=ref_now,
                    )
                    error_to_raise = GoneError(
                        code="bootstrap_expired",
                        detail=(
                            "Bootstrap token has expired; generate a fresh bootstrap token via CLI."
                        ),
                    )
                elif (
                    token_row.loopback_only
                    and request_scheme.lower() != "https"
                    and client_ip.lower() not in _LOOPBACK_CLIENTS
                ):
                    await append_audit_entry(
                        db,
                        actor_type="anonymous",
                        actor_id="anonymous",
                        action="setup.owner_claim",
                        target=f"bootstrap_token:{token_row.id}",
                        decision="deny",
                        reason_code="bootstrap_loopback_required",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        occurred_at=ref_now,
                    )
                    error_to_raise = ForbiddenError(
                        code="bootstrap_loopback_required",
                        detail=(
                            "Plain-HTTP bootstrap claim is restricted to loopback clients; "
                            "use HTTPS or SSH port-forwarding."
                        ),
                    )

            if error_to_raise is None:
                assert token_row is not None
                validate_new_password_policy(
                    payload.password,
                    disallowed_substrings=(payload.display_name, payload.email or ""),
                )
                if instance_row is None:
                    instance_row = InstanceModel(
                        id=new_uuid7(now=ref_now),
                        singleton_guard=True,
                        deployment_mode=self._deployment_mode,
                        public_base_url=self._public_base_url,
                        config_revision=1,
                        recovery_epoch=1,
                        initialized_at=ref_now,
                        version=1,
                        created_at=ref_now,
                        updated_at=ref_now,
                    )
                    db.add(instance_row)
                    await db.flush()
                else:
                    instance_row.initialized_at = ref_now
                    instance_row.updated_at = ref_now
                    instance_row.version += 1

                normalized_username = payload.display_name.strip().lower()[:120]
                user_row = UserModel(
                    id=new_uuid7(now=ref_now),
                    username=normalized_username,
                    email=payload.email,
                    display_name=payload.display_name.strip(),
                    password_hash=hash_password(payload.password, hasher=self._password_hasher),
                    is_instance_owner=True,
                    status="active",
                    mfa_enabled=False,
                    grant_epoch=1,
                    disabled_at=None,
                    version=1,
                    created_at=ref_now,
                    updated_at=ref_now,
                )
                db.add(user_row)
                await db.flush()

                token_row.claimed_at = ref_now
                token_row.claimed_by_user_id = user_row.id

                session_row, raw_session_token, raw_csrf_token = await self._mint_db_session(
                    db,
                    user=user_row,
                    recovery_epoch=instance_row.recovery_epoch,
                    auth_strength="password",
                    step_up_at=ref_now,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    now=ref_now,
                )
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=user_row.id,
                    action="setup.owner_claimed",
                    target=f"user:{user_row.id}",
                    decision="allow",
                    reason_code="bootstrap_claimed",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                response_dto = SetupClaimResponse(
                    user=_to_user_dto(user_row),
                    session=_to_session_dto(session_row),
                    csrf_token=raw_csrf_token,
                    is_instance_owner=True,
                )
                return response_dto, raw_session_token

        raise error_to_raise

    async def login(
        self,
        payload: LoginRequest,
        *,
        existing_session_cookie: str | None,
        client_ip: str,
        user_agent: str | None,
        correlation_id: str,
    ) -> tuple[LoginResponse, str | None]:
        """Authenticate local account via Argon2id + optional RFC 6238 TOTP MFA (A-02)."""
        ref_now = self.now()
        normalized_ident = payload.identifier.strip().lower()
        ident_digest = hashlib.sha256(normalized_ident.encode("utf-8")).hexdigest()[:32]
        acct_ip_bucket = f"acct_ip:{ident_digest}:{client_ip}"
        ip_bucket = f"ip:{client_ip}"

        raised_error: Exception | None = None
        result_pair: tuple[LoginResponse, str | None] | None = None

        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            retry_after = await self._check_rate_limits(
                db,
                checks=[
                    ("login", acct_ip_bucket, LOGIN_ACCOUNT_IP_MAX_FAILURES),
                    ("login", ip_bucket, LOGIN_IP_SPRAY_MAX_FAILURES),
                ],
                now=ref_now,
            )
            if retry_after is not None:
                await append_audit_entry(
                    db,
                    actor_type="anonymous",
                    actor_id="anonymous",
                    action="auth.login",
                    target=f"identifier_sha256:{ident_digest}",
                    decision="deny",
                    reason_code="rate_limited",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                raised_error = RateLimitedError(
                    code="rate_limited",
                    detail="Too many failed sign-in attempts. Please wait before retrying.",
                    retry_after_seconds=retry_after,
                )
            else:
                user_row = await db.scalar(
                    select(UserModel)
                    .where(
                        or_(
                            UserModel.email == normalized_ident,
                            UserModel.username == normalized_ident,
                        )
                    )
                    .with_for_update()
                )
                if user_row is None or user_row.status != "active":
                    verify_dummy_password(payload.password, hasher=self._password_hasher)
                    await self._record_rate_limit_failures(
                        db,
                        buckets=[("login", acct_ip_bucket), ("login", ip_bucket)],
                        now=ref_now,
                    )
                    await append_audit_entry(
                        db,
                        actor_type="anonymous",
                        actor_id="anonymous",
                        action="auth.login",
                        target=f"identifier_sha256:{ident_digest}",
                        decision="deny",
                        reason_code="invalid_credentials",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        occurred_at=ref_now,
                    )
                    raised_error = UnauthorizedError(
                        code="invalid_credentials",
                        detail="Invalid identifier or password.",
                    )
                else:
                    pw_ok, needs_rehash = verify_password_and_check_rehash(
                        user_row.password_hash,
                        payload.password,
                        hasher=self._password_hasher,
                    )
                    if not pw_ok:
                        await self._record_rate_limit_failures(
                            db,
                            buckets=[("login", acct_ip_bucket), ("login", ip_bucket)],
                            now=ref_now,
                        )
                        await append_audit_entry(
                            db,
                            actor_type="user",
                            actor_id=user_row.id,
                            action="auth.login",
                            target=f"user:{user_row.id}",
                            decision="deny",
                            reason_code="invalid_credentials",
                            correlation_id=correlation_id,
                            client_ip=client_ip,
                            occurred_at=ref_now,
                        )
                        raised_error = UnauthorizedError(
                            code="invalid_credentials",
                            detail="Invalid identifier or password.",
                        )
                    else:
                        if needs_rehash:
                            user_row.password_hash = hash_password(
                                payload.password,
                                hasher=self._password_hasher,
                            )
                            user_row.updated_at = ref_now

                        # Revoke any pre-existing session cookie presented at login (anti-fixation)
                        if existing_session_cookie:
                            old_hash = hash_opaque_token(existing_session_cookie)
                            await db.execute(
                                update(SessionModel)
                                .where(
                                    SessionModel.token_hash == old_hash,
                                    SessionModel.revoked_at.is_(None),
                                )
                                .values(
                                    revoked_at=ref_now,
                                    revoke_reason="login_rotated",
                                    updated_at=ref_now,
                                )
                            )

                        if user_row.mfa_enabled and payload.otp is None:
                            challenge_row = AuthChallengeModel(
                                id=new_uuid7(now=ref_now),
                                user_id=user_row.id,
                                purpose="login_mfa",
                                client_ip=client_ip,
                                expires_at=ref_now + MFA_LOGIN_CHALLENGE_TTL,
                                consumed_at=None,
                                failed_attempts=0,
                                created_at=ref_now,
                            )
                            db.add(challenge_row)
                            await append_audit_entry(
                                db,
                                actor_type="user",
                                actor_id=user_row.id,
                                action="auth.login.mfa_challenge",
                                target=f"user:{user_row.id}",
                                decision="allow",
                                reason_code="mfa_challenge_issued",
                                correlation_id=correlation_id,
                                client_ip=client_ip,
                                occurred_at=ref_now,
                            )
                            # CRITICAL: raw_session_token is None -> NO session cookie issued!
                            result_pair = (
                                LoginResponse(
                                    status="mfa_required",
                                    mfa_challenge_id=challenge_row.id,
                                ),
                                None,
                            )
                        elif user_row.mfa_enabled and payload.otp is not None:
                            challenge_to_mark: AuthChallengeModel | None = None
                            if payload.mfa_challenge_id is not None:
                                challenge_to_mark = await db.scalar(
                                    select(AuthChallengeModel)
                                    .where(
                                        AuthChallengeModel.id == payload.mfa_challenge_id,
                                        AuthChallengeModel.user_id == user_row.id,
                                        AuthChallengeModel.purpose == "login_mfa",
                                    )
                                    .with_for_update()
                                )
                                if (
                                    challenge_to_mark is None
                                    or challenge_to_mark.consumed_at is not None
                                    or challenge_to_mark.failed_attempts >= 5
                                ):
                                    await self._record_rate_limit_failures(
                                        db,
                                        buckets=[("login", acct_ip_bucket), ("login", ip_bucket)],
                                        now=ref_now,
                                    )
                                    await append_audit_entry(
                                        db,
                                        actor_type="user",
                                        actor_id=user_row.id,
                                        action="auth.login.mfa_verify",
                                        target=f"user:{user_row.id}",
                                        decision="deny",
                                        reason_code="invalid_mfa_challenge",
                                        correlation_id=correlation_id,
                                        client_ip=client_ip,
                                        occurred_at=ref_now,
                                    )
                                    raised_error = UnauthorizedError(
                                        code="invalid_credentials",
                                        detail="Invalid identifier or authentication code.",
                                    )
                                elif ref_now >= challenge_to_mark.expires_at.astimezone(UTC):
                                    await append_audit_entry(
                                        db,
                                        actor_type="user",
                                        actor_id=user_row.id,
                                        action="auth.login.mfa_verify",
                                        target=f"user:{user_row.id}",
                                        decision="deny",
                                        reason_code="mfa_challenge_expired",
                                        correlation_id=correlation_id,
                                        client_ip=client_ip,
                                        occurred_at=ref_now,
                                    )
                                    raised_error = GoneError(
                                        code="mfa_challenge_expired",
                                        detail="MFA challenge has expired; please sign in again.",
                                    )

                            if raised_error is None:
                                cred_row = await db.scalar(
                                    select(MfaCredentialModel)
                                    .where(
                                        MfaCredentialModel.user_id == user_row.id,
                                        MfaCredentialModel.status == "active",
                                    )
                                    .with_for_update()
                                )
                                if cred_row is None:
                                    raised_error = UnauthorizedError(
                                        code="invalid_credentials",
                                        detail="Invalid identifier or authentication code.",
                                    )
                                else:
                                    raw_secret = await self._totp_vault.resolve_totp_secret(
                                        db,
                                        secret_ref=cred_row.secret_ref,
                                    )
                                    totp_ok, matched_step, replayed = verify_totp_code(
                                        raw_secret,
                                        otp=payload.otp,
                                        at_time=ref_now,
                                        last_used_timestep=cred_row.last_used_timestep,
                                    )
                                    if not totp_ok:
                                        if challenge_to_mark is not None:
                                            challenge_to_mark.failed_attempts += 1
                                        await self._record_rate_limit_failures(
                                            db,
                                            buckets=[
                                                ("login", acct_ip_bucket),
                                                ("login", ip_bucket),
                                            ],
                                            now=ref_now,
                                        )
                                        await append_audit_entry(
                                            db,
                                            actor_type="user",
                                            actor_id=user_row.id,
                                            action="auth.login.mfa_verify",
                                            target=f"user:{user_row.id}",
                                            decision="deny",
                                            reason_code=(
                                                "totp_replayed" if replayed else "invalid_totp"
                                            ),
                                            correlation_id=correlation_id,
                                            client_ip=client_ip,
                                            occurred_at=ref_now,
                                        )
                                        raised_error = UnauthorizedError(
                                            code="invalid_credentials",
                                            detail="Invalid identifier or authentication code.",
                                        )
                                    else:
                                        cred_row.last_used_timestep = matched_step
                                        cred_row.updated_at = ref_now
                                        if challenge_to_mark is not None:
                                            challenge_to_mark.consumed_at = ref_now

                                        inst_row = await db.scalar(select(InstanceModel))
                                        rec_epoch = (
                                            inst_row.recovery_epoch if inst_row is not None else 1
                                        )
                                        (
                                            session_row,
                                            raw_sess_tok,
                                            raw_csrf_tok,
                                        ) = await self._mint_db_session(
                                            db,
                                            user=user_row,
                                            recovery_epoch=rec_epoch,
                                            auth_strength="mfa",
                                            step_up_at=ref_now,
                                            client_ip=client_ip,
                                            user_agent=user_agent,
                                            now=ref_now,
                                        )
                                        await append_audit_entry(
                                            db,
                                            actor_type="user",
                                            actor_id=user_row.id,
                                            action="auth.login",
                                            target=f"session:{session_row.id}",
                                            decision="allow",
                                            reason_code="mfa_verified",
                                            correlation_id=correlation_id,
                                            client_ip=client_ip,
                                            occurred_at=ref_now,
                                        )
                                        result_pair = (
                                            LoginResponse(
                                                status="authenticated",
                                                user=_to_user_dto(user_row),
                                                session=_to_session_dto(session_row),
                                                csrf_token=raw_csrf_tok,
                                            ),
                                            raw_sess_tok,
                                        )
                        else:
                            inst_row = await db.scalar(select(InstanceModel))
                            rec_epoch = inst_row.recovery_epoch if inst_row is not None else 1
                            session_row, raw_sess_tok, raw_csrf_tok = await self._mint_db_session(
                                db,
                                user=user_row,
                                recovery_epoch=rec_epoch,
                                auth_strength="password",
                                step_up_at=None,
                                client_ip=client_ip,
                                user_agent=user_agent,
                                now=ref_now,
                            )
                            await append_audit_entry(
                                db,
                                actor_type="user",
                                actor_id=user_row.id,
                                action="auth.login",
                                target=f"session:{session_row.id}",
                                decision="allow",
                                reason_code="password_verified",
                                correlation_id=correlation_id,
                                client_ip=client_ip,
                                occurred_at=ref_now,
                            )
                            result_pair = (
                                LoginResponse(
                                    status="authenticated",
                                    user=_to_user_dto(user_row),
                                    session=_to_session_dto(session_row),
                                    csrf_token=raw_csrf_tok,
                                ),
                                raw_sess_tok,
                            )

        if raised_error is not None:
            raise raised_error
        assert result_pair is not None
        return result_pair

    async def authenticate_request(
        self,
        request: Request,
        *,
        require_csrf: bool,
        correlation_id: str,
    ) -> AuthenticatedContext:
        """Validate opaque session cookie, idle/absolute timeouts, epochs, and optional CSRF."""
        authorization = request.headers.get("authorization", "")
        if authorization:
            scheme, _, credential = authorization.partition(" ")
            if scheme.lower() != "bearer" or not credential or " " in credential:
                raise UnauthorizedError(
                    code="invalid_authorization_header", detail="Authorization header is invalid."
                )
            if request.url.path.startswith(("/api/v1/auth/", "/api/v1/me", "/api/v1/setup/")):
                raise ForbiddenError(
                    code="api_token_endpoint_denied",
                    detail="API tokens cannot access session, MFA, or setup endpoints.",
                )
            from red2pr_control.iam.api_tokens import (
                ApiTokenSession,
                authenticate_api_token,
            )

            user_row, api_token = await authenticate_api_token(
                self._session_factory, raw_token=credential, now=self.now()
            )
            return AuthenticatedContext(
                user=user_row,
                session=cast(
                    SessionModel,
                    ApiTokenSession(
                        id=api_token.id,
                        user_id=user_row.id,
                        grant_epoch=user_row.grant_epoch,
                    ),
                ),
                csrf_token="",
                csrf_cookie_refreshed=False,
                api_token=api_token,
            )

        raw_cookie = extract_session_cookie(request, secure=self._secure_cookies)
        if not raw_cookie:
            raise UnauthorizedError(
                code="unauthenticated",
                detail="Authentication session cookie is required.",
            )

        ref_now = self.now()
        client_ip = extract_client_ip(request)
        token_hash = hash_opaque_token(raw_cookie)
        raised_error: Exception | None = None

        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            session_row = await db.scalar(
                select(SessionModel).where(SessionModel.token_hash == token_hash).with_for_update()
            )
            if session_row is None or session_row.revoked_at is not None:
                raised_error = UnauthorizedError(
                    code="unauthenticated",
                    detail="Session is invalid or has been revoked.",
                )
            else:
                session_user_row = await db.scalar(
                    select(UserModel).where(UserModel.id == session_row.user_id)
                )
                inst_row = await db.scalar(select(InstanceModel))
                expected_rec_epoch = inst_row.recovery_epoch if inst_row is not None else 1

                if ref_now >= session_row.expires_at.astimezone(
                    UTC
                ) or ref_now >= session_row.idle_expires_at.astimezone(UTC):
                    session_row.revoked_at = ref_now
                    session_row.revoke_reason = "expired"
                    session_row.updated_at = ref_now
                    raised_error = UnauthorizedError(
                        code="session_expired",
                        detail="Session has expired; please sign in again.",
                    )
                elif (
                    session_user_row is None
                    or session_user_row.status != "active"
                    or session_row.recovery_epoch != expected_rec_epoch
                ):
                    session_row.revoked_at = ref_now
                    session_row.revoke_reason = "epoch_or_status_invalidated"
                    session_row.updated_at = ref_now
                    raised_error = UnauthorizedError(
                        code="session_revoked",
                        detail="Session is no longer authorized; please sign in again.",
                    )
                elif require_csrf:
                    try:
                        validate_double_submit_csrf(
                            request,
                            public_base_url=self._public_base_url,
                            signing_key=self._csrf_signing_key,
                            expected_session_csrf_hash=session_row.csrf_secret_hash,
                        )
                    except ForbiddenError as csrf_exc:
                        await append_audit_entry(
                            db,
                            actor_type="user",
                            actor_id=session_user_row.id,
                            action="security.csrf_check",
                            target=request.url.path,
                            decision="deny",
                            reason_code=csrf_exc.code,
                            correlation_id=correlation_id,
                            client_ip=client_ip,
                            occurred_at=ref_now,
                        )
                        raised_error = csrf_exc

                if raised_error is None:
                    assert session_user_row is not None
                    if session_row.grant_epoch != session_user_row.grant_epoch:
                        session_row.grant_epoch = session_user_row.grant_epoch
                    session_row.last_seen_at = ref_now
                    session_row.idle_expires_at = min(
                        session_row.expires_at.astimezone(UTC),
                        ref_now + SESSION_IDLE_TIMEOUT,
                    )
                    session_row.updated_at = ref_now

                    incoming_csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
                    csrf_refreshed = False
                    if incoming_csrf_cookie and hmac.compare_digest(
                        hash_csrf_secret(incoming_csrf_cookie),
                        session_row.csrf_secret_hash,
                    ):
                        active_csrf_token = incoming_csrf_cookie
                    else:
                        active_csrf_token, new_csrf_hash = mint_session_csrf_token()
                        session_row.csrf_secret_hash = new_csrf_hash
                        csrf_refreshed = True

                    await db.flush()
                    db.expunge(session_user_row)
                    db.expunge(session_row)
                    return AuthenticatedContext(
                        user=session_user_row,
                        session=session_row,
                        csrf_token=active_csrf_token,
                        csrf_cookie_refreshed=csrf_refreshed,
                    )

        raise raised_error

    async def logout(
        self,
        ctx: AuthenticatedContext,
        *,
        client_ip: str,
        correlation_id: str,
    ) -> None:
        """Revoke the active authenticated session and audit logout (A-02)."""
        ref_now = self.now()
        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            row = await db.scalar(
                select(SessionModel).where(SessionModel.id == ctx.session.id).with_for_update()
            )
            if row is not None and row.revoked_at is None:
                row.revoked_at = ref_now
                row.revoke_reason = "logout"
                row.updated_at = ref_now
                row.version += 1
            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=ctx.user.id,
                action="auth.logout",
                target=f"session:{ctx.session.id}",
                decision="allow",
                reason_code="user_logout",
                correlation_id=correlation_id,
                client_ip=client_ip,
                occurred_at=ref_now,
            )

    async def step_up(
        self,
        ctx: AuthenticatedContext,
        payload: StepUpRequest,
        *,
        client_ip: str,
        user_agent: str | None,
        correlation_id: str,
    ) -> tuple[StepUpResponse, str]:
        """Verify password (+ TOTP if enrolled) and mint rotated 5m step-up session (A-02)."""
        ref_now = self.now()
        step_bucket = f"user_ip:{ctx.user.id}:{client_ip}"
        raised_error: Exception | None = None

        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            retry_after = await self._check_rate_limits(
                db,
                checks=[("step_up", step_bucket, STEP_UP_MAX_FAILURES)],
                now=ref_now,
            )
            if retry_after is not None:
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=ctx.user.id,
                    action="auth.step_up",
                    target=f"session:{ctx.session.id}",
                    decision="deny",
                    reason_code="rate_limited",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                raised_error = RateLimitedError(
                    code="rate_limited",
                    detail="Too many step-up attempts. Please wait before retrying.",
                    retry_after_seconds=retry_after,
                )
            else:
                user_row = await db.scalar(
                    select(UserModel).where(UserModel.id == ctx.user.id).with_for_update()
                )
                old_sess = await db.scalar(
                    select(SessionModel).where(SessionModel.id == ctx.session.id).with_for_update()
                )
                if user_row is None or old_sess is None or old_sess.revoked_at is not None:
                    raised_error = UnauthorizedError(
                        code="unauthenticated",
                        detail="Session is no longer active.",
                    )
                else:
                    pw_ok, _ = verify_password_and_check_rehash(
                        user_row.password_hash,
                        payload.password,
                        hasher=self._password_hasher,
                    )
                    if not pw_ok:
                        await self._record_rate_limit_failures(
                            db,
                            buckets=[("step_up", step_bucket)],
                            now=ref_now,
                        )
                        await append_audit_entry(
                            db,
                            actor_type="user",
                            actor_id=user_row.id,
                            action="auth.step_up",
                            target=f"session:{old_sess.id}",
                            decision="deny",
                            reason_code="invalid_credentials",
                            correlation_id=correlation_id,
                            client_ip=client_ip,
                            occurred_at=ref_now,
                        )
                        raised_error = UnauthorizedError(
                            code="invalid_credentials",
                            detail="Step-up password verification failed.",
                        )
                    elif user_row.mfa_enabled:
                        if payload.otp is None:
                            await self._record_rate_limit_failures(
                                db,
                                buckets=[("step_up", step_bucket)],
                                now=ref_now,
                            )
                            await append_audit_entry(
                                db,
                                actor_type="user",
                                actor_id=user_row.id,
                                action="auth.step_up",
                                target=f"session:{old_sess.id}",
                                decision="deny",
                                reason_code="mfa_otp_required",
                                correlation_id=correlation_id,
                                client_ip=client_ip,
                                occurred_at=ref_now,
                            )
                            raised_error = UnauthorizedError(
                                code="mfa_otp_required",
                                detail=(
                                    "6-digit TOTP code is required for step-up on MFA-enabled "
                                    "accounts."
                                ),
                            )
                        else:
                            cred_row = await db.scalar(
                                select(MfaCredentialModel)
                                .where(
                                    MfaCredentialModel.user_id == user_row.id,
                                    MfaCredentialModel.status == "active",
                                )
                                .with_for_update()
                            )
                            if cred_row is None:
                                raised_error = UnauthorizedError(
                                    code="invalid_credentials",
                                    detail="Active MFA credential not found.",
                                )
                            else:
                                raw_secret = await self._totp_vault.resolve_totp_secret(
                                    db,
                                    secret_ref=cred_row.secret_ref,
                                )
                                totp_ok, matched_step, replayed = verify_totp_code(
                                    raw_secret,
                                    otp=payload.otp,
                                    at_time=ref_now,
                                    last_used_timestep=cred_row.last_used_timestep,
                                )
                                if not totp_ok:
                                    await self._record_rate_limit_failures(
                                        db,
                                        buckets=[("step_up", step_bucket)],
                                        now=ref_now,
                                    )
                                    await append_audit_entry(
                                        db,
                                        actor_type="user",
                                        actor_id=user_row.id,
                                        action="auth.step_up",
                                        target=f"session:{old_sess.id}",
                                        decision="deny",
                                        reason_code=(
                                            "totp_replayed" if replayed else "invalid_totp"
                                        ),
                                        correlation_id=correlation_id,
                                        client_ip=client_ip,
                                        occurred_at=ref_now,
                                    )
                                    raised_error = UnauthorizedError(
                                        code="invalid_totp",
                                        detail="Invalid or already-used 6-digit TOTP code.",
                                    )
                                else:
                                    cred_row.last_used_timestep = matched_step
                                    cred_row.updated_at = ref_now

                    if raised_error is None:
                        old_sess.revoked_at = ref_now
                        old_sess.revoke_reason = "step_up_rotated"
                        old_sess.updated_at = ref_now

                        strength: AuthStrength = "mfa" if user_row.mfa_enabled else "password"
                        new_sess, raw_sess_tok, raw_csrf_tok = await self._mint_db_session(
                            db,
                            user=user_row,
                            recovery_epoch=old_sess.recovery_epoch,
                            auth_strength=strength,
                            step_up_at=ref_now,
                            client_ip=client_ip,
                            user_agent=user_agent,
                            now=ref_now,
                            absolute_expires_at=old_sess.expires_at.astimezone(UTC),
                        )
                        await append_audit_entry(
                            db,
                            actor_type="user",
                            actor_id=user_row.id,
                            action="auth.step_up",
                            target=f"session:{new_sess.id}",
                            decision="allow",
                            reason_code="step_up_verified",
                            correlation_id=correlation_id,
                            client_ip=client_ip,
                            occurred_at=ref_now,
                        )
                        return (
                            StepUpResponse(
                                session=_to_session_dto(new_sess),
                                csrf_token=raw_csrf_tok,
                                step_up_expires_at=ref_now + STEP_UP_VALIDITY_WINDOW,
                            ),
                            raw_sess_tok,
                        )

        raise raised_error

    async def recover_account(
        self,
        payload: RecoveryRequest,
        *,
        client_ip: str,
        user_agent: str | None,
        correlation_id: str,
    ) -> tuple[RecoveryResponse, str]:
        """Redeem a single-use recovery code to reset password, MFA & sessions (SEC-038)."""
        ref_now = self.now()
        ip_bucket = f"ip:{client_ip}"
        code_digest = hash_recovery_code(self._recovery_hmac_key, payload.single_use_code)
        raised_error: Exception | None = None

        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            retry_after = await self._check_rate_limits(
                db,
                checks=[("recovery", ip_bucket, RECOVERY_MAX_FAILURES)],
                now=ref_now,
            )
            if retry_after is not None:
                await append_audit_entry(
                    db,
                    actor_type="anonymous",
                    actor_id="anonymous",
                    action="auth.recovery",
                    target="recovery_code",
                    decision="deny",
                    reason_code="rate_limited",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                raised_error = RateLimitedError(
                    code="rate_limited",
                    detail="Too many account recovery attempts. Please wait before retrying.",
                    retry_after_seconds=retry_after,
                )
            else:
                code_row = await db.scalar(
                    select(RecoveryCodeModel)
                    .where(RecoveryCodeModel.code_hash == code_digest)
                    .with_for_update()
                )
                if (
                    code_row is None
                    or code_row.used_at is not None
                    or code_row.revoked_at is not None
                ):
                    await self._record_rate_limit_failures(
                        db,
                        buckets=[("recovery", ip_bucket)],
                        now=ref_now,
                    )
                    await append_audit_entry(
                        db,
                        actor_type="anonymous",
                        actor_id="anonymous",
                        action="auth.recovery",
                        target="recovery_code",
                        decision="deny",
                        reason_code=(
                            "recovery_code_replayed"
                            if (code_row is not None and code_row.used_at is not None)
                            else "invalid_recovery_code"
                        ),
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        occurred_at=ref_now,
                    )
                    raised_error = UnauthorizedError(
                        code="invalid_recovery_code",
                        detail="Invalid or already-used single-use recovery code.",
                    )
                else:
                    user_row = await db.scalar(
                        select(UserModel).where(UserModel.id == code_row.user_id).with_for_update()
                    )
                    normalized_ident = (
                        payload.identifier.strip().lower() if payload.identifier else None
                    )
                    ident_mismatch = (
                        normalized_ident is not None
                        and user_row is not None
                        and normalized_ident not in {user_row.username, user_row.email or ""}
                    )
                    if user_row is None or user_row.status != "active" or ident_mismatch:
                        await self._record_rate_limit_failures(
                            db,
                            buckets=[("recovery", ip_bucket)],
                            now=ref_now,
                        )
                        await append_audit_entry(
                            db,
                            actor_type="anonymous",
                            actor_id="anonymous",
                            action="auth.recovery",
                            target="recovery_code",
                            decision="deny",
                            reason_code="invalid_recovery_code",
                            correlation_id=correlation_id,
                            client_ip=client_ip,
                            occurred_at=ref_now,
                        )
                        raised_error = UnauthorizedError(
                            code="invalid_recovery_code",
                            detail="Invalid or already-used single-use recovery code.",
                        )
                    else:
                        validate_new_password_policy(
                            payload.new_password,
                            disallowed_substrings=(
                                user_row.display_name,
                                user_row.username,
                                user_row.email or "",
                            ),
                            field_name="new_password",
                        )

                        had_mfa = bool(user_row.mfa_enabled)
                        code_row.used_at = ref_now

                        # Revoke existing TOTP credentials & Z2 secret entries
                        mfa_rows = (
                            await db.scalars(
                                select(MfaCredentialModel)
                                .where(
                                    MfaCredentialModel.user_id == user_row.id,
                                    MfaCredentialModel.status.in_(("pending", "active")),
                                )
                                .with_for_update()
                            )
                        ).all()
                        for cred in mfa_rows:
                            cred.status = "revoked"
                            cred.revoked_at = ref_now
                            cred.updated_at = ref_now
                            cred.version += 1
                            await self._totp_vault.revoke_totp_secret(
                                db,
                                secret_ref=cred.secret_ref,
                                now=ref_now,
                            )

                        # Update password, bump grant_epoch, and revoke ALL prior sessions
                        user_row.password_hash = hash_password(
                            payload.new_password,
                            hasher=self._password_hasher,
                        )
                        user_row.mfa_enabled = False
                        user_row.grant_epoch += 1
                        user_row.version += 1
                        user_row.updated_at = ref_now

                        await db.execute(
                            update(SessionModel)
                            .where(
                                SessionModel.user_id == user_row.id,
                                SessionModel.revoked_at.is_(None),
                            )
                            .values(
                                revoked_at=ref_now,
                                revoke_reason="account_recovery",
                                updated_at=ref_now,
                            )
                        )

                        inst_row = await db.scalar(select(InstanceModel))
                        rec_epoch = inst_row.recovery_epoch if inst_row is not None else 1
                        new_sess, raw_sess_tok, raw_csrf_tok = await self._mint_db_session(
                            db,
                            user=user_row,
                            recovery_epoch=rec_epoch,
                            auth_strength="password",
                            step_up_at=ref_now,
                            client_ip=client_ip,
                            user_agent=user_agent,
                            now=ref_now,
                        )

                        await append_audit_entry(
                            db,
                            actor_type="user",
                            actor_id=user_row.id,
                            action="auth.recovery_used",
                            target=f"user:{user_row.id}",
                            decision="allow",
                            reason_code="single_use_recovery_redeemed",
                            correlation_id=correlation_id,
                            client_ip=client_ip,
                            metadata={
                                "severity": "high",
                                "grant_epoch": user_row.grant_epoch,
                                "mfa_reset": had_mfa,
                            },
                            occurred_at=ref_now,
                        )
                        await enqueue_outbox_event(
                            db,
                            EventEnvelope(
                                event_id=new_uuid7(now=ref_now),
                                type="identity.permission_revoked",
                                occurred_at=ref_now,
                                workspace_id=None,
                                aggregate_id=user_row.id,
                                aggregate_version=user_row.version,
                                correlation_id=correlation_id,
                                payload=SecurityIdentityEventPayload(
                                    target_id=user_row.id,
                                    reason_code="recovery_code_used",
                                ),
                            ),
                            now=ref_now,
                        )

                        return (
                            RecoveryResponse(
                                user=_to_user_dto(user_row),
                                session=_to_session_dto(new_sess),
                                csrf_token=raw_csrf_tok,
                                mfa_re_enrollment_required=bool(
                                    user_row.is_instance_owner or had_mfa
                                ),
                            ),
                            raw_sess_tok,
                        )

        raise raised_error

    async def get_me(self, ctx: AuthenticatedContext) -> MeResponse:
        """Return A-03 current principal profile, session metadata, MFA posture & grants."""
        from red2pr_control.iam.workspaces import load_principal_workspaces_and_memberships

        ref_now = self.now()
        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            remaining_codes = int(
                (
                    await db.scalar(
                        select(func.count())
                        .select_from(RecoveryCodeModel)
                        .where(
                            RecoveryCodeModel.user_id == ctx.user.id,
                            RecoveryCodeModel.used_at.is_(None),
                            RecoveryCodeModel.revoked_at.is_(None),
                        )
                    )
                )
                or 0
            )

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            telegram_link = await db.scalar(
                select(TelegramLinkModel)
                .where(
                    TelegramLinkModel.user_id == ctx.user.id,
                    TelegramLinkModel.revoked_at.is_(None),
                )
                .order_by(TelegramLinkModel.linked_at.desc())
                .limit(1)
            )
            pending_link = await db.scalar(
                select(TelegramLinkChallengeModel.id)
                .where(
                    TelegramLinkChallengeModel.user_id == ctx.user.id,
                    TelegramLinkChallengeModel.scope == "account_link",
                    TelegramLinkChallengeModel.used_at.is_(None),
                    TelegramLinkChallengeModel.expires_at > ref_now,
                )
                .limit(1)
            )

        workspaces, memberships, has_admin_role = await load_principal_workspaces_and_memberships(
            self._session_factory,
            user_id=ctx.user.id,
            now=ref_now,
        )

        step_up_until: datetime | None = None
        if ctx.session.step_up_at is not None and is_step_up_fresh(ctx.session, now=ref_now):
            step_up_until = ctx.session.step_up_at.astimezone(UTC) + STEP_UP_VALIDITY_WINDOW

        return MeResponse(
            user=_to_user_dto(ctx.user),
            session=_to_session_dto(ctx.session),
            is_instance_owner=ctx.user.is_instance_owner,
            mfa_enabled=ctx.user.mfa_enabled,
            mfa_required_for_privileged=bool(ctx.user.is_instance_owner or has_admin_role),
            step_up_valid_until=step_up_until,
            recovery_codes_remaining=min(20, remaining_codes),
            workspaces=workspaces,
            memberships=memberships,
            telegram_link=TelegramLinkSummary(
                status="linked"
                if telegram_link is not None
                else "pending"
                if pending_link is not None
                else "not_configured",
                linked_at=telegram_link.linked_at if telegram_link is not None else None,
            ),
            csrf_token=ctx.csrf_token,
        )

    async def list_my_sessions(self, ctx: AuthenticatedContext) -> SessionPage:
        """Return S-04 paginated active sessions for the current user (zero raw tokens)."""
        ref_now = self.now()
        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            rows = (
                await db.scalars(
                    select(SessionModel)
                    .where(
                        SessionModel.user_id == ctx.user.id,
                        SessionModel.revoked_at.is_(None),
                        SessionModel.expires_at > ref_now,
                        SessionModel.idle_expires_at > ref_now,
                    )
                    .order_by(SessionModel.created_at.desc(), SessionModel.id.desc())
                    .limit(100)
                )
            ).all()

        items = [
            SessionListItem(
                id=row.id,
                version=row.version,
                created_at=row.created_at,
                updated_at=row.updated_at,
                user_id=row.user_id,
                expires_at=row.expires_at,
                auth_strength=cast(AuthStrength, row.auth_strength),
                step_up_at=row.step_up_at,
                grant_epoch=row.grant_epoch,
                is_current=(row.id == ctx.session.id),
                last_seen_at=row.last_seen_at,
                idle_expires_at=row.idle_expires_at,
                client_ip=row.client_ip,
                user_agent_summary=row.user_agent,
            )
            for row in rows
        ]
        return SessionPage(items=items, next_cursor=None, snapshot_at=ref_now)

    async def revoke_my_session(
        self,
        ctx: AuthenticatedContext,
        *,
        session_id: str,
        client_ip: str,
        correlation_id: str,
    ) -> bool:
        """Revoke an active session owned by `ctx.user` (`404` if foreign/missing).

        Returns True iff the revoked session was the caller's current session.
        """
        ref_now = self.now()
        raised_error: Exception | None = None

        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            target_row = await db.scalar(
                select(SessionModel)
                .where(
                    SessionModel.id == session_id,
                    SessionModel.user_id == ctx.user.id,
                )
                .with_for_update()
            )
            if target_row is None:
                raised_error = NotFoundError(
                    code="session_not_found",
                    detail="Session not found.",
                )
            else:
                if target_row.revoked_at is None:
                    target_row.revoked_at = ref_now
                    target_row.revoke_reason = "user_revoked"
                    target_row.updated_at = ref_now
                    target_row.version += 1
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=ctx.user.id,
                    action="account.session_revoked",
                    target=f"session:{session_id}",
                    decision="allow",
                    reason_code="user_revoked_session",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                return session_id == ctx.session.id

        raise raised_error

    async def _require_fresh_step_up_or_audit_deny(
        self,
        db: AsyncSession,
        *,
        ctx: AuthenticatedContext,
        action: str,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> ForbiddenError | None:
        if is_step_up_fresh(ctx.session, now=now):
            return None
        await append_audit_entry(
            db,
            actor_type="user",
            actor_id=ctx.user.id,
            action=action,
            target=f"user:{ctx.user.id}",
            decision="deny",
            reason_code="step_up_required",
            correlation_id=correlation_id,
            client_ip=client_ip,
            occurred_at=now,
        )
        return ForbiddenError(
            code="step_up_required",
            detail=(
                "Fresh 5-minute step-up re-authentication is required before modifying "
                "privileged security settings."
            ),
        )

    async def enroll_mfa(
        self,
        ctx: AuthenticatedContext,
        payload: MfaEnrollRequest,
        *,
        client_ip: str,
        user_agent: str | None,
        correlation_id: str,
    ) -> tuple[MfaEnrollResponse, str | None]:
        """Begin (`{}`) or confirm (`{challenge_id, otp}`) TOTP MFA enrollment (A-03)."""
        ref_now = self.now()
        verify_bucket = f"user_ip:{ctx.user.id}:{client_ip}"
        raised_error: Exception | None = None

        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            step_err = await self._require_fresh_step_up_or_audit_deny(
                db,
                ctx=ctx,
                action="account.mfa_enroll",
                client_ip=client_ip,
                correlation_id=correlation_id,
                now=ref_now,
            )
            if step_err is not None:
                raised_error = step_err
            elif payload.challenge_id is None and payload.otp is None:
                # Stage 1: generate 160-bit TOTP key in Z2 vault & show secret ONCE ONLY
                stale_pending = (
                    await db.scalars(
                        select(MfaCredentialModel)
                        .where(
                            MfaCredentialModel.user_id == ctx.user.id,
                            MfaCredentialModel.status == "pending",
                        )
                        .with_for_update()
                    )
                ).all()
                for pending_row in stale_pending:
                    pending_row.status = "revoked"
                    pending_row.revoked_at = ref_now
                    pending_row.updated_at = ref_now
                    pending_row.version += 1
                    await self._totp_vault.revoke_totp_secret(
                        db,
                        secret_ref=pending_row.secret_ref,
                        now=ref_now,
                    )

                raw_secret, secret_base32 = generate_totp_secret()
                secret_ref = await self._totp_vault.store_totp_secret(
                    db,
                    plaintext=raw_secret,
                    now=ref_now,
                )
                account_label = ctx.user.email or ctx.user.username
                otpauth_uri = build_otpauth_uri(
                    secret_base32=secret_base32,
                    account_label=account_label,
                )
                expires_at = ref_now + MFA_ENROLL_CHALLENGE_TTL
                cred_row = MfaCredentialModel(
                    id=new_uuid7(now=ref_now),
                    user_id=ctx.user.id,
                    secret_ref=secret_ref,
                    status="pending",
                    last_used_timestep=None,
                    challenge_expires_at=expires_at,
                    enrolled_at=None,
                    revoked_at=None,
                    version=1,
                    created_at=ref_now,
                    updated_at=ref_now,
                )
                db.add(cred_row)
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=ctx.user.id,
                    action="account.mfa_enrollment_started",
                    target=f"mfa_credential:{cred_row.id}",
                    decision="allow",
                    reason_code="challenge_issued",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                return (
                    MfaEnrollResponse(
                        status="enrollment_pending",
                        challenge_id=cred_row.id,
                        secret_base32=secret_base32,
                        otpauth_uri=otpauth_uri,
                        expires_at=expires_at,
                    ),
                    None,
                )
            else:
                # Stage 2: confirm `{challenge_id, otp}`, activate MFA & mint 10 recovery codes
                assert payload.challenge_id is not None and payload.otp is not None
                retry_after = await self._check_rate_limits(
                    db,
                    checks=[("mfa_verify", verify_bucket, MFA_VERIFY_MAX_FAILURES)],
                    now=ref_now,
                )
                if retry_after is not None:
                    await append_audit_entry(
                        db,
                        actor_type="user",
                        actor_id=ctx.user.id,
                        action="account.mfa_enroll_confirm",
                        target=f"mfa_credential:{payload.challenge_id}",
                        decision="deny",
                        reason_code="rate_limited",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        occurred_at=ref_now,
                    )
                    raised_error = RateLimitedError(
                        code="rate_limited",
                        detail="Too many MFA verification attempts. Please wait before retrying.",
                        retry_after_seconds=retry_after,
                    )
                else:
                    pending_cred = await db.scalar(
                        select(MfaCredentialModel)
                        .where(
                            MfaCredentialModel.id == payload.challenge_id,
                            MfaCredentialModel.user_id == ctx.user.id,
                        )
                        .with_for_update()
                    )
                    if pending_cred is None:
                        raised_error = NotFoundError(
                            code="mfa_challenge_not_found",
                            detail="MFA enrollment challenge not found.",
                        )
                    elif pending_cred.status != "pending":
                        raised_error = ConflictError(
                            code="mfa_challenge_already_processed",
                            detail="MFA enrollment challenge is no longer pending.",
                        )
                    elif (
                        pending_cred.challenge_expires_at is not None
                        and ref_now >= pending_cred.challenge_expires_at.astimezone(UTC)
                    ):
                        pending_cred.status = "revoked"
                        pending_cred.revoked_at = ref_now
                        pending_cred.updated_at = ref_now
                        await self._totp_vault.revoke_totp_secret(
                            db,
                            secret_ref=pending_cred.secret_ref,
                            now=ref_now,
                        )
                        raised_error = GoneError(
                            code="mfa_challenge_expired",
                            detail="MFA enrollment challenge has expired; start enrollment again.",
                        )
                    else:
                        raw_secret = await self._totp_vault.resolve_totp_secret(
                            db,
                            secret_ref=pending_cred.secret_ref,
                        )
                        totp_ok, matched_step, replayed = verify_totp_code(
                            raw_secret,
                            otp=payload.otp,
                            at_time=ref_now,
                            last_used_timestep=pending_cred.last_used_timestep,
                        )
                        if not totp_ok:
                            await self._record_rate_limit_failures(
                                db,
                                buckets=[("mfa_verify", verify_bucket)],
                                now=ref_now,
                            )
                            await append_audit_entry(
                                db,
                                actor_type="user",
                                actor_id=ctx.user.id,
                                action="account.mfa_enroll_confirm",
                                target=f"mfa_credential:{pending_cred.id}",
                                decision="deny",
                                reason_code="totp_replayed" if replayed else "invalid_totp",
                                correlation_id=correlation_id,
                                client_ip=client_ip,
                                occurred_at=ref_now,
                            )
                            raised_error = UnauthorizedError(
                                code="invalid_totp",
                                detail="Invalid 6-digit TOTP verification code.",
                            )
                        else:
                            # Revoke any previously active TOTP credential (atomic rotation)
                            prior_active = (
                                await db.scalars(
                                    select(MfaCredentialModel)
                                    .where(
                                        MfaCredentialModel.user_id == ctx.user.id,
                                        MfaCredentialModel.status == "active",
                                    )
                                    .with_for_update()
                                )
                            ).all()
                            for old_active in prior_active:
                                old_active.status = "revoked"
                                old_active.revoked_at = ref_now
                                old_active.updated_at = ref_now
                                old_active.version += 1
                                await self._totp_vault.revoke_totp_secret(
                                    db,
                                    secret_ref=old_active.secret_ref,
                                    now=ref_now,
                                )
                            await db.flush()

                            pending_cred.status = "active"
                            pending_cred.enrolled_at = ref_now
                            pending_cred.last_used_timestep = matched_step
                            pending_cred.updated_at = ref_now
                            pending_cred.version += 1

                            user_row = await db.scalar(
                                select(UserModel)
                                .where(UserModel.id == ctx.user.id)
                                .with_for_update()
                            )
                            old_sess = await db.scalar(
                                select(SessionModel)
                                .where(SessionModel.id == ctx.session.id)
                                .with_for_update()
                            )
                            assert user_row is not None and old_sess is not None
                            user_row.mfa_enabled = True
                            user_row.version += 1
                            user_row.updated_at = ref_now

                            # Revoke any previous recovery code batches & issue 10 fresh codes
                            await db.execute(
                                update(RecoveryCodeModel)
                                .where(
                                    RecoveryCodeModel.user_id == user_row.id,
                                    RecoveryCodeModel.used_at.is_(None),
                                    RecoveryCodeModel.revoked_at.is_(None),
                                )
                                .values(revoked_at=ref_now)
                            )
                            batch_id = new_uuid7(now=ref_now)
                            generated_batch = generate_recovery_code_batch(self._recovery_hmac_key)
                            display_codes: list[str] = []
                            for display_code, code_hash in generated_batch:
                                display_codes.append(display_code)
                                db.add(
                                    RecoveryCodeModel(
                                        id=new_uuid7(now=ref_now),
                                        user_id=user_row.id,
                                        batch_id=batch_id,
                                        code_hash=code_hash,
                                        used_at=None,
                                        revoked_at=None,
                                        created_at=ref_now,
                                    )
                                )

                            old_sess.revoked_at = ref_now
                            old_sess.revoke_reason = "mfa_enrolled_rotated"
                            old_sess.updated_at = ref_now

                            new_sess, raw_sess_tok, raw_csrf_tok = await self._mint_db_session(
                                db,
                                user=user_row,
                                recovery_epoch=old_sess.recovery_epoch,
                                auth_strength="mfa",
                                step_up_at=ref_now,
                                client_ip=client_ip,
                                user_agent=user_agent,
                                now=ref_now,
                                absolute_expires_at=old_sess.expires_at.astimezone(UTC),
                            )
                            await append_audit_entry(
                                db,
                                actor_type="user",
                                actor_id=user_row.id,
                                action="account.mfa_enrolled",
                                target=f"mfa_credential:{pending_cred.id}",
                                decision="allow",
                                reason_code="mfa_activated",
                                correlation_id=correlation_id,
                                client_ip=client_ip,
                                occurred_at=ref_now,
                            )
                            return (
                                MfaEnrollResponse(
                                    status="active",
                                    user=_to_user_dto(user_row),
                                    session=_to_session_dto(new_sess),
                                    recovery_codes=display_codes,
                                    csrf_token=raw_csrf_tok,
                                ),
                                raw_sess_tok,
                            )

        raise raised_error

    async def delete_mfa(
        self,
        ctx: AuthenticatedContext,
        payload: MfaDeleteRequest,
        *,
        client_ip: str,
        user_agent: str | None,
        correlation_id: str,
    ) -> tuple[str, str]:
        """Disable MFA for non-privileged accounts; deny mandatory-policy bypass (ADR-034)."""
        from red2pr_control.iam.workspaces import load_principal_workspaces_and_memberships

        ref_now = self.now()
        _, _, has_admin_role = await load_principal_workspaces_and_memberships(
            self._session_factory,
            user_id=ctx.user.id,
            now=ref_now,
        )
        rec_bucket = f"user_ip:{ctx.user.id}:{client_ip}"
        code_digest = hash_recovery_code(self._recovery_hmac_key, payload.recovery_authorization)
        raised_error: Exception | None = None

        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            step_err = await self._require_fresh_step_up_or_audit_deny(
                db,
                ctx=ctx,
                action="account.mfa_disable",
                client_ip=client_ip,
                correlation_id=correlation_id,
                now=ref_now,
            )
            if step_err is not None:
                raised_error = step_err
            elif ctx.user.is_instance_owner or has_admin_role:
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=ctx.user.id,
                    action="account.mfa_disable",
                    target=f"user:{ctx.user.id}",
                    decision="deny",
                    reason_code="mfa_policy_mandatory",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                await enqueue_outbox_event(
                    db,
                    EventEnvelope(
                        event_id=new_uuid7(now=ref_now),
                        type="security.policy.denied",
                        occurred_at=ref_now,
                        workspace_id=None,
                        aggregate_id=ctx.user.id,
                        aggregate_version=ctx.user.version,
                        correlation_id=correlation_id,
                        payload=SecurityIdentityEventPayload(
                            target_id=ctx.user.id,
                            reason_code="mfa_policy_mandatory",
                        ),
                    ),
                    now=ref_now,
                )
                raised_error = ForbiddenError(
                    code="mfa_policy_mandatory",
                    detail=(
                        "Multi-factor authentication is mandatory for privileged accounts and "
                        "cannot be disabled. Enroll a replacement authenticator instead."
                    ),
                )
            else:
                retry_after = await self._check_rate_limits(
                    db,
                    checks=[("recovery", rec_bucket, RECOVERY_MAX_FAILURES)],
                    now=ref_now,
                )
                if retry_after is not None:
                    raised_error = RateLimitedError(
                        code="rate_limited",
                        detail="Too many MFA disable attempts. Please wait before retrying.",
                        retry_after_seconds=retry_after,
                    )
                else:
                    code_row = await db.scalar(
                        select(RecoveryCodeModel)
                        .where(
                            RecoveryCodeModel.user_id == ctx.user.id,
                            RecoveryCodeModel.code_hash == code_digest,
                        )
                        .with_for_update()
                    )
                    if (
                        code_row is None
                        or code_row.used_at is not None
                        or code_row.revoked_at is not None
                    ):
                        await self._record_rate_limit_failures(
                            db,
                            buckets=[("recovery", rec_bucket)],
                            now=ref_now,
                        )
                        await append_audit_entry(
                            db,
                            actor_type="user",
                            actor_id=ctx.user.id,
                            action="account.mfa_disable",
                            target=f"user:{ctx.user.id}",
                            decision="deny",
                            reason_code="invalid_recovery_code",
                            correlation_id=correlation_id,
                            client_ip=client_ip,
                            occurred_at=ref_now,
                        )
                        raised_error = UnauthorizedError(
                            code="invalid_recovery_code",
                            detail="Invalid or already-used recovery authorization code.",
                        )
                    else:
                        code_row.used_at = ref_now
                        active_creds = (
                            await db.scalars(
                                select(MfaCredentialModel)
                                .where(
                                    MfaCredentialModel.user_id == ctx.user.id,
                                    MfaCredentialModel.status.in_(("pending", "active")),
                                )
                                .with_for_update()
                            )
                        ).all()
                        for cred in active_creds:
                            cred.status = "revoked"
                            cred.revoked_at = ref_now
                            cred.updated_at = ref_now
                            cred.version += 1
                            await self._totp_vault.revoke_totp_secret(
                                db,
                                secret_ref=cred.secret_ref,
                                now=ref_now,
                            )

                        await db.execute(
                            update(RecoveryCodeModel)
                            .where(
                                RecoveryCodeModel.user_id == ctx.user.id,
                                RecoveryCodeModel.used_at.is_(None),
                                RecoveryCodeModel.revoked_at.is_(None),
                            )
                            .values(revoked_at=ref_now)
                        )

                        user_row = await db.scalar(
                            select(UserModel).where(UserModel.id == ctx.user.id).with_for_update()
                        )
                        old_sess = await db.scalar(
                            select(SessionModel)
                            .where(SessionModel.id == ctx.session.id)
                            .with_for_update()
                        )
                        assert user_row is not None and old_sess is not None
                        user_row.mfa_enabled = False
                        user_row.version += 1
                        user_row.updated_at = ref_now

                        old_sess.revoked_at = ref_now
                        old_sess.revoke_reason = "mfa_disabled_rotated"
                        old_sess.updated_at = ref_now

                        _, raw_sess_tok, raw_csrf_tok = await self._mint_db_session(
                            db,
                            user=user_row,
                            recovery_epoch=old_sess.recovery_epoch,
                            auth_strength="password",
                            step_up_at=ref_now,
                            client_ip=client_ip,
                            user_agent=user_agent,
                            now=ref_now,
                            absolute_expires_at=old_sess.expires_at.astimezone(UTC),
                        )
                        await append_audit_entry(
                            db,
                            actor_type="user",
                            actor_id=user_row.id,
                            action="account.mfa_disabled",
                            target=f"user:{user_row.id}",
                            decision="allow",
                            reason_code="recovery_authorized_disable",
                            correlation_id=correlation_id,
                            client_ip=client_ip,
                            occurred_at=ref_now,
                        )
                        return raw_sess_tok, raw_csrf_tok

        raise raised_error
