"""Canonical IAM, auth, MFA, workspace, membership & invite contracts (S-06, S-07, A-01..A-03).

Implements:
- S-06: User and Session DTOs (normalized email, no password hash or raw token fields).
- S-07: Workspace, Membership (including 'auditor' per ADR-038), and Invite DTOs.
- A-01 (claim), A-02 (login/logout/step-up/recovery), A-03 (/me, /me/sessions, /me/mfa) wire DTOs.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal, Self

from pydantic import BeforeValidator, Field, StrictBool, StrictInt, StrictStr, model_validator

from py_contracts.primitives import (
    BoundedName,
    InstanceResourceBase,
    InternalId,
    Page,
    PositiveVersion,
    StrictContractModel,
    UtcTimestamp,
    WorkspaceResourceBase,
)

_EMAIL_RE = re.compile(r"^[^@\s\x00-\x1f\x7f]+@[^@\s\x00-\x1f\x7f]+\.[^@\s\x00-\x1f\x7f]+$")


def _normalize_email(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Email must be a string")
    normalized = value.strip().lower()
    if not normalized or len(normalized) > 254 or not _EMAIL_RE.fullmatch(normalized):
        raise ValueError("Invalid email address")
    return normalized


NormalizedEmail = Annotated[StrictStr, BeforeValidator(_normalize_email)]
CsrfTokenStr = Annotated[StrictStr, Field(min_length=16, max_length=256)]
OtpCodeStr = Annotated[StrictStr, Field(pattern=r"^\d{6}$")]
NewPasswordStr = Annotated[StrictStr, Field(min_length=12, max_length=256)]
LoginPasswordStr = Annotated[StrictStr, Field(min_length=1, max_length=256)]
RecoveryCodeStr = Annotated[StrictStr, Field(min_length=8, max_length=128)]

UserStatus = Literal["active", "disabled"]
AuthStrength = Literal["password", "mfa"]
WorkspaceStatus = Literal["active", "suspended", "deleting"]
WorkspaceRole = Literal["admin", "maintainer", "reviewer", "viewer", "auditor"]
InviteStatus = Literal["pending", "accepted", "expired", "revoked"]


class User(InstanceResourceBase):
    """S-06 user profile DTO (never exposes password hashes or secret credentials)."""

    display_name: BoundedName
    email: NormalizedEmail | None = None
    status: UserStatus


class Session(InstanceResourceBase):
    """S-06 authenticated session metadata DTO (never exposes raw session cookie token)."""

    user_id: InternalId
    expires_at: UtcTimestamp
    auth_strength: AuthStrength
    step_up_at: UtcTimestamp | None = None
    grant_epoch: PositiveVersion


class Workspace(InstanceResourceBase):
    """S-07 multi-workspace tenant resource (ADR-030)."""

    name: BoundedName
    status: WorkspaceStatus
    paused: StrictBool = False


class Membership(WorkspaceResourceBase):
    """S-07 workspace role assignment with scoped repository grants (ADR-038)."""

    user_id: InternalId
    role: WorkspaceRole
    repository_grants: list[InternalId] = Field(default_factory=list)


class Invite(WorkspaceResourceBase):
    """S-07 identity-bound workspace invitation metadata (never exposes raw invite token)."""

    email: NormalizedEmail
    role: WorkspaceRole
    expires_at: UtcTimestamp
    status: InviteStatus


class CsrfBootstrapResponse(StrictContractModel):
    """CSRF synchronizer/double-submit bootstrap state for pre-auth and session forms."""

    csrf_token: CsrfTokenStr
    bootstrap_claim_required: StrictBool


class SetupClaimRequest(StrictContractModel):
    """A-01 one-time expiring instance-owner bootstrap claim input."""

    bootstrap_token: Annotated[StrictStr, Field(min_length=16, max_length=256)]
    password: NewPasswordStr
    display_name: BoundedName
    email: NormalizedEmail | None = None


class SetupClaimResponse(StrictContractModel):
    """A-01 instance-owner claim response returning S-06 User + Session metadata."""

    user: User
    session: Session
    csrf_token: CsrfTokenStr
    is_instance_owner: StrictBool = True


class LoginRequest(StrictContractModel):
    """A-02 local password + optional TOTP MFA login input."""

    identifier: Annotated[StrictStr, Field(min_length=1, max_length=254)]
    password: LoginPasswordStr
    otp: OtpCodeStr | None = None
    mfa_challenge_id: InternalId | None = None


class LoginResponse(StrictContractModel):
    """A-02 login result: either authenticated S-06 session or cookie-free MFA challenge."""

    status: Literal["authenticated", "mfa_required"]
    user: User | None = None
    session: Session | None = None
    mfa_challenge_id: InternalId | None = None
    csrf_token: CsrfTokenStr | None = None

    @model_validator(mode="after")
    def _validate_login_outcome_shape(self) -> Self:
        if self.status == "authenticated":
            if self.user is None or self.session is None or self.csrf_token is None:
                raise ValueError("authenticated LoginResponse requires user, session, csrf_token")
            if self.mfa_challenge_id is not None:
                raise ValueError("authenticated LoginResponse must not carry mfa_challenge_id")
        else:
            if self.mfa_challenge_id is None:
                raise ValueError("mfa_required LoginResponse requires mfa_challenge_id")
            if self.user is not None or self.session is not None:
                raise ValueError("mfa_required LoginResponse must never expose user or session")
        return self


class LogoutRequest(StrictContractModel):
    """A-02 explicit logout request body."""


class StepUpRequest(StrictContractModel):
    """A-02 5-minute privileged step-up re-authentication input."""

    password: LoginPasswordStr
    otp: OtpCodeStr | None = None


class StepUpResponse(StrictContractModel):
    """A-02 5-minute step-up confirmation with rotated session metadata."""

    session: Session
    csrf_token: CsrfTokenStr
    step_up_expires_at: UtcTimestamp


class RecoveryRequest(StrictContractModel):
    """A-02 single-use recovery code emergency password & MFA reset input (SEC-038)."""

    single_use_code: RecoveryCodeStr
    new_password: NewPasswordStr
    identifier: Annotated[StrictStr, Field(min_length=1, max_length=254)] | None = None


class RecoveryResponse(StrictContractModel):
    """A-02 single-use recovery outcome with rotated session and re-enrollment flag."""

    user: User
    session: Session
    csrf_token: CsrfTokenStr
    mfa_re_enrollment_required: StrictBool


class TelegramLinkSummary(StrictContractModel):
    """Honest personal Telegram link status summary on /account until U20 (NOT-02)."""

    status: Literal["not_configured", "pending", "linked"] = "not_configured"


class MeResponse(StrictContractModel):
    """A-03 current principal profile, session, MFA posture, and workspace grants."""

    user: User
    session: Session
    is_instance_owner: StrictBool
    mfa_enabled: StrictBool
    mfa_required_for_privileged: StrictBool
    step_up_valid_until: UtcTimestamp | None = None
    recovery_codes_remaining: Annotated[StrictInt, Field(ge=0, le=20)]
    workspaces: list[Workspace] = Field(default_factory=list)
    memberships: list[Membership] = Field(default_factory=list)
    telegram_link: TelegramLinkSummary = Field(default_factory=TelegramLinkSummary)
    csrf_token: CsrfTokenStr


class SessionListItem(Session):
    """A-03 active session row extending S-06 Session with safe non-secret metadata."""

    is_current: StrictBool
    last_seen_at: UtcTimestamp
    idle_expires_at: UtcTimestamp
    client_ip: BoundedName | None = None
    user_agent_summary: BoundedName | None = None


SessionPage = Page[SessionListItem]


class MfaEnrollRequest(StrictContractModel):
    """A-03 TOTP MFA enrollment request: `{}` to begin, `{challenge_id, otp}` to confirm."""

    challenge_id: InternalId | None = None
    otp: OtpCodeStr | None = None

    @model_validator(mode="after")
    def _validate_enrollment_stage(self) -> Self:
        if (self.challenge_id is None) != (self.otp is None):
            raise ValueError(
                "MfaEnrollRequest must be either empty `{}` or supply both challenge_id and otp"
            )
        return self


class MfaEnrollResponse(StrictContractModel):
    """A-03 TOTP MFA enrollment response (secret and recovery codes shown once only)."""

    status: Literal["enrollment_pending", "active"]
    challenge_id: InternalId | None = None
    secret_base32: Annotated[StrictStr, Field(min_length=16, max_length=128)] | None = None
    otpauth_uri: Annotated[StrictStr, Field(min_length=20, max_length=512)] | None = None
    expires_at: UtcTimestamp | None = None
    user: User | None = None
    session: Session | None = None
    recovery_codes: list[Annotated[StrictStr, Field(min_length=8, max_length=64)]] | None = None
    csrf_token: CsrfTokenStr | None = None

    @model_validator(mode="after")
    def _validate_once_only_fields(self) -> Self:
        if self.status == "enrollment_pending":
            if (
                self.challenge_id is None
                or self.secret_base32 is None
                or self.otpauth_uri is None
                or self.expires_at is None
            ):
                raise ValueError(
                    "enrollment_pending response requires challenge_id, secret_base32, "
                    "otpauth_uri, and expires_at"
                )
            if self.recovery_codes is not None or self.user is not None or self.session is not None:
                raise ValueError("enrollment_pending response must not carry active MFA fields")
        else:
            if (
                self.user is None
                or self.session is None
                or self.recovery_codes is None
                or self.csrf_token is None
            ):
                raise ValueError(
                    "active MFA enrollment response requires user, session, recovery_codes, "
                    "and csrf_token"
                )
            if self.secret_base32 is not None or self.otpauth_uri is not None:
                raise ValueError("active MFA enrollment response must never re-expose TOTP secret")
        return self


class MfaDeleteRequest(StrictContractModel):
    """A-03 MFA disable request requiring step-up + single-use recovery code authorization."""

    recovery_authorization: RecoveryCodeStr
