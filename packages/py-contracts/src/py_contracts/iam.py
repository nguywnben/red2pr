"""Canonical IAM, workspace, membership, and invitation contracts (S-06, S-07).

Implements:
- S-06: User and Session DTOs (normalized email, no password hash or raw token fields).
- S-07: Workspace, Membership (including 'auditor' per ADR-038), and Invite DTOs.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field, StrictBool, StrictStr

from py_contracts.primitives import (
    BoundedName,
    InstanceResourceBase,
    InternalId,
    PositiveVersion,
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
