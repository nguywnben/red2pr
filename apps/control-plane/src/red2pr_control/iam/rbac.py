"""Server-enforced multi-workspace RBAC, repo-grant intersection & signed S-04 cursors.

Implements Unit U06 (`IAM-02`, `S-02`, `S-04`, `ADR-030`, `ADR-034`, `ADR-038`,
`SEC-010`, `SEC-022`, `SEC-032`):
- Deny-by-default authorization: `installation ∩ workspace_membership ∩ repo_grant ∩ policy`.
- `instance_owner` never implicitly receives read/write access to workspace repositories
  or members without an explicit `Membership` or an active, unexpired, audited
  `BreakGlassGrant` (`ADR-034`).
- Consistent `404 workspace_not_found` / `404 repository_not_found` anti-enumeration
  responses when a principal has zero access to a workspace or repository (`SEC-010`,
  `SEC-032`), and audited `403 insufficient_role` when a workspace member lacks the
  required role (`SEC-022`).
- HMAC-SHA256 signed `S-04` pagination cursors binding `(workspace_id, principal_id,
  grant_epoch, query_hash, expires_at, created_at, id)` (`410 cursor_expired` on TTL
  expiry or `grant_epoch` invalidation; `400 invalid_cursor` on cross-workspace or
  query tampering).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from collections.abc import Collection
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal, cast

from fastapi import Depends, Path, Request
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.crypto import canonical_json_bytes, sha256_canonical_json
from py_contracts.events import EventEnvelope, SecurityIdentityEventPayload
from py_contracts.iam import WorkspaceRole, WorkspaceSlugStr
from py_contracts.primitives import InternalId, new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    BadRequestError,
    ConflictError,
    ForbiddenError,
    GoneError,
    NotFoundError,
    PreconditionFailedError,
)
from red2pr_control.core.logging import current_correlation_id
from red2pr_control.db.base import (
    BreakGlassGrantModel,
    MembershipModel,
    RepoGrantModel,
    WorkspaceModel,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.sessions import (
    AuthenticatedContext,
    IamService,
    extract_client_ip,
)

ALL_WORKSPACE_ROLES: frozenset[WorkspaceRole] = frozenset(
    {"admin", "maintainer", "reviewer", "viewer", "auditor"}
)
ADMIN_ONLY_ROLES: frozenset[WorkspaceRole] = frozenset({"admin"})
ADMIN_OR_AUDITOR_ROLES: frozenset[WorkspaceRole] = frozenset({"admin", "auditor"})

ROLE_PRIVILEGE_RANK: dict[WorkspaceRole, int] = {
    "viewer": 10,
    "auditor": 15,
    "reviewer": 20,
    "maintainer": 30,
    "admin": 40,
}

DEFAULT_CURSOR_TTL = timedelta(hours=1)

_UUID_ADAPTER: TypeAdapter[str] = TypeAdapter(InternalId)
_SLUG_ADAPTER: TypeAdapter[str] = TypeAdapter(WorkspaceSlugStr)
_ETAG_VERSION_RE = re.compile(r'^(?:W/)?"?v?([1-9][0-9]*)"?$')


def derive_iam_subkey(master_key: bytes, *, context: bytes) -> bytes:
    """Derive a domain-separated 32-byte HMAC subkey from `IamService.csrf_signing_key`."""
    return hmac.new(master_key, context, hashlib.sha256).digest()


def format_version_etag(version: int) -> str:
    """Format an optimistic concurrency entity tag (`S-02`)."""
    return f'"v{version}"'


def parse_if_match_version(if_match_header: str | None) -> int | None:
    """Parse optional `If-Match` header into an integer version (`400` if malformed)."""
    if if_match_header is None:
        return None
    cleaned = if_match_header.strip()
    if not cleaned:
        return None
    if cleaned == "*":
        return None
    match = _ETAG_VERSION_RE.fullmatch(cleaned)
    if match is None:
        raise BadRequestError(
            code="invalid_if_match",
            detail="Malformed If-Match header; expected entity version tag such as '\"v1\"'.",
        )
    return int(match.group(1))


def enforce_optimistic_version(
    *,
    current_version: int,
    if_match_header: str | None = None,
    expected_version: int | None = None,
) -> None:
    """Enforce S-02 `If-Match` (`412`) and body `expected_version` (`409`) concurrency guards."""
    parsed_if_match = parse_if_match_version(if_match_header)
    if parsed_if_match is not None and parsed_if_match != current_version:
        raise PreconditionFailedError(
            code="version_precondition_failed",
            detail=(
                f"Resource version is {current_version}, which does not match "
                f"If-Match version {parsed_if_match}."
            ),
        )
    if expected_version is not None and expected_version != current_version:
        raise ConflictError(
            code="version_conflict",
            detail=(
                f"Resource version is {current_version}, which does not match "
                f"expected_version {expected_version}."
            ),
        )


@dataclass(frozen=True)
class DecodedSignedCursor:
    """Verified S-04 keyset pagination cursor."""

    workspace_scope: str
    principal_id: str
    grant_epoch: int
    query_hash: str
    expires_at: datetime
    created_at: datetime
    item_id: str


def compute_query_filter_hash(filters: dict[str, Any]) -> str:
    """Compute canonical SHA-256 digest of query filter parameters (`S-04`)."""
    return sha256_canonical_json(filters)


def encode_signed_cursor(
    *,
    signing_key: bytes,
    workspace_scope: str,
    principal_id: str,
    grant_epoch: int,
    query_hash: str,
    created_at: datetime,
    item_id: str,
    now: datetime,
    ttl: timedelta = DEFAULT_CURSOR_TTL,
) -> str:
    """Encode an opaque HMAC-SHA256 signed S-04 pagination cursor."""
    subkey = derive_iam_subkey(signing_key, context=b"red2pr:s04-cursor:v1")
    exp_dt = now.astimezone(UTC) + ttl
    payload_obj = {
        "exp": int(exp_dt.timestamp()),
        "ge": grant_epoch,
        "id": item_id,
        "qh": query_hash,
        "ts": created_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "uid": principal_id,
        "v": 1,
        "ws": workspace_scope,
    }
    raw_bytes = canonical_json_bytes(payload_obj)
    b64_payload = base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")
    sig_hex = hmac.new(subkey, b64_payload.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{b64_payload}.{sig_hex}"


def decode_signed_cursor(
    raw_cursor: str,
    *,
    signing_key: bytes,
    expected_workspace_scope: str,
    expected_principal_id: str,
    current_grant_epoch: int,
    expected_query_hash: str,
    now: datetime,
) -> DecodedSignedCursor:
    """Verify HMAC signature, workspace scope, principal, grant_epoch, query hash, and TTL."""
    if not raw_cursor or "." not in raw_cursor or len(raw_cursor) > 1024:
        raise BadRequestError(
            code="invalid_cursor",
            detail="Malformed pagination cursor.",
        )

    b64_part, sig_part = raw_cursor.split(".", 1)
    if not b64_part or len(sig_part) != 64:
        raise BadRequestError(
            code="invalid_cursor",
            detail="Malformed pagination cursor.",
        )

    subkey = derive_iam_subkey(signing_key, context=b"red2pr:s04-cursor:v1")
    expected_sig = hmac.new(subkey, b64_part.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig_part, expected_sig):
        raise BadRequestError(
            code="invalid_cursor",
            detail="Pagination cursor signature verification failed.",
        )

    padding = "=" * ((4 - (len(b64_part) % 4)) % 4)
    try:
        decoded_bytes = base64.urlsafe_b64decode(b64_part + padding)
        parsed = json.loads(decoded_bytes.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BadRequestError(
            code="invalid_cursor",
            detail="Malformed pagination cursor payload.",
        ) from exc

    if not isinstance(parsed, dict) or parsed.get("v") != 1:
        raise BadRequestError(
            code="invalid_cursor",
            detail="Unsupported pagination cursor version.",
        )

    ws_scope = parsed.get("ws")
    uid = parsed.get("uid")
    grant_epoch = parsed.get("ge")
    query_hash = parsed.get("qh")
    exp_ts = parsed.get("exp")
    ts_raw = parsed.get("ts")
    item_id = parsed.get("id")

    if (
        not isinstance(ws_scope, str)
        or not isinstance(uid, str)
        or not isinstance(grant_epoch, int)
        or not isinstance(query_hash, str)
        or not isinstance(exp_ts, int)
        or not isinstance(ts_raw, str)
        or not isinstance(item_id, str)
    ):
        raise BadRequestError(
            code="invalid_cursor",
            detail="Invalid pagination cursor fields.",
        )

    # Cross-workspace cursor tampering is deterministically rejected (SEC-032).
    if ws_scope != expected_workspace_scope:
        raise BadRequestError(
            code="invalid_cursor",
            detail="Pagination cursor does not belong to this workspace scope.",
        )

    if uid != expected_principal_id:
        raise ForbiddenError(
            code="cursor_principal_mismatch",
            detail="Pagination cursor is bound to a different authenticated principal.",
        )

    if query_hash != expected_query_hash:
        raise BadRequestError(
            code="cursor_query_mismatch",
            detail="Pagination cursor cannot be reused with modified filter parameters.",
        )

    expires_at = datetime.fromtimestamp(exp_ts, tz=UTC)
    ref_now = now.astimezone(UTC)
    if ref_now >= expires_at or grant_epoch != current_grant_epoch:
        raise GoneError(
            code="cursor_expired",
            detail="Pagination cursor has expired or permissions changed; refetch first page.",
        )

    try:
        created_at = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).astimezone(UTC)
        validated_id = _UUID_ADAPTER.validate_python(item_id)
    except (ValueError, ValidationError) as exc:
        raise BadRequestError(
            code="invalid_cursor",
            detail="Malformed timestamp or identifier in pagination cursor.",
        ) from exc

    return DecodedSignedCursor(
        workspace_scope=ws_scope,
        principal_id=uid,
        grant_epoch=grant_epoch,
        query_hash=query_hash,
        expires_at=expires_at,
        created_at=created_at,
        item_id=validated_id,
    )


def parse_workspace_identifier_or_404(raw_ws: str) -> tuple[Literal["id", "slug"], str]:
    """Classify `{ws}` path parameter as canonical UUID `id` or `slug` (`404` otherwise)."""
    candidate = raw_ws.strip()
    if not candidate or len(candidate) > 120:
        raise NotFoundError(code="workspace_not_found", detail="Workspace not found.")
    try:
        validated_uuid = _UUID_ADAPTER.validate_python(candidate)
        return ("id", validated_uuid)
    except ValidationError:
        pass
    try:
        validated_slug = _SLUG_ADAPTER.validate_python(candidate)
        return ("slug", validated_slug)
    except ValidationError as exc:
        raise NotFoundError(code="workspace_not_found", detail="Workspace not found.") from exc


@dataclass(frozen=True)
class WorkspaceAccessContext:
    """Authoritative per-request workspace RBAC & repository grant context."""

    auth: AuthenticatedContext
    workspace: WorkspaceModel
    membership: MembershipModel | None
    repository_grants: frozenset[str]
    break_glass_grant: BreakGlassGrantModel | None

    @property
    def workspace_id(self) -> str:
        return self.workspace.id

    @property
    def effective_role(self) -> WorkspaceRole | Literal["break_glass"]:
        if self.membership is not None:
            return cast(WorkspaceRole, self.membership.role)
        return "break_glass"

    @property
    def has_workspace_wide_repo_read(self) -> bool:
        """True only for workspace `admin` or active time-bounded break-glass read grant."""
        if getattr(self.auth, "api_token", None) is not None:
            return False
        if self.membership is not None and self.membership.role == "admin":
            return True
        return self.break_glass_grant is not None

    def can_read_repository(self, repository_id: str) -> bool:
        """Enforce deny-by-default repository read visibility (`ADR-030`, `SEC-010`)."""
        if self.has_workspace_wide_repo_read:
            return True
        return repository_id in self.repository_grants

    def can_act_on_repository(
        self,
        repository_id: str,
        *,
        allowed_roles: Collection[WorkspaceRole],
    ) -> bool:
        """Enforce repository mutation/action authorization (break-glass is read-only)."""
        if self.membership is None:
            return False
        role = cast(WorkspaceRole, self.membership.role)
        if role not in allowed_roles:
            return False
        if role == "admin":
            return (
                repository_id in self.repository_grants
                if getattr(self.auth, "api_token", None) is not None
                else True
            )
        return repository_id in self.repository_grants


_API_TOKEN_ACTION_SCOPES: dict[str, str] = {
    "notification.read": "notifications:read",
    "notification.manage": "notifications:write",
    "repair.read": "repairs:read",
    "repair.action": "repairs:write",
    "integration.read": "integrations:read",
    "integration.mutate": "integrations:write",
    "sse.subscribe": "events:read",
}


async def load_workspace_by_identifier(
    db: AsyncSession,
    raw_ws: str,
    *,
    include_deleting: bool = False,
) -> WorkspaceModel | None:
    """Resolve `WorkspaceModel` by UUID `id` or `slug` under `instance_admin` RLS."""
    kind, value = parse_workspace_identifier_or_404(raw_ws)
    stmt = select(WorkspaceModel).where(
        WorkspaceModel.id == value if kind == "id" else WorkspaceModel.slug == value
    )
    if not include_deleting:
        stmt = stmt.where(
            WorkspaceModel.status != "deleting",
            WorkspaceModel.deleted_at.is_(None),
        )
    return cast(WorkspaceModel | None, await db.scalar(stmt))


async def authorize_workspace_access(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    auth: AuthenticatedContext,
    raw_ws: str,
    allowed_roles: Collection[WorkspaceRole],
    allow_break_glass: bool,
    action: str,
    client_ip: str,
    correlation_id: str,
    now: datetime,
) -> WorkspaceAccessContext:
    """Enforce server-side workspace RBAC & anti-enumeration (`404` non-member, `403` role).

    Critically (`ADR-034`): `auth.user.is_instance_owner` NEVER bypasses workspace
    membership or active break-glass requirements on workspace data endpoints.
    """
    ref_now = now.astimezone(UTC)
    api_token = getattr(auth, "api_token", None)

    async with instance_rls_session(session_factory, mode="instance_admin") as db:
        ws_row = await load_workspace_by_identifier(db, raw_ws)
        if ws_row is None:
            await append_audit_entry(
                db,
                actor_type="user",
                actor_id=auth.user.id,
                action=action,
                target=f"workspace:{raw_ws[:120]}",
                decision="deny",
                reason_code="workspace_not_found",
                correlation_id=correlation_id,
                client_ip=client_ip,
                occurred_at=ref_now,
            )
            raise NotFoundError(code="workspace_not_found", detail="Workspace not found.")

        ws_id = ws_row.id
        db.expunge(ws_row)

    if api_token is not None and api_token.workspace_id != ws_id:
        raise NotFoundError(code="workspace_not_found", detail="Workspace not found.")

    # Execute membership, break-glass, and audit checks strictly inside workspace RLS!
    raised_error: Exception | None = None
    resolved_ctx: WorkspaceAccessContext | None = None

    async with workspace_rls_session(session_factory, workspace_id=ws_id) as ws_db:
        membership_row = await ws_db.scalar(
            select(MembershipModel).where(
                MembershipModel.workspace_id == ws_id,
                MembershipModel.user_id == auth.user.id,
            )
        )
        grant_ids: frozenset[str] = frozenset()
        if membership_row is not None:
            repo_rows = (
                await ws_db.scalars(
                    select(RepoGrantModel.repository_id).where(
                        RepoGrantModel.workspace_id == ws_id,
                        RepoGrantModel.membership_id == membership_row.id,
                    )
                )
            ).all()
            grant_ids = frozenset(repo_rows)

        bg_row: BreakGlassGrantModel | None = None
        if auth.user.is_instance_owner:
            bg_row = await ws_db.scalar(
                select(BreakGlassGrantModel)
                .where(
                    BreakGlassGrantModel.workspace_id == ws_id,
                    BreakGlassGrantModel.user_id == auth.user.id,
                    BreakGlassGrantModel.revoked_at.is_(None),
                    BreakGlassGrantModel.expires_at > ref_now,
                )
                .order_by(BreakGlassGrantModel.expires_at.desc())
                .limit(1)
            )

        if membership_row is None and bg_row is None:
            await append_audit_entry(
                ws_db,
                workspace_id=ws_id,
                actor_type="user",
                actor_id=auth.user.id,
                action=action,
                target=f"workspace:{ws_id}",
                decision="deny",
                reason_code="workspace_access_denied",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={"is_instance_owner": auth.user.is_instance_owner},
                occurred_at=ref_now,
            )
            raised_error = NotFoundError(
                code="workspace_not_found",
                detail="Workspace not found.",
            )
        else:
            if api_token is not None:
                required_scope = _API_TOKEN_ACTION_SCOPES.get(action)
                if required_scope is None or required_scope not in api_token.scopes:
                    await append_audit_entry(
                        ws_db,
                        workspace_id=ws_id,
                        actor_type="user",
                        actor_id=api_token.owner_user_id,
                        action=action,
                        target=f"workspace:{ws_id}",
                        decision="deny",
                        reason_code="api_token_scope_denied",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        metadata={
                            "required_scope": required_scope or "none",
                            "api_token_id": api_token.id,
                        },
                        occurred_at=ref_now,
                    )
                    raised_error = ForbiddenError(
                        code="api_token_scope_denied",
                        detail="API token scope does not permit this operation.",
                    )
            role_permitted = (
                membership_row is not None
                and cast(WorkspaceRole, membership_row.role) in allowed_roles
            )
            bg_permitted = allow_break_glass and bg_row is not None

            if raised_error is None and not role_permitted and not bg_permitted:
                reason = (
                    "break_glass_read_only"
                    if membership_row is None and bg_row is not None
                    else "insufficient_role"
                )
                await append_audit_entry(
                    ws_db,
                    workspace_id=ws_id,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action=action,
                    target=f"workspace:{ws_id}",
                    decision="deny",
                    reason_code=reason,
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={
                        "effective_role": (
                            membership_row.role if membership_row is not None else "break_glass"
                        ),
                        "required_roles": sorted(allowed_roles),
                    },
                    occurred_at=ref_now,
                )
                await enqueue_outbox_event(
                    ws_db,
                    EventEnvelope(
                        event_id=new_uuid7(now=ref_now),
                        type="security.policy.denied",
                        occurred_at=ref_now,
                        workspace_id=ws_id,
                        aggregate_id=auth.user.id,
                        aggregate_version=auth.user.version,
                        correlation_id=correlation_id,
                        payload=SecurityIdentityEventPayload(
                            target_id=auth.user.id,
                            reason_code=reason,
                        ),
                    ),
                    now=ref_now,
                )
                raised_error = ForbiddenError(
                    code=reason,
                    detail="Your workspace role does not permit this operation.",
                )
            elif raised_error is None:
                if membership_row is not None:
                    ws_db.expunge(membership_row)
                if bg_row is not None:
                    ws_db.expunge(bg_row)
                resolved_ctx = WorkspaceAccessContext(
                    auth=auth,
                    workspace=ws_row,
                    membership=membership_row,
                    repository_grants=(
                        grant_ids.intersection(api_token.repository_ids)
                        if api_token is not None
                        else grant_ids
                    ),
                    break_glass_grant=bg_row,
                )

    if raised_error is not None:
        raise raised_error
    assert resolved_ctx is not None
    return resolved_ctx


def _req_correlation_id(request: Request) -> str:
    state_corr = getattr(request.state, "correlation_id", None)
    if isinstance(state_corr, str) and state_corr:
        return state_corr
    return current_correlation_id()


def _resolve_iam_from_request(request: Request) -> IamService:
    from red2pr_control.core.errors import DependencyUnavailableError

    svc = getattr(request.app.state, "iam_service", None)
    if not isinstance(svc, IamService):
        raise DependencyUnavailableError(
            code="iam_unconfigured",
            detail="IAM persistence service is not configured on this control-plane instance.",
        )
    return svc


def make_workspace_rbac_dependency(
    *,
    allowed_roles: Collection[WorkspaceRole],
    require_csrf: bool,
    allow_break_glass: bool,
    action: str,
) -> Any:
    """Create a mandatory FastAPI server-side RBAC dependency for `/workspaces/{ws}` routes."""
    frozen_roles = frozenset(allowed_roles)

    async def _dependency(
        ws: Annotated[str, Path(min_length=1, max_length=120)],
        request: Request,
        iam: Annotated[IamService, Depends(_resolve_iam_from_request)],
    ) -> WorkspaceAccessContext:
        corr_id = _req_correlation_id(request)
        auth = await iam.authenticate_request(
            request,
            require_csrf=require_csrf,
            correlation_id=corr_id,
        )
        return await authorize_workspace_access(
            iam.session_factory,
            auth=auth,
            raw_ws=ws,
            allowed_roles=frozen_roles,
            allow_break_glass=allow_break_glass,
            action=action,
            client_ip=extract_client_ip(request),
            correlation_id=corr_id,
            now=iam.now(),
        )

    return _dependency
