"""Workspace memberships, scoped repo grants & single-use invitations (`A-05`, `SEC-038`).

Implements:
- `GET /api/v1/workspaces/{ws}/members`: cursor-paginated `Membership` list (`S-04`
  signed cursor bound to `workspace_id`, `principal_id`, `grant_epoch`, `query_hash`,
  `expires_at`).
- `GET /api/v1/workspaces/{ws}/invitations`: cursor-paginated `Invite` metadata for
  workspace `admin` / `auditor` / break-glass without exposing raw tokens (`S-07`).
- `POST /api/v1/workspaces/{ws}/invitations`: workspace `admin` creates email-bound
  single-use invitation; SHA-256 `token_hash` stored at rest; `invite_token` returned
  ONCE ONLY.
- `DELETE /api/v1/workspaces/{ws}/invitations/{invite_id}`: workspace `admin` revokes
  pending invitation.
- `POST /api/v1/invitations/accept`: authenticated user redeems single-use token under
  row lock (`FOR UPDATE`), verifying normalized email equality (`403 invite_email_mismatch`),
  TTL (`410 invite_expired`), and replay (`409 invite_already_used`) (`SEC-038`).
- `PATCH /api/v1/workspaces/{ws}/members/{member_id}` & `DELETE .../{member_id}`:
  optimistic concurrency (`412`/`409`), last-admin protection (`409 last_admin`),
  cross-workspace `repository_grants` isolation (`404`), atomic `grant_epoch` bump,
  and `identity.permission_revoked` `S-19` outbox emission (`NFR-04`, `SEC-022`).
"""

from __future__ import annotations

import hashlib
import math
import secrets
from datetime import UTC, datetime, timedelta
from typing import cast

from sqlalchemy import and_, delete, func, or_, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.events import EventEnvelope, SecurityIdentityEventPayload
from py_contracts.iam import (
    Invite,
    InviteAcceptRequest,
    InviteCreateRequest,
    InviteCreateResponse,
    InvitePage,
    InviteStatus,
    Membership,
    MembershipPage,
    MemberUpdateRequest,
    WorkspaceRole,
)
from py_contracts.primitives import new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    ConflictError,
    ForbiddenError,
    GoneError,
    NotFoundError,
    RateLimitedError,
    UnprocessableEntityError,
)
from red2pr_control.db.base import (
    AuthRateLimitModel,
    InvitationModel,
    MembershipModel,
    RepoGrantModel,
    UserModel,
    WorkspaceModel,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.rbac import (
    ROLE_PRIVILEGE_RANK,
    WorkspaceAccessContext,
    compute_query_filter_hash,
    decode_signed_cursor,
    encode_signed_cursor,
    enforce_optimistic_version,
)
from red2pr_control.iam.sessions import AuthenticatedContext, hash_opaque_token
from red2pr_control.iam.workspaces import bump_user_grant_epoch_in_tx, to_membership_dto

DEFAULT_INVITE_TTL = timedelta(days=7)
MAX_INVITE_TTL = timedelta(days=30)
INVITE_RATE_WINDOW = timedelta(minutes=15)
INVITE_CREATE_MAX_IN_WINDOW = 25
INVITE_ACCEPT_MAX_FAILURES = 10


def _mint_raw_invite_token() -> tuple[str, str]:
    """Generate a 256-bit single-use opaque invite token and its SHA-256 hex digest."""
    raw = f"inv_{secrets.token_urlsafe(32)}"
    digest = hashlib.sha256(raw.encode("ascii")).hexdigest()
    return raw, digest


def to_invite_dto(row: InvitationModel, *, now: datetime) -> Invite:
    """Convert `InvitationModel` to `S-07` `Invite` DTO (never exposes raw token)."""
    ref_now = now.astimezone(UTC)
    effective_status: InviteStatus = cast(InviteStatus, row.status)
    if effective_status == "pending" and ref_now >= row.expires_at.astimezone(UTC):
        effective_status = "expired"
    return Invite(
        id=row.id,
        workspace_id=row.workspace_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        email=row.email,
        role=cast(WorkspaceRole, row.role),
        expires_at=row.expires_at,
        status=effective_status,
        repository_grants=sorted(set(row.repository_grants_json or [])),
    )


class MemberInviteService:
    """Implements A-05 workspace memberships, invitations, and scoped repo grants."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        signing_key: bytes,
    ) -> None:
        self._session_factory = session_factory
        self._signing_key = signing_key

    async def _check_rate_limit(
        self,
        *,
        action: str,
        bucket_key: str,
        limit: int,
        now: datetime,
    ) -> int | None:
        window_start = now - INVITE_RATE_WINDOW
        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
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
                return max(
                    1,
                    math.ceil(((oldest + INVITE_RATE_WINDOW) - now).total_seconds()),
                )
        return None

    async def _record_rate_limit_event(
        self,
        *,
        action: str,
        bucket_key: str,
        now: datetime,
    ) -> None:
        async with instance_rls_session(self._session_factory, mode="instance_only") as db:
            db.add(
                AuthRateLimitModel(
                    id=new_uuid7(now=now),
                    action=action,
                    bucket_key=bucket_key,
                    attempted_at=now,
                    expires_at=now + INVITE_RATE_WINDOW,
                )
            )

    async def _assert_repo_ids_isolated_to_workspace(
        self,
        *,
        workspace_id: str,
        repository_ids: list[str],
    ) -> list[str]:
        """Reject cross-workspace repository IDs (`404 repository_not_found`, `SEC-032`)."""
        deduped = sorted(set(repository_ids))
        if not deduped:
            return []

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            foreign_grant_repo = await db.scalar(
                select(RepoGrantModel.repository_id)
                .where(
                    RepoGrantModel.repository_id.in_(deduped),
                    RepoGrantModel.workspace_id != workspace_id,
                )
                .limit(1)
            )
            if foreign_grant_repo is not None:
                raise NotFoundError(
                    code="repository_not_found",
                    detail="One or more repository identifiers do not belong to this workspace.",
                )

            has_repos_table = await db.scalar(
                text("SELECT to_regclass('public.repositories') IS NOT NULL")
            )
            if has_repos_table:
                foreign_repo = await db.scalar(
                    text(
                        "SELECT id FROM public.repositories "
                        "WHERE id = ANY(:repo_ids) AND workspace_id <> :ws_id LIMIT 1"
                    ),
                    {"repo_ids": deduped, "ws_id": workspace_id},
                )
                if foreign_repo is not None:
                    raise NotFoundError(
                        code="repository_not_found",
                        detail=(
                            "One or more repository identifiers do not belong to this workspace."
                        ),
                    )
        return deduped

    async def list_members(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        cursor: str | None,
        limit: int,
        role_filter: WorkspaceRole | None,
        now: datetime,
    ) -> MembershipPage:
        """List workspace members with user metadata & scoped `repository_grants` (`A-05`)."""
        ref_now = now.astimezone(UTC)
        ws_id = ws_ctx.workspace_id
        q_hash = compute_query_filter_hash({"endpoint": "members.list", "role": role_filter or ""})
        decoded = (
            decode_signed_cursor(
                cursor,
                signing_key=self._signing_key,
                expected_workspace_scope=ws_id,
                expected_principal_id=ws_ctx.auth.user.id,
                current_grant_epoch=ws_ctx.auth.user.grant_epoch,
                expected_query_hash=q_hash,
                now=ref_now,
            )
            if cursor is not None
            else None
        )

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            stmt = (
                select(MembershipModel, UserModel)
                .join(UserModel, UserModel.id == MembershipModel.user_id)
                .where(MembershipModel.workspace_id == ws_id)
            )
            if role_filter is not None:
                stmt = stmt.where(MembershipModel.role == role_filter)
            if decoded is not None:
                stmt = stmt.where(
                    or_(
                        MembershipModel.created_at < decoded.created_at,
                        and_(
                            MembershipModel.created_at == decoded.created_at,
                            MembershipModel.id < decoded.item_id,
                        ),
                    )
                )
            stmt = stmt.order_by(
                MembershipModel.created_at.desc(),
                MembershipModel.id.desc(),
            ).limit(limit + 1)

            joined_rows = list((await db.execute(stmt)).all())
            has_more = len(joined_rows) > limit
            page_pairs = joined_rows[:limit]

            grants_map: dict[str, list[str]] = {}
            if page_pairs:
                mem_ids = [pair[0].id for pair in page_pairs]
                rg_rows = (
                    await db.execute(
                        select(RepoGrantModel.membership_id, RepoGrantModel.repository_id).where(
                            RepoGrantModel.workspace_id == ws_id,
                            RepoGrantModel.membership_id.in_(mem_ids),
                        )
                    )
                ).all()
                for m_id, r_id in rg_rows:
                    grants_map.setdefault(m_id, []).append(r_id)

        next_cursor: str | None = None
        if has_more and page_pairs:
            last_mem = page_pairs[-1][0]
            next_cursor = encode_signed_cursor(
                signing_key=self._signing_key,
                workspace_scope=ws_id,
                principal_id=ws_ctx.auth.user.id,
                grant_epoch=ws_ctx.auth.user.grant_epoch,
                query_hash=q_hash,
                created_at=last_mem.created_at,
                item_id=last_mem.id,
                now=ref_now,
            )

        items = [
            to_membership_dto(
                mem_row,
                repository_grants=grants_map.get(mem_row.id, []),
                user=user_row,
            )
            for mem_row, user_row in page_pairs
        ]
        return MembershipPage(items=items, next_cursor=next_cursor, snapshot_at=ref_now)

    async def list_invitations(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        cursor: str | None,
        limit: int,
        status_filter: InviteStatus | None,
        now: datetime,
    ) -> InvitePage:
        """List workspace invitation records without raw tokens (`A-05`, `S-07`)."""
        ref_now = now.astimezone(UTC)
        ws_id = ws_ctx.workspace_id
        q_hash = compute_query_filter_hash(
            {"endpoint": "invitations.list", "status": status_filter or ""}
        )
        decoded = (
            decode_signed_cursor(
                cursor,
                signing_key=self._signing_key,
                expected_workspace_scope=ws_id,
                expected_principal_id=ws_ctx.auth.user.id,
                current_grant_epoch=ws_ctx.auth.user.grant_epoch,
                expected_query_hash=q_hash,
                now=ref_now,
            )
            if cursor is not None
            else None
        )

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            stmt = select(InvitationModel).where(InvitationModel.workspace_id == ws_id)
            if status_filter == "pending":
                stmt = stmt.where(
                    InvitationModel.status == "pending",
                    InvitationModel.expires_at > ref_now,
                )
            elif status_filter == "expired":
                stmt = stmt.where(
                    or_(
                        InvitationModel.status == "expired",
                        and_(
                            InvitationModel.status == "pending",
                            InvitationModel.expires_at <= ref_now,
                        ),
                    )
                )
            elif status_filter is not None:
                stmt = stmt.where(InvitationModel.status == status_filter)

            if decoded is not None:
                stmt = stmt.where(
                    or_(
                        InvitationModel.created_at < decoded.created_at,
                        and_(
                            InvitationModel.created_at == decoded.created_at,
                            InvitationModel.id < decoded.item_id,
                        ),
                    )
                )
            stmt = stmt.order_by(
                InvitationModel.created_at.desc(),
                InvitationModel.id.desc(),
            ).limit(limit + 1)

            rows = list((await db.scalars(stmt)).all())

        has_more = len(rows) > limit
        page_rows = rows[:limit]
        next_cursor: str | None = None
        if has_more and page_rows:
            last_inv = page_rows[-1]
            next_cursor = encode_signed_cursor(
                signing_key=self._signing_key,
                workspace_scope=ws_id,
                principal_id=ws_ctx.auth.user.id,
                grant_epoch=ws_ctx.auth.user.grant_epoch,
                query_hash=q_hash,
                created_at=last_inv.created_at,
                item_id=last_inv.id,
                now=ref_now,
            )

        return InvitePage(
            items=[to_invite_dto(r, now=ref_now) for r in page_rows],
            next_cursor=next_cursor,
            snapshot_at=ref_now,
        )

    async def create_invitation(
        self,
        ws_ctx: WorkspaceAccessContext,
        payload: InviteCreateRequest,
        *,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> InviteCreateResponse:
        """Create an email-bound single-use workspace invitation (`A-05`, `SEC-038`)."""
        ref_now = now.astimezone(UTC)
        ws_id = ws_ctx.workspace_id
        rate_bucket = f"ws_admin:{ws_id}:{ws_ctx.auth.user.id}"

        retry_after = await self._check_rate_limit(
            action="invite_create",
            bucket_key=rate_bucket,
            limit=INVITE_CREATE_MAX_IN_WINDOW,
            now=ref_now,
        )
        if retry_after is not None:
            raise RateLimitedError(
                code="rate_limited",
                detail="Too many invitations created in a short window; retry later.",
                retry_after_seconds=retry_after,
            )

        expires_at = (
            payload.expires_at.astimezone(UTC)
            if payload.expires_at is not None
            else (ref_now + DEFAULT_INVITE_TTL)
        )
        if expires_at <= ref_now or expires_at > (ref_now + MAX_INVITE_TTL):
            raise UnprocessableEntityError(
                code="invalid_invite_expiry",
                detail=(
                    "Invitation expires_at must be in the future and at most 30 days from now."
                ),
            )

        validated_repos = await self._assert_repo_ids_isolated_to_workspace(
            workspace_id=ws_id,
            repository_ids=payload.repository_grants,
        )

        normalized_email = payload.email.strip().lower()
        raw_token, token_digest = _mint_raw_invite_token()

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            # Reject if an account with this email is already a member of the workspace
            existing_member = await db.scalar(
                select(MembershipModel.id)
                .join(UserModel, UserModel.id == MembershipModel.user_id)
                .where(
                    MembershipModel.workspace_id == ws_id,
                    UserModel.email == normalized_email,
                )
            )
            if existing_member is not None:
                raise ConflictError(
                    code="member_already_exists",
                    detail="A user with that email address is already a member of this workspace.",
                )

            existing_pending = await db.scalar(
                select(InvitationModel)
                .where(
                    InvitationModel.workspace_id == ws_id,
                    InvitationModel.email == normalized_email,
                    InvitationModel.status == "pending",
                )
                .with_for_update()
            )
            if existing_pending is not None:
                if existing_pending.expires_at.astimezone(UTC) > ref_now:
                    raise ConflictError(
                        code="invite_already_pending",
                        detail="An active pending invitation already exists for this email.",
                    )
                existing_pending.status = "expired"
                existing_pending.updated_at = ref_now
                existing_pending.version += 1
                await db.flush()

            invite_id = new_uuid7(now=ref_now)
            inv_row = InvitationModel(
                id=invite_id,
                workspace_id=ws_id,
                email=normalized_email,
                role=payload.role,
                token_hash=token_digest,
                repository_grants_json=validated_repos,
                status="pending",
                invited_by_user_id=ws_ctx.auth.user.id,
                accepted_by_user_id=None,
                expires_at=expires_at,
                accepted_at=None,
                revoked_at=None,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            db.add(inv_row)
            try:
                await db.flush()
            except IntegrityError as exc:
                raise ConflictError(
                    code="invite_already_pending",
                    detail="An active pending invitation already exists for this email.",
                ) from exc

            await append_audit_entry(
                db,
                workspace_id=ws_id,
                actor_type="user",
                actor_id=ws_ctx.auth.user.id,
                action="workspace.invitation_created",
                target=f"invitation:{invite_id}",
                decision="allow",
                reason_code="admin_invited_member",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={
                    "invited_email": normalized_email,
                    "role": payload.role,
                    "repository_grants_count": len(validated_repos),
                    "expires_at": expires_at.isoformat(),
                },
                occurred_at=ref_now,
            )
            dto = to_invite_dto(inv_row, now=ref_now)

        await self._record_rate_limit_event(
            action="invite_create",
            bucket_key=rate_bucket,
            now=ref_now,
        )
        return InviteCreateResponse(invite=dto, invite_token=raw_token)

    async def revoke_invitation(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        invite_id: str,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> None:
        """Revoke a pending workspace invitation (`A-05`)."""
        ref_now = now.astimezone(UTC)
        ws_id = ws_ctx.workspace_id
        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            inv_row = await db.scalar(
                select(InvitationModel)
                .where(
                    InvitationModel.workspace_id == ws_id,
                    InvitationModel.id == invite_id,
                )
                .with_for_update()
            )
            if inv_row is None:
                raise NotFoundError(code="invite_not_found", detail="Invitation not found.")
            if inv_row.status == "accepted":
                raise ConflictError(
                    code="invite_already_used",
                    detail="Invitation has already been accepted; remove the member instead.",
                )
            if inv_row.status == "pending":
                inv_row.status = "revoked"
                inv_row.revoked_at = ref_now
                inv_row.updated_at = ref_now
                inv_row.version += 1

            await append_audit_entry(
                db,
                workspace_id=ws_id,
                actor_type="user",
                actor_id=ws_ctx.auth.user.id,
                action="workspace.invitation_revoked",
                target=f"invitation:{invite_id}",
                decision="allow",
                reason_code="admin_revoked_invitation",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={"invited_email": inv_row.email},
                occurred_at=ref_now,
            )

    async def accept_invitation(
        self,
        auth: AuthenticatedContext,
        payload: InviteAcceptRequest,
        *,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> Membership:
        """Atomically redeem a single-use email-bound workspace invitation (`SEC-038`)."""
        ref_now = now.astimezone(UTC)
        rate_bucket = f"user_ip:{auth.user.id}:{client_ip}"
        retry_after = await self._check_rate_limit(
            action="invite_accept",
            bucket_key=rate_bucket,
            limit=INVITE_ACCEPT_MAX_FAILURES,
            now=ref_now,
        )
        if retry_after is not None:
            raise RateLimitedError(
                code="rate_limited",
                detail="Too many failed invitation redemption attempts; retry later.",
                retry_after_seconds=retry_after,
            )

        token_digest = hash_opaque_token(payload.token)
        target_ws_id: str | None = None

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            ws_lookup = await db.scalar(
                select(InvitationModel.workspace_id).where(
                    InvitationModel.token_hash == token_digest
                )
            )
            if ws_lookup is None:
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="workspace.invitation_accept",
                    target="invitation:unknown",
                    decision="deny",
                    reason_code="invite_not_found",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
            else:
                target_ws_id = ws_lookup

        if target_ws_id is None:
            await self._record_rate_limit_event(
                action="invite_accept",
                bucket_key=rate_bucket,
                now=ref_now,
            )
            raise NotFoundError(code="invite_not_found", detail="Invitation token is invalid.")

        raised_error: Exception | None = None
        record_failure = False
        accepted_dto: Membership | None = None

        async with workspace_rls_session(self._session_factory, workspace_id=target_ws_id) as ws_db:
            inv_row = await ws_db.scalar(
                select(InvitationModel)
                .where(
                    InvitationModel.workspace_id == target_ws_id,
                    InvitationModel.token_hash == token_digest,
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            ws_row = await ws_db.scalar(
                select(WorkspaceModel).where(WorkspaceModel.id == target_ws_id)
            )
            if inv_row is None or ws_row is None:
                record_failure = True
                raised_error = NotFoundError(
                    code="invite_not_found",
                    detail="Invitation token is invalid.",
                )
            elif ws_row.status != "active" or ws_row.deleted_at is not None:
                await append_audit_entry(
                    ws_db,
                    workspace_id=target_ws_id,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="workspace.invitation_accept",
                    target=f"invitation:{inv_row.id}",
                    decision="deny",
                    reason_code="workspace_inactive",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                raised_error = ConflictError(
                    code="workspace_inactive",
                    detail="Target workspace is not active.",
                )
            elif inv_row.status in {"accepted", "revoked"}:
                reason = "invite_already_used" if inv_row.status == "accepted" else "invite_revoked"
                await append_audit_entry(
                    ws_db,
                    workspace_id=target_ws_id,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="workspace.invitation_accept",
                    target=f"invitation:{inv_row.id}",
                    decision="deny",
                    reason_code=reason,
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                raised_error = ConflictError(
                    code="invite_already_used",
                    detail="Invitation has already been redeemed or revoked.",
                )
            elif inv_row.status == "expired" or ref_now >= inv_row.expires_at.astimezone(UTC):
                if inv_row.status == "pending":
                    inv_row.status = "expired"
                    inv_row.updated_at = ref_now
                    inv_row.version += 1
                await append_audit_entry(
                    ws_db,
                    workspace_id=target_ws_id,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="workspace.invitation_accept",
                    target=f"invitation:{inv_row.id}",
                    decision="deny",
                    reason_code="invite_expired",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                raised_error = GoneError(
                    code="invite_expired",
                    detail="Invitation has expired; ask a workspace admin for a new invitation.",
                )
            else:
                caller_email = (auth.user.email or "").strip().lower()
                if not caller_email or caller_email != inv_row.email.strip().lower():
                    record_failure = True
                    await append_audit_entry(
                        ws_db,
                        workspace_id=target_ws_id,
                        actor_type="user",
                        actor_id=auth.user.id,
                        action="workspace.invitation_accept",
                        target=f"invitation:{inv_row.id}",
                        decision="deny",
                        reason_code="invite_email_mismatch",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        metadata={"severity": "high"},
                        occurred_at=ref_now,
                    )
                    await enqueue_outbox_event(
                        ws_db,
                        EventEnvelope(
                            event_id=new_uuid7(now=ref_now),
                            type="security.policy.denied",
                            occurred_at=ref_now,
                            workspace_id=target_ws_id,
                            aggregate_id=auth.user.id,
                            aggregate_version=auth.user.version,
                            correlation_id=correlation_id,
                            payload=SecurityIdentityEventPayload(
                                target_id=auth.user.id,
                                reason_code="invite_email_mismatch",
                            ),
                        ),
                        now=ref_now,
                    )
                    raised_error = ForbiddenError(
                        code="invite_email_mismatch",
                        detail=(
                            "Authenticated account email does not match the invited email address."
                        ),
                    )
                else:
                    existing_mem = await ws_db.scalar(
                        select(MembershipModel.id).where(
                            MembershipModel.workspace_id == target_ws_id,
                            MembershipModel.user_id == auth.user.id,
                        )
                    )
                    if existing_mem is not None:
                        raised_error = ConflictError(
                            code="member_already_exists",
                            detail="You are already a member of this workspace.",
                        )
                    else:
                        inv_row.status = "accepted"
                        inv_row.accepted_by_user_id = auth.user.id
                        inv_row.accepted_at = ref_now
                        inv_row.updated_at = ref_now
                        inv_row.version += 1

                        mem_id = new_uuid7(now=ref_now)
                        mem_row = MembershipModel(
                            id=mem_id,
                            workspace_id=target_ws_id,
                            user_id=auth.user.id,
                            role=inv_row.role,
                            invited_by_user_id=inv_row.invited_by_user_id,
                            version=1,
                            created_at=ref_now,
                            updated_at=ref_now,
                        )
                        ws_db.add(mem_row)
                        await ws_db.flush()

                        repo_ids = sorted(set(inv_row.repository_grants_json or []))
                        for repo_id in repo_ids:
                            ws_db.add(
                                RepoGrantModel(
                                    id=new_uuid7(now=ref_now),
                                    workspace_id=target_ws_id,
                                    membership_id=mem_id,
                                    repository_id=repo_id,
                                    granted_by_user_id=inv_row.invited_by_user_id,
                                    created_at=ref_now,
                                )
                            )
                        await ws_db.flush()
                        await bump_user_grant_epoch_in_tx(ws_db, user_id=auth.user.id)

                        await append_audit_entry(
                            ws_db,
                            workspace_id=target_ws_id,
                            actor_type="user",
                            actor_id=auth.user.id,
                            action="workspace.invitation_accepted",
                            target=f"membership:{mem_id}",
                            decision="allow",
                            reason_code="single_use_invite_redeemed",
                            correlation_id=correlation_id,
                            client_ip=client_ip,
                            metadata={
                                "invitation_id": inv_row.id,
                                "role": inv_row.role,
                                "repository_grants_count": len(repo_ids),
                            },
                            occurred_at=ref_now,
                        )
                        accepted_dto = to_membership_dto(
                            mem_row,
                            repository_grants=repo_ids,
                            user=auth.user,
                        )

        if record_failure:
            await self._record_rate_limit_event(
                action="invite_accept",
                bucket_key=rate_bucket,
                now=ref_now,
            )
        if raised_error is not None:
            raise raised_error
        assert accepted_dto is not None
        return accepted_dto

    async def update_member(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        member_id: str,
        payload: MemberUpdateRequest,
        if_match_header: str | None,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> Membership:
        """Update member role & `repository_grants` (`409 last_admin`, `grant_epoch` bump)."""
        ref_now = now.astimezone(UTC)
        ws_id = ws_ctx.workspace_id

        validated_repos: list[str] | None = None
        if payload.repository_grants is not None:
            validated_repos = await self._assert_repo_ids_isolated_to_workspace(
                workspace_id=ws_id,
                repository_ids=payload.repository_grants,
            )

        raised_error: Exception | None = None
        updated_dto: Membership | None = None

        try:
            async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
                # Serialize concurrent admin updates/deletes on the workspace row first!
                ws_row = await db.scalar(
                    select(WorkspaceModel).where(WorkspaceModel.id == ws_id).with_for_update()
                )
                if ws_row is None or ws_row.status == "deleting" or ws_row.deleted_at is not None:
                    raise NotFoundError(code="workspace_not_found", detail="Workspace not found.")

                mem_row = await db.scalar(
                    select(MembershipModel)
                    .where(
                        MembershipModel.workspace_id == ws_id,
                        MembershipModel.id == member_id,
                    )
                    .with_for_update()
                )
                if mem_row is None:
                    raise NotFoundError(code="member_not_found", detail="Member not found.")

                enforce_optimistic_version(
                    current_version=mem_row.version,
                    if_match_header=if_match_header,
                    expected_version=payload.expected_version,
                )

                old_role = cast(WorkspaceRole, mem_row.role)
                new_role = payload.role if payload.role is not None else old_role

                if old_role == "admin" and new_role != "admin":
                    other_active_admins = int(
                        (
                            await db.scalar(
                                select(func.count())
                                .select_from(MembershipModel)
                                .join(UserModel, UserModel.id == MembershipModel.user_id)
                                .where(
                                    MembershipModel.workspace_id == ws_id,
                                    MembershipModel.role == "admin",
                                    MembershipModel.id != mem_row.id,
                                    UserModel.status == "active",
                                )
                            )
                        )
                        or 0
                    )
                    if other_active_admins == 0:
                        await append_audit_entry(
                            db,
                            workspace_id=ws_id,
                            actor_type="user",
                            actor_id=ws_ctx.auth.user.id,
                            action="workspace.member_update",
                            target=f"membership:{mem_row.id}",
                            decision="deny",
                            reason_code="last_admin",
                            correlation_id=correlation_id,
                            client_ip=client_ip,
                            occurred_at=ref_now,
                        )
                        raised_error = ConflictError(
                            code="last_admin",
                            detail=(
                                "Cannot demote the last active workspace admin; promote another "
                                "member to admin first."
                            ),
                        )

                if raised_error is None:
                    old_grants = sorted(
                        set(
                            (
                                await db.scalars(
                                    select(RepoGrantModel.repository_id).where(
                                        RepoGrantModel.workspace_id == ws_id,
                                        RepoGrantModel.membership_id == mem_row.id,
                                    )
                                )
                            ).all()
                        )
                    )
                    final_grants = old_grants if validated_repos is None else validated_repos

                    mem_row.role = new_role
                    mem_row.version += 1
                    mem_row.updated_at = ref_now
                    await db.flush()

                    if validated_repos is not None and set(validated_repos) != set(old_grants):
                        await db.execute(
                            delete(RepoGrantModel).where(
                                RepoGrantModel.workspace_id == ws_id,
                                RepoGrantModel.membership_id == mem_row.id,
                            )
                        )
                        for repo_id in validated_repos:
                            db.add(
                                RepoGrantModel(
                                    id=new_uuid7(now=ref_now),
                                    workspace_id=ws_id,
                                    membership_id=mem_row.id,
                                    repository_id=repo_id,
                                    granted_by_user_id=ws_ctx.auth.user.id,
                                    created_at=ref_now,
                                )
                            )
                        await db.flush()

                    role_changed = new_role != old_role
                    grants_changed = set(final_grants) != set(old_grants)
                    if role_changed or grants_changed:
                        await bump_user_grant_epoch_in_tx(db, user_id=mem_row.user_id)

                    role_downgraded = ROLE_PRIVILEGE_RANK[new_role] < ROLE_PRIVILEGE_RANK[old_role]
                    grants_removed = bool(set(old_grants) - set(final_grants))
                    if role_downgraded or grants_removed:
                        await enqueue_outbox_event(
                            db,
                            EventEnvelope(
                                event_id=new_uuid7(now=ref_now),
                                type="identity.permission_revoked",
                                occurred_at=ref_now,
                                workspace_id=ws_id,
                                aggregate_id=mem_row.user_id,
                                aggregate_version=mem_row.version,
                                correlation_id=correlation_id,
                                payload=SecurityIdentityEventPayload(
                                    target_id=mem_row.user_id,
                                    reason_code=(
                                        "role_downgraded"
                                        if role_downgraded
                                        else "repository_grant_revoked"
                                    ),
                                ),
                            ),
                            now=ref_now,
                        )

                    target_user = await db.scalar(
                        select(UserModel).where(UserModel.id == mem_row.user_id)
                    )
                    await append_audit_entry(
                        db,
                        workspace_id=ws_id,
                        actor_type="user",
                        actor_id=ws_ctx.auth.user.id,
                        action="workspace.member_updated",
                        target=f"membership:{mem_row.id}",
                        decision="allow",
                        reason_code="admin_updated_member",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        metadata={
                            "target_user_id": mem_row.user_id,
                            "old_role": old_role,
                            "new_role": new_role,
                            "old_repository_grants": old_grants,
                            "new_repository_grants": final_grants,
                        },
                        occurred_at=ref_now,
                    )
                    updated_dto = to_membership_dto(
                        mem_row,
                        repository_grants=final_grants,
                        user=target_user,
                    )
        except DBAPIError as exc:
            err_msg = str(exc)
            if "last_admin" in err_msg:
                raise ConflictError(
                    code="last_admin",
                    detail=(
                        "Cannot demote the last active workspace admin; promote another "
                        "member to admin first."
                    ),
                ) from exc
            if "cross_workspace_repository_grant" in err_msg:
                raise NotFoundError(
                    code="repository_not_found",
                    detail="One or more repository identifiers do not belong to this workspace.",
                ) from exc
            raise

        if raised_error is not None:
            raise raised_error
        assert updated_dto is not None
        return updated_dto

    async def delete_member(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        member_id: str,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> None:
        """Remove a workspace member (`409 last_admin`, `grant_epoch` bump & SSE cutoff)."""
        ref_now = now.astimezone(UTC)
        ws_id = ws_ctx.workspace_id
        raised_error: Exception | None = None

        try:
            async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
                ws_row = await db.scalar(
                    select(WorkspaceModel).where(WorkspaceModel.id == ws_id).with_for_update()
                )
                if ws_row is None or ws_row.status == "deleting" or ws_row.deleted_at is not None:
                    raise NotFoundError(code="workspace_not_found", detail="Workspace not found.")

                mem_row = await db.scalar(
                    select(MembershipModel)
                    .where(
                        MembershipModel.workspace_id == ws_id,
                        MembershipModel.id == member_id,
                    )
                    .with_for_update()
                )
                if mem_row is None:
                    raise NotFoundError(code="member_not_found", detail="Member not found.")

                if mem_row.role == "admin":
                    other_active_admins = int(
                        (
                            await db.scalar(
                                select(func.count())
                                .select_from(MembershipModel)
                                .join(UserModel, UserModel.id == MembershipModel.user_id)
                                .where(
                                    MembershipModel.workspace_id == ws_id,
                                    MembershipModel.role == "admin",
                                    MembershipModel.id != mem_row.id,
                                    UserModel.status == "active",
                                )
                            )
                        )
                        or 0
                    )
                    if other_active_admins == 0:
                        await append_audit_entry(
                            db,
                            workspace_id=ws_id,
                            actor_type="user",
                            actor_id=ws_ctx.auth.user.id,
                            action="workspace.member_remove",
                            target=f"membership:{mem_row.id}",
                            decision="deny",
                            reason_code="last_admin",
                            correlation_id=correlation_id,
                            client_ip=client_ip,
                            occurred_at=ref_now,
                        )
                        raised_error = ConflictError(
                            code="last_admin",
                            detail=(
                                "Cannot remove the last active workspace admin; promote another "
                                "member to admin first."
                            ),
                        )

                if raised_error is None:
                    target_user_id = mem_row.user_id
                    old_role = mem_row.role
                    old_version = mem_row.version
                    await db.delete(mem_row)
                    await db.flush()

                    await bump_user_grant_epoch_in_tx(db, user_id=target_user_id)
                    await enqueue_outbox_event(
                        db,
                        EventEnvelope(
                            event_id=new_uuid7(now=ref_now),
                            type="identity.permission_revoked",
                            occurred_at=ref_now,
                            workspace_id=ws_id,
                            aggregate_id=target_user_id,
                            aggregate_version=old_version + 1,
                            correlation_id=correlation_id,
                            payload=SecurityIdentityEventPayload(
                                target_id=target_user_id,
                                reason_code="membership_removed",
                            ),
                        ),
                        now=ref_now,
                    )
                    await append_audit_entry(
                        db,
                        workspace_id=ws_id,
                        actor_type="user",
                        actor_id=ws_ctx.auth.user.id,
                        action="workspace.member_removed",
                        target=f"membership:{member_id}",
                        decision="allow",
                        reason_code="admin_removed_member",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        metadata={
                            "target_user_id": target_user_id,
                            "removed_role": old_role,
                        },
                        occurred_at=ref_now,
                    )
        except DBAPIError as exc:
            if "last_admin" in str(exc):
                raise ConflictError(
                    code="last_admin",
                    detail=(
                        "Cannot remove the last active workspace admin; promote another "
                        "member to admin first."
                    ),
                ) from exc
            raise

        if raised_error is not None:
            raise raised_error
