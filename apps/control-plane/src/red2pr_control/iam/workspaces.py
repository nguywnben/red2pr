"""Multi-workspace lifecycle (`A-04`) and owner break-glass service (`ADR-030`, `ADR-034`).

Provides:
- `GET /api/v1/workspaces`: cursor-paginated workspaces where caller holds active
  membership or active unexpired break-glass grant (never all workspaces by title alone).
- `POST /api/v1/workspaces`: `instance_owner`-only workspace creation with initial `admin`
  membership so the `last_admin` invariant holds from `t = 0`.
- `GET /api/v1/workspaces/{ws}` & `PATCH /api/v1/workspaces/{ws}`: workspace metadata &
  admin settings with `If-Match` (`412`) and `expected_version` (`409`) concurrency guards.
- `DELETE /api/v1/workspaces/{ws}`: `instance_owner` + fresh `5m` step-up + `confirm_name`
  + mandatory `S-05` `Idempotency-Key` freeze/revoke/tombstone workflow returning `202`
  `ActionReceipt`.
- `POST/GET/DELETE /api/v1/workspaces/{ws}/break-glass`: time-bounded (`5..240` min),
  step-up-gated, dual-audited owner break-glass read grants (`ADR-034`).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import cast

from sqlalchemy import and_, delete, exists, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.events import EventEnvelope, SecurityIdentityEventPayload
from py_contracts.iam import (
    BreakGlassCreateRequest,
    BreakGlassGrant,
    BreakGlassGrantPage,
    Membership,
    User,
    UserStatus,
    Workspace,
    WorkspaceCreateRequest,
    WorkspaceDeleteRequest,
    WorkspacePage,
    WorkspaceRole,
    WorkspaceStatus,
    WorkspaceUpdateRequest,
)
from py_contracts.primitives import ActionReceipt, new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    BadRequestError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
)
from red2pr_control.db.base import (
    BreakGlassGrantModel,
    InvitationModel,
    MembershipModel,
    RepoGrantModel,
    UserModel,
    WorkspaceModel,
)
from red2pr_control.db.idempotency import (
    claim_idempotent_operation,
    complete_idempotent_operation,
    upsert_operation_receipt,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.rbac import (
    WorkspaceAccessContext,
    compute_query_filter_hash,
    decode_signed_cursor,
    encode_signed_cursor,
    enforce_optimistic_version,
    load_workspace_by_identifier,
)
from red2pr_control.iam.sessions import AuthenticatedContext, is_step_up_fresh

_NON_SLUG_CHARS_RE = re.compile(r"[^a-z0-9]+")
_INSTANCE_CURSOR_SCOPE = "__instance__"


def slugify_workspace_name(name: str) -> str:
    """Derive a canonical lowercase URL slug from a workspace display name."""
    lowered = name.strip().lower()
    collapsed = _NON_SLUG_CHARS_RE.sub("-", lowered).strip("-")
    if not collapsed:
        collapsed = "workspace"
    return collapsed[:100].rstrip("-") or "workspace"


def to_user_summary_dto(row: UserModel) -> User:
    """Convert `UserModel` to `S-06` `User` wire DTO."""
    return User(
        id=row.id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        display_name=row.display_name,
        email=row.email,
        status=cast(UserStatus, row.status),
    )


def to_workspace_dto(row: WorkspaceModel) -> Workspace:
    """Convert `WorkspaceModel` to `S-07` `Workspace` wire DTO."""
    return Workspace(
        id=row.id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        name=row.name,
        slug=row.slug,
        status=cast(WorkspaceStatus, row.status),
        paused=row.paused,
    )


def to_membership_dto(
    row: MembershipModel,
    *,
    repository_grants: list[str],
    user: UserModel | None = None,
) -> Membership:
    """Convert `MembershipModel` + sorted repository IDs to `S-07` `Membership` wire DTO."""
    return Membership(
        id=row.id,
        workspace_id=row.workspace_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        user_id=row.user_id,
        role=cast(WorkspaceRole, row.role),
        repository_grants=sorted(set(repository_grants)),
        user=to_user_summary_dto(user) if user is not None else None,
    )


def to_break_glass_dto(row: BreakGlassGrantModel, *, now: datetime) -> BreakGlassGrant:
    """Convert `BreakGlassGrantModel` to `BreakGlassGrant` wire DTO."""
    ref_now = now.astimezone(UTC)
    is_active = row.revoked_at is None and row.expires_at.astimezone(UTC) > ref_now
    return BreakGlassGrant(
        id=row.id,
        workspace_id=row.workspace_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        user_id=row.user_id,
        reason=row.reason,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        active=is_active,
    )


async def bump_user_grant_epoch_in_tx(db: AsyncSession, *, user_id: str) -> int:
    """Atomically increment `users.grant_epoch` via narrow `SECURITY DEFINER` function."""
    new_epoch = await db.scalar(
        text("SELECT public.red2pr_bump_user_grant_epoch(:uid)"),
        {"uid": user_id},
    )
    if not isinstance(new_epoch, int):
        raise NotFoundError(code="user_not_found", detail="User account not found.")
    return new_epoch


async def load_principal_workspaces_and_memberships(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    user_id: str,
    now: datetime,
) -> tuple[list[Workspace], list[Membership], bool]:
    """Load caller's authorized workspaces, memberships, and privileged-admin flag for `/me`."""
    ref_now = now.astimezone(UTC)
    async with instance_rls_session(session_factory, mode="instance_admin") as db:
        membership_rows = (
            await db.scalars(
                select(MembershipModel)
                .join(WorkspaceModel, WorkspaceModel.id == MembershipModel.workspace_id)
                .where(
                    MembershipModel.user_id == user_id,
                    WorkspaceModel.status != "deleting",
                    WorkspaceModel.deleted_at.is_(None),
                )
                .order_by(MembershipModel.created_at.asc(), MembershipModel.id.asc())
            )
        ).all()

        grants_by_membership: dict[str, list[str]] = {}
        if membership_rows:
            mem_ids = [m.id for m in membership_rows]
            rg_rows = (
                await db.execute(
                    select(RepoGrantModel.membership_id, RepoGrantModel.repository_id).where(
                        RepoGrantModel.membership_id.in_(mem_ids)
                    )
                )
            ).all()
            for mem_id, repo_id in rg_rows:
                grants_by_membership.setdefault(mem_id, []).append(repo_id)

        bg_ws_ids = (
            await db.scalars(
                select(BreakGlassGrantModel.workspace_id).where(
                    BreakGlassGrantModel.user_id == user_id,
                    BreakGlassGrantModel.revoked_at.is_(None),
                    BreakGlassGrantModel.expires_at > ref_now,
                )
            )
        ).all()

        authorized_ws_ids = {m.workspace_id for m in membership_rows} | set(bg_ws_ids)
        ws_rows: list[WorkspaceModel] = []
        if authorized_ws_ids:
            ws_rows = list(
                (
                    await db.scalars(
                        select(WorkspaceModel)
                        .where(
                            WorkspaceModel.id.in_(authorized_ws_ids),
                            WorkspaceModel.status != "deleting",
                            WorkspaceModel.deleted_at.is_(None),
                        )
                        .order_by(WorkspaceModel.created_at.desc(), WorkspaceModel.id.desc())
                    )
                ).all()
            )

        workspaces = [to_workspace_dto(w) for w in ws_rows]
        memberships = [
            to_membership_dto(
                m,
                repository_grants=grants_by_membership.get(m.id, []),
            )
            for m in membership_rows
        ]
        has_admin_role = any(m.role == "admin" for m in membership_rows)
        return workspaces, memberships, has_admin_role


class WorkspaceService:
    """Implements A-04 workspace CRUD and ADR-034 audited break-glass grants."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        signing_key: bytes,
    ) -> None:
        self._session_factory = session_factory
        self._signing_key = signing_key

    async def list_workspaces(
        self,
        auth: AuthenticatedContext,
        *,
        cursor: str | None,
        limit: int,
        now: datetime,
    ) -> WorkspacePage:
        """List workspaces where `auth.user` holds active membership or break-glass grant."""
        ref_now = now.astimezone(UTC)
        q_hash = compute_query_filter_hash({"endpoint": "workspaces.list"})
        decoded = (
            decode_signed_cursor(
                cursor,
                signing_key=self._signing_key,
                expected_workspace_scope=_INSTANCE_CURSOR_SCOPE,
                expected_principal_id=auth.user.id,
                current_grant_epoch=auth.user.grant_epoch,
                expected_query_hash=q_hash,
                now=ref_now,
            )
            if cursor is not None
            else None
        )

        member_exists = exists(
            select(1).where(
                MembershipModel.workspace_id == WorkspaceModel.id,
                MembershipModel.user_id == auth.user.id,
            )
        )
        bg_exists = exists(
            select(1).where(
                BreakGlassGrantModel.workspace_id == WorkspaceModel.id,
                BreakGlassGrantModel.user_id == auth.user.id,
                BreakGlassGrantModel.revoked_at.is_(None),
                BreakGlassGrantModel.expires_at > ref_now,
            )
        )

        stmt = select(WorkspaceModel).where(
            WorkspaceModel.status != "deleting",
            WorkspaceModel.deleted_at.is_(None),
            or_(member_exists, bg_exists),
        )
        if decoded is not None:
            stmt = stmt.where(
                or_(
                    WorkspaceModel.created_at < decoded.created_at,
                    and_(
                        WorkspaceModel.created_at == decoded.created_at,
                        WorkspaceModel.id < decoded.item_id,
                    ),
                )
            )
        stmt = stmt.order_by(WorkspaceModel.created_at.desc(), WorkspaceModel.id.desc()).limit(
            limit + 1
        )

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            rows = list((await db.scalars(stmt)).all())

        has_more = len(rows) > limit
        page_rows = rows[:limit]
        next_cursor: str | None = None
        if has_more and page_rows:
            last_row = page_rows[-1]
            next_cursor = encode_signed_cursor(
                signing_key=self._signing_key,
                workspace_scope=_INSTANCE_CURSOR_SCOPE,
                principal_id=auth.user.id,
                grant_epoch=auth.user.grant_epoch,
                query_hash=q_hash,
                created_at=last_row.created_at,
                item_id=last_row.id,
                now=ref_now,
            )

        return WorkspacePage(
            items=[to_workspace_dto(r) for r in page_rows],
            next_cursor=next_cursor,
            snapshot_at=ref_now,
        )

    async def create_workspace(
        self,
        auth: AuthenticatedContext,
        payload: WorkspaceCreateRequest,
        *,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> Workspace:
        """Create a new workspace (`instance_owner` only) with initial `admin` membership."""
        ref_now = now.astimezone(UTC)
        raised_error: Exception | None = None
        created_dto: Workspace | None = None

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            if not auth.user.is_instance_owner:
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="workspace.create",
                    target="instance:workspaces",
                    decision="deny",
                    reason_code="instance_owner_required",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                raised_error = ForbiddenError(
                    code="instance_owner_required",
                    detail="Only an Instance Owner may create workspaces.",
                )
            else:
                target_admin_id = payload.initial_admin_user_id or auth.user.id
                admin_user = await db.scalar(
                    select(UserModel)
                    .where(
                        UserModel.id == target_admin_id,
                        UserModel.status == "active",
                    )
                    .with_for_update()
                )
                if admin_user is None:
                    raised_error = NotFoundError(
                        code="initial_admin_not_found",
                        detail="Initial workspace admin user was not found or is inactive.",
                    )
                else:
                    if payload.slug is not None:
                        existing_slug = await db.scalar(
                            select(WorkspaceModel.id).where(WorkspaceModel.slug == payload.slug)
                        )
                        if existing_slug is not None:
                            raised_error = ConflictError(
                                code="workspace_slug_conflict",
                                detail=f"Workspace slug {payload.slug!r} is already in use.",
                            )
                        chosen_slug = payload.slug
                    else:
                        base_slug = slugify_workspace_name(payload.name)
                        chosen_slug = base_slug
                        suffix = 2
                        while (
                            await db.scalar(
                                select(WorkspaceModel.id).where(WorkspaceModel.slug == chosen_slug)
                            )
                            is not None
                        ):
                            chosen_slug = f"{base_slug[:96]}-{suffix}"
                            suffix += 1

                    if raised_error is None:
                        ws_id = new_uuid7(now=ref_now)
                        ws_row = WorkspaceModel(
                            id=ws_id,
                            name=payload.name.strip(),
                            slug=chosen_slug,
                            owner_user_id=auth.user.id,
                            status="active",
                            paused=False,
                            retention_policy={},
                            last_event_seq=0,
                            version=1,
                            created_at=ref_now,
                            updated_at=ref_now,
                            deleted_at=None,
                        )
                        mem_id = new_uuid7(now=ref_now)
                        mem_row = MembershipModel(
                            id=mem_id,
                            workspace_id=ws_id,
                            user_id=admin_user.id,
                            role="admin",
                            invited_by_user_id=auth.user.id,
                            version=1,
                            created_at=ref_now,
                            updated_at=ref_now,
                        )
                        db.add(ws_row)
                        try:
                            await db.flush()
                        except IntegrityError as exc:
                            raise ConflictError(
                                code="workspace_slug_conflict",
                                detail=f"Workspace slug {chosen_slug!r} is already in use.",
                            ) from exc

                        db.add(mem_row)
                        admin_user.grant_epoch += 1
                        admin_user.version += 1
                        admin_user.updated_at = ref_now
                        await db.flush()

                        await append_audit_entry(
                            db,
                            actor_type="user",
                            actor_id=auth.user.id,
                            action="workspace.created",
                            target=f"workspace:{ws_id}",
                            decision="allow",
                            reason_code="owner_created_workspace",
                            correlation_id=correlation_id,
                            client_ip=client_ip,
                            metadata={
                                "slug": chosen_slug,
                                "initial_admin_user_id": admin_user.id,
                            },
                            occurred_at=ref_now,
                        )
                        created_dto = to_workspace_dto(ws_row)

        if raised_error is not None:
            raise raised_error
        assert created_dto is not None
        return created_dto

    async def update_workspace(
        self,
        ws_ctx: WorkspaceAccessContext,
        payload: WorkspaceUpdateRequest,
        *,
        if_match_header: str | None,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> Workspace:
        """Update workspace settings (`admin` only) with optimistic concurrency (`A-04`)."""
        ref_now = now.astimezone(UTC)
        ws_id = ws_ctx.workspace_id

        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as db:
            ws_row = await db.scalar(
                select(WorkspaceModel).where(WorkspaceModel.id == ws_id).with_for_update()
            )
            if ws_row is None or ws_row.status == "deleting" or ws_row.deleted_at is not None:
                raise NotFoundError(code="workspace_not_found", detail="Workspace not found.")

            enforce_optimistic_version(
                current_version=ws_row.version,
                if_match_header=if_match_header,
                expected_version=payload.expected_version,
            )

            old_name = ws_row.name
            old_paused = ws_row.paused
            if payload.name is not None:
                ws_row.name = payload.name.strip()
            if payload.paused is not None:
                ws_row.paused = payload.paused
            ws_row.version += 1
            ws_row.updated_at = ref_now
            await db.flush()

            await append_audit_entry(
                db,
                workspace_id=ws_id,
                actor_type="user",
                actor_id=ws_ctx.auth.user.id,
                action="workspace.updated",
                target=f"workspace:{ws_id}",
                decision="allow",
                reason_code="admin_settings_updated",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={
                    "old_name": old_name,
                    "new_name": ws_row.name,
                    "old_paused": old_paused,
                    "new_paused": ws_row.paused,
                    "new_version": ws_row.version,
                },
                occurred_at=ref_now,
            )
            return to_workspace_dto(ws_row)

    async def delete_workspace(
        self,
        auth: AuthenticatedContext,
        *,
        raw_ws: str,
        payload: WorkspaceDeleteRequest,
        idempotency_key: str | None,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> ActionReceipt:
        """Freeze, revoke grants/invites, and tombstone workspace (`A-04`, `S-05`)."""
        ref_now = now.astimezone(UTC)
        if not idempotency_key:
            raise BadRequestError(
                code="missing_idempotency_key",
                detail="DELETE /api/v1/workspaces/{ws} requires an S-05 Idempotency-Key header.",
            )

        raised_error: Exception | None = None
        target_ws_id: str | None = None

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            if not auth.user.is_instance_owner:
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="workspace.delete",
                    target=f"workspace:{raw_ws[:120]}",
                    decision="deny",
                    reason_code="instance_owner_required",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                raised_error = ForbiddenError(
                    code="instance_owner_required",
                    detail="Only an Instance Owner may delete workspaces.",
                )
            elif not is_step_up_fresh(auth.session, now=ref_now):
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="workspace.delete",
                    target=f"workspace:{raw_ws[:120]}",
                    decision="deny",
                    reason_code="step_up_required",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                raised_error = ForbiddenError(
                    code="step_up_required",
                    detail=(
                        "Fresh 5-minute step-up re-authentication is required before "
                        "deleting a workspace."
                    ),
                )
            else:
                ws_lookup = await load_workspace_by_identifier(db, raw_ws, include_deleting=True)
                if ws_lookup is None:
                    raised_error = NotFoundError(
                        code="workspace_not_found",
                        detail="Workspace not found.",
                    )
                else:
                    target_ws_id = ws_lookup.id

        if raised_error is not None:
            raise raised_error
        assert target_ws_id is not None

        async with workspace_rls_session(self._session_factory, workspace_id=target_ws_id) as ws_db:
            ws_row = await ws_db.scalar(
                select(WorkspaceModel).where(WorkspaceModel.id == target_ws_id).with_for_update()
            )
            if ws_row is None:
                raise NotFoundError(code="workspace_not_found", detail="Workspace not found.")

            # Validate confirm_name BEFORE claiming idempotency on active workspaces
            if ws_row.status != "deleting" and payload.confirm_name != ws_row.name:
                await append_audit_entry(
                    ws_db,
                    workspace_id=target_ws_id,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="workspace.delete",
                    target=f"workspace:{target_ws_id}",
                    decision="deny",
                    reason_code="confirm_name_mismatch",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                body_err = BadRequestError(
                    code="confirm_name_mismatch",
                    detail="confirm_name must exactly match the workspace name.",
                )
                # Commit the deny audit entry cleanly before raising
                raised_error = body_err
            else:
                claim = await claim_idempotent_operation(
                    ws_db,
                    workspace_id=target_ws_id,
                    principal_id=auth.user.id,
                    operation="workspace.delete",
                    idempotency_key=idempotency_key,
                    request_payload=payload.model_dump(mode="json"),
                    logical_effect_key=f"workspace.delete:{target_ws_id}",
                    resource_id=target_ws_id,
                    status_url=None,
                    correlation_id=correlation_id,
                    now=ref_now,
                )
                if not claim.is_new_claim:
                    return claim.receipt

                ws_row.status = "deleting"
                ws_row.paused = True
                ws_row.deleted_at = ref_now
                ws_row.updated_at = ref_now
                ws_row.version += 1
                # Flush status='deleting' first so trg_memberships_protect_last_admin permits purge
                await ws_db.flush()

                affected_member_uids = list(
                    (
                        await ws_db.scalars(
                            select(MembershipModel.user_id).where(
                                MembershipModel.workspace_id == target_ws_id
                            )
                        )
                    ).all()
                )
                affected_bg_uids = list(
                    (
                        await ws_db.scalars(
                            select(BreakGlassGrantModel.user_id).where(
                                BreakGlassGrantModel.workspace_id == target_ws_id,
                                BreakGlassGrantModel.revoked_at.is_(None),
                            )
                        )
                    ).all()
                )

                await ws_db.execute(
                    update(InvitationModel)
                    .where(
                        InvitationModel.workspace_id == target_ws_id,
                        InvitationModel.status == "pending",
                    )
                    .values(
                        status="revoked",
                        revoked_at=ref_now,
                        updated_at=ref_now,
                        version=InvitationModel.version + 1,
                    )
                )
                await ws_db.execute(
                    update(BreakGlassGrantModel)
                    .where(
                        BreakGlassGrantModel.workspace_id == target_ws_id,
                        BreakGlassGrantModel.revoked_at.is_(None),
                    )
                    .values(
                        revoked_at=ref_now,
                        updated_at=ref_now,
                        version=BreakGlassGrantModel.version + 1,
                    )
                )
                await ws_db.execute(
                    delete(MembershipModel).where(MembershipModel.workspace_id == target_ws_id)
                )

                for uid in sorted(set(affected_member_uids) | set(affected_bg_uids)):
                    await bump_user_grant_epoch_in_tx(ws_db, user_id=uid)

                await enqueue_outbox_event(
                    ws_db,
                    EventEnvelope(
                        event_id=new_uuid7(now=ref_now),
                        type="identity.permission_revoked",
                        occurred_at=ref_now,
                        workspace_id=target_ws_id,
                        aggregate_id=target_ws_id,
                        aggregate_version=ws_row.version,
                        correlation_id=correlation_id,
                        payload=SecurityIdentityEventPayload(
                            target_id=target_ws_id,
                            reason_code="workspace_deleting",
                        ),
                    ),
                    now=ref_now,
                )
                await append_audit_entry(
                    ws_db,
                    workspace_id=target_ws_id,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="workspace.deleted",
                    target=f"workspace:{target_ws_id}",
                    decision="allow",
                    reason_code="owner_confirmed_delete",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    metadata={
                        "severity": "high",
                        "revoked_members_count": len(set(affected_member_uids)),
                    },
                    occurred_at=ref_now,
                )
                final_receipt = await complete_idempotent_operation(
                    ws_db,
                    workspace_id=target_ws_id,
                    operation_id=claim.receipt.operation_id,
                    state="succeeded",
                    status_code=202,
                    now=ref_now,
                )
                await upsert_operation_receipt(
                    ws_db,
                    operation_id=final_receipt.operation_id,
                    scope="workspace",
                    workspace_id=target_ws_id,
                    repository_id=None,
                    principal_id=auth.user.id,
                    required_role="instance_owner",
                    operation_kind="workspace.delete",
                    resource_id=target_ws_id,
                    state="succeeded",
                    correlation_id=final_receipt.correlation_id,
                    status_url=final_receipt.status_url,
                    logical_effect_key=f"workspace.delete:{target_ws_id}",
                    now=ref_now,
                )
                return final_receipt

        raise raised_error

    async def create_break_glass_grant(
        self,
        auth: AuthenticatedContext,
        *,
        raw_ws: str,
        payload: BreakGlassCreateRequest,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> BreakGlassGrant:
        """Issue a time-bounded, step-up-gated, dual-audited owner break-glass grant (`ADR-034`)."""
        ref_now = now.astimezone(UTC)
        raised_error: Exception | None = None
        target_ws_id: str | None = None

        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            if not auth.user.is_instance_owner:
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="workspace.break_glass_create",
                    target=f"workspace:{raw_ws[:120]}",
                    decision="deny",
                    reason_code="instance_owner_required",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                raised_error = ForbiddenError(
                    code="instance_owner_required",
                    detail="Only an Instance Owner may request break-glass access.",
                )
            elif not is_step_up_fresh(auth.session, now=ref_now):
                await append_audit_entry(
                    db,
                    actor_type="user",
                    actor_id=auth.user.id,
                    action="workspace.break_glass_create",
                    target=f"workspace:{raw_ws[:120]}",
                    decision="deny",
                    reason_code="step_up_required",
                    correlation_id=correlation_id,
                    client_ip=client_ip,
                    occurred_at=ref_now,
                )
                raised_error = ForbiddenError(
                    code="step_up_required",
                    detail=(
                        "Fresh 5-minute step-up re-authentication is required before "
                        "activating temporary break-glass access."
                    ),
                )
            else:
                ws_row = await load_workspace_by_identifier(db, raw_ws)
                if ws_row is None:
                    raised_error = NotFoundError(
                        code="workspace_not_found",
                        detail="Workspace not found.",
                    )
                else:
                    target_ws_id = ws_row.id
                    await append_audit_entry(
                        db,
                        actor_type="user",
                        actor_id=auth.user.id,
                        action="workspace.break_glass_granted",
                        target=f"workspace:{target_ws_id}",
                        decision="allow",
                        reason_code="owner_break_glass",
                        correlation_id=correlation_id,
                        client_ip=client_ip,
                        metadata={
                            "severity": "high",
                            "duration_minutes": payload.duration_minutes,
                            "reason": payload.reason.strip(),
                        },
                        occurred_at=ref_now,
                    )

        if raised_error is not None:
            raise raised_error
        assert target_ws_id is not None

        expires_at = ref_now + timedelta(minutes=payload.duration_minutes)
        async with workspace_rls_session(self._session_factory, workspace_id=target_ws_id) as ws_db:
            bg_id = new_uuid7(now=ref_now)
            bg_row = BreakGlassGrantModel(
                id=bg_id,
                workspace_id=target_ws_id,
                user_id=auth.user.id,
                reason=payload.reason.strip(),
                expires_at=expires_at,
                revoked_at=None,
                version=1,
                created_at=ref_now,
                updated_at=ref_now,
            )
            ws_db.add(bg_row)
            await ws_db.flush()
            await bump_user_grant_epoch_in_tx(ws_db, user_id=auth.user.id)

            await append_audit_entry(
                ws_db,
                workspace_id=target_ws_id,
                actor_type="user",
                actor_id=auth.user.id,
                action="workspace.break_glass_granted",
                target=f"break_glass:{bg_id}",
                decision="allow",
                reason_code="owner_break_glass",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={
                    "severity": "high",
                    "expires_at": expires_at.isoformat(),
                    "reason": payload.reason.strip(),
                },
                occurred_at=ref_now,
            )
            return to_break_glass_dto(bg_row, now=ref_now)

    async def list_break_glass_grants(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        now: datetime,
    ) -> BreakGlassGrantPage:
        """List break-glass records in `{ws}` for workspace `admin`, `auditor`, or owner."""
        ref_now = now.astimezone(UTC)
        ws_id = ws_ctx.workspace_id
        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as ws_db:
            rows = list(
                (
                    await ws_db.scalars(
                        select(BreakGlassGrantModel)
                        .where(BreakGlassGrantModel.workspace_id == ws_id)
                        .order_by(
                            BreakGlassGrantModel.created_at.desc(),
                            BreakGlassGrantModel.id.desc(),
                        )
                        .limit(100)
                    )
                ).all()
            )
        return BreakGlassGrantPage(
            items=[to_break_glass_dto(r, now=ref_now) for r in rows],
            next_cursor=None,
            snapshot_at=ref_now,
        )

    async def revoke_break_glass_grant(
        self,
        ws_ctx: WorkspaceAccessContext,
        *,
        grant_id: str,
        client_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> None:
        """Immediately revoke a break-glass grant, bump `grant_epoch` & sever SSE (`NFR-04`)."""
        ref_now = now.astimezone(UTC)
        ws_id = ws_ctx.workspace_id
        async with workspace_rls_session(self._session_factory, workspace_id=ws_id) as ws_db:
            bg_row = await ws_db.scalar(
                select(BreakGlassGrantModel)
                .where(
                    BreakGlassGrantModel.workspace_id == ws_id,
                    BreakGlassGrantModel.id == grant_id,
                )
                .with_for_update()
            )
            if bg_row is None:
                raise NotFoundError(
                    code="break_glass_not_found",
                    detail="Break-glass grant not found.",
                )
            if bg_row.revoked_at is None:
                bg_row.revoked_at = ref_now
                bg_row.updated_at = ref_now
                bg_row.version += 1
                await bump_user_grant_epoch_in_tx(ws_db, user_id=bg_row.user_id)
                await enqueue_outbox_event(
                    ws_db,
                    EventEnvelope(
                        event_id=new_uuid7(now=ref_now),
                        type="identity.permission_revoked",
                        occurred_at=ref_now,
                        workspace_id=ws_id,
                        aggregate_id=bg_row.user_id,
                        aggregate_version=bg_row.version,
                        correlation_id=correlation_id,
                        payload=SecurityIdentityEventPayload(
                            target_id=bg_row.user_id,
                            reason_code="break_glass_revoked",
                        ),
                    ),
                    now=ref_now,
                )

            await append_audit_entry(
                ws_db,
                workspace_id=ws_id,
                actor_type="user",
                actor_id=ws_ctx.auth.user.id,
                action="workspace.break_glass_revoked",
                target=f"break_glass:{grant_id}",
                decision="allow",
                reason_code="explicit_revocation",
                correlation_id=correlation_id,
                client_ip=client_ip,
                metadata={"grantee_user_id": bg_row.user_id},
                occurred_at=ref_now,
            )
