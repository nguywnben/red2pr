"""U21 scoped notification preferences, destination administration and inbox APIs."""

from __future__ import annotations

import secrets
from datetime import UTC, timedelta
from typing import Annotated, cast
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, Header, Path, Query, Request, Response
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from py_contracts.events import EventType
from py_contracts.iam import WorkspaceRole
from py_contracts.integrations import (
    DeliveryState,
    DestinationScope,
    DestinationStatus,
    NotificationChannel,
    NotificationCredentialWriteRequest,
    NotificationDelivery,
    NotificationDestination,
    NotificationDestinationCreateRequest,
    NotificationDestinationPatchRequest,
    NotificationInboxItem,
    NotificationPreferencesPatchRequest,
    NotificationPreferencesState,
    NotificationReadPatchRequest,
    NotificationSeverity,
    NotificationTestRequest,
    QuietHoursWindow,
    SecretPresence,
    WebhookSigningKeyRotateResponse,
)
from py_contracts.primitives import Page, new_uuid7
from red2pr_control.analytics_audit.audit_chain import append_audit_entry
from red2pr_control.core.errors import (
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    NotFoundError,
    UnprocessableEntityError,
)
from red2pr_control.core.logging import current_correlation_id
from red2pr_control.db.base import (
    ConsentModel,
    MembershipModel,
    NotificationDeliveryModel,
    NotificationDestinationModel,
    NotificationEventModel,
    SecretEntryModel,
    UserInboxItemModel,
    UserNotificationPreferenceModel,
    WebhookSigningKeyModel,
)
from red2pr_control.db.idempotency import (
    claim_idempotent_operation,
    complete_idempotent_operation,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.rbac import (
    WorkspaceAccessContext,
    compute_query_filter_hash,
    decode_signed_cursor,
    encode_signed_cursor,
    make_workspace_rbac_dependency,
)
from red2pr_control.iam.router import get_iam_service
from red2pr_control.iam.sessions import IamService, extract_client_ip
from red2pr_control.secrets.broker import SecretBroker

_READ_ROLES: frozenset[WorkspaceRole] = frozenset(
    {"admin", "maintainer", "reviewer", "viewer", "auditor"}
)
_WRITE_ROLES: frozenset[WorkspaceRole] = frozenset({"admin", "maintainer"})
_READ = make_workspace_rbac_dependency(
    allowed_roles=_READ_ROLES,
    require_csrf=False,
    allow_break_glass=False,
    action="notification.read",
)
_WRITE = make_workspace_rbac_dependency(
    allowed_roles=_WRITE_ROLES,
    require_csrf=True,
    allow_break_glass=False,
    action="notification.manage",
)
_SEVERITY = ("info", "success", "warning", "action", "error", "high", "critical")


def _destination_dto(row: NotificationDestinationModel) -> NotificationDestination:
    return NotificationDestination(
        id=row.id,
        workspace_id=row.workspace_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
        channel=cast(NotificationChannel, row.channel),
        scope=cast(DestinationScope, row.scope),
        verified_at=row.verified_at,
        consent_id=row.consent_id,
        status=cast(DestinationStatus, row.status),
        secret_presence=SecretPresence(
            configured=row.secret_ref is not None, secret_version=1 if row.secret_ref else None
        ),
    )


def _inbox_dto(row: UserInboxItemModel) -> NotificationInboxItem:
    return NotificationInboxItem(
        id=row.id,
        event_id=row.event_id,
        event_type=cast(EventType, row.event_type),
        title=row.title,
        body=row.body,
        severity=cast(NotificationSeverity, row.severity),
        deep_link=row.deep_link,
        is_security=row.is_security,
        read_at=row.read_at,
        created_at=row.created_at,
    )


def _preference_state(
    row: UserNotificationPreferenceModel | None, workspace_id: str | None
) -> NotificationPreferencesState:
    if row is None:
        return NotificationPreferencesState(
            workspace_id=workspace_id,
            event_types=[],
            min_severity="info",
            quiet_hours=None,
            timezone="UTC",
            version=1,
        )
    return NotificationPreferencesState(
        workspace_id=row.workspace_id,
        event_types=[cast(EventType, event_type) for event_type in row.event_types_json],
        min_severity=cast(NotificationSeverity, row.min_severity),
        quiet_hours=QuietHoursWindow.model_validate(row.quiet_hours_json)
        if row.quiet_hours_json
        else None,
        timezone=row.timezone,
        version=row.version,
    )


async def _get_preference(
    db: AsyncSession, *, user_id: str, workspace_id: str | None
) -> UserNotificationPreferenceModel | None:
    return cast(
        UserNotificationPreferenceModel | None,
        await db.scalar(
            select(UserNotificationPreferenceModel).where(
                UserNotificationPreferenceModel.user_id == user_id,
                UserNotificationPreferenceModel.workspace_id.is_(None)
                if workspace_id is None
                else UserNotificationPreferenceModel.workspace_id == workspace_id,
            )
        ),
    )


def build_notifications_router() -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["notifications"])

    @router.get("/workspaces/{ws}/notifications", response_model=Page[NotificationInboxItem])
    async def list_notifications(
        request: Request,
        ws: Annotated[str, Path()],
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
        unread: bool | None = None,
        severity: Annotated[
            str | None, Query(pattern="^(info|success|warning|action|error|high|critical)$")
        ] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
    ) -> Page[NotificationInboxItem]:
        iam = get_iam_service(request)
        now = iam.now().astimezone(UTC)
        filter_hash = compute_query_filter_hash(
            {"endpoint": "notifications.list", "unread": str(unread), "severity": severity or ""}
        )
        decoded = (
            decode_signed_cursor(
                cursor,
                signing_key=iam.csrf_signing_key,
                expected_workspace_scope=ctx.workspace_id,
                expected_principal_id=ctx.auth.user.id,
                current_grant_epoch=ctx.auth.user.grant_epoch,
                expected_query_hash=filter_hash,
                now=now,
            )
            if cursor
            else None
        )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            query = select(UserInboxItemModel).where(
                UserInboxItemModel.workspace_id == ctx.workspace_id,
                UserInboxItemModel.user_id == ctx.auth.user.id,
            )
            if not ctx.has_workspace_wide_repo_read:
                query = query.where(
                    or_(
                        UserInboxItemModel.repository_id.is_(None),
                        UserInboxItemModel.repository_id.in_(ctx.repository_grants),
                    )
                )
            if unread is True:
                query = query.where(UserInboxItemModel.read_at.is_(None))
            elif unread is False:
                query = query.where(UserInboxItemModel.read_at.is_not(None))
            if severity:
                query = query.where(UserInboxItemModel.severity == severity)
            if decoded:
                query = query.where(
                    or_(
                        UserInboxItemModel.created_at < decoded.created_at,
                        and_(
                            UserInboxItemModel.created_at == decoded.created_at,
                            UserInboxItemModel.id < decoded.item_id,
                        ),
                    )
                )
            rows = list(
                (
                    await db.scalars(
                        query.order_by(
                            UserInboxItemModel.created_at.desc(), UserInboxItemModel.id.desc()
                        ).limit(limit + 1)
                    )
                ).all()
            )
            visible = rows[:limit]
            next_cursor = (
                encode_signed_cursor(
                    signing_key=iam.csrf_signing_key,
                    workspace_scope=ctx.workspace_id,
                    principal_id=ctx.auth.user.id,
                    grant_epoch=ctx.auth.user.grant_epoch,
                    query_hash=filter_hash,
                    created_at=visible[-1].created_at,
                    item_id=visible[-1].id,
                    now=now,
                )
                if len(rows) > limit and visible
                else None
            )
            return Page[NotificationInboxItem](
                items=[_inbox_dto(row) for row in visible], next_cursor=next_cursor, snapshot_at=now
            )

    @router.get(
        "/workspaces/{ws}/notifications/{notification_id}", response_model=NotificationInboxItem
    )
    async def get_notification(
        request: Request,
        ws: Annotated[str, Path()],
        notification_id: str,
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
    ) -> NotificationInboxItem:
        iam = get_iam_service(request)
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            row = await db.scalar(
                select(UserInboxItemModel).where(
                    UserInboxItemModel.workspace_id == ctx.workspace_id,
                    UserInboxItemModel.id == notification_id,
                    UserInboxItemModel.user_id == ctx.auth.user.id,
                )
            )
            if row is None or (
                row.repository_id is not None and not ctx.can_read_repository(row.repository_id)
            ):
                raise NotFoundError(
                    code="notification_not_found", detail="Notification was not found."
                )
            return _inbox_dto(row)

    @router.patch(
        "/workspaces/{ws}/notifications/{notification_id}", response_model=NotificationInboxItem
    )
    async def update_notification_read_state(
        body: NotificationReadPatchRequest,
        request: Request,
        ws: Annotated[str, Path()],
        notification_id: str,
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
    ) -> NotificationInboxItem:
        # A read receipt is a self-scoped action; CSRF is still mandatory for cookie writes.
        iam = get_iam_service(request)
        auth = await iam.authenticate_request(
            request, require_csrf=True, correlation_id=current_correlation_id()
        )
        if auth.user.id != ctx.auth.user.id:
            raise ForbiddenError(
                code="identity_changed", detail="Authenticated identity changed during request."
            )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            row = await db.scalar(
                select(UserInboxItemModel)
                .where(
                    UserInboxItemModel.workspace_id == ctx.workspace_id,
                    UserInboxItemModel.id == notification_id,
                    UserInboxItemModel.user_id == auth.user.id,
                )
                .with_for_update()
            )
            if row is None or (
                row.repository_id is not None and not ctx.can_read_repository(row.repository_id)
            ):
                raise NotFoundError(
                    code="notification_not_found", detail="Notification was not found."
                )
            # The inbox row is retained even when read, including for security/audit events.
            row.read_at = iam.now().astimezone(UTC) if body.read else None
            return _inbox_dto(row)

    @router.get(
        "/workspaces/{ws}/notification-destinations", response_model=Page[NotificationDestination]
    )
    async def list_destinations(
        request: Request,
        ws: Annotated[str, Path()],
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
    ) -> Page[NotificationDestination]:
        iam = get_iam_service(request)
        now = iam.now().astimezone(UTC)
        query_hash = compute_query_filter_hash({"endpoint": "notification-destinations.list"})
        decoded = (
            decode_signed_cursor(
                cursor,
                signing_key=iam.csrf_signing_key,
                expected_workspace_scope=ctx.workspace_id,
                expected_principal_id=ctx.auth.user.id,
                current_grant_epoch=ctx.auth.user.grant_epoch,
                expected_query_hash=query_hash,
                now=now,
            )
            if cursor
            else None
        )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            query = select(NotificationDestinationModel).where(
                NotificationDestinationModel.workspace_id == ctx.workspace_id
            )
            if decoded:
                query = query.where(
                    or_(
                        NotificationDestinationModel.created_at < decoded.created_at,
                        and_(
                            NotificationDestinationModel.created_at == decoded.created_at,
                            NotificationDestinationModel.id < decoded.item_id,
                        ),
                    )
                )
            rows = list(
                (
                    await db.scalars(
                        query.order_by(
                            NotificationDestinationModel.created_at.desc(),
                            NotificationDestinationModel.id.desc(),
                        ).limit(limit + 1)
                    )
                ).all()
            )
            visible = rows[:limit]
            next_cursor = (
                encode_signed_cursor(
                    signing_key=iam.csrf_signing_key,
                    workspace_scope=ctx.workspace_id,
                    principal_id=ctx.auth.user.id,
                    grant_epoch=ctx.auth.user.grant_epoch,
                    query_hash=query_hash,
                    created_at=visible[-1].created_at,
                    item_id=visible[-1].id,
                    now=now,
                )
                if len(rows) > limit and visible
                else None
            )
            return Page[NotificationDestination](
                items=[_destination_dto(row) for row in visible],
                next_cursor=next_cursor,
                snapshot_at=now,
            )

    @router.post(
        "/workspaces/{ws}/notification-destinations",
        response_model=NotificationDestination,
        status_code=201,
    )
    async def create_destination(
        body: NotificationDestinationCreateRequest,
        request: Request,
        ws: Annotated[str, Path()],
        ctx: Annotated[WorkspaceAccessContext, Depends(_WRITE)],
        idempotency_key: Annotated[
            str, Header(alias="Idempotency-Key", min_length=1, max_length=120)
        ],
    ) -> NotificationDestination:
        iam = get_iam_service(request)
        if body.channel == "in_app":
            raise ConflictError(
                code="in_app_destination_managed",
                detail="The in-app inbox destination is managed by Red2PR.",
            )
        if body.scope == "user" and body.address.strip() == "":
            raise UnprocessableEntityError(
                code="destination_address_required", detail="A destination address is required."
            )
        if body.consent_id is None:
            raise ConflictError(
                code="notification_consent_required",
                detail="An active notification consent is required for an external destination.",
            )
        if body.consent_id is not None:
            async with workspace_rls_session(
                iam.session_factory, workspace_id=ctx.workspace_id
            ) as db:
                consent = await db.scalar(
                    select(ConsentModel).where(
                        ConsentModel.workspace_id == ctx.workspace_id,
                        ConsentModel.id == body.consent_id,
                        ConsentModel.purpose == "notification",
                        ConsentModel.revoked_at.is_(None),
                    )
                )
                if consent is None or consent.destination != body.address:
                    raise ConflictError(
                        code="notification_consent_invalid",
                        detail="An active consent matching this destination is required.",
                    )
        if body.secret_ref is not None:
            async with workspace_rls_session(
                iam.session_factory, workspace_id=ctx.workspace_id
            ) as db:
                secret = await db.scalar(
                    select(SecretEntryModel.id).where(
                        SecretEntryModel.workspace_id == ctx.workspace_id,
                        SecretEntryModel.secret_ref == body.secret_ref,
                        SecretEntryModel.purpose == "notification_channel",
                        SecretEntryModel.revoked_at.is_(None),
                    )
                )
                if secret is None:
                    raise ConflictError(
                        code="notification_secret_ref_invalid",
                        detail=(
                            "Secret reference is not an active notification-channel secret "
                            "for this workspace."
                        ),
                    )
        now = iam.now().astimezone(UTC)
        destination_id = new_uuid7(now=now)
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            claim = await claim_idempotent_operation(
                db,
                workspace_id=ctx.workspace_id,
                principal_id=ctx.auth.user.id,
                operation="notification.destination.create",
                idempotency_key=idempotency_key,
                request_payload=body.model_dump(mode="json"),
                logical_effect_key=(
                    f"notification-destination:{ctx.workspace_id}:{ctx.auth.user.id}:"
                    f"{idempotency_key}"
                ),
                resource_id=destination_id,
                status_url=f"/api/v1/workspaces/{ws}/notification-destinations",
                correlation_id=current_correlation_id(),
                now=now,
            )
            if not claim.is_new_claim:
                if claim.cached_response is None:
                    raise ConflictError(
                        code="idempotency_in_progress",
                        detail="Destination creation is still being recorded; retry safely.",
                    )
                return NotificationDestination.model_validate(claim.cached_response)
            row = NotificationDestinationModel(
                id=destination_id,
                workspace_id=ctx.workspace_id,
                user_id=ctx.auth.user.id if body.scope == "user" else None,
                channel=body.channel,
                scope=body.scope,
                address=body.address.strip(),
                secret_ref=body.secret_ref,
                consent_id=body.consent_id,
                status="not_configured",
                created_at=now,
                updated_at=now,
            )
            db.add(row)
            await append_audit_entry(
                db,
                workspace_id=ctx.workspace_id,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                action="notification.destination.created",
                target=f"notification_destination:{destination_id}",
                decision="allow",
                reason_code="configured",
                correlation_id=current_correlation_id(),
                client_ip=extract_client_ip(request),
                occurred_at=now,
            )
            await db.flush()
            result = _destination_dto(row)
            await complete_idempotent_operation(
                db,
                workspace_id=ctx.workspace_id,
                operation_id=claim.receipt.operation_id,
                state="succeeded",
                status_code=201,
                result_id=destination_id,
                response_payload=result.model_dump(mode="json"),
                now=now,
            )
            return result

    @router.patch(
        "/workspaces/{ws}/notification-destinations/{destination_id}",
        response_model=NotificationDestination,
    )
    async def patch_destination(
        body: NotificationDestinationPatchRequest,
        request: Request,
        ws: Annotated[str, Path()],
        destination_id: str,
        ctx: Annotated[WorkspaceAccessContext, Depends(_WRITE)],
        if_match: Annotated[str, Header(alias="If-Match", min_length=4, max_length=32)],
    ) -> NotificationDestination:
        iam = get_iam_service(request)
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            row = await db.scalar(
                select(NotificationDestinationModel)
                .where(
                    NotificationDestinationModel.workspace_id == ctx.workspace_id,
                    NotificationDestinationModel.id == destination_id,
                )
                .with_for_update()
            )
            if row is None or (row.user_id is not None and row.user_id != ctx.auth.user.id):
                raise NotFoundError(
                    code="notification_destination_not_found",
                    detail="Notification destination was not found.",
                )
            fields = body.model_fields_set
            if "address" in fields or "consent_id" in fields:
                next_address = (body.address or "").strip() if "address" in fields else row.address
                next_consent_id = body.consent_id if "consent_id" in fields else row.consent_id
                consent = (
                    await db.scalar(
                        select(ConsentModel.id).where(
                            ConsentModel.workspace_id == ctx.workspace_id,
                            ConsentModel.id == next_consent_id,
                            ConsentModel.purpose == "notification",
                            ConsentModel.destination == next_address,
                            ConsentModel.revoked_at.is_(None),
                        )
                    )
                    if next_consent_id
                    else None
                )
                if consent is None:
                    raise ConflictError(
                        code="notification_consent_invalid",
                        detail="An active consent matching the destination address is required.",
                    )
            if if_match != f'"v{row.version}"':
                raise ConflictError(
                    code="version_conflict", detail="Destination was changed by another request."
                )
            if body.status == "ready":
                raise ConflictError(
                    code="destination_adapter_unavailable",
                    detail=(
                        "A channel adapter and successful verification are required "
                        "before enabling this destination."
                    ),
                )
            changed = False
            if "address" in fields and body.address is not None:
                address_changed = row.address != body.address.strip()
                changed = changed or address_changed
                row.address = body.address.strip()
                if address_changed:
                    row.status = "not_configured"
            if "consent_id" in fields:
                consent_changed = row.consent_id != body.consent_id
                changed = changed or consent_changed
                row.consent_id = body.consent_id
                if consent_changed:
                    row.status = "not_configured"
            if body.status is not None:
                changed = changed or row.status != body.status
                row.status = body.status
            if changed:
                row.version += 1
                row.updated_at = iam.now().astimezone(UTC)
                await append_audit_entry(
                    db,
                    workspace_id=ctx.workspace_id,
                    actor_type="user",
                    actor_id=ctx.auth.user.id,
                    action="notification.destination.updated",
                    target=f"notification_destination:{destination_id}",
                    decision="allow",
                    reason_code="configured",
                    correlation_id=current_correlation_id(),
                    client_ip=extract_client_ip(request),
                    occurred_at=row.updated_at,
                )
            await db.flush()
            return _destination_dto(row)

    @router.delete("/workspaces/{ws}/notification-destinations/{destination_id}", status_code=204)
    async def delete_destination(
        request: Request,
        ws: Annotated[str, Path()],
        destination_id: str,
        ctx: Annotated[WorkspaceAccessContext, Depends(_WRITE)],
    ) -> Response:
        iam = get_iam_service(request)
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            row = await db.scalar(
                select(NotificationDestinationModel)
                .where(
                    NotificationDestinationModel.workspace_id == ctx.workspace_id,
                    NotificationDestinationModel.id == destination_id,
                )
                .with_for_update()
            )
            if row is None or (row.user_id is not None and row.user_id != ctx.auth.user.id):
                raise NotFoundError(
                    code="notification_destination_not_found",
                    detail="Notification destination was not found.",
                )
            if row.channel == "in_app":
                raise ConflictError(
                    code="in_app_destination_managed",
                    detail="The in-app inbox destination cannot be removed.",
                )
            if row.status == "disabled" and row.address == "[removed]":
                return Response(status_code=204)
            # Preserve delivery history and logical keys while removing destination access.
            row.address = "[removed]"
            row.secret_ref = None
            row.consent_id = None
            row.status = "disabled"
            row.version += 1
            row.updated_at = iam.now().astimezone(UTC)
            await append_audit_entry(
                db,
                workspace_id=ctx.workspace_id,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                action="notification.destination.removed",
                target=f"notification_destination:{destination_id}",
                decision="allow",
                reason_code="operator_removed",
                correlation_id=current_correlation_id(),
                client_ip=extract_client_ip(request),
                occurred_at=row.updated_at,
            )
            return Response(status_code=204)

    @router.post(
        "/workspaces/{ws}/notification-destinations/{destination_id}/tests", status_code=202
    )
    async def test_destination(
        body: NotificationTestRequest,
        request: Request,
        ws: Annotated[str, Path()],
        destination_id: str,
        ctx: Annotated[WorkspaceAccessContext, Depends(_WRITE)],
    ) -> dict[str, str]:
        if not body.confirmed:
            raise ForbiddenError(
                code="test_send_confirmation_required",
                detail="Explicit confirmation is required before a test send.",
            )
        iam = get_iam_service(request)
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            destination = await db.scalar(
                select(NotificationDestinationModel).where(
                    NotificationDestinationModel.workspace_id == ctx.workspace_id,
                    NotificationDestinationModel.id == destination_id,
                )
            )
            if destination is None or (
                destination.user_id is not None and destination.user_id != ctx.auth.user.id
            ):
                raise NotFoundError(
                    code="notification_destination_not_found",
                    detail="Notification destination was not found.",
                )
            expected_version = destination.version
        dispatcher = getattr(request.app.state, "notification_dispatcher", None)
        if dispatcher is None:
            raise DependencyUnavailableError(
                code="notification_adapter_unavailable",
                detail="No channel adapter is configured; no test message was sent.",
            )
        result = await dispatcher.test_destination(
            ctx.workspace_id, destination_id, expected_version=expected_version
        )
        if result == "version_conflict":
            raise ConflictError(
                code="version_conflict",
                detail="Notification destination changed; reload before sending a test.",
            )
        if result == "unavailable":
            raise DependencyUnavailableError(
                code="notification_adapter_unavailable",
                detail="No channel adapter is configured; no test message was sent.",
            )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            await append_audit_entry(
                db,
                workspace_id=ctx.workspace_id,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                action="notification.destination.tested",
                target=f"notification_destination:{destination_id}",
                decision="allow" if result == "accepted" else "deny",
                reason_code=f"test_{result}",
                correlation_id=current_correlation_id(),
                client_ip=extract_client_ip(request),
                occurred_at=iam.now().astimezone(UTC),
            )
        return {"state": result}

    @router.get(
        "/workspaces/{ws}/notification-deliveries", response_model=Page[NotificationDelivery]
    )
    async def list_deliveries(
        request: Request,
        ws: Annotated[str, Path()],
        ctx: Annotated[WorkspaceAccessContext, Depends(_READ)],
        destination_id: Annotated[str | None, Query()] = None,
        state: Annotated[
            str | None,
            Query(
                pattern="^(pending|sending|accepted|delivered|bounced|retry_wait|unknown|possible_duplicate|failed_final|suppressed)$"
            ),
        ] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
    ) -> Page[NotificationDelivery]:
        iam = get_iam_service(request)
        now = iam.now().astimezone(UTC)
        filter_hash = compute_query_filter_hash(
            {
                "endpoint": "notification-deliveries.list",
                "destination_id": destination_id or "",
                "state": state or "",
            }
        )
        decoded = (
            decode_signed_cursor(
                cursor,
                signing_key=iam.csrf_signing_key,
                expected_workspace_scope=ctx.workspace_id,
                expected_principal_id=ctx.auth.user.id,
                current_grant_epoch=ctx.auth.user.grant_epoch,
                expected_query_hash=filter_hash,
                now=now,
            )
            if cursor
            else None
        )
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            query = (
                select(NotificationDeliveryModel)
                .join(
                    NotificationEventModel,
                    and_(
                        NotificationEventModel.workspace_id
                        == NotificationDeliveryModel.workspace_id,
                        NotificationEventModel.id == NotificationDeliveryModel.event_id,
                    ),
                )
                .where(NotificationDeliveryModel.workspace_id == ctx.workspace_id)
            )
            if not ctx.has_workspace_wide_repo_read:
                query = query.where(
                    or_(
                        NotificationEventModel.repository_id.is_(None),
                        NotificationEventModel.repository_id.in_(ctx.repository_grants),
                    )
                )
            if destination_id:
                query = query.where(NotificationDeliveryModel.destination_id == destination_id)
            if state:
                query = query.where(NotificationDeliveryModel.state == state)
            if decoded:
                query = query.where(
                    or_(
                        NotificationDeliveryModel.created_at < decoded.created_at,
                        and_(
                            NotificationDeliveryModel.created_at == decoded.created_at,
                            NotificationDeliveryModel.id < decoded.item_id,
                        ),
                    )
                )
            rows = list(
                (
                    await db.scalars(
                        query.order_by(
                            NotificationDeliveryModel.created_at.desc(),
                            NotificationDeliveryModel.id.desc(),
                        ).limit(limit + 1)
                    )
                ).all()
            )
            visible = rows[:limit]
            next_cursor = (
                encode_signed_cursor(
                    signing_key=iam.csrf_signing_key,
                    workspace_scope=ctx.workspace_id,
                    principal_id=ctx.auth.user.id,
                    grant_epoch=ctx.auth.user.grant_epoch,
                    query_hash=filter_hash,
                    created_at=visible[-1].created_at,
                    item_id=visible[-1].id,
                    now=now,
                )
                if len(rows) > limit and visible
                else None
            )
            items = [
                NotificationDelivery(
                    id=row.id,
                    workspace_id=row.workspace_id,
                    version=1,
                    created_at=row.created_at,
                    updated_at=row.updated_at,
                    event_id=row.event_id,
                    destination_id=row.destination_id,
                    template_revision=row.template_revision,
                    state=cast(DeliveryState, row.state),
                    possible_duplicate=row.possible_duplicate,
                    attempt=row.attempt,
                    next_retry_at=row.next_retry_at,
                    provider_id=row.provider_id,
                    last_error_code=row.last_error_code,
                )
                for row in visible
            ]
            return Page[NotificationDelivery](items=items, next_cursor=next_cursor, snapshot_at=now)

    @router.get("/me/notification-preferences", response_model=NotificationPreferencesState)
    async def get_preferences(
        request: Request,
        iam: Annotated[IamService, Depends(get_iam_service)],
        workspace_id: Annotated[str | None, Query()] = None,
    ) -> NotificationPreferencesState:
        auth = await iam.authenticate_request(
            request, require_csrf=False, correlation_id=current_correlation_id()
        )
        if workspace_id is None:
            async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
                row = await _get_preference(db, user_id=auth.user.id, workspace_id=None)
                return _preference_state(row, None)
        async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
            membership = await db.scalar(
                select(MembershipModel.id).where(
                    MembershipModel.workspace_id == workspace_id,
                    MembershipModel.user_id == auth.user.id,
                )
            )
            if membership is None:
                raise NotFoundError(code="workspace_not_found", detail="Workspace not found.")
        async with workspace_rls_session(iam.session_factory, workspace_id=workspace_id) as db:
            row = await _get_preference(db, user_id=auth.user.id, workspace_id=workspace_id)
            if row is not None:
                return _preference_state(row, workspace_id)
            return _preference_state(None, workspace_id)

    @router.patch("/me/notification-preferences", response_model=NotificationPreferencesState)
    async def patch_preferences(
        body: NotificationPreferencesPatchRequest,
        request: Request,
        iam: Annotated[IamService, Depends(get_iam_service)],
    ) -> NotificationPreferencesState:
        auth = await iam.authenticate_request(
            request, require_csrf=True, correlation_id=current_correlation_id()
        )
        if body.timezone is not None:
            try:
                ZoneInfo(body.timezone)
            except ZoneInfoNotFoundError as exc:
                raise UnprocessableEntityError(
                    code="invalid_timezone", detail="Timezone must be a valid IANA timezone."
                ) from exc
        now = iam.now().astimezone(UTC)
        if body.workspace_id is not None:
            async with instance_rls_session(iam.session_factory, mode="instance_admin") as db:
                membership = await db.scalar(
                    select(MembershipModel.id).where(
                        MembershipModel.workspace_id == body.workspace_id,
                        MembershipModel.user_id == auth.user.id,
                    )
                )
                if membership is None:
                    raise NotFoundError(code="workspace_not_found", detail="Workspace not found.")
        if body.workspace_id is None:
            context = instance_rls_session(iam.session_factory, mode="instance_admin")
        else:
            context = workspace_rls_session(iam.session_factory, workspace_id=body.workspace_id)
        async with context as db:
            row = await _get_preference(db, user_id=auth.user.id, workspace_id=body.workspace_id)
            is_new = row is None
            if row is None:
                row = UserNotificationPreferenceModel(
                    id=new_uuid7(now=now),
                    workspace_id=body.workspace_id,
                    user_id=auth.user.id,
                    event_types_json=[],
                    min_severity="info",
                    quiet_hours_json=None,
                    timezone="UTC",
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
                db.add(row)
            next_event_types: list[str] = (
                list(dict.fromkeys(body.event_types))
                if body.event_types is not None
                else row.event_types_json
            )
            next_min_severity = body.min_severity or row.min_severity
            next_quiet_hours = (
                (body.quiet_hours.model_dump(mode="json") if body.quiet_hours else None)
                if "quiet_hours" in body.model_fields_set
                else row.quiet_hours_json
            )
            next_timezone = body.timezone or row.timezone
            changed = is_new or (
                next_event_types != row.event_types_json
                or next_min_severity != row.min_severity
                or next_quiet_hours != row.quiet_hours_json
                or next_timezone != row.timezone
            )
            if body.event_types is not None:
                row.event_types_json = next_event_types
            if body.min_severity is not None:
                row.min_severity = next_min_severity
            if "quiet_hours" in body.model_fields_set:
                row.quiet_hours_json = next_quiet_hours
            if body.timezone is not None:
                row.timezone = next_timezone
            if changed:
                if not is_new:
                    row.version += 1
                row.updated_at = now
            await db.flush()
            return _preference_state(row, body.workspace_id)

    @router.post(
        "/workspaces/{ws}/notification-destinations/{destination_id}/webhook-key/rotate",
        status_code=201,
        response_model=WebhookSigningKeyRotateResponse,
    )
    async def rotate_webhook_key(
        request: Request,
        ws: Annotated[str, Path()],
        destination_id: str,
        ctx: Annotated[WorkspaceAccessContext, Depends(_WRITE)],
    ) -> WebhookSigningKeyRotateResponse:
        iam = get_iam_service(request)
        broker = getattr(request.app.state, "notification_secret_broker", None)
        if not isinstance(broker, SecretBroker):
            raise DependencyUnavailableError(
                code="notification_secret_store_unavailable",
                detail=(
                    "Notification signing keys cannot be issued while the encrypted secret "
                    "store is unavailable."
                ),
            )
        now = iam.now().astimezone(UTC)
        key_id = f"whk_{new_uuid7(now=now)}"
        raw_secret = secrets.token_urlsafe(32)
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            destination = await db.scalar(
                select(NotificationDestinationModel)
                .where(
                    NotificationDestinationModel.workspace_id == ctx.workspace_id,
                    NotificationDestinationModel.id == destination_id,
                )
                .with_for_update()
            )
            if destination is None or destination.channel != "webhook":
                raise NotFoundError(
                    code="webhook_destination_not_found",
                    detail="Signed webhook destination was not found.",
                )
            active = await db.scalar(
                select(WebhookSigningKeyModel)
                .where(
                    WebhookSigningKeyModel.workspace_id == ctx.workspace_id,
                    WebhookSigningKeyModel.destination_id == destination.id,
                    WebhookSigningKeyModel.status == "active",
                )
                .with_for_update()
            )
            if active is not None:
                active.status = "overlap"
                active.expires_at = now + timedelta(hours=48)
            metadata = await broker.store_secret(
                db,
                plaintext=raw_secret.encode("ascii"),
                purpose="notification_channel",
                workspace_id=ctx.workspace_id,
                now=now,
            )
            db.add(
                WebhookSigningKeyModel(
                    id=new_uuid7(now=now),
                    workspace_id=ctx.workspace_id,
                    destination_id=destination.id,
                    key_id=key_id,
                    secret_ref=metadata.secret_ref,
                    status="active",
                    created_at=now,
                    expires_at=None,
                    revoked_at=None,
                )
            )
            destination.secret_ref = metadata.secret_ref
            destination.status = "not_configured"
            destination.verified_at = None
            destination.version += 1
            destination.updated_at = now
            await append_audit_entry(
                db,
                workspace_id=ctx.workspace_id,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                action="notification.webhook_key.rotated",
                target=f"notification_destination:{destination.id}",
                decision="allow",
                reason_code="active_key_rotated_with_48h_overlap",
                correlation_id=current_correlation_id(),
                client_ip=extract_client_ip(request),
                occurred_at=now,
                metadata={"key_id": key_id},
            )
        return WebhookSigningKeyRotateResponse(key_id=key_id, secret=raw_secret, overlap_hours=48)

    @router.put(
        "/workspaces/{ws}/notification-destinations/{destination_id}/credentials",
        status_code=204,
    )
    async def replace_notification_credential(
        body: NotificationCredentialWriteRequest,
        request: Request,
        ws: Annotated[str, Path()],
        destination_id: str,
        ctx: Annotated[WorkspaceAccessContext, Depends(_WRITE)],
    ) -> Response:
        iam = get_iam_service(request)
        broker = getattr(request.app.state, "notification_secret_broker", None)
        if not isinstance(broker, SecretBroker):
            raise DependencyUnavailableError(
                code="notification_secret_store_unavailable",
                detail=(
                    "Notification credentials cannot be stored while the encrypted secret "
                    "store is unavailable."
                ),
            )
        now = iam.now().astimezone(UTC)
        async with workspace_rls_session(iam.session_factory, workspace_id=ctx.workspace_id) as db:
            destination = await db.scalar(
                select(NotificationDestinationModel)
                .where(
                    NotificationDestinationModel.workspace_id == ctx.workspace_id,
                    NotificationDestinationModel.id == destination_id,
                )
                .with_for_update()
            )
            if destination is None or destination.channel in {"webhook", "in_app"}:
                raise NotFoundError(
                    code="notification_destination_not_found",
                    detail="Credential-managed notification destination was not found.",
                )
            previous_secret_ref = destination.secret_ref
            metadata = await broker.store_secret(
                db,
                plaintext=body.secret_value.get_secret_value().encode("utf-8"),
                purpose="notification_channel",
                workspace_id=ctx.workspace_id,
                now=now,
            )
            destination.secret_ref = metadata.secret_ref
            destination.status = "not_configured"
            destination.verified_at = None
            destination.version += 1
            destination.updated_at = now
            if previous_secret_ref:
                await broker.revoke_secret(
                    db,
                    secret_ref=previous_secret_ref,
                    workspace_id=ctx.workspace_id,
                    now=now,
                )
            await append_audit_entry(
                db,
                workspace_id=ctx.workspace_id,
                actor_type="user",
                actor_id=ctx.auth.user.id,
                action="notification.destination.credential_replaced",
                target=f"notification_destination:{destination.id}",
                decision="allow",
                reason_code="encrypted_credential_replaced",
                correlation_id=current_correlation_id(),
                client_ip=extract_client_ip(request),
                occurred_at=now,
                metadata={"channel": destination.channel},
            )
        return Response(status_code=204)

    return router
