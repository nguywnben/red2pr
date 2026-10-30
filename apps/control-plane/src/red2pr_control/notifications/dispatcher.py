"""Committed S-19 outbox projection into a scoped, durable in-app inbox (U21)."""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from py_contracts.crypto import sha256_canonical_json
from py_contracts.events import EventEnvelope
from py_contracts.primitives import new_uuid7
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor
from red2pr_control.db.base import (
    ConsentModel,
    DeliveryAttemptModel,
    MembershipModel,
    NotificationDeliveryModel,
    NotificationDestinationModel,
    NotificationEventModel,
    OutboxEventModel,
    RepoGrantModel,
    RepositoryModel,
    SecretEntryModel,
    UserInboxItemModel,
    UserModel,
    UserNotificationPreferenceModel,
    WorkspaceModel,
)
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.notifications.templates import render_event_template

_SECURITY_EVENTS = frozenset(
    {
        "security.policy.denied",
        "identity.permission_revoked",
        "worker.quarantined",
        "backup.failed",
    }
)
_SEVERITY_ORDER = {
    "info": 0,
    "success": 0,
    "warning": 1,
    "action": 2,
    "error": 3,
    "high": 4,
    "critical": 5,
}
_ADAPTER_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True, slots=True)
class DispatchResult:
    events_processed: int
    inbox_items_created: int


@dataclass(frozen=True, slots=True)
class DeliveryAttemptResult:
    state: str
    possible_duplicate: bool
    next_retry_at: datetime | None
    error_code: str | None


@dataclass(frozen=True, slots=True)
class NotificationSendRequest:
    """Redacted, minimal channel payload; secret references are opaque and write-only."""

    workspace_id: str
    delivery_id: str | None
    event_id: str | None
    correlation_id: str
    channel: str
    address: str
    secret_ref: str | None
    title: str
    body: str
    severity: str
    deep_link: str | None
    request_digest: str
    is_test: bool = False


@dataclass(frozen=True, slots=True)
class NotificationAdapterResult:
    """Sanitized transport result; response bodies and credentials are never retained."""

    http_status: int | None = None
    provider_id: str | None = None
    retry_after_seconds: int | None = None
    timed_out_after_send: bool = False
    error_code: str | None = None


class NotificationChannelAdapter(Protocol):
    """Channel adapters perform bounded I/O through the channel-specific secret broker."""

    async def deliver(self, request: NotificationSendRequest) -> NotificationAdapterResult: ...

    async def send_test(self, request: NotificationSendRequest) -> NotificationAdapterResult: ...


def classify_delivery_attempt(
    *,
    attempt: int,
    first_attempt_at: datetime,
    now: datetime,
    http_status: int | None = None,
    timed_out_after_send: bool = False,
    retry_after_seconds: int | None = None,
    random_value: float = 0.5,
) -> DeliveryAttemptResult:
    """Apply the bounded 8-attempt/24-hour policy without retrying ambiguous writes."""
    if timed_out_after_send:
        return DeliveryAttemptResult("unknown", True, None, "timeout_after_send")
    if http_status is not None and 200 <= http_status < 300:
        return DeliveryAttemptResult("accepted", False, None, None)
    permanent = http_status in {400, 401, 403, 404, 410, 422}
    if permanent:
        return DeliveryAttemptResult("failed_final", False, None, f"http_{http_status}")
    elapsed = now.astimezone(UTC) - first_attempt_at.astimezone(UTC)
    if attempt >= 8 or elapsed >= timedelta(hours=24):
        return DeliveryAttemptResult("failed_final", False, None, "attempt_budget_exhausted")
    base_seconds = min(30 * (2 ** max(0, attempt - 1)), 6 * 60 * 60)
    jitter = 0.8 + max(0.0, min(1.0, random_value)) * 0.4
    retry_after = max(0, min(retry_after_seconds or 0, 24 * 60 * 60))
    delay = max(base_seconds * jitter, float(retry_after))
    return DeliveryAttemptResult(
        "retry_wait",
        False,
        now.astimezone(UTC) + timedelta(seconds=delay),
        f"http_{http_status}" if http_status is not None else "transport_error",
    )


def should_defer_external_delivery(
    *,
    event_type: str,
    severity: str,
    preference: UserNotificationPreferenceModel | None,
    now: datetime,
) -> bool:
    """Evaluate event subscription, severity floor and local-time quiet hours."""
    if preference is None:
        return False
    if preference.event_types_json and event_type not in preference.event_types_json:
        return True
    if _SEVERITY_ORDER.get(severity, 0) < _SEVERITY_ORDER.get(preference.min_severity, 0):
        return True
    window = preference.quiet_hours_json
    if not window:
        return False
    try:
        local_now = now.astimezone(ZoneInfo(preference.timezone))
    except ZoneInfoNotFoundError:
        return True
    minute = local_now.hour * 60 + local_now.minute
    start_h, start_m = (int(part) for part in window["start_hhmm"].split(":"))
    end_h, end_m = (int(part) for part in window["end_hhmm"].split(":"))
    start, end = start_h * 60 + start_m, end_h * 60 + end_m
    if start == end:
        return False
    return start <= minute < end if start < end else minute >= start or minute < end


async def _destination_consent_is_active(
    db: AsyncSession,
    *,
    workspace_id: str,
    destination: NotificationDestinationModel,
) -> bool:
    if destination.consent_id is None:
        return False
    consent = await db.scalar(
        select(ConsentModel.id).where(
            ConsentModel.workspace_id == workspace_id,
            ConsentModel.id == destination.consent_id,
            ConsentModel.purpose == "notification",
            ConsentModel.destination == destination.address,
            ConsentModel.revoked_at.is_(None),
        )
    )
    if consent is None:
        return False
    if destination.secret_ref is None:
        return True
    secret = await db.scalar(
        select(SecretEntryModel.id).where(
            SecretEntryModel.workspace_id == workspace_id,
            SecretEntryModel.secret_ref == destination.secret_ref,
            SecretEntryModel.purpose == "notification_channel",
            SecretEntryModel.revoked_at.is_(None),
        )
    )
    return secret is not None


async def _preference_delivery_window(
    db: AsyncSession,
    *,
    workspace_id: str,
    user_ids: list[str],
    event_type: str,
    severity: str,
    now: datetime,
) -> tuple[str | None, datetime | None]:
    preferences = list(
        await db.scalars(
            select(UserNotificationPreferenceModel).where(
                UserNotificationPreferenceModel.workspace_id == workspace_id,
                UserNotificationPreferenceModel.user_id.in_(user_ids),
            )
        )
    )
    by_user = {preference.user_id: preference for preference in preferences}
    due_times: list[datetime] = []
    eligible_now = False
    has_unmuted_recipient = False
    for user_id in user_ids:
        preference = by_user.get(user_id)
        if preference is not None and (
            (preference.event_types_json and event_type not in preference.event_types_json)
            or _SEVERITY_ORDER.get(severity, 0) < _SEVERITY_ORDER.get(preference.min_severity, 0)
        ):
            continue
        has_unmuted_recipient = True
        if preference is None or not should_defer_external_delivery(
            event_type=event_type,
            severity=severity,
            preference=preference,
            now=now,
        ):
            eligible_now = True
        elif preference.quiet_hours_json:
            try:
                due_times.append(_quiet_hours_end_utc(preference, now))
            except (ValueError, KeyError, ZoneInfoNotFoundError):
                return "invalid_preference", None
    if eligible_now:
        return None, None
    if due_times:
        return "quiet_hours", min(due_times)
    return (None, None) if has_unmuted_recipient else ("muted", None)


def _quiet_hours_end_utc(preference: UserNotificationPreferenceModel, now: datetime) -> datetime:
    window = preference.quiet_hours_json or {}
    zone = ZoneInfo(preference.timezone)
    local_now = now.astimezone(zone)
    end_hour, end_minute = (int(part) for part in window["end_hhmm"].split(":"))
    candidate = local_now.replace(hour=end_hour, minute=end_minute, second=0, microsecond=0, fold=0)
    if candidate <= local_now:
        candidate += timedelta(days=1)
    return candidate.astimezone(UTC)


def _safe_adapter_error_code(value: str) -> str:
    """Persist only a short identifier, never adapter-provided response text."""
    if len(value) > 120 or re.fullmatch(r"[a-zA-Z0-9_.:-]+", value) is None:
        return "adapter_error"
    return value


def _safe_provider_id(value: str | None, redactor: Redactor) -> str | None:
    if not value:
        return None
    candidate = redactor.redact_text(value)
    if len(candidate) > 128 or any(ord(char) < 32 for char in candidate):
        return None
    return candidate


class NotificationDispatcher:
    """Project committed events and drive bounded, consent-checked channel delivery."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        redactor: Redactor = DEFAULT_REDACTOR,
        clock: Callable[[], datetime] | None = None,
        poll_interval_seconds: float = 1.0,
        adapters: Mapping[str, NotificationChannelAdapter] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._redactor = redactor
        self._clock = clock or (lambda: datetime.now(tz=UTC))
        self._poll_interval_seconds = max(0.25, poll_interval_seconds)
        self._adapters = dict(adapters or {})

    def register_setup_probe(self, registry: Any) -> None:
        """Register U21's actual in-app readiness check with the existing setup registry."""
        from red2pr_control.operations.setup_wizard import SetupStepProbeResult

        async def probe(_phase: str, _draft: dict[str, Any]) -> SetupStepProbeResult:
            try:
                async with instance_rls_session(self._session_factory, mode="instance_only") as db:
                    await db.execute(select(1))
            except Exception:
                return SetupStepProbeResult(
                    probe_status="blocked",
                    detail="Notification persistence is unavailable.",
                    blocking_reasons=("notification_persistence_unavailable",),
                )
            return SetupStepProbeResult(
                probe_status="passed",
                detail="Committed-event dispatcher and in-app inbox persistence are available.",
            )

        registry.register_probe("notifications", probe)

    async def dispatch_workspace_once(
        self, workspace_id: str, *, limit: int = 50
    ) -> DispatchResult:
        """Claim and project a bounded batch in one DB transaction, with row-lock deduplication."""
        now = self._clock().astimezone(UTC)
        processed = inbox_created = 0
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            # Serialize lazy in-app destination creation and outbox claims per workspace.
            workspace = await db.scalar(
                select(WorkspaceModel).where(WorkspaceModel.id == workspace_id).with_for_update()
            )
            if workspace is None:
                return DispatchResult(0, 0)
            destination = await db.scalar(
                select(NotificationDestinationModel).where(
                    NotificationDestinationModel.workspace_id == workspace_id,
                    NotificationDestinationModel.channel == "in_app",
                    NotificationDestinationModel.scope == "workspace",
                )
            )
            if destination is None:
                destination = NotificationDestinationModel(
                    id=new_uuid7(now=now),
                    workspace_id=workspace_id,
                    channel="in_app",
                    scope="workspace",
                    address=f"inbox:{workspace_id}",
                    status="ready",
                    created_at=now,
                    updated_at=now,
                )
                db.add(destination)
                await db.flush()

            rows = (
                await db.scalars(
                    select(OutboxEventModel)
                    .where(
                        OutboxEventModel.workspace_id == workspace_id,
                        ~select(NotificationEventModel.id)
                        .where(NotificationEventModel.id == OutboxEventModel.id)
                        .exists(),
                    )
                    .order_by(OutboxEventModel.created_at, OutboxEventModel.id)
                    .limit(max(1, min(limit, 100)))
                    .with_for_update(skip_locked=True)
                )
            ).all()
            for outbox in rows:
                event = EventEnvelope.model_validate(
                    {
                        "event_id": outbox.id,
                        "schema_version": outbox.schema_version,
                        "type": outbox.event_type,
                        "occurred_at": outbox.occurred_at,
                        "workspace_id": outbox.workspace_id,
                        "repository_id": outbox.repository_id,
                        "session_id": outbox.session_id,
                        "aggregate_id": outbox.aggregate_id,
                        "aggregate_version": outbox.aggregate_version,
                        "correlation_id": outbox.correlation_id,
                        "causation_id": outbox.causation_id,
                        "payload": outbox.payload,
                    }
                )
                payload = self._redactor.redact_value(event.payload.model_dump(mode="json"))
                event_projection = NotificationEventModel(
                    id=event.event_id,
                    workspace_id=workspace_id,
                    event_type=event.type,
                    correlation_id=event.correlation_id,
                    repository_id=event.repository_id,
                    payload_json=payload if isinstance(payload, dict) else {},
                    template_revision=1,
                    occurred_at=event.occurred_at.astimezone(UTC),
                    created_at=now,
                )
                db.add(event_projection)
                await db.flush()
                repo_name = None
                if event.repository_id is not None:
                    repo_name = await db.scalar(
                        select(RepositoryModel.name).where(
                            RepositoryModel.workspace_id == workspace_id,
                            RepositoryModel.id == event.repository_id,
                        )
                    )
                target = _event_link(
                    workspace_id, event.type, event.payload.model_dump(mode="json")
                )
                rendered = render_event_template(
                    event,
                    repository_name=repo_name,
                    deep_link=target,
                    redactor=self._redactor,
                )
                recipients = await self._recipients(
                    db,
                    workspace_id=workspace_id,
                    repository_id=event.repository_id,
                    security=event.type in _SECURITY_EVENTS,
                )
                if recipients:
                    statement = (
                        pg_insert(UserInboxItemModel)
                        .values(
                            [
                                {
                                    "id": new_uuid7(now=now),
                                    "workspace_id": workspace_id,
                                    "event_id": event.event_id,
                                    "user_id": user_id,
                                    "repository_id": event.repository_id,
                                    "event_type": event.type,
                                    "title": rendered.title[:120],
                                    "body": rendered.body[:4096],
                                    "severity": rendered.severity,
                                    "deep_link": rendered.deep_link,
                                    "is_security": event.type in _SECURITY_EVENTS,
                                    "read_at": None,
                                    "created_at": now,
                                }
                                for user_id in recipients
                            ]
                        )
                        .on_conflict_do_nothing(constraint="uq_user_inbox_event_user")
                        .returning(UserInboxItemModel.id)
                    )
                    result = await db.execute(statement)
                    inbox_created += len(result.scalars().all())
                destinations = list(
                    await db.scalars(
                        select(NotificationDestinationModel).where(
                            NotificationDestinationModel.workspace_id == workspace_id,
                            NotificationDestinationModel.status != "disabled",
                        )
                    )
                )
                for target_destination in destinations:
                    prior_delivery = await db.scalar(
                        select(NotificationDeliveryModel).where(
                            NotificationDeliveryModel.workspace_id == workspace_id,
                            NotificationDeliveryModel.event_id == event.event_id,
                            NotificationDeliveryModel.destination_id == target_destination.id,
                            NotificationDeliveryModel.template_revision == 1,
                        )
                    )
                    if prior_delivery is not None:
                        continue
                    target_recipients = recipients
                    if target_destination.scope == "user":
                        target_recipients = [
                            user_id
                            for user_id in recipients
                            if user_id == target_destination.user_id
                        ]
                    delivery_state = "pending"
                    error_code = None
                    next_retry_at = None
                    if target_destination.channel == "in_app":
                        delivery_state = "accepted" if target_recipients else "suppressed"
                        error_code = None if target_recipients else "no_authorized_recipients"
                    elif not target_recipients:
                        delivery_state = "suppressed"
                        error_code = "no_authorized_recipients"
                    elif target_destination.status != "ready":
                        delivery_state = "suppressed"
                        error_code = "destination_not_ready"
                    elif not await _destination_consent_is_active(
                        db, workspace_id=workspace_id, destination=target_destination
                    ):
                        delivery_state = "suppressed"
                        error_code = "notification_consent_revoked"
                    else:
                        deferred, due = await _preference_delivery_window(
                            db,
                            workspace_id=workspace_id,
                            user_ids=target_recipients,
                            event_type=event.type,
                            severity=rendered.severity,
                            now=now,
                        )
                        if deferred == "muted":
                            delivery_state = "suppressed"
                            error_code = "recipient_preference_suppressed"
                        elif deferred == "invalid_preference":
                            delivery_state = "suppressed"
                            error_code = "invalid_notification_preference"
                        elif deferred == "quiet_hours":
                            delivery_state = "retry_wait"
                            next_retry_at = due
                            error_code = "quiet_hours"
                    digest = sha256_canonical_json(
                        {
                            "event_id": event.event_id,
                            "destination_id": target_destination.id,
                            "template_revision": 1,
                            "title": rendered.title,
                            "body": rendered.body,
                            "deep_link": rendered.deep_link,
                        }
                    )
                    db.add(
                        NotificationDeliveryModel(
                            id=new_uuid7(now=now),
                            workspace_id=workspace_id,
                            event_id=event.event_id,
                            destination_id=target_destination.id,
                            template_revision=1,
                            state=delivery_state,
                            possible_duplicate=False,
                            attempt=0,
                            next_retry_at=next_retry_at,
                            request_digest=digest,
                            last_error_code=error_code,
                            created_at=now,
                            updated_at=now,
                        )
                    )
                processed += 1
            await db.flush()
        return DispatchResult(processed, inbox_created)

    async def test_destination(
        self, workspace_id: str, destination_id: str, *, expected_version: int
    ) -> str:
        """Send a confirmed, fixed-content probe; only a verified response enables delivery."""
        now = self._clock().astimezone(UTC)
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            destination = await db.scalar(
                select(NotificationDestinationModel)
                .where(
                    NotificationDestinationModel.workspace_id == workspace_id,
                    NotificationDestinationModel.id == destination_id,
                )
                .with_for_update()
            )
            if destination is None or destination.channel == "in_app":
                return "unavailable"
            if destination.version != expected_version:
                return "version_conflict"
            adapter = self._adapters.get(destination.channel)
            if adapter is None:
                return "unavailable"
            if destination.status == "disabled" or not await _destination_consent_is_active(
                db, workspace_id=workspace_id, destination=destination
            ):
                return "suppressed"
            request = NotificationSendRequest(
                workspace_id=workspace_id,
                delivery_id=None,
                event_id=None,
                correlation_id=new_uuid7(now=now),
                channel=destination.channel,
                address=destination.address,
                secret_ref=destination.secret_ref,
                title="Red2PR notification test",
                body="This is a test notification. No project data is included.",
                severity="info",
                deep_link=None,
                request_digest=sha256_canonical_json(
                    {
                        "channel": destination.channel,
                        "destination_id": destination.id,
                        "purpose": "notification_test",
                        "template_revision": 1,
                    }
                ),
                is_test=True,
            )

        try:
            result = await asyncio.wait_for(
                adapter.send_test(request), timeout=_ADAPTER_TIMEOUT_SECONDS
            )
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            return "unknown"
        except Exception:
            return "retry_wait"
        if result.timed_out_after_send:
            return "unknown"
        if result.http_status is None or not 200 <= result.http_status < 300:
            return "retry_wait"

        verified_at = self._clock().astimezone(UTC)
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            current = await db.scalar(
                select(NotificationDestinationModel)
                .where(
                    NotificationDestinationModel.workspace_id == workspace_id,
                    NotificationDestinationModel.id == destination_id,
                )
                .with_for_update()
            )
            if (
                current is None
                or current.status == "disabled"
                or current.address != request.address
                or current.consent_id != destination.consent_id
                or not await _destination_consent_is_active(
                    db, workspace_id=workspace_id, destination=current
                )
            ):
                return "suppressed"
            current.status = "ready"
            current.verified_at = verified_at
            current.updated_at = verified_at
        return "accepted"

    async def dispatch_pending_once(self, workspace_id: str, *, limit: int = 25) -> int:
        """Claim, re-authorize, send, and persist one bounded batch of external deliveries."""
        now = self._clock().astimezone(UTC)
        claimed: list[
            tuple[NotificationDeliveryModel, NotificationSendRequest, str, int, datetime]
        ] = []
        async with workspace_rls_session(self._session_factory, workspace_id=workspace_id) as db:
            # A crashed worker may leave a committed claim without an outcome. Never resend it.
            stale_sending = list(
                (
                    await db.scalars(
                        select(NotificationDeliveryModel)
                        .where(
                            NotificationDeliveryModel.workspace_id == workspace_id,
                            NotificationDeliveryModel.state == "sending",
                            NotificationDeliveryModel.updated_at
                            <= now - timedelta(seconds=_ADAPTER_TIMEOUT_SECONDS + 5),
                        )
                        .order_by(NotificationDeliveryModel.updated_at)
                        .limit(100)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
            )
            for stale in stale_sending:
                claimed_at = stale.updated_at
                attempt_exists = await db.scalar(
                    select(DeliveryAttemptModel.id).where(
                        DeliveryAttemptModel.workspace_id == workspace_id,
                        DeliveryAttemptModel.delivery_id == stale.id,
                        DeliveryAttemptModel.attempt == stale.attempt,
                    )
                )
                stale.state = "unknown"
                stale.possible_duplicate = True
                stale.next_retry_at = None
                stale.last_error_code = "sender_lease_expired"
                stale.updated_at = now
                if attempt_exists is None:
                    db.add(
                        DeliveryAttemptModel(
                            id=new_uuid7(now=now),
                            workspace_id=workspace_id,
                            delivery_id=stale.id,
                            attempt=stale.attempt,
                            outcome="unknown",
                            error_code="sender_lease_expired",
                            request_digest=stale.request_digest,
                            started_at=claimed_at,
                            completed_at=now,
                        )
                    )
            rows = list(
                (
                    await db.scalars(
                        select(NotificationDeliveryModel)
                        .where(
                            NotificationDeliveryModel.workspace_id == workspace_id,
                            NotificationDeliveryModel.state.in_(("pending", "retry_wait")),
                            or_(
                                NotificationDeliveryModel.next_retry_at.is_(None),
                                NotificationDeliveryModel.next_retry_at <= now,
                            ),
                        )
                        .order_by(
                            NotificationDeliveryModel.created_at, NotificationDeliveryModel.id
                        )
                        .limit(max(1, min(limit, 100)))
                        .with_for_update(skip_locked=True)
                    )
                ).all()
            )
            for delivery in rows:
                destination = await db.scalar(
                    select(NotificationDestinationModel).where(
                        NotificationDestinationModel.workspace_id == workspace_id,
                        NotificationDestinationModel.id == delivery.destination_id,
                    )
                )
                adapter = self._adapters.get(destination.channel) if destination else None
                if destination is None:
                    delivery.state = "failed_final"
                    delivery.last_error_code = "notification_destination_missing"
                    delivery.updated_at = now
                    continue
                if adapter is None:
                    delivery.state = "suppressed"
                    delivery.last_error_code = "notification_adapter_unavailable"
                    delivery.updated_at = now
                    continue
                if destination.status != "ready":
                    delivery.state = "suppressed"
                    delivery.last_error_code = "destination_not_ready"
                    delivery.updated_at = now
                    continue
                if not await _destination_consent_is_active(
                    db, workspace_id=workspace_id, destination=destination
                ):
                    delivery.state = "suppressed"
                    delivery.last_error_code = "notification_consent_revoked"
                    delivery.updated_at = now
                    continue
                event = await db.scalar(
                    select(NotificationEventModel).where(
                        NotificationEventModel.workspace_id == workspace_id,
                        NotificationEventModel.id == delivery.event_id,
                    )
                )
                if event is None:
                    delivery.state = "failed_final"
                    delivery.last_error_code = "notification_event_missing"
                    delivery.updated_at = now
                    continue
                recipient_ids = await self._recipients(
                    db,
                    workspace_id=workspace_id,
                    repository_id=event.repository_id,
                    security=event.event_type in _SECURITY_EVENTS,
                )
                if destination.scope == "user":
                    recipient_ids = [
                        user_id for user_id in recipient_ids if user_id == destination.user_id
                    ]
                if not recipient_ids:
                    delivery.state = "suppressed"
                    delivery.last_error_code = "no_authorized_recipients"
                    delivery.updated_at = now
                    continue
                inbox_item = await db.scalar(
                    select(UserInboxItemModel)
                    .where(
                        UserInboxItemModel.workspace_id == workspace_id,
                        UserInboxItemModel.event_id == event.id,
                        UserInboxItemModel.user_id.in_(recipient_ids),
                    )
                    .order_by(UserInboxItemModel.user_id)
                    .limit(1)
                )
                if inbox_item is None:
                    delivery.state = "suppressed"
                    delivery.last_error_code = "no_authorized_recipients"
                    delivery.updated_at = now
                    continue
                preference_result, due_at = await _preference_delivery_window(
                    db,
                    workspace_id=workspace_id,
                    user_ids=recipient_ids,
                    event_type=event.event_type,
                    severity=inbox_item.severity,
                    now=now,
                )
                if preference_result == "muted":
                    delivery.state = "suppressed"
                    delivery.last_error_code = "recipient_preference_suppressed"
                    delivery.updated_at = now
                    continue
                if preference_result == "invalid_preference":
                    delivery.state = "suppressed"
                    delivery.last_error_code = "invalid_notification_preference"
                    delivery.updated_at = now
                    continue
                if preference_result == "quiet_hours":
                    delivery.state = "retry_wait"
                    delivery.next_retry_at = due_at
                    delivery.last_error_code = "quiet_hours"
                    delivery.updated_at = now
                    continue
                request_digest = delivery.request_digest or sha256_canonical_json(
                    {
                        "event_id": event.id,
                        "destination_id": destination.id,
                        "template_revision": delivery.template_revision,
                        "title": inbox_item.title,
                        "body": inbox_item.body,
                        "deep_link": inbox_item.deep_link,
                    }
                )
                first_attempt_at = await db.scalar(
                    select(DeliveryAttemptModel.started_at)
                    .where(DeliveryAttemptModel.delivery_id == delivery.id)
                    .order_by(DeliveryAttemptModel.attempt)
                    .limit(1)
                )
                if first_attempt_at is None:
                    first_attempt_at = now
                delivery.request_digest = request_digest
                delivery.state = "sending"
                delivery.attempt += 1
                delivery.updated_at = now
                request = NotificationSendRequest(
                    workspace_id=workspace_id,
                    delivery_id=delivery.id,
                    event_id=event.id,
                    correlation_id=event.correlation_id,
                    channel=destination.channel,
                    address=destination.address,
                    secret_ref=destination.secret_ref,
                    title=inbox_item.title,
                    body=self._redactor.redact_text(inbox_item.body)[:4096],
                    severity=inbox_item.severity,
                    deep_link=inbox_item.deep_link,
                    request_digest=request_digest,
                )
                claimed.append(
                    (delivery, request, destination.channel, delivery.attempt, first_attempt_at)
                )
            await db.flush()

        completed = 0
        cancelled = False
        for claim_index, (delivery, request, channel, attempt_no, first_attempt_at) in enumerate(
            claimed
        ):
            adapter = self._adapters[channel]
            timed_out = False
            adapter_result = NotificationAdapterResult(error_code="adapter_error")
            try:
                adapter_result = await asyncio.wait_for(
                    adapter.deliver(request), timeout=_ADAPTER_TIMEOUT_SECONDS
                )
            except asyncio.CancelledError:
                timed_out = True
                cancelled = True
            except TimeoutError:
                timed_out = True
            except Exception:
                adapter_result = NotificationAdapterResult(error_code="adapter_error")
            outcome = classify_delivery_attempt(
                attempt=attempt_no,
                first_attempt_at=first_attempt_at,
                now=self._clock(),
                http_status=adapter_result.http_status,
                timed_out_after_send=timed_out or adapter_result.timed_out_after_send,
                retry_after_seconds=adapter_result.retry_after_seconds,
            )
            error_code = outcome.error_code
            if error_code is None and adapter_result.error_code:
                error_code = _safe_adapter_error_code(adapter_result.error_code)
            provider_id = _safe_provider_id(adapter_result.provider_id, self._redactor)
            finished_at = self._clock().astimezone(UTC)
            async with workspace_rls_session(
                self._session_factory, workspace_id=workspace_id
            ) as db:
                current = await db.scalar(
                    select(NotificationDeliveryModel)
                    .where(
                        NotificationDeliveryModel.workspace_id == workspace_id,
                        NotificationDeliveryModel.id == delivery.id,
                    )
                    .with_for_update()
                )
                if current is None:
                    continue
                current.state = outcome.state
                current.possible_duplicate = outcome.possible_duplicate
                current.next_retry_at = outcome.next_retry_at
                current.provider_id = provider_id
                current.last_error_code = error_code
                current.updated_at = finished_at
                db.add(
                    DeliveryAttemptModel(
                        id=new_uuid7(now=finished_at),
                        workspace_id=workspace_id,
                        delivery_id=current.id,
                        attempt=attempt_no,
                        outcome=outcome.state,
                        error_code=error_code,
                        request_digest=request.request_digest,
                        started_at=now,
                        completed_at=finished_at,
                    )
                )
            completed += 1
            if cancelled:
                # Persist the ambiguous outcome before honoring task cancellation.
                for (
                    unsent_delivery,
                    _unsent_request,
                    _unsent_channel,
                    _unsent_attempt,
                    _,
                ) in claimed[claim_index + 1 :]:
                    async with workspace_rls_session(
                        self._session_factory, workspace_id=workspace_id
                    ) as db:
                        unsent = await db.scalar(
                            select(NotificationDeliveryModel)
                            .where(
                                NotificationDeliveryModel.workspace_id == workspace_id,
                                NotificationDeliveryModel.id == unsent_delivery.id,
                                NotificationDeliveryModel.state == "sending",
                            )
                            .with_for_update()
                        )
                        if unsent is not None:
                            unsent.state = "pending"
                            unsent.attempt = max(0, unsent.attempt - 1)
                            unsent.updated_at = self._clock().astimezone(UTC)
                raise asyncio.CancelledError
        return completed

    async def dispatch_all_once(self, *, limit_per_workspace: int = 50) -> DispatchResult:
        async with instance_rls_session(self._session_factory, mode="instance_admin") as db:
            workspace_ids = list(
                await db.scalars(
                    select(WorkspaceModel.id).where(
                        WorkspaceModel.status == "active",
                        WorkspaceModel.deleted_at.is_(None),
                    )
                )
            )
        events = inbox = 0
        for workspace_id in workspace_ids:
            result = await self.dispatch_workspace_once(workspace_id, limit=limit_per_workspace)
            await self.dispatch_pending_once(workspace_id)
            events += result.events_processed
            inbox += result.inbox_items_created
        return DispatchResult(events, inbox)

    async def run_forever(self) -> None:
        """Poll committed events; PostgreSQL row locks coordinate app replicas."""
        while True:
            try:
                await self.dispatch_all_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logging.getLogger(__name__).exception("notification_dispatch_iteration_failed")
            await asyncio.sleep(self._poll_interval_seconds)

    @staticmethod
    async def _recipients(
        db: AsyncSession,
        *,
        workspace_id: str,
        repository_id: str | None,
        security: bool,
    ) -> list[str]:
        query = (
            select(MembershipModel.user_id)
            .join(UserModel, UserModel.id == MembershipModel.user_id)
            .where(MembershipModel.workspace_id == workspace_id, UserModel.status == "active")
        )
        if security:
            query = query.where(MembershipModel.role == "admin")
        elif repository_id is not None:
            query = query.where(
                or_(
                    MembershipModel.role == "admin",
                    MembershipModel.id.in_(
                        select(RepoGrantModel.membership_id).where(
                            RepoGrantModel.workspace_id == workspace_id,
                            RepoGrantModel.repository_id == repository_id,
                        )
                    ),
                )
            )
        return list(await db.scalars(query))


def _event_link(workspace_id: str, event_type: str, payload: dict[str, Any]) -> str:
    if event_type.startswith("repair.") and payload.get("repair_id"):
        return f"/w/{workspace_id}/repairs/{payload['repair_id']}"
    if event_type.startswith("repair.approval."):
        return f"/w/{workspace_id}/approvals"
    return f"/w/{workspace_id}/notifications"
