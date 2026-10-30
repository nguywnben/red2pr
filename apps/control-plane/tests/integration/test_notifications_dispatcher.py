"""U21 notification outbox, scoped inbox and security-negative integration tests."""

from __future__ import annotations

import importlib.util
import sys
import time
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError

from py_contracts.events import EventEnvelope
from py_contracts.primitives import new_uuid7
from red2pr_control.db.base import (
    ConsentModel,
    DeliveryAttemptModel,
    MembershipModel,
    NotificationDeliveryModel,
    NotificationDestinationModel,
    NotificationEventModel,
    UserInboxItemModel,
    UserModel,
    UserNotificationPreferenceModel,
)
from red2pr_control.db.outbox import enqueue_outbox_event
from red2pr_control.db.rls import instance_rls_session, workspace_rls_session
from red2pr_control.iam.passwords import hash_password
from red2pr_control.notifications.dispatcher import (
    NotificationAdapterResult,
    NotificationDispatcher,
    NotificationSendRequest,
    classify_delivery_attempt,
    should_defer_external_delivery,
)
from red2pr_control.notifications.templates import render_event_template
from red2pr_control.operations.setup_wizard import SetupStepRegistry

_U17_PATH = Path(__file__).with_name("test_agents_and_state_machine.py")
_U17_SPEC = importlib.util.spec_from_file_location("red2pr_u21_test_support", _U17_PATH)
assert _U17_SPEC is not None and _U17_SPEC.loader is not None
_U17 = importlib.util.module_from_spec(_U17_SPEC)
sys.modules[_U17_SPEC.name] = _U17
_U17_SPEC.loader.exec_module(_U17)
ManualClock = _U17.ManualClock
_build_u17_harness = _U17._build_u17_harness
_bootstrap_workspace_and_repo = _U17._bootstrap_workspace_and_repo
_csrf_headers = _U17._csrf_headers


class _TestChannelAdapter:
    """Hermetic adapter double: captures only the dispatcher contract, never performs I/O."""

    def __init__(self, result: NotificationAdapterResult) -> None:
        self.result = result
        self.requests: list[NotificationSendRequest] = []

    async def deliver(self, request: NotificationSendRequest) -> NotificationAdapterResult:
        self.requests.append(request)
        return self.result

    async def send_test(self, request: NotificationSendRequest) -> NotificationAdapterResult:
        self.requests.append(request)
        return self.result


@pytest.fixture(scope="module")
def pg_urls() -> Iterator[object]:
    yield from _U17.pg_urls.__wrapped__()


@pytest.fixture
async def migrated_db(pg_urls: object) -> AsyncIterator[object]:
    async for result in _U17.migrated_db.__wrapped__(pg_urls):
        yield result


def test_template_uses_only_allowlisted_event_fields_and_redacts_secrets() -> None:
    event = EventEnvelope.model_validate(
        {
            "event_id": "019a4b4c-7d00-7000-8000-000000000001",
            "schema_version": 1,
            "type": "repair.blocked",
            "occurred_at": datetime(2026, 10, 30, tzinfo=UTC),
            "workspace_id": "019a4b4c-7d00-7000-8000-000000000002",
            "repository_id": "019a4b4c-7d00-7000-8000-000000000003",
            "aggregate_id": "019a4b4c-7d00-7000-8000-000000000004",
            "aggregate_version": 1,
            "correlation_id": "corr-u21",
            "payload": {
                "repair_id": "019a4b4c-7d00-7000-8000-000000000004",
                "state": "blocked",
                "reason_code": "TOKEN=top-secret",
            },
        }
    )

    rendered = render_event_template(event, repository_name="red2pr", deep_link="/w/ws/repairs/r")

    assert rendered.severity == "warning"
    assert rendered.title
    assert "top-secret" not in rendered.body
    assert rendered.deep_link == "/w/ws/repairs/r"
    assert "TOKEN" not in rendered.body


def test_delivery_retry_policy_preserves_unknown_outcomes_and_bounds_retries() -> None:
    now = datetime(2026, 10, 30, tzinfo=UTC)
    unknown = classify_delivery_attempt(
        attempt=1,
        first_attempt_at=now,
        now=now,
        timed_out_after_send=True,
    )
    assert unknown.state == "unknown"
    assert unknown.possible_duplicate is True
    assert unknown.next_retry_at is None

    transient = classify_delivery_attempt(
        attempt=1,
        first_attempt_at=now,
        now=now,
        http_status=503,
        retry_after_seconds=90,
        random_value=0.5,
    )
    assert transient.state == "retry_wait"
    assert transient.next_retry_at == now + timedelta(seconds=90)

    exhausted = classify_delivery_attempt(
        attempt=8,
        first_attempt_at=now,
        now=now,
        http_status=503,
    )
    assert exhausted.state == "failed_final"
    age_exhausted = classify_delivery_attempt(
        attempt=2,
        first_attempt_at=now - timedelta(hours=24),
        now=now,
        http_status=503,
    )
    assert age_exhausted.state == "failed_final"


def test_quiet_hours_use_configured_timezone_and_wrap_midnight() -> None:
    from red2pr_control.db.base import UserNotificationPreferenceModel

    prefs = UserNotificationPreferenceModel(
        id=new_uuid7(),
        workspace_id=None,
        user_id=new_uuid7(),
        event_types_json=[],
        min_severity="info",
        quiet_hours_json={"start_hhmm": "22:00", "end_hhmm": "06:00"},
        timezone="UTC",
    )
    assert should_defer_external_delivery(
        event_type="worker.quarantined",
        severity="critical",
        preference=prefs,
        now=datetime(2026, 10, 30, 23, 0, tzinfo=UTC),
    )
    assert not should_defer_external_delivery(
        event_type="worker.quarantined",
        severity="critical",
        preference=prefs,
        now=datetime(2026, 10, 30, 12, 0, tzinfo=UTC),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "adapter_result",
        "expected_state",
        "expected_duplicate",
        "revoke_before_send",
        "quiet_hours",
        "stale_sending",
    ),
    [
        (
            NotificationAdapterResult(http_status=202, provider_id="local-sink-1"),
            "accepted",
            False,
            False,
            False,
            False,
        ),
        (
            NotificationAdapterResult(http_status=503, retry_after_seconds=90),
            "retry_wait",
            False,
            False,
            False,
            False,
        ),
        (
            NotificationAdapterResult(timed_out_after_send=True),
            "unknown",
            True,
            False,
            False,
            False,
        ),
        (NotificationAdapterResult(http_status=202), "suppressed", False, True, False, False),
        (NotificationAdapterResult(http_status=202), "retry_wait", False, False, True, False),
        (NotificationAdapterResult(http_status=202), "unknown", True, False, False, True),
    ],
)
async def test_u21_external_dispatch_persists_attempt_outcomes_and_never_retries_ambiguous_send(
    migrated_db: object,
    tmp_path: Path,
    adapter_result: NotificationAdapterResult,
    expected_state: str,
    expected_duplicate: bool,
    revoke_before_send: bool,
    quiet_hours: bool,
    stale_sending: bool,
) -> None:
    clock = ManualClock()
    harness = _build_u17_harness(
        migrated_db.app_url,
        clock=clock,
        store_dir=tmp_path / f"artifacts-{expected_state}",
    )
    client, _csrf, owner_id, workspace_id, repo_id = await _bootstrap_workspace_and_repo(
        harness,
        clock=clock,
        ws_slug=f"u21-delivery-{expected_state.replace('_', '-')}",
    )
    try:
        address = f"https://sink.example.invalid/{expected_state}"
        consent_id = new_uuid7(now=clock())
        destination_id = new_uuid7(now=clock())
        event_id = new_uuid7(now=clock())
        event = EventEnvelope.model_validate(
            {
                "event_id": event_id,
                "schema_version": 1,
                "type": "repair.blocked",
                "occurred_at": clock(),
                "workspace_id": workspace_id,
                "repository_id": repo_id,
                "aggregate_id": new_uuid7(now=clock()),
                "aggregate_version": 1,
                "correlation_id": f"corr-u21-{expected_state}",
                "payload": {"repair_id": new_uuid7(now=clock()), "state": "blocked"},
            }
        )
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            db.add(
                ConsentModel(
                    id=consent_id,
                    purpose="notification",
                    scope="workspace",
                    workspace_id=workspace_id,
                    repository_id=None,
                    destination=address,
                    data_classes_json=["workspace_internal"],
                    granted_by_user_id=owner_id,
                    granted_at=clock(),
                    revoked_by_user_id=None,
                    revoked_at=None,
                    revoke_reason=None,
                    policy_version=1,
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
            db.add(
                NotificationDestinationModel(
                    id=destination_id,
                    workspace_id=workspace_id,
                    user_id=owner_id if revoke_before_send else None,
                    channel="webhook",
                    scope="user" if revoke_before_send else "workspace",
                    address=address,
                    secret_ref=None,
                    consent_id=consent_id,
                    status="ready",
                    verified_at=clock(),
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
            if quiet_hours:
                db.add(
                    UserNotificationPreferenceModel(
                        id=new_uuid7(now=clock()),
                        workspace_id=workspace_id,
                        user_id=owner_id,
                        event_types_json=[],
                        min_severity="info",
                        quiet_hours_json={"start_hhmm": "14:00", "end_hhmm": "16:00"},
                        timezone="UTC",
                        version=1,
                        created_at=clock(),
                        updated_at=clock(),
                    )
                )
            await enqueue_outbox_event(db, event, now=clock())

        adapter = _TestChannelAdapter(adapter_result)
        dispatcher = NotificationDispatcher(
            session_factory=harness.app_factory,
            redactor=harness.redactor,
            clock=clock,
            adapters={"webhook": adapter},
        )
        first_attempt_started = time.monotonic()
        await dispatcher.dispatch_workspace_once(workspace_id)
        if stale_sending:
            async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
                pending = await db.scalar(
                    select(NotificationDeliveryModel).where(
                        NotificationDeliveryModel.event_id == event_id,
                        NotificationDeliveryModel.destination_id == destination_id,
                    )
                )
                assert pending is not None
                pending.state = "sending"
                pending.attempt = 1
                pending.updated_at = clock() - timedelta(seconds=30)
        if revoke_before_send:
            replacement_admin_id = new_uuid7(now=clock())
            async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
                db.add(
                    UserModel(
                        id=replacement_admin_id,
                        username="u21-delivery-replacement-admin",
                        email="u21-delivery-replacement-admin@example.invalid",
                        display_name="U21 Delivery Replacement Admin",
                        password_hash=hash_password("{{SECRET_deliverytest}}"),
                        is_instance_owner=False,
                        status="active",
                        created_at=clock(),
                        updated_at=clock(),
                    )
                )
                await db.flush()
                db.add(
                    MembershipModel(
                        id=new_uuid7(now=clock()),
                        workspace_id=workspace_id,
                        user_id=replacement_admin_id,
                        role="admin",
                        created_at=clock(),
                        updated_at=clock(),
                    )
                )
            async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
                membership = await db.scalar(
                    select(MembershipModel).where(
                        MembershipModel.workspace_id == workspace_id,
                        MembershipModel.user_id == owner_id,
                    )
                )
                assert membership is not None
                await db.delete(membership)
        revoked_at = time.monotonic() if revoke_before_send else None
        delivered = await dispatcher.dispatch_pending_once(workspace_id)
        if revoked_at is not None:
            assert time.monotonic() - revoked_at < 5
        if not revoke_before_send and not quiet_hours and not stale_sending:
            assert time.monotonic() - first_attempt_started < 30
        expected_delivered = 0 if revoke_before_send or quiet_hours or stale_sending else 1
        assert delivered == expected_delivered
        assert len(adapter.requests) == expected_delivered
        if adapter.requests:
            assert adapter.requests[0].event_id == event_id
            assert "secret" not in adapter.requests[0].body.lower()
            assert adapter.requests[0].request_digest

        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            row = await db.scalar(
                select(NotificationDeliveryModel).where(
                    NotificationDeliveryModel.event_id == event_id,
                    NotificationDeliveryModel.destination_id == destination_id,
                )
            )
            attempts = list(
                await db.scalars(
                    select(DeliveryAttemptModel).where(DeliveryAttemptModel.delivery_id == row.id)
                )
            )
        assert row is not None
        assert row.state == expected_state
        assert row.possible_duplicate is expected_duplicate
        assert len(attempts) == (1 if stale_sending else expected_delivered)
        if attempts:
            assert attempts[0].outcome == expected_state
        if expected_state == "unknown":
            assert await dispatcher.dispatch_pending_once(workspace_id) == 0
            assert len(adapter.requests) == expected_delivered
    finally:
        await client.aclose()
        await harness.app_engine.dispose()


@pytest.mark.asyncio
async def test_u21_outbox_projection_is_idempotent_scoped_and_security_inbox_is_immutable(
    migrated_db: object,
    tmp_path: Path,
) -> None:
    clock = ManualClock()
    harness = _build_u17_harness(
        migrated_db.app_url,
        clock=clock,
        store_dir=tmp_path / "artifacts",
    )
    client, csrf, owner_id, workspace_id, repo_id = await _bootstrap_workspace_and_repo(
        harness,
        clock=clock,
        ws_slug="u21-notifications",
    )
    try:
        event_id = new_uuid7(now=clock())
        repair_id = new_uuid7(now=clock())
        event = EventEnvelope.model_validate(
            {
                "event_id": event_id,
                "schema_version": 1,
                "type": "repair.blocked",
                "occurred_at": clock(),
                "workspace_id": workspace_id,
                "repository_id": repo_id,
                "aggregate_id": repair_id,
                "aggregate_version": 1,
                "correlation_id": "corr-u21-inbox",
                "payload": {
                    "repair_id": repair_id,
                    "state": "blocked",
                    "reason_code": "TOKEN=top-secret-u21",
                },
            }
        )
        security_event_id = new_uuid7(now=clock())
        security_event = EventEnvelope.model_validate(
            {
                "event_id": security_event_id,
                "schema_version": 1,
                "type": "security.policy.denied",
                "occurred_at": clock(),
                "workspace_id": workspace_id,
                "aggregate_id": new_uuid7(now=clock()),
                "aggregate_version": 1,
                "correlation_id": "corr-u21-security",
                "payload": {"target_id": new_uuid7(now=clock()), "reason_code": "policy_denied"},
            }
        )
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            await enqueue_outbox_event(db, event, now=clock())
            await enqueue_outbox_event(db, security_event, now=clock())

        dispatcher = NotificationDispatcher(
            session_factory=harness.app_factory,
            redactor=harness.redactor,
            clock=clock,
        )
        setup_registry = SetupStepRegistry()
        dispatcher.register_setup_probe(setup_registry)
        notification_probe = setup_registry.get_probe("notifications")
        assert notification_probe is not None
        assert (await notification_probe("notifications", {})).probe_status == "passed"
        first = await dispatcher.dispatch_workspace_once(workspace_id)
        second = await dispatcher.dispatch_workspace_once(workspace_id)
        assert (first.events_processed, first.inbox_items_created) == (2, 2)
        assert (second.events_processed, second.inbox_items_created) == (0, 0)

        response = await client.get("/api/v1/workspaces/u21-notifications/notifications")
        assert response.status_code == 200, response.text
        items = response.json()["items"]
        assert len(items) == 2
        assert all("TOKEN=top-secret-u21" not in item["body"] for item in items)
        security_item = next(item for item in items if item["is_security"])

        mark_read = await client.patch(
            f"/api/v1/workspaces/u21-notifications/notifications/{security_item['id']}",
            headers=_csrf_headers(csrf),
            json={"read": True},
        )
        assert mark_read.status_code == 200, mark_read.text
        assert mark_read.json()["read_at"] is not None
        read_replay = await client.patch(
            f"/api/v1/workspaces/u21-notifications/notifications/{security_item['id']}",
            headers=_csrf_headers(csrf),
            json={"read": True},
        )
        assert read_replay.status_code == 200
        assert read_replay.json()["read_at"] == mark_read.json()["read_at"]

        unread = await client.get("/api/v1/workspaces/u21-notifications/notifications?unread=true")
        assert unread.status_code == 200
        assert len(unread.json()["items"]) == 1

        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            security_row = await db.scalar(
                select(UserInboxItemModel).where(
                    UserInboxItemModel.workspace_id == workspace_id,
                    UserInboxItemModel.event_id == security_event_id,
                    UserInboxItemModel.user_id == owner_id,
                )
            )
            assert security_row is not None and security_row.is_security
            with pytest.raises(DBAPIError):
                await db.delete(security_row)
                await db.flush()
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            projection = await db.scalar(
                select(NotificationEventModel).where(NotificationEventModel.id == event_id)
            )
            assert projection is not None
            assert "TOKEN=top-secret-u21" not in str(projection.payload_json)

        destination_key = new_uuid7(now=clock())
        consent_id = new_uuid7(now=clock())
        destination_body = {
            "channel": "webhook",
            "scope": "workspace",
            "address": "https://hooks.example.invalid/red2pr",
            "consent_id": consent_id,
            "secret_ref": None,
        }
        destination_url = "/api/v1/workspaces/u21-notifications/notification-destinations"
        no_consent = await client.post(
            destination_url,
            headers={**_csrf_headers(csrf), "Idempotency-Key": new_uuid7(now=clock())},
            json={**destination_body, "consent_id": None},
        )
        assert no_consent.status_code == 409
        assert no_consent.json()["code"] == "notification_consent_required"
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            db.add(
                ConsentModel(
                    id=consent_id,
                    purpose="notification",
                    scope="workspace",
                    workspace_id=workspace_id,
                    repository_id=None,
                    destination=destination_body["address"],
                    data_classes_json=["workspace_internal"],
                    granted_by_user_id=owner_id,
                    granted_at=clock(),
                    revoked_by_user_id=None,
                    revoked_at=None,
                    revoke_reason=None,
                    policy_version=1,
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
        missing_key = await client.post(
            destination_url,
            headers=_csrf_headers(csrf),
            json=destination_body,
        )
        assert missing_key.status_code == 422
        destination = await client.post(
            destination_url,
            headers={**_csrf_headers(csrf), "Idempotency-Key": destination_key},
            json=destination_body,
        )
        assert destination.status_code == 201, destination.text
        assert "address" not in destination.json()
        assert "secret_ref" not in destination.json()
        assert destination.json()["secret_presence"]["configured"] is False
        replay = await client.post(
            destination_url,
            headers={**_csrf_headers(csrf), "Idempotency-Key": destination_key},
            json=destination_body,
        )
        assert replay.status_code == 201, replay.text
        assert replay.json()["id"] == destination.json()["id"]
        mismatch = await client.post(
            destination_url,
            headers={**_csrf_headers(csrf), "Idempotency-Key": destination_key},
            json={**destination_body, "scope": "user"},
        )
        assert mismatch.status_code == 409
        assert mismatch.json()["code"] == "idempotency_payload_mismatch"
        replacement_address = "https://hooks.example.invalid/replacement"
        replacement_consent_id = new_uuid7(now=clock())
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            db.add(
                ConsentModel(
                    id=replacement_consent_id,
                    purpose="notification",
                    scope="workspace",
                    workspace_id=workspace_id,
                    repository_id=None,
                    destination=replacement_address,
                    data_classes_json=["workspace_internal"],
                    granted_by_user_id=owner_id,
                    granted_at=clock(),
                    revoked_by_user_id=None,
                    revoked_at=None,
                    revoke_reason=None,
                    policy_version=1,
                    version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
        updated_destination = await client.patch(
            f"{destination_url}/{destination.json()['id']}",
            headers={**_csrf_headers(csrf), "If-Match": '"v1"'},
            json={"address": replacement_address, "consent_id": replacement_consent_id},
        )
        assert updated_destination.status_code == 200, updated_destination.text
        assert updated_destination.json()["version"] == 2
        assert updated_destination.json()["status"] == "not_configured"
        assert "address" not in updated_destination.json()
        update_replay = await client.patch(
            f"{destination_url}/{destination.json()['id']}",
            headers={**_csrf_headers(csrf), "If-Match": '"v2"'},
            json={"address": replacement_address, "consent_id": replacement_consent_id},
        )
        assert update_replay.status_code == 200
        assert update_replay.json()["version"] == 2
        stale_update = await client.patch(
            f"{destination_url}/{destination.json()['id']}",
            headers={**_csrf_headers(csrf), "If-Match": '"v1"'},
            json={"status": "disabled"},
        )
        assert stale_update.status_code == 409
        assert stale_update.json()["code"] == "version_conflict"
        test_url = f"{destination_url}/{destination.json()['id']}/tests"
        unconfirmed = await client.post(
            test_url,
            headers=_csrf_headers(csrf),
            json={"confirmed": False},
        )
        assert unconfirmed.status_code == 403
        no_adapter = await client.post(
            test_url,
            headers=_csrf_headers(csrf),
            json={"confirmed": True},
        )
        assert no_adapter.status_code == 503
        assert no_adapter.json()["code"] == "notification_adapter_unavailable"
        test_adapter = _TestChannelAdapter(NotificationAdapterResult(http_status=202))
        app_dispatcher = harness.api_app.state.notification_dispatcher
        app_dispatcher._adapters["webhook"] = test_adapter
        verified_test = await client.post(
            test_url,
            headers=_csrf_headers(csrf),
            json={"confirmed": True},
        )
        assert verified_test.status_code == 202, verified_test.text
        assert verified_test.json() == {"state": "accepted"}
        assert len(test_adapter.requests) == 1
        assert test_adapter.requests[0].is_test is True
        assert test_adapter.requests[0].event_id is None
        assert (
            test_adapter.requests[0].body
            == "This is a test notification. No project data is included."
        )
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            verified_destination = await db.scalar(
                select(NotificationDestinationModel).where(
                    NotificationDestinationModel.id == destination.json()["id"]
                )
            )
            assert verified_destination is not None
            assert verified_destination.status == "ready"
            assert verified_destination.verified_at is not None
        removed = await client.delete(
            f"{destination_url}/{destination.json()['id']}",
            headers=_csrf_headers(csrf),
        )
        assert removed.status_code == 204
        remove_replay = await client.delete(
            f"{destination_url}/{destination.json()['id']}",
            headers=_csrf_headers(csrf),
        )
        assert remove_replay.status_code == 204

        preferences_url = "/api/v1/me/notification-preferences"
        preferences = await client.get(preferences_url, params={"workspace_id": workspace_id})
        assert preferences.status_code == 200
        assert preferences.json()["timezone"] == "UTC"
        saved_preferences = await client.patch(
            preferences_url,
            headers=_csrf_headers(csrf),
            json={
                "workspace_id": workspace_id,
                "timezone": "Asia/Ho_Chi_Minh",
                "min_severity": "warning",
                "quiet_hours": {"start_hhmm": "22:00", "end_hhmm": "06:00"},
            },
        )
        assert saved_preferences.status_code == 200, saved_preferences.text
        assert saved_preferences.json()["quiet_hours"]["start_hhmm"] == "22:00"
        preferences_replay = await client.patch(
            preferences_url,
            headers=_csrf_headers(csrf),
            json={
                "workspace_id": workspace_id,
                "timezone": "Asia/Ho_Chi_Minh",
                "min_severity": "warning",
                "quiet_hours": {"start_hhmm": "22:00", "end_hhmm": "06:00"},
            },
        )
        assert preferences_replay.status_code == 200
        assert preferences_replay.json()["version"] == saved_preferences.json()["version"]
        invalid_timezone = await client.patch(
            preferences_url,
            headers=_csrf_headers(csrf),
            json={"workspace_id": workspace_id, "timezone": "Mars/Olympus"},
        )
        assert invalid_timezone.status_code == 422
        assert invalid_timezone.json()["code"] == "invalid_timezone"

        revoked_event_id = new_uuid7(now=clock())
        revoked_repair_id = new_uuid7(now=clock())
        revoked_event = EventEnvelope.model_validate(
            {
                "event_id": revoked_event_id,
                "schema_version": 1,
                "type": "repair.blocked",
                "occurred_at": clock(),
                "workspace_id": workspace_id,
                "repository_id": repo_id,
                "aggregate_id": revoked_repair_id,
                "aggregate_version": 1,
                "correlation_id": "corr-u21-revoked-member",
                "payload": {
                    "repair_id": revoked_repair_id,
                    "state": "blocked",
                    "reason_code": "policy_denied",
                },
            }
        )
        remaining_admin_id = new_uuid7(now=clock())
        async with instance_rls_session(harness.app_factory, mode="instance_admin") as db:
            db.add(
                UserModel(
                    id=remaining_admin_id,
                    username="u21-remaining-admin",
                    email="u21-remaining-admin@example.invalid",
                    display_name="U21 Remaining Admin",
                    password_hash=hash_password("test-only-u21-credential"),
                    status="active",
                    is_instance_owner=False,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
            await db.flush()
            db.add(
                MembershipModel(
                    id=new_uuid7(now=clock()),
                    workspace_id=workspace_id,
                    user_id=remaining_admin_id,
                    role="admin",
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            membership = await db.scalar(
                select(MembershipModel).where(
                    MembershipModel.workspace_id == workspace_id,
                    MembershipModel.user_id == owner_id,
                )
            )
            assert membership is not None
            await db.delete(membership)
            await enqueue_outbox_event(db, revoked_event, now=clock())
        suppressed = await dispatcher.dispatch_workspace_once(workspace_id)
        assert (suppressed.events_processed, suppressed.inbox_items_created) == (1, 1)
        async with workspace_rls_session(harness.app_factory, workspace_id=workspace_id) as db:
            revoked_recipient = await db.scalar(
                select(UserInboxItemModel.id).where(
                    UserInboxItemModel.workspace_id == workspace_id,
                    UserInboxItemModel.event_id == revoked_event_id,
                    UserInboxItemModel.user_id == owner_id,
                )
            )
            remaining_admin_item = await db.scalar(
                select(UserInboxItemModel.id).where(
                    UserInboxItemModel.workspace_id == workspace_id,
                    UserInboxItemModel.event_id == revoked_event_id,
                    UserInboxItemModel.user_id == remaining_admin_id,
                )
            )
        assert revoked_recipient is None
        assert remaining_admin_item is not None
        denied = await client.get("/api/v1/workspaces/u21-notifications/notifications")
        assert denied.status_code in {403, 404}
    finally:
        await client.aclose()
        await harness.app_engine.dispose()


def test_u21_migration_downgrade_and_upgrade_is_reversible(migrated_db: object) -> None:
    _U17.run_alembic_downgrade(
        migrated_db.admin_url,
        "0016_publications_and_remote_checks",
        app_role_name=_U17.APP_ROLE_NAME,
    )
    _U17.run_alembic_upgrade(
        migrated_db.admin_url,
        "head",
        app_role_name=_U17.APP_ROLE_NAME,
        app_role_password=_U17.APP_ROLE_PASSWORD,
    )
