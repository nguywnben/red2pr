import asyncio
import sys
from datetime import UTC, datetime, timedelta

from red2pr_control.core.alarms import AlarmEvaluator, AlarmObservation
from red2pr_control.secrets.rotation import RotationDrain

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def test_sustained_alarm_fires_with_bounded_labels_and_resolves() -> None:
    evaluator = AlarmEvaluator(queue_lag_seconds=60, sustained_for=timedelta(minutes=3))
    start = datetime(2026, 10, 30, tzinfo=UTC)
    observation = AlarmObservation(queue_lag_seconds=90)
    assert evaluator.evaluate(observation, now=start) == ()
    fired = evaluator.evaluate(observation, now=start + timedelta(minutes=3))
    assert [alarm.code for alarm in fired] == ["queue_lag"]
    assert fired[0].labels == {"signal": "queue_lag"}
    resolved = evaluator.evaluate(AlarmObservation(), now=start + timedelta(minutes=6))
    assert resolved[0].state == "resolved"


def test_default_alarm_window_is_strictly_below_five_minutes() -> None:
    evaluator = AlarmEvaluator()
    start = datetime(2026, 10, 30, tzinfo=UTC)
    observation = AlarmObservation(queue_lag_seconds=61)
    assert evaluator.evaluate(observation, now=start) == ()
    alarms = evaluator.evaluate(observation, now=start + timedelta(minutes=3))
    assert len(alarms) == 1
    assert alarms[0].code == "queue_lag"


def test_audit_mismatch_and_critical_watermark_alarm_immediately() -> None:
    evaluator = AlarmEvaluator(sustained_for=timedelta(minutes=5))
    alarms = evaluator.evaluate(
        AlarmObservation(storage_percent=90, audit_chain_mismatch=True),
        now=datetime(2026, 10, 30, tzinfo=UTC),
    )
    assert {alarm.code for alarm in alarms} == {"storage_hard_limit", "audit_chain_mismatch"}


def test_alarm_labels_do_not_include_untrusted_dimensions() -> None:
    evaluator = AlarmEvaluator(queue_lag_seconds=50, sustained_for=timedelta(0))
    alarms = evaluator.evaluate(
        AlarmObservation(
            queue_lag_seconds=100,
            repository_name="secret-repo",
            secret_ref="token-value",
        ),
        now=datetime(2026, 10, 30, tzinfo=UTC),
    )
    assert alarms[0].labels == {"signal": "queue_lag"}
    assert "secret-repo" not in repr(alarms)
    assert "token-value" not in repr(alarms)


def test_key_rotation_waits_for_active_broker_operations_and_blocks_new_ones() -> None:
    async def scenario() -> None:
        drain = RotationDrain()
        operation_started = asyncio.Event()
        release_operation = asyncio.Event()
        rotation_started = asyncio.Event()
        release_rotation = asyncio.Event()
        next_operation_started = asyncio.Event()

        async def operation() -> None:
            async with drain.operation():
                operation_started.set()
                await release_operation.wait()

        async def rotate() -> None:
            async with drain.rotation():
                rotation_started.set()
                await release_rotation.wait()

        async def next_operation() -> None:
            async with drain.operation():
                next_operation_started.set()

        first = asyncio.create_task(operation())
        await operation_started.wait()
        rotating = asyncio.create_task(rotate())
        await asyncio.sleep(0)
        assert not rotation_started.is_set()
        release_operation.set()
        await first
        assert rotation_started.is_set()
        following = asyncio.create_task(next_operation())
        await asyncio.sleep(0)
        assert not next_operation_started.is_set()
        release_rotation.set()
        await rotating
        await following
        assert next_operation_started.is_set()

    asyncio.run(scenario())
