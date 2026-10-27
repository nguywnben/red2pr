"""Redis + Dramatiq wakeup transport for Red2PR durable PostgreSQL task queue (ADR-035).

Enforces non-negotiable invariants (`JOB-01`, `NFR-01`, `ADR-035`, `AGENTS.md` #5, #6, #8):
- PostgreSQL `task_jobs` is the single source of truth; Redis + Dramatiq carries ONLY
  opaque `(workspace_id, job_id)` wakeup hints — never secrets, source code, or
  authoritative execution state.
- `RedisBroker` runs with `middleware=[]` so Dramatiq NEVER performs hidden blind
  retries inside Redis; all retry/backoff/DLQ transitions are governed by PostgreSQL.
- If Redis is temporarily unreachable or wiped (`FLUSHALL` / empty restart), zero
  acknowledged PostgreSQL jobs are lost; transport health degrades truthfully and
  `QueueLeaseSweeper.rebuild_transport_from_db` deterministically re-enqueues wakeup
  hints for all eligible ready jobs.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, cast

import dramatiq
import redis
from dramatiq.brokers.redis import RedisBroker

from py_contracts.worker import QueueTransportStatus
from red2pr_control.core.logging import get_structured_logger
from red2pr_control.core.redaction import Redactor

WAKEUP_QUEUE_NAME = "red2pr_wakeup"
WAKEUP_PENDING_SET_KEY = "red2pr:wakeup:pending"
_LOGGER = get_structured_logger("red2pr_control.orchestrator.transport")


@dataclass(frozen=True)
class QueueWakeupHint:
    """Opaque non-sensitive transport hint signalling ready work in PostgreSQL."""

    workspace_id: str
    job_id: str
    enqueued_at_iso: str


class QueueWakeupTransport(Protocol):
    """Transport abstraction allowing degraded or unconfigured fallback without DB loss."""

    def publish_wakeup(
        self,
        *,
        workspace_id: str,
        job_id: str,
        now: datetime,
        force: bool = False,
    ) -> bool: ...

    def probe_health(self) -> tuple[QueueTransportStatus, str | None]: ...

    def close(self) -> None: ...


class NullQueueTransport:
    """Fallback transport when no Redis URL is configured (`unconfigured`)."""

    def publish_wakeup(
        self,
        *,
        workspace_id: str,
        job_id: str,
        now: datetime,
        force: bool = False,
    ) -> bool:
        del workspace_id, job_id, now, force
        return False

    def probe_health(self) -> tuple[QueueTransportStatus, str | None]:
        return (
            "unconfigured",
            "Redis wakeup transport is not configured; workers rely on PostgreSQL polling.",
        )

    def close(self) -> None:
        return None


class Red2PrQueueTransport:
    """Production Dramatiq `RedisBroker` wakeup transport backed by Redis 7."""

    def __init__(
        self,
        *,
        redis_url: str,
        namespace: str = "red2pr",
        redactor: Redactor | None = None,
        on_wakeup: Callable[[QueueWakeupHint], None] | None = None,
        socket_timeout_seconds: float = 1.5,
    ) -> None:
        self._redis_url = redis_url
        self._namespace = namespace
        self._redactor = redactor or Redactor()
        self._on_wakeup = on_wakeup
        self._lock = threading.Lock()
        self._closed = False
        self._last_error: str | None = None

        self._redis_client: redis.Redis = redis.Redis.from_url(
            redis_url,
            socket_timeout=socket_timeout_seconds,
            socket_connect_timeout=socket_timeout_seconds,
            health_check_interval=15,
        )
        # middleware=[] guarantees zero hidden transport-level retries (AGENTS.md #5).
        broker_cls: Any = RedisBroker
        self._broker: RedisBroker = broker_cls(
            client=self._redis_client,
            namespace=f"{namespace}:dramatiq",
            middleware=[],
        )
        self._pending_set_key = f"{namespace}:{WAKEUP_PENDING_SET_KEY}"

        transport_ref = self

        def _handle_wakeup(workspace_id: str, job_id: str, enqueued_at_iso: str) -> None:
            with suppress(redis.RedisError, OSError):
                transport_ref._redis_client.srem(transport_ref._pending_set_key, job_id)
            if transport_ref._on_wakeup is not None:
                transport_ref._on_wakeup(
                    QueueWakeupHint(
                        workspace_id=workspace_id,
                        job_id=job_id,
                        enqueued_at_iso=enqueued_at_iso,
                    )
                )

        decorator = dramatiq.actor(
            broker=self._broker,
            actor_name=f"{namespace}_dispatch_wakeup",
            queue_name=WAKEUP_QUEUE_NAME,
        )
        self._wakeup_actor = decorator(_handle_wakeup)
        self._worker: dramatiq.Worker | None = None

    @property
    def broker(self) -> RedisBroker:
        return self._broker

    @property
    def redis_client(self) -> redis.Redis:
        return self._redis_client

    def publish_wakeup(
        self,
        *,
        workspace_id: str,
        job_id: str,
        now: datetime,
        force: bool = False,
    ) -> bool:
        """Enqueue a Dramatiq wakeup message without failing already-committed DB jobs."""
        if self._closed:
            return False

        enqueued_iso = now.astimezone(UTC).isoformat().replace("+00:00", "Z")
        try:
            if not force:
                raw_added = cast(Any, self._redis_client.sadd(self._pending_set_key, job_id))
                added = int(raw_added)
                self._redis_client.expire(self._pending_set_key, 3600)
                if added == 0:
                    self._last_error = None
                    return True
            else:
                self._redis_client.sadd(self._pending_set_key, job_id)
                self._redis_client.expire(self._pending_set_key, 3600)

            self._wakeup_actor.send(workspace_id, job_id, enqueued_iso)
            self._last_error = None
            return True
        except (redis.RedisError, OSError) as exc:
            safe_detail = self._redactor.redact_text(str(exc))[:240]
            self._last_error = safe_detail or "Redis wakeup publish failed."
            _LOGGER.warning(
                "Redis wakeup publish degraded; PostgreSQL job remains durable",
                extra={
                    "event": "queue.transport.degraded",
                    "workspace_id": workspace_id,
                    "job_id": job_id,
                    "error_code": "redis_transport_unavailable",
                },
            )
            return False

    def probe_health(self) -> tuple[QueueTransportStatus, str | None]:
        """Execute a live Redis PING probe and report truthful transport status."""
        if self._closed:
            return ("degraded", "Queue wakeup transport is closed.")
        try:
            pong = bool(self._redis_client.ping())
            if pong:
                self._last_error = None
                return ("healthy", None)
            return ("degraded", "Redis PING returned unexpected response.")
        except (redis.RedisError, OSError) as exc:
            safe_detail = self._redactor.redact_text(str(exc))[:240]
            self._last_error = safe_detail or "Redis transport unreachable."
            return ("degraded", self._last_error)

    def consume_wakeup_batch(
        self,
        *,
        max_messages: int = 64,
        timeout_ms: int = 100,
    ) -> list[QueueWakeupHint]:
        """Consume and ack a bounded batch of Dramatiq wakeup messages from Redis."""
        if self._closed or max_messages <= 0:
            return []

        hints: list[QueueWakeupHint] = []
        seen_jobs: set[str] = set()
        consumer = self._broker.consume(
            WAKEUP_QUEUE_NAME,
            prefetch=min(max_messages, 64),
            timeout=timeout_ms,
        )
        try:
            while len(hints) < max_messages:
                proxy = next(consumer, None)
                if proxy is None:
                    break
                try:
                    raw_args = getattr(proxy, "args", ())
                    if (
                        isinstance(raw_args, tuple | list)
                        and len(raw_args) >= 3
                        and isinstance(raw_args[0], str)
                        and isinstance(raw_args[1], str)
                        and isinstance(raw_args[2], str)
                    ):
                        ws_id, job_id, ts_iso = raw_args[0], raw_args[1], raw_args[2]
                        with suppress(redis.RedisError, OSError):
                            self._redis_client.srem(self._pending_set_key, job_id)
                        hint = QueueWakeupHint(
                            workspace_id=ws_id,
                            job_id=job_id,
                            enqueued_at_iso=ts_iso,
                        )
                        if self._on_wakeup is not None:
                            self._on_wakeup(hint)
                        if job_id not in seen_jobs:
                            seen_jobs.add(job_id)
                            hints.append(hint)
                finally:
                    consumer.ack(proxy)
        finally:
            with suppress(Exception):
                consumer.close()
        return hints

    def start_worker(self, *, worker_threads: int = 1) -> None:
        """Start background `dramatiq.Worker` consuming wakeup hints."""
        with self._lock:
            if self._closed or self._worker is not None:
                return
            worker = dramatiq.Worker(
                self._broker,
                queues={WAKEUP_QUEUE_NAME},
                worker_threads=max(1, worker_threads),
                worker_timeout=200,
            )
            worker.start()
            self._worker = worker

    def stop_worker(self, *, timeout_ms: int = 2000) -> None:
        """Stop background `dramatiq.Worker` cleanly if running."""
        with self._lock:
            worker = self._worker
            self._worker = None
        if worker is not None:
            worker.stop(timeout=timeout_ms)
            worker.join()

    def close(self) -> None:
        """Tear down Dramatiq worker, RedisBroker, and pooled TCP sockets cleanly."""
        self.stop_worker()
        with self._lock:
            if self._closed:
                return
            self._closed = True
        with suppress(Exception):
            self._broker.close()
        with suppress(Exception):
            self._redis_client.connection_pool.disconnect()
        with suppress(Exception):
            self._redis_client.close()
