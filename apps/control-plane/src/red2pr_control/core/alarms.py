"""Bounded, deterministic operational alarm evaluation (OPS-01 / NFR-13)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal


@dataclass(frozen=True)
class AlarmObservation:
    """One operational snapshot. Free-form dimensions are deliberately ignored."""

    queue_lag_seconds: float = 0
    backup_failed: bool = False
    worker_quarantined: bool = False
    storage_percent: float = 0
    audit_chain_mismatch: bool = False
    repository_name: str | None = field(default=None, repr=False)
    secret_ref: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class Alarm:
    code: str
    state: Literal["firing", "resolved"]
    first_seen_at: datetime
    observed_at: datetime
    labels: dict[str, str]


class AlarmEvaluator:
    """Evaluate incident signals without unbounded or user supplied metric labels."""

    def __init__(
        self,
        *,
        queue_lag_seconds: float = 60,
        sustained_for: timedelta = timedelta(minutes=3),
    ) -> None:
        if queue_lag_seconds < 0 or sustained_for < timedelta(0):
            raise ValueError("Alarm thresholds must be non-negative.")
        self.queue_lag_seconds = queue_lag_seconds
        self.sustained_for = sustained_for
        self._active: dict[str, datetime] = {}
        self._emitted: set[str] = set()

    def restore_firing(self, code: str, *, first_seen_at: datetime) -> None:
        """Restore durable firing state after process restart."""
        self._active[code] = first_seen_at.astimezone(UTC)
        self._emitted.add(code)

    def evaluate(self, observation: AlarmObservation, *, now: datetime) -> tuple[Alarm, ...]:
        observed_at = now.astimezone(UTC)
        signals = {
            "queue_lag": observation.queue_lag_seconds >= self.queue_lag_seconds,
            "backup_failed": observation.backup_failed,
            "worker_quarantined": observation.worker_quarantined,
            "storage_soft_limit": 80 <= observation.storage_percent < 90,
            "storage_hard_limit": observation.storage_percent >= 90,
            "audit_chain_mismatch": observation.audit_chain_mismatch,
        }
        alarms: list[Alarm] = []
        for code, active in signals.items():
            first_seen = self._active.get(code)
            if active and first_seen is None:
                first_seen = observed_at
                self._active[code] = first_seen
            if active:
                assert first_seen is not None
                immediate = code in {
                    "backup_failed",
                    "worker_quarantined",
                    "storage_hard_limit",
                    "audit_chain_mismatch",
                }
                if code not in self._emitted and (
                    immediate or observed_at - first_seen >= self.sustained_for
                ):
                    alarms.append(Alarm(code, "firing", first_seen, observed_at, {"signal": code}))
                    self._emitted.add(code)
            elif first_seen is not None:
                alarms.append(Alarm(code, "resolved", first_seen, observed_at, {"signal": code}))
                del self._active[code]
                self._emitted.discard(code)
        return tuple(alarms)
