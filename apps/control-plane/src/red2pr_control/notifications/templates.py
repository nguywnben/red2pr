"""Allowlisted, redacted notification copy derived from canonical S-19 events."""

from __future__ import annotations

import re
from dataclasses import dataclass

from py_contracts.events import EventEnvelope
from red2pr_control.core.redaction import DEFAULT_REDACTOR, Redactor

_TITLES: dict[str, tuple[str, str]] = {
    "provider.run.failed": ("CI run failed", "warning"),
    "repair.session.created": ("Repair investigation started", "info"),
    "repair.diagnosed": ("Repair diagnosis ready", "info"),
    "repair.reproduction.completed": ("Baseline reproduction completed", "warning"),
    "repair.patch.proposed": ("Patch proposed", "action"),
    "repair.verification.completed": ("Repair verification completed", "info"),
    "repair.approval.requested": ("Approval requested", "action"),
    "repair.approval.decided": ("Approval updated", "info"),
    "repair.publication.created": ("Draft pull request created", "success"),
    "repair.remote_ci.completed": ("Remote CI completed", "success"),
    "repair.blocked": ("Repair needs attention", "warning"),
    "repair.cancelled": ("Repair cancelled", "info"),
    "provider.connection.created": ("Provider connection created", "info"),
    "provider.run.retried": ("CI run retried", "info"),
    "worker.offline": ("Worker is offline", "error"),
    "worker.quarantined": ("Worker quarantined", "critical"),
    "integration.disconnected": ("Integration disconnected", "error"),
    "usage.budget.exceeded": ("Usage budget reached", "warning"),
    "security.policy.denied": ("Security policy blocked an action", "critical"),
    "backup.failed": ("Backup failed", "critical"),
    "release.update_available": ("Red2PR update available", "info"),
    "identity.permission_revoked": ("Access changed", "critical"),
    "notification.delivery.failed": ("Notification delivery failed", "warning"),
    "operations.restore.completed": ("Restore operation completed", "info"),
    "operations.alarm": ("Operational alarm", "warning"),
}
_SECRET_MARKER = re.compile(r"(?i)(?:token|secret|password|authorization|api[_-]?key)\s*[:=]\s*\S+")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069]")


@dataclass(frozen=True, slots=True)
class RenderedNotification:
    title: str
    body: str
    severity: str
    deep_link: str | None


def _safe_text(value: str, redactor: Redactor) -> str:
    scrubbed = redactor.redact_text(value)
    scrubbed = _SECRET_MARKER.sub("[REDACTED]", scrubbed)
    return _CONTROL_CHARS.sub("", scrubbed).strip()[:240]


def _safe_link(value: str | None) -> str | None:
    if value is None or not value.startswith("/w/") or value.startswith("//") or "\\" in value:
        return None
    if any(ord(char) < 32 for char in value):
        return None
    return value[:512]


def render_event_template(
    event: EventEnvelope,
    *,
    repository_name: str | None = None,
    deep_link: str | None = None,
    redactor: Redactor = DEFAULT_REDACTOR,
) -> RenderedNotification:
    """Render only canonical event fields; never include arbitrary source or log text."""
    title, severity = _TITLES[event.type]
    label = _safe_text(repository_name or "", redactor)
    payload = event.payload.model_dump(mode="json")
    detail: str | None = None
    if event.type in {"repair.blocked", "repair.diagnosed", "repair.cancelled"}:
        detail = payload.get("reason_code") or payload.get("state")
    elif event.type == "repair.verification.completed":
        detail = f"Verification outcome: {payload.get('outcome', 'unknown')}"
    elif event.type == "repair.remote_ci.completed":
        detail = f"Remote CI outcome: {payload.get('outcome', 'unknown')}"
    elif event.type == "provider.run.failed":
        detail = f"Failed run {payload.get('attempt_key', 'unknown')}"
    elif event.type == "notification.delivery.failed":
        detail = "A notification could not be delivered."
    elif event.type == "operations.alarm":
        code = payload.get("alarm_code", "unknown")
        state = payload.get("state", "unknown")
        detail = f"{code}: {state}"
        if code in {"storage_hard_limit", "audit_chain_mismatch", "backup_failed"}:
            severity = "critical"

    parts = [label] if label else []
    if detail:
        parts.append(_safe_text(str(detail), redactor))
    body = " · ".join(part for part in parts if part) or title
    return RenderedNotification(
        title=_safe_text(title, redactor),
        body=body,
        severity=severity,
        deep_link=_safe_link(deep_link),
    )
