"""Structured JSON logging and OpenTelemetry ingress redaction (NFR-13, SEC-017).

Propagates correlation_id, entry_point, workspace_id, repository_id, and session_id
across async/sync execution boundaries and scrubs every log line and OpenTelemetry
span attribute/event through Redactor v1 before emission.
"""

from __future__ import annotations

import contextvars
import json
import logging
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, Literal

from opentelemetry.context import Context
from opentelemetry.sdk.trace import Event, ReadableSpan, Span, SpanProcessor

from py_contracts.primitives import new_uuid7
from red2pr_control.core.redaction import DEFAULT_REDACTOR, REDACTION_VERSION, Redactor

EntryPoint = Literal["api", "webhook", "scheduler", "worker_rpc", "cli"]

_correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "red2pr_correlation_id", default=""
)
_entry_point_var: contextvars.ContextVar[EntryPoint] = contextvars.ContextVar(
    "red2pr_entry_point", default="api"
)
_workspace_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "red2pr_workspace_id", default=None
)
_repository_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "red2pr_repository_id", default=None
)
_session_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "red2pr_session_id", default=None
)


def current_correlation_id() -> str:
    """Return active correlation_id or generate an ephemeral UUIDv7 if unbound."""
    corr = _correlation_id_var.get()
    return corr if corr else new_uuid7()


@contextmanager
def bind_telemetry_context(
    *,
    correlation_id: str,
    entry_point: EntryPoint,
    workspace_id: str | None = None,
    repository_id: str | None = None,
    session_id: str | None = None,
) -> Iterator[None]:
    """Bind correlation and attribution context across an execution scope."""
    t_corr = _correlation_id_var.set(correlation_id)
    t_ep = _entry_point_var.set(entry_point)
    t_ws = _workspace_id_var.set(workspace_id)
    t_repo = _repository_id_var.set(repository_id)
    t_sess = _session_id_var.set(session_id)
    try:
        yield
    finally:
        _correlation_id_var.reset(t_corr)
        _entry_point_var.reset(t_ep)
        _workspace_id_var.reset(t_ws)
        _repository_id_var.reset(t_repo)
        _session_id_var.reset(t_sess)


class StructuredJsonFormatter(logging.Formatter):
    """Formats Python LogRecords as single-line JSON scrubbed by Redactor v1."""

    def __init__(self, *, redactor: Redactor | None = None) -> None:
        super().__init__()
        self._redactor = redactor if redactor is not None else DEFAULT_REDACTOR

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=UTC).isoformat().replace("+00:00", "Z")
        event_name = getattr(record, "event", record.name)
        error_code = getattr(record, "error_code", None)
        raw_attributes = getattr(record, "attributes", None)

        payload: dict[str, Any] = {
            "timestamp": ts,
            "severity": record.levelname,
            "component": record.name,
            "event": self._redactor.redact_text(str(event_name)),
            "message": self._redactor.redact_text(record.getMessage()),
            "entry_point": _entry_point_var.get(),
            "correlation_id": current_correlation_id(),
            "redaction_version": REDACTION_VERSION,
        }

        ws_id = _workspace_id_var.get()
        if ws_id is not None:
            payload["workspace_id"] = ws_id
        repo_id = _repository_id_var.get()
        if repo_id is not None:
            payload["repository_id"] = repo_id
        sess_id = _session_id_var.get()
        if sess_id is not None:
            payload["session_id"] = sess_id
        if error_code is not None:
            payload["error_code"] = self._redactor.redact_text(str(error_code))
        if isinstance(raw_attributes, Mapping):
            payload["attributes"] = self._redactor.redact_value(raw_attributes)
        if record.exc_info:
            exc_text = self.formatException(record.exc_info)
            payload["exception"] = self._redactor.redact_text(exc_text)

        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def get_structured_logger(
    name: str,
    *,
    level: int = logging.INFO,
    handler: logging.Handler | None = None,
    redactor: Redactor | None = None,
) -> logging.Logger:
    """Create or configure a non-propagating structured JSON logger."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False
    if handler is not None:
        logger.handlers = [handler]
    elif not logger.handlers:
        default_handler = logging.StreamHandler()
        default_handler.setFormatter(StructuredJsonFormatter(redactor=redactor))
        logger.addHandler(default_handler)
    return logger


def _scrub_otel_attribute_value(redactor: Redactor, key: str, value: Any) -> Any:
    scrubbed_map = redactor.redact_value({key: value})
    candidate = scrubbed_map[key]
    if isinstance(candidate, (bool, int, float, str)):
        return candidate
    if isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes)):
        return tuple(
            str(item) if not isinstance(item, (bool, int, float, str)) else item
            for item in candidate
        )
    return str(candidate)


def _scrub_otel_mapping(
    redactor: Redactor,
    attrs: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if attrs is None:
        return None
    return {str(k): _scrub_otel_attribute_value(redactor, str(k), v) for k, v in attrs.items()}


class RedactingSpanProcessor(SpanProcessor):
    """OpenTelemetry SpanProcessor wrapper scrubbing attributes and events before export."""

    def __init__(
        self,
        *,
        delegate: SpanProcessor,
        redactor: Redactor | None = None,
    ) -> None:
        self._delegate = delegate
        self._redactor = redactor if redactor is not None else DEFAULT_REDACTOR

    def on_start(self, span: Span, parent_context: Context | None = None) -> None:
        if span.is_recording():
            span.set_attribute("red2pr.correlation_id", current_correlation_id())
            span.set_attribute("red2pr.entry_point", _entry_point_var.get())
            span.set_attribute("red2pr.redaction_version", REDACTION_VERSION)
        self._delegate.on_start(span, parent_context=parent_context)

    def on_end(self, span: ReadableSpan) -> None:
        scrubbed_attrs = _scrub_otel_mapping(self._redactor, span.attributes)
        scrubbed_events = tuple(
            Event(
                name=self._redactor.redact_text(ev.name),
                attributes=_scrub_otel_mapping(self._redactor, ev.attributes),
                timestamp=ev.timestamp,
            )
            for ev in span.events
        )
        sanitized_span = ReadableSpan(
            name=self._redactor.redact_text(span.name),
            context=span.get_span_context(),
            parent=span.parent,
            resource=span.resource,
            attributes=scrubbed_attrs,
            events=scrubbed_events,
            links=span.links,
            kind=span.kind,
            status=span.status,
            start_time=span.start_time,
            end_time=span.end_time,
            instrumentation_scope=span.instrumentation_scope,
        )
        self._delegate.on_end(sanitized_span)

    def shutdown(self) -> None:
        self._delegate.shutdown()

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return self._delegate.force_flush(timeout_millis=timeout_millis)
