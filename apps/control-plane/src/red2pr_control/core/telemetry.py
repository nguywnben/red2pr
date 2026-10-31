"""OpenTelemetry setup and correlation propagation for the control-plane boundary."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.metrics import Meter, get_meter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import MetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from red2pr_control.core.logging import RedactingSpanProcessor

_W3C_TRACE_CONTEXT = TraceContextTextMapPropagator()


def configure_telemetry(
    *,
    service_name: str = "red2pr-control-plane",
    span_exporter: SpanExporter | None = None,
    metric_reader: MetricReader | None = None,
) -> tuple[TracerProvider, MeterProvider]:
    """Install OTel providers; exporters remain host injected and disabled by default."""
    resource = Resource.create({"service.name": service_name})
    existing_tracer = trace.get_tracer_provider()
    if isinstance(existing_tracer, TracerProvider):
        tracer_provider = existing_tracer
        if span_exporter is not None:
            tracer_provider.add_span_processor(
                RedactingSpanProcessor(delegate=BatchSpanProcessor(span_exporter))
            )
    else:
        tracer_provider = TracerProvider(resource=resource)
        if span_exporter is not None:
            tracer_provider.add_span_processor(
                RedactingSpanProcessor(delegate=BatchSpanProcessor(span_exporter))
            )
        trace.set_tracer_provider(tracer_provider)
    existing_meter = metrics.get_meter_provider()
    if isinstance(existing_meter, MeterProvider):
        meter_provider = existing_meter
    else:
        meter_provider = MeterProvider(
            resource=resource, metric_readers=(metric_reader,) if metric_reader else ()
        )
        metrics.set_meter_provider(meter_provider)
    return tracer_provider, meter_provider


def inject_trace_context(carrier: dict[str, str]) -> dict[str, str]:
    """Inject W3C trace context into a transport carrier, never baggage data."""
    _W3C_TRACE_CONTEXT.inject(carrier)
    return carrier


def extract_trace_context(carrier: Mapping[str, str]) -> Any:
    """Extract W3C trace context at a process boundary."""
    safe_carrier = {
        key: value for key, value in carrier.items() if key.lower() in {"traceparent", "tracestate"}
    }
    return _W3C_TRACE_CONTEXT.extract(safe_carrier)


def get_control_plane_meter() -> Meter:
    """Return the bounded Red2PR meter namespace."""
    return get_meter("red2pr.control_plane")
