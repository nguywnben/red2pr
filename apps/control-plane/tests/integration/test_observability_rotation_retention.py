"""U25 integration-adjacent checks for unsampled, redacted OTel propagation."""

from opentelemetry import context
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from red2pr_control.core.logging import RedactingSpanProcessor, bind_telemetry_context
from red2pr_control.core.telemetry import extract_trace_context, inject_trace_context


def test_trace_context_crosses_process_carrier_and_sensitive_attributes_are_redacted() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(RedactingSpanProcessor(delegate=SimpleSpanProcessor(exporter)))
    tracer = provider.get_tracer("u25.integration")
    with (
        bind_telemetry_context(correlation_id="u25-correlation-1", entry_point="test"),
        tracer.start_as_current_span("api-to-outbox") as parent,
    ):
        parent.set_attribute("authorization", "Bearer ghp_12345678901234567890")
        carrier: dict[str, str] = {}
        inject_trace_context(carrier)
        extracted = extract_trace_context(carrier)
        token = context.attach(extracted)
        try:
            with tracer.start_as_current_span("task-job"):  # follows the propagated parent
                pass
        finally:
            context.detach(token)
    provider.force_flush()
    spans = exporter.get_finished_spans()
    assert len(spans) == 2
    by_name = {span.name: span for span in spans}
    assert by_name["task-job"].parent is not None
    assert by_name["task-job"].parent.span_id == by_name["api-to-outbox"].context.span_id
    assert by_name["api-to-outbox"].attributes["red2pr.correlation_id"] == "u25-correlation-1"
    assert "ghp_12345678901234567890" not in repr(by_name["api-to-outbox"].attributes)
    provider.shutdown()
