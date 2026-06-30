from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)

from capgate.engine.decision import Decision
from capgate.proxy.events import ToolCallEvent

_tracer_provider: TracerProvider | None = None


class _BestEffortSpanExporter(SpanExporter):
    def __init__(self, exporter: SpanExporter) -> None:
        self._exporter = exporter

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        try:
            return self._exporter.export(spans)
        except Exception:
            return SpanExportResult.FAILURE

    def shutdown(self) -> None:
        with suppress(Exception):
            self._exporter.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        try:
            return self._exporter.force_flush(timeout_millis)
        except Exception:
            return False


def configure_telemetry(exporter: SpanExporter) -> TracerProvider:
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(_BestEffortSpanExporter(exporter)))

    global _tracer_provider
    _tracer_provider = provider
    return provider


@contextmanager
def tool_call_span(event: ToolCallEvent, decision: Decision) -> Iterator[None]:
    tracer = (
        _tracer_provider.get_tracer("capgate")
        if _tracer_provider is not None
        else trace.get_tracer("capgate")
    )
    with tracer.start_as_current_span("execute_tool") as span:
        span.set_attribute("capgate.session_id", event.session_id)
        span.set_attribute("capgate.server", event.server)
        span.set_attribute("capgate.tool", event.tool)
        span.set_attribute("capgate.verdict", decision.verdict)
        span.set_attribute("capgate.reason", decision.reason)
        span.set_attribute("capgate.taint_labels", sorted(decision.labels))
        if decision.rule_id is not None:
            span.set_attribute("capgate.rule_id", decision.rule_id)
        span.set_attribute("gen_ai.operation.name", "execute_tool")
        yield


def configure_noop(_: Any = None) -> None:
    global _tracer_provider
    _tracer_provider = None
