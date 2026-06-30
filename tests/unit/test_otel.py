from __future__ import annotations

from collections.abc import Sequence

import pytest
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from capgate.engine.decision import STAGE0_ALLOW, Decision
from capgate.proxy.events import JsonValue, ToolCallEvent
from capgate.telemetry.otel import configure_noop, configure_telemetry, tool_call_span


class FailingExporter(SpanExporter):
    def __init__(self) -> None:
        self.export_attempts = 0
        self.shutdown_attempts = 0

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        assert spans
        self.export_attempts += 1
        raise RuntimeError("exporter unavailable")

    def shutdown(self) -> None:
        self.shutdown_attempts += 1
        raise RuntimeError("exporter shutdown failed")


def _event(*, arguments: dict[str, JsonValue] | None = None) -> ToolCallEvent:
    return ToolCallEvent(
        session_id="session-1",
        server="test-server",
        tool="search",
        arguments=arguments or {},
        arg_provenance={},
        request_id=1,
    )


def test_tool_call_span_context_manager_runs() -> None:
    with tool_call_span(_event(), STAGE0_ALLOW):
        value = 42

    assert value == 42


def test_configured_exporter_receives_decision_metadata_without_raw_data() -> None:
    raw_argument = "raw-argument-must-not-be-exported"
    raw_result = "raw-result-must-not-be-exported"
    exporter = InMemorySpanExporter()
    provider = configure_telemetry(exporter)
    decision = Decision(
        verdict="BLOCK",
        reason="policy denied external network access",
        rule_id="policy.no_external_network",
        labels=frozenset({"integrity:untrusted", "web"}),
    )

    try:
        with tool_call_span(_event(arguments={"query": raw_argument}), decision):
            result = raw_result

        spans = exporter.get_finished_spans()
        assert result == raw_result
        assert len(spans) == 1
        span = spans[0]
        assert span.name == "execute_tool"
        assert span.attributes is not None
        assert span.attributes["capgate.session_id"] == "session-1"
        assert span.attributes["capgate.server"] == "test-server"
        assert span.attributes["capgate.tool"] == "search"
        assert span.attributes["capgate.verdict"] == "BLOCK"
        assert span.attributes["capgate.reason"] == decision.reason
        assert span.attributes["capgate.rule_id"] == decision.rule_id
        assert span.attributes["capgate.taint_labels"] == ("integrity:untrusted", "web")
        assert span.attributes["gen_ai.operation.name"] == "execute_tool"
        exported_metadata = repr(dict(span.attributes))
        assert raw_argument not in exported_metadata
        assert raw_result not in exported_metadata
        assert all("argument" not in key and "result" not in key for key in span.attributes)
    finally:
        provider.shutdown()
        configure_noop()


def test_exporter_failure_does_not_fail_tool_span() -> None:
    exporter = FailingExporter()
    provider = configure_telemetry(exporter)

    try:
        with tool_call_span(_event(), STAGE0_ALLOW):
            completed = True

        assert completed is True
        assert exporter.export_attempts == 1
        provider.shutdown()
        assert exporter.shutdown_attempts == 1
    finally:
        configure_noop()


def test_tool_failure_still_propagates_with_best_effort_exporter() -> None:
    exporter = FailingExporter()
    provider = configure_telemetry(exporter)

    try:
        with (
            pytest.raises(RuntimeError, match="tool execution failed"),
            tool_call_span(_event(), STAGE0_ALLOW),
        ):
            raise RuntimeError("tool execution failed")
        assert exporter.export_attempts == 1
    finally:
        provider.shutdown()
        configure_noop()
