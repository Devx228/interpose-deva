from __future__ import annotations

from capgate.engine.context import AgentContext
from capgate.engine.pipeline import DecisionPipeline, ToolMetadata
from capgate.flow.sinks import SinkKind
from capgate.proxy.events import ToolCallEvent, ToolResultEvent
from capgate.sandbox.base import RiskClass
from capgate.taint.labels import Confidentiality, Integrity, Label


def test_private_untrusted_tool_result_cannot_flow_to_external_sink() -> None:
    pipeline = DecisionPipeline(
        {
            "read_private_message": ToolMetadata(
                result_label=Label(
                    Confidentiality.SECRET,
                    Integrity.UNTRUSTED,
                    frozenset({"mcp:untrusted-inbox"}),
                ),
                risk_class=RiskClass.TRUSTED_DIRECT,
            ),
            "send_external": ToolMetadata(
                result_label=Label(Confidentiality.PUBLIC, Integrity.UNTRUSTED),
                risk_class=RiskClass.FIXED_RISKY,
                sink=SinkKind.NETWORK_EXTERNAL,
            ),
        }
    )
    context = AgentContext("regression-session")
    read = _call("read_private_message", 1)

    assert pipeline.decide(context, read).verdict == "ALLOW"
    pipeline.observe_result(
        context,
        read,
        ToolResultEvent(
            session_id=read.session_id,
            server=read.server,
            tool=read.tool,
            result={"content": "hashed by receipts, never logged here"},
            request_id=read.request_id,
        ),
    )

    decision = pipeline.decide(context, _call("send_external", 2))

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == "flow.lethal_trifecta"


def _call(tool: str, request_id: int) -> ToolCallEvent:
    return ToolCallEvent(
        session_id="regression-session",
        server="mcp-server",
        tool=tool,
        arguments={},
        arg_provenance={},
        request_id=request_id,
    )
