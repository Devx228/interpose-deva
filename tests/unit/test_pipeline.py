from __future__ import annotations

from typing import cast

from capgate.engine.context import AgentContext
from capgate.engine.pipeline import DecisionPipeline, ToolMetadata
from capgate.flow.sinks import SinkKind
from capgate.policy import parse_policy
from capgate.proxy.events import ToolCallEvent, ToolResultEvent
from capgate.sandbox.base import RiskClass, SandboxBackend
from capgate.taint.labels import Confidentiality, Integrity, Label


def _call(tool: str, request_id: int = 1) -> ToolCallEvent:
    return ToolCallEvent(
        session_id="session-1",
        server="test-server",
        tool=tool,
        arguments={},
        arg_provenance={},
        request_id=request_id,
    )


def _result(call: ToolCallEvent) -> ToolResultEvent:
    return ToolResultEvent(
        session_id=call.session_id,
        server=call.server,
        tool=call.tool,
        result={"ok": True},
        request_id=call.request_id,
    )


def _pipeline(*, with_policy: bool = False) -> DecisionPipeline:
    policy = None
    if with_policy:
        policy = parse_policy(
            """
agent: test-agent
can: [read:private]
cannot: []
requires_approval: [send:external]
"""
        )
    return DecisionPipeline(
        {
            "read_private": ToolMetadata(
                result_label=Label(
                    Confidentiality.INTERNAL,
                    Integrity.UNTRUSTED,
                    frozenset({"private-calendar"}),
                ),
                risk_class=RiskClass.TRUSTED_DIRECT,
                capability="read:private",
            ),
            "send_external": ToolMetadata(
                result_label=Label(
                    Confidentiality.PUBLIC,
                    Integrity.UNTRUSTED,
                    frozenset({"email"}),
                ),
                risk_class=RiskClass.FIXED_RISKY,
                sink=SinkKind.EMAIL_EXTERNAL,
                capability="send:external",
            ),
        },
        policy=policy,
    )


def test_pipeline_blocks_private_untrusted_flow_to_external_sink() -> None:
    pipeline = _pipeline()
    context = AgentContext(session_id="session-1")
    read_call = _call("read_private")

    assert pipeline.decide(context, read_call).verdict == "ALLOW"
    pipeline.observe_result(context, read_call, _result(read_call))

    decision = pipeline.decide(context, _call("send_external", request_id=2))

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == "flow.lethal_trifecta"
    assert "private data influenced by untrusted content" in decision.reason


def test_pipeline_allows_external_sink_without_private_untrusted_influence() -> None:
    decision = _pipeline().decide(
        AgentContext(session_id="session-1"),
        _call("send_external"),
    )

    assert decision.verdict == "ALLOW"


def test_pipeline_fails_closed_for_unknown_tool() -> None:
    decision = _pipeline().decide(
        AgentContext(session_id="session-1"),
        _call("not_registered"),
    )

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == "engine.unknown_tool"


def test_pipeline_applies_policy_before_flow_checks() -> None:
    pipeline = _pipeline(with_policy=True)

    assert pipeline.decide(AgentContext("session-1"), _call("read_private")).verdict == "ALLOW"
    decision = pipeline.decide(AgentContext("session-1"), _call("send_external"))

    assert decision.verdict == "REQUIRE_APPROVAL"
    assert decision.rule_id == "policy.requires_approval.send:external"


def test_pipeline_policy_requires_explicit_tool_capability() -> None:
    pipeline = DecisionPipeline(
        {
            "tool": ToolMetadata(
                result_label=Label(Confidentiality.PUBLIC, Integrity.TRUSTED),
                risk_class=RiskClass.TRUSTED_DIRECT,
            )
        },
        policy=parse_policy("agent: test\ncan: [read:public]"),
    )

    decision = pipeline.decide(AgentContext("session-1"), _call("tool"))

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == "policy.missing_capability"


def test_pipeline_exposes_explicit_execution_route() -> None:
    pipeline = _pipeline()

    direct = pipeline.route_execution("read_private")
    risky = pipeline.route_execution("send_external")
    unknown = pipeline.route_execution("not_registered")

    assert direct.decision.verdict == "ALLOW" and direct.backend is None
    assert risky.decision.verdict == "ALLOW"
    assert risky.backend is SandboxBackend.GVISOR
    assert unknown.decision.verdict == "BLOCK"
    assert unknown.decision.rule_id == "sandbox.risk.unknown"


def test_pipeline_decision_fails_closed_for_untrusted_raw_risk_value() -> None:
    pipeline = DecisionPipeline(
        {
            "tool": ToolMetadata(
                result_label=Label(Confidentiality.PUBLIC, Integrity.TRUSTED),
                risk_class=cast(RiskClass, "trusted_direct"),
            )
        }
    )

    decision = pipeline.decide(AgentContext("session-1"), _call("tool"))

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == "sandbox.risk.unknown"
