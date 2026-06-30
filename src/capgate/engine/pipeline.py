from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace

from capgate.engine.context import AgentContext
from capgate.engine.decision import Decision
from capgate.flow.rules import check_flow, label_strings
from capgate.flow.sinks import SinkKind
from capgate.policy.enforce import enforce
from capgate.policy.model import Policy
from capgate.proxy.events import ToolCallEvent, ToolResultEvent
from capgate.sandbox.base import RiskClass, SandboxRoute, route_backend
from capgate.taint.labels import Label
from capgate.taint.propagation import propagate_tool_result


@dataclass(frozen=True)
class ToolMetadata:
    result_label: Label
    risk_class: RiskClass
    sink: SinkKind = SinkKind.NONE
    capability: str | None = None


class DecisionPipeline:
    def __init__(
        self,
        tool_metadata: Mapping[str, ToolMetadata],
        policy: Policy | None = None,
    ) -> None:
        self._tool_metadata = dict(tool_metadata)
        self._policy = policy

    def decide(self, context: AgentContext, event: ToolCallEvent) -> Decision:
        argument_label = context.label_for_call(tuple(event.arg_provenance.values()))
        try:
            return self._decide(event, argument_label)
        except Exception:
            return Decision(
                verdict="BLOCK",
                reason="decision pipeline failed closed",
                rule_id="engine.decision_error",
                labels=label_strings(argument_label),
            )

    def _decide(self, event: ToolCallEvent, argument_label: Label) -> Decision:
        metadata = self._tool_metadata.get(event.tool)
        if metadata is None:
            return Decision(
                verdict="BLOCK",
                reason=f"tool has no registered security metadata: {event.tool}",
                rule_id="engine.unknown_tool",
                labels=label_strings(argument_label),
            )
        if self._policy is not None:
            if metadata.capability is None:
                return Decision(
                    verdict="BLOCK",
                    reason=f"tool has no registered capability: {event.tool}",
                    rule_id="policy.missing_capability",
                    labels=label_strings(argument_label),
                )
            policy_decision = replace(
                enforce(self._policy, metadata.capability),
                labels=label_strings(argument_label),
            )
            if policy_decision.verdict != "ALLOW":
                return policy_decision
        flow_decision = check_flow(argument_label, metadata.sink)
        if flow_decision is not None:
            return flow_decision
        route = route_backend(metadata.risk_class)
        if route.decision.verdict != "ALLOW":
            return replace(route.decision, labels=label_strings(argument_label))
        return Decision(
            verdict="ALLOW",
            reason="stage1 flow checks passed",
            rule_id=None,
            labels=label_strings(argument_label),
        )

    def observe_result(
        self,
        context: AgentContext,
        call_event: ToolCallEvent,
        result_event: ToolResultEvent,
    ) -> None:
        metadata = self._tool_metadata[call_event.tool]
        argument_label = context.label_for_call(tuple(call_event.arg_provenance.values()))
        result_label = propagate_tool_result(argument_label, metadata.result_label)
        context.record_result(_provenance_id(result_event), result_label)

    def route_execution(self, tool: str) -> SandboxRoute:
        metadata = self._tool_metadata.get(tool)
        return route_backend(metadata.risk_class if metadata is not None else None)


def _provenance_id(event: ToolResultEvent) -> str:
    return f"{event.server}:{event.tool}:{event.request_id}"
