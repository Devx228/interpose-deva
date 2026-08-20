from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace

from capgate.engine.context import AgentContext, ProvenanceMode
from capgate.engine.decision import Decision
from capgate.flow.rules import DEFAULT_DENY_PAIRS, DenyPair, check_flow, label_strings
from capgate.flow.sinks import SinkKind
from capgate.policy.enforce import enforce
from capgate.policy.model import Policy
from capgate.proxy.events import JsonValue, ToolCallEvent, ToolResultEvent
from capgate.sandbox.base import RiskClass, SandboxRoute, route_backend
from capgate.taint.declassify import DeclassificationSpec
from capgate.taint.labels import Label
from capgate.taint.propagation import propagate_tool_result


@dataclass(frozen=True)
class ToolMetadata:
    result_label: Label
    risk_class: RiskClass
    sink: SinkKind = SinkKind.NONE
    capability: str | None = None
    #: When True and the session runs in value-level provenance mode, this tool's result
    #: is stored behind an opaque reference and the planner receives the token instead of
    #: the raw value. Ignored entirely in session mode.
    returns_reference: bool = False
    #: When set, this tool is a declared declassifier: its output must validate against
    #: the spec's closed field domains, and only then does it carry the spec's (lower)
    #: label instead of the conservative join. A nonconforming output is withheld from
    #: the planner entirely. See docs/design-notes/DECLASSIFICATION.md.
    declassification: DeclassificationSpec | None = None


@dataclass(frozen=True, slots=True)
class ObservedResult:
    """What observing one tool result produced, for the mediator to act on."""

    reference: str | None = None
    #: Set when a declassification validated: the audited upper bound on
    #: attacker-choosable bits this call released. The mediator records it in the
    #: signed receipt's taint labels.
    declassified_bits: float | None = None


class DecisionPipeline:
    def __init__(
        self,
        tool_metadata: Mapping[str, ToolMetadata],
        policy: Policy | None = None,
        deny_pairs: tuple[DenyPair, ...] = DEFAULT_DENY_PAIRS,
        require_trusted_for_state_change: bool = False,
    ) -> None:
        self._tool_metadata = dict(tool_metadata)
        self._policy = policy
        self._deny_pairs = deny_pairs
        self._require_trusted_for_state_change = require_trusted_for_state_change

    def decide(
        self,
        context: AgentContext,
        event: ToolCallEvent,
        *,
        approved: bool = False,
    ) -> Decision:
        """Decide one tool call.

        ``approved`` records that a trusted human has authorized this specific call. It
        satisfies **only** the capability gate — a `REQUIRE_APPROVAL` verdict becomes
        eligible to continue. Every later check still runs, so an approved call whose data
        would violate a flow rule is still blocked. Approval is permission to act, never
        permission to leak.
        """

        argument_label = context.label_for_call(tuple(event.arg_provenance.values()))
        try:
            return self._decide(event, argument_label, approved=approved)
        except Exception:
            return Decision(
                verdict="BLOCK",
                reason="decision pipeline failed closed",
                rule_id="engine.decision_error",
                labels=label_strings(argument_label),
            )

    def _decide(
        self,
        event: ToolCallEvent,
        argument_label: Label,
        *,
        approved: bool = False,
    ) -> Decision:
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
            approval_satisfied = (
                approved and policy_decision.verdict == "REQUIRE_APPROVAL"
            )
            if policy_decision.verdict != "ALLOW" and not approval_satisfied:
                return policy_decision
        flow_decision = check_flow(
            argument_label,
            metadata.sink,
            self._deny_pairs,
            require_trusted_for_state_change=self._require_trusted_for_state_change,
        )
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
        *,
        payload: JsonValue | None = None,
    ) -> ObservedResult:
        """Record a result's provenance; report references and declassifications.

        A reference-returning tool's result (``payload`` when the framework projects one,
        else the full result) is stored under an unguessable token carrying the exact
        result label, and the session influence join is skipped: the planner receives only
        the token, so the raw value cannot have influenced it and cannot be re-emitted
        from memory. Every other tool joins session influence exactly as before.

        A declared declassifier's output is validated against its closed-domain spec
        first. On success the result carries the spec's lower label and the released-bits
        bound is reported for the receipt. On failure :class:`DeclassificationError`
        propagates and *nothing* is recorded — the caller must withhold the result from
        the planner, because a nonconforming extraction is a quarantine escape attempt.
        """

        metadata = self._tool_metadata[call_event.tool]
        argument_label = context.label_for_call(tuple(call_event.arg_provenance.values()))
        declassified_bits: float | None = None
        if metadata.declassification is not None:
            declassified_bits = metadata.declassification.validate(
                payload if payload is not None else result_event.result
            )
            result_label = metadata.declassification.output_label
        else:
            result_label = propagate_tool_result(argument_label, metadata.result_label)
        reference: str | None = None
        joins_influence = True
        if (
            metadata.returns_reference
            and context.provenance_mode is ProvenanceMode.VALUE_LEVEL
        ):
            stored = context.values.store(
                result_label,
                payload if payload is not None else result_event.result,
            )
            reference = stored.reference
            joins_influence = False
        context.record_result(
            _provenance_id(result_event),
            result_label,
            joins_influence=joins_influence,
        )
        return ObservedResult(reference=reference, declassified_bits=declassified_bits)

    def route_execution(self, tool: str) -> SandboxRoute:
        metadata = self._tool_metadata.get(tool)
        return route_backend(metadata.risk_class if metadata is not None else None)


def _provenance_id(event: ToolResultEvent) -> str:
    return f"{event.server}:{event.tool}:{event.request_id}"
