from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from threading import Lock
from typing import Generic, TypeVar, cast

from capgate.engine.context import AgentContext, ProvenanceMode
from capgate.engine.decision import Decision
from capgate.engine.pipeline import DecisionPipeline
from capgate.proxy.events import JsonObject, JsonValue, ToolCallEvent, ToolResultEvent
from capgate.receipts.signer import ReceiptWriter
from capgate.taint.labels import Label
from capgate.taint.propagation import join_labels
from capgate.taint.values import resolve_argument

ResultT = TypeVar("ResultT")


@dataclass(frozen=True, slots=True)
class MediationOutcome(Generic[ResultT]):
    """The decision, execution fact, and original value for one mediated call."""

    decision: Decision
    executed: bool
    value: ResultT | None
    #: Set when the tool is reference-returning in value-level mode. The adapter must show
    #: the planner this token instead of the raw result; the receipt already recorded the
    #: real result's hash.
    reference: str | None = None


@dataclass(frozen=True, slots=True)
class ResolvedArguments:
    """Arguments after reference resolution, with the exact labels resolution proved."""

    arguments: JsonObject
    #: Per top-level argument, the join of every reference label resolved inside it.
    #: Missing keys mean nothing resolved there. These labels are additions to the
    #: caller's declared label, never replacements.
    reference_labels: Mapping[str, Label]
    substituted: bool


class ToolCallMediator:
    """Serialize framework-neutral authorization, execution, and audit state."""

    def __init__(
        self,
        *,
        pipeline: DecisionPipeline,
        context: AgentContext,
        receipt_writer: ReceiptWriter,
    ) -> None:
        self._pipeline = pipeline
        self._context = context
        self._receipt_writer = receipt_writer
        self._lock = Lock()
        self._failed_closed = False

    @property
    def provenance_mode(self) -> ProvenanceMode:
        return self._context.provenance_mode

    def resolve_arguments(self, arguments: JsonObject) -> ResolvedArguments:
        """Substitute stored values for references in the call's arguments.

        In session mode this is the identity: no store is consulted and no label is
        produced, so existing behavior is untouched. In value-level mode each top-level
        argument is walked, resolvable tokens are replaced with the values they name, and
        the exact labels of those values are returned so the adapter can join them into
        the declared argument labels. Unresolvable tokens stay inert.
        """

        if self._context.provenance_mode is not ProvenanceMode.VALUE_LEVEL:
            return ResolvedArguments(
                arguments=arguments, reference_labels={}, substituted=False
            )
        with self._lock:
            resolved_arguments: JsonObject = {}
            reference_labels: dict[str, Label] = {}
            substituted = False
            for name, value in arguments.items():
                resolution = resolve_argument(value, self._context.values)
                resolved_arguments[name] = cast(JsonValue, resolution.value)
                if resolution.labels:
                    reference_labels[name] = join_labels(resolution.labels)
                substituted = substituted or resolution.substituted
            return ResolvedArguments(
                arguments=resolved_arguments,
                reference_labels=reference_labels,
                substituted=substituted,
            )

    def mediate(
        self,
        event: ToolCallEvent,
        execute: Callable[[], ResultT],
        *,
        result_to_json: Callable[[ResultT], JsonValue] | None = None,
        argument_labels: Mapping[str, Label] | None = None,
        approve: Callable[[Decision], bool] | None = None,
        result_payload: Callable[[ResultT], JsonValue] | None = None,
    ) -> MediationOutcome[ResultT]:
        """Mediate one direct tool call and return a sanitized outcome.

        On success, ``value`` is exactly the object returned by ``execute``.
        Framework-specific results require an explicit ``result_to_json`` projection
        for receipts and provenance. Every non-empty argument set requires matching
        provenance IDs on the event and trusted labels in ``argument_labels``.

        ``approve`` is trusted code that resolves a ``REQUIRE_APPROVAL`` verdict. Without
        it, approval-required calls are refused, because a verdict nobody can answer must
        never behave like an allow. It is called before anything executes, so exceptions
        are deliberately **not** caught: a framework may implement approval by suspending
        the run (LangGraph raises to pause), and swallowing that would turn a pause into a
        silent decision. Nothing has executed at that point, so propagating is safe.
        """

        with self._lock:
            return self._mediate_locked(
                event, execute, result_to_json, argument_labels, approve, result_payload
            )

    def _mediate_locked(
        self,
        event: ToolCallEvent,
        execute: Callable[[], ResultT],
        result_to_json: Callable[[ResultT], JsonValue] | None,
        argument_labels: Mapping[str, Label] | None,
        approve: Callable[[Decision], bool] | None = None,
        result_payload: Callable[[ResultT], JsonValue] | None = None,
    ) -> MediationOutcome[ResultT]:
        if self._failed_closed:
            return self._rejected(
                event,
                _decision(
                    "mediator session failed closed after an earlier "
                    "execution or bookkeeping failure",
                    "mediator.session_failed_closed",
                ),
                execution_started=False,
            )
        if event.session_id != self._context.session_id:
            return self._rejected(
                event,
                _decision(
                    "tool call session does not match the mediator session",
                    "mediator.session_mismatch",
                ),
                execution_started=False,
            )

        argument_label_error = _record_argument_labels(
            self._context,
            event,
            argument_labels,
        )
        if argument_label_error is not None:
            return self._rejected(event, argument_label_error, execution_started=False)

        decision = self._pipeline.decide(self._context, event)
        if decision.verdict == "REQUIRE_APPROVAL" and approve is not None:
            decision = self._resolve_approval(event, decision, approve)
        if decision.verdict != "ALLOW":
            return self._rejected(event, decision, execution_started=False)

        try:
            route = self._pipeline.route_execution(event.tool)
        except Exception:
            return self._rejected(
                event,
                _decision(
                    "tool execution routing failed closed",
                    "mediator.routing_failed",
                    decision.labels,
                ),
                execution_started=False,
            )
        if route.decision.verdict != "ALLOW":
            return self._rejected(
                event,
                _decision(route.decision.reason, route.decision.rule_id, decision.labels),
                execution_started=False,
            )
        if route.backend is not None:
            return self._rejected(
                event,
                _decision(
                    "required sandbox execution path is unavailable",
                    "sandbox.call.unavailable",
                    decision.labels,
                ),
                execution_started=False,
            )

        try:
            result = execute()
        except Exception:
            self._failed_closed = True
            return self._rejected(
                event,
                _decision(
                    "tool execution failed after starting; partial side effects may have occurred; "
                    "session failed closed",
                    "mediator.execution_failed",
                    decision.labels,
                ),
                execution_started=True,
            )

        try:
            json_result = _json_result(result, result_to_json)
            payload = (
                _json_result(result, result_payload) if result_payload is not None else None
            )
        except Exception:
            self._failed_closed = True
            return self._rejected(
                event,
                _decision(
                    "tool result was not safely representable; "
                    "session failed closed after execution",
                    "mediator.result_invalid",
                    decision.labels,
                ),
                execution_started=True,
            )

        result_event = _result_event(event, json_result)
        try:
            reference = self._pipeline.observe_result(
                self._context, event, result_event, payload=payload
            )
        except Exception:
            self._failed_closed = True
            return self._rejected(
                event,
                _decision(
                    "tool provenance update failed; session failed closed after execution",
                    "mediator.provenance_failed",
                    decision.labels,
                ),
                execution_started=True,
            )

        try:
            self._receipt_writer.write_tool_call(
                call_event=event,
                result_event=result_event,
                decision=decision,
            )
        except Exception:
            self._failed_closed = True
            return MediationOutcome(
                decision=_decision(
                    "tool receipt recording failed; session failed closed after execution",
                    "mediator.receipt_failed",
                    decision.labels,
                ),
                executed=True,
                value=None,
            )
        return MediationOutcome(
            decision=decision, executed=True, value=result, reference=reference
        )

    def _resolve_approval(
        self,
        event: ToolCallEvent,
        decision: Decision,
        approve: Callable[[Decision], bool],
    ) -> Decision:
        """Ask trusted code to resolve an approval-required call.

        A grant satisfies the capability gate only. The pipeline is re-run with
        ``approved=True`` so every later check still applies — an approved call whose data
        would violate a flow rule is still blocked. Approval is permission to act, never
        permission to leak.
        """

        if approve(decision) is not True:
            return _decision(
                "approval was refused for this tool call",
                "policy.approval.denied",
                decision.labels,
            )
        approved = self._pipeline.decide(self._context, event, approved=True)
        if approved.verdict != "ALLOW":
            return approved
        return replace(
            approved,
            reason=f"{approved.reason}; executed after explicit approval",
            rule_id="policy.approval.granted",
        )

    def _rejected(
        self,
        event: ToolCallEvent,
        decision: Decision,
        *,
        execution_started: bool,
    ) -> MediationOutcome[ResultT]:
        try:
            self._receipt_writer.write_tool_call(
                call_event=event,
                result_event=_result_event(event, _decision_result(decision)),
                decision=decision,
            )
        except Exception:
            self._failed_closed = True
            return MediationOutcome(
                decision=_decision(
                    "tool receipt recording failed; mediator session failed closed",
                    "mediator.receipt_failed",
                    decision.labels,
                ),
                executed=execution_started,
                value=None,
            )
        return MediationOutcome(
            decision=decision,
            executed=execution_started,
            value=None,
        )


def _decision(
    reason: str,
    rule_id: str | None,
    labels: frozenset[str] = frozenset(),
) -> Decision:
    return Decision("BLOCK", reason, rule_id, labels)


def _result_event(event: ToolCallEvent, result: JsonValue) -> ToolResultEvent:
    return ToolResultEvent(
        session_id=event.session_id,
        server=event.server,
        tool=event.tool,
        result=result,
        request_id=event.request_id,
    )


def _decision_result(decision: Decision) -> JsonValue:
    detail: JsonObject = {
        "verdict": decision.verdict,
        "rule_id": decision.rule_id,
    }
    return {"capgate": detail}


def _record_argument_labels(
    context: AgentContext,
    event: ToolCallEvent,
    labels: Mapping[str, Label] | None,
) -> Decision | None:
    argument_names = set(event.arguments)
    if not argument_names:
        if event.arg_provenance or labels:
            return _decision(
                "tool argument labels do not match the call arguments",
                "mediator.argument_labels_invalid",
            )
        return None
    if (
        labels is None
        or set(labels) != argument_names
        or set(event.arg_provenance) != argument_names
    ):
        return _decision(
            "every tool argument requires a trusted provenance label",
            "mediator.argument_labels_missing",
        )
    checked: list[tuple[str, Label]] = []
    for name in sorted(argument_names):
        label = labels[name]
        provenance_id = event.arg_provenance[name]
        if not isinstance(label, Label) or not provenance_id:
            return _decision(
                "tool argument provenance labels are invalid",
                "mediator.argument_labels_invalid",
            )
        checked.append((provenance_id, label))
    for provenance_id, label in checked:
        context.tracker.record(provenance_id, label)
    return None


def _json_result(
    result: ResultT,
    converter: Callable[[ResultT], JsonValue] | None,
) -> JsonValue:
    converted: object = converter(result) if converter is not None else result
    if not _is_json_value(converted):
        raise ValueError("tool result is not a JSON value")
    return cast(JsonValue, converted)


def _is_json_value(value: object) -> bool:
    if value is None or isinstance(value, str | bool | int):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_is_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _is_json_value(item) for key, item in value.items()
        )
    return False
