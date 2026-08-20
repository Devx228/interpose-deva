from __future__ import annotations

import math
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from threading import Condition
from typing import TYPE_CHECKING, Any

from capgate.engine.decision import Decision
from capgate.engine.mediator import ToolCallMediator
from capgate.proxy.events import JsonObject, JsonValue, ToolCallEvent
from capgate.taint.labels import Label

if TYPE_CHECKING:
    from langchain_core.messages import ToolMessage
    from langchain_core.tools import BaseTool
    from langgraph.prebuilt import ToolNode
    from langgraph.prebuilt.tool_node import ToolCallRequest
    from langgraph.types import Command
    from pydantic import BaseModel


@dataclass(frozen=True, slots=True)
class LangGraphToolCall:
    """Dependency-free shape matching the fields needed from a LangGraph tool call."""

    name: str
    args: JsonObject
    call_id: str


class ToolCallRejected(RuntimeError):
    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(decision.reason)


class _TurnSequencer:
    """Serialize a multi-call turn's mediations into the planner's emission order.

    `ToolNode` dispatches a turn's calls concurrently, and thread scheduling is not a
    security order: judged against clean pre-turn state, a read-secret + send pair would
    both pass. So each call waits for its slot — call *k* mediates only after calls
    ``0..k-1`` have finished mediating — which makes every decision see the taint the
    earlier calls in the same turn produced, exactly as if the planner had issued them
    one turn apart.

    Deadlock-freedom rests on how `ToolNode` runs the batch: it submits the calls in
    emission order to a FIFO thread-pool executor, so whenever call *k* is running,
    every earlier call has already been picked up by some worker. The earliest
    unfinished call therefore always holds a worker and can make progress; only
    later-index calls ever wait. The timeout is a fail-closed backstop for executors
    that do not satisfy that property — expiry raises, which aborts the run rather
    than executing out of order.
    """

    def __init__(self, timeout_seconds: float = 30.0) -> None:
        self._condition = Condition()
        self._turn: tuple[str, ...] | None = None
        self._next = 0
        self._timeout = timeout_seconds

    @contextmanager
    def slot(self, order: tuple[str, ...], call_id: str) -> Iterator[None]:
        index = order.index(call_id)
        with self._condition:
            if self._turn != order or self._next >= len(order):
                # First arrival of a new turn (or of a repeat of a finished turn).
                self._turn = order
                self._next = 0
            granted = self._condition.wait_for(
                lambda: self._turn == order and self._next == index,
                timeout=self._timeout,
            )
            if not granted:
                raise ValueError(
                    "CapGate turn sequencing timed out waiting for an earlier tool call; "
                    "failing closed instead of mediating out of order"
                )
        try:
            yield
        finally:
            with self._condition:
                if self._turn == order and self._next == index:
                    self._next += 1
                    self._condition.notify_all()


def to_tool_call_event(
    call: LangGraphToolCall,
    *,
    session_id: str,
    server: str,
    arg_provenance: Mapping[str, str] | None = None,
) -> ToolCallEvent:
    if not call.name or not call.call_id or not session_id or not server:
        raise ValueError("tool call identity fields must be non-empty")
    return ToolCallEvent(
        session_id=session_id,
        server=server,
        tool=call.name,
        arguments=deepcopy(call.args),
        arg_provenance=dict(arg_provenance or {}),
        request_id=call.call_id,
    )


def require_allowed(decision: Decision) -> None:
    if decision.verdict != "ALLOW":
        raise ToolCallRejected(decision)


def interrupt_for_approval(decision: Decision) -> bool:
    """Pause the graph with LangGraph's `interrupt` and return the human's answer.

    Requires a checkpointer on the compiled graph; resume with
    `Command(resume=True)` to approve. Only the exact boolean `True` approves — any other
    resume value, including a truthy string, denies. A human answering an approval prompt
    with something the runtime did not expect must never be read as consent.

    Only bounded decision metadata is surfaced. Raw arguments never reach the prompt,
    because an approval UI is one more place a secret could be copied to.
    """

    from langgraph.types import interrupt

    answer = interrupt(
        {
            "capgate": {
                "verdict": decision.verdict,
                "rule_id": decision.rule_id,
                "reason": decision.reason,
                "labels": sorted(decision.labels),
            }
        }
    )
    return answer is True


def build_secure_tool_node(
    tools: Sequence[BaseTool | Callable[..., Any]],
    *,
    mediator: ToolCallMediator,
    session_id: str,
    label_arguments: Callable[[ToolCallRequest, JsonObject], Mapping[str, Label]],
    server: str = "langgraph",
    approve: Callable[[Decision], bool] | None = None,
) -> ToolNode:
    """Build a LangGraph ToolNode whose labeled calls pass through CapGate.

    Multi-call turns are supported by *serializing* them: each call's mediation waits for
    its slot in the planner's emission order, so every decision sees the taint produced by
    the earlier calls of the same turn. Thread scheduling never becomes a security order.

    ``approve`` resolves `REQUIRE_APPROVAL` verdicts. Pass `interrupt_for_approval` to
    pause the graph for a human, or leave it `None` to keep refusing such calls. A grant
    satisfies only the capability gate; flow rules still run afterwards. Approval pausing
    is offered only in single-call turns — a resumed multi-call turn would re-execute its
    finished siblings — so batched approval-required calls are refused instead.
    """

    try:
        from langchain_core.messages import ToolCall, ToolMessage
        from langgraph.prebuilt import ToolNode
    except ImportError as exc:  # pragma: no cover - exercised by packaging, not this extra
        raise RuntimeError(
            'LangGraph support requires `python -m pip install -e ".[langgraph]"`'
        ) from exc

    if not session_id or not server:
        raise ValueError("LangGraph session and server identity must be non-empty")

    sequencer = _TurnSequencer()

    def wrap_tool_call(
        request: ToolCallRequest,
        execute: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        turn_order = _turn_plan(request)
        call = _from_langgraph_call(request.tool_call)
        if request.tool is not None:
            if _has_injected_arguments(request.tool):
                raise ValueError("CapGate v0.1 does not support injected LangGraph tool arguments")
            call = LangGraphToolCall(
                name=call.name,
                args=_validated_tool_arguments(request.tool, call.args),
                call_id=call.call_id,
            )
        try:
            argument_labels = dict(label_arguments(request, deepcopy(call.args)))
        except Exception:
            raise ValueError("CapGate argument labeling failed closed") from None
        resolved = mediator.resolve_arguments(call.args)
        if resolved.substituted:
            resolved_args = resolved.arguments
            if request.tool is not None:
                # Substitution changes values, so the schema contract is re-checked on
                # what will actually execute. A stored value that does not fit the
                # schema fails closed here, before anything runs.
                resolved_args = _validated_tool_arguments(request.tool, resolved_args)
            call = LangGraphToolCall(
                name=call.name,
                args=resolved_args,
                call_id=call.call_id,
            )
        for name, reference_label in resolved.reference_labels.items():
            # Exact lineage only ever adds to the declared label, never replaces it: a
            # partially composed argument keeps its pessimistic base.
            argument_labels[name] = argument_labels[name].join(reference_label)
        event = to_tool_call_event(
            call,
            session_id=session_id,
            server=server,
            arg_provenance=_argument_provenance(call, server),
        )
        execution_request = request.override(
            tool_call=ToolCall(
                name=call.name,
                args=deepcopy(call.args),
                id=call.call_id,
                type="tool_call",
            )
        )
        # Approval works by suspending the graph, and a resumed multi-call turn would
        # re-run its already-executed siblings — a duplicated side effect. So a pause is
        # only offered in single-call turns; in a batch, approval-required calls are
        # refused outright, which is the fail-closed reading of "nobody could answer".
        effective_approve = approve if len(turn_order) == 1 else None
        with sequencer.slot(turn_order, call.call_id):
            outcome = mediator.mediate(
                event,
                lambda: execute(execution_request),
                result_to_json=lambda result: _langgraph_result_to_json(
                    result,
                    expected_name=call.name,
                    expected_call_id=call.call_id,
                ),
                argument_labels=argument_labels,
                approve=effective_approve,
                result_payload=_langgraph_result_payload,
            )
        if outcome.decision.verdict == "ALLOW":
            if outcome.value is None:
                raise RuntimeError("CapGate allowed a tool call without a result")
            if outcome.reference is not None:
                # Reference-returning tool: the planner receives the opaque token. The
                # raw result was recorded (as a hash) in the signed receipt and stored
                # for later resolution; it must not enter the model's context.
                return ToolMessage(
                    content=outcome.reference,
                    name=call.name,
                    tool_call_id=call.call_id,
                )
            return outcome.value
        return ToolMessage(
            content="CapGate rejected this tool-call outcome.",
            name=call.name,
            tool_call_id=call.call_id,
            status="error",
            artifact={
                "capgate": {
                    "verdict": outcome.decision.verdict,
                    "rule_id": outcome.decision.rule_id,
                    "execution_started": outcome.executed,
                }
            },
        )

    tool_node = ToolNode(
        tools,
        handle_tool_errors=False,
        wrap_tool_call=wrap_tool_call,
    )
    if any(_has_injected_arguments(tool) for tool in tool_node.tools_by_name.values()):
        raise ValueError("CapGate v0.1 does not support injected LangGraph tool arguments")
    return tool_node


def _from_langgraph_call(call: Mapping[str, object]) -> LangGraphToolCall:
    name = call.get("name")
    call_id = call.get("id")
    arguments = call.get("args")
    if not isinstance(name, str) or not name or not isinstance(call_id, str) or not call_id:
        raise ValueError("LangGraph tool call identity fields must be non-empty strings")
    if not isinstance(arguments, Mapping):
        raise ValueError("LangGraph tool call arguments must be a JSON object")
    return LangGraphToolCall(
        name=name,
        args=_json_object(arguments),
        call_id=call_id,
    )


def _langgraph_result_to_json(
    result: ToolMessage | Command[Any],
    *,
    expected_name: str,
    expected_call_id: str,
) -> JsonValue:
    from langchain_core.messages import ToolMessage

    if not isinstance(result, ToolMessage):
        raise ValueError("LangGraph Command results are not supported by CapGate v0.1")
    if result.tool_call_id != expected_call_id:
        raise ValueError("LangGraph ToolMessage call ID does not match the audited call")
    if result.name is not None and result.name != expected_name:
        raise ValueError("LangGraph ToolMessage name does not match the audited tool")
    return _json_value(result.model_dump(mode="json"))


def _langgraph_result_payload(result: ToolMessage | Command[Any]) -> JsonValue:
    """Project the planner-visible content of a result for reference storage.

    Only the content is stored behind a reference — it is what a later argument would
    pass through. The full message envelope stays in the receipt hash as usual.
    """

    from langchain_core.messages import ToolMessage

    if not isinstance(result, ToolMessage):
        raise ValueError("LangGraph Command results are not supported by CapGate v0.1")
    return _json_value(result.content)


def _argument_provenance(call: LangGraphToolCall, server: str) -> dict[str, str]:
    return {
        name: f"{server}:{call.name}:{call.call_id}:argument:{name}"
        for name in call.args
    }


def _turn_plan(request: ToolCallRequest) -> tuple[str, ...]:
    """Return the turn's call IDs in the planner's emission order, validated.

    The order comes from the turn's own `AIMessage` — the one artifact the planner
    actually produced — never from thread scheduling. The current call must appear in it
    exactly once, and every ID in the turn must be a unique non-empty string, because
    these IDs are what the sequencer keys slots on.
    """

    from langchain_core.messages import AIMessage

    state = request.state
    if isinstance(state, Mapping):
        messages = state.get("messages")
    elif isinstance(state, list):
        messages = state
    else:
        messages = None
    if not isinstance(messages, list) or not messages:
        raise ValueError("CapGate v0.1 requires a standard LangGraph messages state")
    last_message = messages[-1]
    if not isinstance(last_message, AIMessage) or not last_message.tool_calls:
        raise ValueError("CapGate requires the turn's tool calls in the last AIMessage")
    order: list[str] = []
    for turn_call in last_message.tool_calls:
        call_id = turn_call.get("id")
        if not isinstance(call_id, str) or not call_id:
            raise ValueError("every LangGraph tool call in a turn needs a non-empty ID")
        order.append(call_id)
    if len(set(order)) != len(order):
        raise ValueError("LangGraph turn contains duplicate tool call IDs")
    current_id = request.tool_call.get("id")
    current_name = request.tool_call.get("name")
    matched = [
        turn_call
        for turn_call in last_message.tool_calls
        if turn_call.get("id") == current_id
    ]
    if len(matched) != 1 or matched[0].get("name") != current_name:
        raise ValueError("LangGraph tool request does not match the current turn")
    return tuple(order)


def _validated_tool_arguments(tool: BaseTool, arguments: JsonObject) -> JsonObject:
    schema = _input_schema(tool)
    normalized = _json_object(schema.model_validate(arguments).model_dump(mode="json"))
    repeated = _json_object(schema.model_validate(normalized).model_dump(mode="json"))
    if repeated != normalized:
        raise ValueError("LangGraph tool argument normalization must be idempotent")
    return normalized


def _has_injected_arguments(tool: BaseTool) -> bool:
    from langgraph.prebuilt.tool_node import _get_all_injected_args

    _input_schema(tool)
    injected = _get_all_injected_args(tool)
    return bool(
        injected.all_injected_keys
        or injected.state
        or injected.store is not None
        or injected.runtime is not None
    )


def _input_schema(tool: BaseTool) -> type[BaseModel]:
    from pydantic import BaseModel
    from pydantic.functional_validators import (
        AfterValidator,
        BeforeValidator,
        PlainValidator,
        WrapValidator,
    )

    schema = tool.get_input_schema()
    if not issubclass(schema, BaseModel):
        raise ValueError("CapGate v0.1 requires a Pydantic v2 LangGraph tool schema")
    decorators = schema.__pydantic_decorators__
    if any(
        (
            decorators.validators,
            decorators.field_validators,
            decorators.root_validators,
            decorators.field_serializers,
            decorators.model_serializers,
            decorators.model_validators,
            decorators.computed_fields,
        )
    ):
        raise ValueError("CapGate v0.1 does not support custom tool schema transforms")
    transform_types = BeforeValidator | AfterValidator | PlainValidator | WrapValidator
    if any(
        isinstance(metadata, transform_types)
        for field in schema.model_fields.values()
        for metadata in field.metadata
    ):
        raise ValueError("CapGate v0.1 does not support custom tool schema transforms")
    return schema


def _json_object(value: Mapping[Any, Any]) -> JsonObject:
    result: JsonObject = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError("LangGraph tool call argument keys must be strings")
        result[key] = _json_value(item)
    return result


def _json_value(value: object) -> JsonValue:
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("LangGraph values must contain only finite JSON numbers")
        return value
    if isinstance(value, Mapping):
        return _json_object(value)
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    raise ValueError("LangGraph values must be JSON-compatible")
