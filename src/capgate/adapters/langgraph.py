from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass

from capgate.engine.decision import Decision
from capgate.proxy.events import JsonObject, ToolCallEvent


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
