from __future__ import annotations

import pytest

from capgate.adapters.langgraph import (
    LangGraphToolCall,
    ToolCallRejected,
    require_allowed,
    to_tool_call_event,
)
from capgate.engine.decision import Decision
from capgate.proxy.events import JsonObject


def _decision(verdict: str) -> Decision:
    if verdict == "ALLOW":
        return Decision("ALLOW", "allowed", None, frozenset())
    if verdict == "BLOCK":
        return Decision("BLOCK", "blocked safely", "test.block", frozenset())
    return Decision(
        "REQUIRE_APPROVAL",
        "approval required",
        "test.approval",
        frozenset(),
    )


def test_langgraph_call_maps_exactly_and_copies_mutable_inputs() -> None:
    arguments: JsonObject = {"query": {"text": "hello"}}
    provenance = {"query": "server:source:1"}

    event = to_tool_call_event(
        LangGraphToolCall(name="search", args=arguments, call_id="call-1"),
        session_id="session-1",
        server="langgraph",
        arg_provenance=provenance,
    )
    nested = arguments["query"]
    assert isinstance(nested, dict)
    nested["text"] = "changed"
    provenance["query"] = "changed"

    assert event.session_id == "session-1"
    assert event.server == "langgraph"
    assert event.tool == "search"
    assert event.request_id == "call-1"
    assert event.arguments == {"query": {"text": "hello"}}
    assert event.arg_provenance == {"query": "server:source:1"}


def test_require_allowed_accepts_allow() -> None:
    require_allowed(_decision("ALLOW"))


@pytest.mark.parametrize("verdict", ["BLOCK", "REQUIRE_APPROVAL"])
def test_require_allowed_rejects_every_non_allow_verdict(verdict: str) -> None:
    decision = _decision(verdict)

    with pytest.raises(ToolCallRejected) as raised:
        require_allowed(decision)

    assert raised.value.decision is decision
    assert str(raised.value) == decision.reason


@pytest.mark.parametrize("field", ["name", "call_id", "session_id", "server"])
def test_translation_rejects_missing_identity(field: str) -> None:
    values = {
        "name": "search",
        "call_id": "call-1",
        "session_id": "session-1",
        "server": "langgraph",
    }
    values[field] = ""

    with pytest.raises(ValueError, match="identity fields"):
        to_tool_call_event(
            LangGraphToolCall(
                name=values["name"],
                args={},
                call_id=values["call_id"],
            ),
            session_id=values["session_id"],
            server=values["server"],
        )
