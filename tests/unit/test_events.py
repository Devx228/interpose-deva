from __future__ import annotations

from capgate.proxy.events import (
    JsonObject,
    tool_call_event_from_message,
    tool_result_event_from_response,
)


def test_tool_call_event_extracts_tool_and_arguments() -> None:
    message: JsonObject = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "search", "arguments": {"query": "capabilities"}},
    }

    event = tool_call_event_from_message(
        session_id="session-1",
        server="test-server",
        message=message,
    )

    assert event.session_id == "session-1"
    assert event.server == "test-server"
    assert event.tool == "search"
    assert event.arguments == {"query": "capabilities"}
    assert event.request_id == 7


def test_tool_result_event_uses_error_as_result_when_present() -> None:
    call_message: JsonObject = {
        "jsonrpc": "2.0",
        "id": "abc",
        "method": "tools/call",
        "params": {"name": "search", "arguments": {}},
    }
    call_event = tool_call_event_from_message(
        session_id="session-1",
        server="test-server",
        message=call_message,
    )
    response: JsonObject = {
        "jsonrpc": "2.0",
        "id": "abc",
        "error": {"code": -32000, "message": "failed"},
    }

    result_event = tool_result_event_from_response(call_event=call_event, response=response)

    assert result_event.result == {"error": {"code": -32000, "message": "failed"}}
