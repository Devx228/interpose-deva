from __future__ import annotations

import pytest

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


@pytest.mark.parametrize(
    "message",
    [
        {"jsonrpc": "2.0", "method": "tools/call", "params": {}},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": []},
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "", "arguments": {}},
        },
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "search", "arguments": ["not-an-object"]},
        },
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "search", "arguments": {}, "untracked": "value"},
        },
    ],
)
def test_tool_call_event_rejects_malformed_requests(message: JsonObject) -> None:
    with pytest.raises(ValueError):
        tool_call_event_from_message(
            session_id="session-1",
            server="test-server",
            message=message,
        )


@pytest.mark.parametrize(
    "response",
    [
        {"jsonrpc": "1.0", "id": 1, "result": {}},
        {"jsonrpc": "2.0", "id": 2, "result": {}},
        {"jsonrpc": "2.0", "id": 1},
        {"jsonrpc": "2.0", "id": 1, "result": {}, "error": {}},
        {"jsonrpc": "2.0", "id": 1, "error": "not-an-object"},
        {"jsonrpc": "2.0", "id": 1, "result": {}, "params": {"untracked": True}},
    ],
)
def test_tool_result_event_rejects_malformed_responses(response: JsonObject) -> None:
    call_event = tool_call_event_from_message(
        session_id="session-1",
        server="test-server",
        message={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "search", "arguments": {}},
        },
    )

    with pytest.raises(ValueError):
        tool_result_event_from_response(call_event=call_event, response=response)
