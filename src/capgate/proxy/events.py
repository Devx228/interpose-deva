from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias

JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)
JsonObject: TypeAlias = dict[str, JsonValue]


@dataclass(frozen=True)
class ToolListEvent:
    session_id: str
    server: str
    request_id: JsonValue


@dataclass(frozen=True)
class ToolCallEvent:
    session_id: str
    server: str
    tool: str
    arguments: JsonObject
    arg_provenance: dict[str, str]
    request_id: JsonValue


@dataclass(frozen=True)
class ToolResultEvent:
    session_id: str
    server: str
    tool: str
    result: JsonValue
    request_id: JsonValue


def ensure_json_object(value: JsonValue) -> JsonObject:
    if isinstance(value, dict):
        return value
    return {}


def is_tool_list(message: JsonObject) -> bool:
    return message.get("method") == "tools/list"


def is_tool_call(message: JsonObject) -> bool:
    return message.get("method") == "tools/call"


def tool_list_event_from_message(
    *,
    session_id: str,
    server: str,
    message: JsonObject,
) -> ToolListEvent:
    return ToolListEvent(
        session_id=session_id,
        server=server,
        request_id=message.get("id"),
    )


def tool_call_event_from_message(
    *,
    session_id: str,
    server: str,
    message: JsonObject,
) -> ToolCallEvent:
    params = ensure_json_object(message.get("params"))
    arguments = ensure_json_object(params.get("arguments"))
    tool = params.get("name")
    if not isinstance(tool, str):
        tool = "<unknown>"
    return ToolCallEvent(
        session_id=session_id,
        server=server,
        tool=tool,
        arguments=arguments,
        arg_provenance={},
        request_id=message.get("id"),
    )


def tool_result_event_from_response(
    *,
    call_event: ToolCallEvent,
    response: JsonObject,
) -> ToolResultEvent:
    result = response["result"] if "result" in response else {"error": response.get("error")}
    return ToolResultEvent(
        session_id=call_event.session_id,
        server=call_event.server,
        tool=call_event.tool,
        result=result,
        request_id=call_event.request_id,
    )
