from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TypeAlias

JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)
JsonObject: TypeAlias = dict[str, JsonValue]

_CONTROL_REQUESTS = frozenset({"initialize", "logging/setLevel", "ping"})
_CONTROL_NOTIFICATIONS = frozenset(
    {
        "notifications/cancelled",
        "notifications/initialized",
        "notifications/progress",
        "notifications/roots/list_changed",
    }
)
_LOG_LEVELS = frozenset(
    {"debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"}
)


@dataclass(frozen=True)
class ToolListEvent:
    session_id: str
    server: str
    arguments: JsonObject
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
    _validate_request(message, "tools/list")
    arguments = message.get("params", {})
    if not isinstance(arguments, dict):
        raise ValueError("tools/list params must be an object")
    if set(arguments) - {"cursor"}:
        raise ValueError("tools/list params contain unsupported fields")
    cursor = arguments.get("cursor")
    if cursor is not None and not isinstance(cursor, str):
        raise ValueError("tools/list cursor must be a string")
    return ToolListEvent(
        session_id=session_id,
        server=server,
        arguments=arguments,
        request_id=message["id"],
    )


def tool_call_event_from_message(
    *,
    session_id: str,
    server: str,
    message: JsonObject,
) -> ToolCallEvent:
    _validate_request(message, "tools/call")
    params = message.get("params")
    if not isinstance(params, dict):
        raise ValueError("tools/call params must be an object")
    if set(params) - {"name", "arguments"}:
        raise ValueError("tools/call params contain unsupported fields")
    tool = params.get("name")
    if not isinstance(tool, str) or not tool.strip():
        raise ValueError("tools/call name must be a non-empty string")
    arguments = params.get("arguments", {})
    if not isinstance(arguments, dict):
        raise ValueError("tools/call arguments must be an object")
    return ToolCallEvent(
        session_id=session_id,
        server=server,
        tool=tool,
        arguments=arguments,
        arg_provenance={},
        request_id=message["id"],
    )


def tool_result_event_from_response(
    *,
    call_event: ToolCallEvent,
    response: JsonObject,
) -> ToolResultEvent:
    validate_jsonrpc_response(response, call_event.request_id)
    result = response["result"] if "result" in response else {"error": response.get("error")}
    return ToolResultEvent(
        session_id=call_event.session_id,
        server=call_event.server,
        tool=call_event.tool,
        result=result,
        request_id=call_event.request_id,
    )


def validate_jsonrpc_response(response: JsonObject, request_id: JsonValue) -> None:
    if response.get("jsonrpc") != "2.0":
        raise ValueError("downstream response has an invalid JSON-RPC version")
    response_id = response.get("id")
    if type(response_id) is not type(request_id) or response_id != request_id:
        raise ValueError("downstream response ID does not match the request")
    has_result = "result" in response
    has_error = "error" in response
    if has_result == has_error:
        raise ValueError("downstream response must contain exactly one of result or error")
    payload_field = "result" if has_result else "error"
    if set(response) != {"jsonrpc", "id", payload_field}:
        raise ValueError("downstream response contains unsupported fields")
    if has_error and not isinstance(response["error"], dict):
        raise ValueError("downstream response error must be an object")


def validate_control_message(message: JsonObject) -> None:
    method = message.get("method")
    if not isinstance(method, str) or method not in (
        _CONTROL_REQUESTS | _CONTROL_NOTIFICATIONS
    ):
        raise ValueError("control message method is unsupported")
    if message.get("jsonrpc") != "2.0":
        raise ValueError("control message has an invalid JSON-RPC version")

    required_fields = {"jsonrpc", "method"}
    if method in _CONTROL_REQUESTS:
        required_fields.add("id")
        if "id" not in message or not _is_mcp_request_id(message["id"]):
            raise ValueError("control request ID is missing or invalid")
    if required_fields - set(message) or set(message) - (required_fields | {"params"}):
        raise ValueError("control message fields do not match the supported schema")

    params_value = message.get("params")
    if "params" in message and not isinstance(params_value, dict):
        raise ValueError("control message params must be an object")
    params: JsonObject = params_value if isinstance(params_value, dict) else {}
    if "_meta" in params and not isinstance(params["_meta"], dict):
        raise ValueError("control message _meta must be an object")

    if method == "initialize":
        _validate_initialize_params(message, params)
    elif method == "logging/setLevel":
        _validate_logging_params(message, params)
    elif method == "notifications/cancelled":
        _validate_cancelled_params(message, params)
    elif method == "notifications/progress":
        _validate_progress_params(message, params)


def _validate_initialize_params(message: JsonObject, params: JsonObject) -> None:
    if "params" not in message:
        raise ValueError("initialize params are required")
    protocol_version = params.get("protocolVersion")
    capabilities = params.get("capabilities")
    client_info = params.get("clientInfo")
    if not isinstance(protocol_version, str) or not protocol_version:
        raise ValueError("initialize protocolVersion must be a non-empty string")
    if not isinstance(capabilities, dict):
        raise ValueError("initialize capabilities must be an object")
    if not isinstance(client_info, dict):
        raise ValueError("initialize clientInfo must be an object")
    for field in ("name", "version"):
        value = client_info.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"initialize clientInfo {field} must be a non-empty string")
    if "title" in client_info and not isinstance(client_info["title"], str):
        raise ValueError("initialize clientInfo title must be a string")


def _validate_logging_params(message: JsonObject, params: JsonObject) -> None:
    if "params" not in message or params.get("level") not in _LOG_LEVELS:
        raise ValueError("logging/setLevel requires a supported level")


def _validate_cancelled_params(message: JsonObject, params: JsonObject) -> None:
    if "params" not in message or not _is_mcp_request_id(params.get("requestId")):
        raise ValueError("notifications/cancelled requires a valid requestId")
    if "reason" in params and not isinstance(params["reason"], str):
        raise ValueError("notifications/cancelled reason must be a string")


def _validate_progress_params(message: JsonObject, params: JsonObject) -> None:
    if "params" not in message or not _is_mcp_request_id(params.get("progressToken")):
        raise ValueError("notifications/progress requires a valid progressToken")
    if not _is_finite_number(params.get("progress")):
        raise ValueError("notifications/progress requires finite progress")
    if "total" in params and not _is_finite_number(params["total"]):
        raise ValueError("notifications/progress total must be finite")
    if "message" in params and not isinstance(params["message"], str):
        raise ValueError("notifications/progress message must be a string")


def _validate_request(message: JsonObject, method: str) -> None:
    if message.get("jsonrpc") != "2.0" or message.get("method") != method:
        raise ValueError("tool request has an invalid JSON-RPC envelope")
    required_fields = {"jsonrpc", "id", "method"}
    if required_fields - set(message) or set(message) - (required_fields | {"params"}):
        raise ValueError("tool request fields do not match the supported schema")
    if "id" not in message or not _is_request_id(message["id"]):
        raise ValueError("tool request ID is missing or invalid")


def _is_request_id(value: JsonValue) -> bool:
    if value is None or isinstance(value, str):
        return True
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value)


def _is_mcp_request_id(value: JsonValue) -> bool:
    return value is not None and _is_request_id(value)


def _is_finite_number(value: JsonValue) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value)
