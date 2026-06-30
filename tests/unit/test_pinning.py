from __future__ import annotations

import pytest

from capgate.mcp_security.pinning import (
    PIN_CHANGED_RULE_ID,
    PIN_INVALID_RULE_ID,
    ToolPinRegistry,
    hash_tool_definition,
)

_DEFAULT_SCHEMA = object()


def test_tool_hash_is_stable_across_schema_key_order() -> None:
    left = _definition(
        schema={
            "type": "object",
            "properties": {"recipient": {"type": "string"}, "body": {"type": "string"}},
        }
    )
    right = _definition(
        schema={
            "properties": {"body": {"type": "string"}, "recipient": {"type": "string"}},
            "type": "object",
        }
    )

    assert hash_tool_definition(left) == hash_tool_definition(right)


def test_first_seen_definition_is_pinned_and_allowed() -> None:
    registry = ToolPinRegistry()
    definition = _definition()

    decision = registry.check("mail-server", definition)

    assert decision.verdict == "ALLOW"
    assert registry.pinned_hash("mail-server", "send_message") == hash_tool_definition(definition)


def test_unchanged_definition_is_allowed() -> None:
    registry = ToolPinRegistry()
    definition = _definition()
    registry.check("mail-server", definition)

    decision = registry.check("mail-server", definition)

    assert decision.verdict == "ALLOW"


def test_changed_definition_is_blocked_without_leaking_definition() -> None:
    registry = ToolPinRegistry()
    original = _definition(description="Send an approved message")
    registry.check("mail-server", original)
    changed = _definition(description="SECRET RUG PULL INSTRUCTIONS")

    decision = registry.check("mail-server", changed)

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == PIN_CHANGED_RULE_ID
    assert "SECRET RUG PULL INSTRUCTIONS" not in decision.reason
    assert registry.pinned_hash("mail-server", "send_message") == hash_tool_definition(original)


def test_pins_are_isolated_by_server() -> None:
    registry = ToolPinRegistry()
    registry.check("trusted-server", _definition(description="Trusted definition"))

    other_server_decision = registry.check(
        "other-server",
        _definition(description="Different server definition"),
    )

    assert other_server_decision.verdict == "ALLOW"


@pytest.mark.parametrize("schema", [None, [], "not-a-schema"])
def test_malformed_schema_fails_closed(schema: object) -> None:
    registry = ToolPinRegistry()

    decision = registry.check("mail-server", _definition(schema=schema))

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == PIN_INVALID_RULE_ID
    assert registry.pinned_hash("mail-server", "send_message") is None


def _definition(
    *,
    description: str = "Send a message",
    schema: object = _DEFAULT_SCHEMA,
) -> dict[str, object]:
    if schema is _DEFAULT_SCHEMA:
        schema = {
            "type": "object",
            "properties": {"recipient": {"type": "string"}},
        }
    return {
        "name": "send_message",
        "description": description,
        "inputSchema": schema,
    }
