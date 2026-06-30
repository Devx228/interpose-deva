from __future__ import annotations

import math
from collections.abc import Mapping

from capgate.engine.decision import Decision
from capgate.mcp_security.store import PinStatus, PinStoreError, ToolPinStore
from capgate.receipts.model import canonical_json_bytes, sha256_bytes

PIN_CHANGED_RULE_ID = "mcp.tool_definition_changed"
PIN_INVALID_RULE_ID = "mcp.tool_definition_invalid"
PIN_STORE_ERROR_RULE_ID = "mcp.tool_pin_store_error"


def hash_tool_definition(definition: Mapping[str, object]) -> str:
    """Return a deterministic hash of security-relevant MCP tool metadata."""
    name, description, input_schema = _validated_components(definition)
    return sha256_bytes(
        canonical_json_bytes(
            {
                "description": description,
                "inputSchema": input_schema,
                "name": name,
            }
        )
    )


class ToolPinRegistry:
    """Keep first-seen MCP tool-definition hashes for the life of this process."""

    def __init__(self, store: ToolPinStore | None = None) -> None:
        self._pins: dict[tuple[str, str], str] = {}
        self._store = store

    def check(self, server: str, definition: Mapping[str, object]) -> Decision:
        if not server.strip():
            return _invalid_definition_decision()

        try:
            name, _, _ = _validated_components(definition)
            observed_hash = hash_tool_definition(definition)
        except (RecursionError, TypeError, ValueError):
            return _invalid_definition_decision()

        key = (server, name)
        if self._store is not None:
            try:
                check = self._store.check_and_pin(server, name, observed_hash)
            except PinStoreError:
                return Decision(
                    verdict="BLOCK",
                    reason="tool pin persistence is unavailable",
                    rule_id=PIN_STORE_ERROR_RULE_ID,
                    labels=frozenset(),
                )
            self._pins[key] = check.pinned_hash
            if check.status is PinStatus.CHANGED:
                return _changed_definition_decision(check.pinned_hash)
            action = "pinned" if check.status is PinStatus.NEW else "matches pinned hash"
            return Decision(
                verdict="ALLOW",
                reason=f"tool definition {action} {check.pinned_hash}",
                rule_id=None,
                labels=frozenset(),
            )

        pinned_hash = self._pins.get(key)
        if pinned_hash is None:
            self._pins[key] = observed_hash
            return Decision(
                verdict="ALLOW",
                reason=f"tool definition pinned at {observed_hash}",
                rule_id=None,
                labels=frozenset(),
            )
        if pinned_hash == observed_hash:
            return Decision(
                verdict="ALLOW",
                reason=f"tool definition matches pinned hash {pinned_hash}",
                rule_id=None,
                labels=frozenset(),
            )
        return _changed_definition_decision(pinned_hash)

    def pinned_hash(self, server: str, tool: str) -> str | None:
        if self._store is not None:
            try:
                return self._store.get(server, tool)
            except PinStoreError:
                return None
        return self._pins.get((server, tool))


def _validated_components(
    definition: Mapping[str, object],
) -> tuple[str, str, dict[str, object]]:
    name = definition.get("name")
    description = definition.get("description", "")
    input_schema = definition.get("inputSchema")

    if not isinstance(name, str) or not name.strip():
        raise ValueError("tool name must be a non-empty string")
    if not isinstance(description, str):
        raise ValueError("tool description must be a string")
    if not isinstance(input_schema, dict) or not _is_json_value(input_schema):
        raise ValueError("tool inputSchema must be a JSON object")

    return name, description, input_schema


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


def _invalid_definition_decision() -> Decision:
    return Decision(
        verdict="BLOCK",
        reason="tool definition is malformed",
        rule_id=PIN_INVALID_RULE_ID,
        labels=frozenset(),
    )


def _changed_definition_decision(pinned_hash: str) -> Decision:
    return Decision(
        verdict="BLOCK",
        reason=f"tool definition differs from pinned hash {pinned_hash}",
        rule_id=PIN_CHANGED_RULE_ID,
        labels=frozenset(),
    )
