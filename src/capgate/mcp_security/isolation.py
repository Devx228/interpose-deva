from __future__ import annotations

from dataclasses import dataclass

from capgate.engine.decision import Decision

TOOL_SHADOW_RULE_ID = "mcp.tool_shadow"
CROSS_SERVER_RULE_ID = "mcp.cross_server_provenance"
UNKNOWN_PROVENANCE_RULE_ID = "mcp.unknown_provenance"
UNKNOWN_TARGET_RULE_ID = "mcp.unknown_target"


@dataclass(frozen=True, order=True)
class ToolIdentity:
    server: str
    tool: str


@dataclass(frozen=True)
class CrossServerGrant:
    source_server: str
    target: ToolIdentity


class ServerToolRegistry:
    """Track tool ownership and reject names shadowed by another MCP server."""

    def __init__(self) -> None:
        self._tools_by_server: dict[str, set[str]] = {}
        self._owner_by_tool: dict[str, str] = {}

    def register(self, identity: ToolIdentity) -> Decision:
        owner = self._owner_by_tool.get(identity.tool)
        if owner is not None and owner != identity.server:
            return Decision(
                verdict="BLOCK",
                reason=(
                    f"tool name {identity.tool!r} is already registered by server {owner!r}"
                ),
                rule_id=TOOL_SHADOW_RULE_ID,
                labels=frozenset(),
            )

        self._owner_by_tool[identity.tool] = identity.server
        self._tools_by_server.setdefault(identity.server, set()).add(identity.tool)
        return Decision(
            verdict="ALLOW",
            reason="tool name is unique across registered MCP servers",
            rule_id=None,
            labels=frozenset(),
        )

    def has_server(self, server: str) -> bool:
        return server in self._tools_by_server

    def contains(self, identity: ToolIdentity) -> bool:
        return identity.tool in self._tools_by_server.get(identity.server, set())


class CrossServerIsolation:
    """Authorize provenance flow into an exact target server and tool."""

    def __init__(
        self,
        registry: ServerToolRegistry,
        grants: frozenset[CrossServerGrant] = frozenset(),
    ) -> None:
        self._registry = registry
        self._grants = grants

    def check(
        self,
        source_servers: frozenset[str],
        target: ToolIdentity,
    ) -> Decision:
        if not self._registry.contains(target):
            return Decision(
                verdict="BLOCK",
                reason="target server/tool is not registered",
                rule_id=UNKNOWN_TARGET_RULE_ID,
                labels=frozenset(),
            )

        unknown_sources = sorted(
            source for source in source_servers if not self._registry.has_server(source)
        )
        if not source_servers or unknown_sources:
            return Decision(
                verdict="BLOCK",
                reason="provenance source server is missing or unknown",
                rule_id=UNKNOWN_PROVENANCE_RULE_ID,
                labels=frozenset(),
            )

        denied_sources = sorted(
            source
            for source in source_servers
            if source != target.server
            and CrossServerGrant(source_server=source, target=target) not in self._grants
        )
        if denied_sources:
            return Decision(
                verdict="BLOCK",
                reason="cross-server provenance is not allowlisted for the target tool",
                rule_id=CROSS_SERVER_RULE_ID,
                labels=frozenset(),
            )

        return Decision(
            verdict="ALLOW",
            reason="provenance is same-server or exactly allowlisted",
            rule_id=None,
            labels=frozenset(),
        )
