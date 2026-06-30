from __future__ import annotations

from capgate.mcp_security.isolation import (
    CROSS_SERVER_RULE_ID,
    TOOL_SHADOW_RULE_ID,
    UNKNOWN_PROVENANCE_RULE_ID,
    CrossServerGrant,
    CrossServerIsolation,
    ServerToolRegistry,
    ToolIdentity,
)


def _registered_registry() -> ServerToolRegistry:
    registry = ServerToolRegistry()
    assert registry.register(ToolIdentity("calendar", "read_events")).verdict == "ALLOW"
    assert registry.register(ToolIdentity("email", "send_email")).verdict == "ALLOW"
    assert registry.register(ToolIdentity("email", "delete_email")).verdict == "ALLOW"
    return registry


def test_duplicate_tool_name_on_distinct_server_is_blocked_as_shadow() -> None:
    registry = ServerToolRegistry()
    assert registry.register(ToolIdentity("trusted", "send_email")).verdict == "ALLOW"

    decision = registry.register(ToolIdentity("untrusted", "send_email"))

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == TOOL_SHADOW_RULE_ID
    assert not registry.contains(ToolIdentity("untrusted", "send_email"))


def test_same_server_may_register_same_tool_name_again() -> None:
    registry = ServerToolRegistry()
    tool = ToolIdentity("email", "send_email")

    assert registry.register(tool).verdict == "ALLOW"
    assert registry.register(tool).verdict == "ALLOW"
    assert registry.contains(tool)


def test_cross_server_provenance_is_denied_by_default() -> None:
    isolation = CrossServerIsolation(_registered_registry())

    decision = isolation.check(
        frozenset({"calendar"}),
        ToolIdentity("email", "send_email"),
    )

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == CROSS_SERVER_RULE_ID


def test_same_server_provenance_is_allowed() -> None:
    isolation = CrossServerIsolation(_registered_registry())

    decision = isolation.check(
        frozenset({"email"}),
        ToolIdentity("email", "send_email"),
    )

    assert decision.verdict == "ALLOW"


def test_exact_allowlisted_source_and_target_pair_is_allowed() -> None:
    target = ToolIdentity("email", "send_email")
    isolation = CrossServerIsolation(
        _registered_registry(),
        grants=frozenset({CrossServerGrant("calendar", target)}),
    )

    assert isolation.check(frozenset({"calendar"}), target).verdict == "ALLOW"
    assert (
        isolation.check(
            frozenset({"calendar"}),
            ToolIdentity("email", "delete_email"),
        ).verdict
        == "BLOCK"
    )


def test_unknown_or_missing_provenance_fails_closed() -> None:
    isolation = CrossServerIsolation(_registered_registry())
    target = ToolIdentity("email", "send_email")

    for sources in (frozenset(), frozenset({"not-registered"})):
        decision = isolation.check(sources, target)
        assert decision.verdict == "BLOCK"
        assert decision.rule_id == UNKNOWN_PROVENANCE_RULE_ID
