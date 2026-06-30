from __future__ import annotations

from pathlib import Path

import pytest

from capgate.policy import (
    PolicyError,
    enforce,
    is_monotonic_narrowing,
    load_policy,
    parse_policy,
)


def _policy(**overrides: list[str]) -> str:
    values = {
        "can": ["read:docs.*"],
        "cannot": ["read:docs.secret"],
        "requires_approval": ["read:docs.internal"],
        **overrides,
    }
    lines = ["agent: test-agent"]
    for field in ("can", "cannot", "requires_approval"):
        if values[field]:
            lines.append(f"{field}:")
            lines.extend(f"  - {item}" for item in values[field])
        else:
            lines.append(f"{field}: []")
    return "\n".join(lines)


def test_parser_builds_immutable_typed_policy() -> None:
    policy = parse_policy(_policy())

    assert policy.agent == "test-agent"
    assert str(policy.can[0]) == "read:docs.*"
    with pytest.raises(AttributeError):
        policy.agent = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    "text",
    [
        "- not-a-policy",
        "agent: test\ncan: read:web",
        "agent: test\nunknown: []",
        "agent: test\ncan: [missing_separator]",
        "agent: test\ncan: [read:web:extra]",
        "agent: test\ncan: [READ:web]",
    ],
)
def test_malformed_policy_raises(text: str) -> None:
    with pytest.raises(PolicyError):
        parse_policy(text)


def test_precedence_is_cannot_then_approval_then_can() -> None:
    policy = parse_policy(_policy())

    assert enforce(policy, "read:docs.secret").verdict == "BLOCK"
    assert enforce(policy, "read:docs.internal").verdict == "REQUIRE_APPROVAL"
    assert enforce(policy, "read:docs.public").verdict == "ALLOW"


def test_resource_glob_and_exact_action_matching() -> None:
    policy = parse_policy(_policy())

    assert enforce(policy, "read:docs.public").verdict == "ALLOW"
    assert enforce(policy, "write:docs.public").verdict == "BLOCK"


def test_default_deny_has_stable_human_readable_decision() -> None:
    decision = enforce(parse_policy(_policy()), "send:email.external")

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == "policy.default_deny"
    assert "no rule permitting" in decision.reason


def test_approval_decision_identifies_matching_rule() -> None:
    decision = enforce(parse_policy(_policy()), "read:docs.internal")

    assert decision.verdict == "REQUIRE_APPROVAL"
    assert decision.rule_id == "policy.requires_approval.read:docs.internal"
    assert "requires_approval rule" in decision.reason


def test_confinement_accepts_narrower_allow_and_stronger_deny() -> None:
    current = parse_policy(_policy(cannot=["read:docs.secret"]))
    proposed = parse_policy(
        _policy(
            can=["read:docs.public.*"],
            cannot=["read:docs.*"],
            requires_approval=["read:docs.team"],
        )
    )

    assert is_monotonic_narrowing(current, proposed)


@pytest.mark.parametrize(
    "proposed",
    [
        _policy(can=["read:*"]),
        _policy(requires_approval=["send:email.external"]),
        _policy(cannot=[]),
        _policy(can=["read:docs.*"], requires_approval=[], cannot=[]),
    ],
)
def test_confinement_rejects_expansion_or_weakened_deny(proposed: str) -> None:
    assert not is_monotonic_narrowing(parse_policy(_policy()), parse_policy(proposed))


def test_all_policy_templates_parse() -> None:
    templates = Path("src/capgate/policy/templates")

    policies = [load_policy(path) for path in sorted(templates.glob("*.yaml"))]

    assert [policy.agent for policy in policies] == [
        "coding-agent",
        "email-agent",
        "research-agent",
    ]
