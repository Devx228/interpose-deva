from __future__ import annotations

from collections.abc import Iterable

from capgate.engine.decision import Decision, Verdict
from capgate.policy.model import Capability, CapabilityPattern, Policy


def enforce(policy: Policy, capability: str | Capability) -> Decision:
    requested = Capability.parse(capability) if isinstance(capability, str) else capability
    rules: tuple[tuple[str, tuple[CapabilityPattern, ...], Verdict], ...] = (
        ("cannot", policy.cannot, "BLOCK"),
        ("requires_approval", policy.requires_approval, "REQUIRE_APPROVAL"),
        ("can", policy.can, "ALLOW"),
    )
    for effect, patterns, verdict in rules:
        matched = _first_match(patterns, requested)
        if matched is not None:
            return Decision(
                verdict=verdict,
                reason=(
                    f"agent {policy.agent!r} matched {effect} rule {str(matched)!r} "
                    f"for {str(requested)!r}"
                ),
                rule_id=f"policy.{effect}.{matched}",
                labels=frozenset(),
            )
    return Decision(
        verdict="BLOCK",
        reason=f"agent {policy.agent!r} has no rule permitting {str(requested)!r}",
        rule_id="policy.default_deny",
        labels=frozenset(),
    )


def _first_match(
    patterns: Iterable[CapabilityPattern], capability: Capability
) -> CapabilityPattern | None:
    return next((pattern for pattern in patterns if pattern.matches(capability)), None)
