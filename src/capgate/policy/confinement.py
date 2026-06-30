from __future__ import annotations

from collections.abc import Iterable

from capgate.policy.model import CapabilityPattern, Policy


def is_monotonic_narrowing(current: Policy, proposed: Policy) -> bool:
    """Return whether ``proposed`` can be applied without human approval."""
    if current.agent != proposed.agent:
        return False
    return (
        _all_covered(proposed.can, current.can)
        and _all_covered(
            proposed.requires_approval, current.can + current.requires_approval
        )
        and _all_covered(current.cannot, proposed.cannot)
    )


def _all_covered(
    required: Iterable[CapabilityPattern], covering: Iterable[CapabilityPattern]
) -> bool:
    candidates = tuple(covering)
    return all(any(item.is_subset_of(candidate) for candidate in candidates) for item in required)
