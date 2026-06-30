from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Verdict = Literal["ALLOW", "BLOCK", "REQUIRE_APPROVAL"]


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    rule_id: str | None
    labels: frozenset[str]


STAGE0_ALLOW = Decision(
    verdict="ALLOW",
    reason="passthrough (stage0)",
    rule_id=None,
    labels=frozenset(),
)
