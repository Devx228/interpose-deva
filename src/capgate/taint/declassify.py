"""Audited, bandwidth-bounded declassification — the only way a label moves down.

Monotonic joins remain the rule everywhere else. A tool may lower its result's label only
through an explicit :class:`DeclassificationSpec` in its trusted metadata: the exact output
fields, each with a **closed domain** (bool, bounded int, string enum). The runtime
validates the tool's actual output against that spec; a conforming extraction carries the
declared lower label, and everything else is a hard failure — never a silent fallback to
the conservative label, because a nonconforming extraction is a quarantine escape attempt
and must not reach the planner at all.

The security accounting: an attacker who controls the extracted-from content can choose
*which* in-domain value each field takes, and nothing else. The channel they get is at most
``sum(log2(|domain|))`` bits per call — computed here and recorded in the signed receipt by
the caller. No free-length strings, ever: an unbounded field would make that number
fiction.

See ``docs/design-notes/DECLASSIFICATION.md`` for the reasoning and the stated residual
(k bits of steering is still k bits of steering).
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field

from capgate.taint.labels import Label


class DeclassificationError(ValueError):
    """The tool's output does not conform to its declared declassification spec."""


@dataclass(frozen=True)
class BoolField:
    """A single yes/no fact: exactly one bit."""

    def bits(self) -> float:
        return 1.0

    def contains(self, value: object) -> bool:
        return isinstance(value, bool)

    def describe(self) -> str:
        return "bool"


@dataclass(frozen=True)
class IntRangeField:
    """An integer in a closed range, ``minimum..maximum`` inclusive."""

    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        if self.minimum > self.maximum:
            raise ValueError("declassification int range must have minimum <= maximum")

    def bits(self) -> float:
        return math.log2(self.maximum - self.minimum + 1)

    def contains(self, value: object) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and self.minimum <= value <= self.maximum
        )

    def describe(self) -> str:
        return f"int[{self.minimum}..{self.maximum}]"


@dataclass(frozen=True)
class EnumField:
    """One string out of a closed, declared set. Never a free-form string."""

    values: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.values:
            raise ValueError("declassification enum must declare at least one value")

    def bits(self) -> float:
        return math.log2(len(self.values))

    def contains(self, value: object) -> bool:
        return isinstance(value, str) and value in self.values

    def describe(self) -> str:
        return f"enum[{len(self.values)}]"


FieldDomain = BoolField | IntRangeField | EnumField


@dataclass(frozen=True)
class DeclassificationSpec:
    """The declared shape a tool's output must take to earn the lower label."""

    fields: Mapping[str, FieldDomain]
    output_label: Label

    def __post_init__(self) -> None:
        if not self.fields:
            raise ValueError("a declassification spec must declare at least one field")

    def released_bits(self) -> float:
        """Upper bound on attacker-choosable information per conforming call."""

        return sum(domain.bits() for domain in self.fields.values())

    def validate(self, payload: object) -> float:
        """Check one actual output against the spec; return the released bits.

        Accepts the parsed JSON object or a JSON string encoding one — tool contents cross
        the boundary as text. Field set equality is required: a missing field, an extra
        field, or any out-of-domain value raises :class:`DeclassificationError`. Callers
        must treat that as a BLOCK of the result, not as "use the conservative label" —
        the planner never sees a nonconforming extraction.
        """

        data = _parse_payload(payload)
        declared = set(self.fields)
        actual = set(data)
        if actual != declared:
            raise DeclassificationError(
                "declassification output fields do not match the declared spec"
            )
        for name, domain in self.fields.items():
            if not domain.contains(data[name]):
                raise DeclassificationError(
                    f"declassification field is outside its declared domain: "
                    f"{name} ({domain.describe()})"
                )
        return self.released_bits()


def _parse_payload(payload: object) -> dict[str, object]:
    candidate: object = payload
    if isinstance(candidate, str):
        try:
            candidate = json.loads(candidate)
        except ValueError:
            raise DeclassificationError(
                "declassification output is not a JSON object"
            ) from None
    if not isinstance(candidate, dict) or any(
        not isinstance(key, str) for key in candidate
    ):
        raise DeclassificationError("declassification output must be a JSON object")
    return {str(key): value for key, value in candidate.items()}
