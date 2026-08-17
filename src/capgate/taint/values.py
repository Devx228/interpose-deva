"""Opaque references to labelled values — step 1 of value-level provenance.

Session-wide influence is safe and blunt: one untrusted read marks everything after it, so a
call is judged on everything the session has ever seen rather than on the data actually
feeding it. See `docs/design-notes/VALUE_LEVEL_PROVENANCE.md` for why content matching was
rejected as a way out, and why references were chosen instead.

A tool result can be stored here and handed to the planner as an opaque token. When that token
later appears in an argument, the exact label of the value it names is recovered — lineage
carried structurally, outside the model, where no rewording or re-encoding can launder it.

Two properties do the security work:

**References are unforgeable from data.** Identifiers come from `secrets.token_hex`, so a
`capgate-ref:` string that an attacker plants inside untrusted content resolves to nothing. It
is not rejected as suspicious; it simply names no stored value.

**Resolution failure is never silently permissive.** `resolve` returns `None` for an unknown
reference, and callers must treat that as "provenance unknown" and fall back to the pessimistic
session label — never as "no taint here".

This module is pure bookkeeping: it makes no decisions and changes no verdicts on its own.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from capgate.taint.labels import Label

#: Prefix identifying a CapGate value reference. Deliberately distinctive so it cannot be
#: confused with ordinary tool output.
REFERENCE_PREFIX = "capgate-ref:"

_TOKEN_BYTES = 16
_DEFAULT_CAPACITY = 4096


@dataclass(frozen=True, slots=True)
class StoredValue:
    """A value held for later reference, with the label it carried when stored."""

    reference: str
    label: Label


def is_reference(candidate: object) -> bool:
    """Return whether a value *looks* like a reference.

    Looking like one proves nothing — only `ValueStore.resolve` can tell whether a token
    names a real stored value. This is a cheap pre-filter, never an authorization check.
    """

    return isinstance(candidate, str) and candidate.startswith(REFERENCE_PREFIX)


class ValueStore:
    """Per-session map from unguessable reference to the label of the value it names.

    Bounded so a long-running session cannot grow without limit. When the capacity is
    reached the oldest entries are dropped, and a dropped reference then resolves to `None`
    — which callers must treat as unknown provenance and therefore as untrusted. Eviction
    can only ever make the system more conservative.
    """

    def __init__(self, capacity: int = _DEFAULT_CAPACITY) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._capacity = capacity
        self._labels: dict[str, Label] = {}

    def store(self, label: Label) -> StoredValue:
        """Mint a fresh reference for a labelled value."""

        reference = f"{REFERENCE_PREFIX}{secrets.token_hex(_TOKEN_BYTES)}"
        if len(self._labels) >= self._capacity:
            oldest = next(iter(self._labels))
            del self._labels[oldest]
        self._labels[reference] = label
        return StoredValue(reference=reference, label=label)

    def resolve(self, reference: object) -> Label | None:
        """Return the label a reference names, or `None` when it names nothing.

        `None` means *provenance unknown*, which callers must resolve pessimistically. It
        never means *untainted*.
        """

        if not is_reference(reference):
            return None
        assert isinstance(reference, str)
        return self._labels.get(reference)

    def __len__(self) -> int:
        return len(self._labels)

    def __contains__(self, reference: object) -> bool:
        return self.resolve(reference) is not None
