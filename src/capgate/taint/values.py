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

import re
import secrets
from dataclasses import dataclass

from capgate.taint.labels import Label
from capgate.taint.propagation import join_labels

#: Prefix identifying a CapGate value reference. Deliberately distinctive so it cannot be
#: confused with ordinary tool output.
REFERENCE_PREFIX = "capgate-ref:"

_TOKEN_BYTES = 16
_DEFAULT_CAPACITY = 4096

#: Exact shape of a minted token. Matching this proves nothing — only resolution against a
#: store does — but it lets embedded tokens be located inside composed text.
_REFERENCE_PATTERN = re.compile(re.escape(REFERENCE_PREFIX) + rf"[0-9a-f]{{{_TOKEN_BYTES * 2}}}")


@dataclass(frozen=True, slots=True)
class StoredValue:
    """A value held for later reference, with the label it carried when stored."""

    reference: str
    label: Label
    value: object


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
        self._entries: dict[str, StoredValue] = {}

    def store(self, label: Label, value: object) -> StoredValue:
        """Mint a fresh reference for a labelled value."""

        reference = f"{REFERENCE_PREFIX}{secrets.token_hex(_TOKEN_BYTES)}"
        if len(self._entries) >= self._capacity:
            oldest = next(iter(self._entries))
            del self._entries[oldest]
        entry = StoredValue(reference=reference, label=label, value=value)
        self._entries[reference] = entry
        return entry

    def resolve(self, reference: object) -> Label | None:
        """Return the label a reference names, or `None` when it names nothing.

        `None` means *provenance unknown*, which callers must resolve pessimistically. It
        never means *untainted*.
        """

        entry = self.resolve_entry(reference)
        return entry.label if entry is not None else None

    def resolve_entry(self, reference: object) -> StoredValue | None:
        """Return the full stored entry a reference names, or `None` for unknown tokens."""

        if not is_reference(reference):
            return None
        assert isinstance(reference, str)
        return self._entries.get(reference)

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, reference: object) -> bool:
        return self.resolve_entry(reference) is not None


@dataclass(frozen=True, slots=True)
class ArgumentResolution:
    """One argument after reference resolution.

    ``labels`` holds the exact label of every reference that actually resolved. It is the
    *addition* lineage proves, never a replacement for the caller's fallback: a partially
    composed argument (free text around a token) must still join the pessimistic session
    label, so callers always join these labels *into* their fallback rather than instead
    of it.
    """

    value: object
    labels: tuple[Label, ...]
    substituted: bool

    def joined_label(self, fallback: Label) -> Label:
        return join_labels((fallback, *self.labels))


def resolve_argument(
    value: object,
    store: ValueStore,
    *,
    max_depth: int = 8,
    max_nodes: int = 256,
) -> ArgumentResolution:
    """Substitute resolvable references inside one argument value.

    A string that *is* a minted token becomes the stored value with its exact type. A
    token embedded in composed text is substituted only when the stored value is itself a
    string. Containers are walked to a bounded depth and node count; anything beyond the
    budget is left untouched, which fails in the safe direction — an unsubstituted token
    stays an opaque string that names nothing downstream.

    Tokens that resolve to nothing (attacker-planted, evicted, or foreign) are left
    exactly as they are. They carry no stored value, so there is nothing to substitute
    and nothing to label; the caller's pessimistic fallback covers them.
    """

    budget = [max_nodes]
    labels: list[Label] = []
    resolved = _resolve(value, store, labels, budget, max_depth)
    return ArgumentResolution(
        value=resolved,
        labels=tuple(labels),
        substituted=resolved is not value,
    )


def _resolve(
    value: object,
    store: ValueStore,
    labels: list[Label],
    budget: list[int],
    depth: int,
) -> object:
    if budget[0] <= 0 or depth < 0:
        return value
    budget[0] -= 1
    if isinstance(value, str):
        return _resolve_string(value, store, labels)
    if isinstance(value, list):
        items = [_resolve(item, store, labels, budget, depth - 1) for item in value]
        changed = any(new is not old for new, old in zip(items, value, strict=True))
        return items if changed else value
    if isinstance(value, dict):
        entries = {
            key: _resolve(item, store, labels, budget, depth - 1)
            for key, item in value.items()
        }
        changed = any(entries[key] is not value[key] for key in value)
        return entries if changed else value
    return value


def _resolve_string(value: str, store: ValueStore, labels: list[Label]) -> object:
    entry = store.resolve_entry(value)
    if entry is not None:
        labels.append(entry.label)
        return entry.value

    def _substitute(match: re.Match[str]) -> str:
        embedded = store.resolve_entry(match.group(0))
        if embedded is None or not isinstance(embedded.value, str):
            return match.group(0)
        labels.append(embedded.label)
        return embedded.value

    substituted = _REFERENCE_PATTERN.sub(_substitute, value)
    return substituted if substituted != value else value
