from __future__ import annotations

import pytest

from capgate.taint.labels import Confidentiality, Integrity, Label
from capgate.taint.values import REFERENCE_PREFIX, ValueStore, is_reference

SECRET = Label(Confidentiality.SECRET, Integrity.UNTRUSTED, frozenset({"secrets"}))
PUBLIC = Label(Confidentiality.PUBLIC, Integrity.TRUSTED)


def test_a_stored_value_resolves_to_its_exact_label() -> None:
    store = ValueStore()

    stored = store.store(SECRET)

    assert store.resolve(stored.reference) == SECRET


def test_references_are_unique_per_store_call() -> None:
    store = ValueStore()

    first = store.store(PUBLIC)
    second = store.store(PUBLIC)

    assert first.reference != second.reference


@pytest.mark.parametrize(
    "forged",
    [
        pytest.param(f"{REFERENCE_PREFIX}aaaaaaaaaaaaaaaa", id="plausible-shape"),
        pytest.param(f"{REFERENCE_PREFIX}", id="empty-token"),
        pytest.param(f"{REFERENCE_PREFIX}../../etc/passwd", id="path-traversal-shaped"),
    ],
)
def test_a_reference_planted_by_an_attacker_resolves_to_nothing(forged: str) -> None:
    """The core property: references cannot be forged from untrusted content.

    An attacker who writes a `capgate-ref:` string into a document they control must not be
    able to name a real value. Tokens come from `secrets.token_hex`, so guessing one is
    infeasible, and an unknown token resolves to None — which callers treat as unknown
    provenance and therefore untrusted.
    """

    store = ValueStore()
    store.store(SECRET)

    assert store.resolve(forged) is None
    assert forged not in store


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("just a string", id="plain-text"),
        pytest.param(None, id="none"),
        pytest.param(42, id="int"),
        pytest.param({"ref": "x"}, id="dict"),
    ],
)
def test_non_references_resolve_to_nothing(value: object) -> None:
    assert ValueStore().resolve(value) is None


def test_is_reference_is_only_a_shape_check() -> None:
    """Looking like a reference is not the same as being one."""

    assert is_reference(f"{REFERENCE_PREFIX}deadbeef") is True
    assert is_reference("capgate-ref") is False
    assert is_reference(123) is False


def test_eviction_fails_toward_unknown_provenance() -> None:
    """A dropped reference resolves to None, so it is treated as untrusted, not clean."""

    store = ValueStore(capacity=2)
    first = store.store(SECRET)
    store.store(PUBLIC)
    store.store(PUBLIC)

    assert store.resolve(first.reference) is None
    assert len(store) == 2


def test_capacity_must_be_positive() -> None:
    with pytest.raises(ValueError, match="capacity"):
        ValueStore(capacity=0)
