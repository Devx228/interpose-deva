from __future__ import annotations

import pytest

from capgate.taint.labels import Confidentiality, Integrity, Label
from capgate.taint.values import (
    REFERENCE_PREFIX,
    ValueStore,
    is_reference,
    resolve_argument,
)

SECRET = Label(Confidentiality.SECRET, Integrity.UNTRUSTED, frozenset({"secrets"}))
PUBLIC = Label(Confidentiality.PUBLIC, Integrity.TRUSTED)


def test_a_stored_value_resolves_to_its_exact_label() -> None:
    store = ValueStore()

    stored = store.store(SECRET, "the payroll file")

    assert store.resolve(stored.reference) == SECRET


def test_a_stored_value_resolves_to_its_exact_value() -> None:
    store = ValueStore()

    stored = store.store(SECRET, {"rows": 3})
    entry = store.resolve_entry(stored.reference)

    assert entry is not None
    assert entry.value == {"rows": 3}
    assert entry.label == SECRET


def test_references_are_unique_per_store_call() -> None:
    store = ValueStore()

    first = store.store(PUBLIC, "a")
    second = store.store(PUBLIC, "a")

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
    store.store(SECRET, "real")

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
    first = store.store(SECRET, "a")
    store.store(PUBLIC, "b")
    store.store(PUBLIC, "c")

    assert store.resolve(first.reference) is None
    assert len(store) == 2


def test_capacity_must_be_positive() -> None:
    with pytest.raises(ValueError, match="capacity"):
        ValueStore(capacity=0)


# --------------------------------------------------------------------------------------
# Argument resolution
# --------------------------------------------------------------------------------------


def test_an_exact_reference_argument_resolves_to_the_typed_value() -> None:
    store = ValueStore()
    stored = store.store(SECRET, {"salary": 90000})

    resolution = resolve_argument(stored.reference, store)

    assert resolution.value == {"salary": 90000}
    assert resolution.labels == (SECRET,)
    assert resolution.substituted is True


def test_an_embedded_reference_is_substituted_and_its_label_collected() -> None:
    store = ValueStore()
    stored = store.store(SECRET, "S3CR3T")

    resolution = resolve_argument(f"https://x.example/p?d={stored.reference}", store)

    assert resolution.value == "https://x.example/p?d=S3CR3T"
    assert resolution.labels == (SECRET,)


def test_partial_derivation_joins_the_fallback_not_replaces_it() -> None:
    """A composed argument keeps the pessimistic fallback; lineage only ever adds."""

    store = ValueStore()
    stored = store.store(SECRET, "S3CR3T")
    fallback = Label(Confidentiality.INTERNAL, Integrity.UNTRUSTED, frozenset({"email"}))

    resolution = resolve_argument(f"data: {stored.reference}", store)
    joined = resolution.joined_label(fallback)

    assert joined.confidentiality is Confidentiality.SECRET
    assert joined.integrity is Integrity.UNTRUSTED
    assert joined.source_tags == frozenset({"secrets", "email"})


def test_a_forged_token_is_left_inert() -> None:
    store = ValueStore()
    forged = f"{REFERENCE_PREFIX}{'a' * 32}"

    resolution = resolve_argument(f"payload {forged}", store)

    assert resolution.value == f"payload {forged}"
    assert resolution.labels == ()
    assert resolution.substituted is False


def test_references_resolve_inside_nested_containers() -> None:
    store = ValueStore()
    stored = store.store(SECRET, "S3CR3T")

    resolution = resolve_argument({"outer": [{"inner": stored.reference}]}, store)

    assert resolution.value == {"outer": [{"inner": "S3CR3T"}]}
    assert resolution.labels == (SECRET,)


def test_a_non_string_value_is_not_spliced_into_composed_text() -> None:
    """Embedding is string substitution; a structured value cannot be flattened into text."""

    store = ValueStore()
    stored = store.store(SECRET, {"k": "v"})

    resolution = resolve_argument(f"data: {stored.reference}", store)

    assert resolution.value == f"data: {stored.reference}"
    assert resolution.labels == ()


def test_depth_and_node_budgets_stop_substitution_not_safety() -> None:
    """Beyond the budget the token stays opaque, which resolves to nothing downstream."""

    store = ValueStore()
    stored = store.store(SECRET, "S3CR3T")
    deep: object = stored.reference
    for _ in range(20):
        deep = [deep]

    resolution = resolve_argument(deep, store, max_depth=4)

    assert resolution.labels == ()
    flattened = resolution.value
    for _ in range(20):
        assert isinstance(flattened, list)
        flattened = flattened[0]
    assert flattened == stored.reference
