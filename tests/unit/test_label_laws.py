"""Property tests for the label lattice.

The join is the load-bearing operation in the whole system: it is why taint cannot be
laundered. Example-based tests confirm the cases someone thought of. These confirm the
*algebraic laws* over thousands of generated labels, which is what makes "monotonic" a claim
rather than a hope.

If any of these fail, an attacker has a way to combine values into a weaker label — which
would defeat the source-to-sink rules regardless of how the rules themselves are written.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from capgate.taint.labels import BOTTOM_LABEL, Confidentiality, Integrity, Label

_CONFIDENTIALITY_ORDER = {
    Confidentiality.PUBLIC: 0,
    Confidentiality.INTERNAL: 1,
    Confidentiality.SECRET: 2,
}

labels = st.builds(
    Label,
    confidentiality=st.sampled_from(list(Confidentiality)),
    integrity=st.sampled_from(list(Integrity)),
    source_tags=st.frozensets(
        st.text(min_size=1, max_size=12).filter(lambda s: s.strip() == s and s != ""),
        max_size=5,
    ),
)


def _at_least_as_restrictive(result: Label, source: Label) -> bool:
    """A join result may never be weaker than an input on any axis."""

    return (
        _CONFIDENTIALITY_ORDER[result.confidentiality]
        >= _CONFIDENTIALITY_ORDER[source.confidentiality]
        and not (
            source.integrity is Integrity.UNTRUSTED
            and result.integrity is Integrity.TRUSTED
        )
        and result.source_tags >= source.source_tags
    )


@given(labels, labels)
def test_join_is_commutative(first: Label, second: Label) -> None:
    """Order of combination cannot change the result, so it cannot be gamed."""

    assert first.join(second) == second.join(first)


@given(labels, labels, labels)
def test_join_is_associative(first: Label, second: Label, third: Label) -> None:
    """Grouping cannot change the result either."""

    assert first.join(second).join(third) == first.join(second.join(third))


@given(labels)
def test_join_is_idempotent(label: Label) -> None:
    """Re-joining a value with itself cannot dilute it."""

    assert label.join(label) == label


@given(labels, labels)
def test_join_never_weakens_either_input(first: Label, second: Label) -> None:
    """The monotonicity property the whole design rests on.

    Confidentiality never drops, trust is never restored, and no source tag is ever lost.
    There is therefore no operation an attacker can use to launder provenance.
    """

    joined = first.join(second)
    assert _at_least_as_restrictive(joined, first)
    assert _at_least_as_restrictive(joined, second)


@given(labels)
def test_bottom_label_is_the_identity_element(label: Label) -> None:
    """`(public, trusted, {})` adds nothing, which is what makes it a safe default."""

    assert label.join(BOTTOM_LABEL) == label
    assert BOTTOM_LABEL.join(label) == label


@given(labels, labels)
def test_untrusted_is_absorbing(first: Label, second: Label) -> None:
    """One untrusted input is enough to make the result untrusted, always."""

    if Integrity.UNTRUSTED in {first.integrity, second.integrity}:
        assert first.join(second).integrity is Integrity.UNTRUSTED


@given(labels, labels)
def test_join_takes_the_maximum_confidentiality(first: Label, second: Label) -> None:
    expected = max(
        first.confidentiality,
        second.confidentiality,
        key=_CONFIDENTIALITY_ORDER.__getitem__,
    )
    assert first.join(second).confidentiality is expected
