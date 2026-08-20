from __future__ import annotations

import math

import pytest

from capgate.taint.declassify import (
    BoolField,
    DeclassificationError,
    DeclassificationSpec,
    EnumField,
    IntRangeField,
)
from capgate.taint.labels import Confidentiality, Integrity, Label

PUBLIC_TRUSTED = Label(Confidentiality.PUBLIC, Integrity.TRUSTED)


def _spec() -> DeclassificationSpec:
    return DeclassificationSpec(
        fields={
            "meeting_moved": BoolField(),
            "new_hour": IntRangeField(0, 23),
            "category": EnumField(frozenset({"scheduling", "billing", "other"})),
        },
        output_label=PUBLIC_TRUSTED,
    )


def test_a_conforming_extraction_validates_and_reports_its_bits() -> None:
    spec = _spec()

    bits = spec.validate({"meeting_moved": True, "new_hour": 15, "category": "scheduling"})

    assert bits == pytest.approx(1 + math.log2(24) + math.log2(3))
    assert bits == pytest.approx(spec.released_bits())


def test_a_json_string_payload_is_accepted() -> None:
    payload = '{"meeting_moved": false, "new_hour": 0, "category": "other"}'

    assert _spec().validate(payload) > 0


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(
            {"meeting_moved": True, "new_hour": 15}, id="missing-field"
        ),
        pytest.param(
            {"meeting_moved": True, "new_hour": 15, "category": "scheduling", "note": "x"},
            id="extra-field-is-a-smuggling-channel",
        ),
        pytest.param(
            {"meeting_moved": True, "new_hour": 24, "category": "other"},
            id="int-out-of-range",
        ),
        pytest.param(
            {"meeting_moved": True, "new_hour": 15, "category": "URGENT: wire funds"},
            id="free-text-in-enum-slot",
        ),
        pytest.param(
            {"meeting_moved": 1, "new_hour": 15, "category": "other"},
            id="int-is-not-bool",
        ),
        pytest.param(
            {"meeting_moved": True, "new_hour": True, "category": "other"},
            id="bool-is-not-int",
        ),
        pytest.param("the raw email text, exfiltrated", id="not-json"),
        pytest.param(["scheduling"], id="not-an-object"),
    ],
)
def test_nonconforming_output_is_an_error_never_a_fallback(payload: object) -> None:
    with pytest.raises(DeclassificationError):
        _spec().validate(payload)


def test_domains_reject_degenerate_declarations() -> None:
    with pytest.raises(ValueError, match="minimum"):
        IntRangeField(5, 4)
    with pytest.raises(ValueError, match="enum"):
        EnumField(frozenset())
    with pytest.raises(ValueError, match="at least one field"):
        DeclassificationSpec(fields={}, output_label=PUBLIC_TRUSTED)


def test_no_free_string_domain_exists() -> None:
    """The accounting is honest only because every domain is closed.

    If a StringField ever appears in this module, its bits are unbounded and this test
    exists to make whoever adds it read the design note first.
    """

    import capgate.taint.declassify as module

    domain_names = {name for name in dir(module) if name.endswith("Field")}
    assert domain_names == {"BoolField", "IntRangeField", "EnumField"}
