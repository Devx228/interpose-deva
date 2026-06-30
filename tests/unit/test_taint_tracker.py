from __future__ import annotations

from capgate.taint.labels import Confidentiality, Integrity, Label
from capgate.taint.tracker import TaintTracker


def test_tracker_joins_known_provenance_without_losing_taint() -> None:
    tracker = TaintTracker()
    tracker.record(
        "private",
        Label(Confidentiality.SECRET, Integrity.TRUSTED, frozenset({"vault"})),
    )
    tracker.record(
        "untrusted",
        Label(Confidentiality.PUBLIC, Integrity.UNTRUSTED, frozenset({"web"})),
    )

    label = tracker.join(("private", "untrusted"))

    assert label == Label(
        Confidentiality.SECRET,
        Integrity.UNTRUSTED,
        frozenset({"vault", "web"}),
    )


def test_tracker_treats_missing_provenance_as_untrusted() -> None:
    label = TaintTracker().join(("missing",))

    assert label.confidentiality is Confidentiality.PUBLIC
    assert label.integrity is Integrity.UNTRUSTED
    assert label.source_tags == frozenset({"unknown"})


def test_tracker_cannot_downgrade_existing_provenance() -> None:
    tracker = TaintTracker()
    tracker.record(
        "value",
        Label(Confidentiality.SECRET, Integrity.UNTRUSTED, frozenset({"web"})),
    )
    tracker.record("value", Label(Confidentiality.PUBLIC, Integrity.TRUSTED))

    assert tracker.get("value") == Label(
        Confidentiality.SECRET,
        Integrity.UNTRUSTED,
        frozenset({"web"}),
    )
