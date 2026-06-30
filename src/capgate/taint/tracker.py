from __future__ import annotations

from collections.abc import Iterable

from capgate.taint.labels import BOTTOM_LABEL, Label
from capgate.taint.propagation import join_labels
from capgate.taint.sources import UNKNOWN_LABEL


class TaintTracker:
    def __init__(self) -> None:
        self._labels: dict[str, Label] = {}

    def record(self, provenance_id: str, label: Label) -> None:
        existing = self._labels.get(provenance_id, BOTTOM_LABEL)
        self._labels[provenance_id] = existing.join(label)

    def get(self, provenance_id: str) -> Label:
        return self._labels.get(provenance_id, UNKNOWN_LABEL)

    def join(self, provenance_ids: Iterable[str]) -> Label:
        return join_labels(self.get(provenance_id) for provenance_id in provenance_ids)
