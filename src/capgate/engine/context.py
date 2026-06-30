from __future__ import annotations

from dataclasses import dataclass, field

from capgate.taint.labels import BOTTOM_LABEL, Label
from capgate.taint.propagation import join_labels
from capgate.taint.tracker import TaintTracker


@dataclass
class AgentContext:
    session_id: str
    tracker: TaintTracker = field(default_factory=TaintTracker)
    influence: Label = BOTTOM_LABEL

    def label_for_call(self, provenance_ids: tuple[str, ...]) -> Label:
        return join_labels((self.influence, self.tracker.join(provenance_ids)))

    def record_result(self, provenance_id: str, label: Label) -> None:
        self.tracker.record(provenance_id, label)
        self.influence = self.influence.join(label)
