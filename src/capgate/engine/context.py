from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from capgate.taint.labels import BOTTOM_LABEL, Label
from capgate.taint.propagation import join_labels
from capgate.taint.tracker import TaintTracker
from capgate.taint.values import ValueStore


class ProvenanceMode(StrEnum):
    """How argument lineage is approximated for this session.

    ``SESSION`` is today's conservative default: every tool result joins one session-wide
    influence label, and every later call is judged on everything the session has ever
    seen. ``VALUE_LEVEL`` activates reference-based lineage: results of tools marked
    reference-returning are stored behind opaque tokens instead of joining influence,
    because a planner that only ever received an unguessable token cannot have been
    influenced by — and cannot re-emit — the value it names.
    """

    SESSION = "session"
    VALUE_LEVEL = "value_level"


@dataclass
class AgentContext:
    session_id: str
    tracker: TaintTracker = field(default_factory=TaintTracker)
    influence: Label = BOTTOM_LABEL
    provenance_mode: ProvenanceMode = ProvenanceMode.SESSION
    values: ValueStore = field(default_factory=ValueStore)

    def label_for_call(self, provenance_ids: tuple[str, ...]) -> Label:
        return join_labels((self.influence, self.tracker.join(provenance_ids)))

    def record_result(
        self,
        provenance_id: str,
        label: Label,
        *,
        joins_influence: bool = True,
    ) -> None:
        """Record a tool result's label, optionally without contaminating the session.

        ``joins_influence=False`` is sound only when the raw value provably never reached
        the planner — the reference-returning path, where the planner received an opaque
        token instead. The tracker entry always records the true label, so the value's own
        lineage is never weakened; only the session-wide spread is skipped.
        """

        self.tracker.record(provenance_id, label)
        if joins_influence:
            self.influence = self.influence.join(label)
