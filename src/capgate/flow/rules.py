from __future__ import annotations

from dataclasses import dataclass

from capgate.engine.decision import Decision
from capgate.flow.sinks import EXTERNAL_SINKS, STATE_CHANGING_SINKS, SinkKind
from capgate.flow.sources import DataSourceKind
from capgate.taint.labels import Confidentiality, Integrity, Label

LETHAL_TRIFECTA_RULE_ID = "flow.lethal_trifecta"
UNTRUSTED_STATE_CHANGE_RULE_ID = "flow.untrusted_state_change"


@dataclass(frozen=True)
class DenyPair:
    source: DataSourceKind
    sink: SinkKind

    @property
    def rule_id(self) -> str:
        sink_id = self.sink.value.replace(".", "_")
        return f"flow.deny.{self.source.value}_to_{sink_id}"


DEFAULT_DENY_PAIRS = (
    DenyPair(DataSourceKind.SECRETS, SinkKind.NETWORK_EXTERNAL),
    DenyPair(DataSourceKind.UNTRUSTED_WEB, SinkKind.SHELL_EXEC),
    DenyPair(DataSourceKind.CUSTOMER_PII, SinkKind.SLACK_PUBLIC),
)


def label_strings(label: Label) -> frozenset[str]:
    return frozenset(
        {
            f"confidentiality:{label.confidentiality.value}",
            f"integrity:{label.integrity.value}",
            *label.source_tags,
        }
    )


def check_flow(
    label: Label,
    sink: SinkKind,
    deny_pairs: tuple[DenyPair, ...] = DEFAULT_DENY_PAIRS,
    *,
    require_trusted_for_state_change: bool = False,
) -> Decision | None:
    for pair in deny_pairs:
        if pair.source.value in label.source_tags and pair.sink is sink:
            return Decision(
                verdict="BLOCK",
                reason=f"flow from {pair.source.value} to {pair.sink.value} is denied",
                rule_id=pair.rule_id,
                labels=label_strings(label),
            )
    trifecta = check_lethal_trifecta(label, sink)
    if trifecta is not None:
        return trifecta
    if require_trusted_for_state_change:
        return check_untrusted_state_change(label, sink)
    return None


def check_untrusted_state_change(label: Label, sink: SinkKind) -> Decision | None:
    """Block untrusted-influenced data from driving an action that changes the world.

    The lethal-trifecta rule guards *confidentiality*: it fires only when the data is at
    least internal, because its concern is data escaping. That leaves a real gap. An
    injected "delete every record" or "run this shell command" carries no private data at
    all, so the trifecta rule never sees it, and only capability policy stands in the way —
    which helps solely if the operator thought to deny that capability in advance.

    This rule closes it on the *integrity* axis instead: whatever the confidentiality,
    untrusted content must not drive a state-changing sink. It is the same "Rule of Two"
    reasoning applied to destruction rather than exfiltration.

    Off by default, because it is only affordable once provenance is precise. Under
    session-wide influence a single untrusted read taints everything that follows, so
    enabling this would refuse most later writes. Measure the utility cost before turning
    it on; `bench/run_scenarios.py --strict-integrity` reports it.
    """

    if label.integrity is Integrity.UNTRUSTED and sink in STATE_CHANGING_SINKS:
        return Decision(
            verdict="BLOCK",
            reason=(
                "state-changing sink blocked: action is influenced by untrusted content"
            ),
            rule_id=UNTRUSTED_STATE_CHANGE_RULE_ID,
            labels=label_strings(label),
        )
    return None


def check_lethal_trifecta(label: Label, sink: SinkKind) -> Decision | None:
    is_private = label.confidentiality in {
        Confidentiality.INTERNAL,
        Confidentiality.SECRET,
    }
    if is_private and label.integrity is Integrity.UNTRUSTED and sink in EXTERNAL_SINKS:
        return Decision(
            verdict="BLOCK",
            reason="external sink blocked: private data influenced by untrusted content",
            rule_id=LETHAL_TRIFECTA_RULE_ID,
            labels=label_strings(label),
        )
    return None
