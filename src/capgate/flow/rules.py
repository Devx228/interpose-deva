from __future__ import annotations

from dataclasses import dataclass

from capgate.engine.decision import Decision
from capgate.flow.sinks import EXTERNAL_SINKS, SinkKind
from capgate.flow.sources import DataSourceKind
from capgate.taint.labels import Confidentiality, Integrity, Label

LETHAL_TRIFECTA_RULE_ID = "flow.lethal_trifecta"


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
) -> Decision | None:
    for pair in deny_pairs:
        if pair.source.value in label.source_tags and pair.sink is sink:
            return Decision(
                verdict="BLOCK",
                reason=f"flow from {pair.source.value} to {pair.sink.value} is denied",
                rule_id=pair.rule_id,
                labels=label_strings(label),
            )
    return check_lethal_trifecta(label, sink)


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
