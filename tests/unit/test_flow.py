from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from capgate.flow.rules import DEFAULT_DENY_PAIRS, check_flow, check_lethal_trifecta
from capgate.flow.sinks import EXTERNAL_SINKS, SinkKind
from capgate.flow.sources import SourceKind
from capgate.taint.labels import Confidentiality, Integrity, Label


@pytest.mark.parametrize(
    ("source", "sink", "rule_id"),
    [
        (
            SourceKind.SECRETS,
            SinkKind.NETWORK_EXTERNAL,
            "flow.deny.secrets_to_network_external",
        ),
        (
            SourceKind.UNTRUSTED_WEB,
            SinkKind.SHELL_EXEC,
            "flow.deny.untrusted_web_to_shell_exec",
        ),
        (
            SourceKind.CUSTOMER_PII,
            SinkKind.SLACK_PUBLIC,
            "flow.deny.customer_pii_to_slack_public",
        ),
    ],
)
def test_default_source_to_sink_pairs_block_with_stable_rule_ids(
    source: SourceKind,
    sink: SinkKind,
    rule_id: str,
) -> None:
    decision = check_flow(
        Label(Confidentiality.PUBLIC, Integrity.TRUSTED, frozenset({source.value})),
        sink,
    )

    assert decision is not None
    assert decision.verdict == "BLOCK"
    assert decision.rule_id == rule_id


def test_static_pair_does_not_block_a_different_sink() -> None:
    decision = check_flow(
        Label(
            Confidentiality.PUBLIC,
            Integrity.TRUSTED,
            frozenset({SourceKind.SECRETS.value}),
        ),
        SinkKind.EMAIL_EXTERNAL,
    )

    assert decision is None


def test_static_pair_precedes_lethal_trifecta() -> None:
    label = Label(
        Confidentiality.SECRET,
        Integrity.UNTRUSTED,
        frozenset({SourceKind.SECRETS.value}),
    )

    decision = check_flow(label, SinkKind.NETWORK_EXTERNAL)

    assert decision is not None
    assert decision.rule_id == "flow.deny.secrets_to_network_external"
    assert check_lethal_trifecta(label, SinkKind.NETWORK_EXTERNAL) is not None


def test_deny_pairs_are_immutable() -> None:
    pair = DEFAULT_DENY_PAIRS[0]

    with pytest.raises(FrozenInstanceError):
        type(pair).__setattr__(pair, "source", SourceKind.MEMORY)


@pytest.mark.parametrize("confidentiality", [Confidentiality.INTERNAL, Confidentiality.SECRET])
@pytest.mark.parametrize("sink", tuple(EXTERNAL_SINKS))
def test_lethal_trifecta_blocks_every_private_untrusted_external_combination(
    confidentiality: Confidentiality,
    sink: SinkKind,
) -> None:
    decision = check_lethal_trifecta(
        Label(confidentiality, Integrity.UNTRUSTED, frozenset({"untrusted-source"})),
        sink,
    )

    assert decision is not None
    assert decision.verdict == "BLOCK"


@pytest.mark.parametrize(
    ("label", "sink"),
    [
        (Label(Confidentiality.PUBLIC, Integrity.UNTRUSTED), SinkKind.EMAIL_EXTERNAL),
        (Label(Confidentiality.INTERNAL, Integrity.TRUSTED), SinkKind.NETWORK_EXTERNAL),
        (Label(Confidentiality.SECRET, Integrity.UNTRUSTED), SinkKind.NONE),
    ],
)
def test_lethal_trifecta_allows_when_one_required_condition_is_absent(
    label: Label,
    sink: SinkKind,
) -> None:
    assert check_lethal_trifecta(label, sink) is None
