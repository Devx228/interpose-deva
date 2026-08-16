from __future__ import annotations

from pathlib import Path

import pytest

from capgate.engine.context import AgentContext
from capgate.engine.decision import Decision
from capgate.engine.mediator import ToolCallMediator
from capgate.engine.pipeline import DecisionPipeline, ToolMetadata
from capgate.flow.sinks import SinkKind
from capgate.policy import parse_policy
from capgate.proxy.events import ToolCallEvent
from capgate.receipts.signer import Ed25519Signer, ReceiptWriter
from capgate.receipts.store import JsonlReceiptStore
from capgate.sandbox.base import RiskClass
from capgate.taint.labels import Confidentiality, Integrity, Label

SESSION = "approval-session"


def _pipeline(*, sink: SinkKind = SinkKind.NONE) -> DecisionPipeline:
    return DecisionPipeline(
        {
            "read_private": ToolMetadata(
                result_label=Label(
                    Confidentiality.SECRET,
                    Integrity.UNTRUSTED,
                    frozenset({"secrets"}),
                ),
                risk_class=RiskClass.TRUSTED_DIRECT,
                capability="read:private",
            ),
            "sensitive_action": ToolMetadata(
                result_label=Label(Confidentiality.PUBLIC, Integrity.TRUSTED),
                risk_class=RiskClass.TRUSTED_DIRECT,
                sink=sink,
                capability="write:github.issue",
            ),
        },
        policy=parse_policy(
            """
agent: approval-test
can: [read:private]
cannot: []
requires_approval: [write:github.issue]
"""
        ),
    )


def _mediator(tmp_path: Path, *, sink: SinkKind = SinkKind.NONE) -> ToolCallMediator:
    return ToolCallMediator(
        pipeline=_pipeline(sink=sink),
        context=AgentContext(SESSION),
        receipt_writer=ReceiptWriter(
            store=JsonlReceiptStore(tmp_path / "receipts.jsonl"),
            signer=Ed25519Signer.generate(),
        ),
    )


def _call(tool: str, request_id: str) -> ToolCallEvent:
    return ToolCallEvent(
        session_id=SESSION,
        server="test",
        tool=tool,
        arguments={},
        arg_provenance={},
        request_id=request_id,
    )


def test_approval_required_call_is_refused_without_an_approver(tmp_path: Path) -> None:
    """A verdict nobody can answer must never behave like an allow."""

    executed = 0

    def execute() -> str:
        nonlocal executed
        executed += 1
        return "done"

    outcome = _mediator(tmp_path).mediate(_call("sensitive_action", "r1"), execute)

    assert outcome.decision.verdict == "REQUIRE_APPROVAL"
    assert outcome.executed is False
    assert executed == 0


def test_granted_approval_executes_the_call(tmp_path: Path) -> None:
    executed = 0

    def execute() -> str:
        nonlocal executed
        executed += 1
        return "done"

    outcome = _mediator(tmp_path).mediate(
        _call("sensitive_action", "r1"),
        execute,
        approve=lambda _decision: True,
    )

    assert outcome.decision.verdict == "ALLOW"
    assert outcome.decision.rule_id == "policy.approval.granted"
    assert outcome.executed is True
    assert executed == 1


def test_refused_approval_blocks_before_execution(tmp_path: Path) -> None:
    executed = 0

    def execute() -> str:
        nonlocal executed
        executed += 1
        return "done"

    outcome = _mediator(tmp_path).mediate(
        _call("sensitive_action", "r1"),
        execute,
        approve=lambda _decision: False,
    )

    assert outcome.decision.verdict == "BLOCK"
    assert outcome.decision.rule_id == "policy.approval.denied"
    assert outcome.executed is False
    assert executed == 0


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param("yes", id="truthy-string"),
        pytest.param(1, id="truthy-int"),
        pytest.param(None, id="none"),
        pytest.param([], id="empty-list"),
    ],
)
def test_only_exact_true_approves(tmp_path: Path, answer: object) -> None:
    """A resume value the runtime did not expect must never be read as consent."""

    executed = 0

    def execute() -> str:
        nonlocal executed
        executed += 1
        return "done"

    outcome = _mediator(tmp_path).mediate(
        _call("sensitive_action", "r1"),
        execute,
        approve=lambda _decision: answer,  # type: ignore[arg-type,return-value]
    )

    assert outcome.decision.verdict == "BLOCK"
    assert executed == 0


def test_approval_does_not_override_flow_rules(tmp_path: Path) -> None:
    """The security property that matters: approval permits an action, not a leak."""

    mediator = _mediator(tmp_path, sink=SinkKind.NETWORK_EXTERNAL)
    executed = 0

    def execute() -> str:
        nonlocal executed
        executed += 1
        return "done"

    # Taint the session with secret, untrusted data first.
    read = mediator.mediate(_call("read_private", "r0"), lambda: "secret-value")
    assert read.decision.verdict == "ALLOW"

    outcome = mediator.mediate(
        _call("sensitive_action", "r1"),
        execute,
        approve=lambda _decision: True,
    )

    assert outcome.decision.verdict == "BLOCK"
    assert outcome.decision.rule_id == "flow.deny.secrets_to_network_external"
    assert outcome.executed is False
    assert executed == 0


def test_approval_outcome_is_recorded_in_the_receipt_chain(tmp_path: Path) -> None:
    store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
    mediator = ToolCallMediator(
        pipeline=_pipeline(),
        context=AgentContext(SESSION),
        receipt_writer=ReceiptWriter(store=store, signer=Ed25519Signer.generate()),
    )

    mediator.mediate(
        _call("sensitive_action", "r1"),
        lambda: "done",
        approve=lambda _decision: True,
    )
    mediator.mediate(
        _call("sensitive_action", "r2"),
        lambda: "done",
        approve=lambda _decision: False,
    )

    receipts = store.iter_receipts(SESSION)
    assert [receipt.rule_id for receipt in receipts] == [
        "policy.approval.granted",
        "policy.approval.denied",
    ]
    assert [receipt.verdict for receipt in receipts] == ["ALLOW", "BLOCK"]


def test_approver_exceptions_propagate_so_a_pause_is_never_swallowed() -> None:
    """LangGraph implements approval by raising to suspend the run."""

    class Suspend(Exception):
        pass

    def approve(_decision: Decision) -> bool:
        raise Suspend

    store = JsonlReceiptStore(Path("unused"))
    mediator = ToolCallMediator(
        pipeline=_pipeline(),
        context=AgentContext(SESSION),
        receipt_writer=ReceiptWriter(store=store, signer=Ed25519Signer.generate()),
    )

    with pytest.raises(Suspend):
        mediator.mediate(_call("sensitive_action", "r1"), lambda: "done", approve=approve)
