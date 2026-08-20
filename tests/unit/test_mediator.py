from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from threading import Event

from capgate.engine.context import AgentContext
from capgate.engine.mediator import ToolCallMediator
from capgate.engine.pipeline import DecisionPipeline, ToolMetadata
from capgate.flow.sinks import SinkKind
from capgate.policy import parse_policy
from capgate.proxy.events import JsonValue, ToolCallEvent, ToolResultEvent
from capgate.receipts.replay import replay_session
from capgate.receipts.signer import Ed25519Signer, ReceiptWriter
from capgate.receipts.store import JsonlReceiptStore
from capgate.sandbox.base import RiskClass
from capgate.taint.labels import Confidentiality, Integrity, Label

PUBLIC_TRUSTED = Label(Confidentiality.PUBLIC, Integrity.TRUSTED)
PRIVATE_UNTRUSTED = Label(
    Confidentiality.SECRET,
    Integrity.UNTRUSTED,
    frozenset({"private-demo"}),
)


@dataclass(frozen=True)
class FrameworkResult:
    content: str


def test_allow_preserves_result_records_provenance_and_writes_receipts(
    tmp_path: Path,
) -> None:
    pipeline = DecisionPipeline(
        {
            "read_private": _metadata(PRIVATE_UNTRUSTED),
            "send_external": _metadata(
                PUBLIC_TRUSTED,
                sink=SinkKind.NETWORK_EXTERNAL,
            ),
        }
    )
    mediator, store, signer = _mediator(tmp_path, pipeline)
    private_result = FrameworkResult("PRIVATE_MARKER")

    returned = mediator.mediate(
        _call("read_private", 1),
        lambda: private_result,
        result_to_json=lambda value: {"content_length": len(value.content)},
    )
    side_effects = 0

    def send() -> dict[str, bool]:
        nonlocal side_effects
        side_effects += 1
        return {"sent": True}

    rejected = mediator.mediate(_call("send_external", 2), send)

    assert returned.value is private_result
    assert returned.decision.verdict == "ALLOW"
    assert returned.executed is True
    assert rejected.decision.rule_id == "flow.lethal_trifecta"
    assert rejected.executed is False
    assert side_effects == 0
    report = replay_session(store.path, "session-1", signer.verifier())
    assert [receipt.verdict for receipt in report.receipts] == ["ALLOW", "BLOCK"]
    assert "PRIVATE_MARKER" not in store.path.read_text(encoding="utf-8")


def test_approval_and_unknown_tool_never_execute(tmp_path: Path) -> None:
    pipeline = DecisionPipeline(
        {
            "send": _metadata(PUBLIC_TRUSTED, capability="send:external"),
        },
        policy=parse_policy(
            """
agent: test
can: []
cannot: []
requires_approval: [send:external]
"""
        ),
    )
    mediator, store, _ = _mediator(tmp_path, pipeline)
    side_effects = 0

    def handler() -> None:
        nonlocal side_effects
        side_effects += 1

    approval = mediator.mediate(_call("send", 1), handler)
    unknown = mediator.mediate(_call("unknown", 2), handler)

    assert approval.decision.verdict == "REQUIRE_APPROVAL"
    assert unknown.decision.rule_id == "engine.unknown_tool"
    assert side_effects == 0
    assert [receipt.verdict for receipt in store.iter_receipts("session-1")] == [
        "REQUIRE_APPROVAL",
        "BLOCK",
    ]


def test_labeled_private_argument_blocks_first_call_to_external_sink(tmp_path: Path) -> None:
    mediator, store, _ = _mediator(
        tmp_path,
        DecisionPipeline(
            {
                "send_external": _metadata(
                    PUBLIC_TRUSTED,
                    sink=SinkKind.NETWORK_EXTERNAL,
                )
            }
        ),
    )
    call = ToolCallEvent(
        session_id="session-1",
        server="langgraph",
        tool="send_external",
        arguments={"payload": "PRIVATE_MARKER"},
        arg_provenance={"payload": "langgraph:argument:payload"},
        request_id=1,
    )
    side_effects = 0

    def send() -> str:
        nonlocal side_effects
        side_effects += 1
        return "sent"

    outcome = mediator.mediate(
        call,
        send,
        argument_labels={"payload": PRIVATE_UNTRUSTED},
    )

    assert outcome.decision.rule_id == "flow.lethal_trifecta"
    assert outcome.executed is False
    assert side_effects == 0
    assert store.iter_receipts("session-1")[0].rule_id == "flow.lethal_trifecta"
    assert "PRIVATE_MARKER" not in store.path.read_text(encoding="utf-8")


def test_unlabeled_argument_fails_closed_before_execution(tmp_path: Path) -> None:
    mediator, store, _ = _mediator(
        tmp_path,
        DecisionPipeline({"echo": _metadata(PUBLIC_TRUSTED)}),
    )
    call = ToolCallEvent(
        session_id="session-1",
        server="langgraph",
        tool="echo",
        arguments={"value": "unlabeled"},
        arg_provenance={},
        request_id=1,
    )
    side_effects = 0

    def handler() -> str:
        nonlocal side_effects
        side_effects += 1
        return "ok"

    outcome = mediator.mediate(call, handler)

    assert outcome.decision.rule_id == "mediator.argument_labels_missing"
    assert outcome.executed is False
    assert side_effects == 0
    assert store.iter_receipts("session-1")[0].verdict == "BLOCK"


def test_required_sandbox_route_never_executes_directly(tmp_path: Path) -> None:
    mediator, store, _ = _mediator(
        tmp_path,
        DecisionPipeline(
            {
                "risky": _metadata(
                    PUBLIC_TRUSTED,
                    risk_class=RiskClass.FIXED_RISKY,
                )
            }
        ),
    )
    side_effects = 0

    def handler() -> None:
        nonlocal side_effects
        side_effects += 1

    rejected = mediator.mediate(_call("risky", 1), handler)

    assert rejected.decision.rule_id == "sandbox.call.unavailable"
    assert rejected.executed is False
    assert side_effects == 0
    assert store.iter_receipts("session-1")[0].verdict == "BLOCK"


def test_full_sequence_is_serialized_across_threads(tmp_path: Path) -> None:
    mediator, store, _ = _mediator(
        tmp_path,
        DecisionPipeline({"echo": _metadata(PUBLIC_TRUSTED)}),
    )
    first_entered = Event()
    release_first = Event()
    second_invoking = Event()
    second_entered = Event()

    def first_handler() -> int:
        first_entered.set()
        assert release_first.wait(timeout=2)
        return 1

    def second_handler() -> int:
        second_entered.set()
        return 2

    def invoke_second() -> int:
        second_invoking.set()
        outcome = mediator.mediate(_call("echo", 2), second_handler)
        assert outcome.value is not None
        return outcome.value

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(mediator.mediate, _call("echo", 1), first_handler)
        assert first_entered.wait(timeout=2)
        second = executor.submit(invoke_second)
        assert second_invoking.wait(timeout=2)
        assert not second_entered.wait(timeout=0.05)
        release_first.set()
        assert first.result(timeout=2).value == 1
        assert second.result(timeout=2) == 2

    receipts = store.iter_receipts("session-1")
    assert [receipt.seq for receipt in receipts] == [1, 2]
    assert [receipt.tool for receipt in receipts] == ["echo", "echo"]


def test_execution_failure_is_sanitized_and_fails_session_closed(tmp_path: Path) -> None:
    mediator, store, _ = _mediator(
        tmp_path,
        DecisionPipeline({"echo": _metadata(PUBLIC_TRUSTED)}),
    )

    def fail() -> None:
        raise RuntimeError("PRIVATE_EXECUTION_DETAIL")

    failed = mediator.mediate(_call("echo", 1), fail)
    later_side_effect = 0

    def later() -> None:
        nonlocal later_side_effect
        later_side_effect += 1

    closed = mediator.mediate(_call("echo", 2), later)

    assert failed.decision.rule_id == "mediator.execution_failed"
    assert failed.executed is True
    assert "PRIVATE_EXECUTION_DETAIL" not in failed.decision.reason
    assert closed.decision.rule_id == "mediator.session_failed_closed"
    assert later_side_effect == 0
    assert "PRIVATE_EXECUTION_DETAIL" not in store.path.read_text(encoding="utf-8")


def test_invalid_result_is_not_stringified_or_leaked(tmp_path: Path) -> None:
    mediator, store, _ = _mediator(
        tmp_path,
        DecisionPipeline({"echo": _metadata(PUBLIC_TRUSTED)}),
    )

    rejected = mediator.mediate(
        _call("echo", 1),
        lambda: FrameworkResult("PRIVATE_RESULT"),
    )

    assert rejected.decision.rule_id == "mediator.result_invalid"
    assert rejected.executed is True
    assert "PRIVATE_RESULT" not in store.path.read_text(encoding="utf-8")


def test_receipt_failure_after_execution_is_sanitized(tmp_path: Path) -> None:
    receipt_path = tmp_path / "receipts.jsonl"
    receipt_path.mkdir()
    mediator = ToolCallMediator(
        pipeline=DecisionPipeline({"echo": _metadata(PUBLIC_TRUSTED)}),
        context=AgentContext("session-1"),
        receipt_writer=ReceiptWriter(
            store=JsonlReceiptStore(receipt_path),
            signer=Ed25519Signer.generate(),
        ),
    )
    executed = 0

    def handler() -> dict[str, bool]:
        nonlocal executed
        executed += 1
        return {"ok": True}

    rejected = mediator.mediate(_call("echo", 1), handler)

    assert executed == 1
    assert rejected.decision.rule_id == "mediator.receipt_failed"
    assert rejected.executed is True
    assert "directory" not in rejected.decision.reason.lower()


def test_provenance_failure_is_receipted_and_fails_session_closed(tmp_path: Path) -> None:
    pipeline = FailingObservationPipeline({"echo": _metadata(PUBLIC_TRUSTED)})
    mediator, store, _ = _mediator(tmp_path, pipeline)

    rejected = mediator.mediate(_call("echo", 1), lambda: {"ok": True})

    assert rejected.decision.rule_id == "mediator.provenance_failed"
    assert rejected.executed is True
    receipt = store.iter_receipts("session-1")[0]
    assert receipt.verdict == "BLOCK"
    assert receipt.rule_id == "mediator.provenance_failed"
    assert "PRIVATE_PROVENANCE_DETAIL" not in store.path.read_text(encoding="utf-8")


class FailingObservationPipeline(DecisionPipeline):
    def observe_result(
        self,
        context: AgentContext,
        call_event: ToolCallEvent,
        result_event: ToolResultEvent,
        *,
        payload: JsonValue | None = None,
    ) -> str | None:
        raise RuntimeError("PRIVATE_PROVENANCE_DETAIL")


def _mediator(
    tmp_path: Path,
    pipeline: DecisionPipeline,
) -> tuple[ToolCallMediator, JsonlReceiptStore, Ed25519Signer]:
    signer = Ed25519Signer.generate()
    store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
    return (
        ToolCallMediator(
            pipeline=pipeline,
            context=AgentContext("session-1"),
            receipt_writer=ReceiptWriter(store=store, signer=signer),
        ),
        store,
        signer,
    )


def _metadata(
    result_label: Label,
    *,
    risk_class: RiskClass = RiskClass.TRUSTED_DIRECT,
    sink: SinkKind = SinkKind.NONE,
    capability: str | None = None,
) -> ToolMetadata:
    return ToolMetadata(
        result_label=result_label,
        risk_class=risk_class,
        sink=sink,
        capability=capability,
    )


def _call(tool: str, request_id: int) -> ToolCallEvent:
    return ToolCallEvent(
        session_id="session-1",
        server="langgraph",
        tool=tool,
        arguments={},
        arg_provenance={},
        request_id=request_id,
    )
