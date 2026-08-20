"""Parallel multi-call turns: emission order is the security order.

`ToolNode` dispatches a turn's calls concurrently. The adapter serializes their mediation
into the planner's emission order, so call *k*'s decision sees the taint produced by calls
``0..k-1`` of the same turn. These tests pin the two properties that make that the right
design:

- a read-secret + send pair emitted together must block the send (a pre-turn-state barrier
  would let both pass — that is the discriminating case);
- a send emitted *before* the tainting read is judged against pre-read state and passes,
  because the planner could not have used a value it had not requested yet.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

pytest.importorskip("langgraph")

from langchain_core.messages import AIMessage, ToolCall, ToolMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from langgraph.graph import END, START, MessagesState, StateGraph  # noqa: E402
from langgraph.prebuilt import ToolNode  # noqa: E402
from langgraph.prebuilt.tool_node import ToolCallRequest  # noqa: E402

from capgate.adapters.langgraph import build_secure_tool_node  # noqa: E402
from capgate.engine.context import AgentContext  # noqa: E402
from capgate.engine.decision import Decision  # noqa: E402
from capgate.engine.mediator import ToolCallMediator  # noqa: E402
from capgate.engine.pipeline import DecisionPipeline, ToolMetadata  # noqa: E402
from capgate.flow.sinks import SinkKind  # noqa: E402
from capgate.policy import parse_policy  # noqa: E402
from capgate.proxy.events import JsonObject  # noqa: E402
from capgate.receipts.signer import Ed25519Signer, ReceiptWriter  # noqa: E402
from capgate.receipts.store import JsonlReceiptStore  # noqa: E402
from capgate.sandbox.base import RiskClass  # noqa: E402
from capgate.taint.labels import (  # noqa: E402
    BOTTOM_LABEL,
    Confidentiality,
    Integrity,
    Label,
)

MARKER = "CAPGATE_PARALLEL_TURN_SECRET_71ac04"


def _label_bottom(_: ToolCallRequest, arguments: JsonObject) -> dict[str, Label]:
    return {name: BOTTOM_LABEL for name in arguments}


def _compile(node: ToolNode) -> Any:
    builder = StateGraph(MessagesState)
    builder.add_node("tools", node)
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    return builder.compile()


def _invoke(graph: Any, calls: list[ToolCall]) -> list[ToolMessage]:
    state = cast(
        MessagesState,
        graph.invoke({"messages": [AIMessage(content="", tool_calls=calls)]}),
    )
    return [m for m in state["messages"] if isinstance(m, ToolMessage)]


class _Harness:
    def __init__(self, tmp_path: Path, session_id: str) -> None:
        self.executed: list[str] = []
        self.sent: list[str] = []
        harness = self

        @tool
        def read_private() -> str:
            """Read a private, untrusted-influenced value."""

            harness.executed.append("read_private")
            return MARKER

        @tool
        def send_external(payload: str) -> str:
            """Send a payload to an external recipient."""

            harness.executed.append("send_external")
            harness.sent.append(payload)
            return "sent"

        metadata = {
            "read_private": ToolMetadata(
                result_label=Label(
                    Confidentiality.SECRET, Integrity.UNTRUSTED, frozenset({"secrets"})
                ),
                risk_class=RiskClass.TRUSTED_DIRECT,
            ),
            "send_external": ToolMetadata(
                result_label=BOTTOM_LABEL,
                risk_class=RiskClass.TRUSTED_DIRECT,
                sink=SinkKind.EMAIL_EXTERNAL,
            ),
        }
        self.store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
        mediator = ToolCallMediator(
            pipeline=DecisionPipeline(metadata),
            context=AgentContext(session_id),
            receipt_writer=ReceiptWriter(
                store=self.store, signer=Ed25519Signer.generate()
            ),
        )
        self.graph = _compile(
            build_secure_tool_node(
                [read_private, send_external],
                mediator=mediator,
                session_id=session_id,
                label_arguments=_label_bottom,
            )
        )


def test_a_read_then_send_pair_in_one_turn_blocks_the_send(tmp_path: Path) -> None:
    """The discriminating case against a pre-turn-state barrier."""

    harness = _Harness(tmp_path, "parallel-attack")

    messages = _invoke(
        harness.graph,
        [
            ToolCall(name="read_private", args={}, id="c-read", type="tool_call"),
            ToolCall(name="send_external", args={"payload": MARKER}, id="c-send", type="tool_call"),
        ],
    )

    assert harness.executed == ["read_private"]
    assert harness.sent == []
    send_message = next(m for m in messages if m.tool_call_id == "c-send")
    assert send_message.status == "error"
    artifact = cast(dict[str, Any], send_message.artifact)
    assert artifact["capgate"]["rule_id"] == "flow.lethal_trifecta"


def test_a_send_emitted_before_the_read_is_judged_against_pre_read_state(
    tmp_path: Path,
) -> None:
    """Emission order, not turn membership, decides what taint a call sees."""

    harness = _Harness(tmp_path, "parallel-benign")

    _invoke(
        harness.graph,
        [
            ToolCall(
                name="send_external",
                args={"payload": "benign status update"},
                id="c-send",
                type="tool_call",
            ),
            ToolCall(name="read_private", args={}, id="c-read", type="tool_call"),
        ],
    )

    assert harness.executed == ["send_external", "read_private"]
    assert harness.sent == ["benign status update"]


def test_large_turns_mediate_in_emission_order_every_time(tmp_path: Path) -> None:
    executed: list[str] = []

    @tool
    def step(index: int) -> str:
        """Record one step of a batch."""

        executed.append(f"step-{index}")
        return "ok"

    mediator = ToolCallMediator(
        pipeline=DecisionPipeline(
            {
                "step": ToolMetadata(
                    result_label=BOTTOM_LABEL, risk_class=RiskClass.TRUSTED_DIRECT
                )
            }
        ),
        context=AgentContext("parallel-order"),
        receipt_writer=ReceiptWriter(
            store=JsonlReceiptStore(tmp_path / "order.jsonl"),
            signer=Ed25519Signer.generate(),
        ),
    )
    graph = _compile(
        build_secure_tool_node(
            [step],
            mediator=mediator,
            session_id="parallel-order",
            label_arguments=_label_bottom,
        )
    )

    for round_number in range(3):
        executed.clear()
        _invoke(
            graph,
            [
                ToolCall(
                    name="step",
                    args={"index": index},
                    id=f"round-{round_number}-call-{index}",
                    type="tool_call",
                )
                for index in range(6)
            ],
        )
        assert executed == [f"step-{index}" for index in range(6)]


def test_approval_required_calls_in_a_batch_are_refused_not_paused(
    tmp_path: Path,
) -> None:
    """A resumed multi-call turn would re-run executed siblings, so no pause is offered."""

    executed: list[str] = []
    approvals: list[Decision] = []

    @tool
    def sensitive(payload: str) -> str:
        """An action whose capability requires human approval."""

        executed.append(payload)
        return "done"

    def approve(decision: Decision) -> bool:
        approvals.append(decision)
        return True

    mediator = ToolCallMediator(
        pipeline=DecisionPipeline(
            {
                "sensitive": ToolMetadata(
                    result_label=BOTTOM_LABEL,
                    risk_class=RiskClass.TRUSTED_DIRECT,
                    capability="send:external",
                )
            },
            policy=parse_policy(
                """
agent: parallel-approval
can: []
cannot: []
requires_approval: [send:external]
"""
            ),
        ),
        context=AgentContext("parallel-approval"),
        receipt_writer=ReceiptWriter(
            store=JsonlReceiptStore(tmp_path / "approval.jsonl"),
            signer=Ed25519Signer.generate(),
        ),
    )
    graph = _compile(
        build_secure_tool_node(
            [sensitive],
            mediator=mediator,
            session_id="parallel-approval",
            label_arguments=_label_bottom,
            approve=approve,
        )
    )

    messages = _invoke(
        graph,
        [
            ToolCall(name="sensitive", args={"payload": "a"}, id="c-1", type="tool_call"),
            ToolCall(name="sensitive", args={"payload": "b"}, id="c-2", type="tool_call"),
        ],
    )

    assert executed == []
    assert approvals == []  # the approver was never even consulted
    for message in messages:
        assert message.status == "error"
        artifact = cast(dict[str, Any], message.artifact)
        assert artifact["capgate"]["verdict"] == "REQUIRE_APPROVAL"
