from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
from langchain_core.messages import AIMessage, BaseMessage, ToolCall, ToolMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt.tool_node import ToolCallRequest
from langgraph.types import Command

from capgate.adapters.langgraph import build_secure_tool_node, interrupt_for_approval
from capgate.engine.context import AgentContext
from capgate.engine.mediator import ToolCallMediator
from capgate.engine.pipeline import DecisionPipeline, ToolMetadata
from capgate.flow.sinks import SinkKind
from capgate.policy import parse_policy
from capgate.proxy.events import JsonObject
from capgate.receipts.signer import Ed25519Signer, ReceiptWriter
from capgate.receipts.store import JsonlReceiptStore
from capgate.sandbox.base import RiskClass
from capgate.taint.labels import BOTTOM_LABEL, Confidentiality, Integrity, Label

SESSION = "langgraph-approval"


def _label_public(_request: ToolCallRequest, arguments: JsonObject) -> dict[str, Label]:
    return {name: BOTTOM_LABEL for name in arguments}


def _pipeline(sink: SinkKind) -> DecisionPipeline:
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
            "file_issue": ToolMetadata(
                result_label=Label(Confidentiality.PUBLIC, Integrity.TRUSTED),
                risk_class=RiskClass.TRUSTED_DIRECT,
                sink=sink,
                capability="write:github.issue",
            ),
        },
        policy=parse_policy(
            """
agent: approval-graph
can: [read:private]
cannot: []
requires_approval: [write:github.issue]
"""
        ),
    )


def _build(
    tmp_path: Path,
    calls: list[tuple[str, str]],
    *,
    sink: SinkKind = SinkKind.NONE,
) -> tuple[Any, list[str], JsonlReceiptStore]:
    executed: list[str] = []

    @tool
    def read_private(payload: str = "") -> str:
        """Read synthetic private data."""

        executed.append("read_private")
        return "synthetic-secret"

    @tool
    def file_issue(payload: str = "") -> str:
        """Perform an action that requires human approval."""

        executed.append("file_issue")
        return f"filed: {payload}"

    store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
    mediator = ToolCallMediator(
        pipeline=_pipeline(sink),
        context=AgentContext(SESSION),
        receipt_writer=ReceiptWriter(store=store, signer=Ed25519Signer.generate()),
    )
    secure_tools = build_secure_tool_node(
        [read_private, file_issue],
        mediator=mediator,
        session_id=SESSION,
        label_arguments=_label_public,
        approve=interrupt_for_approval,
    )

    def planner(state: MessagesState) -> dict[str, list[BaseMessage]]:
        done = sum(1 for m in state["messages"] if isinstance(m, ToolMessage))
        if done >= len(calls):
            return {"messages": [AIMessage(content="complete")]}
        name, payload = calls[done]
        return {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        ToolCall(
                            name=name,
                            args={"payload": payload},
                            id=f"call-{done}",
                            type="tool_call",
                        )
                    ],
                )
            ]
        }

    def route(state: MessagesState) -> str:
        last = state["messages"][-1]
        if isinstance(last, AIMessage) and last.tool_calls:
            return "tools"
        return END

    builder = StateGraph(MessagesState)
    builder.add_node("planner", planner)
    builder.add_node("tools", secure_tools)
    builder.add_edge(START, "planner")
    builder.add_conditional_edges("planner", route)
    builder.add_edge("tools", "planner")
    graph = builder.compile(checkpointer=MemorySaver())
    return graph, executed, store


def _config(thread: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": thread}}


def test_approval_required_call_pauses_the_graph_before_execution(tmp_path: Path) -> None:
    graph, executed, _ = _build(tmp_path, [("file_issue", "ship it")])
    config = _config("pause")

    paused = cast(dict[str, Any], graph.invoke({"messages": []}, config))

    assert "__interrupt__" in paused
    payload = paused["__interrupt__"][0].value
    assert payload["capgate"]["verdict"] == "REQUIRE_APPROVAL"
    assert payload["capgate"]["rule_id"] == "policy.requires_approval.write:github.issue"
    assert executed == [], "the handler ran before a human answered"


def test_resuming_with_true_executes_the_call(tmp_path: Path) -> None:
    graph, executed, store = _build(tmp_path, [("file_issue", "ship it")])
    config = _config("approve")

    graph.invoke({"messages": []}, config)
    final = cast(dict[str, Any], graph.invoke(Command(resume=True), config))

    assert executed == ["file_issue"]
    messages = [m for m in final["messages"] if isinstance(m, ToolMessage)]
    assert messages[-1].status != "error"
    receipts = store.iter_receipts(SESSION)
    assert receipts[-1].rule_id == "policy.approval.granted"
    assert receipts[-1].verdict == "ALLOW"


def test_resuming_with_false_refuses_the_call(tmp_path: Path) -> None:
    graph, executed, store = _build(tmp_path, [("file_issue", "ship it")])
    config = _config("deny")

    graph.invoke({"messages": []}, config)
    final = cast(dict[str, Any], graph.invoke(Command(resume=False), config))

    assert executed == []
    messages = [m for m in final["messages"] if isinstance(m, ToolMessage)]
    assert messages[-1].status == "error"
    receipts = store.iter_receipts(SESSION)
    assert receipts[-1].rule_id == "policy.approval.denied"
    assert receipts[-1].verdict == "BLOCK"


@pytest.mark.parametrize(
    "answer",
    [pytest.param("yes", id="truthy-string"), pytest.param(1, id="truthy-int")],
)
def test_only_exact_true_resumes_into_execution(tmp_path: Path, answer: object) -> None:
    graph, executed, _ = _build(tmp_path, [("file_issue", "ship it")])
    config = _config(f"loose-{answer!r}")

    graph.invoke({"messages": []}, config)
    graph.invoke(Command(resume=answer), config)

    assert executed == []


def test_human_approval_cannot_override_a_flow_rule(tmp_path: Path) -> None:
    """The property worth demonstrating: a human may authorise an action, not a leak."""

    graph, executed, store = _build(
        tmp_path,
        [("read_private", ""), ("file_issue", "leak")],
        sink=SinkKind.NETWORK_EXTERNAL,
    )
    config = _config("flow")

    graph.invoke({"messages": []}, config)
    final = cast(dict[str, Any], graph.invoke(Command(resume=True), config))

    assert executed == ["read_private"], "the approved call still reached its handler"
    messages = [m for m in final["messages"] if isinstance(m, ToolMessage)]
    assert messages[-1].status == "error"
    receipts = store.iter_receipts(SESSION)
    assert receipts[-1].rule_id == "flow.deny.secrets_to_network_external"
