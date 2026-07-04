from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Annotated, Any, cast

import pytest
from langchain_core.messages import AIMessage, ToolCall, ToolMessage
from langchain_core.tools import StructuredTool, tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import InjectedState, ToolNode
from langgraph.prebuilt.tool_node import ToolCallRequest
from pydantic import BaseModel, field_validator

from capgate.adapters.langgraph import build_secure_tool_node
from capgate.engine.context import AgentContext
from capgate.engine.mediator import ToolCallMediator
from capgate.engine.pipeline import DecisionPipeline, ToolMetadata
from capgate.flow.sinks import SinkKind
from capgate.policy import parse_policy
from capgate.proxy.events import JsonObject, JsonValue
from capgate.receipts.model import hash_json
from capgate.receipts.replay import replay_session
from capgate.receipts.signer import Ed25519Signer, ReceiptWriter
from capgate.receipts.store import JsonlReceiptStore
from capgate.sandbox.base import RiskClass
from capgate.taint.labels import BOTTOM_LABEL, Confidentiality, Integrity, Label

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO = REPO_ROOT / "examples" / "langgraph_security_demo.py"
MARKER = "CAPGATE_LANGGRAPH_PRIVATE_MARKER_42b7d1"
SCOPE = "offline LangGraph control validation, not model or production-isolation evidence"


def test_real_langgraph_demo_blocks_exfiltration_without_api_or_network() -> None:
    completed = subprocess.run(
        [sys.executable, str(DEMO)],
        cwd=REPO_ROOT,
        env={},
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert len(completed.stdout.splitlines()) == 1
    assert MARKER not in completed.stdout
    assert MARKER not in completed.stderr
    assert _json_object(completed.stdout) == {
        "scope": SCOPE,
        "compiled_state_graph": True,
        "real_tool_node": True,
        "public_status": "ALLOW",
        "read_private": "ALLOW",
        "send_external": "BLOCK",
        "send_rule_id": "flow.lethal_trifecta",
        "send_reached_sink": False,
        "receipt_count": 3,
        "receipts_replayed": True,
        "raw_marker_in_receipts": False,
        "model_api_used": False,
        "network_used": False,
    }


def test_real_tool_node_short_circuits_approval_and_unknown_tools(tmp_path: Path) -> None:
    executed = 0

    @tool
    def approval_action(payload: str) -> str:
        """Represent an action that requires human approval."""

        nonlocal executed
        executed += 1
        return payload

    signer = Ed25519Signer.generate()
    store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
    session_id = "langgraph-policy-test"
    pipeline = DecisionPipeline(
        {
            "approval_action": ToolMetadata(
                result_label=Label(Confidentiality.PUBLIC, Integrity.TRUSTED),
                risk_class=RiskClass.TRUSTED_DIRECT,
                capability="send:external",
            )
        },
        policy=parse_policy(
            """
agent: langgraph-test
can: []
cannot: []
requires_approval: [send:external]
"""
        ),
    )
    mediator = ToolCallMediator(
        pipeline=pipeline,
        context=AgentContext(session_id),
        receipt_writer=ReceiptWriter(store=store, signer=signer),
    )
    secured_tools = build_secure_tool_node(
        [approval_action],
        mediator=mediator,
        session_id=session_id,
        label_arguments=_label_public_arguments,
    )
    graph = _compile_tool_graph(secured_tools)

    approval_state = _invoke_calls(
        graph,
        [
            ToolCall(
                name="approval_action",
                args={"payload": "synthetic"},
                id="approval-1",
                type="tool_call",
            )
        ],
    )
    unknown_state = _invoke_calls(
        graph,
        [ToolCall(name="unknown", args={}, id="unknown-1", type="tool_call")],
    )
    approval = approval_state["messages"][-1]
    unknown = unknown_state["messages"][-1]

    assert executed == 0
    assert isinstance(approval, ToolMessage)
    assert approval.status == "error"
    assert approval.tool_call_id == "approval-1"
    assert approval.artifact == {
        "capgate": {
            "verdict": "REQUIRE_APPROVAL",
            "rule_id": "policy.requires_approval.send:external",
            "execution_started": False,
        }
    }
    assert isinstance(unknown, ToolMessage)
    assert unknown.status == "error"
    assert unknown.tool_call_id == "unknown-1"
    assert unknown.artifact == {
        "capgate": {
            "verdict": "BLOCK",
            "rule_id": "engine.unknown_tool",
            "execution_started": False,
        }
    }
    receipts = replay_session(store.path, session_id, signer.verifier()).receipts
    assert [receipt.verdict for receipt in receipts] == ["REQUIRE_APPROVAL", "BLOCK"]


def test_first_turn_private_argument_is_blocked_before_external_sink(tmp_path: Path) -> None:
    sink_calls = 0

    @tool
    def send_external(payload: str) -> str:
        """Represent a synthetic external sink."""

        nonlocal sink_calls
        sink_calls += 1
        return payload

    session_id = "langgraph-private-argument"
    signer = Ed25519Signer.generate()
    store = JsonlReceiptStore(tmp_path / "private-argument.jsonl")
    mediator = ToolCallMediator(
        pipeline=DecisionPipeline(
            {
                "send_external": ToolMetadata(
                    result_label=Label(Confidentiality.PUBLIC, Integrity.TRUSTED),
                    risk_class=RiskClass.TRUSTED_DIRECT,
                    sink=SinkKind.NETWORK_EXTERNAL,
                )
            }
        ),
        context=AgentContext(session_id),
        receipt_writer=ReceiptWriter(store=store, signer=signer),
    )

    def label_private(
        _: ToolCallRequest,
        arguments: JsonObject,
    ) -> dict[str, Label]:
        return {
            name: Label(Confidentiality.SECRET, Integrity.UNTRUSTED)
            for name in arguments
        }

    graph = _compile_tool_graph(
        build_secure_tool_node(
            [send_external],
            mediator=mediator,
            session_id=session_id,
            label_arguments=label_private,
        )
    )
    state = _invoke_calls(
        graph,
        [
            ToolCall(
                name="send_external",
                args={"payload": "SYNTHETIC_PRIVATE"},
                id="private-1",
                type="tool_call",
            )
        ],
    )
    result = state["messages"][-1]

    assert sink_calls == 0
    assert isinstance(result, ToolMessage)
    assert result.artifact == {
        "capgate": {
            "verdict": "BLOCK",
            "rule_id": "flow.lethal_trifecta",
            "execution_started": False,
        }
    }
    receipt = replay_session(store.path, session_id, signer.verifier()).receipts[0]
    assert receipt.rule_id == "flow.lethal_trifecta"
    assert "SYNTHETIC_PRIVATE" not in store.path.read_text(encoding="utf-8")


def test_multi_call_turn_is_rejected_before_any_handler_runs(tmp_path: Path) -> None:
    executed: list[str] = []

    @tool
    def first() -> str:
        """First synthetic tool."""

        executed.append("first")
        return "first"

    @tool
    def second() -> str:
        """Second synthetic tool."""

        executed.append("second")
        return "second"

    session_id = "langgraph-multi-call"
    store = JsonlReceiptStore(tmp_path / "multi-call.jsonl")
    mediator = ToolCallMediator(
        pipeline=DecisionPipeline(
            {
                "first": _public_metadata(),
                "second": _public_metadata(),
            }
        ),
        context=AgentContext(session_id),
        receipt_writer=ReceiptWriter(store=store, signer=Ed25519Signer.generate()),
    )
    graph = _compile_tool_graph(
        build_secure_tool_node(
            [first, second],
            mediator=mediator,
            session_id=session_id,
            label_arguments=_label_public_arguments,
        )
    )

    with pytest.raises(ValueError, match="exactly one tool call"):
        _invoke_calls(
            graph,
            [
                ToolCall(name="first", args={}, id="first-1", type="tool_call"),
                ToolCall(name="second", args={}, id="second-1", type="tool_call"),
            ],
        )

    assert executed == []
    assert store.iter_receipts(session_id) == []


def test_injected_tool_arguments_are_rejected_when_node_is_built(tmp_path: Path) -> None:
    @tool
    def stateful(
        value: str,
        state: Annotated[dict[str, object], InjectedState],
    ) -> str:
        """Synthetic state-injected tool."""

        return value + str(len(state))

    @tool
    def hidden_runtime(runtime: Any) -> str:
        """Use LangGraph's reserved runtime parameter name."""

        return str(runtime)

    session_id = "langgraph-injected-state"
    mediator = ToolCallMediator(
        pipeline=DecisionPipeline({"stateful": _public_metadata()}),
        context=AgentContext(session_id),
        receipt_writer=ReceiptWriter(
            store=JsonlReceiptStore(tmp_path / "injected.jsonl"),
            signer=Ed25519Signer.generate(),
        ),
    )

    for injected_tool in (stateful, hidden_runtime):
        with pytest.raises(ValueError, match="injected LangGraph tool arguments"):
            build_secure_tool_node(
                [injected_tool],
                mediator=mediator,
                session_id=session_id,
                label_arguments=_label_public_arguments,
            )


def test_custom_schema_transform_is_rejected_before_execution(tmp_path: Path) -> None:
    executions = 0

    class IncrementingArguments(BaseModel):
        value: int

        @field_validator("value")
        @classmethod
        def increment(cls, value: int) -> int:
            return value + 1

    def transformed_handler(value: int) -> str:
        nonlocal executions
        executions += 1
        return str(value)

    transformed = StructuredTool.from_function(
        func=transformed_handler,
        name="transformed",
        description="Synthetic tool with a non-idempotent validator.",
        args_schema=IncrementingArguments,
    )
    session_id = "langgraph-custom-transform"
    mediator = ToolCallMediator(
        pipeline=DecisionPipeline({"transformed": _public_metadata()}),
        context=AgentContext(session_id),
        receipt_writer=ReceiptWriter(
            store=JsonlReceiptStore(tmp_path / "transformed.jsonl"),
            signer=Ed25519Signer.generate(),
        ),
    )

    with pytest.raises(ValueError, match="custom tool schema transforms"):
        build_secure_tool_node(
            [transformed],
            mediator=mediator,
            session_id=session_id,
            label_arguments=_label_public_arguments,
        )

    assert executions == 0


def test_schema_coercion_is_shared_by_receipt_and_handler(tmp_path: Path) -> None:
    observed: list[int] = []
    labeled: list[JsonObject] = []

    @tool
    def typed_tool(value: int) -> str:
        """Receive one integer after schema validation."""

        observed.append(value)
        return str(value)

    def label_validated(
        _: ToolCallRequest,
        arguments: JsonObject,
    ) -> dict[str, Label]:
        labeled.append(arguments)
        return {name: BOTTOM_LABEL for name in arguments}

    session_id = "langgraph-coercion"
    store = JsonlReceiptStore(tmp_path / "coercion.jsonl")
    mediator = ToolCallMediator(
        pipeline=DecisionPipeline({"typed_tool": _public_metadata()}),
        context=AgentContext(session_id),
        receipt_writer=ReceiptWriter(
            store=store,
            signer=Ed25519Signer.generate(),
        ),
    )
    graph = _compile_tool_graph(
        build_secure_tool_node(
            [typed_tool],
            mediator=mediator,
            session_id=session_id,
            label_arguments=label_validated,
        )
    )

    _invoke_calls(
        graph,
        [
            ToolCall(
                name="typed_tool",
                args={"value": "7"},
                id="typed-1",
                type="tool_call",
            )
        ],
    )

    assert observed == [7]
    assert labeled == [{"value": 7}]
    assert store.iter_receipts(session_id)[0].args_hash == hash_json({"value": 7})


def test_spoofed_tool_message_identity_fails_closed_after_execution(tmp_path: Path) -> None:
    executions = 0

    @tool
    def spoofed() -> ToolMessage:
        """Return a deliberately mismatched ToolMessage."""

        nonlocal executions
        executions += 1
        return ToolMessage(
            content="spoofed",
            name="different-tool",
            tool_call_id="different-call",
        )

    session_id = "langgraph-spoofed-result"
    store = JsonlReceiptStore(tmp_path / "spoofed.jsonl")
    mediator = ToolCallMediator(
        pipeline=DecisionPipeline({"spoofed": _public_metadata()}),
        context=AgentContext(session_id),
        receipt_writer=ReceiptWriter(
            store=store,
            signer=Ed25519Signer.generate(),
        ),
    )
    graph = _compile_tool_graph(
        build_secure_tool_node(
            [spoofed],
            mediator=mediator,
            session_id=session_id,
            label_arguments=_label_public_arguments,
        )
    )
    state = _invoke_calls(
        graph,
        [ToolCall(name="spoofed", args={}, id="expected-call", type="tool_call")],
    )
    result = state["messages"][-1]

    assert executions == 1
    assert isinstance(result, ToolMessage)
    assert result.tool_call_id == "expected-call"
    assert result.name == "spoofed"
    assert result.artifact == {
        "capgate": {
            "verdict": "BLOCK",
            "rule_id": "mediator.result_invalid",
            "execution_started": True,
        }
    }
    assert store.iter_receipts(session_id)[0].rule_id == "mediator.result_invalid"


def _label_public_arguments(
    _: ToolCallRequest,
    arguments: JsonObject,
) -> dict[str, Label]:
    return {name: BOTTOM_LABEL for name in arguments}


def _public_metadata() -> ToolMetadata:
    return ToolMetadata(
        result_label=Label(Confidentiality.PUBLIC, Integrity.TRUSTED),
        risk_class=RiskClass.TRUSTED_DIRECT,
    )


def _compile_tool_graph(tool_node: ToolNode) -> Any:
    builder = StateGraph(MessagesState)
    builder.add_node("tools", tool_node)
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    return builder.compile()


def _invoke_calls(graph: Any, calls: list[ToolCall]) -> MessagesState:
    return cast(
        MessagesState,
        graph.invoke({"messages": [AIMessage(content="", tool_calls=calls)]}),
    )


def _json_object(text: str) -> dict[str, JsonValue]:
    decoded = cast(object, json.loads(text))
    assert isinstance(decoded, dict)
    assert all(isinstance(key, str) for key in decoded)
    return cast(dict[str, JsonValue], decoded)
