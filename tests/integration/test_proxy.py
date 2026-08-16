from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

from capgate.engine.context import AgentContext
from capgate.engine.decision import Decision
from capgate.engine.pipeline import DecisionPipeline, ToolMetadata
from capgate.flow.sinks import SinkKind
from capgate.mcp_security.isolation import ServerToolRegistry
from capgate.mcp_security.pinning import ToolPinRegistry
from capgate.policy import parse_policy
from capgate.proxy.client import StdioJsonRpcClient
from capgate.proxy.events import JsonObject, ToolCallEvent
from capgate.proxy.sandbox import SandboxCallExecutor
from capgate.proxy.session import ProxySession
from capgate.receipts.model import hash_json
from capgate.receipts.replay import replay_session
from capgate.receipts.signer import Ed25519Signer, Ed25519Verifier, ReceiptWriter
from capgate.receipts.store import JsonlReceiptStore
from capgate.sandbox.base import ExecResult, ExecSpec, RiskClass, SandboxBackend
from capgate.sandbox.limits import SandboxLimits, SessionBudget
from capgate.taint.labels import Confidentiality, Integrity, Label


class RecordingDownstream:
    def __init__(self) -> None:
        self.calls = 0

    async def request(self, message: JsonObject) -> JsonObject:
        self.calls += 1
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"ok": True}}


class FailingDownstream:
    async def request(self, message: JsonObject) -> JsonObject:
        _ = message
        raise RuntimeError("sensitive downstream failure")


class FailingDecisionPipeline(DecisionPipeline):
    def decide(
        self,
        context: AgentContext,
        event: ToolCallEvent,
        *,
        approved: bool = False,
    ) -> Decision:
        _ = context, event, approved
        raise RuntimeError("sensitive internal failure")


class MutableToolListDownstream:
    def __init__(self, description: str = "Original description") -> None:
        self.description = description
        self.methods: list[str] = []

    async def request(self, message: JsonObject) -> JsonObject:
        method = message.get("method")
        self.methods.append(method if isinstance(method, str) else "<unknown>")
        if method != "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {"ok": True},
            }
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "tools": [
                    {
                        "name": "shared_tool",
                        "description": self.description,
                        "inputSchema": {"type": "object"},
                    }
                ]
            },
        }


class StaticResponseDownstream:
    def __init__(self, response: JsonObject) -> None:
        self.response = response
        self.calls = 0

    async def request(self, message: JsonObject) -> JsonObject:
        _ = message
        self.calls += 1
        return self.response


class RecordingSandbox:
    def __init__(self, backend: SandboxBackend, result: ExecResult) -> None:
        self.backend = backend
        self.result = result
        self.calls = 0

    async def run(self, spec: ExecSpec) -> ExecResult:
        _ = spec
        self.calls += 1
        return self.result


def _sandbox_limits(*, max_tool_calls: int = 10) -> SandboxLimits:
    return SandboxLimits(
        cpu_millis=1_000,
        memory_bytes=64 * 1024 * 1024,
        swap_bytes=1,
        process_count=8,
        wall_time_millis=1_000,
        writable_bytes=1024,
        output_bytes=1024,
        max_tool_calls=max_tool_calls,
        max_tokens=100,
        max_cost_micros=100,
    )


def _sandbox_spec(risk_class: RiskClass) -> ExecSpec:
    return ExecSpec(
        argv=("tool",),
        stdin=b"request",
        image_digest="sha256:" + "a" * 64,
        risk_class=risk_class,
        limits=_sandbox_limits(),
    )


def _sandbox_pipeline(risk_class: RiskClass) -> DecisionPipeline:
    return DecisionPipeline(
        {
            "tool": ToolMetadata(
                result_label=Label(Confidentiality.PUBLIC, Integrity.TRUSTED),
                risk_class=risk_class,
            )
        }
    )


def _error_data(response: JsonObject | None) -> JsonObject:
    assert response is not None
    error = response.get("error")
    assert isinstance(error, dict)
    data = error.get("data")
    assert isinstance(data, dict)
    return data


def test_stdio_client_round_trips_json_rpc_to_downstream() -> None:
    async def run() -> None:
        client = StdioJsonRpcClient([sys.executable, "tests/fixtures/echo_mcp_server.py"])
        await client.start()
        try:
            message: JsonObject = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            response = await client.request(message)
        finally:
            await client.close()

        assert response == {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Echo arguments.",
                        "inputSchema": {"type": "object"},
                    }
                ]
            },
        }

    asyncio.run(run())


def test_proxy_forwards_tool_call_and_records_receipt(tmp_path: Path) -> None:
    async def run() -> tuple[JsonObject | None, Path, Ed25519Signer]:
        signer = Ed25519Signer.generate()
        store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
        writer = ReceiptWriter(store=store, signer=signer)
        client = StdioJsonRpcClient([sys.executable, "tests/fixtures/echo_mcp_server.py"])
        await client.start()
        try:
            session = ProxySession(
                downstream=client,
                receipt_writer=writer,
                server_name="echo-server",
                session_id="session-1",
            )
            message: JsonObject = {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"value": "hello"}},
            }
            response = await session.handle_message(message)
        finally:
            await client.close()
        return response, store.path, signer

    response, receipt_log, signer = asyncio.run(run())

    assert response == {
        "jsonrpc": "2.0",
        "id": 9,
        "result": {"content": [{"type": "text", "text": '{"value": "hello"}'}]},
    }
    report = replay_session(receipt_log, "session-1", signer.verifier())
    assert len(report.receipts) == 1
    receipt = report.receipts[0]
    assert receipt.server == "echo-server"
    assert receipt.tool == "echo"
    assert receipt.verdict == "ALLOW"
    assert receipt.reason == "passthrough (stage0)"


def test_proxy_blocks_private_untrusted_flow_before_external_call(tmp_path: Path) -> None:
    async def run() -> tuple[JsonObject | None, Path, Ed25519Signer]:
        signer = Ed25519Signer.generate()
        store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
        writer = ReceiptWriter(store=store, signer=signer)
        client = StdioJsonRpcClient([sys.executable, "tests/fixtures/echo_mcp_server.py"])
        pipeline = DecisionPipeline(
            {
                "read_private": ToolMetadata(
                    result_label=Label(
                        Confidentiality.INTERNAL,
                        Integrity.UNTRUSTED,
                        frozenset({"mcp:test"}),
                    ),
                    risk_class=RiskClass.TRUSTED_DIRECT,
                ),
                "send_external": ToolMetadata(
                    result_label=Label(
                        Confidentiality.PUBLIC,
                        Integrity.UNTRUSTED,
                        frozenset({"mcp:test"}),
                    ),
                    risk_class=RiskClass.FIXED_RISKY,
                    sink=SinkKind.NETWORK_EXTERNAL,
                ),
            }
        )
        await client.start()
        try:
            session = ProxySession(
                downstream=client,
                receipt_writer=writer,
                server_name="echo-server",
                session_id="session-1",
                decision_pipeline=pipeline,
                require_tool_discovery=False,
            )
            await session.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "read_private", "arguments": {}},
                }
            )
            blocked_response = await session.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "send_external", "arguments": {"value": "private"}},
                }
            )
        finally:
            await client.close()
        return blocked_response, store.path, signer

    response, receipt_log, signer = asyncio.run(run())

    assert response is not None
    assert "result" not in response
    error = response["error"]
    assert isinstance(error, dict)
    assert error["code"] == -32001
    report = replay_session(receipt_log, "session-1", signer.verifier())
    assert [receipt.verdict for receipt in report.receipts] == ["ALLOW", "BLOCK"]
    assert report.receipts[-1].rule_id == "flow.lethal_trifecta"


def test_proxy_does_not_execute_approval_required_call(tmp_path: Path) -> None:
    async def run() -> tuple[JsonObject | None, RecordingDownstream, Path, Ed25519Signer]:
        signer = Ed25519Signer.generate()
        store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
        downstream = RecordingDownstream()
        pipeline = DecisionPipeline(
            {
                "send": ToolMetadata(
                    result_label=Label(Confidentiality.PUBLIC, Integrity.TRUSTED),
                    risk_class=RiskClass.FIXED_RISKY,
                    capability="send:email.external",
                )
            },
            policy=parse_policy(
                "agent: test\nrequires_approval: [send:email.external]\ncan: []\ncannot: []"
            ),
        )
        session = ProxySession(
            downstream=downstream,
            receipt_writer=ReceiptWriter(store=store, signer=signer),
            server_name="test-server",
            session_id="session-1",
            decision_pipeline=pipeline,
            require_tool_discovery=False,
        )
        response = await session.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "send", "arguments": {}},
            }
        )
        return response, downstream, store.path, signer

    response, downstream, receipt_log, signer = asyncio.run(run())

    assert downstream.calls == 0
    assert response is not None and "error" in response
    receipt = replay_session(receipt_log, "session-1", signer.verifier()).receipts[0]
    assert receipt.verdict == "REQUIRE_APPROVAL"


def test_proxy_decision_exception_blocks_without_exposing_error(tmp_path: Path) -> None:
    async def run() -> tuple[JsonObject | None, RecordingDownstream, Path, Ed25519Signer]:
        signer = Ed25519Signer.generate()
        store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
        downstream = RecordingDownstream()
        session = ProxySession(
            downstream=downstream,
            receipt_writer=ReceiptWriter(store=store, signer=signer),
            server_name="test-server",
            session_id="session-1",
            decision_pipeline=FailingDecisionPipeline({}),
            require_tool_discovery=False,
        )
        response = await session.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "tool", "arguments": {}},
            }
        )
        return response, downstream, store.path, signer

    response, downstream, receipt_log, signer = asyncio.run(run())

    assert downstream.calls == 0
    assert response is not None and "sensitive internal failure" not in str(response)
    receipt = replay_session(receipt_log, "session-1", signer.verifier()).receipts[0]
    assert receipt.verdict == "BLOCK"
    assert receipt.rule_id == "engine.decision_error"
    assert "sensitive internal failure" not in receipt.reason


def test_proxy_downstream_exception_produces_block_receipt(tmp_path: Path) -> None:
    async def run() -> tuple[JsonObject | None, Path, Ed25519Signer]:
        signer = Ed25519Signer.generate()
        store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
        session = ProxySession(
            downstream=FailingDownstream(),
            receipt_writer=ReceiptWriter(store=store, signer=signer),
            server_name="test-server",
            session_id="session-1",
        )
        response = await session.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "tool", "arguments": {}},
            }
        )
        return response, store.path, signer

    response, receipt_log, signer = asyncio.run(run())

    assert response is not None and "sensitive downstream failure" not in str(response)
    receipt = replay_session(receipt_log, "session-1", signer.verifier()).receipts[0]
    assert receipt.verdict == "BLOCK"
    assert receipt.rule_id == "proxy.downstream_error"


def test_cli_proxy_loads_policy_and_blocks_before_downstream(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "agent: cli-test\ncan: []\ncannot: [read:echo]\nrequires_approval: []\n",
        encoding="utf-8",
    )
    metadata = tmp_path / "tools.yaml"
    metadata.write_text(
        """
tools:
  echo:
    capability: read:echo
    confidentiality: public
    integrity: untrusted
    risk_class: trusted_direct
""",
        encoding="utf-8",
    )
    receipt_log = tmp_path / "receipts.jsonl"
    public_key = tmp_path / "ed25519.public"
    list_message: JsonObject = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/list",
    }
    message: JsonObject = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"value": "blocked"}},
    }

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "capgate",
            "proxy",
            "--policy-file",
            str(policy),
            "--tool-metadata-file",
            str(metadata),
            "--receipt-log",
            str(receipt_log),
            "--key-file",
            str(tmp_path / "ed25519.private"),
            "--public-key-file",
            str(public_key),
            "--tool-pin-db",
            str(tmp_path / "tool-pins.sqlite3"),
            "--downstream",
            sys.executable,
            "tests/fixtures/echo_mcp_server.py",
        ],
        input=json.dumps(list_message) + "\n" + json.dumps(message) + "\n",
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    responses = [json.loads(line) for line in completed.stdout.splitlines()]
    response = responses[-1]
    assert response["error"]["data"]["rule_id"] == "policy.cannot.read:echo"
    verifier = Ed25519Verifier.from_public_key_file(public_key)
    stored = JsonlReceiptStore(receipt_log).iter_receipts()
    receipt = replay_session(receipt_log, stored[0].session_id, verifier)
    assert [item.verdict for item in receipt.receipts] == ["ALLOW", "BLOCK"]


def test_proxy_blocks_changed_tool_definition(tmp_path: Path) -> None:
    async def run() -> JsonObject | None:
        downstream = MutableToolListDownstream()
        session = ProxySession(
            downstream=downstream,
            receipt_writer=ReceiptWriter(
                store=JsonlReceiptStore(tmp_path / "receipts.jsonl"),
                signer=Ed25519Signer.generate(),
            ),
            server_name="server-a",
            tool_pin_registry=ToolPinRegistry(),
        )
        message: JsonObject = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        first = await session.handle_message(message)
        assert first is not None and "result" in first
        downstream.description = "Changed description"
        return await session.handle_message(message)

    response = asyncio.run(run())

    assert response is not None
    error = response["error"]
    assert isinstance(error, dict)
    assert error["data"] == {"rule_id": "mcp.tool_definition_changed"}
    receipts = JsonlReceiptStore(tmp_path / "receipts.jsonl").iter_receipts()
    assert [receipt.verdict for receipt in receipts] == ["ALLOW", "BLOCK"]


def test_enforcement_requires_a_fully_accepted_tool_catalog(tmp_path: Path) -> None:
    async def run() -> tuple[list[JsonObject | None], MutableToolListDownstream]:
        downstream = MutableToolListDownstream()
        session = ProxySession(
            downstream=downstream,
            receipt_writer=ReceiptWriter(
                store=JsonlReceiptStore(tmp_path / "receipts.jsonl"),
                signer=Ed25519Signer.generate(),
            ),
            server_name="server-a",
            session_id="session",
            decision_pipeline=DecisionPipeline(
                {
                    "shared_tool": ToolMetadata(
                        result_label=Label(Confidentiality.PUBLIC, Integrity.TRUSTED),
                        risk_class=RiskClass.TRUSTED_DIRECT,
                    )
                }
            ),
            tool_pin_registry=ToolPinRegistry(),
            server_tool_registry=ServerToolRegistry(),
        )
        call: JsonObject = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "shared_tool", "arguments": {}},
        }
        listing: JsonObject = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        before_list = await session.handle_message(call)
        accepted_list = await session.handle_message(listing)
        allowed_call = await session.handle_message(call)
        downstream.description = "Changed description"
        rejected_list = await session.handle_message(listing)
        after_rejected_list = await session.handle_message(call)
        return (
            [before_list, accepted_list, allowed_call, rejected_list, after_rejected_list],
            downstream,
        )

    responses, downstream = asyncio.run(run())

    assert _error_data(responses[0]) == {"rule_id": "mcp.tool_not_discovered"}
    assert responses[1] is not None and "result" in responses[1]
    assert responses[2] is not None and responses[2].get("result") == {"ok": True}
    assert _error_data(responses[3]) == {"rule_id": "mcp.tool_definition_changed"}
    assert _error_data(responses[4]) == {"rule_id": "mcp.tool_not_discovered"}
    assert downstream.methods == ["tools/list", "tools/call", "tools/list"]


@pytest.mark.parametrize("method", ["resources/read", "prompts/get", "custom/write"])
def test_enforcement_blocks_unmediated_methods_with_a_receipt(
    tmp_path: Path,
    method: str,
) -> None:
    downstream = RecordingDownstream()

    async def run() -> JsonObject | None:
        session = ProxySession(
            downstream=downstream,
            receipt_writer=ReceiptWriter(
                store=JsonlReceiptStore(tmp_path / "receipts.jsonl"),
                signer=Ed25519Signer.generate(),
            ),
            server_name="server",
            session_id="session",
            decision_pipeline=_sandbox_pipeline(RiskClass.TRUSTED_DIRECT),
        )
        return await session.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": {"uri": "file:///private"},
            }
        )

    response = asyncio.run(run())

    assert downstream.calls == 0
    assert _error_data(response) == {"rule_id": "proxy.unmediated_method"}
    receipt = JsonlReceiptStore(tmp_path / "receipts.jsonl").iter_receipts()[0]
    assert receipt.verdict == "BLOCK"
    assert receipt.tool == f"rpc:{method}"


def test_enforcement_blocks_non_string_method_without_crashing(tmp_path: Path) -> None:
    downstream = RecordingDownstream()

    async def run() -> JsonObject | None:
        session = ProxySession(
            downstream=downstream,
            receipt_writer=ReceiptWriter(
                store=JsonlReceiptStore(tmp_path / "receipts.jsonl"),
                signer=Ed25519Signer.generate(),
            ),
            server_name="server",
            session_id="session",
            decision_pipeline=_sandbox_pipeline(RiskClass.TRUSTED_DIRECT),
        )
        return await session.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": ["tools/call"]}
        )

    response = asyncio.run(run())

    assert downstream.calls == 0
    assert _error_data(response) == {"rule_id": "proxy.unmediated_method"}
    receipt = JsonlReceiptStore(tmp_path / "receipts.jsonl").iter_receipts()[0]
    assert receipt.verdict == "BLOCK"


def test_enforcement_forwards_required_control_method(tmp_path: Path) -> None:
    downstream = RecordingDownstream()

    async def run() -> JsonObject | None:
        session = ProxySession(
            downstream=downstream,
            receipt_writer=ReceiptWriter(
                store=JsonlReceiptStore(tmp_path / "receipts.jsonl"),
                signer=Ed25519Signer.generate(),
            ),
            server_name="server",
            decision_pipeline=_sandbox_pipeline(RiskClass.TRUSTED_DIRECT),
        )
        return await session.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1.0"},
                },
            }
        )

    response = asyncio.run(run())

    assert downstream.calls == 1
    assert response is not None and response.get("result") == {"ok": True}


@pytest.mark.parametrize(
    "message",
    [
        {"jsonrpc": "1.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "method": "ping"},
        {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": None},
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        },
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "logging/setLevel",
            "params": {"level": "verbose"},
        },
        {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {},
        },
        {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {"progressToken": "task", "progress": True},
        },
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "notifications/initialized",
        },
        {"jsonrpc": "2.0", "id": 1, "method": "ping", "unexpected": True},
    ],
)
def test_enforcement_rejects_malformed_control_messages_with_receipt(
    tmp_path: Path,
    message: JsonObject,
) -> None:
    downstream = RecordingDownstream()

    async def run() -> JsonObject | None:
        session = ProxySession(
            downstream=downstream,
            receipt_writer=ReceiptWriter(
                store=JsonlReceiptStore(tmp_path / "receipts.jsonl"),
                signer=Ed25519Signer.generate(),
            ),
            server_name="server",
            session_id="session",
            decision_pipeline=_sandbox_pipeline(RiskClass.TRUSTED_DIRECT),
        )
        return await session.handle_message(message)

    response = asyncio.run(run())

    assert downstream.calls == 0
    if "id" in message:
        assert _error_data(response) == {"rule_id": "proxy.invalid_control_request"}
    else:
        assert response is None
    receipt = JsonlReceiptStore(tmp_path / "receipts.jsonl").iter_receipts()[0]
    assert receipt.verdict == "BLOCK"
    assert receipt.rule_id == "proxy.invalid_control_request"


def test_proxy_rejects_malformed_arguments_before_forwarding(tmp_path: Path) -> None:
    downstream = RecordingDownstream()
    message: JsonObject = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "tool", "arguments": ["private-value"]},
    }

    async def run() -> JsonObject | None:
        session = ProxySession(
            downstream=downstream,
            receipt_writer=ReceiptWriter(
                store=JsonlReceiptStore(tmp_path / "receipts.jsonl"),
                signer=Ed25519Signer.generate(),
            ),
            server_name="server",
            session_id="session",
        )
        return await session.handle_message(message)

    response = asyncio.run(run())

    assert downstream.calls == 0
    assert _error_data(response) == {"rule_id": "proxy.invalid_tool_request"}
    receipt = JsonlReceiptStore(tmp_path / "receipts.jsonl").iter_receipts()[0]
    assert receipt.args_hash == hash_json({"request": message})
    assert receipt.args_hash != hash_json({})


def test_proxy_rejects_mismatched_downstream_response(tmp_path: Path) -> None:
    downstream = StaticResponseDownstream(
        {"jsonrpc": "2.0", "id": 999, "result": {"private": "value"}}
    )

    async def run() -> JsonObject | None:
        session = ProxySession(
            downstream=downstream,
            receipt_writer=ReceiptWriter(
                store=JsonlReceiptStore(tmp_path / "receipts.jsonl"),
                signer=Ed25519Signer.generate(),
            ),
            server_name="server",
            session_id="session",
        )
        return await session.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "tool", "arguments": {}},
            }
        )

    response = asyncio.run(run())

    assert downstream.calls == 1
    assert _error_data(response) == {"rule_id": "proxy.downstream_error"}
    receipt = JsonlReceiptStore(tmp_path / "receipts.jsonl").iter_receipts()[0]
    assert receipt.verdict == "BLOCK"
    assert receipt.rule_id == "proxy.downstream_error"


def test_proxy_blocks_cross_server_tool_shadowing(tmp_path: Path) -> None:
    async def run() -> JsonObject | None:
        registry = ServerToolRegistry()
        message: JsonObject = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        first = ProxySession(
            downstream=MutableToolListDownstream(),
            receipt_writer=ReceiptWriter(
                store=JsonlReceiptStore(tmp_path / "first.jsonl"),
                signer=Ed25519Signer.generate(),
            ),
            server_name="server-a",
            server_tool_registry=registry,
        )
        second = ProxySession(
            downstream=MutableToolListDownstream(),
            receipt_writer=ReceiptWriter(
                store=JsonlReceiptStore(tmp_path / "second.jsonl"),
                signer=Ed25519Signer.generate(),
            ),
            server_name="server-b",
            server_tool_registry=registry,
        )
        first_response = await first.handle_message(message)
        assert first_response is not None and "result" in first_response
        return await second.handle_message(message)

    response = asyncio.run(run())

    assert response is not None
    error = response["error"]
    assert isinstance(error, dict)
    assert error["data"] == {"rule_id": "mcp.tool_shadow"}
    receipts = JsonlReceiptStore(tmp_path / "second.jsonl").iter_receipts()
    assert len(receipts) == 1
    assert receipts[0].verdict == "BLOCK"


@pytest.mark.parametrize(
    ("risk_class", "backend"),
    [
        (RiskClass.FIXED_RISKY, SandboxBackend.GVISOR),
        (RiskClass.GENERATED_CODE, SandboxBackend.FIRECRACKER),
    ],
)
def test_proxy_routes_risky_calls_only_to_required_sandbox(
    tmp_path: Path,
    risk_class: RiskClass,
    backend: SandboxBackend,
) -> None:
    async def run() -> tuple[JsonObject | None, RecordingDownstream, RecordingSandbox]:
        downstream = RecordingDownstream()
        sandbox = RecordingSandbox(
            backend,
            ExecResult(
                backend=backend,
                exit_code=0,
                stdout=b'{"jsonrpc":"2.0","id":1,"result":{"isolated":true}}',
                stderr=b"",
            ),
        )
        executor = SandboxCallExecutor(
            sandbox,
            lambda message, event: _sandbox_spec(risk_class),
        )
        session = ProxySession(
            downstream=downstream,
            receipt_writer=ReceiptWriter(
                store=JsonlReceiptStore(tmp_path / "receipts.jsonl"),
                signer=Ed25519Signer.generate(),
            ),
            server_name="server",
            session_id="session",
            decision_pipeline=_sandbox_pipeline(risk_class),
            sandbox_executors={backend: executor},
            require_tool_discovery=False,
        )
        response = await session.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "tool", "arguments": {}},
            }
        )
        return response, downstream, sandbox

    response, downstream, sandbox = asyncio.run(run())

    assert response == {"jsonrpc": "2.0", "id": 1, "result": {"isolated": True}}
    assert downstream.calls == 0
    assert sandbox.calls == 1
    receipt = JsonlReceiptStore(tmp_path / "receipts.jsonl").iter_receipts()[0]
    assert receipt.verdict == "ALLOW"
    assert backend.value in receipt.reason
    assert receipt.sandbox is not None
    assert receipt.sandbox.backend == backend.value
    assert receipt.sandbox.status == "completed"
    assert receipt.sandbox.image_digest == "sha256:" + "a" * 64
    assert receipt.signature is not None


def test_proxy_blocks_risky_call_when_required_executor_is_missing(tmp_path: Path) -> None:
    downstream = RecordingDownstream()

    async def run() -> JsonObject | None:
        session = ProxySession(
            downstream=downstream,
            receipt_writer=ReceiptWriter(
                store=JsonlReceiptStore(tmp_path / "receipts.jsonl"),
                signer=Ed25519Signer.generate(),
            ),
            server_name="server",
            session_id="session",
            decision_pipeline=_sandbox_pipeline(RiskClass.FIXED_RISKY),
            require_tool_discovery=False,
        )
        return await session.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "tool", "arguments": {}},
            }
        )

    response = asyncio.run(run())

    assert downstream.calls == 0
    assert response is not None
    receipt = JsonlReceiptStore(tmp_path / "receipts.jsonl").iter_receipts()[0]
    assert receipt.verdict == "BLOCK"
    assert receipt.rule_id == "sandbox.call.unavailable"
    assert receipt.sandbox is not None
    assert receipt.sandbox.backend == "gvisor"
    assert receipt.sandbox.status == "unavailable"
    assert receipt.sandbox.image_digest is None
    assert receipt.signature is not None


@pytest.mark.parametrize(
    ("result", "rule_id"),
    [
        (
            ExecResult(SandboxBackend.FIRECRACKER, 0, b"{}", b""),
            "sandbox.call.backend_mismatch",
        ),
        (
            ExecResult(SandboxBackend.GVISOR, None, b"", b"", timed_out=True),
            "sandbox.call.timeout",
        ),
        (
            ExecResult(
                SandboxBackend.GVISOR,
                None,
                b"",
                b"",
                output_limit_exceeded=True,
            ),
            "sandbox.call.output_limit",
        ),
        (
            ExecResult(SandboxBackend.GVISOR, 9, b"", b""),
            "sandbox.call.execution_failed",
        ),
        (
            ExecResult(SandboxBackend.GVISOR, 0, b"sensitive malformed output", b""),
            "sandbox.call.response_invalid",
        ),
    ],
)
def test_proxy_sandbox_failures_block_without_raw_fallback_and_are_receipted(
    tmp_path: Path,
    result: ExecResult,
    rule_id: str,
) -> None:
    downstream = RecordingDownstream()

    async def run() -> JsonObject | None:
        sandbox = RecordingSandbox(SandboxBackend.GVISOR, result)
        executor = SandboxCallExecutor(
            sandbox,
            lambda message, event: _sandbox_spec(RiskClass.FIXED_RISKY),
        )
        session = ProxySession(
            downstream=downstream,
            receipt_writer=ReceiptWriter(
                store=JsonlReceiptStore(tmp_path / "receipts.jsonl"),
                signer=Ed25519Signer.generate(),
            ),
            server_name="server",
            session_id="session",
            decision_pipeline=_sandbox_pipeline(RiskClass.FIXED_RISKY),
            sandbox_executors={SandboxBackend.GVISOR: executor},
            require_tool_discovery=False,
        )
        return await session.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "tool", "arguments": {}},
            }
        )

    response = asyncio.run(run())

    assert downstream.calls == 0
    assert response is not None and "sensitive malformed output" not in str(response)
    receipt = JsonlReceiptStore(tmp_path / "receipts.jsonl").iter_receipts()[0]
    assert receipt.verdict == "BLOCK"
    assert receipt.rule_id == rule_id
    assert receipt.sandbox is not None
    assert receipt.sandbox.backend == "gvisor"
    assert receipt.sandbox.status == rule_id.removeprefix("sandbox.call.")
    assert receipt.signature is not None


def test_proxy_session_call_budget_blocks_before_second_execution(tmp_path: Path) -> None:
    downstream = RecordingDownstream()

    async def run() -> JsonObject | None:
        session = ProxySession(
            downstream=downstream,
            receipt_writer=ReceiptWriter(
                store=JsonlReceiptStore(tmp_path / "receipts.jsonl"),
                signer=Ed25519Signer.generate(),
            ),
            server_name="server",
            session_id="session",
            decision_pipeline=_sandbox_pipeline(RiskClass.TRUSTED_DIRECT),
            session_budget=SessionBudget(_sandbox_limits(max_tool_calls=1)),
            require_tool_discovery=False,
        )
        message: JsonObject = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "tool", "arguments": {}},
        }
        first = await session.handle_message(message)
        assert first is not None and "result" in first
        message["id"] = 2
        return await session.handle_message(message)

    response = asyncio.run(run())

    assert downstream.calls == 1
    assert response is not None and "error" in response
    receipts = JsonlReceiptStore(tmp_path / "receipts.jsonl").iter_receipts()
    assert [receipt.verdict for receipt in receipts] == ["ALLOW", "BLOCK"]
    assert receipts[-1].rule_id == "sandbox.budget.tool_calls_exhausted"


def test_proxy_receipts_tool_list_downstream_failure(tmp_path: Path) -> None:
    async def run() -> JsonObject | None:
        session = ProxySession(
            downstream=FailingDownstream(),
            receipt_writer=ReceiptWriter(
                store=JsonlReceiptStore(tmp_path / "receipts.jsonl"),
                signer=Ed25519Signer.generate(),
            ),
            server_name="server",
            session_id="session",
        )
        return await session.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        )

    response = asyncio.run(run())

    assert response is not None and "sensitive downstream failure" not in str(response)
    receipt = JsonlReceiptStore(tmp_path / "receipts.jsonl").iter_receipts()[0]
    assert receipt.verdict == "BLOCK"
    assert receipt.rule_id == "proxy.downstream_list_error"


def test_cli_proxy_persists_tool_definition_pin_across_restarts(tmp_path: Path) -> None:
    pin_db = tmp_path / "tool-pins.sqlite3"
    message = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n"

    def run(description: str, suffix: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "capgate",
                "proxy",
                "--server-name",
                "echo-server",
                "--tool-pin-db",
                str(pin_db),
                "--receipt-log",
                str(tmp_path / f"receipts-{suffix}.jsonl"),
                "--key-file",
                str(tmp_path / f"key-{suffix}.private"),
                "--public-key-file",
                str(tmp_path / f"key-{suffix}.public"),
                "--downstream",
                sys.executable,
                "tests/fixtures/echo_mcp_server.py",
                description,
            ],
            input=message,
            check=False,
            capture_output=True,
            text=True,
        )

    first = run("Original description", "first")
    second = run("Changed description", "second")

    assert first.returncode == 0, first.stderr
    assert "result" in json.loads(first.stdout)
    assert second.returncode == 0, second.stderr
    response = json.loads(second.stdout)
    assert response["error"]["data"] == {"rule_id": "mcp.tool_definition_changed"}
    receipts = JsonlReceiptStore(tmp_path / "receipts-second.jsonl").iter_receipts()
    assert len(receipts) == 1
    assert receipts[0].verdict == "BLOCK"
