from __future__ import annotations

import asyncio

import pytest

from capgate.proxy.events import JsonObject, ToolCallEvent
from capgate.proxy.sandbox import SandboxCallError, SandboxCallExecutor, SandboxCallFailure
from capgate.sandbox.base import (
    ExecResult,
    ExecSpec,
    RiskClass,
    SandboxBackend,
    SandboxUnavailable,
)
from capgate.sandbox.limits import SandboxLimits


def _limits() -> SandboxLimits:
    return SandboxLimits(
        cpu_millis=1_000,
        memory_bytes=64 * 1024 * 1024,
        swap_bytes=1,
        process_count=8,
        wall_time_millis=1_000,
        writable_bytes=1024,
        output_bytes=1024,
        max_tool_calls=10,
        max_tokens=100,
        max_cost_micros=100,
    )


def _event(request_id: int | None = 1) -> ToolCallEvent:
    return ToolCallEvent("session", "server", "tool", {}, {}, request_id)


def _message(request_id: int | None = 1) -> JsonObject:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "tool", "arguments": {}},
    }


def _spec(risk_class: RiskClass = RiskClass.FIXED_RISKY) -> ExecSpec:
    return ExecSpec(
        argv=("tool",),
        stdin=b"request",
        image_digest="sha256:" + "a" * 64,
        risk_class=risk_class,
        limits=_limits(),
    )


class FakeSandbox:
    backend = SandboxBackend.GVISOR

    def __init__(self, result: ExecResult) -> None:
        self.result = result
        self.calls = 0

    async def run(self, spec: ExecSpec) -> ExecResult:
        _ = spec
        self.calls += 1
        return self.result


class RaisingSandbox:
    backend = SandboxBackend.GVISOR

    def __init__(self, error: Exception) -> None:
        self.error = error

    async def run(self, spec: ExecSpec) -> ExecResult:
        _ = spec
        raise self.error


def _result(
    *,
    backend: SandboxBackend = SandboxBackend.GVISOR,
    exit_code: int | None = 0,
    stdout: bytes = b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}',
    stderr: bytes = b"",
    timed_out: bool = False,
    output_limit_exceeded: bool = False,
) -> ExecResult:
    return ExecResult(
        backend=backend,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        output_limit_exceeded=output_limit_exceeded,
    )


def test_executor_accepts_only_matching_successful_json_rpc_response() -> None:
    sandbox = FakeSandbox(_result())
    executor = SandboxCallExecutor(sandbox, lambda message, event: _spec())

    outcome = asyncio.run(executor.execute(_message(), _event()))

    assert outcome.response == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    assert outcome.audit.backend == "gvisor"
    assert outcome.audit.status == "completed"
    assert outcome.audit.image_digest == "sha256:" + "a" * 64
    assert sandbox.calls == 1


@pytest.mark.parametrize(
    ("result", "failure"),
    [
        (_result(backend=SandboxBackend.FIRECRACKER), SandboxCallFailure.BACKEND_MISMATCH),
        (_result(timed_out=True), SandboxCallFailure.TIMEOUT),
        (_result(output_limit_exceeded=True), SandboxCallFailure.OUTPUT_LIMIT),
        (_result(exit_code=7), SandboxCallFailure.EXECUTION_FAILED),
        (_result(exit_code=None), SandboxCallFailure.EXECUTION_FAILED),
        (_result(stdout=b"not-json"), SandboxCallFailure.RESPONSE_INVALID),
        (
            _result(stdout=b'{"jsonrpc":"2.0","id":2,"result":{}}'),
            SandboxCallFailure.RESPONSE_INVALID,
        ),
        (
            _result(stdout=b'{"jsonrpc":"2.0","id":true,"result":{}}'),
            SandboxCallFailure.RESPONSE_INVALID,
        ),
        (
            _result(stdout=b'{"jsonrpc":"2.0","id":1,"result":{},"error":{}}'),
            SandboxCallFailure.RESPONSE_INVALID,
        ),
    ],
)
def test_executor_fails_closed_for_invalid_outcomes(
    result: ExecResult,
    failure: SandboxCallFailure,
) -> None:
    executor = SandboxCallExecutor(FakeSandbox(result), lambda message, event: _spec())

    with pytest.raises(SandboxCallError) as raised:
        asyncio.run(executor.execute(_message(), _event()))

    assert raised.value.failure is failure
    audit = raised.value.audit(SandboxBackend.GVISOR)
    assert audit.status == failure.value
    assert audit.image_digest == "sha256:" + "a" * 64


def test_executor_rejects_profile_for_a_different_backend_before_execution() -> None:
    sandbox = FakeSandbox(_result())
    executor = SandboxCallExecutor(
        sandbox,
        lambda message, event: _spec(RiskClass.GENERATED_CODE),
    )

    with pytest.raises(SandboxCallError) as raised:
        asyncio.run(executor.execute(_message(), _event()))

    assert raised.value.failure is SandboxCallFailure.BACKEND_MISMATCH
    assert sandbox.calls == 0


def test_executor_allows_empty_notification_response() -> None:
    executor = SandboxCallExecutor(
        FakeSandbox(_result(stdout=b"")),
        lambda message, event: _spec(),
    )

    outcome = asyncio.run(executor.execute(_message(None), _event(None)))
    assert outcome.response is None
    assert outcome.audit.status == "completed"


@pytest.mark.parametrize(
    ("error", "failure"),
    [
        (SandboxUnavailable(SandboxBackend.GVISOR), SandboxCallFailure.UNAVAILABLE),
        (RuntimeError("sensitive backend detail"), SandboxCallFailure.EXECUTION_FAILED),
    ],
)
def test_executor_sanitizes_backend_exceptions_with_auditable_image(
    error: Exception,
    failure: SandboxCallFailure,
) -> None:
    executor = SandboxCallExecutor(
        RaisingSandbox(error),
        lambda message, event: _spec(),
    )

    with pytest.raises(SandboxCallError) as raised:
        asyncio.run(executor.execute(_message(), _event()))

    assert raised.value.failure is failure
    assert "sensitive backend detail" not in str(raised.value)
    assert raised.value.audit(SandboxBackend.GVISOR).image_digest == "sha256:" + "a" * 64


def test_sandbox_error_exposes_only_stable_sanitized_decision() -> None:
    error = SandboxCallError(SandboxCallFailure.UNAVAILABLE)

    decision = error.decision(frozenset({"integrity:untrusted"}))

    assert decision.rule_id == "sandbox.call.unavailable"
    assert "sensitive runtime detail" not in decision.reason
    assert decision.labels == frozenset({"integrity:untrusted"})
