from __future__ import annotations

import json
import math
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from capgate.engine.decision import Decision
from capgate.proxy.events import JsonObject, JsonValue, ToolCallEvent
from capgate.receipts.model import SandboxAudit
from capgate.sandbox.base import (
    ExecSpec,
    Sandbox,
    SandboxBackend,
    SandboxUnavailable,
    route_backend,
)


class SandboxCallFailure(StrEnum):
    UNAVAILABLE = "unavailable"
    BACKEND_MISMATCH = "backend_mismatch"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    EXECUTION_FAILED = "execution_failed"
    RESPONSE_INVALID = "response_invalid"


_FAILURES: dict[SandboxCallFailure, tuple[str, str]] = {
    SandboxCallFailure.UNAVAILABLE: (
        "required sandbox execution path is unavailable",
        "sandbox.call.unavailable",
    ),
    SandboxCallFailure.BACKEND_MISMATCH: (
        "sandbox execution did not use the required backend",
        "sandbox.call.backend_mismatch",
    ),
    SandboxCallFailure.TIMEOUT: (
        "sandbox execution exceeded its wall-clock limit",
        "sandbox.call.timeout",
    ),
    SandboxCallFailure.OUTPUT_LIMIT: (
        "sandbox execution exceeded its output limit",
        "sandbox.call.output_limit",
    ),
    SandboxCallFailure.EXECUTION_FAILED: (
        "sandbox execution failed closed",
        "sandbox.call.execution_failed",
    ),
    SandboxCallFailure.RESPONSE_INVALID: (
        "sandbox returned an invalid JSON-RPC response",
        "sandbox.call.response_invalid",
    ),
}


class SandboxCallError(RuntimeError):
    """A stable, sanitized sandbox-call failure safe for receipts and responses."""

    def __init__(
        self,
        failure: SandboxCallFailure,
        *,
        backend: SandboxBackend | None = None,
        image_digest: str | None = None,
    ) -> None:
        self.failure = failure
        self.backend = backend
        self.image_digest = image_digest
        reason, _ = _FAILURES[failure]
        super().__init__(reason)

    def decision(self, labels: frozenset[str]) -> Decision:
        reason, rule_id = _FAILURES[self.failure]
        return Decision("BLOCK", reason, rule_id, labels)

    def audit(self, required_backend: SandboxBackend) -> SandboxAudit:
        backend = self.backend or required_backend
        return SandboxAudit(
            backend=backend.value,
            status=self.failure.value,
            image_digest=self.image_digest,
        )


SandboxSpecFactory = Callable[[JsonObject, ToolCallEvent], ExecSpec]


@dataclass(frozen=True, slots=True)
class SandboxCallOutcome:
    response: JsonObject | None
    audit: SandboxAudit


class SandboxCallExecutor:
    """Convert one MCP call to a sandbox invocation and validate its response."""

    def __init__(self, sandbox: Sandbox, spec_factory: SandboxSpecFactory) -> None:
        self._sandbox = sandbox
        self._spec_factory = spec_factory

    @property
    def backend(self) -> SandboxBackend:
        return self._sandbox.backend

    async def execute(
        self,
        message: JsonObject,
        event: ToolCallEvent,
    ) -> SandboxCallOutcome:
        spec = self._spec_factory(message, event)
        route = route_backend(spec.risk_class)
        if route.decision.verdict != "ALLOW" or route.backend is not self.backend:
            raise self._error(SandboxCallFailure.BACKEND_MISMATCH, spec)

        try:
            result = await self._sandbox.run(spec)
        except SandboxUnavailable:
            raise self._error(SandboxCallFailure.UNAVAILABLE, spec) from None
        except Exception:
            raise self._error(SandboxCallFailure.EXECUTION_FAILED, spec) from None
        if result.backend is not self.backend:
            raise self._error(SandboxCallFailure.BACKEND_MISMATCH, spec)
        if result.timed_out:
            raise self._error(SandboxCallFailure.TIMEOUT, spec)
        if result.output_limit_exceeded or (
            len(result.stdout) + len(result.stderr) > spec.limits.output_bytes
        ):
            raise self._error(SandboxCallFailure.OUTPUT_LIMIT, spec)
        if result.exit_code != 0:
            raise self._error(SandboxCallFailure.EXECUTION_FAILED, spec)

        if not result.stdout.strip() and event.request_id is None:
            response = None
        else:
            try:
                response = _parse_response(result.stdout, event.request_id)
            except SandboxCallError:
                raise self._error(SandboxCallFailure.RESPONSE_INVALID, spec) from None
        return SandboxCallOutcome(
            response=response,
            audit=SandboxAudit(
                backend=self.backend.value,
                status="completed",
                image_digest=spec.image_digest,
            ),
        )

    def _error(self, failure: SandboxCallFailure, spec: ExecSpec) -> SandboxCallError:
        return SandboxCallError(
            failure,
            backend=self.backend,
            image_digest=spec.image_digest,
        )


def _parse_response(payload: bytes, request_id: JsonValue) -> JsonObject:
    try:
        raw = cast(object, json.loads(payload))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SandboxCallError(SandboxCallFailure.RESPONSE_INVALID) from None
    if not isinstance(raw, dict) or any(not isinstance(key, str) for key in raw):
        raise SandboxCallError(SandboxCallFailure.RESPONSE_INVALID)
    response = cast(dict[str, object], raw)
    if (
        response.get("jsonrpc") != "2.0"
        or not _matching_json_id(response.get("id"), request_id)
        or (("result" in response) == ("error" in response))
        or not _is_json_value(response)
    ):
        raise SandboxCallError(SandboxCallFailure.RESPONSE_INVALID)
    return cast(JsonObject, response)


def _matching_json_id(observed: object, expected: JsonValue) -> bool:
    return type(observed) is type(expected) and observed == expected


def _is_json_value(value: object) -> bool:
    if value is None or isinstance(value, str | bool | int):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_is_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _is_json_value(item) for key, item in value.items()
        )
    return False
