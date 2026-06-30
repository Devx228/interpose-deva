from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import replace

from capgate.engine.context import AgentContext
from capgate.engine.decision import STAGE0_ALLOW, Decision
from capgate.engine.pipeline import DecisionPipeline
from capgate.mcp_security.isolation import ServerToolRegistry, ToolIdentity
from capgate.mcp_security.pinning import ToolPinRegistry
from capgate.proxy.client import DownstreamClient
from capgate.proxy.events import (
    JsonObject,
    ToolCallEvent,
    ToolListEvent,
    ToolResultEvent,
    is_tool_call,
    is_tool_list,
    tool_call_event_from_message,
    tool_list_event_from_message,
    tool_result_event_from_response,
)
from capgate.proxy.sandbox import (
    SandboxCallError,
    SandboxCallExecutor,
    SandboxCallFailure,
    SandboxCallOutcome,
)
from capgate.receipts.model import SandboxAudit
from capgate.receipts.signer import ReceiptWriter
from capgate.sandbox.base import SandboxBackend, SandboxUnavailable
from capgate.sandbox.limits import SessionBudget
from capgate.telemetry.otel import tool_call_span


class ProxySession:
    def __init__(
        self,
        *,
        downstream: DownstreamClient,
        receipt_writer: ReceiptWriter,
        server_name: str,
        session_id: str | None = None,
        decision_pipeline: DecisionPipeline | None = None,
        tool_pin_registry: ToolPinRegistry | None = None,
        server_tool_registry: ServerToolRegistry | None = None,
        sandbox_executors: Mapping[SandboxBackend, SandboxCallExecutor] | None = None,
        session_budget: SessionBudget | None = None,
    ) -> None:
        self.downstream = downstream
        self.receipt_writer = receipt_writer
        self.server_name = server_name
        self.session_id = session_id or str(uuid.uuid4())
        self.decision_pipeline = decision_pipeline
        self.tool_pin_registry = tool_pin_registry
        self.server_tool_registry = server_tool_registry
        self.sandbox_executors = dict(sandbox_executors or {})
        self.session_budget = session_budget
        self.context = AgentContext(session_id=self.session_id)
        self._session_failed_closed = False

    async def handle_message(self, message: JsonObject) -> JsonObject | None:
        if is_tool_list(message):
            list_event = tool_list_event_from_message(
                session_id=self.session_id,
                server=self.server_name,
                message=message,
            )
            return await self.handle_list(message, list_event)

        if is_tool_call(message):
            call_event = tool_call_event_from_message(
                session_id=self.session_id,
                server=self.server_name,
                message=message,
            )
            return await self.handle_call(message, call_event)

        return await self.downstream.request(message)

    async def handle_list(self, message: JsonObject, event: ToolListEvent) -> JsonObject | None:
        try:
            response = await self.downstream.request(message)
        except Exception:
            decision = Decision(
                verdict="BLOCK",
                reason="downstream tool discovery failed closed",
                rule_id="proxy.downstream_list_error",
                labels=frozenset(),
            )
            blocked = _blocked_list_response(event, decision)
            self._write_tool_list_receipt(event, blocked, decision)
            return blocked
        if response is None:
            self._write_tool_list_receipt(event, None, STAGE0_ALLOW)
            return None
        definitions = _tool_definitions(response)
        if definitions is None:
            decision = Decision(
                verdict="BLOCK",
                reason="tool list response is malformed",
                rule_id="mcp.tool_definition_invalid",
                labels=frozenset(),
            )
            blocked = _blocked_list_response(event, decision)
            self._write_tool_list_receipt(event, blocked, decision)
            return blocked
        for definition in definitions:
            if self.tool_pin_registry is not None:
                decision = self.tool_pin_registry.check(self.server_name, definition)
                if decision.verdict != "ALLOW":
                    blocked = _blocked_list_response(event, decision)
                    self._write_tool_list_receipt(event, blocked, decision)
                    return blocked
            if self.server_tool_registry is not None:
                name = definition.get("name")
                if not isinstance(name, str):
                    decision = Decision(
                        verdict="BLOCK",
                        reason="tool list response is malformed",
                        rule_id="mcp.tool_definition_invalid",
                        labels=frozenset(),
                    )
                    blocked = _blocked_list_response(event, decision)
                    self._write_tool_list_receipt(event, blocked, decision)
                    return blocked
                decision = self.server_tool_registry.register(
                    ToolIdentity(self.server_name, name)
                )
                if decision.verdict != "ALLOW":
                    blocked = _blocked_list_response(event, decision)
                    self._write_tool_list_receipt(event, blocked, decision)
                    return blocked
        self._write_tool_list_receipt(
            event,
            response,
            Decision(
                verdict="ALLOW",
                reason="tool definitions accepted",
                rule_id=None,
                labels=frozenset(),
            ),
        )
        return response

    async def handle_call(self, message: JsonObject, event: ToolCallEvent) -> JsonObject | None:
        budget_decision = self._reserve_call_attempt()
        if budget_decision is not None:
            return self._record_blocked_call(event, budget_decision)

        decision = self._decide(event)
        if decision.verdict != "ALLOW":
            return self._record_blocked_call(event, decision)

        required_backend: SandboxBackend | None = None
        sandbox_audit: SandboxAudit | None = None
        if self.decision_pipeline is not None:
            route = self.decision_pipeline.route_execution(event.tool)
            if route.decision.verdict != "ALLOW":
                return self._record_blocked_call(
                    event,
                    replace(route.decision, labels=decision.labels),
                )
            required_backend = route.backend

        try:
            with tool_call_span(event, decision):
                if required_backend is None:
                    response = await self.downstream.request(message)
                else:
                    outcome = await self._execute_sandboxed(
                        message,
                        event,
                        required_backend,
                    )
                    response = outcome.response
                    sandbox_audit = outcome.audit
                    decision = replace(
                        decision,
                        reason=(
                            f"{decision.reason}; executed with required "
                            f"{required_backend.value} sandbox"
                        ),
                    )
        except SandboxCallError as exc:
            return self._record_blocked_call(
                event,
                exc.decision(decision.labels),
                sandbox=exc.audit(required_backend) if required_backend is not None else None,
            )
        except SandboxUnavailable:
            unavailable_error = SandboxCallError(
                SandboxCallFailure.UNAVAILABLE,
                backend=required_backend,
            )
            return self._record_blocked_call(
                event,
                unavailable_error.decision(decision.labels),
                sandbox=(
                    unavailable_error.audit(required_backend)
                    if required_backend is not None
                    else None
                ),
            )
        except Exception:
            if required_backend is not None:
                sandbox_error = SandboxCallError(
                    SandboxCallFailure.EXECUTION_FAILED,
                    backend=required_backend,
                )
                failure_decision = sandbox_error.decision(decision.labels)
                failure_audit = sandbox_error.audit(required_backend)
            else:
                failure_decision = Decision(
                    verdict="BLOCK",
                    reason="downstream tool execution failed closed",
                    rule_id="proxy.downstream_error",
                    labels=decision.labels,
                )
                failure_audit = None
            return self._record_blocked_call(
                event,
                failure_decision,
                sandbox=failure_audit,
            )
        if response is None:
            self.receipt_writer.write_tool_call(
                call_event=event,
                result_event=ToolResultEvent(
                    session_id=event.session_id,
                    server=event.server,
                    tool=event.tool,
                    result=None,
                    request_id=event.request_id,
                ),
                decision=decision,
                sandbox=sandbox_audit,
            )
            return None
        result_event = tool_result_event_from_response(call_event=event, response=response)
        self.receipt_writer.write_tool_call(
            call_event=event,
            result_event=result_event,
            decision=decision,
            sandbox=sandbox_audit,
        )
        if self.decision_pipeline is not None:
            try:
                self.decision_pipeline.observe_result(self.context, event, result_event)
            except Exception:
                self._session_failed_closed = True
        return response

    async def _execute_sandboxed(
        self,
        message: JsonObject,
        event: ToolCallEvent,
        required_backend: SandboxBackend,
    ) -> SandboxCallOutcome:
        executor = self.sandbox_executors.get(required_backend)
        if executor is None:
            raise SandboxCallError(
                SandboxCallFailure.UNAVAILABLE,
                backend=required_backend,
            )
        if executor.backend is not required_backend:
            raise SandboxCallError(
                SandboxCallFailure.BACKEND_MISMATCH,
                backend=required_backend,
            )
        return await executor.execute(message, event)

    def _reserve_call_attempt(self) -> Decision | None:
        if self.session_budget is None:
            return None
        result = self.session_budget.reserve(tokens=0, cost_micros=0)
        if result.decision.verdict != "ALLOW" or result.reservation is None:
            return result.decision
        reconciliation = self.session_budget.reconcile(
            result.reservation,
            actual_tokens=0,
            actual_cost_micros=0,
            trusted_usage=True,
        )
        return reconciliation if reconciliation.verdict != "ALLOW" else None

    def _record_blocked_call(
        self,
        event: ToolCallEvent,
        decision: Decision,
        *,
        sandbox: SandboxAudit | None = None,
    ) -> JsonObject:
        blocked_response = _blocked_response(event, decision.reason, decision.rule_id)
        result_event = tool_result_event_from_response(
            call_event=event,
            response=blocked_response,
        )
        with tool_call_span(event, decision):
            self.receipt_writer.write_tool_call(
                call_event=event,
                result_event=result_event,
                decision=decision,
                sandbox=sandbox,
            )
        return blocked_response

    def _decide(self, event: ToolCallEvent) -> Decision:
        if self._session_failed_closed:
            return Decision(
                verdict="BLOCK",
                reason="session blocked after provenance tracking failure",
                rule_id="engine.session_failed_closed",
                labels=frozenset(),
            )
        if self.decision_pipeline is None:
            return STAGE0_ALLOW
        try:
            return self.decision_pipeline.decide(self.context, event)
        except Exception:
            return Decision(
                verdict="BLOCK",
                reason="decision pipeline failed closed",
                rule_id="engine.decision_error",
                labels=frozenset(),
            )

    def _write_tool_list_receipt(
        self,
        event: ToolListEvent,
        response: JsonObject | None,
        decision: Decision,
    ) -> None:
        call_event = ToolCallEvent(
            session_id=event.session_id,
            server=event.server,
            tool="tools/list",
            arguments={},
            arg_provenance={},
            request_id=event.request_id,
        )
        self.receipt_writer.write_tool_call(
            call_event=call_event,
            result_event=ToolResultEvent(
                session_id=event.session_id,
                server=event.server,
                tool="tools/list",
                result=response,
                request_id=event.request_id,
            ),
            decision=decision,
        )


def _blocked_response(
    event: ToolCallEvent,
    reason: str,
    rule_id: str | None,
) -> JsonObject:
    return {
        "jsonrpc": "2.0",
        "id": event.request_id,
        "error": {
            "code": -32001,
            "message": reason,
            "data": {"rule_id": rule_id},
        },
    }


def _tool_definitions(response: JsonObject) -> list[dict[str, object]] | None:
    result = response.get("result")
    if not isinstance(result, dict):
        return None
    tools = result.get("tools")
    if not isinstance(tools, list):
        return None
    definitions: list[dict[str, object]] = []
    for tool in tools:
        if not isinstance(tool, dict):
            return None
        definitions.append(dict(tool))
    return definitions


def _blocked_list_response(event: ToolListEvent, decision: Decision) -> JsonObject:
    return {
        "jsonrpc": "2.0",
        "id": event.request_id,
        "error": {
            "code": -32001,
            "message": decision.reason,
            "data": {"rule_id": decision.rule_id},
        },
    }
