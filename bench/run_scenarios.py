"""Run the offline scenario corpus and report containment and false-block rates.

Each scenario runs twice:

- **undefended** — handlers are invoked directly, with no mediation. This is the control. An
  attack that does not succeed undefended proves nothing about the defense, so the report
  flags such scenarios as vacuous rather than counting them as wins.
- **capgate** — the identical call sequence through a real compiled LangGraph `StateGraph`
  and `ToolNode` wrapped by `build_secure_tool_node`.

Attack success means the exfiltration handler actually ran *with the secret marker in its
arguments*. Not "an error was returned" — the side effect either happened or it did not.

No API key, no network, fully deterministic.

    python bench/run_scenarios.py
    python bench/run_scenarios.py --out bench/reports/scenarios.json
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))

from langchain_core.messages import (  # noqa: E402
    AIMessage,
    BaseMessage,
    ToolCall,
    ToolMessage,
)
from langchain_core.tools import StructuredTool  # noqa: E402
from langgraph.graph import END, START, MessagesState, StateGraph  # noqa: E402
from scenarios import (  # noqa: E402
    ALL_SCENARIOS,
    SECRET_MARKER,
    PlannedCall,
    Scenario,
    ToolSpec,
)

from capgate.adapters.langgraph import build_secure_tool_node  # noqa: E402
from capgate.engine.context import AgentContext  # noqa: E402
from capgate.engine.mediator import ToolCallMediator  # noqa: E402
from capgate.engine.pipeline import DecisionPipeline, ToolMetadata  # noqa: E402
from capgate.policy.model import CapabilityPattern, Policy  # noqa: E402
from capgate.receipts.replay import replay_session  # noqa: E402
from capgate.receipts.signer import Ed25519Signer, ReceiptWriter  # noqa: E402
from capgate.receipts.store import JsonlReceiptStore  # noqa: E402
from capgate.sandbox.base import RiskClass  # noqa: E402
from capgate.taint.labels import BOTTOM_LABEL, Label  # noqa: E402

Mode = Literal["undefended", "capgate"]


@dataclass
class ScenarioResult:
    scenario: str
    kind: str
    mode: Mode
    incident: str | None
    executed_tools: list[str] = field(default_factory=list)
    blocked: list[dict[str, str | None]] = field(default_factory=list)
    exfil_reached: bool = False
    all_calls_executed: bool = False
    receipt_count: int = 0
    receipts_replayed: bool | None = None
    error: str | None = None


def _tool_metadata(spec: ToolSpec) -> ToolMetadata:
    return ToolMetadata(
        result_label=Label(spec.confidentiality, spec.integrity, spec.source_tags),
        risk_class=RiskClass.TRUSTED_DIRECT,
        sink=spec.sink,
        capability=spec.capability,
    )


def _pipeline(scenario: Scenario) -> DecisionPipeline:
    return DecisionPipeline(
        {spec.name: _tool_metadata(spec) for spec in scenario.tools},
        policy=Policy(
            agent=f"scenario-{scenario.name}",
            can=tuple(CapabilityPattern.parse(item) for item in scenario.capabilities()),
            cannot=(),
            requires_approval=(),
        ),
    )


class _Recorder:
    """Track what actually happened to the outside world."""

    def __init__(self, scenario: Scenario) -> None:
        self.executed: list[str] = []
        self.exfil_hits: list[str] = []
        self._exfil_tools = scenario.exfil_tools()
        self._breach = scenario.breach

    def invoke(self, spec: ToolSpec, payload: str) -> str:
        self.executed.append(spec.name)
        if spec.name in self._exfil_tools and self._is_breach(payload):
            self.exfil_hits.append(spec.name)
        return spec.returns

    def _is_breach(self, payload: str) -> bool:
        if self._breach == "handler_reached":
            return True
        return SECRET_MARKER in payload


def run_undefended(scenario: Scenario) -> ScenarioResult:
    recorder = _Recorder(scenario)
    specs = {spec.name: spec for spec in scenario.tools}
    result = ScenarioResult(
        scenario=scenario.name,
        kind=scenario.kind,
        mode="undefended",
        incident=scenario.incident,
    )
    for call in scenario.calls:
        recorder.invoke(specs[call.tool], call.payload)
    result.executed_tools = list(recorder.executed)
    result.exfil_reached = bool(recorder.exfil_hits)
    result.all_calls_executed = len(recorder.executed) == len(scenario.calls)
    return result


def _build_tools(scenario: Scenario, recorder: _Recorder) -> list[Any]:
    tools: list[Any] = []
    for spec in scenario.tools:
        def handler(payload: str = "", _spec: ToolSpec = spec) -> str:
            return recorder.invoke(_spec, payload)

        tools.append(
            StructuredTool.from_function(
                func=handler,
                name=spec.name,
                description=f"Scenario tool {spec.name}.",
            )
        )
    return tools


def _label_arguments(_request: Any, arguments: dict[str, Any]) -> dict[str, Label]:
    """Scripted arguments enter from controlled graph input, so they carry the bottom label.

    Taint reaches the decision through the session influence recorded from tool *results*,
    which is exactly the conservative approximation this corpus is measuring.
    """

    return {name: BOTTOM_LABEL for name in arguments}


def run_capgate(scenario: Scenario) -> ScenarioResult:
    recorder = _Recorder(scenario)
    result = ScenarioResult(
        scenario=scenario.name,
        kind=scenario.kind,
        mode="capgate",
        incident=scenario.incident,
    )
    session_id = f"scenario-{scenario.name}"
    calls: Sequence[PlannedCall] = scenario.calls

    with tempfile.TemporaryDirectory(prefix="capgate-scenario-") as directory:
        store = JsonlReceiptStore(Path(directory) / "receipts.jsonl")
        signer = Ed25519Signer.generate()
        mediator = ToolCallMediator(
            pipeline=_pipeline(scenario),
            context=AgentContext(session_id),
            receipt_writer=ReceiptWriter(store=store, signer=signer),
        )
        secure_tools = build_secure_tool_node(
            _build_tools(scenario, recorder),
            mediator=mediator,
            session_id=session_id,
            label_arguments=_label_arguments,
        )

        def planner(state: MessagesState) -> dict[str, list[BaseMessage]]:
            done = sum(1 for m in state["messages"] if isinstance(m, ToolMessage))
            if done >= len(calls):
                return {"messages": [AIMessage(content="scenario complete")]}
            planned = calls[done]
            return {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            ToolCall(
                                name=planned.tool,
                                args={"payload": planned.payload},
                                id=f"{session_id}-call-{done}",
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
        graph = builder.compile()

        try:
            final = cast(
                MessagesState,
                graph.invoke(
                    {"messages": [AIMessage(content="start", id="seed")]},
                    {"recursion_limit": 4 * len(calls) + 10},
                ),
            )
        except Exception as exc:  # noqa: BLE001 - reported, never silently swallowed
            result.error = f"{type(exc).__name__}: {exc}"
            result.executed_tools = list(recorder.executed)
            result.exfil_reached = bool(recorder.exfil_hits)
            return result

        for message in final["messages"]:
            if not isinstance(message, ToolMessage) or message.status != "error":
                continue
            artifact = message.artifact if isinstance(message.artifact, dict) else {}
            capgate_detail = artifact.get("capgate", {}) if artifact else {}
            detail = capgate_detail if isinstance(capgate_detail, dict) else {}
            result.blocked.append(
                {
                    "tool": message.name,
                    "rule_id": cast(str | None, detail.get("rule_id")),
                }
            )

        receipts = store.iter_receipts(session_id)
        result.receipt_count = len(receipts)
        try:
            replay_session(store.path, session_id, signer.verifier())
            result.receipts_replayed = True
        except Exception:  # noqa: BLE001 - a replay failure is a reportable result
            result.receipts_replayed = False

    result.executed_tools = list(recorder.executed)
    result.exfil_reached = bool(recorder.exfil_hits)
    result.all_calls_executed = len(recorder.executed) == len(calls)
    return result


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def build_report(scenarios: Sequence[Scenario]) -> dict[str, Any]:
    results: list[ScenarioResult] = []
    for scenario in scenarios:
        results.append(run_undefended(scenario))
        results.append(run_capgate(scenario))

    by_mode = {
        (item.scenario, item.mode): item for item in results
    }
    attacks = [s for s in scenarios if s.kind == "attack"]
    benign = [s for s in scenarios if s.kind == "benign"]

    viable_attacks = [
        s for s in attacks if by_mode[(s.name, "undefended")].exfil_reached
    ]
    vacuous_attacks = [s.name for s in attacks if s not in viable_attacks]
    contained = [
        s for s in viable_attacks if not by_mode[(s.name, "capgate")].exfil_reached
    ]

    false_blocked = [
        s for s in benign if not by_mode[(s.name, "capgate")].all_calls_executed
    ]

    # A block for an unrelated reason is not a win. Containment counts only when the
    # scenario was stopped by the rule it was written to exercise.
    wrong_rule: list[dict[str, Any]] = []
    for scenario in attacks:
        if scenario.expected_rule_id is None:
            continue
        fired = {entry["rule_id"] for entry in by_mode[(scenario.name, "capgate")].blocked}
        if scenario.expected_rule_id not in fired:
            wrong_rule.append(
                {
                    "scenario": scenario.name,
                    "expected": scenario.expected_rule_id,
                    "observed": sorted(rule for rule in fired if rule is not None),
                }
            )

    replay_failures = [
        item.scenario
        for item in results
        if item.mode == "capgate" and item.receipts_replayed is False
    ]
    errors = [
        {"scenario": item.scenario, "mode": item.mode, "error": item.error}
        for item in results
        if item.error is not None
    ]

    return {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "harness": "scripted-compromised-planner",
        "scope": (
            "Offline deterministic containment measurement against a worst-case scripted "
            "attacker. Not comparable to published AgentDojo results, which measure whether "
            "a model falls for an injection."
        ),
        "model_api_used": False,
        "network_used": False,
        "attack_scenarios": len(attacks),
        "viable_attack_scenarios": len(viable_attacks),
        "vacuous_attack_scenarios": vacuous_attacks,
        "benign_scenarios": len(benign),
        "undefended_attack_success_rate": _rate(len(viable_attacks), len(attacks)),
        "containment_rate": _rate(len(contained), len(viable_attacks)),
        "uncontained_attacks": [
            s.name for s in viable_attacks if by_mode[(s.name, "capgate")].exfil_reached
        ],
        "false_block_rate": _rate(len(false_blocked), len(benign)),
        "false_blocked_scenarios": [s.name for s in false_blocked],
        "unexpected_rule_ids": wrong_rule,
        "receipt_replay_failures": replay_failures,
        "errors": errors,
        "results": [asdict(item) for item in results],
    }


def _percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def print_summary(report: dict[str, Any]) -> None:
    print("CapGate offline scenario corpus")
    print("=" * 62)
    print(f"  attack scenarios          {report['attack_scenarios']}")
    print(f"  benign scenarios          {report['benign_scenarios']}")
    print()
    print(f"  undefended attack success {_percent(report['undefended_attack_success_rate'])}")
    print(f"  containment rate          {_percent(report['containment_rate'])}")
    print(f"  false-block rate          {_percent(report['false_block_rate'])}")
    print()
    if report["vacuous_attack_scenarios"]:
        print("  VACUOUS (did not succeed undefended, so they prove nothing):")
        for name in report["vacuous_attack_scenarios"]:
            print(f"    - {name}")
    if report["uncontained_attacks"]:
        print("  UNCONTAINED:")
        for name in report["uncontained_attacks"]:
            print(f"    - {name}")
    if report["false_blocked_scenarios"]:
        print("  FALSE-BLOCKED (legitimate work refused):")
        for name in report["false_blocked_scenarios"]:
            print(f"    - {name}")
    if report["unexpected_rule_ids"]:
        print("  BLOCKED BY THE WRONG RULE:")
        for item in report["unexpected_rule_ids"]:
            observed = ", ".join(item["observed"]) or "none"
            print(f"    - {item['scenario']}: expected {item['expected']}, saw {observed}")
    if report["receipt_replay_failures"]:
        print("  RECEIPT REPLAY FAILURES:")
        for name in report["receipt_replay_failures"]:
            print(f"    - {name}")
    if report["errors"]:
        print("  ERRORS:")
        for item in report["errors"]:
            print(f"    - {item['scenario']} ({item['mode']}): {item['error']}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="Write the full JSON report here.")
    parser.add_argument("--json", action="store_true", help="Print the JSON report to stdout.")
    args = parser.parse_args(argv)

    report = build_report(ALL_SCENARIOS)

    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print_summary(report)

    failed = bool(
        report["uncontained_attacks"]
        or report["vacuous_attack_scenarios"]
        or report["unexpected_rule_ids"]
        or report["receipt_replay_failures"]
        or report["errors"]
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
