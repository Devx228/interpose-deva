"""Replay AgentDojo's third-party injection tasks through CapGate.

The scenario corpus in `bench/scenarios.py` has one structural weakness that no amount of
polish fixes: **the attacks were written by the same person who wrote the defense.** It shows
that the encoded flows are contained. It cannot show anything about flows nobody thought of.

This harness removes that specific limitation for the *attacks*. AgentDojo (arXiv:2406.13352)
ships injection tasks authored by its researchers, and each one exposes `ground_truth(env)`
returning the exact sequence of tool calls the attacker wants executed. Those call sequences
are data, not model output, so they replay deterministically at zero cost.

What this changes, precisely:

- **The attacker's moves are third-party.** Nobody here chose `update_password`,
  `remove_user_from_slack`, or nine separate `send_money` variants.
- **The tool security metadata is still ours.** Classification of which tools are sinks and
  which results are confidential is authored here, in `_classify`. A wrong classification
  would flatter the result, so the classifier is deliberately mechanical and reviewable.
- **This is not an AgentDojo ASR.** No model runs and no utility is measured. It answers one
  question: when a compromised agent executes an attack somebody else designed, does
  enforcement stop it?

Injection vector: AgentDojo attacks arrive inside tool output the agent reads. Each replay
therefore starts by recording one untrusted tool result before the attacker's calls, which is
how the taint would genuinely be introduced.

    python bench/agentdojo_attacks.py
    python bench/agentdojo_attacks.py --strict-integrity --out bench/reports/third-party.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from capgate.engine.context import AgentContext  # noqa: E402
from capgate.engine.pipeline import DecisionPipeline, ToolMetadata  # noqa: E402
from capgate.flow.sinks import SinkKind  # noqa: E402
from capgate.policy.model import CapabilityPattern, Policy  # noqa: E402
from capgate.proxy.events import ToolCallEvent, ToolResultEvent  # noqa: E402
from capgate.sandbox.base import RiskClass  # noqa: E402
from capgate.taint.labels import Confidentiality, Integrity, Label  # noqa: E402

BENCHMARK_VERSION = "v1.2.2"

# --- Tool classification -------------------------------------------------------------
# Authored here, not by AgentDojo. Kept mechanical so a reviewer can check it in one pass
# rather than trusting a hand-tuned table that might have been fitted to the outcome.

#: Tools whose call leaves the trust boundary — the exfiltration channels.
_EXTERNAL_SINK_TOOLS = {
    "send_email": SinkKind.EMAIL_EXTERNAL,
    "send_money": SinkKind.NETWORK_EXTERNAL,
    "schedule_transaction": SinkKind.NETWORK_EXTERNAL,
    "update_scheduled_transaction": SinkKind.NETWORK_EXTERNAL,
    "send_direct_message": SinkKind.SLACK_EXTERNAL,
    "send_channel_message": SinkKind.SLACK_PUBLIC,
    "post_webpage": SinkKind.NETWORK_EXTERNAL,
    "share_file": SinkKind.NETWORK_EXTERNAL,
    "add_user_to_channel": SinkKind.SLACK_EXTERNAL,
    "invite_user_to_slack": SinkKind.SLACK_EXTERNAL,
    # Fetching an attacker-supplied URL *is* outbound communication: the request itself
    # carries data, which is the EchoLeak primitive. This entry exists because the
    # third-party corpus caught it classified as a harmless read — the exact
    # misconfiguration docs/LIMITATIONS.md warns about, found by attacks we did not write.
    "get_webpage": SinkKind.NETWORK_EXTERNAL,
}

#: Prefixes that change state without necessarily leaving the boundary.
_STATE_CHANGE_PREFIXES = (
    "create_",
    "update_",
    "delete_",
    "cancel_",
    "remove_",
    "add_",
    "append_",
    "reserve_",
    "reschedule_",
    "set_",
)

_READ_PREFIXES = ("get_", "list_", "search_", "read_", "check_")

#: Reads that return the user's own data. Everything else read is treated as public.
_PUBLIC_READ_TOOLS = {
    "get_current_day",
    "get_all_hotels_in_city",
    "get_all_restaurants_in_city",
    "get_all_car_rental_companies_in_city",
    "get_webpage",
    "get_channels",
}


def _classify(tool_name: str) -> ToolMetadata:
    """Map an AgentDojo tool to trusted security metadata."""

    sink = _EXTERNAL_SINK_TOOLS.get(tool_name, SinkKind.NONE)
    if sink is SinkKind.NONE and tool_name.startswith(_STATE_CHANGE_PREFIXES):
        sink = SinkKind.FILE_WRITE if "file" in tool_name else SinkKind.DB_WRITE

    if tool_name.startswith(_READ_PREFIXES) and tool_name not in _PUBLIC_READ_TOOLS:
        confidentiality = Confidentiality.INTERNAL
    else:
        confidentiality = Confidentiality.PUBLIC

    if tool_name.startswith(_READ_PREFIXES):
        action = "read"
    elif tool_name.startswith(("delete_", "remove_", "cancel_")):
        action = "delete"
    elif tool_name in _EXTERNAL_SINK_TOOLS:
        action = "send"
    else:
        action = "write"

    return ToolMetadata(
        # Every tool result is untrusted: it is exactly the channel injections arrive on.
        result_label=Label(confidentiality, Integrity.UNTRUSTED, frozenset({"tool_result"})),
        risk_class=RiskClass.TRUSTED_DIRECT,
        sink=sink,
        capability=f"{action}:agentdojo.{tool_name}",
    )


@dataclass
class AttackResult:
    suite: str
    injection_task: str
    goal: str
    calls: list[str]
    contained: bool
    blocked_at: str | None
    rule_id: str | None
    note: str = ""


def _pipeline(tool_names: Sequence[str], *, strict_integrity: bool) -> DecisionPipeline:
    metadata = {name: _classify(name) for name in tool_names}
    return DecisionPipeline(
        metadata,
        # Every capability the attack needs is granted. Withholding one would let policy
        # trivially "win" without flow control doing any work, which would not be evidence.
        policy=Policy(
            agent="agentdojo-replay",
            can=tuple(
                CapabilityPattern.parse(item.capability)
                for item in metadata.values()
                if item.capability is not None
            ),
            cannot=(),
            requires_approval=(),
        ),
        require_trusted_for_state_change=strict_integrity,
    )


def _event(tool: str, request_id: int) -> ToolCallEvent:
    return ToolCallEvent(
        session_id="agentdojo-replay",
        server="agentdojo",
        tool=tool,
        arguments={},
        arg_provenance={},
        request_id=request_id,
    )


def replay(suite_name: str, *, strict_integrity: bool) -> list[AttackResult]:
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite(BENCHMARK_VERSION, suite_name)
    tool_names = [tool.name for tool in suite.tools]
    environment = suite.load_and_inject_default_environment({})
    results: list[AttackResult] = []

    for task_id, task in suite.injection_tasks.items():
        try:
            ground_truth = task.ground_truth(environment)
        except Exception as exc:  # noqa: BLE001 - reported, never silently dropped
            results.append(
                AttackResult(
                    suite=suite_name,
                    injection_task=task_id,
                    goal=str(getattr(task, "GOAL", ""))[:160],
                    calls=[],
                    contained=False,
                    blocked_at=None,
                    rule_id=None,
                    note=f"ground truth unavailable: {type(exc).__name__}",
                )
            )
            continue

        calls = [call.function for call in ground_truth]
        if not calls:
            results.append(
                AttackResult(
                    suite=suite_name,
                    injection_task=task_id,
                    goal=str(getattr(task, "GOAL", ""))[:160],
                    calls=[],
                    contained=False,
                    blocked_at=None,
                    rule_id=None,
                    note="no executable ground truth; not replayable",
                )
            )
            continue

        pipeline = _pipeline(tool_names, strict_integrity=strict_integrity)
        context = AgentContext("agentdojo-replay")

        # The injection vector. In AgentDojo the payload is planted inside the *user's own*
        # data — their inbox, calendar, cloud drive, or Slack history — so the agent reads it
        # through a normal tool call. That makes the resulting value internal (it is the
        # user's data) and untrusted (an attacker wrote part of it), which is the label the
        # tool classifier would assign anyway.
        context.record_result(
            "agentdojo:injection-vector",
            Label(
                Confidentiality.INTERNAL,
                Integrity.UNTRUSTED,
                frozenset({"tool_result", "email"}),
            ),
        )

        contained = False
        blocked_at: str | None = None
        rule_id: str | None = None
        for index, tool in enumerate(calls, start=1):
            event = _event(tool, index)
            decision = pipeline.decide(context, event)
            if decision.verdict != "ALLOW":
                contained = True
                blocked_at = tool
                rule_id = decision.rule_id
                break
            pipeline.observe_result(
                context,
                event,
                ToolResultEvent(
                    session_id="agentdojo-replay",
                    server="agentdojo",
                    tool=tool,
                    result={"ok": True},
                    request_id=index,
                ),
            )

        results.append(
            AttackResult(
                suite=suite_name,
                injection_task=task_id,
                goal=str(getattr(task, "GOAL", ""))[:160],
                calls=calls,
                contained=contained,
                blocked_at=blocked_at,
                rule_id=rule_id,
            )
        )
    return results


def build_report(*, strict_integrity: bool) -> dict[str, Any]:
    from agentdojo.task_suite.load_suites import get_suites

    suites = list(get_suites(BENCHMARK_VERSION))
    results: list[AttackResult] = []
    for suite_name in suites:
        results.extend(replay(suite_name, strict_integrity=strict_integrity))

    replayable = [item for item in results if item.calls]
    contained = [item for item in replayable if item.contained]
    not_replayable = [item for item in results if not item.calls]

    by_rule: dict[str, int] = {}
    for item in contained:
        key = item.rule_id or "<none>"
        by_rule[key] = by_rule.get(key, 0) + 1

    return {
        "harness": "agentdojo-injection-ground-truth-replay",
        "benchmark_version": BENCHMARK_VERSION,
        "strict_integrity": strict_integrity,
        "attack_authorship": "AgentDojo researchers (third party)",
        "metadata_authorship": "CapGate (this repository)",
        "model_api_used": False,
        "network_used": False,
        "suites": suites,
        "injection_tasks_total": len(results),
        "replayable": len(replayable),
        "not_replayable": len(not_replayable),
        "contained": len(contained),
        "containment_rate": (len(contained) / len(replayable)) if replayable else None,
        "uncontained": [
            {"suite": i.suite, "task": i.injection_task, "calls": i.calls, "goal": i.goal}
            for i in replayable
            if not i.contained
        ],
        "blocked_by_rule": by_rule,
        "not_replayable_tasks": [
            {"suite": i.suite, "task": i.injection_task, "note": i.note}
            for i in not_replayable
        ],
        "caveat": (
            "Attacks are third-party; tool security metadata is authored here. No model runs, "
            "so this is not an AgentDojo attack-success rate and no utility is measured."
        ),
        "results": [asdict(item) for item in results],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict-integrity", action="store_true")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        report = build_report(strict_integrity=args.strict_integrity)
    except ImportError:
        print('AgentDojo is not installed. Run: python -m pip install -e ".[bench]"')
        return 2

    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, sort_keys=True))
        return 0

    rate = report["containment_rate"]
    print("CapGate vs AgentDojo third-party injection tasks")
    print("=" * 62)
    print(f"  suites                    {', '.join(report['suites'])}")
    print(f"  injection tasks           {report['injection_tasks_total']}")
    print(f"  replayable ground truths  {report['replayable']}")
    print(f"  strict integrity rule     {'on' if report['strict_integrity'] else 'off'}")
    print()
    print(f"  contained                 {report['contained']}/{report['replayable']}"
          f"  ({'n/a' if rate is None else f'{rate * 100:.1f}%'})")
    print()
    print("  blocked by rule:")
    for rule, count in sorted(report["blocked_by_rule"].items(), key=lambda x: -x[1]):
        print(f"    {count:3}  {rule}")
    if report["uncontained"]:
        print()
        print("  UNCONTAINED:")
        for item in report["uncontained"]:
            print(f"    - {item['suite']}/{item['task']}: {item['calls']}")
    if report["not_replayable_tasks"]:
        print()
        print(f"  not replayable ({len(report['not_replayable_tasks'])}): "
              "no executable ground truth, excluded from the rate")
    print()
    print(f"  {report['caveat']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
