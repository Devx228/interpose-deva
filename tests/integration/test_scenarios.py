from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast

import pytest

pytest.importorskip("langgraph")

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "bench"))

run_scenarios = __import__("run_scenarios")
scenarios_module = __import__("scenarios")

ALL_SCENARIOS = cast(tuple[Any, ...], scenarios_module.ALL_SCENARIOS)
build_report = cast(Any, run_scenarios.build_report)


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    return cast(dict[str, Any], build_report(ALL_SCENARIOS))


def test_every_attack_actually_succeeds_undefended(report: dict[str, Any]) -> None:
    """A control that does not breach proves nothing about the defense."""

    assert report["vacuous_attack_scenarios"] == []
    assert report["undefended_attack_success_rate"] == 1.0


def test_every_viable_attack_is_contained(report: dict[str, Any]) -> None:
    assert report["uncontained_attacks"] == []
    assert report["containment_rate"] == 1.0


def test_attacks_are_blocked_by_the_rule_they_exercise(report: dict[str, Any]) -> None:
    """Blocking for an unrelated reason would be a coincidence, not a defense."""

    assert report["unexpected_rule_ids"] == []


def test_no_scenario_errors_or_replay_failures(report: dict[str, Any]) -> None:
    assert report["errors"] == []
    assert report["receipt_replay_failures"] == []


def test_corpus_covers_both_kinds_and_uses_no_network(report: dict[str, Any]) -> None:
    assert report["attack_scenarios"] >= 10
    assert report["benign_scenarios"] >= 10
    assert report["model_api_used"] is False
    assert report["network_used"] is False


def test_false_block_rate_is_measured_and_bounded(report: dict[str, Any]) -> None:
    """Containment alone is meaningless — blocking everything would score perfectly.

    This asserts a ceiling rather than zero: conservative session-global taint is
    expected to refuse some legitimate work today. Value-level provenance should lower
    it, and this bound is what stops a regression from going unnoticed.
    """

    false_block_rate = report["false_block_rate"]
    assert false_block_rate is not None
    assert false_block_rate <= 0.2, report["false_blocked_scenarios"]


def test_benign_scenarios_all_succeed_undefended(report: dict[str, Any]) -> None:
    undefended_benign = [
        item
        for item in report["results"]
        if item["mode"] == "undefended" and item["kind"] == "benign"
    ]
    assert undefended_benign
    assert all(item["all_calls_executed"] for item in undefended_benign)
