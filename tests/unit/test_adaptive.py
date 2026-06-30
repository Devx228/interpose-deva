from __future__ import annotations

import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, cast

import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "bench"))

adaptive = __import__("adaptive")
EvidenceError = cast(type[Exception], adaptive.EvidenceError)
compare_reports = cast(
    Callable[[Sequence[Path], Sequence[Path]], dict[str, object]],
    adaptive.compare_reports,
)
main = cast(Callable[[Sequence[str] | None], int], adaptive.main)


def _report(*, mode: str, user_task: str = "user_task_0") -> dict[str, Any]:
    capgate = mode == "capgate"
    return {
        "status": "completed",
        "evaluation_methodology": "attacker-moves-second",
        "mode": mode,
        "enforcement": "stage1" if capgate else "none",
        "mediation": "agentdojo-runtime" if capgate else "none",
        "receipt_chain_valid": True if capgate else None,
        "command": ["python", "bench/agentdojo_runner.py"],
        "code_revision": "abc123",
        "agentdojo_version": "0.1.35",
        "benchmark_version": "v1.2.2",
        "suite": "workspace",
        "pipeline": "agentdojo",
        "model": "test-model",
        "attack": "adaptive-direct",
        "user_tasks": [user_task],
        "injection_tasks": ["injection_task_0"],
        "asr": 0.5,
        "utility": 0.75,
        "security_cases": 2,
        "utility_cases": 2,
    }


def _write(path: Path, report: dict[str, Any]) -> Path:
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_comparison_aggregates_only_supplied_numeric_evidence(tmp_path: Path) -> None:
    control_one = _report(mode="undefended")
    capgate_one = _report(mode="capgate")
    capgate_one["asr"] = 0.25
    capgate_one["utility"] = 0.5
    control_two = _report(mode="undefended", user_task="user_task_1")
    control_two.update(asr=1.0, utility=0.0, security_cases=1, utility_cases=1)
    capgate_two = _report(mode="capgate", user_task="user_task_1")
    capgate_two.update(asr=0.0, utility=1.0, security_cases=1, utility_cases=1)

    result = compare_reports(
        [
            _write(tmp_path / "control-1.json", control_one),
            _write(tmp_path / "control-2.json", control_two),
        ],
        [
            _write(tmp_path / "capgate-1.json", capgate_one),
            _write(tmp_path / "capgate-2.json", capgate_two),
        ],
    )

    assert result["case_groups"] == 2
    control = result["control"]
    capgate = result["capgate"]
    deltas = result["deltas"]
    assert isinstance(control, dict)
    assert isinstance(capgate, dict)
    assert isinstance(deltas, dict)
    assert control["asr"] == pytest.approx(2 / 3)
    assert capgate["asr"] == pytest.approx(1 / 6)
    assert control["utility"] == pytest.approx(0.5)
    assert capgate["utility"] == pytest.approx(2 / 3)
    assert deltas["asr_capgate_minus_control"] == pytest.approx(-0.5)
    assert deltas["asr_reduction_control_minus_capgate"] == pytest.approx(0.5)
    assert deltas["utility_capgate_minus_control"] == pytest.approx(1 / 6)


@pytest.mark.parametrize(
    ("field", "value"),
    [("asr", None), ("asr", float("nan")), ("utility", True), ("security_cases", 0)],
)
def test_comparison_rejects_unmeasured_numeric_evidence(
    tmp_path: Path, field: str, value: object
) -> None:
    control = _report(mode="undefended")
    control[field] = value

    with pytest.raises(EvidenceError):
        compare_reports(
            [_write(tmp_path / "control.json", control)],
            [_write(tmp_path / "capgate.json", _report(mode="capgate"))],
        )


def test_comparison_rejects_static_report_without_adaptive_provenance(tmp_path: Path) -> None:
    control = _report(mode="undefended")
    control.pop("evaluation_methodology")

    with pytest.raises(EvidenceError, match="adaptive-methodology"):
        compare_reports(
            [_write(tmp_path / "control.json", control)],
            [_write(tmp_path / "capgate.json", _report(mode="capgate"))],
        )


def test_comparison_rejects_incompatible_case_identity(tmp_path: Path) -> None:
    with pytest.raises(EvidenceError, match="case identities"):
        compare_reports(
            [_write(tmp_path / "control.json", _report(mode="undefended"))],
            [
                _write(
                    tmp_path / "capgate.json",
                    _report(mode="capgate", user_task="user_task_99"),
                )
            ],
        )


def test_comparison_rejects_missing_code_revision_on_both_sides(tmp_path: Path) -> None:
    control = _report(mode="undefended")
    capgate = _report(mode="capgate")
    control["code_revision"] = None
    capgate["code_revision"] = None

    with pytest.raises(EvidenceError, match="code-revision"):
        compare_reports(
            [_write(tmp_path / "control.json", control)],
            [_write(tmp_path / "capgate.json", capgate)],
        )


def test_cli_writes_json_only_after_valid_comparison(tmp_path: Path) -> None:
    control = _write(tmp_path / "control.json", _report(mode="undefended"))
    capgate = _write(tmp_path / "capgate.json", _report(mode="capgate"))
    output = tmp_path / "comparison.json"

    exit_code = main(
        ["--control", str(control), "--capgate", str(capgate), "--out", str(output)]
    )

    assert exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "completed"


def test_cli_reports_not_measured_without_creating_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    control = _report(mode="undefended")
    control["status"] = "blocked"
    control_path = _write(tmp_path / "secret-control-name.json", control)
    capgate_path = _write(tmp_path / "capgate.json", _report(mode="capgate"))
    output = tmp_path / "comparison.json"

    exit_code = main(
        [
            "--control",
            str(control_path),
            "--capgate",
            str(capgate_path),
            "--out",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "NOT YET MEASURED" in captured.err
    assert "secret-control-name" not in captured.err
    assert not output.exists()
