from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

ADAPTIVE_METHODOLOGY = "attacker-moves-second"
Mode = Literal["undefended", "capgate"]


class EvidenceError(ValueError):
    """A sanitized explanation for unavailable comparison evidence."""


@dataclass(frozen=True)
class ReportEvidence:
    path: Path
    sha256: str
    mode: Mode
    case_key: tuple[object, ...]
    code_revision: str
    agentdojo_version: str
    asr: float
    utility: float
    security_cases: int
    utility_cases: int


def compare_reports(
    control_paths: Sequence[Path],
    capgate_paths: Sequence[Path],
) -> dict[str, object]:
    if not control_paths or not capgate_paths:
        raise EvidenceError("both control and CapGate reports are required")

    controls = _index_reports(control_paths, "undefended")
    capgate = _index_reports(capgate_paths, "capgate")
    if controls.keys() != capgate.keys():
        raise EvidenceError("control and CapGate case identities do not match")

    for case_key, control in controls.items():
        protected = capgate[case_key]
        if control.agentdojo_version != protected.agentdojo_version:
            raise EvidenceError("paired reports use incompatible AgentDojo versions")
        if control.code_revision != protected.code_revision:
            raise EvidenceError("paired reports use incompatible code revisions")
        if control.security_cases != protected.security_cases:
            raise EvidenceError("paired reports contain different security case counts")
        if control.utility_cases != protected.utility_cases:
            raise EvidenceError("paired reports contain different utility case counts")

    control_aggregate = _aggregate(tuple(controls.values()))
    capgate_aggregate = _aggregate(tuple(capgate.values()))
    return {
        "status": "completed",
        "evaluation_methodology": ADAPTIVE_METHODOLOGY,
        "comparison": "supplied-control-vs-capgate-reports",
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "case_groups": len(controls),
        "control": control_aggregate,
        "capgate": capgate_aggregate,
        "deltas": {
            "asr_capgate_minus_control": (
                capgate_aggregate["asr"] - control_aggregate["asr"]
            ),
            "asr_reduction_control_minus_capgate": (
                control_aggregate["asr"] - capgate_aggregate["asr"]
            ),
            "utility_capgate_minus_control": (
                capgate_aggregate["utility"] - control_aggregate["utility"]
            ),
        },
        "sources": {
            "control": _source_records(tuple(controls.values())),
            "capgate": _source_records(tuple(capgate.values())),
        },
        "evidence_basis": "completed numeric fields from supplied reports only",
    }


def write_comparison(report: Mapping[str, object], output: Path) -> None:
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(encoded, encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate and compare existing adaptive AgentDojo reports offline."
    )
    parser.add_argument("--control", action="append", type=Path, required=True)
    parser.add_argument("--capgate", action="append", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = compare_reports(args.control, args.capgate)
        write_comparison(report, args.out)
    except (EvidenceError, OSError) as exc:
        message = str(exc) if isinstance(exc, EvidenceError) else "report output is unavailable"
        print(f"NOT YET MEASURED — {message}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


def _index_reports(paths: Sequence[Path], mode: Mode) -> dict[tuple[object, ...], ReportEvidence]:
    indexed: dict[tuple[object, ...], ReportEvidence] = {}
    for path in paths:
        evidence = _load_report(path, mode)
        if evidence.case_key in indexed:
            raise EvidenceError("duplicate case identity in supplied reports")
        indexed[evidence.case_key] = evidence
    return indexed


def _load_report(path: Path, expected_mode: Mode) -> ReportEvidence:
    try:
        raw = path.read_bytes()
        document: Any = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError("an input report is missing or invalid JSON") from exc
    if not isinstance(document, dict):
        raise EvidenceError("an input report is not a JSON object")

    report: Mapping[str, Any] = document
    if report.get("status") != "completed":
        raise EvidenceError("an input report is not a completed run")
    if report.get("evaluation_methodology") != ADAPTIVE_METHODOLOGY:
        raise EvidenceError("explicit adaptive-methodology provenance is missing")
    if report.get("mode") != expected_mode:
        raise EvidenceError("an input report has the wrong comparison mode")

    command = report.get("command")
    if not isinstance(command, list) or not command or not all(
        isinstance(part, str) and part for part in command
    ):
        raise EvidenceError("run-command provenance is missing")

    if expected_mode == "undefended":
        if report.get("enforcement") != "none" or report.get("mediation") != "none":
            raise EvidenceError("control report is not an undefended run")
    elif (
        report.get("enforcement") in {None, "none"}
        or report.get("mediation") != "agentdojo-runtime"
        or report.get("receipt_chain_valid") is not True
    ):
        raise EvidenceError("CapGate report lacks mediated enforcement evidence")

    case_key = (
        _required_string(report, "benchmark_version"),
        _required_string(report, "suite"),
        _required_string(report, "pipeline"),
        _required_string(report, "model"),
        _required_string(report, "attack"),
        _string_tuple(report, "user_tasks"),
        _string_tuple(report, "injection_tasks"),
    )
    return ReportEvidence(
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        mode=expected_mode,
        case_key=case_key,
        code_revision=_required_string(report, "code_revision"),
        agentdojo_version=_required_string(report, "agentdojo_version"),
        asr=_rate(report, "asr"),
        utility=_rate(report, "utility"),
        security_cases=_positive_int(report, "security_cases"),
        utility_cases=_positive_int(report, "utility_cases"),
    )


def _required_string(report: Mapping[str, Any], field: str) -> str:
    value = report.get(field)
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"required {field.replace('_', '-')} provenance is missing")
    return value


def _string_tuple(report: Mapping[str, Any], field: str) -> tuple[str, ...]:
    value = report.get(field)
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item for item in value
    ):
        raise EvidenceError(f"required {field.replace('_', '-')} case identity is missing")
    return tuple(value)


def _rate(report: Mapping[str, Any], field: str) -> float:
    value = report.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceError(f"{field} is not measured")
    measured = float(value)
    if not math.isfinite(measured) or not 0.0 <= measured <= 1.0:
        raise EvidenceError(f"{field} is not a finite rate")
    return measured


def _positive_int(report: Mapping[str, Any], field: str) -> int:
    value = report.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise EvidenceError(f"{field.replace('_', ' ')} is not a positive measured count")
    return value


def _aggregate(reports: tuple[ReportEvidence, ...]) -> dict[str, float | int]:
    security_cases = sum(report.security_cases for report in reports)
    utility_cases = sum(report.utility_cases for report in reports)
    return {
        "asr": sum(report.asr * report.security_cases for report in reports) / security_cases,
        "utility": sum(report.utility * report.utility_cases for report in reports) / utility_cases,
        "security_cases": security_cases,
        "utility_cases": utility_cases,
        "report_count": len(reports),
    }


def _source_records(reports: tuple[ReportEvidence, ...]) -> list[dict[str, str]]:
    return [
        {"path": str(report.path), "sha256": report.sha256}
        for report in sorted(reports, key=lambda item: str(item.path))
    ]


if __name__ == "__main__":
    raise SystemExit(main())
