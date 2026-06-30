from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


def test_capgate_ground_truth_run_replay_verifies_every_tool_call(tmp_path: Path) -> None:
    pytest.importorskip("agentdojo")
    report_path = tmp_path / "report.json"
    subprocess.run(
        [
            sys.executable,
            "bench/agentdojo_runner.py",
            "--mode",
            "capgate",
            "--enforcement",
            "stage1",
            "--pipeline",
            "ground-truth",
            "--benchmark-version",
            "v1.2.2",
            "--suite",
            "workspace",
            "--attack",
            "none",
            "--user-task",
            "user_task_0",
            "--logdir",
            str(tmp_path / "runs"),
            "--force-rerun",
            "--receipt-log",
            str(tmp_path / "receipts.jsonl"),
            "--key-file",
            str(tmp_path / "ed25519.private"),
            "--public-key-file",
            str(tmp_path / "ed25519.public"),
            "--out",
            str(report_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["status"] == "completed"
    assert report["utility"] == 1.0
    assert report["mediation"] == "agentdojo-runtime"
    assert report["observed_tool_calls"] > 0
    assert report["mediated_tool_calls"] == report["observed_tool_calls"]
    assert report["verified_receipts"] == report["observed_tool_calls"]
    assert report["receipt_chain_valid"] is True
    assert report["receipt_session_ids"]
    assert report["agentdojo_version"]
    assert report["command"][1] == "bench/agentdojo_runner.py"
    assert report["code_revision"] is None
    assert report["enforcement"] == "stage1"
    assert report["allowed_tool_calls"] == report["observed_tool_calls"]
    assert report["blocked_tool_calls"] == 0
