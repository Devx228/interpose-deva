from __future__ import annotations

import json
import runpy
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest


def test_capgate_ground_truth_run_replay_verifies_every_tool_call(tmp_path: Path) -> None:
    pytest.importorskip("agentdojo")
    repo_root = Path(__file__).resolve().parents[2]
    clean_git_revision = _load_clean_git_revision(repo_root)
    expected_revision = clean_git_revision(repo_root)
    (tmp_path / ".env").mkdir()
    report_path = tmp_path / "report.json"
    subprocess.run(
        [
            sys.executable,
            str(repo_root / "bench/agentdojo_runner.py"),
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
        cwd=tmp_path,
        timeout=30,
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
    assert report["code_revision"] == expected_revision
    assert report["enforcement"] == "stage1"
    assert report["allowed_tool_calls"] == report["observed_tool_calls"]
    assert report["blocked_tool_calls"] == 0


def test_clean_git_revision_requires_head_and_clean_worktree(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    clean_git_revision = _load_clean_git_revision(repo_root)
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")

    assert clean_git_revision(repo) is None

    _git(repo, "config", "user.email", "capgate-test@example.invalid")
    _git(repo, "config", "user.name", "CapGate Test")
    (repo / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    _git(repo, "add", "tracked.txt")
    _git(repo, "commit", "--quiet", "-m", "initial")
    expected = _git(repo, "rev-parse", "HEAD").stdout.strip()

    assert clean_git_revision(repo) == expected

    (repo / "untracked.txt").write_text("untracked\n", encoding="utf-8")

    assert clean_git_revision(repo) is None


def _load_clean_git_revision(repo_root: Path) -> Callable[[Path], str | None]:
    namespace = runpy.run_path(str(repo_root / "bench/agentdojo_runner.py"))
    return cast(Callable[[Path], str | None], namespace["_clean_git_revision"])


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "--no-optional-locks", *args],
        cwd=repo,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        text=True,
        timeout=10,
    )
