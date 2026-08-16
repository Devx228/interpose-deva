from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO = REPO_ROOT / "examples" / "offline_demo" / "run.py"
MARKER = "CAPGATE_OFFLINE_PRIVATE_MARKER_7f3a9c"
SCOPE = "offline deterministic control validation, not AgentDojo ASR or production isolation"


def test_offline_cli_demo_proves_deterministic_controls(
    credential_free_env: dict[str, str],
) -> None:
    completed = subprocess.run(
        [sys.executable, str(DEMO)],
        cwd=REPO_ROOT,
        env=credential_free_env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert len(completed.stdout.splitlines()) == 1
    assert MARKER not in completed.stdout
    assert MARKER not in completed.stderr
    summary = _json_object(completed.stdout)
    assert summary == {
        "scope": SCOPE,
        "tools_list": "ALLOW",
        "read_private": "ALLOW",
        "send_external": "BLOCK",
        "send_rule_id": "flow.lethal_trifecta",
        "send_reached_server": False,
        "receipt_count": 3,
        "receipts_replayed": True,
        "raw_marker_in_receipts": False,
        "definition_change": "BLOCK",
        "definition_change_rule_id": "mcp.tool_definition_changed",
        "tamper_detected": True,
    }


def _json_object(text: str) -> dict[str, object]:
    decoded = cast(object, json.loads(text))
    assert isinstance(decoded, dict)
    assert all(isinstance(key, str) for key in decoded)
    return cast(dict[str, object], decoded)
