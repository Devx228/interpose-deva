from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import cast

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_DIR = Path(__file__).resolve().parent
SERVER = DEMO_DIR / "server.py"
POLICY = DEMO_DIR / "policy.yaml"
TOOL_METADATA = DEMO_DIR / "tool-metadata.yaml"
MARKER = "CAPGATE_OFFLINE_PRIVATE_MARKER_7f3a9c"
SCOPE = "offline deterministic control validation, not AgentDojo ASR or production isolation"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="capgate-offline-demo-") as directory:
        state = Path(directory)
        first_responses = _run_proxy(
            state,
            private_description="Read private demo data.",
            messages=[
                _request(1, "tools/list"),
                _tool_call(2, "read_private", {}),
                _tool_call(3, "send_external", {"payload": MARKER}),
            ],
        )
        _require(len(first_responses) == 3, "first proxy run returned unexpected output")
        listed, private_result, external_result = first_responses
        _require("result" in listed, "tools/list did not succeed")
        _require(MARKER in json.dumps(private_result), "private marker was not returned")
        _require(
            _error_rule_id(external_result) == "flow.lethal_trifecta",
            "external send was not blocked by the lethal-trifecta rule",
        )

        receipt_log = state / "receipts.jsonl"
        receipt_text = receipt_log.read_text(encoding="utf-8")
        _require(MARKER not in receipt_text, "raw private marker appeared in receipt log")
        first_receipts = _json_lines(receipt_text)
        _require(len(first_receipts) == 3, "first proxy run wrote an unexpected receipt count")
        session_id = _required_string(first_receipts[0], "session_id")

        replay = _run(_replay_command(state, receipt_log, session_id))
        _require_success(replay, "receipt replay failed")
        _require("signature_chain=valid" in replay.stdout, "receipt replay was not verified")
        _require("receipt_count=3" in replay.stdout, "receipt replay count was unexpected")

        changed = _run_proxy(
            state,
            private_description="Changed private tool definition.",
            messages=[_request(4, "tools/list")],
        )
        _require(len(changed) == 1, "restart returned unexpected output")
        _require(
            _error_rule_id(changed[0]) == "mcp.tool_definition_changed",
            "changed tool definition was not blocked",
        )

        call_log = state / "server-calls.txt"
        server_calls = call_log.read_text(encoding="utf-8").splitlines()
        _require(server_calls == ["read_private"], "blocked external tool reached the server")

        tampered_log = state / "tampered-receipts.jsonl"
        tampered_receipts = _json_lines(receipt_log.read_text(encoding="utf-8"))
        tampered_receipts[0]["reason"] = "tampered"
        tampered_log.write_text(
            "".join(
                json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
                for receipt in tampered_receipts
            ),
            encoding="utf-8",
        )
        tampered_replay = _run(_replay_command(state, tampered_log, session_id))
        tamper_detected = (
            tampered_replay.returncode != 0
            and "invalid receipt signature" in tampered_replay.stderr
        )
        _require(tamper_detected, "tampered receipt replay did not fail verification")

        summary: dict[str, object] = {
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
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


def _run_proxy(
    state: Path,
    *,
    private_description: str,
    messages: list[dict[str, object]],
) -> list[dict[str, object]]:
    command = [
        sys.executable,
        "-m",
        "capgate",
        "proxy",
        "--receipt-log",
        str(state / "receipts.jsonl"),
        "--key-file",
        str(state / "ed25519.private"),
        "--public-key-file",
        str(state / "ed25519.public"),
        "--server-name",
        "offline-demo",
        "--tool-pin-db",
        str(state / "tool-pins.sqlite3"),
        "--policy-file",
        str(POLICY),
        "--tool-metadata-file",
        str(TOOL_METADATA),
        "--downstream",
        sys.executable,
        str(SERVER),
        "--call-log",
        str(state / "server-calls.txt"),
        "--marker",
        MARKER,
        "--private-description",
        private_description,
    ]
    input_text = "".join(
        json.dumps(message, sort_keys=True, separators=(",", ":")) + "\n"
        for message in messages
    )
    completed = _run(command, input_text=input_text)
    _require_success(completed, "proxy run failed")
    return _json_lines(completed.stdout)


def _replay_command(state: Path, receipt_log: Path, session_id: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "capgate",
        "replay",
        session_id,
        "--receipt-log",
        str(receipt_log),
        "--public-key-file",
        str(state / "ed25519.public"),
    ]


def _child_environment() -> dict[str, str]:
    """Return the smallest environment a child needs, carrying no ambient credentials.

    The demo proves it runs with no API key, no `.env`, and no inherited secrets, so it
    supplies an explicit environment instead of the parent's. POSIX needs nothing;
    Windows needs `SYSTEMROOT` before `import asyncio` can load its extension modules.
    """

    if sys.platform != "win32":
        return {}
    system_root = os.environ.get("SYSTEMROOT")
    return {"SYSTEMROOT": system_root} if system_root else {}


def _run(
    command: list[str],
    *,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # noqa: S603 - command is assembled only from demo constants
            command,
            cwd=REPO_ROOT,
            env=_child_environment(),
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("offline demo command timed out") from None


def _request(request_id: int, method: str) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "method": method}


def _tool_call(
    request_id: int,
    tool: str,
    arguments: dict[str, object],
) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


def _json_lines(text: str) -> list[dict[str, object]]:
    return [_json_object(line) for line in text.splitlines() if line]


def _json_object(text: str) -> dict[str, object]:
    decoded = cast(object, json.loads(text))
    if not isinstance(decoded, dict) or any(not isinstance(key, str) for key in decoded):
        raise RuntimeError("offline demo received a non-object JSON value")
    return cast(dict[str, object], decoded)


def _error_rule_id(response: dict[str, object]) -> str | None:
    error = response.get("error")
    if not isinstance(error, dict):
        return None
    data = error.get("data")
    if not isinstance(data, dict):
        return None
    rule_id = data.get("rule_id")
    return rule_id if isinstance(rule_id, str) else None


def _required_string(data: dict[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise RuntimeError("offline demo receipt is missing required identity")
    return value


def _require_success(completed: subprocess.CompletedProcess[str], message: str) -> None:
    _require(completed.returncode == 0, message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


if __name__ == "__main__":
    raise SystemExit(main())
