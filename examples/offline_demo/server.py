from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import cast


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--call-log", type=Path, required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--private-description", required=True)
    args = parser.parse_args(argv)

    for line in sys.stdin:
        request = _json_object(line)
        response = _response_for(
            request,
            call_log=args.call_log,
            marker=args.marker,
            private_description=args.private_description,
        )
        sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    return 0


def _response_for(
    request: dict[str, object],
    *,
    call_log: Path,
    marker: str,
    private_description: str,
) -> dict[str, object]:
    request_id = request.get("id")
    method = request.get("method")
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "read_private",
                        "description": private_description,
                        "inputSchema": {"type": "object", "additionalProperties": False},
                    },
                    {
                        "name": "send_external",
                        "description": "Send a payload to an external destination.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"payload": {"type": "string"}},
                            "required": ["payload"],
                            "additionalProperties": False,
                        },
                    },
                ]
            },
        }
    if method != "tools/call":
        return _error(request_id, -32601, "method not found")

    params = request.get("params")
    if not isinstance(params, dict):
        return _error(request_id, -32602, "invalid params")
    typed_params = cast(dict[str, object], params)
    tool = typed_params.get("name")
    if not isinstance(tool, str):
        return _error(request_id, -32602, "invalid tool name")

    call_log.parent.mkdir(parents=True, exist_ok=True)
    with call_log.open("a", encoding="utf-8") as handle:
        handle.write(tool + "\n")

    if tool == "read_private":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"content": [{"type": "text", "text": marker}]},
        }
    if tool == "send_external":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"content": [{"type": "text", "text": "sent"}]},
        }
    return _error(request_id, -32601, "unknown tool")


def _error(request_id: object, code: int, message: str) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _json_object(text: str) -> dict[str, object]:
    decoded = cast(object, json.loads(text))
    if not isinstance(decoded, dict) or any(not isinstance(key, str) for key in decoded):
        raise ValueError("expected a JSON object")
    return cast(dict[str, object], decoded)


if __name__ == "__main__":
    raise SystemExit(main())
