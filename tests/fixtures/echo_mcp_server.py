from __future__ import annotations

import json
import sys
from typing import Any


def main() -> int:
    description = sys.argv[1] if len(sys.argv) > 1 else "Echo arguments."
    for line in sys.stdin:
        message = json.loads(line)
        if not isinstance(message, dict):
            continue
        response = _response_for(message, description=description)
        sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    return 0


def _response_for(message: dict[str, Any], *, description: str) -> dict[str, Any]:
    request_id = message.get("id")
    method = message.get("method")
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "echo",
                        "description": description,
                        "inputSchema": {"type": "object"},
                    }
                ]
            },
        }
    if method == "tools/call":
        params = message.get("params", {})
        if not isinstance(params, dict):
            params = {}
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(params.get("arguments", {}), sort_keys=True),
                    }
                ]
            },
        }
    return {"jsonrpc": "2.0", "id": request_id, "result": {"ok": True}}


if __name__ == "__main__":
    raise SystemExit(main())
