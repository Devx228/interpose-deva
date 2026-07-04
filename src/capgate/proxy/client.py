from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from typing import Protocol

from capgate.proxy.events import JsonObject, JsonValue, validate_jsonrpc_response


class DownstreamClient(Protocol):
    async def request(self, message: JsonObject) -> JsonObject | None: ...


class StdioJsonRpcClient:
    def __init__(self, command: Sequence[str]) -> None:
        self._command = list(command)
        self._process: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        self._process = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def close(self) -> None:
        if self._process is None:
            return
        self._process.terminate()
        try:
            await asyncio.wait_for(self._process.wait(), timeout=2)
        except TimeoutError:
            self._process.kill()
            await self._process.wait()

    async def request(self, message: JsonObject) -> JsonObject | None:
        process = self._require_process()
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("downstream process stdio is unavailable")

        async with self._lock:
            payload = json.dumps(message, separators=(",", ":"), sort_keys=True).encode()
            process.stdin.write(payload + b"\n")
            await process.stdin.drain()
            if "id" not in message:
                return None
            return await self._read_response(process, message["id"])

    def _require_process(self) -> asyncio.subprocess.Process:
        if self._process is None:
            raise RuntimeError("downstream process has not been started")
        return self._process

    async def _read_response(
        self,
        process: asyncio.subprocess.Process,
        request_id: JsonValue,
    ) -> JsonObject:
        if process.stdout is None:
            raise RuntimeError("downstream stdout is unavailable")
        line = await process.stdout.readline()
        if not line:
            raise RuntimeError("downstream process closed stdout")
        decoded = json.loads(line.decode())
        if not isinstance(decoded, dict):
            raise RuntimeError("downstream returned a non-object JSON-RPC message")
        validate_jsonrpc_response(decoded, request_id)
        return decoded
