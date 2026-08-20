from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from capgate.engine.pipeline import DecisionPipeline
from capgate.mcp_security.isolation import ServerToolRegistry
from capgate.mcp_security.pinning import ToolPinRegistry
from capgate.mcp_security.store import SqliteToolPinStore
from capgate.proxy.client import StdioJsonRpcClient
from capgate.proxy.events import JsonObject
from capgate.proxy.session import ProxySession
from capgate.receipts.anchor import JsonlAnchorStore
from capgate.receipts.signer import Ed25519Signer, ReceiptWriter
from capgate.receipts.store import JsonlReceiptStore


async def run_stdio_proxy(
    *,
    downstream_command: Sequence[str],
    receipt_log: Path,
    private_key_file: Path,
    public_key_file: Path,
    server_name: str,
    decision_pipeline: DecisionPipeline | None = None,
    tool_pin_db: Path | None = None,
    anchor_file: Path | None = None,
) -> None:
    signer = Ed25519Signer.load_or_create(private_key_file, public_key_file)
    store = JsonlReceiptStore(receipt_log)
    receipt_writer = ReceiptWriter(
        store=store,
        signer=signer,
        anchor_store=JsonlAnchorStore(anchor_file) if anchor_file is not None else None,
    )
    downstream = StdioJsonRpcClient(downstream_command)
    await downstream.start()
    session = ProxySession(
        downstream=downstream,
        receipt_writer=receipt_writer,
        server_name=server_name,
        decision_pipeline=decision_pipeline,
        tool_pin_registry=ToolPinRegistry(
            SqliteToolPinStore(tool_pin_db) if tool_pin_db is not None else None
        ),
        server_tool_registry=ServerToolRegistry(),
    )

    try:
        while True:
            line = await asyncio.to_thread(sys.stdin.readline)
            if not line:
                break
            response = await session.handle_message(_load_json_object(line))
            if response is not None:
                sys.stdout.write(json.dumps(response, separators=(",", ":"), sort_keys=True) + "\n")
                sys.stdout.flush()
    finally:
        await downstream.close()


def _load_json_object(line: str) -> JsonObject:
    decoded = json.loads(line)
    if not isinstance(decoded, dict):
        raise ValueError("expected a JSON object per stdio line")
    return decoded
