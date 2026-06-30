from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from capgate.receipts.model import Receipt


@dataclass(frozen=True)
class ReceiptSessionState:
    next_seq: int
    prev_receipt_hash: str | None


class JsonlReceiptStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, receipt: Receipt) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            encoded = json.dumps(receipt.to_dict(), sort_keys=True, separators=(",", ":"))
            handle.write(encoded + "\n")

    def iter_receipts(self, session_id: str | None = None) -> list[Receipt]:
        if not self.path.exists():
            return []
        receipts: list[Receipt] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                data = json.loads(line)
                if not isinstance(data, dict):
                    raise ValueError("receipt log line must be a JSON object")
                receipt = Receipt.from_dict(data)
                if session_id is None or receipt.session_id == session_id:
                    receipts.append(receipt)
        return receipts

    def last_state(self, session_id: str) -> ReceiptSessionState:
        receipts = self.iter_receipts(session_id)
        if not receipts:
            return ReceiptSessionState(next_seq=1, prev_receipt_hash=None)
        last = receipts[-1]
        return ReceiptSessionState(next_seq=last.seq + 1, prev_receipt_hash=last.receipt_hash())
