from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from capgate.receipts.model import Receipt


@dataclass(frozen=True)
class ReceiptSessionState:
    next_seq: int
    prev_receipt_hash: str | None


_EMPTY_SESSION_STATE = ReceiptSessionState(next_seq=1, prev_receipt_hash=None)


class JsonlReceiptStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._states: dict[str, ReceiptSessionState] = {}
        self._scanned_size = -1

    def append(self, receipt: Receipt) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            encoded = json.dumps(receipt.to_dict(), sort_keys=True, separators=(",", ":"))
            handle.write(encoded + "\n")
        if self._scanned_size >= 0:
            self._states[receipt.session_id] = ReceiptSessionState(
                next_seq=receipt.seq + 1,
                prev_receipt_hash=receipt.receipt_hash(),
            )
            self._scanned_size = self._current_size()

    def iter_receipts(self, session_id: str | None = None) -> list[Receipt]:
        if not self.path.exists():
            return []
        receipts: list[Receipt] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                data = cast(
                    object,
                    json.loads(line, object_pairs_hook=_reject_duplicate_keys),
                )
                if not isinstance(data, dict):
                    raise ValueError("receipt log line must be a JSON object")
                receipt = Receipt.from_dict(cast(dict[str, Any], data))
                if session_id is None or receipt.session_id == session_id:
                    receipts.append(receipt)
        return receipts

    def last_state(self, session_id: str) -> ReceiptSessionState:
        """Return the next sequence and previous hash for a session.

        Scanning the whole log on every append is quadratic over a session, so the tail
        state is cached per session and advanced on write. The cache is discarded
        whenever the file size no longer matches the last scan, so an append by another
        writer forces a fresh read rather than a stale sequence number.
        """

        size = self._current_size()
        if size != self._scanned_size:
            self._rescan()
        return self._states.get(session_id, _EMPTY_SESSION_STATE)

    def _rescan(self) -> None:
        states: dict[str, ReceiptSessionState] = {}
        for receipt in self.iter_receipts():
            states[receipt.session_id] = ReceiptSessionState(
                next_seq=receipt.seq + 1,
                prev_receipt_hash=receipt.receipt_hash(),
            )
        self._states = states
        self._scanned_size = self._current_size()

    def _current_size(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("receipt log contains duplicate JSON object keys")
        result[key] = value
    return result
