"""External anchoring for the receipt chain — the tail-deletion detector.

The signed hash chain proves that *retained* receipts were not modified. It cannot prove
completeness: truncate the last three entries and the remainder still verifies, and an
attacker who replaces both the log and the signing key can fabricate a clean history. Both
gaps have the same shape — nothing *outside* the log remembers how far the chain had got.

An anchor is that outside memory: after each append, the chain head (session, sequence,
receipt hash) is recorded somewhere the log's attacker cannot rewrite. Verification then
demands that the replayed chain still *contains* the anchored head, hash-identical. A
truncated tail no longer contains it; a rebuilt log contains a different hash at that
sequence. Either way, gone is detected as gone.

Honest scope: this module supplies the mechanism and a JSONL backend. The trust argument
is entirely about *where* the anchor file lives — a different host, append-only storage, a
git remote, a timestamping service. An anchor on the same disk as the log only defends
against attackers who did not think of it, and the docs say so rather than implying more.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from capgate.receipts.model import Receipt

_ANCHOR_FIELDS = frozenset({"session_id", "seq", "receipt_hash"})


@dataclass(frozen=True)
class ChainAnchor:
    """One remembered chain head."""

    session_id: str
    seq: int
    receipt_hash: str

    def __post_init__(self) -> None:
        if not self.session_id or not self.receipt_hash or self.seq < 1:
            raise ValueError("chain anchor fields must be non-empty and seq positive")


class AnchorStore(Protocol):
    def record(self, anchor: ChainAnchor) -> None: ...

    def latest(self, session_id: str) -> ChainAnchor | None: ...


class JsonlAnchorStore:
    """Append-only JSONL anchor backend.

    Strict on read: a malformed or non-monotonic anchor file is an error, never something
    to skip past — a corrupted anchor trail is exactly the artifact an attacker would
    leave, so it must fail verification rather than soften it.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def record(self, anchor: ChainAnchor) -> None:
        previous = self.latest(anchor.session_id)
        if previous is not None and anchor.seq <= previous.seq:
            raise ValueError("chain anchor sequence must advance monotonically")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(
            {
                "session_id": anchor.session_id,
                "seq": anchor.seq,
                "receipt_hash": anchor.receipt_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def latest(self, session_id: str) -> ChainAnchor | None:
        if not session_id:
            raise ValueError("anchor lookup requires a session id")
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        newest: ChainAnchor | None = None
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                raise ValueError(f"anchor file contains a blank line at {line_number}")
            anchor = _parse_anchor_line(line, line_number)
            if anchor.session_id != session_id:
                continue
            if newest is not None and anchor.seq <= newest.seq:
                raise ValueError(
                    f"anchor file is not monotonic for the session at line {line_number}"
                )
            newest = anchor
        return newest


def anchor_for(receipt: Receipt) -> ChainAnchor:
    return ChainAnchor(
        session_id=receipt.session_id,
        seq=receipt.seq,
        receipt_hash=receipt.receipt_hash(),
    )


def verify_anchor(receipts: tuple[Receipt, ...], anchor: ChainAnchor) -> None:
    """Require the replayed chain to still contain the anchored head, hash-identical.

    Raising here means the log the anchor remembers is not the log being verified: either
    the tail was deleted past the anchor, or the log was rebuilt (new key, new history).
    """

    for receipt in receipts:
        if receipt.seq != anchor.seq:
            continue
        if receipt.receipt_hash() != anchor.receipt_hash:
            raise ValueError(
                "anchored receipt hash does not match the log: the chain was rebuilt"
            )
        return
    raise ValueError(
        "anchored chain head is missing from the log: the tail was deleted or the log "
        "was replaced"
    )


def _parse_anchor_line(line: str, line_number: int) -> ChainAnchor:
    try:
        decoded: object = json.loads(line)
    except ValueError:
        raise ValueError(f"anchor file line {line_number} is not valid JSON") from None
    if not isinstance(decoded, dict) or set(decoded) != _ANCHOR_FIELDS:
        raise ValueError(f"anchor file line {line_number} has an invalid schema")
    session_id = decoded["session_id"]
    seq = decoded["seq"]
    receipt_hash = decoded["receipt_hash"]
    if (
        not isinstance(session_id, str)
        or not isinstance(seq, int)
        or isinstance(seq, bool)
        or not isinstance(receipt_hash, str)
    ):
        raise ValueError(f"anchor file line {line_number} has invalid field types")
    try:
        return ChainAnchor(session_id=session_id, seq=seq, receipt_hash=receipt_hash)
    except ValueError:
        raise ValueError(f"anchor file line {line_number} has invalid values") from None
