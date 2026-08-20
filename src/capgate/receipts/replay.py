from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from capgate.receipts.anchor import AnchorStore, verify_anchor
from capgate.receipts.model import Receipt
from capgate.receipts.signer import Ed25519Verifier
from capgate.receipts.store import JsonlReceiptStore


@dataclass(frozen=True)
class ReplayReport:
    session_id: str
    receipts: tuple[Receipt, ...]

    def to_lines(self) -> list[str]:
        lines = [
            f"session_id={self.session_id}",
            f"receipt_count={len(self.receipts)}",
            "signature_chain=valid",
        ]
        for receipt in self.receipts:
            fields = [
                f"seq={receipt.seq}",
                f"server={receipt.server}",
                f"tool={receipt.tool}",
                f"verdict={receipt.verdict}",
                f"rule_id={receipt.rule_id}",
                f"reason={receipt.reason}",
            ]
            if receipt.sandbox is not None:
                fields.extend(
                    [
                        f"sandbox_backend={receipt.sandbox.backend}",
                        f"sandbox_status={receipt.sandbox.status}",
                        f"sandbox_image_digest={receipt.sandbox.image_digest}",
                    ]
                )
            lines.append(
                " ".join(fields)
            )
        return lines


def replay_session(
    receipt_log: Path,
    session_id: str,
    verifier: Ed25519Verifier,
    *,
    anchor_store: AnchorStore | None = None,
) -> ReplayReport:
    """Verify a session's chain; with an anchor store, also verify completeness.

    Anchored verification fails closed in every direction: a session with no recorded
    anchor is an error (an attacker who deleted the whole trail must not verify clean),
    and a chain missing the anchored head — truncated tail or rebuilt log — is an error.
    """

    store = JsonlReceiptStore(receipt_log)
    receipts = tuple(store.iter_receipts(session_id))
    if not receipts:
        raise ValueError("receipt session is absent or empty")
    verify_receipt_chain(receipts, verifier)
    if anchor_store is not None:
        anchor = anchor_store.latest(session_id)
        if anchor is None:
            raise ValueError(
                "no chain anchor is recorded for this session; completeness cannot be "
                "verified"
            )
        verify_anchor(receipts, anchor)
    return ReplayReport(session_id=session_id, receipts=receipts)


def verify_receipt_chain(receipts: tuple[Receipt, ...], verifier: Ed25519Verifier) -> None:
    prev_hash: str | None = None
    expected_seq = 1
    for receipt in receipts:
        if receipt.seq != expected_seq:
            raise ValueError(f"expected receipt seq {expected_seq}, got {receipt.seq}")
        if receipt.prev_receipt_hash != prev_hash:
            raise ValueError(f"receipt seq {receipt.seq} has an invalid previous hash")
        verifier.verify_receipt(receipt)
        prev_hash = receipt.receipt_hash()
        expected_seq += 1
