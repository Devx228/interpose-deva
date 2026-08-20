"""External chain anchoring: gone must be detected as gone.

The signed chain alone verifies whatever remains; these tests pin the property it cannot
provide by itself — completeness — and the fail-closed posture of the anchor trail.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from capgate.engine.decision import Decision
from capgate.proxy.events import ToolCallEvent, ToolResultEvent
from capgate.receipts.anchor import ChainAnchor, JsonlAnchorStore
from capgate.receipts.replay import replay_session
from capgate.receipts.signer import Ed25519Signer, ReceiptWriter
from capgate.receipts.store import JsonlReceiptStore

SESSION = "anchor-session"


def _write_receipts(
    tmp_path: Path, count: int, *, anchored: bool = True
) -> tuple[Path, Path, Ed25519Signer]:
    log = tmp_path / "receipts.jsonl"
    anchors = tmp_path / "anchors.jsonl"
    signer = Ed25519Signer.generate()
    writer = ReceiptWriter(
        store=JsonlReceiptStore(log),
        signer=signer,
        anchor_store=JsonlAnchorStore(anchors) if anchored else None,
    )
    for index in range(count):
        event = ToolCallEvent(
            session_id=SESSION,
            server="test",
            tool="echo",
            arguments={"n": index},
            arg_provenance={"n": f"test:echo:{index}:argument:n"},
            request_id=index,
        )
        writer.write_tool_call(
            call_event=event,
            result_event=ToolResultEvent(
                session_id=SESSION,
                server="test",
                tool="echo",
                result={"ok": True},
                request_id=index,
            ),
            decision=Decision("ALLOW", "test", None, frozenset()),
        )
    return log, anchors, signer


def _truncate_tail(log: Path, lines_to_drop: int) -> None:
    lines = log.read_text(encoding="utf-8").splitlines()
    log.write_text(
        "".join(line + "\n" for line in lines[:-lines_to_drop]), encoding="utf-8"
    )


def test_an_intact_anchored_log_replays_clean(tmp_path: Path) -> None:
    log, anchors, signer = _write_receipts(tmp_path, 3)

    report = replay_session(
        log, SESSION, signer.verifier(), anchor_store=JsonlAnchorStore(anchors)
    )

    assert len(report.receipts) == 3


def test_tail_deletion_passes_plain_replay_but_fails_anchored_replay(
    tmp_path: Path,
) -> None:
    """The exact gap anchoring exists for: truncation leaves a valid-looking chain."""

    log, anchors, signer = _write_receipts(tmp_path, 3)
    _truncate_tail(log, 1)

    # Without the anchor the shortened chain still verifies — that is the problem.
    assert len(replay_session(log, SESSION, signer.verifier()).receipts) == 2

    with pytest.raises(ValueError, match="tail was deleted or the log was replaced"):
        replay_session(
            log, SESSION, signer.verifier(), anchor_store=JsonlAnchorStore(anchors)
        )


def test_a_rebuilt_log_with_a_new_key_fails_anchored_replay(tmp_path: Path) -> None:
    """Replacing log and key together beats the signatures; the anchor remembers."""

    _, anchors, _ = _write_receipts(tmp_path, 3)
    rebuilt_dir = tmp_path / "rebuilt"
    rebuilt_dir.mkdir()
    rebuilt_log, _, new_signer = _write_receipts(rebuilt_dir, 3, anchored=False)

    # The rebuilt log verifies against its own key...
    replay_session(rebuilt_log, SESSION, new_signer.verifier())
    # ...but not against the surviving anchor trail.
    with pytest.raises(ValueError, match="chain was rebuilt"):
        replay_session(
            rebuilt_log,
            SESSION,
            new_signer.verifier(),
            anchor_store=JsonlAnchorStore(anchors),
        )


def test_a_missing_anchor_is_an_error_not_a_pass(tmp_path: Path) -> None:
    log, _, signer = _write_receipts(tmp_path, 2, anchored=False)

    with pytest.raises(ValueError, match="no chain anchor is recorded"):
        replay_session(
            log,
            SESSION,
            signer.verifier(),
            anchor_store=JsonlAnchorStore(tmp_path / "empty-anchors.jsonl"),
        )


def test_anchor_records_must_advance(tmp_path: Path) -> None:
    store = JsonlAnchorStore(tmp_path / "anchors.jsonl")
    store.record(ChainAnchor(SESSION, 2, "hash-2"))

    with pytest.raises(ValueError, match="advance monotonically"):
        store.record(ChainAnchor(SESSION, 2, "hash-2b"))


@pytest.mark.parametrize(
    "line",
    [
        pytest.param("not json", id="not-json"),
        pytest.param('{"session_id": "s", "seq": 1}', id="missing-field"),
        pytest.param(
            '{"session_id": "s", "seq": true, "receipt_hash": "h"}', id="bool-seq"
        ),
        pytest.param(
            '{"session_id": "s", "seq": 0, "receipt_hash": "h"}', id="zero-seq"
        ),
        pytest.param("", id="blank-line"),
    ],
)
def test_a_corrupted_anchor_trail_fails_closed(tmp_path: Path, line: str) -> None:
    path = tmp_path / "anchors.jsonl"
    path.write_text(line + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="anchor"):
        JsonlAnchorStore(path).latest(SESSION)


def test_a_non_monotonic_anchor_trail_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "anchors.jsonl"
    path.write_text(
        '{"receipt_hash":"h3","seq":3,"session_id":"anchor-session"}\n'
        '{"receipt_hash":"h2","seq":2,"session_id":"anchor-session"}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="not monotonic"):
        JsonlAnchorStore(path).latest(SESSION)
