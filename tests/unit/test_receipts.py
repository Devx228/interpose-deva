from __future__ import annotations

import base64
import json
from dataclasses import replace
from pathlib import Path

import pytest

from capgate.engine.decision import STAGE0_ALLOW
from capgate.proxy.events import JsonValue, ToolCallEvent, ToolResultEvent
from capgate.receipts.model import Receipt, SandboxAudit, hash_json
from capgate.receipts.replay import replay_session
from capgate.receipts.signer import Ed25519Signer, Ed25519Verifier, ReceiptWriter
from capgate.receipts.store import JsonlReceiptStore


def test_hash_json_is_stable_for_key_order() -> None:
    assert hash_json({"b": 2, "a": 1}) == hash_json({"a": 1, "b": 2})


def test_receipt_writer_signs_and_chains_receipts(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate()
    store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
    writer = ReceiptWriter(store=store, signer=signer)

    first = writer.write_tool_call(
        call_event=_call_event("session-1", "search", {"query": "one"}),
        result_event=_result_event("session-1", "search", {"content": "one"}),
        decision=STAGE0_ALLOW,
    )
    second = writer.write_tool_call(
        call_event=_call_event("session-1", "search", {"query": "two"}),
        result_event=_result_event("session-1", "search", {"content": "two"}),
        decision=STAGE0_ALLOW,
    )

    assert first.seq == 1
    assert first.prev_receipt_hash is None
    assert second.seq == 2
    assert second.prev_receipt_hash == first.receipt_hash()
    assert store.iter_receipts("session-1") == [first, second]


def test_replay_verifies_signature_and_hash_chain(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate()
    store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
    writer = ReceiptWriter(store=store, signer=signer)
    writer.write_tool_call(
        call_event=_call_event("session-1", "search", {"query": "one"}),
        result_event=_result_event("session-1", "search", {"content": "one"}),
        decision=STAGE0_ALLOW,
    )

    report = replay_session(store.path, "session-1", signer.verifier())

    assert report.session_id == "session-1"
    assert len(report.receipts) == 1
    assert report.to_lines()[2] == "signature_chain=valid"


def test_replay_rejects_tampered_receipt(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate()
    store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
    writer = ReceiptWriter(store=store, signer=signer)
    writer.write_tool_call(
        call_event=_call_event("session-1", "search", {"query": "one"}),
        result_event=_result_event("session-1", "search", {"content": "one"}),
        decision=STAGE0_ALLOW,
    )
    line = store.path.read_text(encoding="utf-8")
    store.path.write_text(line.replace("passthrough (stage0)", "tampered"), encoding="utf-8")

    with pytest.raises(ValueError, match="invalid receipt signature"):
        replay_session(store.path, "session-1", signer.verifier())


def test_replay_rejects_unsigned_extra_receipt_field(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate()
    store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
    receipt = ReceiptWriter(store=store, signer=signer).write_tool_call(
        call_event=_call_event("session-1", "search", {}),
        result_event=_result_event("session-1", "search", {"ok": True}),
        decision=STAGE0_ALLOW,
    )
    data = receipt.to_dict()
    data["unsigned_extra"] = "tampered"
    store.path.write_text(json.dumps(data) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="v2 fields"):
        replay_session(store.path, "session-1", signer.verifier())


@pytest.mark.parametrize(
    "signature",
    [
        "ed25519:not-base64!",
        "ed25519:" + base64.b64encode(b"too short").decode("ascii"),
    ],
)
def test_verifier_rejects_malformed_signature(signature: str) -> None:
    signer = Ed25519Signer.generate()
    receipt = signer.sign_receipt(_receipt(v=2))

    with pytest.raises(ValueError, match="receipt signature is invalid"):
        signer.verifier().verify_receipt(replace(receipt, signature=signature))


def test_verifier_rejects_signature_with_junk_suffix() -> None:
    signer = Ed25519Signer.generate()
    receipt = signer.sign_receipt(_receipt(v=2))
    assert receipt.signature is not None

    with pytest.raises(ValueError, match="receipt signature is invalid"):
        signer.verifier().verify_receipt(
            replace(receipt, signature=receipt.signature + "!!!!")
        )


def test_key_files_require_canonical_base64_and_exact_length(tmp_path: Path) -> None:
    private_key = tmp_path / "private.key"
    public_key = tmp_path / "public.key"
    private_key.write_text(base64.b64encode(b"short").decode("ascii"), encoding="ascii")
    public_key.write_text("not-base64!", encoding="ascii")

    with pytest.raises(ValueError, match="private key is invalid"):
        Ed25519Signer.load_or_create(private_key, tmp_path / "generated.public")
    with pytest.raises(ValueError, match="public key is invalid"):
        Ed25519Verifier.from_public_key_file(public_key)


def test_receipt_store_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate()
    store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
    ReceiptWriter(store=store, signer=signer).write_tool_call(
        call_event=_call_event("session-1", "search", {}),
        result_event=_result_event("session-1", "search", {"ok": True}),
        decision=STAGE0_ALLOW,
    )
    encoded = store.path.read_text(encoding="utf-8").rstrip("\n")
    store.path.write_text(encoded[:-1] + ',"tool":"duplicate"}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate JSON object keys"):
        store.iter_receipts()


def test_replay_rejects_absent_or_empty_session(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="absent or empty"):
        replay_session(
            tmp_path / "missing.jsonl",
            "missing-session",
            Ed25519Signer.generate().verifier(),
        )


def test_receipt_from_dict_validates_label_shape() -> None:
    with pytest.raises(ValueError, match="taint_labels"):
        Receipt.from_dict(
            {
                "v": 1,
                "session_id": "session-1",
                "seq": 1,
                "ts": "2026-01-01T00:00:00Z",
                "server": "server",
                "tool": "tool",
                "verdict": "ALLOW",
                "rule_id": None,
                "reason": "ok",
                "taint_labels": [123],
                "args_hash": "sha256:a",
                "result_hash": "sha256:b",
                "prev_receipt_hash": None,
                "signature": None,
            }
        )


def test_receipt_writer_signs_structured_sandbox_audit(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate()
    store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
    audit = SandboxAudit(
        backend="gvisor",
        status="completed",
        image_digest="sha256:" + "a" * 64,
    )

    receipt = ReceiptWriter(store=store, signer=signer).write_tool_call(
        call_event=_call_event("session-1", "search", {}),
        result_event=_result_event("session-1", "search", {"ok": True}),
        decision=STAGE0_ALLOW,
        sandbox=audit,
    )

    assert receipt.v == 2
    assert receipt.sandbox == audit
    assert store.iter_receipts("session-1") == [receipt]
    signer.verifier().verify_receipt(receipt)
    replay = replay_session(store.path, "session-1", signer.verifier())
    assert "sandbox_backend=gvisor" in replay.to_lines()[-1]
    assert "sandbox_status=completed" in replay.to_lines()[-1]


def test_receipt_v1_rejects_sandbox_audit_field() -> None:
    data = {
        "v": 1,
        "session_id": "session-1",
        "seq": 1,
        "ts": "2026-01-01T00:00:00Z",
        "server": "server",
        "tool": "tool",
        "verdict": "ALLOW",
        "rule_id": None,
        "reason": "ok",
        "taint_labels": [],
        "args_hash": "sha256:a",
        "result_hash": "sha256:b",
        "prev_receipt_hash": None,
        "sandbox": {
            "backend": "gvisor",
            "status": "completed",
            "image_digest": "sha256:" + "a" * 64,
        },
        "signature": None,
    }

    with pytest.raises(ValueError, match="v1"):
        Receipt.from_dict(data)


def test_receipt_v1_still_replays(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate()
    store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
    signed = signer.sign_receipt(_receipt(v=1))
    store.append(signed)

    assert replay_session(store.path, "session-1", signer.verifier()).receipts == (signed,)


def _call_event(session_id: str, tool: str, arguments: dict[str, JsonValue]) -> ToolCallEvent:
    return ToolCallEvent(
        session_id=session_id,
        server="test-server",
        tool=tool,
        arguments=arguments,
        arg_provenance={},
        request_id=1,
    )


def _result_event(session_id: str, tool: str, result: JsonValue) -> ToolResultEvent:
    return ToolResultEvent(
        session_id=session_id,
        server="test-server",
        tool=tool,
        result=result,
        request_id=1,
    )


def _receipt(*, v: int) -> Receipt:
    return Receipt(
        v=v,
        session_id="session-1",
        seq=1,
        ts="2026-01-01T00:00:00Z",
        server="server",
        tool="tool",
        verdict="ALLOW",
        rule_id=None,
        reason="ok",
        taint_labels=(),
        args_hash="sha256:a",
        result_hash="sha256:b",
        prev_receipt_hash=None,
    )
