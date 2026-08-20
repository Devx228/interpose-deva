from __future__ import annotations

import base64
import binascii
import os
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from capgate.engine.decision import Decision
from capgate.proxy.events import ToolCallEvent, ToolResultEvent
from capgate.receipts.anchor import AnchorStore, anchor_for
from capgate.receipts.model import Receipt, SandboxAudit, hash_json
from capgate.receipts.store import JsonlReceiptStore

SIGNATURE_PREFIX = "ed25519:"
_ED25519_KEY_BYTES = 32
_ED25519_SIGNATURE_BYTES = 64


class Ed25519Signer:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls) -> Ed25519Signer:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_or_create(cls, private_key_file: Path, public_key_file: Path) -> Ed25519Signer:
        private_key_file.parent.mkdir(parents=True, exist_ok=True)
        public_key_file.parent.mkdir(parents=True, exist_ok=True)
        if private_key_file.exists():
            raw_private = _read_base64_file(
                private_key_file,
                expected_bytes=_ED25519_KEY_BYTES,
                field="private key",
            )
            private_key = Ed25519PrivateKey.from_private_bytes(raw_private)
        else:
            private_key = Ed25519PrivateKey.generate()
            raw_private = private_key.private_bytes(
                encoding=Encoding.Raw,
                format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption(),
            )
            private_key_file.write_text(
                base64.b64encode(raw_private).decode("ascii"),
                encoding="ascii",
            )
            os.chmod(private_key_file, 0o600)
        public_key_file.write_text(
            base64.b64encode(_raw_public_key(private_key.public_key())).decode("ascii"),
            encoding="ascii",
        )
        return cls(private_key)

    def sign_receipt(self, receipt: Receipt) -> Receipt:
        signature = self.sign(receipt.canonical_unsigned_bytes())
        return replace(receipt, signature=signature)

    def sign(self, payload: bytes) -> str:
        signature = self._private_key.sign(payload)
        return SIGNATURE_PREFIX + base64.b64encode(signature).decode("ascii")

    def verifier(self) -> Ed25519Verifier:
        return Ed25519Verifier(self._private_key.public_key())


class Ed25519Verifier:
    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public_key = public_key

    @classmethod
    def from_public_key_file(cls, public_key_file: Path) -> Ed25519Verifier:
        raw_public = _read_base64_file(
            public_key_file,
            expected_bytes=_ED25519_KEY_BYTES,
            field="public key",
        )
        return cls(Ed25519PublicKey.from_public_bytes(raw_public))

    def verify_receipt(self, receipt: Receipt) -> None:
        if receipt.signature is None:
            raise ValueError("receipt is unsigned")
        self.verify(receipt.canonical_unsigned_bytes(), receipt.signature)

    def verify(self, payload: bytes, signature: str) -> None:
        if not signature.startswith(SIGNATURE_PREFIX):
            raise ValueError("unsupported signature scheme")
        raw_signature = _decode_base64(
            signature.removeprefix(SIGNATURE_PREFIX),
            expected_bytes=_ED25519_SIGNATURE_BYTES,
            field="receipt signature",
        )
        try:
            self._public_key.verify(raw_signature, payload)
        except InvalidSignature as exc:
            raise ValueError("invalid receipt signature") from exc


class ReceiptWriter:
    def __init__(
        self,
        *,
        store: JsonlReceiptStore,
        signer: Ed25519Signer,
        anchor_store: AnchorStore | None = None,
    ) -> None:
        self.store = store
        self.signer = signer
        self.anchor_store = anchor_store

    def write_tool_call(
        self,
        *,
        call_event: ToolCallEvent,
        result_event: ToolResultEvent,
        decision: Decision,
        sandbox: SandboxAudit | None = None,
    ) -> Receipt:
        last_state = self.store.last_state(call_event.session_id)
        receipt = Receipt(
            v=2,
            session_id=call_event.session_id,
            seq=last_state.next_seq,
            ts=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            server=call_event.server,
            tool=call_event.tool,
            verdict=decision.verdict,
            rule_id=decision.rule_id,
            reason=decision.reason,
            taint_labels=tuple(sorted(decision.labels)),
            args_hash=hash_json(call_event.arguments),
            result_hash=hash_json(result_event.result),
            prev_receipt_hash=last_state.prev_receipt_hash,
            sandbox=sandbox,
        )
        signed = self.signer.sign_receipt(receipt)
        self.store.append(signed)
        if self.anchor_store is not None:
            # Anchor failure propagates: a deployment that asked for external memory of
            # the chain head must not keep acting while that memory silently stops.
            self.anchor_store.record(anchor_for(signed))
        return signed


def _raw_public_key(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)


def _read_base64_file(path: Path, *, expected_bytes: int, field: str) -> bytes:
    try:
        encoded = path.read_text(encoding="ascii")
    except UnicodeError:
        raise ValueError(f"{field} is invalid") from None
    return _decode_base64(encoded, expected_bytes=expected_bytes, field=field)


def _decode_base64(encoded: str, *, expected_bytes: int, field: str) -> bytes:
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"{field} is invalid") from None
    if (
        len(decoded) != expected_bytes
        or base64.b64encode(decoded).decode("ascii") != encoded
    ):
        raise ValueError(f"{field} is invalid")
    return decoded
