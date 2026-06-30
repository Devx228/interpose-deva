from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from typing import Any, Literal, TypeAlias, cast

from capgate.proxy.events import JsonValue

ReceiptVerdict = Literal["ALLOW", "BLOCK", "REQUIRE_APPROVAL"]
SandboxAuditStatus: TypeAlias = Literal[
    "completed",
    "unavailable",
    "backend_mismatch",
    "timeout",
    "output_limit",
    "execution_failed",
    "response_invalid",
]
SandboxAuditBackend: TypeAlias = Literal["gvisor", "firecracker"]
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SANDBOX_STATUSES = {
    "completed",
    "unavailable",
    "backend_mismatch",
    "timeout",
    "output_limit",
    "execution_failed",
    "response_invalid",
}


@dataclass(frozen=True)
class SandboxAudit:
    backend: SandboxAuditBackend
    status: SandboxAuditStatus
    image_digest: str | None = None

    def __post_init__(self) -> None:
        if self.backend not in {"gvisor", "firecracker"}:
            raise ValueError("sandbox audit backend is invalid")
        if self.status not in _SANDBOX_STATUSES:
            raise ValueError("sandbox audit status is invalid")
        if self.image_digest is not None and _IMAGE_DIGEST.fullmatch(self.image_digest) is None:
            raise ValueError("sandbox audit image digest is invalid")

    def to_dict(self) -> dict[str, str | None]:
        return {
            "backend": self.backend,
            "status": self.status,
            "image_digest": self.image_digest,
        }

    @classmethod
    def from_dict(cls, data: object) -> SandboxAudit:
        if not isinstance(data, dict) or set(data) != {"backend", "status", "image_digest"}:
            raise ValueError("sandbox audit must have exact fields")
        backend = data["backend"]
        status = data["status"]
        image_digest = data["image_digest"]
        if backend not in {"gvisor", "firecracker"}:
            raise ValueError("sandbox audit backend is invalid")
        if status not in _SANDBOX_STATUSES:
            raise ValueError("sandbox audit status is invalid")
        if image_digest is not None and not isinstance(image_digest, str):
            raise ValueError("sandbox audit image digest is invalid")
        return cls(
            backend=cast(SandboxAuditBackend, backend),
            status=cast(SandboxAuditStatus, status),
            image_digest=image_digest,
        )


@dataclass(frozen=True)
class Receipt:
    v: int
    session_id: str
    seq: int
    ts: str
    server: str
    tool: str
    verdict: ReceiptVerdict
    rule_id: str | None
    reason: str
    taint_labels: tuple[str, ...]
    args_hash: str
    result_hash: str
    prev_receipt_hash: str | None
    sandbox: SandboxAudit | None = None
    signature: str | None = None

    def unsigned(self) -> Receipt:
        return replace(self, signature=None)

    def to_dict(self, *, include_signature: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "v": self.v,
            "session_id": self.session_id,
            "seq": self.seq,
            "ts": self.ts,
            "server": self.server,
            "tool": self.tool,
            "verdict": self.verdict,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "taint_labels": list(self.taint_labels),
            "args_hash": self.args_hash,
            "result_hash": self.result_hash,
            "prev_receipt_hash": self.prev_receipt_hash,
        }
        if self.sandbox is not None:
            data["sandbox"] = self.sandbox.to_dict()
        if include_signature:
            data["signature"] = self.signature
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Receipt:
        labels = data.get("taint_labels", [])
        if not isinstance(labels, list) or not all(isinstance(item, str) for item in labels):
            raise ValueError("taint_labels must be a list of strings")
        version = _as_int(data["v"], "v")
        if version not in {1, 2}:
            raise ValueError("receipt version is unsupported")
        sandbox = SandboxAudit.from_dict(data["sandbox"]) if "sandbox" in data else None
        if version == 1 and sandbox is not None:
            raise ValueError("receipt v1 cannot contain sandbox audit metadata")
        return cls(
            v=version,
            session_id=_as_str(data["session_id"], "session_id"),
            seq=_as_int(data["seq"], "seq"),
            ts=_as_str(data["ts"], "ts"),
            server=_as_str(data["server"], "server"),
            tool=_as_str(data["tool"], "tool"),
            verdict=_as_verdict(data["verdict"]),
            rule_id=_as_optional_str(data.get("rule_id"), "rule_id"),
            reason=_as_str(data["reason"], "reason"),
            taint_labels=tuple(labels),
            args_hash=_as_str(data["args_hash"], "args_hash"),
            result_hash=_as_str(data["result_hash"], "result_hash"),
            prev_receipt_hash=_as_optional_str(
                data.get("prev_receipt_hash"),
                "prev_receipt_hash",
            ),
            sandbox=sandbox,
            signature=_as_optional_str(data.get("signature"), "signature"),
        )

    def canonical_unsigned_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict(include_signature=False))

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict(include_signature=True))

    def receipt_hash(self) -> str:
        return sha256_bytes(self.canonical_bytes())


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def hash_json(value: JsonValue) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _as_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    return value


def _as_optional_str(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _as_str(value, field)


def _as_int(value: Any, field: str) -> int:
    if not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    return value


def _as_verdict(value: Any) -> ReceiptVerdict:
    if value not in {"ALLOW", "BLOCK", "REQUIRE_APPROVAL"}:
        raise ValueError("verdict must be ALLOW, BLOCK, or REQUIRE_APPROVAL")
    return cast(ReceiptVerdict, value)
