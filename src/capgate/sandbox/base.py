from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from capgate.engine.decision import Decision
from capgate.sandbox.limits import SandboxLimits

UNKNOWN_RISK_RULE_ID = "sandbox.risk.unknown"
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class RiskClass(StrEnum):
    """Trusted classification used to select an isolation boundary."""

    TRUSTED_DIRECT = "trusted_direct"
    FIXED_RISKY = "fixed_risky"
    GENERATED_CODE = "generated_code"


class SandboxBackend(StrEnum):
    GVISOR = "gvisor"
    FIRECRACKER = "firecracker"


class SandboxUnavailable(RuntimeError):
    """Sanitized prerequisite failure that never includes paths or raw exceptions."""

    def __init__(self, backend: SandboxBackend) -> None:
        self.backend = backend
        super().__init__(f"required {backend.value} sandbox backend is unavailable")


@dataclass(frozen=True, slots=True)
class ExecSpec:
    argv: tuple[str, ...]
    stdin: bytes
    image_digest: str
    risk_class: RiskClass
    limits: SandboxLimits

    def __post_init__(self) -> None:
        if not isinstance(self.argv, tuple) or not self.argv:
            raise ValueError("argv must be a non-empty tuple")
        if any(not isinstance(part, str) or not part for part in self.argv):
            raise ValueError("argv entries must be non-empty strings")
        if not isinstance(self.stdin, bytes):
            raise ValueError("stdin must be immutable bytes")
        if _IMAGE_DIGEST.fullmatch(self.image_digest) is None:
            raise ValueError("image_digest must be a pinned sha256 digest")
        if not isinstance(self.risk_class, RiskClass):
            raise ValueError("risk_class must be trusted and known")
        if not isinstance(self.limits, SandboxLimits):
            raise ValueError("limits must be a validated SandboxLimits profile")


@dataclass(frozen=True, slots=True)
class ExecResult:
    backend: SandboxBackend
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    output_limit_exceeded: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.backend, SandboxBackend):
            raise ValueError("backend must be a known sandbox backend")
        if self.exit_code is not None and (
            isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)
        ):
            raise ValueError("exit_code must be an integer or None")
        if not isinstance(self.stdout, bytes) or not isinstance(self.stderr, bytes):
            raise ValueError("sandbox output must be immutable bytes")
        if not isinstance(self.timed_out, bool) or not isinstance(
            self.output_limit_exceeded, bool
        ):
            raise ValueError("termination flags must be booleans")


@runtime_checkable
class Sandbox(Protocol):
    backend: SandboxBackend

    async def run(self, spec: ExecSpec) -> ExecResult: ...


@dataclass(frozen=True, slots=True)
class SandboxRoute:
    decision: Decision
    backend: SandboxBackend | None


def route_backend(risk_class: object) -> SandboxRoute:
    """Route only trusted risk classes; never return a weaker fallback."""

    if risk_class is RiskClass.TRUSTED_DIRECT:
        return SandboxRoute(
            decision=Decision(
                verdict="ALLOW",
                reason="trusted risk metadata explicitly permits direct execution",
                rule_id=None,
                labels=frozenset(),
            ),
            backend=None,
        )
    if risk_class is RiskClass.FIXED_RISKY:
        backend = SandboxBackend.GVISOR
    elif risk_class is RiskClass.GENERATED_CODE:
        backend = SandboxBackend.FIRECRACKER
    else:
        return SandboxRoute(
            decision=Decision(
                verdict="BLOCK",
                reason="tool risk class is missing or unknown",
                rule_id=UNKNOWN_RISK_RULE_ID,
                labels=frozenset(),
            ),
            backend=None,
        )

    return SandboxRoute(
        decision=Decision(
            verdict="ALLOW",
            reason=f"risk class requires the {backend.value} sandbox backend",
            rule_id=None,
            labels=frozenset(),
        ),
        backend=backend,
    )
