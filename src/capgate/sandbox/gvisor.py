from __future__ import annotations

import hashlib
import json
import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from capgate.sandbox.base import (
    ExecResult,
    ExecSpec,
    RiskClass,
    SandboxBackend,
    SandboxUnavailable,
)
from capgate.sandbox.limits import SandboxLimits, check_backend_limit_support


@dataclass(frozen=True, slots=True)
class CommandRequest:
    """A shell-free request for a trusted, limit-enforcing runtime launcher."""

    argv: tuple[str, ...]
    runtime_config: bytes
    workload_argv: tuple[str, ...]
    stdin: bytes
    image_digest: str
    limits: SandboxLimits
    timeout_millis: int
    output_bytes: int
    environment: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class CommandOutcome:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    output_limit_exceeded: bool = False


class CommandRunner(Protocol):
    """Trusted launcher seam.

    Implementations must materialize ``runtime_config`` in fresh backend-private
    state, verify/provision ``image_digest``, exec ``request.argv`` directly without
    a shell, use exactly ``request.environment``, enforce every limit, terminate at
    either streaming bound, and never retry on the host or a weaker backend.
    """

    async def run(self, request: CommandRequest) -> CommandOutcome: ...


class GVisorSandbox:
    """Unvalidated gVisor adapter for fixed, pinned risky tools only."""

    backend = SandboxBackend.GVISOR

    def __init__(
        self,
        runner: CommandRunner,
        *,
        bundle_path: Path,
        runsc_path: Path = Path("/usr/local/bin/runsc"),
    ) -> None:
        self._runner = runner
        self._runsc_path = runsc_path
        self._bundle_path = bundle_path

    async def run(self, spec: ExecSpec) -> ExecResult:
        self._check_prerequisites(spec)
        request = self._request(spec)
        try:
            outcome = await self._runner.run(request)
        except Exception:
            raise SandboxUnavailable(self.backend) from None
        return _bounded_result(self.backend, outcome, spec.limits.output_bytes)

    def _check_prerequisites(self, spec: ExecSpec) -> None:
        supported = check_backend_limit_support(
            spec.limits,
            supports_syscall_limit=False,
        )
        if (
            spec.risk_class is not RiskClass.FIXED_RISKY
            or supported.verdict != "ALLOW"
            or platform.system() != "Linux"
            or not _is_executable(self._runsc_path)
            or not self._bundle_path.is_absolute()
        ):
            raise SandboxUnavailable(self.backend)

    def _request(self, spec: ExecSpec) -> CommandRequest:
        config = _canonical_json(_oci_config(spec))
        container_id = hashlib.sha256(config + hashlib.sha256(spec.stdin).digest()).hexdigest()[:20]
        return CommandRequest(
            argv=(
                str(self._runsc_path),
                "--network=none",
                "--rootless=true",
                "--file-access=exclusive",
                "--platform=systrap",
                "run",
                f"--bundle={self._bundle_path}",
                f"capgate-{container_id}",
            ),
            runtime_config=config,
            workload_argv=spec.argv,
            stdin=spec.stdin,
            image_digest=spec.image_digest,
            limits=spec.limits,
            timeout_millis=spec.limits.wall_time_millis,
            output_bytes=spec.limits.output_bytes,
        )


def _oci_config(spec: ExecSpec) -> dict[str, object]:
    limits = spec.limits
    empty_capabilities: dict[str, list[str]] = {
        name: []
        for name in ("ambient", "bounding", "effective", "inheritable", "permitted")
    }
    return {
        "ociVersion": "1.1.0",
        "process": {
            "terminal": False,
            "user": {"uid": 65534, "gid": 65534},
            "args": list(spec.argv),
            "env": [],
            "cwd": "/workspace",
            "capabilities": empty_capabilities,
            "noNewPrivileges": True,
            "rlimits": [
                {
                    "type": "RLIMIT_NPROC",
                    "hard": limits.process_count,
                    "soft": limits.process_count,
                }
            ],
        },
        "root": {"path": "rootfs", "readonly": True},
        "hostname": "capgate",
        "mounts": [
            {
                "destination": "/proc",
                "type": "proc",
                "source": "proc",
                "options": ["nosuid", "noexec", "nodev"],
            },
            {
                "destination": "/workspace",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": [
                    "nosuid",
                    "noexec",
                    "nodev",
                    f"size={limits.writable_bytes}",
                ],
            },
        ],
        "linux": {
            "namespaces": [
                {"type": namespace}
                for namespace in ("pid", "network", "mount", "ipc", "uts", "user")
            ],
            "resources": {
                "memory": {
                    "limit": limits.memory_bytes,
                    "swap": limits.memory_bytes + limits.swap_bytes,
                },
                "pids": {"limit": limits.process_count},
            },
        },
        "annotations": {"capgate.image.digest": spec.image_digest},
    }


def _bounded_result(
    backend: SandboxBackend,
    outcome: CommandOutcome,
    output_limit: int,
) -> ExecResult:
    overflow = (
        outcome.output_limit_exceeded
        or len(outcome.stdout) + len(outcome.stderr) > output_limit
    )
    stdout = outcome.stdout[:output_limit]
    stderr = outcome.stderr[: max(0, output_limit - len(stdout))]
    terminated = outcome.timed_out or overflow
    return ExecResult(
        backend=backend,
        exit_code=None if terminated else outcome.exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=outcome.timed_out,
        output_limit_exceeded=overflow,
    )


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _is_executable(path: Path) -> bool:
    return path.is_absolute() and path.is_file() and os.access(path, os.X_OK)
