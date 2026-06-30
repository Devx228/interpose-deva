from __future__ import annotations

import os
import platform
from pathlib import Path

from capgate.sandbox.base import (
    ExecResult,
    ExecSpec,
    RiskClass,
    SandboxBackend,
    SandboxUnavailable,
)
from capgate.sandbox.gvisor import (
    CommandRequest,
    CommandRunner,
    _bounded_result,
    _canonical_json,
)
from capgate.sandbox.limits import check_backend_limit_support

_MIB = 1024 * 1024


class FirecrackerSandbox:
    """Unvalidated Firecracker adapter for generated code only.

    The injected runner is responsible for a reviewed guest-agent transport and
    fresh lifecycle state. This adapter never falls back to containers or the host.
    """

    backend = SandboxBackend.FIRECRACKER

    def __init__(
        self,
        runner: CommandRunner,
        *,
        config_path: Path,
        vsock_path: Path,
        firecracker_path: Path = Path("/usr/bin/firecracker"),
        kvm_path: Path = Path("/dev/kvm"),
        kernel_path: Path = Path("/var/lib/capgate/vmlinux"),
        rootfs_path: Path = Path("/var/lib/capgate/rootfs.ext4"),
    ) -> None:
        self._runner = runner
        self._firecracker_path = firecracker_path
        self._kvm_path = kvm_path
        self._kernel_path = kernel_path
        self._rootfs_path = rootfs_path
        self._config_path = config_path
        self._vsock_path = vsock_path

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
        paths_are_safe = self._config_path.is_absolute() and self._vsock_path.is_absolute()
        if (
            spec.risk_class is not RiskClass.GENERATED_CODE
            or supported.verdict != "ALLOW"
            or platform.system() != "Linux"
            or not _is_executable(self._firecracker_path)
            or not _is_readable(self._kernel_path)
            or not _is_readable(self._rootfs_path)
            or not self._kvm_path.is_absolute()
            or not self._kvm_path.exists()
            or not os.access(self._kvm_path, os.R_OK | os.W_OK)
            or not paths_are_safe
            or spec.limits.memory_bytes < _MIB
        ):
            raise SandboxUnavailable(self.backend)

    def _request(self, spec: ExecSpec) -> CommandRequest:
        return CommandRequest(
            argv=(
                str(self._firecracker_path),
                "--no-api",
                f"--config-file={self._config_path}",
            ),
            runtime_config=_canonical_json(self._config(spec)),
            workload_argv=spec.argv,
            stdin=spec.stdin,
            image_digest=spec.image_digest,
            limits=spec.limits,
            timeout_millis=spec.limits.wall_time_millis,
            output_bytes=spec.limits.output_bytes,
        )

    def _config(self, spec: ExecSpec) -> dict[str, object]:
        memory_mib = spec.limits.memory_bytes // _MIB
        return {
            "boot-source": {
                "kernel_image_path": str(self._kernel_path),
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ro",
            },
            "drives": [
                {
                    "drive_id": "rootfs",
                    "path_on_host": str(self._rootfs_path),
                    "is_root_device": True,
                    "is_read_only": True,
                }
            ],
            "machine-config": {
                "vcpu_count": 1,
                "mem_size_mib": memory_mib,
                "smt": False,
                "track_dirty_pages": False,
            },
            "vsock": {
                "guest_cid": 3,
                "uds_path": str(self._vsock_path),
            },
        }


def _is_executable(path: Path) -> bool:
    return path.is_absolute() and path.is_file() and os.access(path, os.X_OK)


def _is_readable(path: Path) -> bool:
    return path.is_absolute() and path.is_file() and os.access(path, os.R_OK)
