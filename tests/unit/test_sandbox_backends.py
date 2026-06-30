from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from capgate.sandbox.base import (
    ExecSpec,
    RiskClass,
    Sandbox,
    SandboxBackend,
    SandboxUnavailable,
)
from capgate.sandbox.gvisor import CommandOutcome, CommandRequest, GVisorSandbox
from capgate.sandbox.limits import SandboxLimits
from capgate.sandbox.microvm import FirecrackerSandbox


class FakeRunner:
    def __init__(
        self,
        outcome: CommandOutcome | None = None,
        error: Exception | None = None,
    ) -> None:
        self.requests: list[CommandRequest] = []
        self._outcome = outcome or CommandOutcome(0, b"ok", b"")
        self._error = error

    async def run(self, request: CommandRequest) -> CommandOutcome:
        self.requests.append(request)
        if self._error is not None:
            raise self._error
        return self._outcome


def test_gvisor_builds_shell_free_deny_network_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("capgate.sandbox.gvisor.platform.system", lambda: "Linux")
    runsc = _executable(tmp_path / "runsc")
    runner = FakeRunner()
    sandbox = GVisorSandbox(runner, runsc_path=runsc, bundle_path=tmp_path / "bundle")

    result = asyncio.run(sandbox.run(_spec(RiskClass.FIXED_RISKY)))

    assert result.backend is SandboxBackend.GVISOR
    assert result.exit_code == 0
    assert len(runner.requests) == 1
    request = runner.requests[0]
    assert request.argv[0] == str(runsc)
    assert "--network=none" in request.argv
    assert request.environment == ()
    assert request.workload_argv == ("/tool", "--safe")
    assert request.image_digest == "sha256:" + "a" * 64
    assert request.limits == _limits()
    assert request.timeout_millis == 2_000
    assert request.output_bytes == 12
    config = _decode_config(request)
    process = _object(config["process"])
    assert process["env"] == []
    assert process["noNewPrivileges"] is True
    assert all(value == [] for value in _object(process["capabilities"]).values())
    assert _object(config["root"])["readonly"] is True
    mounts = _objects(config["mounts"])
    assert all(mount["type"] != "bind" for mount in mounts)
    namespaces = _objects(_object(config["linux"])["namespaces"])
    assert {namespace["type"] for namespace in namespaces} >= {"network", "mount", "user"}


def test_gvisor_request_construction_is_deterministic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("capgate.sandbox.gvisor.platform.system", lambda: "Linux")
    runner = FakeRunner()
    sandbox = _gvisor(tmp_path, runner)
    spec = _spec(RiskClass.FIXED_RISKY)

    asyncio.run(sandbox.run(spec))
    asyncio.run(sandbox.run(spec))

    assert runner.requests[0] == runner.requests[1]


@pytest.mark.parametrize("risk_class", [RiskClass.GENERATED_CODE, RiskClass.TRUSTED_DIRECT])
def test_gvisor_rejects_non_fixed_workloads_before_execution(
    risk_class: RiskClass,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("capgate.sandbox.gvisor.platform.system", lambda: "Linux")
    runner = FakeRunner()
    sandbox = _gvisor(tmp_path, runner)

    with pytest.raises(SandboxUnavailable, match="required gvisor sandbox backend"):
        asyncio.run(sandbox.run(_spec(risk_class)))

    assert runner.requests == []


def test_gvisor_missing_runtime_fails_sanitized_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("capgate.sandbox.gvisor.platform.system", lambda: "Linux")
    runner = FakeRunner()
    missing = tmp_path / "SECRET-runtime-name"
    sandbox = GVisorSandbox(runner, runsc_path=missing, bundle_path=tmp_path / "bundle")

    with pytest.raises(SandboxUnavailable) as caught:
        asyncio.run(sandbox.run(_spec(RiskClass.FIXED_RISKY)))

    assert str(caught.value) == "required gvisor sandbox backend is unavailable"
    assert "SECRET" not in str(caught.value)
    assert runner.requests == []


def test_gvisor_non_linux_platform_fails_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("capgate.sandbox.gvisor.platform.system", lambda: "Darwin")
    runner = FakeRunner()
    sandbox = _gvisor(tmp_path, runner)

    with pytest.raises(SandboxUnavailable):
        asyncio.run(sandbox.run(_spec(RiskClass.FIXED_RISKY)))

    assert runner.requests == []


def test_firecracker_builds_read_only_networkless_generated_code_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("capgate.sandbox.microvm.platform.system", lambda: "Linux")
    runner = FakeRunner()
    sandbox = _firecracker(tmp_path, runner)

    result = asyncio.run(sandbox.run(_spec(RiskClass.GENERATED_CODE)))

    assert result.backend is SandboxBackend.FIRECRACKER
    assert result.exit_code == 0
    assert len(runner.requests) == 1
    request = runner.requests[0]
    assert request.argv[0].endswith("/firecracker")
    assert request.argv[1] == "--no-api"
    assert request.environment == ()
    assert request.workload_argv == ("/tool", "--safe")
    assert request.image_digest == "sha256:" + "a" * 64
    assert request.limits == _limits()
    config = _decode_config(request)
    assert "network-interfaces" not in config
    drives = _objects(config["drives"])
    assert drives == [
        {
            "drive_id": "rootfs",
            "is_read_only": True,
            "is_root_device": True,
            "path_on_host": str(tmp_path / "rootfs.ext4"),
        }
    ]
    assert _object(config["machine-config"])["mem_size_mib"] == 4


@pytest.mark.parametrize("risk_class", [RiskClass.FIXED_RISKY, RiskClass.TRUSTED_DIRECT])
def test_firecracker_rejects_non_generated_workloads_before_execution(
    risk_class: RiskClass,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("capgate.sandbox.microvm.platform.system", lambda: "Linux")
    runner = FakeRunner()
    sandbox = _firecracker(tmp_path, runner)

    with pytest.raises(SandboxUnavailable, match="required firecracker sandbox backend"):
        asyncio.run(sandbox.run(_spec(risk_class)))

    assert runner.requests == []


@pytest.mark.parametrize("missing", ["firecracker", "kvm", "kernel", "rootfs"])
def test_firecracker_missing_prerequisite_fails_before_execution(
    missing: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("capgate.sandbox.microvm.platform.system", lambda: "Linux")
    runner = FakeRunner()
    paths = _firecracker_paths(tmp_path)
    paths[missing].unlink()
    sandbox = FirecrackerSandbox(
        runner,
        firecracker_path=paths["firecracker"],
        kvm_path=paths["kvm"],
        kernel_path=paths["kernel"],
        rootfs_path=paths["rootfs"],
        config_path=tmp_path / "firecracker.json",
        vsock_path=tmp_path / "firecracker.sock",
    )

    with pytest.raises(SandboxUnavailable) as caught:
        asyncio.run(sandbox.run(_spec(RiskClass.GENERATED_CODE)))

    assert str(caught.value) == "required firecracker sandbox backend is unavailable"
    assert runner.requests == []


@pytest.mark.parametrize("backend", ["gvisor", "firecracker"])
def test_backend_bounds_timeout_and_combined_output(
    backend: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome = CommandOutcome(
        exit_code=137,
        stdout=b"0123456789",
        stderr=b"abcdefghij",
        timed_out=True,
    )
    runner = FakeRunner(outcome)
    sandbox: Sandbox
    if backend == "gvisor":
        monkeypatch.setattr("capgate.sandbox.gvisor.platform.system", lambda: "Linux")
        sandbox = _gvisor(tmp_path, runner)
        spec = _spec(RiskClass.FIXED_RISKY)
    else:
        monkeypatch.setattr("capgate.sandbox.microvm.platform.system", lambda: "Linux")
        sandbox = _firecracker(tmp_path, runner)
        spec = _spec(RiskClass.GENERATED_CODE)

    result = asyncio.run(sandbox.run(spec))

    assert result.exit_code is None
    assert result.timed_out is True
    assert result.output_limit_exceeded is True
    assert result.stdout == b"0123456789"
    assert result.stderr == b"ab"
    assert len(result.stdout) + len(result.stderr) == 12


def test_runner_failure_is_sanitized_without_weaker_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("capgate.sandbox.gvisor.platform.system", lambda: "Linux")
    runner = FakeRunner(error=RuntimeError("SECRET launch detail"))
    sandbox = _gvisor(tmp_path, runner)

    with pytest.raises(SandboxUnavailable) as caught:
        asyncio.run(sandbox.run(_spec(RiskClass.FIXED_RISKY)))

    assert str(caught.value) == "required gvisor sandbox backend is unavailable"
    assert "SECRET" not in str(caught.value)
    assert len(runner.requests) == 1


def test_requested_unsupported_syscall_budget_fails_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("capgate.sandbox.gvisor.platform.system", lambda: "Linux")
    runner = FakeRunner()
    sandbox = _gvisor(tmp_path, runner)

    with pytest.raises(SandboxUnavailable):
        asyncio.run(
            sandbox.run(
                ExecSpec(
                    argv=("/tool",),
                    stdin=b"",
                    image_digest="sha256:" + "a" * 64,
                    risk_class=RiskClass.FIXED_RISKY,
                    limits=_limits(max_syscalls=100),
                )
            )
        )

    assert runner.requests == []


def _spec(risk_class: RiskClass) -> ExecSpec:
    return ExecSpec(
        argv=("/tool", "--safe"),
        stdin=b"input",
        image_digest="sha256:" + "a" * 64,
        risk_class=risk_class,
        limits=_limits(),
    )


def _limits(*, max_syscalls: int | None = None) -> SandboxLimits:
    return SandboxLimits(
        cpu_millis=500,
        memory_bytes=4 * 1024 * 1024,
        swap_bytes=1024 * 1024,
        process_count=4,
        wall_time_millis=2_000,
        writable_bytes=1024,
        output_bytes=12,
        max_tool_calls=5,
        max_tokens=1_000,
        max_cost_micros=1_000,
        max_syscalls=max_syscalls,
    )


def _firecracker(tmp_path: Path, runner: FakeRunner) -> FirecrackerSandbox:
    paths = _firecracker_paths(tmp_path)
    return FirecrackerSandbox(
        runner,
        firecracker_path=paths["firecracker"],
        kvm_path=paths["kvm"],
        kernel_path=paths["kernel"],
        rootfs_path=paths["rootfs"],
        config_path=tmp_path / "firecracker.json",
        vsock_path=tmp_path / "firecracker.sock",
    )


def _gvisor(tmp_path: Path, runner: FakeRunner) -> GVisorSandbox:
    return GVisorSandbox(
        runner,
        runsc_path=_executable(tmp_path / "runsc"),
        bundle_path=tmp_path / "bundle",
    )


def _firecracker_paths(tmp_path: Path) -> dict[str, Path]:
    return {
        "firecracker": _executable(tmp_path / "firecracker"),
        "kvm": _file(tmp_path / "kvm"),
        "kernel": _file(tmp_path / "vmlinux"),
        "rootfs": _file(tmp_path / "rootfs.ext4"),
    }


def _executable(path: Path) -> Path:
    path.write_bytes(b"fake")
    path.chmod(0o700)
    return path


def _file(path: Path) -> Path:
    path.write_bytes(b"fake")
    return path


def _decode_config(request: CommandRequest) -> dict[str, object]:
    value = json.loads(request.runtime_config)
    assert isinstance(value, dict)
    return value


def _object(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return value


def _objects(value: object) -> list[dict[str, object]]:
    assert isinstance(value, list)
    assert all(isinstance(item, dict) for item in value)
    return value
