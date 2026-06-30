from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from capgate.sandbox.base import (
    UNKNOWN_RISK_RULE_ID,
    ExecResult,
    ExecSpec,
    RiskClass,
    SandboxBackend,
    SandboxUnavailable,
    route_backend,
)
from capgate.sandbox.limits import SandboxLimits


def _limits() -> SandboxLimits:
    return SandboxLimits(
        cpu_millis=1_000,
        memory_bytes=64 * 1024 * 1024,
        swap_bytes=64 * 1024 * 1024,
        process_count=16,
        wall_time_millis=2_000,
        writable_bytes=1024 * 1024,
        output_bytes=64 * 1024,
        max_tool_calls=10,
        max_tokens=10_000,
        max_cost_micros=1_000_000,
    )


def test_fixed_risky_tool_routes_only_to_gvisor() -> None:
    route = route_backend(RiskClass.FIXED_RISKY)

    assert route.decision.verdict == "ALLOW"
    assert route.backend is SandboxBackend.GVISOR


def test_trusted_direct_execution_requires_an_explicit_risk_class() -> None:
    route = route_backend(RiskClass.TRUSTED_DIRECT)

    assert route.decision.verdict == "ALLOW"
    assert route.backend is None


def test_generated_code_routes_only_to_firecracker() -> None:
    route = route_backend(RiskClass.GENERATED_CODE)

    assert route.decision.verdict == "ALLOW"
    assert route.backend is SandboxBackend.FIRECRACKER


@pytest.mark.parametrize("risk_class", [None, "fixed_risky", "container", object()])
def test_unknown_or_untrusted_risk_class_blocks_without_fallback(risk_class: object) -> None:
    route = route_backend(risk_class)

    assert route.decision.verdict == "BLOCK"
    assert route.decision.rule_id == UNKNOWN_RISK_RULE_ID
    assert route.backend is None


def test_backend_kind_cannot_express_host_or_plain_container() -> None:
    assert set(SandboxBackend) == {SandboxBackend.GVISOR, SandboxBackend.FIRECRACKER}


def test_unavailable_error_is_sanitized() -> None:
    error = SandboxUnavailable(SandboxBackend.FIRECRACKER)

    assert str(error) == "required firecracker sandbox backend is unavailable"
    assert error.backend is SandboxBackend.FIRECRACKER


def test_exec_contracts_are_immutable_and_have_no_environment_or_secret_fields() -> None:
    spec = ExecSpec(
        argv=("tool", "--safe"),
        stdin=b"input",
        image_digest="sha256:" + "a" * 64,
        risk_class=RiskClass.FIXED_RISKY,
        limits=_limits(),
    )
    result = ExecResult(
        backend=SandboxBackend.GVISOR,
        exit_code=0,
        stdout=b"output",
        stderr=b"",
    )

    with pytest.raises(FrozenInstanceError):
        spec.argv = ("other",)  # type: ignore[misc]
    assert "environment" not in ExecSpec.__dataclass_fields__
    assert "environment" not in ExecResult.__dataclass_fields__
    assert "secrets" not in ExecSpec.__dataclass_fields__
    assert "secrets" not in ExecResult.__dataclass_fields__
    assert result.stdout == b"output"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("argv", []),
        ("stdin", bytearray(b"mutable")),
        ("image_digest", "latest"),
        ("risk_class", "fixed_risky"),
        ("limits", None),
    ],
)
def test_exec_spec_rejects_mutable_or_untrusted_fields(field: str, value: object) -> None:
    values: dict[str, object] = {
        "argv": ("tool",),
        "stdin": b"",
        "image_digest": "sha256:" + "a" * 64,
        "risk_class": RiskClass.FIXED_RISKY,
        "limits": _limits(),
    }
    values[field] = value

    with pytest.raises(ValueError):
        ExecSpec(**values)  # type: ignore[arg-type]
