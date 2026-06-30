from __future__ import annotations

from pathlib import Path

import pytest

from capgate.config import ConfigError, load_tool_metadata
from capgate.flow.sinks import SinkKind
from capgate.sandbox.base import RiskClass
from capgate.taint.labels import Confidentiality, Integrity, Label


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "tools.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_load_tool_metadata_builds_typed_metadata(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
tools:
  send_email:
    capability: send:email.external
    confidentiality: internal
    integrity: untrusted
    risk_class: fixed_risky
    source_tags: [email, mcp:mail]
    sink: email.external
""",
    )

    metadata = load_tool_metadata(path)

    assert metadata["send_email"].capability == "send:email.external"
    assert metadata["send_email"].result_label == Label(
        confidentiality=Confidentiality.INTERNAL,
        integrity=Integrity.UNTRUSTED,
        source_tags=frozenset({"email", "mcp:mail"}),
    )
    assert metadata["send_email"].sink is SinkKind.EMAIL_EXTERNAL
    assert metadata["send_email"].risk_class is RiskClass.FIXED_RISKY


def test_load_tool_metadata_applies_optional_defaults(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
tools:
  read_public:
    capability: read:web
    confidentiality: public
    integrity: trusted
    risk_class: trusted_direct
""",
    )

    metadata = load_tool_metadata(path)["read_public"]

    assert metadata.result_label.source_tags == frozenset()
    assert metadata.sink is SinkKind.NONE


@pytest.mark.parametrize(
    "text",
    [
        "",
        "- not-a-mapping\n",
        "unknown: {}\n",
        "tools: {}\nunknown: {}\n",
        "tools: []\n",
        "tools:\n  7: {}\n",
        "tools:\n  example: []\n",
        "tools:\n  example:\n    capability: read:web\n",
        (
            "tools:\n  example:\n    capability: read:web\n"
            "    confidentiality: public\n    integrity: trusted\n    unknown: value\n"
        ),
        (
            "tools:\n  example:\n    capability: [read:web]\n"
            "    confidentiality: public\n    integrity: trusted\n"
        ),
        (
            "tools:\n  example:\n    capability: read:web\n"
            "    confidentiality: [public]\n    integrity: trusted\n"
        ),
        (
            "tools:\n  example:\n    capability: read:web\n"
            "    confidentiality: public\n    integrity: [trusted]\n"
        ),
        (
            "tools:\n  example:\n    capability: read:web\n"
            "    confidentiality: public\n    integrity: trusted\n"
            "    source_tags: email\n"
        ),
        (
            "tools:\n  example:\n    capability: read:web\n"
            "    confidentiality: public\n    integrity: trusted\n"
            "    source_tags: [email, 7]\n"
        ),
        (
            "tools:\n  example:\n    capability: read:web\n"
            "    confidentiality: public\n    integrity: trusted\n    sink: [none]\n"
        ),
        "tools: [\n",
    ],
)
def test_load_tool_metadata_rejects_invalid_shapes(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        load_tool_metadata(_write(tmp_path, text))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("capability", "not-a-capability"),
        ("confidentiality", "top-secret"),
        ("integrity", "maybe"),
        ("risk_class", "maybe"),
        ("sink", "internet"),
    ],
)
def test_load_tool_metadata_rejects_unknown_values(
    tmp_path: Path, field: str, value: str
) -> None:
    values = {
        "capability": "read:web",
        "confidentiality": "public",
        "integrity": "trusted",
        "risk_class": "trusted_direct",
        "sink": "none",
    }
    values[field] = value
    path = _write(
        tmp_path,
        "tools:\n  example:\n"
        + "".join(f"    {key}: {item}\n" for key, item in values.items()),
    )

    with pytest.raises(ConfigError):
        load_tool_metadata(path)


def test_config_error_does_not_echo_secret_content(tmp_path: Path) -> None:
    secret = "SUPER-SECRET-CONTENT-DO-NOT-ECHO"
    path = _write(
        tmp_path,
        "tools:\n  example:\n"
        "    capability: read:web\n"
        "    confidentiality: public\n"
        "    integrity: trusted\n"
        "    risk_class: trusted_direct\n"
        f"    {secret}: true\n",
    )

    with pytest.raises(ConfigError) as raised:
        load_tool_metadata(path)

    assert secret not in str(raised.value)
