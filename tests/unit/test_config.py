from __future__ import annotations

from pathlib import Path

import pytest

from capgate.config import ConfigError, load_deny_pairs, load_tool_metadata
from capgate.flow.rules import DEFAULT_DENY_PAIRS, DenyPair
from capgate.flow.sinks import SinkKind
from capgate.flow.sources import DataSourceKind
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
    assert metadata.returns_reference is False


def test_returns_reference_is_parsed(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
tools:
  read_secret:
    capability: read:private
    confidentiality: secret
    integrity: trusted
    risk_class: trusted_direct
    returns_reference: true
""",
    )

    assert load_tool_metadata(path)["read_secret"].returns_reference is True


def test_returns_reference_must_be_a_boolean(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
tools:
  read_secret:
    capability: read:private
    confidentiality: secret
    integrity: trusted
    risk_class: trusted_direct
    returns_reference: "yes"
""",
    )

    with pytest.raises(ConfigError, match="returns_reference"):
        load_tool_metadata(path)


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
    "tag",
    [
        pytest.param("secret", id="misspelled-secrets"),
        pytest.param("untrusted-web", id="hyphen-instead-of-underscore"),
        pytest.param("Secrets", id="wrong-case"),
        pytest.param("totally_made_up", id="unknown-bare-tag"),
        pytest.param("mcp:", id="namespace-without-value"),
        pytest.param(":mail", id="namespace-without-prefix"),
    ],
)
def test_unknown_bare_source_tag_is_rejected(tmp_path: Path, tag: str) -> None:
    """A bare tag that names no known data source would silently disable a deny pair."""

    path = _write(
        tmp_path,
        "tools:\n  example:\n    capability: read:web\n"
        "    confidentiality: public\n    integrity: trusted\n"
        "    risk_class: trusted_direct\n"
        f'    source_tags: ["{tag}"]\n',
    )

    with pytest.raises(ConfigError, match="source_tags"):
        load_tool_metadata(path)


@pytest.mark.parametrize(
    "tag",
    [
        pytest.param("secrets", id="taxonomy-value"),
        pytest.param("untrusted_web", id="taxonomy-value-with-underscore"),
        pytest.param("mcp:mail", id="namespaced"),
        pytest.param("agentdojo:workspace:send_email", id="multi-segment-namespace"),
    ],
)
def test_known_and_namespaced_source_tags_are_accepted(tmp_path: Path, tag: str) -> None:
    path = _write(
        tmp_path,
        "tools:\n  example:\n    capability: read:web\n"
        "    confidentiality: public\n    integrity: trusted\n"
        "    risk_class: trusted_direct\n"
        f'    source_tags: ["{tag}"]\n',
    )

    metadata = load_tool_metadata(path)

    assert metadata["example"].result_label.source_tags == frozenset({tag})


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


_MINIMAL_TOOL = (
    "tools:\n  example:\n    capability: read:web\n"
    "    confidentiality: public\n    integrity: trusted\n"
    "    risk_class: trusted_direct\n"
)


def test_omitted_deny_section_keeps_the_built_in_defaults(tmp_path: Path) -> None:
    assert load_deny_pairs(_write(tmp_path, _MINIMAL_TOOL)) == DEFAULT_DENY_PAIRS


def test_deny_section_replaces_the_defaults(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _MINIMAL_TOOL + "deny:\n  - from: pii\n    to: github.pr\n",
    )

    assert load_deny_pairs(path) == (DenyPair(DataSourceKind.PII, SinkKind.GITHUB_PR),)


def test_explicitly_empty_deny_section_is_honoured(tmp_path: Path) -> None:
    """An operator may remove every static pair; the trifecta rule still applies."""

    assert load_deny_pairs(_write(tmp_path, _MINIMAL_TOOL + "deny: []\n")) == ()


@pytest.mark.parametrize(
    "deny",
    [
        pytest.param("deny:\n  - from: secrets\n", id="missing-to"),
        pytest.param("deny:\n  - to: shell.exec\n", id="missing-from"),
        pytest.param(
            "deny:\n  - from: secrets\n    to: shell.exec\n    why: nope\n",
            id="extra-field",
        ),
        pytest.param("deny:\n  - from: secret\n    to: shell.exec\n", id="unknown-source"),
        pytest.param("deny:\n  - from: secrets\n    to: shell.exe\n", id="unknown-sink"),
        pytest.param("deny: {}\n", id="not-a-list"),
        pytest.param(
            "deny:\n  - from: secrets\n    to: shell.exec\n"
            "  - from: secrets\n    to: shell.exec\n",
            id="duplicate-entry",
        ),
    ],
)
def test_invalid_deny_sections_are_rejected(tmp_path: Path, deny: str) -> None:
    with pytest.raises(ConfigError):
        load_deny_pairs(_write(tmp_path, _MINIMAL_TOOL + deny))


def test_unknown_root_key_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_tool_metadata(_write(tmp_path, _MINIMAL_TOOL + "extra: 1\n"))
