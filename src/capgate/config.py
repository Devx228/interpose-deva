from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]

from capgate.engine.pipeline import ToolMetadata
from capgate.flow.rules import DEFAULT_DENY_PAIRS, DenyPair
from capgate.flow.sinks import SinkKind
from capgate.flow.sources import DataSourceKind, is_valid_source_tag
from capgate.policy.model import Capability
from capgate.sandbox.base import RiskClass
from capgate.taint.declassify import (
    BoolField,
    DeclassificationSpec,
    EnumField,
    FieldDomain,
    IntRangeField,
)
from capgate.taint.labels import Confidentiality, Integrity, Label

_REQUIRED_ROOT_KEYS = frozenset({"tools"})
_OPTIONAL_ROOT_KEYS = frozenset({"deny"})
_ROOT_KEYS = _REQUIRED_ROOT_KEYS | _OPTIONAL_ROOT_KEYS
_DENY_KEYS = frozenset({"from", "to"})
_REQUIRED_TOOL_KEYS = frozenset(
    {"capability", "confidentiality", "integrity", "risk_class"}
)
_OPTIONAL_TOOL_KEYS = frozenset({"source_tags", "sink", "returns_reference", "declassify"})
_DECLASSIFY_KEYS = frozenset({"fields"})
_TOOL_KEYS = _REQUIRED_TOOL_KEYS | _OPTIONAL_TOOL_KEYS


class ConfigError(ValueError):
    """Raised when configuration is unreadable or does not match its grammar."""


@dataclass(frozen=True)
class CapgatePaths:
    state_dir: Path = Path(".capgate")

    @property
    def private_key_file(self) -> Path:
        return self.state_dir / "ed25519.private"

    @property
    def public_key_file(self) -> Path:
        return self.state_dir / "ed25519.public"

    @property
    def receipt_log(self) -> Path:
        return self.state_dir / "receipts.jsonl"

    @property
    def tool_pin_db(self) -> Path:
        return self.state_dir / "tool-pins.sqlite3"


def _load_root(path: str | Path) -> dict[str, object]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        raise ConfigError("unable to read tool metadata") from None
    try:
        raw = cast(object, yaml.safe_load(text))
    except yaml.YAMLError:
        raise ConfigError("tool metadata is not valid YAML") from None
    if not isinstance(raw, dict) or any(not isinstance(key, str) for key in raw):
        raise ConfigError("tool metadata must be a mapping")
    root = cast(dict[str, object], raw)
    if set(root) - _ROOT_KEYS or _REQUIRED_ROOT_KEYS - set(root):
        raise ConfigError("tool metadata must contain the tools field and may add deny")
    return root


def load_tool_metadata(path: str | Path) -> dict[str, ToolMetadata]:
    root = _load_root(path)
    tools_raw = root["tools"]
    if not isinstance(tools_raw, dict) or any(
        not isinstance(name, str) for name in tools_raw
    ):
        raise ConfigError("tools must be a mapping with string names")

    tools: dict[str, ToolMetadata] = {}
    for name, metadata_raw in cast(dict[str, object], tools_raw).items():
        tools[name] = _parse_tool_metadata(metadata_raw)
    return tools


def load_deny_pairs(path: str | Path) -> tuple[DenyPair, ...]:
    """Return the configured source-to-sink deny pairs, or the built-in defaults.

    Omitting `deny` keeps `DEFAULT_DENY_PAIRS`, so an existing metadata file is unchanged.
    Supplying an explicit empty list is honoured as "no static deny pairs" — the
    lethal-trifecta rule still applies, since it is not expressible as a source/sink pair.
    """

    root = _load_root(path)
    if "deny" not in root:
        return DEFAULT_DENY_PAIRS
    deny_raw = root["deny"]
    if not isinstance(deny_raw, list):
        raise ConfigError("deny must be a list of from/to mappings")

    pairs: list[DenyPair] = []
    for entry in cast(list[object], deny_raw):
        if not isinstance(entry, dict) or set(cast(dict[str, object], entry)) != _DENY_KEYS:
            raise ConfigError("each deny entry must have exactly the from and to fields")
        item = cast(dict[str, object], entry)
        source_raw = item["from"]
        sink_raw = item["to"]
        if not isinstance(source_raw, str) or not isinstance(sink_raw, str):
            raise ConfigError("deny from and to must be strings")
        try:
            pair = DenyPair(DataSourceKind(source_raw), SinkKind(sink_raw))
        except ValueError:
            raise ConfigError(
                f"deny entry names an unknown data source or sink: {source_raw} -> {sink_raw}"
            ) from None
        if pair in pairs:
            raise ConfigError(f"duplicate deny entry: {source_raw} -> {sink_raw}")
        pairs.append(pair)
    return tuple(pairs)


def _parse_tool_metadata(raw: object) -> ToolMetadata:
    if not isinstance(raw, dict) or any(not isinstance(key, str) for key in raw):
        raise ConfigError("each tool must map to security metadata")
    data = cast(dict[str, object], raw)
    if set(data) - _TOOL_KEYS or _REQUIRED_TOOL_KEYS - set(data):
        raise ConfigError("tool metadata fields do not match the required grammar")

    capability_raw = data["capability"]
    confidentiality_raw = data["confidentiality"]
    integrity_raw = data["integrity"]
    risk_class_raw = data["risk_class"]
    sink_raw = data.get("sink", SinkKind.NONE.value)
    if (
        not isinstance(capability_raw, str)
        or not isinstance(confidentiality_raw, str)
        or not isinstance(integrity_raw, str)
        or not isinstance(risk_class_raw, str)
        or not isinstance(sink_raw, str)
    ):
        raise ConfigError("tool metadata scalar fields must be strings")

    returns_reference_raw = data.get("returns_reference", False)
    if not isinstance(returns_reference_raw, bool):
        raise ConfigError("tool metadata returns_reference must be a boolean")

    source_tags_raw = data.get("source_tags", [])
    if not isinstance(source_tags_raw, list) or any(
        not isinstance(tag, str) for tag in source_tags_raw
    ):
        raise ConfigError("tool metadata source_tags must be a list of strings")
    source_tags = cast(list[str], source_tags_raw)
    unknown_tags = sorted({tag for tag in source_tags if not is_valid_source_tag(tag)})
    if unknown_tags:
        raise ConfigError(
            "tool metadata source_tags must name a known data source or be namespaced "
            f"like 'mcp:mail': {', '.join(unknown_tags)}"
        )

    try:
        capability = str(Capability.parse(capability_raw))
    except ValueError:
        raise ConfigError("tool metadata capability is invalid") from None
    try:
        confidentiality = Confidentiality(confidentiality_raw)
        integrity = Integrity(integrity_raw)
        risk_class = RiskClass(risk_class_raw)
        sink = SinkKind(sink_raw)
    except ValueError:
        raise ConfigError("tool metadata label, risk class, or sink is invalid") from None

    result_label = Label(
        confidentiality=confidentiality,
        integrity=integrity,
        source_tags=frozenset(source_tags),
    )
    declassification: DeclassificationSpec | None = None
    if "declassify" in data:
        # A declassifier's declared confidentiality/integrity ARE the post-validation
        # output label; the closed field domains come from the declassify block.
        declassification = _parse_declassification(data["declassify"], result_label)

    return ToolMetadata(
        result_label=result_label,
        risk_class=risk_class,
        sink=sink,
        capability=capability,
        returns_reference=returns_reference_raw,
        declassification=declassification,
    )


def _parse_declassification(raw: object, output_label: Label) -> DeclassificationSpec:
    if not isinstance(raw, dict) or set(cast(dict[str, object], raw)) != _DECLASSIFY_KEYS:
        raise ConfigError("declassify must be a mapping with exactly the fields key")
    fields_raw = cast(dict[str, object], raw)["fields"]
    if not isinstance(fields_raw, dict) or not fields_raw:
        raise ConfigError("declassify fields must be a non-empty mapping")
    fields: dict[str, FieldDomain] = {}
    for name, domain_raw in cast(dict[object, object], fields_raw).items():
        if not isinstance(name, str):
            raise ConfigError("declassify field names must be strings")
        fields[name] = _parse_field_domain(name, domain_raw)
    try:
        return DeclassificationSpec(fields=fields, output_label=output_label)
    except ValueError as error:
        raise ConfigError(f"declassify spec is invalid: {error}") from None


def _parse_field_domain(name: str, raw: object) -> FieldDomain:
    if not isinstance(raw, dict):
        raise ConfigError(f"declassify field must be a mapping: {name}")
    data = cast(dict[str, object], raw)
    kind = data.get("type")
    try:
        if kind == "bool":
            if set(data) != {"type"}:
                raise ConfigError(f"declassify bool field takes no extra keys: {name}")
            return BoolField()
        if kind == "int":
            if set(data) != {"type", "min", "max"}:
                raise ConfigError(f"declassify int field needs exactly min and max: {name}")
            minimum = data["min"]
            maximum = data["max"]
            if (
                not isinstance(minimum, int)
                or not isinstance(maximum, int)
                or isinstance(minimum, bool)
                or isinstance(maximum, bool)
            ):
                raise ConfigError(f"declassify int bounds must be integers: {name}")
            return IntRangeField(minimum, maximum)
        if kind == "enum":
            if set(data) != {"type", "values"}:
                raise ConfigError(f"declassify enum field needs exactly values: {name}")
            values = data["values"]
            if (
                not isinstance(values, list)
                or not values
                or any(not isinstance(item, str) for item in values)
            ):
                raise ConfigError(
                    f"declassify enum values must be a non-empty string list: {name}"
                )
            return EnumField(frozenset(cast(list[str], values)))
    except ValueError as error:
        raise ConfigError(f"declassify field domain is invalid: {name}: {error}") from None
    raise ConfigError(f"declassify field type must be bool, int, or enum: {name}")
