from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]

from capgate.policy.model import CapabilityPattern, Policy, PolicyError

_KEYS = frozenset({"agent", "can", "cannot", "requires_approval"})


def parse_policy(text: str) -> Policy:
    try:
        raw = cast(object, yaml.safe_load(text))
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid policy YAML: {exc}") from exc
    if not isinstance(raw, dict) or any(not isinstance(key, str) for key in raw):
        raise PolicyError("policy must be a YAML mapping with string keys")
    data = cast(dict[str, object], raw)
    unknown = set(data) - _KEYS
    if unknown:
        raise PolicyError(f"unknown policy keys: {', '.join(sorted(unknown))}")
    agent = data.get("agent")
    if not isinstance(agent, str) or not agent or agent != agent.strip():
        raise PolicyError("policy agent must be a non-empty string without outer whitespace")
    return Policy(
        agent=agent,
        can=_patterns(data.get("can", []), "can"),
        cannot=_patterns(data.get("cannot", []), "cannot"),
        requires_approval=_patterns(
            data.get("requires_approval", []), "requires_approval"
        ),
    )


def load_policy(path: str | Path) -> Policy:
    return parse_policy(Path(path).read_text(encoding="utf-8"))


def _patterns(value: object, field: str) -> tuple[CapabilityPattern, ...]:
    if not isinstance(value, list):
        raise PolicyError(f"policy {field} must be a list")
    patterns: list[CapabilityPattern] = []
    for item in value:
        if not isinstance(item, str):
            raise PolicyError(f"policy {field} entries must be strings")
        patterns.append(CapabilityPattern.parse(item))
    return tuple(patterns)
