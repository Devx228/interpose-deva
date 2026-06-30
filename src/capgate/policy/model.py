from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase

_ACTION = re.compile(r"[a-z][a-z0-9_-]*\Z")
_RESOURCE = re.compile(r"[a-z0-9*][a-z0-9._/*-]*\Z")


class PolicyError(ValueError):
    """Raised when policy input does not match the capability grammar."""


def _parts(value: str, *, pattern: bool) -> tuple[str, str]:
    if value.count(":") != 1:
        raise PolicyError(f"capability must be action:resource: {value!r}")
    action, resource = value.split(":", 1)
    if not _ACTION.fullmatch(action) or not _RESOURCE.fullmatch(resource):
        raise PolicyError(f"invalid capability: {value!r}")
    if not pattern and "*" in resource:
        raise PolicyError(f"concrete capability cannot contain a glob: {value!r}")
    return action, resource


@dataclass(frozen=True, order=True)
class Capability:
    action: str
    resource: str

    @classmethod
    def parse(cls, value: str) -> Capability:
        return cls(*_parts(value, pattern=False))

    def __str__(self) -> str:
        return f"{self.action}:{self.resource}"


@dataclass(frozen=True, order=True)
class CapabilityPattern:
    action: str
    resource: str

    @classmethod
    def parse(cls, value: str) -> CapabilityPattern:
        return cls(*_parts(value, pattern=True))

    def matches(self, capability: Capability) -> bool:
        return self.action == capability.action and fnmatchcase(
            capability.resource, self.resource
        )

    def is_subset_of(self, other: CapabilityPattern) -> bool:
        """Conservatively prove this pattern is contained by ``other``."""
        if self.action != other.action:
            return False
        if self.resource == other.resource or other.resource == "*":
            return True
        if "*" not in self.resource:
            return other.matches(Capability(self.action, self.resource))
        if self.resource.endswith("*") and other.resource.endswith("*"):
            return self.resource[:-1].startswith(other.resource[:-1])
        return False

    def __str__(self) -> str:
        return f"{self.action}:{self.resource}"


@dataclass(frozen=True)
class Policy:
    agent: str
    can: tuple[CapabilityPattern, ...]
    cannot: tuple[CapabilityPattern, ...]
    requires_approval: tuple[CapabilityPattern, ...]
