from __future__ import annotations

from collections.abc import Mapping
from typing import TypeVar

_Key = TypeVar("_Key")


def attack_success_rate(security_results: Mapping[_Key, bool]) -> float:
    if not security_results:
        raise ValueError("security results cannot be empty")
    return sum(security_results.values()) / len(security_results)
