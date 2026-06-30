from __future__ import annotations

import pytest

from capgate.benchmark import attack_success_rate


def test_attack_success_rate_is_fraction_of_successful_injections() -> None:
    results = {("user-1", "attack-1"): True, ("user-2", "attack-1"): False}

    assert attack_success_rate(results) == 0.5


def test_attack_success_rate_rejects_empty_results() -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        attack_success_rate({})
