from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace

import pytest

from capgate.sandbox.limits import (
    BUDGET_COST_RULE_ID,
    BUDGET_RESERVATION_RULE_ID,
    BUDGET_TOKENS_RULE_ID,
    BUDGET_TOOL_CALLS_RULE_ID,
    BUDGET_USAGE_RULE_ID,
    UNSUPPORTED_SYSCALL_LIMIT_RULE_ID,
    BudgetReservation,
    SandboxLimits,
    SessionBudget,
    check_backend_limit_support,
)


def _limits(**overrides: int | None) -> SandboxLimits:
    values: dict[str, int | None] = {
        "cpu_millis": 1_000,
        "memory_bytes": 64 * 1024 * 1024,
        "swap_bytes": 64 * 1024 * 1024,
        "process_count": 16,
        "wall_time_millis": 2_000,
        "writable_bytes": 1024 * 1024,
        "output_bytes": 64 * 1024,
        "max_tool_calls": 3,
        "max_tokens": 100,
        "max_cost_micros": 1_000,
        "max_syscalls": None,
    }
    values.update(overrides)
    return SandboxLimits(**values)  # type: ignore[arg-type]


def test_limits_require_every_mandatory_field() -> None:
    with pytest.raises(TypeError):
        SandboxLimits(  # type: ignore[call-arg]
            cpu_millis=1,
            memory_bytes=1,
            swap_bytes=1,
            process_count=1,
            wall_time_millis=1,
            writable_bytes=1,
            output_bytes=1,
            max_tool_calls=1,
            max_tokens=1,
        )


@pytest.mark.parametrize(
    "field",
    [
        "cpu_millis",
        "memory_bytes",
        "swap_bytes",
        "process_count",
        "wall_time_millis",
        "writable_bytes",
        "output_bytes",
        "max_tool_calls",
        "max_tokens",
        "max_cost_micros",
        "max_syscalls",
    ],
)
@pytest.mark.parametrize("invalid", [0, -1, True])
def test_limits_reject_non_positive_or_boolean_values(field: str, invalid: int) -> None:
    with pytest.raises(ValueError, match="positive bounded integer"):
        _limits(**{field: invalid})


def test_limits_reject_values_above_their_bound() -> None:
    with pytest.raises(ValueError, match="cpu_millis"):
        _limits(cpu_millis=86_400_001)


def test_limits_are_immutable() -> None:
    limits = _limits()

    with pytest.raises(FrozenInstanceError):
        limits.max_tokens = 10  # type: ignore[misc]


def test_syscall_limit_is_optional_but_requested_support_is_mandatory() -> None:
    no_syscall_limit = _limits()
    syscall_limit = replace(no_syscall_limit, max_syscalls=1_000)

    assert check_backend_limit_support(
        no_syscall_limit, supports_syscall_limit=False
    ).verdict == "ALLOW"
    assert check_backend_limit_support(
        syscall_limit, supports_syscall_limit=True
    ).verdict == "ALLOW"
    unsupported = check_backend_limit_support(
        syscall_limit, supports_syscall_limit=False
    )
    assert unsupported.verdict == "BLOCK"
    assert unsupported.rule_id == UNSUPPORTED_SYSCALL_LIMIT_RULE_ID


def test_reserve_counts_every_attempt_and_fails_closed_at_tool_limit() -> None:
    budget = SessionBudget(_limits(max_tool_calls=1))

    first = budget.reserve(tokens=0, cost_micros=0)
    blocked = budget.reserve(tokens=0, cost_micros=0)

    assert first.decision.verdict == "ALLOW"
    assert blocked.decision.verdict == "BLOCK"
    assert blocked.decision.rule_id == BUDGET_TOOL_CALLS_RULE_ID
    assert blocked.reservation is None
    assert budget.snapshot().attempts == 2
    assert budget.snapshot().remaining_tool_calls == 0


@pytest.mark.parametrize(
    ("tokens", "cost_micros", "rule_id"),
    [(101, 0, BUDGET_TOKENS_RULE_ID), (0, 1_001, BUDGET_COST_RULE_ID)],
)
def test_reserve_fails_closed_when_model_budget_is_exhausted(
    tokens: int, cost_micros: int, rule_id: str
) -> None:
    budget = SessionBudget(_limits())

    result = budget.reserve(tokens=tokens, cost_micros=cost_micros)

    assert result.decision.verdict == "BLOCK"
    assert result.decision.rule_id == rule_id
    assert result.reservation is None
    assert budget.snapshot().attempts == 1


def test_trusted_reconciliation_commits_actual_usage_and_releases_only_unused_reserve() -> None:
    budget = SessionBudget(_limits())
    result = budget.reserve(tokens=80, cost_micros=800)
    assert result.reservation is not None
    reserved_snapshot = budget.snapshot()

    decision = budget.reconcile(
        result.reservation,
        actual_tokens=30,
        actual_cost_micros=300,
        trusted_usage=True,
    )
    snapshot = budget.snapshot()

    assert decision.verdict == "ALLOW"
    assert reserved_snapshot.remaining_tokens == 20
    assert snapshot.consumed_tokens == 30
    assert snapshot.consumed_cost_micros == 300
    assert snapshot.reserved_tokens == 0
    assert snapshot.remaining_tokens == 70
    assert snapshot.remaining_cost_micros == 700


@pytest.mark.parametrize("trusted_usage", [False, True])
def test_missing_or_untrusted_usage_never_refunds_budget(trusted_usage: bool) -> None:
    budget = SessionBudget(_limits())
    result = budget.reserve(tokens=80, cost_micros=800)
    assert result.reservation is not None

    decision = budget.reconcile(
        result.reservation,
        actual_tokens=None,
        actual_cost_micros=None,
        trusted_usage=trusted_usage,
    )
    snapshot = budget.snapshot()

    assert decision.verdict == "ALLOW"
    assert snapshot.consumed_tokens == 80
    assert snapshot.consumed_cost_micros == 800
    assert snapshot.remaining_tokens == 20
    assert snapshot.remaining_cost_micros == 200


def test_over_reservation_usage_blocks_and_never_replenishes_budget() -> None:
    budget = SessionBudget(_limits())
    result = budget.reserve(tokens=50, cost_micros=500)
    assert result.reservation is not None

    decision = budget.reconcile(
        result.reservation,
        actual_tokens=101,
        actual_cost_micros=1_001,
        trusted_usage=True,
    )

    assert decision.verdict == "BLOCK"
    assert decision.rule_id == BUDGET_USAGE_RULE_ID
    assert budget.snapshot().remaining_tokens == 0
    assert budget.snapshot().remaining_cost_micros == 0
    assert budget.reserve(tokens=0, cost_micros=0).decision.verdict == "BLOCK"


def test_reservation_cannot_be_reconciled_twice_or_forged() -> None:
    budget = SessionBudget(_limits())
    result = budget.reserve(tokens=10, cost_micros=100)
    assert result.reservation is not None
    forged = BudgetReservation(
        result.reservation.reservation_id,
        result.reservation.tokens,
        result.reservation.cost_micros,
    )

    forged_decision = budget.reconcile(
        forged,
        actual_tokens=1,
        actual_cost_micros=1,
        trusted_usage=True,
    )
    assert forged_decision.verdict == "BLOCK"
    assert forged_decision.rule_id == BUDGET_RESERVATION_RULE_ID

    assert budget.reconcile(
        result.reservation,
        actual_tokens=1,
        actual_cost_micros=1,
        trusted_usage=True,
    ).verdict == "ALLOW"
    repeated = budget.reconcile(
        result.reservation,
        actual_tokens=1,
        actual_cost_micros=1,
        trusted_usage=True,
    )
    assert repeated.verdict == "BLOCK"
    assert repeated.rule_id == BUDGET_RESERVATION_RULE_ID


def test_concurrent_reservations_are_atomic_and_attempt_count_is_monotonic() -> None:
    budget = SessionBudget(_limits(max_tool_calls=20, max_tokens=10, max_cost_micros=10))

    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(
            executor.map(lambda _: budget.reserve(tokens=1, cost_micros=1), range(20))
        )

    assert sum(result.decision.verdict == "ALLOW" for result in results) == 10
    assert sum(result.decision.verdict == "BLOCK" for result in results) == 10
    snapshot = budget.snapshot()
    assert snapshot.attempts == 20
    assert snapshot.reserved_tokens == 10
    assert snapshot.reserved_cost_micros == 10
