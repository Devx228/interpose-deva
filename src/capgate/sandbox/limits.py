from __future__ import annotations

from dataclasses import dataclass
from threading import Lock

from capgate.engine.decision import Decision

UNSUPPORTED_SYSCALL_LIMIT_RULE_ID = "sandbox.limits.syscalls_unsupported"
BUDGET_TOOL_CALLS_RULE_ID = "sandbox.budget.tool_calls_exhausted"
BUDGET_TOKENS_RULE_ID = "sandbox.budget.tokens_exhausted"
BUDGET_COST_RULE_ID = "sandbox.budget.cost_exhausted"
BUDGET_USAGE_RULE_ID = "sandbox.budget.usage_invalid"
BUDGET_RESERVATION_RULE_ID = "sandbox.budget.reservation_invalid"

_MAX_CPU_MILLIS = 86_400_000
_MAX_MEMORY_BYTES = 1 << 40
_MAX_SWAP_BYTES = 1 << 40
_MAX_PROCESS_COUNT = 1_000_000
_MAX_WALL_TIME_MILLIS = 604_800_000
_MAX_WRITABLE_BYTES = 1 << 40
_MAX_OUTPUT_BYTES = 1 << 30
_MAX_TOOL_CALLS = 1_000_000
_MAX_TOKENS = 1_000_000_000
_MAX_COST_MICROS = 1_000_000_000_000
_MAX_SYSCALLS = 100_000_000_000


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    cpu_millis: int
    memory_bytes: int
    swap_bytes: int
    process_count: int
    wall_time_millis: int
    writable_bytes: int
    output_bytes: int
    max_tool_calls: int
    max_tokens: int
    max_cost_micros: int
    max_syscalls: int | None = None

    def __post_init__(self) -> None:
        bounds = (
            ("cpu_millis", self.cpu_millis, _MAX_CPU_MILLIS),
            ("memory_bytes", self.memory_bytes, _MAX_MEMORY_BYTES),
            ("swap_bytes", self.swap_bytes, _MAX_SWAP_BYTES),
            ("process_count", self.process_count, _MAX_PROCESS_COUNT),
            ("wall_time_millis", self.wall_time_millis, _MAX_WALL_TIME_MILLIS),
            ("writable_bytes", self.writable_bytes, _MAX_WRITABLE_BYTES),
            ("output_bytes", self.output_bytes, _MAX_OUTPUT_BYTES),
            ("max_tool_calls", self.max_tool_calls, _MAX_TOOL_CALLS),
            ("max_tokens", self.max_tokens, _MAX_TOKENS),
            ("max_cost_micros", self.max_cost_micros, _MAX_COST_MICROS),
        )
        for name, value, maximum in bounds:
            _validate_positive_bounded(name, value, maximum)
        if self.max_syscalls is not None:
            _validate_positive_bounded("max_syscalls", self.max_syscalls, _MAX_SYSCALLS)


def check_backend_limit_support(
    limits: SandboxLimits,
    *,
    supports_syscall_limit: bool,
) -> Decision:
    if limits.max_syscalls is not None and not supports_syscall_limit:
        return _decision(
            "BLOCK",
            "requested syscall accounting is unsupported by the selected backend",
            UNSUPPORTED_SYSCALL_LIMIT_RULE_ID,
        )
    return _decision("ALLOW", "selected backend supports the requested limits", None)


@dataclass(frozen=True, slots=True)
class BudgetReservation:
    reservation_id: int
    tokens: int
    cost_micros: int


@dataclass(frozen=True, slots=True)
class BudgetResult:
    decision: Decision
    reservation: BudgetReservation | None = None


@dataclass(frozen=True, slots=True)
class BudgetSnapshot:
    attempts: int
    consumed_tokens: int
    reserved_tokens: int
    consumed_cost_micros: int
    reserved_cost_micros: int
    remaining_tool_calls: int
    remaining_tokens: int
    remaining_cost_micros: int


class SessionBudget:
    """Trusted, thread-safe quota ledger for a single agent session."""

    def __init__(self, limits: SandboxLimits) -> None:
        self._limits = limits
        self._lock = Lock()
        self._attempts = 0
        self._consumed_tokens = 0
        self._reserved_tokens = 0
        self._consumed_cost_micros = 0
        self._reserved_cost_micros = 0
        self._next_reservation_id = 1
        self._active: dict[int, BudgetReservation] = {}

    def reserve(self, *, tokens: int, cost_micros: int) -> BudgetResult:
        """Count one attempt and atomically reserve its worst-case model budget."""

        with self._lock:
            self._attempts += 1
            if not _is_nonnegative_int(tokens) or not _is_nonnegative_int(cost_micros):
                return BudgetResult(
                    _decision("BLOCK", "budget reservation usage is invalid", BUDGET_USAGE_RULE_ID)
                )
            if self._attempts > self._limits.max_tool_calls:
                return BudgetResult(
                    _decision(
                        "BLOCK",
                        "session tool-call attempt budget is exhausted",
                        BUDGET_TOOL_CALLS_RULE_ID,
                    )
                )
            if (
                self._consumed_tokens + self._reserved_tokens + tokens
                > self._limits.max_tokens
            ):
                return BudgetResult(
                    _decision(
                        "BLOCK",
                        "session token budget is exhausted",
                        BUDGET_TOKENS_RULE_ID,
                    )
                )
            if (
                self._consumed_cost_micros + self._reserved_cost_micros + cost_micros
                > self._limits.max_cost_micros
            ):
                return BudgetResult(
                    _decision(
                        "BLOCK",
                        "session cost budget is exhausted",
                        BUDGET_COST_RULE_ID,
                    )
                )

            reservation = BudgetReservation(
                reservation_id=self._next_reservation_id,
                tokens=tokens,
                cost_micros=cost_micros,
            )
            self._next_reservation_id += 1
            self._active[reservation.reservation_id] = reservation
            self._reserved_tokens += tokens
            self._reserved_cost_micros += cost_micros
            return BudgetResult(
                decision=_decision("ALLOW", "session budget reserved", None),
                reservation=reservation,
            )

    def reconcile(
        self,
        reservation: BudgetReservation,
        *,
        actual_tokens: int | None,
        actual_cost_micros: int | None,
        trusted_usage: bool,
    ) -> Decision:
        """Commit trusted usage; otherwise conservatively consume the full reserve."""

        with self._lock:
            stored = self._active.get(reservation.reservation_id)
            if stored is not reservation:
                return _decision(
                    "BLOCK",
                    "budget reservation is missing or already reconciled",
                    BUDGET_RESERVATION_RULE_ID,
                )

            del self._active[reservation.reservation_id]
            self._reserved_tokens -= reservation.tokens
            self._reserved_cost_micros -= reservation.cost_micros

            if not trusted_usage or actual_tokens is None or actual_cost_micros is None:
                self._consume(reservation.tokens, reservation.cost_micros)
                return _decision(
                    "ALLOW",
                    "full reservation consumed because usage was unavailable or untrusted",
                    None,
                )

            if not _is_nonnegative_int(actual_tokens) or not _is_nonnegative_int(
                actual_cost_micros
            ):
                self._consume(reservation.tokens, reservation.cost_micros)
                return _decision(
                    "BLOCK", "trusted usage report is invalid", BUDGET_USAGE_RULE_ID
                )

            self._consume(actual_tokens, actual_cost_micros)
            if actual_tokens > reservation.tokens or actual_cost_micros > reservation.cost_micros:
                return _decision(
                    "BLOCK",
                    "trusted usage exceeded its reserved session budget",
                    BUDGET_USAGE_RULE_ID,
                )
            return _decision("ALLOW", "trusted usage reconciled", None)

    def snapshot(self) -> BudgetSnapshot:
        with self._lock:
            return BudgetSnapshot(
                attempts=self._attempts,
                consumed_tokens=self._consumed_tokens,
                reserved_tokens=self._reserved_tokens,
                consumed_cost_micros=self._consumed_cost_micros,
                reserved_cost_micros=self._reserved_cost_micros,
                remaining_tool_calls=max(0, self._limits.max_tool_calls - self._attempts),
                remaining_tokens=max(
                    0,
                    self._limits.max_tokens
                    - self._consumed_tokens
                    - self._reserved_tokens,
                ),
                remaining_cost_micros=max(
                    0,
                    self._limits.max_cost_micros
                    - self._consumed_cost_micros
                    - self._reserved_cost_micros,
                ),
            )

    def _consume(self, tokens: int, cost_micros: int) -> None:
        self._consumed_tokens += tokens
        self._consumed_cost_micros += cost_micros


def _validate_positive_bounded(name: str, value: object, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > maximum:
        raise ValueError(f"{name} must be a positive bounded integer")


def _is_nonnegative_int(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _decision(verdict: str, reason: str, rule_id: str | None) -> Decision:
    if verdict == "ALLOW":
        return Decision("ALLOW", reason, rule_id, frozenset())
    return Decision("BLOCK", reason, rule_id, frozenset())
