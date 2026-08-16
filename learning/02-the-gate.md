# 02 — The gate

## Where the gate sits

CapGate sits at the one place every action must pass through: between "the model requested a
tool call" and "the tool runs."

```
  model emits tool_call
          |
          v
  +-----------------+
  |    CapGate      |   <-- deterministic code, no model involved
  +-----------------+
       |        |
    ALLOW    BLOCK
       |        |
       v        v
   tool runs   nothing happens
```

Not a wrapper around the model. Not a filter on the prompt. A gate on the **action**.

## The five questions

At that point CapGate asks five questions that normal software can answer with certainty.

| # | Question | Rule ID if it fails |
|---|---|---|
| 1 | Do I have trusted security metadata for this tool? | `engine.unknown_tool` |
| 2 | Is this agent permitted to use this capability at all? | `policy.default_deny` |
| 3 | Where did the data feeding this call come from? | — (produces a label) |
| 4 | May *this* data reach *this* destination? | `flow.lethal_trifecta` |
| 5 | Does this tool require an isolation boundary I actually have? | `sandbox.risk.unknown` |

Every question is answerable by looking at configuration and recorded state. None of them
requires judging whether text looks malicious. That is the design constraint that makes the
whole thing deterministic: **same inputs, same policy, same decision, every time.**

The implementation is [`DecisionPipeline._decide`](../src/capgate/engine/pipeline.py#L47) —
about thirty lines, evaluated in order, first non-ALLOW verdict wins.

## Fail-closed

If any question cannot be answered safely, the answer is **block**. That principle is called
**fail-closed**, and it is the difference between a security control and a suggestion.

Look at [`pipeline.py:35-45`](../src/capgate/engine/pipeline.py#L35-L45):

```python
def decide(self, context: AgentContext, event: ToolCallEvent) -> Decision:
    argument_label = context.label_for_call(tuple(event.arg_provenance.values()))
    try:
        return self._decide(event, argument_label)
    except Exception:
        return Decision(
            verdict="BLOCK",
            reason="decision pipeline failed closed",
            rule_id="engine.decision_error",
            labels=label_strings(argument_label),
        )
```

A bare `except Exception` is usually a code smell. Here it is the point. If *anything*
unexpected happens inside the decision path — a bug, a malformed config, a `KeyError` — the
result is a block. There is no code path where a crash produces an accidental allow.

The same discipline appears everywhere:

- Unknown tool → block ([`pipeline.py:48-55`](../src/capgate/engine/pipeline.py#L48-L55))
- Missing capability in metadata → block ([`pipeline.py:56-63`](../src/capgate/engine/pipeline.py#L56-L63))
- Unknown risk class → block ([`sandbox/base.py:113-122`](../src/capgate/sandbox/base.py#L113-L122))
- Required sandbox unavailable → block, never fall back to running on the host
- Provenance tracking failed after a call → the whole session is marked failed-closed, so later
  calls cannot proceed on state we no longer trust ([`mediator.py:70-79`](../src/capgate/engine/mediator.py#L70-L79))

### What fail-closed costs

Availability. A missing metadata entry blocks legitimate work. Broken receipt storage blocks
legitimate work. Overly conservative taint blocks legitimate work.

This is a real cost, not a footnote. A security control that people switch off provides zero
security. That is exactly why we will measure a **false-block rate** alongside the containment
rate — see [09 — Roadmap](09-roadmap.md).

## Deny by default

Related but distinct: a capability is blocked unless a rule explicitly allows it.

The alternative — allow unless explicitly denied — requires you to enumerate every bad thing
in advance. You will miss some. Deny-by-default requires you to enumerate the good things,
and the failure mode of missing one is a blocked feature rather than a breach.

## The three verdicts

[`engine/decision.py`](../src/capgate/engine/decision.py) defines exactly three:

```python
Verdict = Literal["ALLOW", "BLOCK", "REQUIRE_APPROVAL"]
```

`REQUIRE_APPROVAL` means a human must answer before the tool runs. Two things make it safe:

**Without an approver, it blocks.** A verdict nobody can answer must never behave like an
allow, so `mediate()` refuses approval-required calls unless trusted code is supplied to
resolve them.

**An approval satisfies only the capability gate.** After a grant, the pipeline re-runs with
`approved=True` and *every later check still applies*. An approved call whose data would
violate a flow rule is still blocked — see
[`_resolve_approval`](../src/capgate/engine/mediator.py). Say this one out loud, because it is
the part people get wrong:

> Approval is permission to **act**, never permission to **leak**.

On the LangGraph side, [`interrupt_for_approval`](../src/capgate/adapters/langgraph.py) pauses
the graph so a person can answer, and only the exact boolean `True` approves — a truthy string
or a stray resume value denies. Someone answering a prompt with something the runtime did not
expect must never be read as consent.

Every decision carries four fields:

```python
@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str              # human-readable, goes in the receipt
    rule_id: str | None      # stable machine-readable ID, e.g. "flow.lethal_trifecta"
    labels: frozenset[str]   # the taint labels that produced this decision
```

`rule_id` matters more than it looks. It is a stable identifier you can grep for, assert on in
tests, and alert on in production. `reason` is for humans; `rule_id` is for machines.
`frozen=True` means a decision cannot be mutated after it is made.

## Two independent checks

Questions 2 and 4 are the substance, and they are genuinely independent:

- **Capabilities** (question 2) answer *may this agent perform this kind of action?*
- **Information flow** (question 4) answers *may this specific data reach this destination?*

Neither is sufficient alone, and the next three sections build them up in order.

---

Previous: [01 — The problem](01-the-problem.md) · Next: [03 — Capabilities](03-capabilities.md)
