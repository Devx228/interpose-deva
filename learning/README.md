# Learning CapGate from zero

This folder teaches the project from first principles. It assumes you can read Python and
know nothing about AI-agent security, information-flow control, or capability systems.

Every concept links directly to the code that implements it. Read a section, then open the
file next to it — the point is to be able to predict what the code does before you read it.

## Reading order

The order matters. Each part depends on the one before it.

| # | File | What you learn |
|---|---|---|
| 01 | [The problem](01-the-problem.md) | What an agent is, what prompt injection is, why filtering fails |
| 02 | [The gate](02-the-gate.md) | The enforcement idea, fail-closed, the five questions |
| 03 | [Capabilities](03-capabilities.md) | Least privilege, the policy DSL, precedence |
| 04 | [Taint labels](04-taint-labels.md) | The lattice, joins, monotonicity |
| 05 | [Flow and the trifecta](05-flow-and-trifecta.md) | Sources, sinks, and the headline defense |
| 06 | [Receipts](06-receipts.md) | Hashing, signatures, chaining, replay, and their limits |
| 07 | [Code walkthrough](07-code-walkthrough.md) | One tool call end to end, file by file |
| 08 | [Where we stand](08-where-we-stand.md) | Real test baseline, what's built, the one real weakness |
| 09 | [Roadmap](09-roadmap.md) | What we're building over the next six weeks, and why |
| 10 | [Interview answers](10-interview-answers.md) | Questions you will be asked, and how to answer them |

## The one-paragraph version

An AI agent that can read your private data and also send email is one convincing sentence
away from mailing your secrets to a stranger. You cannot reliably detect that sentence.
So CapGate assumes the model is already compromised and puts a deterministic enforcement
layer at the tool boundary: every tool call is checked against an explicit capability policy
and an information-flow rule that tracks where the data came from. If private data influenced
by untrusted content tries to reach an external destination, the call is blocked before the
handler runs — and every decision, allowed or blocked, is recorded in a signed, tamper-evident
log.

## Run it right now

No API key, no network:

```bash
python examples/langgraph_security_demo.py
```

A real compiled LangGraph `StateGraph` with a real `ToolNode`. A harmless call succeeds, a
private read succeeds, and the external send is blocked with its handler never invoked.

See [07 — Code walkthrough](07-code-walkthrough.md) for what each line of that output means.

## See the numbers

```bash
python bench/run_scenarios.py
```

22 deterministic scenarios — 12 attacks drawn from real incidents, 10 pieces of legitimate work.
Each attack runs undefended first as a control, then through CapGate:

```
undefended attack success 100.0%     <- proves every attack is real
containment rate          100.0%
false-block rate           10.0%
```

Read those bottom two together. Containment alone is meaningless — refusing every call would
score a perfect 100%. See [09 — Roadmap](09-roadmap.md) for how the harness works.

## Related docs elsewhere in the repo

These are reference material, not tutorials. Come back to them once you've read this folder.

- [`docs/SECURITY_MODEL.md`](../docs/SECURITY_MODEL.md) — formal assets, attacker model, invariants, residual risks
- [`STATUS.md`](../STATUS.md) — the precise implemented/partial/unmeasured boundary
- [`spec-docs/STAGE1_TAINT_DESIGN.md`](../spec-docs/STAGE1_TAINT_DESIGN.md) — the taint design note
- [`bench/reports/README.md`](../bench/reports/README.md) — why no checked-in benchmark number is quotable
