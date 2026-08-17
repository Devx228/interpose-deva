# Handoff — start here

You are picking up CapGate mid-project. Read these four files in order; together they take
about ten minutes and should be enough to continue without re-deriving anything.

| File | What it answers |
|---|---|
| [GOALS.md](GOALS.md) | Why this project exists, the deadline, the hard constraints |
| [CURRENT_STATUS.md](CURRENT_STATUS.md) | Every measured number and where it came from |
| [DECISIONS.md](DECISIONS.md) | Choices already made and why — **do not relitigate these** |
| [NEXT_STEPS.md](NEXT_STEPS.md) | What to do next, in priority order |
| [ENVIRONMENT.md](ENVIRONMENT.md) | Machine setup, how to run everything, known gotchas |

## The project in three sentences

CapGate stops AI agents from leaking data or taking destructive actions when they are
prompt-injected. It does not try to detect malicious prompts — it assumes the model is already
compromised and enforces capability policy plus information-flow rules deterministically at the
tool-call boundary. It is a portfolio project for placements, so **honest measurement matters
more than flattering numbers**.

## The one rule that governs everything

> Report real results or report failure. Never a number you did not produce by running
> something.

This comes from `next-instrux/EXECUTION_DIRECTIVE.md` and it has repeatedly turned out to be
the project's strongest asset. Documented failures are what made an external reviewer take it
seriously. If you are ever tempted to quietly drop a bad number, don't — write it down and
explain it instead.

## Fastest way to see it working

```bash
cd D:\dev\interpose-deva
.venv\Scripts\python.exe -m pytest -q                    # 433 passed
.venv\Scripts\python.exe bench/run_scenarios.py          # self-authored corpus
.venv\Scripts\python.exe bench/agentdojo_attacks.py      # third-party corpus
```

Also read [`docs/LIMITATIONS.md`](../docs/LIMITATIONS.md) — it is where the project is honest
about what it does not catch, and it is deliberately the first thing the README links to.
