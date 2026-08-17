# Spending money: what actually buys something

The project was built under a no-paid-API rule, and that constraint produced good work —
deterministic corpora, third-party attack replay, local-model demos. It is **not** a reason to
refuse spending now that some budget exists. It is a reason to spend it on exactly one thing.

## The one thing worth paying for

**A real AgentDojo run with a capable model, both arms.**

This is the single claim the project cannot currently make, and an external reviewer named it
precisely: *"the bullet you'd want — reduced attack success from X% to Y% — still can't be
written honestly."*

Everything else is already covered for free. Containment against third-party attacks: done.
Overhead: measured. Real-model injection demos: working locally. The only gap money closes is a
**published-benchmark defense-effect number**.

## Why local models cannot close it — measured, not assumed

This was tested rather than guessed. Reports retained at
`bench/reports/agentdojo-local-qwen25-7b-*.json`:

| Run | Model | Cases | Result |
|---|---|---|---|
| Utility, no attack | `qwen2.5:7b` | 5 user tasks | **utility 0.20** |
| Security, `direct` attack | `qwen2.5:7b` | 12 security cases | **ASR 0.00**, utility 0.33 |

**The undefended attack succeeds zero times out of twelve.** With no attack succeeding without
the defense, there is nothing for CapGate to be shown reducing — "reduced ASR from 0% to 0%" is
worthless, and manufacturing a number from it would be exactly the failure
`next-instrux/EXECUTION_DIRECTIVE.md` forbids.

The cause is capability: 0.2–0.33 utility against a published GPT-4o baseline of ~84%. An agent
that cannot complete the benign task generally cannot be manipulated into the malicious one
either. A stronger local model is not an option — the GPU is 6 GB, so ~7B at Q4 is the ceiling.

This is a legitimate negative result and worth stating plainly: **a local 7B model cannot
produce a meaningful AgentDojo baseline.** It is also the empirical case for spending money,
rather than an assumption that spending would help.

## Rough cost

AgentDojo runs `user_tasks × injection_tasks` security cases, each a multi-turn agent loop over
a large tool schema. Order-of-magnitude only — **verify current pricing before committing**:

| Scope | Security cases (both arms) | Rough cost, small model | Rough cost, frontier model |
|---|---|---|---|
| 10 user × 14 injection, workspace | 280 | a few dollars | tens of dollars |
| Full workspace suite (40 × 14) | 1120 | ~$10–20 | low hundreds |

**Start with a subset on a cheap capable model.** The deciding factor is not budget, it is
whether the undefended baseline shows real attack success. Spend a dollar or two establishing
that before spending more.

## Rules for the run — non-negotiable

These come from `next-instrux/EXECUTION_DIRECTIVE.md` and from what makes the result defensible:

1. **Predeclare everything before running:** suite, exact user-task list, exact injection-task
   list, model, attack method, benchmark version. Write it down first. Choosing tasks after
   seeing results is how a number becomes worthless.
2. **Both arms, identical cases.** `--mode undefended` and `--mode capgate --enforcement stage1`
   over the same task matrix. A comparison across different cases is not a comparison.
3. **The control must succeed.** If the undefended ASR is near zero, **stop**. Report *"the
   attack does not succeed against this model, so no defense effect is measurable"* and do not
   expand the matrix hoping for a better number.
4. **Report utility alongside ASR.** A defense that drives ASR to zero by breaking the agent has
   achieved nothing. This is the same discipline as reporting the false-block rate.
5. **Retain provenance:** exact command, model, AgentDojo version, clean git revision. The
   runner already records these; `bench/reports/README.md` explains why 16 historical reports
   are unusable for lacking them.
6. **Keep the key out of git.** Use an untracked `.env` (see `.env.example`).

## How to run it

```bash
# .env, untracked
OPENAI_API_KEY=sk-...

.venv\Scripts\python.exe bench/agentdojo_runner.py \
  --mode undefended --pipeline agentdojo --attack direct \
  --suite workspace --benchmark-version v1.2.2 \
  --model gpt-4o-mini --force-rerun \
  --out bench/reports/agentdojo-undefended.json

.venv\Scripts\python.exe bench/agentdojo_runner.py \
  --mode capgate --enforcement stage1 --pipeline agentdojo --attack direct \
  --suite workspace --benchmark-version v1.2.2 \
  --model gpt-4o-mini --force-rerun \
  --out bench/reports/agentdojo-capgate.json
```

Add matching `--user-task` / `--injection-task` flags to both commands to scope the matrix.

Note `_stage1_pipeline` in the runner currently defines tool metadata for the **workspace suite
only**; other suites raise. Extending it is straightforward but is authored classification, so
keep it mechanical and reviewable, exactly as `bench/agentdojo_attacks.py::_classify` does.

## What you get for the money

A defensible sentence that does not currently exist:

> *Reduced attack success on AgentDojo from X% to Y% with Z points of utility cost, measured
> across N security cases on a predeclared task matrix.*

That is the difference between "an impressive prototype I have to caveat" and "a result".
