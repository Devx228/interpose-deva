# EXECUTION DIRECTIVE — Build capgate As Far As Possible (All Stages)

> **Read this first, then work from `IMPLEMENTATION_SPEC.md` (all four stages) with `RESEARCH.md` and
> `AGENT_RUNTIME_BUILD_PLAN.md` as reference.** This file governs *how you work*. The spec governs *what you build*.
> Build aggressively across all stages, in order, getting as far as genuinely possible. Report exactly where you land.

---

## The One Rule That Overrides Everything

**You report real results or you report failure. You NEVER report a number you did not produce by actually
running the harness.** A hardcoded, stubbed, mocked, estimated, or "expected" benchmark number is the single
worst thing you can produce on this project — worse than an unfinished stage, worse than a failing test.

If a benchmark is not yet runnable (no API access, harness not wired, stage incomplete), the correct output is
**"NOT YET MEASURED — <reason>"**, not a placeholder value. If a measured number misses its target, the correct
output is the **real number + a diagnosis + the next fix** — never a fudge to make it look like it passed.

The benchmark target numbers in the spec/research (e.g. ASR <5%, ~40% baseline, CaMeL 77%, Progent 1%) are
**targets to reproduce, NOT facts to assert**. Do not write them as if your system achieved them. Do not
`assert asr < 0.05` against a value you didn't compute. Reproduce the baseline first by actually running it.

---

## How To Work (maximal but honest)

1. **Work the full spec, all four stages, in order.** Do not stop at an arbitrary stage boundary if time/ability
   remains — keep going. But do not *skip ahead* past a broken foundation either. Order exists because each stage
   depends on the last.
2. **Honor the Exit Gates as measurement checkpoints, not as permission to fake.** At each gate, run the real
   check. If it passes for real, advance. If it doesn't, record the real result and either fix it or, if blocked,
   document the blocker precisely and continue on work that doesn't depend on it.
3. **Design-with-human modules — do not autopilot:** the taint propagation engine (Stage 1) and the sandbox
   (Stage 2). For these, FIRST write a short design note (label lattice / isolation model + tradeoffs) into
   `docs/design-notes/`, THEN implement in small, reviewable, well-tested pieces. These are the novel core; opaque
   mega-implementations here are a failure even if they "work."
4. **Deterministic enforcement, never detection-as-primary-defense.** If you catch yourself writing a regex /
   keyword / LLM-judge whose job is to "spot bad prompts," stop — that is the rejected approach. Enforcement is
   taint + capability + flow rules at sinks.
5. **Every feature change re-runs the harness** (once the harness is live) and records its real effect on
   ASR/utility in `bench/reports/`. No silent changes to the enforcement path.
6. **Fail-closed everywhere.** Any error in the decision pipeline → BLOCK. Deny-by-default. No raw secrets in
   receipts (hash them).
7. **Test as you go.** Unit tests per module; every known attack (AgentDojo security cases, whatsapp-takeout
   rug-pull, EchoLeak-style flow) that you successfully block becomes a frozen regression test. A blocked attack
   without a regression test is incomplete.

---

## Critical-Path Dependencies (surface these IMMEDIATELY, don't silently stub them)

These determine how far you can actually get. If any is missing, say so loudly at the top of your status report
— do not paper over it:

- **LLM API access** for running AgentDojo (which provider/model? rate limits? cost budget?). Without this, the
  baseline and all ASR/utility numbers are **unmeasurable** — report that plainly, build everything else, and
  leave the harness ready to run the instant access exists.
- **Sandbox runtime** (gVisor / Firecracker / Kata) actually installed and functional in the environment. If it
  can't be installed here, the sandbox stage cannot be truly validated — implement against the interface,
  document what's untested, and DO NOT claim isolation you couldn't verify.
- **AgentDojo + Invariant mcp-injection-experiments** installable and runnable. Confirm before relying on them.

---

## Required Status Report (produce this at the end, and at each stage boundary)

Output a `STATUS.md` that states, with zero spin:

```
## capgate build status — <date/time>

### Stages
- Stage 0: <DONE / PARTIAL / BLOCKED>  — <one line of real evidence>
- Stage 1: <DONE / PARTIAL / BLOCKED / NOT STARTED> — <real evidence>
- Stage 2: <...>
- Stage 3: <...>

### Measured numbers (ONLY real runs; "NOT YET MEASURED" otherwise)
- AgentDojo undefended baseline: ASR=<x or NOT YET MEASURED>, utility=<y or NOT YET MEASURED>
- AgentDojo through capgate:      ASR=<x or NOT YET MEASURED>, utility=<y or NOT YET MEASURED>
- Adaptive ASR:                   <x or NOT YET MEASURED>
- Each number must link to the report file + command that produced it.

### Blockers (what stopped real measurement/validation)
- <e.g. "No LLM API key wired — harness ready at bench/agentdojo_runner.py, runs on `make bench` once key set.">

### What is real vs scaffolded
- Genuinely working + tested: <list>
- Interface-only / untested (could not validate in this env): <list>

### Honest next steps to hit each unmet Exit Gate
- <ordered, specific>
```

**If you cannot produce a real number, the report says so. That is a success of honesty, not a failure of
effort.** A report full of "NOT YET MEASURED" with solid, tested scaffolding is a GOOD outcome. A report with
confident numbers you didn't actually measure is sabotage.

---

## What "as far as possible" correctly looks like after hard work

- Stage 0 truly done: proxy forwards losslessly, receipts sign+chain+replay, AgentDojo baseline **actually run**.
- Stage 1 substantially real: taint engine + capability + trifecta enforcing, with a **real measured** ASR/utility
  (even if it misses target — report the real value and the diagnosis).
- Stage 2–3: implemented against interfaces as far as the environment allows, with untested/unvalidated parts
  **explicitly labeled** as such, and a precise list of what's needed to validate them.

That is a defensible, real, week-of-work result. Do not trade it for a fake complete one.
