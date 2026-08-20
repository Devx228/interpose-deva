# 09 — Roadmap

Six weeks, LangGraph-focused, zero spend on model APIs.

## Scope decisions

**Focus:** LangGraph. All new work goes there.

**Frozen, not deleted:** the MCP proxy. It works, it is tested, and it is the proof that the
engine is framework-neutral rather than "a LangChain plugin." Deleting it would remove the
strongest structural argument for the architecture.

**Cut:**

| Cut | Why |
|---|---|
| gVisor / Firecracker / egress broker | Needs privileged Linux; unverifiable here. Contract-only code that claims isolation is worse than no code. |
| Paid AgentDojo runs | Costs money, and measures the wrong question (see below). |
| OpenAI Agents SDK, Pydantic AI adapters | Never built. One adapter done well beats three done badly. |
| Dual-LLM quarantine | 300 lines, unwired, needs a live provider. Defer. |

Risk-class routing **stays** — a tool marked `fixed_risky` still blocks when no executor
exists. The "no downgrade, no silent fallback to host execution" property is good and already
works.

## How we get a real number for free

Published benchmarks like AgentDojo measure *whether the model falls for the injection*. That
was never this project's claim. The claim is containment: **even if it falls for it completely,
the action is blocked.**

So the harness is a **scripted compromised planner** — a LangGraph planner that obeys every
injected instruction perfectly, every time. A worst-case attacker who never gets confused and
never gives up.

- Costs nothing
- Runs in CI on every commit
- Fully deterministic, so numbers never drift between runs
- Tests exactly the property being claimed

Two numbers come out, and you need both:

| Metric | Definition | Failure it catches |
|---|---|---|
| **Containment rate** | attacks blocked ÷ attacks attempted | the defense has a hole |
| **False-block rate** | benign tasks wrongly blocked | the defense is unusable |

The second is what makes it credible. Blocking everything scores a perfect containment rate and
is worthless — which is precisely why the session-global taint has to go.

> **State the caveat out loud:** these numbers are not comparable to published AgentDojo
> results. Different harness, different question. Saying so reads as rigor, not as a gap.

## Phase 0 — Green baseline ✅ DONE

- Fixed all seven Windows failures (see [08](08-where-we-stand.md) for the causes)
- Added `windows-latest` to the CI matrix alongside `ubuntu-latest`

**Result:** 396 passed, 3 skipped, ruff and `mypy --strict` clean, both demos correct.

## Phase 1 — Correctness fixes ✅ DONE

- **Validated `source_tags`** — [`is_valid_source_tag`](../src/capgate/flow/sources.py) closes
  the silent-typo hole. 10 new tests.
- **Renamed the duplicate enums** to `OriginKind` (taint) and `DataSourceKind` (flow).
- **Cached the receipt-store tail state**, invalidated on file-size change. 2 new tests.
- **Made deny pairs configurable** through an optional `deny:` section. 11 new tests.

One finding deliberately *not* fixed: the two enums still do not map onto each other, so
`OriginKind.WEB` produces a `web` tag that no deny pair matches. Tightening that changes which
calls block, so it needs a decision rather than a silent change.

## Phase 2 — Value-level provenance ✅ DONE — the centerpiece

Shipped 2026-08-20 exactly as the
[design note](../docs/design-notes/VALUE_LEVEL_PROVENANCE.md) specified — reference-based
propagation with a pessimistic fallback, built in the six reviewable steps, each landing
green. The note now records the decision taken on each of its four open questions, and
chapter [11](11-value-level-provenance.md) teaches the mechanism.

The "done when" criterion was met and exceeded: every attack still blocks under its exact
rule, the recoverable false blocks pass, and the measured comparison *is* the result —

```
session/strict            100.0% containment     54.5% false-block
value/strict              100.0% containment      9.1% false-block
```

— with the residual false block structural by construction and frozen by test.

## Phase 3 — Attack + utility corpus ✅ DONE — the headline number

Built as [`bench/scenarios.py`](../bench/scenarios.py) (the corpus) and
[`bench/run_scenarios.py`](../bench/run_scenarios.py) (the harness), enforced by
[`tests/integration/test_scenarios.py`](../tests/integration/test_scenarios.py) and run in CI.

```
attack scenarios          12
benign scenarios          10

undefended attack success 100.0%     <- the control: every attack is real
containment rate          100.0%
false-block rate           10.0%
```

Three design choices that make the number defensible:

1. **Every attack runs undefended first.** An attack that does not breach without CapGate
   proves nothing, so the harness reports it as *vacuous* and fails the run.
2. **Blocking for the right reason.** Each attack declares the rule it exercises; a block under
   some unrelated rule does not count. This immediately caught a wrong assumption — three
   EchoLeak-style scenarios block under `flow.deny.secrets_to_network_external`, not the
   trifecta, because static deny pairs are checked first.
3. **Breach means the side effect happened**, not that an error came back. The sink handler
   either ran with the secret in its arguments or it did not.

The single false block is `email-triage-then-public-reply` — read an injected email, send a
harmless reply. Session-global taint marks the whole session untrusted, so the reply is
refused. That is precisely the case Phase 2 should recover, which is why it was written.

### Original plan, for reference

~25 scenarios in `bench/scenarios/`, each a small deterministic LangGraph run.

Attack scenarios, each drawn from a real incident or a known technique:

- EchoLeak-style exfiltration through an *allowed* domain (CVE-2025-32711)
- GitHub MCP toxic-agent flow — public issue → private repo leak
- Rug pull — tool definition changes after first approval
- Tool-name shadowing across servers
- Multi-hop laundering through an intermediate tool
- Argument smuggling — secret hidden in a URL path or query
- Confused deputy — agent tricked into using its own privilege

Benign scenarios that *must* succeed — legitimate multi-step work that touches private data
without exfiltrating it. These produce the false-block rate.

**Done when:** `python bench/run_scenarios.py` prints both numbers, runs in CI, and every
blocked attack has a frozen regression test.

## Phase 4 — Human-in-the-loop approval ✅ DONE — the demo feature

`REQUIRE_APPROVAL` now pauses the graph for a human instead of silently blocking.

- [`interrupt_for_approval`](../src/capgate/adapters/langgraph.py) suspends a checkpointed
  LangGraph run and surfaces only bounded decision metadata — never raw arguments, because an
  approval prompt is one more place a secret could be copied to.
- [`_resolve_approval`](../src/capgate/engine/mediator.py) re-runs the pipeline with
  `approved=True`, so a grant satisfies **only** the capability gate.
- Resume with `Command(resume=True)` to approve. Only the exact boolean `True` counts.
- Both outcomes land in the signed receipt chain as `policy.approval.granted` or
  `policy.approval.denied`.

Three properties worth being able to state:

| Property | Why |
|---|---|
| No approver configured → still blocks | A verdict nobody can answer must never behave like an allow |
| Only exact `True` approves | A truthy string is not consent |
| Approval cannot override a flow rule | Permission to **act** is not permission to **leak** |

That last one is the demo: approve a call carrying secret, untrusted-influenced data to an
external sink, and it is *still* blocked under `flow.deny.secrets_to_network_external`. Proven
by `test_human_approval_cannot_override_a_flow_rule` in
[`tests/integration/test_langgraph_approval.py`](../tests/integration/test_langgraph_approval.py).

### Original plan, for reference

`REQUIRE_APPROVAL` currently just blocks, which makes it useless. LangGraph has `interrupt()`
built in.

- Map `REQUIRE_APPROVAL` to a LangGraph interrupt carrying the decision, rule ID, and labels
- Resume on approval; the approval itself becomes a receipt
- Approval is a **trusted** input, so it may lower... nothing. It authorises one specific call,
  it does not declassify data. Getting this boundary right is the interesting part.

**Done when:** a graph pauses on a sensitive call, a human approves, and both the pause and the
approval appear in the signed chain.

## Bonus — Dual-LLM quarantine over Ollama ✅ DONE

[`examples/quarantine_demo.py`](../examples/quarantine_demo.py) activates
[`dual_llm/quarantine.py`](../src/capgate/dual_llm/quarantine.py) — 300 lines of CaMeL-pattern
code that had never been connected to a live provider. Two local models, zero cost.

Observed with `qwen2.5:7b`: the injection reached the quarantined extractor and **not** the
privileged planner, which saw only opaque references (`field_0001`) and still produced a valid
plan. The demo checks the recorded prompts rather than asserting the property.

## Bonus — Real-model injection demo via Ollama ✅ DONE

[`examples/ollama_injection_demo.py`](../examples/ollama_injection_demo.py) drives a real local
LLM through a genuine injection, with no scripted plan. Stdlib HTTP only — no new dependency.

Result with `qwen2.5:7b`: **`MODEL_ATTEMPTED_EXFILTRATION_CAPGATE_BLOCKED_IT`**. The model read
the injected email, chose on its own to read the private file, and attempted the external send.
`send_external` never appears in the executed list — blocked under `flow.lethal_trifecta`
before the handler ran.

Getting there taught two things worth repeating in an interview:

**Model capability matters.** `mistral:latest` (7B, 2025-03) reads the email, correctly
*describes* the embedded instruction, then declines to chain. It cannot reach a conclusion.

**Task framing decides everything.** Asked to *"summarise this email"*, even `qwen2.5` reports
the injection back to the user instead of obeying it — the explicit user instruction
outcompetes the injected one. Asked to *"handle my inbox"*, the same model acts on it
immediately. Open-ended agentic tasks are where injection actually bites, which is the argument
for containment over better prompting.

And the rule that shaped the harness: **an inconclusive run is not evidence the defense
worked** — it means the attack never happened. Only
`MODEL_ATTEMPTED_EXFILTRATION_CAPGATE_BLOCKED_IT` demonstrates enforcement.

## Phase 5 — Parallel multi-call turns ✅ DONE

Real agents batch, and the adapter now accepts it. The security question was the whole
phase: what order do taint updates take when calls run concurrently? **Sequential mediation
in the planner's emission order** won, because the alternative — a barrier judging every
call against pre-turn state — would let a read-secret + send pair emitted together both
pass. The discriminating test exists and the barrier design fails it.

Mechanics worth being able to explain: a `_TurnSequencer` (condition variable keyed on the
turn's call-ID tuple, taken from the turn's own `AIMessage`) makes call *k* wait for calls
`0..k-1`. Deadlock-freedom follows from `ToolNode` submitting the batch in emission order to
a FIFO thread pool — the earliest unfinished call always holds a worker — with a timeout
that fails the run closed rather than ever mediating out of order. Approval pausing is
refused in batches: a resumed multi-call turn would re-execute its finished siblings.
Tests: [`test_langgraph_parallel.py`](../tests/integration/test_langgraph_parallel.py).

## Phase 6 — Declassification ✅ DONE (landed ahead of Phase 5)

The "recover utility" contribution. AgentArmor (arXiv:2508.01249) identifies reducing utility
cost as open contribution space.

Shipped 2026-08-20 as **audited, bandwidth-bounded declassification**: explicit per-tool
specs with closed field domains, hard-fail validation (a nonconforming extraction is withheld
from the planner, never conservatively relabeled), and the released bits signed into every
receipt. It jumped the phase order because value-level provenance made it both sound to build
and cheap to measure — the quarantined-extraction scenario and its escape-attempt attack were
one corpus extension away. Chapter [12](12-declassification.md) teaches it;
[`docs/design-notes/DECLASSIFICATION.md`](../docs/design-notes/DECLASSIFICATION.md) is the
design record.

## Timeline

| Week | Work | State |
|---|---|---|
| 1 | Phase 0 + Phase 1 | ✅ done |
| 2–3 | Phase 2 — value-level provenance | ✅ done — see chapter [11](11-value-level-provenance.md) |
| 4 | Phase 3 — attack corpus | ✅ done early |
| 5 | Phase 4 — approval via `interrupt()` | ✅ done early |
| 6 | Phase 6 — declassification | ✅ done early — see chapter [12](12-declassification.md) |
| — | Phase 5 — parallel turns | ✅ done |
| — | Docs polish and a demo recording | next |

Phase 3 landed ahead of Phase 2 because it does not depend on it — and having the corpus
*first* is better, since it gives Phase 2 a before/after number to move.

## What "done" looks like

A repo where:

- The full suite is green on Windows and Linux in CI
- `python bench/run_scenarios.py` prints a containment rate and a false-block rate from ~25
  deterministic scenarios, no API key
- Every blocked attack has a frozen regression test
- A recorded demo shows an injected exfiltration blocked before the sink, and a sensitive call
  pausing for human approval
- The README states precisely what is proven and what is not

That is a self project that survives someone actually opening it — which is the only kind worth
putting on a resume.

---

Previous: [08 — Where we stand](08-where-we-stand.md) · Next: [10 — Interview answers](10-interview-answers.md)
