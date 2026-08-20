# Value-level provenance design note

> **STATUS: IMPLEMENTED — 2026-08-20, as designed, with the owner's approval to proceed on
> the recommended answers.** The six steps below all landed; each open question's decision
> is recorded inline. Measured result: with the strict integrity rule on, value-level
> provenance holds 100% containment at a 9.1% false-block rate, versus 54.5% under
> session-global taint — see `bench/reports/scenario-matrix-latest.json` and the corpus
> tests that freeze the comparison.
>
> `AGENTS.md` and `next-instrux/EXECUTION_DIRECTIVE.md` both require the taint engine to be
> designed with the human and implemented in small reviewable pieces. This note existed to
> be argued with before any code changes, and is retained as the design record.

## The problem

[`AgentContext`](../../src/capgate/engine/context.py) holds **one** `influence` label for an
entire session:

```python
def label_for_call(self, provenance_ids: tuple[str, ...]) -> Label:
    return join_labels((self.influence, self.tracker.join(provenance_ids)))

def record_result(self, provenance_id: str, label: Label) -> None:
    self.tracker.record(provenance_id, label)
    self.influence = self.influence.join(label)
```

Every tool result joins into `influence`, and joins are monotonic, so the first
`secret / untrusted` result poisons the session permanently. Every later external-sink call
blocks regardless of whether it touches that data.

In the MCP path it is worse: [`events.py`](../../src/capgate/proxy/events.py) hardcodes
`arg_provenance={}`, so `tracker.join(())` is always bottom and `label_for_call` reduces to
`self.influence` alone. Per-value tracking is not merely imprecise there — it is absent.

**This is safe and useless in the same breath.** It never misses a real attack, and it blocks
so much legitimate work that any measured utility number is meaningless.

## What we are actually trying to know

For a tool call with arguments `{to: ..., body: ...}`, we want the label of the data feeding
*that call* — not everything the session has ever seen.

The obstacle is fundamental: **the model produces arguments as text.** When a planner copies a
value out of a prior `ToolMessage` into an argument, nothing in the framework records that
derivation. The lineage is destroyed by the model, inside the model.

Any design has to answer: *how do we know argument `body` came from tool result #2?*

## Options considered

### A. Content matching — REJECTED

Search argument values for substrings of prior results; join the labels of whatever matches.

Cheap and needs no changes to how agents are written. But it is **unsound in both directions**.
An attacker defeats it with any transformation — base64, reordering, spelling out digits,
translation, "spell the value backwards." And it false-positives on coincidental overlap.

More importantly it is the wrong *shape*: a heuristic scan over attacker-influenced content,
which is exactly the class of defense [`01-the-problem.md`](../../learning/01-the-problem.md)
rejects. A defense whose soundness depends on the attacker not encoding their payload is not a
boundary. **Do not build this**, including as a "supplementary signal" — it would end up in the
enforcement path.

### B. Reference-based propagation — RECOMMENDED CORE

Borrowed from CaMeL (arXiv:2503.18813).

A tool result is stored in a provenance store under an opaque ID, and the planner receives a
**reference** rather than the raw value. When an argument carries a reference, the adapter
resolves it at execution time and joins that value's exact label.

```
read_private()  ->  stored as capgate-ref:7f3a  (label: secret/untrusted)
                    planner sees: {"ref": "capgate-ref:7f3a", "type": "string"}

send_external(payload={"ref": "capgate-ref:7f3a"})
                 ->  adapter resolves the ref
                 ->  argument label = exactly (secret, untrusted, {...})
                 ->  handler receives the real value
```

**Sound.** Lineage is carried structurally, outside the model. The model never has to be trusted
to report where a value came from, and there is no encoding trick — a reference either is one
or it is not.

**Cost:** the planner cannot reason about a value it can only reference. That is the real CaMeL
tradeoff, and it is why CaMeL pairs a privileged planner with a quarantined extractor that *can*
read the data but has no tools.

### C. Read-set scoping — NOT WORTH IT ALONE

Compute the label from the tool results actually visible in graph state at call time, rather
than from a session-wide accumulator.

For a linear conversation this is **identical to today's session influence** — everything seen
so far is exactly everything accumulated so far. It only wins for branching or subgraph state
where some messages are not visible.

Not a fix. Possibly worth folding into option B's fallback later.

### D. Explicit argument labels — already built, keep

[`build_secure_tool_node`](../../src/capgate/adapters/langgraph.py) already requires a trusted
`label_arguments` function for every top-level argument. That handles values entering from
controlled graph input on the first turn. It does not help with values derived from earlier
tool results, which is the case that matters.

## Recommendation: B with a conservative fallback

The design in one sentence:

> **Exact lineage where we can prove it; today's conservative session influence where we
> cannot.**

Concretely, for each top-level argument:

| Argument shape | Label used |
|---|---|
| Resolvable CapGate reference | the referenced value's exact stored label |
| Literal supplied by trusted graph input (via `label_arguments`) | the caller-declared label |
| Anything else — free text the model composed | **session influence** (today's behavior) |

The third row is what keeps this sound. We never guess. If a value's origin is not structurally
proven, it inherits the pessimistic label, exactly as it does now.

The consequence is a system that **degrades gracefully in the safe direction and improves
exactly where the author did the work.** Adopting references for one tool recovers precision
for flows through that tool and changes nothing else. An author who adopts nothing gets today's
behavior — no regression.

This also gives a genuinely honest measurement story: run the scenario corpus in both modes and
report the false-block delta. That comparison *is* a result.

### Why the fallback must stay pessimistic

It is tempting to make unreferenced arguments default to `public/trusted` and rely on references
for everything. That inverts the failure mode: forgetting to use a reference would silently
remove protection, and the failure would be invisible.

Default-deny applies to provenance too. **Unknown lineage is untrusted lineage.**

## Sketch of the change

Small, reviewable pieces, each landing green:

**1. `ValueStore`** — new module, no behavior change. Maps opaque ID → `(Label, value)`, bounded
in size, per-session. Pure data structure with its own unit tests.

**2. Reference type and encoding** — a `capgate-ref:<id>` token plus recognition/parse helpers.
Must be unforgeable *from data*: a raw untrusted string that merely looks like a reference must
not resolve. Simplest sound approach is that only IDs actually minted by the store resolve, and
minted IDs are unguessable — an attacker-supplied `capgate-ref:aaaa` resolves to nothing and
falls back to the pessimistic label.

**3. Resolution in the adapter** — walk the normalized argument object, replace references with
their values, collect their labels. Depth- and count-bounded. Happens *after* schema
normalization and *before* the mediator sees the event, so the receipt records the resolved
call.

**4. Populate `arg_provenance`** — with the IDs the resolution actually used, making
[`label_for_call`](../../src/capgate/engine/pipeline.py) meaningful for real.

**5. Opt-in result storage** — a tool marked as reference-returning stores its result and
returns a reference to the planner. Default off; unmarked tools behave exactly as today.

**6. `AgentContext` mode flag** — `strict_session_influence` (today) vs `value_level`, so the
corpus can measure both.

Each step ships with tests. Steps 1–4 change no observable behavior on their own; step 5 is the
first one that can alter a verdict, and it must land with attack **and** benign scenarios.

## Open questions for review

1. **Reference visibility.** If the planner only ever sees `capgate-ref:7f3a`, a real LLM cannot
   summarise or reason about that data. Do we accept a CaMeL-style split (quarantined reader
   with no tools), or restrict references to values the planner genuinely only needs to *pass
   through* — which covers exfiltration cases but not "summarise this and email the summary"?

   **DECIDED: pass-through only.** It covers the incident classes we care about and needs no
   second model. The cost is kept visible rather than implied away: the corpus carries a
   benign scenario (`email-summary-needs-comprehension`) that is false-blocked in every mode
   because the planner must read the untrusted content raw, and a test asserts it is never
   quietly recovered. No CaMeL parity is claimed.

2. **Nested references.** Resolve inside lists and dicts, or top-level arguments only?
   **DECIDED: nested, depth- and node-bounded** (`resolve_argument`, depth 8, 256 nodes).
   Past the budget, substitution simply stops: an untouched token is an opaque string that
   names nothing downstream, so the bound can only cost utility.

3. **Partial derivation.** If an argument is `"Here is the data: " + ref`, half is proven and
   half is model-composed. **DECIDED: join both.** `ArgumentResolution.joined_label` takes a
   fallback and joins the resolved labels into it; the adapter likewise joins resolved labels
   into the author-declared label. Lineage only ever adds restriction. Embedded substitution
   additionally requires the stored value to itself be a string — a structured value is never
   flattened into composed text.

4. **Does a reference in an argument mean the planner read the value?** It does not, and the
   implementation leans on exactly that: a reference-returning result skips the session
   influence join *because* the planner only ever held the token. Session influence remains
   the control-taint channel — a planner that read untrusted content raw keeps its whole
   session marked, which is why every attack whose injection was actually read stays
   contained.

## What this does not fix

- A model that reads a secret and *retypes it from memory* into free text still falls back to
  session influence. That is correct behavior, not a gap — but it means references improve
  utility, not attack coverage.
- Confidentiality still comes from trusted metadata. Nothing here infers sensitivity.
- No declassification *within this mechanism*. References never lower a label; they only
  report it exactly. The separate, explicitly audited exception landed later the same day —
  see [`DECLASSIFICATION.md`](DECLASSIFICATION.md).

---

Review checklist, closed at implementation:

- [x] Is the pessimistic fallback agreed as non-negotiable? — Yes; unknown lineage falls
      back to session influence everywhere, and influence always joins at decide time.
- [x] Is pass-through-only reference scope acceptable for v1? — Yes; the residual cost is
      measured and frozen rather than hidden (one comprehension-bound benign flow).
- [x] Is the six-step order right, and does each step land green? — Yes; steps 1–4 changed
      no observable behavior, step 5 landed together with attack and benign coverage, and
      step 6 is the `ProvenanceMode` flag the corpus measures both sides of.
- [x] Which open question above changes the answer if we get it wrong? — Question 4. If a
      reference-returning result had *kept* joining influence, no benign flow would have
      been recovered; if session influence had stopped joining into call labels, injected
      sessions could move referenced secrets outward. Both halves are pinned by tests.
