# 11 — Value-level provenance

The single biggest weakness in [08](08-where-we-stand.md) was session-global taint: one
untrusted read marks the whole session, so a rule that wants precision has none to work with.
This chapter is how that got fixed — and, just as important, what the fix deliberately does
not do.

## The measurement that motivated it

Two corpus rules, two numbers each (`python bench/run_scenarios.py --matrix`):

| Provenance | Rules | Containment | False-block |
|---|---|---|---|
| session-global | default | 75% | 18.2% |
| session-global | `--strict-integrity` | 100% | 54.5% |
| value-level | default | 75% | 9.1% |
| value-level | `--strict-integrity` | **100%** | **9.1%** |

Under session-global taint you must choose: miss the destructive-action class (default), or
refuse half the legitimate corpus (strict). The two headline critiques — "cover more" and
"block less" — pull against each other **because they share one cause**. Value-level
provenance removes the cause, and the bottom row is both critiques answered at once.

## Why the obvious fix is unsound

"Just check whether the argument *contains* the secret" is the obvious fix, and it is wrong
in both directions. An attacker defeats substring matching with base64, translation, or
"spell it backwards" — and it false-positives on coincidence. Worse, it is a heuristic scan
over attacker-influenced content, which is the exact class of defense
[chapter 01](01-the-problem.md) rejects. The design note evaluated and rejected it;
[`docs/design-notes/VALUE_LEVEL_PROVENANCE.md`](../docs/design-notes/VALUE_LEVEL_PROVENANCE.md)
records the reasoning.

The fundamental obstacle: the model produces arguments as *text*. When a planner copies a
tool result into an argument, the derivation happens inside the model, and nothing records
it. Any sound design must carry lineage **outside** the model.

## The mechanism: references

Borrowed from CaMeL (arXiv:2503.18813). A tool marked `returns_reference` does not hand the
planner its result. Instead:

```
read_secret()  ->  value stored in ValueStore under capgate-ref:3f9c...   (label: secret/trusted)
                   planner receives: "capgate-ref:3f9c..."                (an opaque token)

send_external(payload="capgate-ref:3f9c...")
               ->  adapter resolves the token back to the value
               ->  the argument's label is EXACTLY the stored label
               ->  decision runs on that label; the handler gets the real value only on ALLOW
```

Three properties do all the security work
([`src/capgate/taint/values.py`](../src/capgate/taint/values.py)):

1. **Unforgeable.** Tokens come from `secrets.token_hex`. A `capgate-ref:` string an attacker
   plants in a document resolves to nothing — it is not "detected", it simply names no value.
2. **Fail-pessimistic.** Unknown token, evicted entry, over-budget nesting: resolution just
   doesn't happen, and the argument falls back to session influence. Unknown lineage is
   untrusted lineage.
3. **Additive.** A resolved label *joins into* the declared label, never replaces it. Partial
   composition (`"data: " + ref`) keeps both the reference's exact label and the pessimistic
   base.

## The subtle part: influence

Here is the question that decides whether the whole design is sound, and it is worth being
able to answer cold in an interview:

> When a reference-returning tool's result is stored, why is it sound to *skip* the session
> influence join?

Because influence models what the planner has **seen**. The planner received a random token,
which carries zero information about the value. A value the planner never saw cannot have
steered its next decision (control), and cannot be retyped from memory into free text (data).
Skipping the join is not a relaxation — it is the label catching up to the truth.

And the converse, which keeps attacks contained: **session influence still joins into every
call's label** ([`label_for_call`](../src/capgate/engine/context.py)). A planner that read an
injected email *raw* has a genuinely influenced context, so when it passes a referenced secret
outward the decision label is `exact-secret-label ⊔ untrusted-influence` = secret + untrusted
at an external sink — the trifecta fires. The integration test
[`test_langgraph_value_provenance.py`](../tests/integration/test_langgraph_value_provenance.py)
pins both halves: the injected session is blocked, the clean session passes the same token
through, and the secret marker appears in no planner-visible message either way.

## What it refuses to fix

One benign scenario, `email-summary-needs-comprehension`, is false-blocked in **every** mode,
on purpose. The planner must read the untrusted email raw to summarise it, so its context is
genuinely influenced, and the external reply is refused. No amount of provenance precision can
recover it, because the influence is real — recovering it soundly needs a quarantined reader
(a second model that can read but has no tools) or explicit declassification. Neither exists
here, and a test asserts the scenario is never quietly recovered: if it ever passes, something
has started unsoundly declassifying planner context.

That is the pattern this project keeps returning to: when a limit is structural, measure it,
freeze it, and say what would actually remove it — never paper over it.

## Where each piece lives

| Piece | File |
|---|---|
| Store, tokens, resolution walker | [`taint/values.py`](../src/capgate/taint/values.py) |
| `ProvenanceMode`, influence skip | [`engine/context.py`](../src/capgate/engine/context.py) |
| `returns_reference`, reference minting | [`engine/pipeline.py`](../src/capgate/engine/pipeline.py) |
| `resolve_arguments`, outcome reference | [`engine/mediator.py`](../src/capgate/engine/mediator.py) |
| Adapter: resolve in, token out | [`adapters/langgraph.py`](../src/capgate/adapters/langgraph.py) |
| Scenario encoding + 2×2 harness | [`bench/scenarios.py`](../bench/scenarios.py), [`bench/run_scenarios.py`](../bench/run_scenarios.py) |
| Frozen comparison | [`tests/integration/test_scenarios.py`](../tests/integration/test_scenarios.py) |

Boundaries that still hold: the precision is opt-in per tool, pass-through only, LangGraph
path only (the MCP proxy always runs session-global), and everything undeclared falls back to
exactly the old behavior.

---

Previous: [10 — Interview answers](10-interview-answers.md) ·
[Back to the index](README.md)
