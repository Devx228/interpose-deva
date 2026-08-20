# 12 — Declassification: the priced exception

Chapter [11](11-value-level-provenance.md) ended on a refusal: the flow where the planner
must *comprehend* untrusted content stays blocked, because the influence is real. This
chapter is the one sound way around it — and why the way around had to be an **exception
with a price tag**, not a relaxation.

## The idea, stolen honestly from CaMeL

If the planner reading the email is the problem, don't let the planner read the email. A
**quarantined extractor** — a component that can read the document but has no tools and no
say in what happens next — turns the unbounded untrusted text into a few fields with
**closed domains**:

```
read_email            -> planner gets a reference token, never the text
extract_meeting(ref)  -> the TOOL receives the resolved raw email
                      -> returns {"meeting_moved": true, "new_hour": 15}
                      -> validated against the declared spec
                      -> label drops to the declared public/trusted
send_email("Noted — see you at the moved time.")   -> passes, default AND strict
```

The planner conditions on two facts it can name — a bool and an hour — instead of on text
an attacker wrote.

## Why the label may drop: count the bits

The attacker controls the email, so the attacker chooses *which* in-domain values come out.
That is real influence — but it is **bounded**: `1 + log2(24) ≈ 5.6 bits` per call for the
spec above, and the runtime writes that number into the signed receipt
(`declassified:5.58bits` in the decision labels). The unbounded injection channel became a
metered one.

This is why the domains are only `bool`, bounded `int`, and closed string `enum`
([`taint/declassify.py`](../src/capgate/taint/declassify.py)). A free-length string field
would make the bits number fiction, so it does not exist — and a unit test asserts no such
domain type ever appears in the module.

## The escape, and why failure must be a wall

The obvious attack: a compromised extractor emits the secret (or free text) instead of the
schema. The rule that makes quarantine real is that a nonconforming output is **withheld
entirely** — `flow.declassification_failed`, planner never sees it, session stays healthy.
It is never "fall back to the conservative label", because by then the payload would be in
the planner's context and the quarantine would be theater.

The corpus proves both sides
([`bench/scenarios.py`](../bench/scenarios.py)):

- `email-triage-quarantined-extraction` — the recovered workflow, passing in a value-level
  run under default *and* strict rules;
- `quarantine-escape-through-extractor` — a compromised extractor smuggling a referenced
  secret through an undeclared field; the undefended control breaches, and CapGate contains
  it in **all four** matrix cells, because validation is deliberately not mode-gated.

And the pair scenario `email-summary-needs-comprehension` — the same task done by reading
the email raw — stays false-blocked in every mode, forever. Same workflow, two designs, and
the corpus shows the exact price of each.

## What to say when pushed in an interview

*"So an enum with 2^n variants declassifies n bits — isn't that a hole?"* — It's not a
hole, it's the deal, stated up front: declassification converts an unbounded injection
channel into an audited k-bit channel. k is computed per call and signed into the receipt.
A deployment that can't tolerate k bits of steering must not declare the spec — and a
deployment that conditions a payment on an extracted field is spending those bits whether
or not anyone reads the receipt.

*"Who reads the email in production?"* — In the corpus, a scripted extractor, because the
enforcement claim must not depend on a model. Live, it's a tool-less LLM
(`examples/quarantine_demo.py`); a lying one can only lie inside its declared domains.

## Where each piece lives

| Piece | File |
|---|---|
| Domains, spec, validation, bits | [`taint/declassify.py`](../src/capgate/taint/declassify.py) |
| Label swap + receipt labels | [`engine/pipeline.py`](../src/capgate/engine/pipeline.py), [`engine/mediator.py`](../src/capgate/engine/mediator.py) |
| YAML `declassify:` grammar | [`config.py`](../src/capgate/config.py) |
| Recovered flow + escape attack | [`bench/scenarios.py`](../bench/scenarios.py) |
| Design record | [`docs/design-notes/DECLASSIFICATION.md`](../docs/design-notes/DECLASSIFICATION.md) |

---

Previous: [11 — Value-level provenance](11-value-level-provenance.md) ·
[Back to the index](README.md)
