# Audited, bandwidth-bounded declassification

> **STATUS: IMPLEMENTED — 2026-08-20.** Written immediately before implementation, in the
> same session, under the owner's standing direction to proceed; recorded so the reasoning
> can be argued with after the fact, exactly like
> [`VALUE_LEVEL_PROVENANCE.md`](VALUE_LEVEL_PROVENANCE.md).

## The residual this exists for

Value-level provenance left exactly one benign class unrecoverable, on purpose:
**comprehension-bound flows**. When the planner must read untrusted content raw to do its
job, its context is genuinely influenced, and every later call is conservatively tainted.
The corpus keeps `email-summary-needs-comprehension` false-blocked in every mode to make
that cost visible.

The sound fix is known from CaMeL: don't let the planner read the content at all. Let a
**quarantined extractor** — a component that can read the data but has no tools and no say
in control flow — turn the unbounded untrusted text into a few **schema-bounded fields**,
and let only those fields reach the planner.

The question this note answers: *under what conditions may the extraction's label be lower
than the join rule would produce?* Because without a label drop, quarantine is pointless —
`propagate_tool_result` would stamp the extraction `internal/untrusted` and the reply would
block exactly as before.

## The principle: declassification is a measured channel, never an exception

Monotonic joins stay the default. A label may be lowered only when **all** of these hold:

1. **Declared, per tool.** The tool's trusted metadata carries an explicit
   `declassification` spec: the exact output fields and the closed domain of each. There is
   no ambient or implicit declassification anywhere.
2. **Validated at the boundary.** The runtime parses the tool's actual output and checks it
   against the spec — field set equality, domain membership, nothing extra, nothing free-form.
   Validation failure does not degrade to the conservative label: the result is **blocked**
   and the planner never sees it, because a nonconforming extraction is precisely a
   quarantine escape attempt.
3. **Bandwidth-accounted.** The information the attacker can push through a conforming
   extraction is at most `Σ log2(|domain_i|)` bits — an attacker who controls the email can
   pick *which* of the allowed values comes out, and nothing else. That number is computed
   per call and recorded in the decision labels, which are part of the signed receipt. The
   audit trail therefore shows exactly how many attacker-influenceable bits were released,
   and when.

## What the lowered label may claim

- **Confidentiality** may drop to the declared level. A 5-bit extraction of a private email
  is not the email.
- **Integrity** may be declared `trusted` — and this is the deliberate, defensible edge.
  "Trusted" here does not mean the attacker had no influence; it means the influence is
  **bounded to k receipted bits** through a channel that cannot carry instructions, code,
  or the payload itself. The residual is stated plainly: an attacker can steer any decision
  the planner conditions on those k bits. If a deployment cannot tolerate k bits of
  steering, it must not declare the spec. The alternative — leaving integrity untrusted —
  would make declassification useless under `--strict-integrity`, which is exactly the mode
  where precision matters most.

## Domains, v1

`bool`, bounded `int` ranges, and closed `enum`s of strings. **No free-length strings** —
a string is an unbounded channel and would turn the bits accounting into fiction. If a
field's honest domain cannot be enumerated, it is not declassifiable.

## What this does not permit

- No declassification of a value the spec does not cover — unknown fields, wrong types,
  out-of-domain values, missing fields all block the result outright.
- No lowering of *inputs*: the referenced raw value keeps its full label everywhere else;
  only the validated extraction output carries the declared label.
- No model in the enforcement path. The extractor may be an LLM (the corpus uses a scripted
  one; `examples/quarantine_demo.py` shows a live one), but the *validation and labeling*
  are ordinary code either way. A lying extractor can only lie inside its k-bit domain.
- No silent failure mode: a schema violation is a BLOCK with its own rule id
  (`flow.declassification_failed`), receipted like every other verdict.

## Interaction with value-level provenance

Designed to compose: the untrusted document enters as a **reference** (the planner never
reads it), the extractor receives the resolved raw value at execution time, and only the
validated, declassified fields return to the planner raw. Session influence stays clean at
every step, so the follow-up reply passes under both default and strict rules. The corpus
encodes this as `email-triage-quarantined-extraction`, and keeps the raw-comprehension
variant false-blocked forever alongside it — declassification recovers flows an author
*explicitly bounded*, never flows in general.

## The attack the tests must contain

The obvious escape: a compromised extractor emits the secret (or free text) instead of the
schema. The corpus attack `quarantine-escape-through-extractor` does exactly that, with an
undefended control proving the smuggled payload reaches the sink without CapGate. Under
CapGate the nonconforming output blocks at validation, the planner never holds the payload,
and the follow-up send carries nothing.
