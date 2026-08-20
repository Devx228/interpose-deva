# 10 — Interview answers

Questions you will actually be asked, and how to answer them. Read these once you understand
[01](01-the-problem.md) through [07](07-code-walkthrough.md) — they are compression, not a
substitute.

## The 60-second pitch

> An AI agent that can read private data and also send email is one convincing sentence away
> from mailing your secrets to a stranger. That sentence can arrive inside a document the user
> asked the agent to read, and language models have no architectural boundary between
> instructions and data — so you cannot reliably detect it.
>
> So I assume the model is already compromised, and enforce at the tool boundary instead. Every
> tool call passes a deterministic gate that checks two independent things: a capability policy
> for what the agent may do, and an information-flow rule for what the data may do. If private
> data influenced by untrusted content tries to reach an external sink, the call is blocked
> before the handler runs — and every decision is written to a signed, hash-chained audit log.
>
> It's a research prototype. I measured containment against a worst-case scripted attacker, not
> published benchmark numbers, and I'm explicit about what that does and doesn't prove.

That last sentence does more work than the rest combined.

---

## "Why not just detect the injection?"

Because detection is a classifier, and classifiers lose to adaptive attackers. *The Attacker
Moves Second* took twelve published defenses reporting near-zero attack rates and re-attacked
them adaptively — they went above 90% attack success, 100% under human red-teaming.

Structurally, a model has no boundary between instruction and data; there's only the next
token. SQL injection is solvable because prepared statements give data a channel that cannot be
parsed as code. No such channel exists in a prompt.

Detection can be a useful extra signal. It cannot be the authorization boundary. I enforce on
the action, so the control holds even when the malicious instruction gets through.

## "Why both capabilities and taint? Isn't one enough?"

They answer different questions and each alone leaves a hole.

Capabilities: *may this agent send email?* Taint: *may it send **this data**?*

Concretely — an email assistant legitimately needs send permission. That's its job. So
capabilities say ALLOW and the exfiltration walks straight through. Conversely, taint alone
can't express "this agent should never touch a shell," because at the start of a session
nothing is tainted yet.

|  | Capabilities alone | Taint alone |
|---|---|---|
| Email agent exfiltrating | allowed — sending is its job | blocked |
| Agent shelling out, nothing tainted | blocked — no `exec:shell` | allowed |

## "Walk me through the taint lattice."

Three parts: confidentiality (`public < internal < secret`), integrity (`trusted < untrusted`),
and a set of source tags.

Joining takes the more restrictive of each: max confidentiality, untrusted if either input is,
union the tags. So `secret/trusted` joined with `public/untrusted` gives `secret/untrusted` —
which is exactly the dangerous state.

The property that matters is monotonicity: a join can never lower confidentiality, restore
trust, or drop a tag. So there's no way to launder data. Summarising a secret doesn't make it
public; copying an untrusted value doesn't make it trusted. There's no operation in the system
that moves a label downward, which means an attacker can't construct one.

It's commutative, associative, and idempotent — a least upper bound on a lattice — so the order
values combine in can't change the result either.

## "What's the lethal trifecta?"

Private data access, untrusted content exposure, and external communication. Any two are
survivable. All three on one path is exfiltration waiting to happen.

My labels already carry the first two and the tool metadata carries the third, so the rule is
three conditions and an `and`. When it fires the tool handler is never called — I test the side
effect, not the return value, because "an error came back" proves nothing about whether the
email went out.

## "What does fail-closed cost you?"

Availability, and it's a real cost. Missing metadata blocks legitimate work. Broken receipt
storage blocks legitimate work. Conservative taint blocks legitimate work.

That's why I measure a false-block rate alongside containment. Blocking everything gives a
perfect containment score and is worthless — a security control people switch off provides zero
security. Getting that tradeoff right is most of the engineering.

## "What's the weakest part of your system?"

Taint precision. Session influence was a single label for the whole session, so the first
secret-and-untrusted result poisoned everything after it — every later external call blocked
whether or not it touched that data. Safe, because it over-approximates, but it blocks real
work.

Value-level provenance was the fix and it's the main thing I built. I kept the old mode
available so I could measure the difference.

I'd also flag that receipts have no external anchor — I can detect modification of retained
entries, but not tail deletion.

*(Naming your own weakness before being asked is the strongest move available in a technical
interview. It signals you've actually thought about the system rather than just built it.)*

## "What does the signature actually prove?"

That these exact bytes were signed by the holder of that private key and haven't changed since.

Not that the signer was uncompromised. Not that the decision was correct — a perfectly signed
receipt can record a terrible policy decision.

And the chain has a specific limit: it proves retained entries weren't modified, but tail
deletion is invisible. Chop off the last three receipts and the rest verifies fine. Fixing that
needs an external anchor — publishing the chain head somewhere I don't control.

## "Why hash the arguments instead of storing them?"

Because an audit log of exfiltration attempts containing the exfiltrated data is its own
breach — you've built a searchable index of every secret the agent touched.

The hash still lets me prove two calls were identical or correlate with an external event. The
demo puts a synthetic marker through the system and asserts it appears nowhere in the log.

Caveat: a hash isn't encryption. Low-entropy values are brute-forceable, so receipt access
stays sensitive.

## "How do you know it works?"

A deterministic scenario suite. The planner is scripted to obey every injected instruction
perfectly — a worst-case attacker who never gets confused. Around 25 scenarios drawn from real
incidents: EchoLeak-style exfil through an allowed domain, the GitHub MCP toxic-agent flow, rug
pulls, multi-hop laundering.

Two numbers: containment rate and false-block rate. No API key, runs in CI, fully deterministic
so the numbers don't drift.

I deliberately didn't run AgentDojo. It measures whether the model falls for the injection —
that's a model property that changes every release. My claim is that enforcement holds when the
model is fully adversarial, so I measured that directly. The tradeoff is that my numbers aren't
comparable to published results, and I'd say so upfront.

## "Why is the adapter so thin?"

Because if security logic lives in the adapter, the framework becomes the security boundary,
and you re-implement everything for the next framework — with different bugs each time.

The adapter translates a LangGraph tool call into a neutral event and translates the outcome
back. That's it. The proof it worked is that the same engine also drives an MCP proxy without
either knowing about the other.

## "You said session taint was your weakness. What did you do about it?"

Fixed it where it can be fixed soundly, and measured the fix.

The problem: one influence label per session, so one untrusted read poisoned everything after
it. That made my strict integrity rule — which closes the destructive-action gap — cost half
the benign corpus. The two critiques of the project pulled against each other because they
shared a cause.

The fix is borrowed from CaMeL: pass-through tool results are stored behind unforgeable random
tokens, and the planner receives the token instead of the value. Lineage travels structurally,
outside the model — no encoding trick can launder it, because a token either names a stored
value or it names nothing. When a token appears in a later argument, I resolve it and the
argument's label is exactly the stored label. Result: 100% containment with the strict rule at
a 9% false-block rate, down from 54%. Both numbers, same corpus, frozen as tests.

The two follow-up questions I'd expect, answered:

*Why is it sound to skip the session influence join for referenced results?* Because influence
models what the planner has seen, and the planner only ever saw a random token. A value it
never saw can't have steered it and can't be retyped from memory. And the converse holds — if
the planner did read untrusted content raw, influence still joins into every call, which is
why an injected planner passing a referenced secret outward is still blocked.

*What can't it do?* The planner can't read a referenced value, so any task that needs
comprehension of untrusted content still inherits session taint. I keep one benign scenario
false-blocked in every mode to make that cost visible, with a test asserting it's never
quietly recovered. For the cases where the *task* can be done without free-text comprehension,
I built the sound path: a quarantined extractor with audited, bandwidth-bounded
declassification — the extraction's fields have closed domains, a nonconforming output is
withheld outright, and every conforming call's attacker-choosable bits are signed into the
receipt. The corpus has both the recovered workflow and the escape attempt, contained in
every mode.

## "What would you do with three more months?"

External anchoring for the receipt chain — tail deletion is my biggest audit gap.

Then explicit declassification. Right now labels only get more restrictive, which is safe but
means long sessions eventually block everything. A reviewed, audited operation that lowers a
label would recover a lot of utility, and reducing utility cost is genuinely open research
space.

Real isolation would need a privileged Linux environment, which I didn't have — so I have the
routing contracts and a hard no-downgrade rule, but I don't claim isolation I couldn't verify.

---

## Things to never say

| Don't | Say instead |
|---|---|
| "It prevents prompt injection" | "It contains the damage when injection succeeds" |
| "It's secure" | "It enforces these specific invariants, with these residual risks" |
| "It achieves X% ASR reduction" | "I measured containment against a scripted worst-case attacker" |
| "The sandbox isolates untrusted code" | "I built the routing contracts; I couldn't validate isolation without privileged Linux" |

The pattern in every good answer above: **state the design, then volunteer its limit.** Nothing
here claims to solve prompt injection — it claims to contain the damage and is explicit about
what stays exposed.

---

Next: [11 — Value-level provenance](11-value-level-provenance.md), the deep dive behind the
session-taint answer above.

Engineers who name their own residual risk get trusted with bigger systems. That habit is worth
more than any single feature in this repo.

---

Previous: [09 — Roadmap](09-roadmap.md) · Back to [index](README.md)
