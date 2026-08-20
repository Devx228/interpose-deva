# 04 — Taint labels

This is the novel core of the project. If you can only defend one part of CapGate in an
interview, defend this one.

## The label

Every value gets a label with three parts.
[`taint/labels.py:25-29`](../src/capgate/taint/labels.py#L25-L29):

```python
@dataclass(frozen=True)
class Label:
    confidentiality: Confidentiality
    integrity: Integrity
    source_tags: frozenset[str] = frozenset()
```

This is **metadata attached alongside the value**. It never changes the value itself. A secret
string is still the same string; the label is a separate fact about it.

### Confidentiality — how sensitive

```
public  <  internal  <  secret
```

An ordered scale. Ranks are explicit in
[`labels.py:18-22`](../src/capgate/taint/labels.py#L18-L22) rather than relying on enum
declaration order, because relying on declaration order for a security comparison is the kind
of thing that breaks quietly when someone reorders the enum.

### Integrity — could an attacker have influenced this?

```
trusted  <  untrusted
```

Only two values. `untrusted` is the more restrictive result.

### Source tags — provenance breadcrumbs

A set of strings: `email`, `untrusted_web`, `tool_result`, `secrets`. Used for explanation and
for the static deny-pair rules in [05](05-flow-and-trifecta.md).

## Read "trusted" carefully

This trips everyone up:

> **"Trusted" does not mean true, correct, or benign.** It means *permitted to influence
> control decisions* under the configured trust boundary.
>
> **"Untrusted" does not mean malicious.** It means the system must preserve the possibility of
> attacker influence.

A trusted source can be wrong. An untrusted source is usually perfectly innocent. The label is
about *provenance*, not *content*.

From [`taint/sources.py:22-28`](../src/capgate/taint/sources.py#L22-L28), exactly three source
kinds are trusted:

```python
_TRUSTED_SOURCES = frozenset({
    OriginKind.DIRECT_USER_INSTRUCTION,
    OriginKind.SYSTEM_PROMPT,
    OriginKind.SIGNED_CONFIG,
})
```

Everything else is untrusted by default — web content, email bodies, file uploads, RAG
retrievals, MCP tool results, and **MCP tool descriptions**. That last one surprises people:
a tool's own description is an attack vector (tool poisoning), so it does not get to be trusted
just because it arrived over a protocol.

## Source kind sets integrity, not confidentiality

Look at the signature ([`sources.py:31-42`](../src/capgate/taint/sources.py#L31-L42)):

```python
def classify_source(
    source: OriginKind,
    *,
    confidentiality: Confidentiality = Confidentiality.PUBLIC,
    source_tags: Iterable[str] = (),
) -> Label:
    integrity = Integrity.TRUSTED if source in _TRUSTED_SOURCES else Integrity.UNTRUSTED
```

Integrity is *derived* from the source kind. Confidentiality is *passed in* — it comes from
explicit tool metadata.

Why the asymmetry? Because you can know structurally that a web page is attacker-influenceable,
but you cannot know from the bytes whether a string is a secret. Guessing confidentiality by
inspecting content means regexes or an LLM classifier — and per [01](01-the-problem.md), that
is exactly the approach this project rejects. Confidentiality must be declared by a data
contract.

## The join

The heart of the system. When two values combine to influence one action, combine their labels
by taking **the more restrictive of each part**.
[`labels.py:31-46`](../src/capgate/taint/labels.py#L31-L46):

```python
def join(self, other: Label) -> Label:
    confidentiality = max(self.confidentiality, other.confidentiality,
                          key=_CONFIDENTIALITY_RANK.__getitem__)
    integrity = (Integrity.UNTRUSTED
                 if Integrity.UNTRUSTED in {self.integrity, other.integrity}
                 else Integrity.TRUSTED)
    return Label(confidentiality, integrity, self.source_tags | other.source_tags)
```

- confidentiality → **max**
- integrity → **untrusted if either is**
- source_tags → **union**

Worked example:

```
(secret,  trusted,   {secrets})
    JOIN
(public,  untrusted, {email})
    =
(secret,  untrusted, {secrets, email})
```

Full table:

| Input A | Input B | Join |
|---|---|---|
| public / trusted | public / trusted | public / trusted |
| secret / trusted | public / trusted | secret / trusted |
| public / untrusted | public / untrusted | public / untrusted |
| **secret / trusted** | **public / untrusted** | **secret / untrusted** |

That last row is our attack, expressed as a single label. Remember it — it is what the trifecta
rule looks for.

## Monotonicity: why this cannot be laundered

The join has one property that carries the entire design:

> A join can **never** lower confidentiality, **never** restore trust, and **never** drop a
> source tag. Labels only move toward *more* restrictive.

That is what "monotonic" means here, and the consequences are strong:

- Summarising a secret does not make it public.
- Copying an untrusted value into a fresh variable does not make it trusted.
- Mixing tainted data with clean data taints the result.
- Asking the model to "rewrite this safely" changes nothing about the label.

There is simply **no operation in the system that moves a label downward**, which means an
attacker cannot construct one. Compare this to a filter, where the attacker's whole job is
finding one input the filter mis-scores. Here there is no scoring to fool.

Mathematically the join is commutative, associative, and idempotent — a *least upper bound* on
a lattice. Practically that means the order in which values combine cannot change the result,
so an attacker cannot reorder operations to get a weaker label. The bottom element is
`(public, trusted, {})`, defined at [`labels.py:49`](../src/capgate/taint/labels.py#L49).

Tests: [`tests/unit/test_taint.py`](../tests/unit/test_taint.py)

## Where labels are stored

[`TaintTracker`](../src/capgate/taint/tracker.py) is a dict from provenance ID to label:

```python
def record(self, provenance_id: str, label: Label) -> None:
    existing = self._labels.get(provenance_id, BOTTOM_LABEL)
    self._labels[provenance_id] = existing.join(label)   # join, never overwrite
```

Note it *joins* rather than overwrites. Recording a label can only ever make an entry more
restrictive — you cannot clear taint by re-recording.

And a missing ID returns `UNKNOWN_LABEL` = `(public, untrusted, {unknown})`, not the bottom
label. Unknown provenance is untrusted. Fail toward less trust.

## The current limitation — read this twice

[`engine/context.py`](../src/capgate/engine/context.py) is 21 lines and contains the project's
one real weakness:

```python
@dataclass
class AgentContext:
    session_id: str
    tracker: TaintTracker = field(default_factory=TaintTracker)
    influence: Label = BOTTOM_LABEL          # <-- one label for the WHOLE session

    def label_for_call(self, provenance_ids: tuple[str, ...]) -> Label:
        return join_labels((self.influence, self.tracker.join(provenance_ids)))

    def record_result(self, provenance_id: str, label: Label) -> None:
        self.tracker.record(provenance_id, label)
        self.influence = self.influence.join(label)    # <-- one-way ratchet
```

There is a **single `influence` label for the entire session**, and every tool result joins into
it. Because joins only move one direction, the first `secret / untrusted` result poisons the
session *permanently*. Every subsequent external-sink call blocks forever — whether or not it
actually touches that data.

It gets worse. In the MCP path,
[`events.py:106`](../src/capgate/proxy/events.py#L106) hardcodes `arg_provenance={}`:

```python
return ToolCallEvent(..., arg_provenance={}, ...)
```

So `provenance_ids` is always empty, `tracker.join(())` returns the bottom label, and
`label_for_call` reduces to **`self.influence` alone**. Per-value tracking is not just
imprecise there — it is entirely absent.

**Is this safe?** Yes. It over-approximates, so it never misses a real attack.

**Is it good?** No. It blocks legitimate work, and a security tool that blocks everything gets
switched off. It also means any utility number you measure today is dominated by false blocks.

**Fixing this became the centerpiece of the project.** Chapter
[11](11-value-level-provenance.md) is the fix and its measurement.

## What is deliberately not here

**No implicit declassification.** No join, propagation, or tracking operation in this
chapter ever lowers a label. The one lowering that exists lives elsewhere and on purpose:
an explicit, per-tool, schema-bounded exception whose released bits are signed into the
receipt — chapter [12](12-declassification.md). If a label ever drops outside that path,
it is a bug.

**No field-level tracking.** Labels apply to whole values, not individual fields of a dict.
The design note ([`spec-docs/STAGE1_TAINT_DESIGN.md`](../spec-docs/STAGE1_TAINT_DESIGN.md))
chose whole-value tracking deliberately: simple and hard to bypass first, precision later.

---

Previous: [03 — Capabilities](03-capabilities.md) · Next: [05 — Flow and the trifecta](05-flow-and-trifecta.md)
