# 03 — Capabilities

## The idea

A **capability** is a permission written as `action:resource`:

```
read:private
send:external
exec:shell
write:database.production
```

Exactly one colon. The grammar is enforced by regex in
[`policy/model.py:7-23`](../src/capgate/policy/model.py#L7-L23) — lowercase actions, restricted
resource characters, and a concrete capability may not contain a glob:

```python
_ACTION = re.compile(r"[a-z][a-z0-9_-]*\Z")
_RESOURCE = re.compile(r"[a-z0-9*][a-z0-9._/*-]*\Z")
```

Being strict here is deliberate. A permissive parser that silently accepts `Read:Private` or
`read::private` gives you a rule that never matches anything and no error telling you so.

## The policy

Each agent gets a policy. Real example from
[`policy/templates/research-agent.yaml`](../src/capgate/policy/templates/research-agent.yaml):

```yaml
agent: research-agent
can:
  - read:web
  - read:docs.company.public
cannot:
  - read:secrets
  - exec:shell
  - send:email.external
  - write:database.production
requires_approval:
  - create:github_issue
  - send:slack
```

Patterns in a policy may use globs on the resource (`read:docs.company.*`); the concrete
capability a tool declares may not.

Parsing lives in [`policy/dsl.py`](../src/capgate/policy/dsl.py) and rejects unknown top-level
keys — a typo like `cannot_do:` is an error, not a silently ignored section.

## Precedence

This is the security-critical part. Order of evaluation, from
[`policy/enforce.py:11-15`](../src/capgate/policy/enforce.py#L11-L15):

| Order | Match | Verdict |
|---|---|---|
| 1 | `cannot` | BLOCK |
| 2 | `requires_approval` | REQUIRE_APPROVAL |
| 3 | `can` | ALLOW |
| 4 | nothing matched | BLOCK — `policy.default_deny` |

```python
rules = (
    ("cannot", policy.cannot, "BLOCK"),
    ("requires_approval", policy.requires_approval, "REQUIRE_APPROVAL"),
    ("can", policy.can, "ALLOW"),
)
for effect, patterns, verdict in rules:
    matched = _first_match(patterns, requested)
    if matched is not None:
        return Decision(verdict=verdict, ...)
return Decision(verdict="BLOCK", rule_id="policy.default_deny", ...)
```

Two things to notice, and both are choices:

**Deny is checked first.** Not "most specific wins." If a policy says `can: [read:*]` and
`cannot: [read:secrets]`, the deny wins. Under a most-specific-wins scheme you would have to
reason about which pattern is narrower — and get it wrong occasionally. First-category-wins is
boring and predictable, which is what you want in an authorization decision.

**No match means block.** Forgetting to write a rule fails safe.

## Least privilege

The principle: an agent holds only the permissions someone deliberately granted, and no more.

The templates ship locked down on purpose. A new adopter who starts from
`research-agent.yaml` cannot exfiltrate, cannot shell out, and cannot write to production —
not because those are blocked by name, but because they were never granted.

## The separation that makes this work

Two different files, both written by you:

| File | Answers |
|---|---|
| **Policy** | May this *agent* exercise this capability? |
| **Tool metadata** | Which capability, result label, sink, and risk class does this *tool* represent? |

Tool metadata looks like this ([`examples/offline_demo/tool-metadata.yaml`](../examples/offline_demo/tool-metadata.yaml)):

```yaml
tools:
  read_private:
    capability: read:private
    confidentiality: secret
    integrity: untrusted
    risk_class: trusted_direct
    source_tags: [tool_result]
    sink: none
  send_external:
    capability: send:external
    confidentiality: public
    integrity: untrusted
    risk_class: trusted_direct
    source_tags: [tool_result]
    sink: network.external
```

Parsed strictly by [`config.py`](../src/capgate/config.py) — missing required fields, unknown
fields, or an invalid enum value all raise `ConfigError`.

**Why keep them separate?** Because a malicious MCP server controls its own tool descriptions.
If a tool could declare its own security classification, an attacker would simply declare
themselves harmless: `sink: none, confidentiality: public`. Classification is trusted
configuration and never comes from the tool.

This generalises to a rule worth remembering: **never let the thing you are securing tell you
how to secure it.**

## Why capabilities are not enough

Now the important part. Go back to the attack in [01](01-the-problem.md).

Our agent is an email assistant. Its whole job is sending email, so its policy legitimately
contains `send:email.external`. When the injected instruction triggers a send to
`attacker@evil.com`:

- Capability requested: `send:email.external`
- Policy says: **ALLOW**
- Data walks out the door.

Capabilities answer *"may this agent send email?"* — and the honest answer is yes. They have no
way to express *"may it send **this particular data**?"*, because they know nothing about the
data at all.

That is the gap. To close it you have to track where the data came from, which is
[04 — Taint labels](04-taint-labels.md).

## Bonus: monotonic confinement

One extra piece, [`policy/confinement.py`](../src/capgate/policy/confinement.py). It answers:
*if the policy changes at runtime, is the new one provably no more permissive than the old one?*

```python
def is_monotonic_narrowing(current: Policy, proposed: Policy) -> bool:
```

The idea (borrowed from Progent, arXiv:2504.11703): a policy change that only **narrows**
permissions can be applied automatically. A change that **expands** them requires human
approval. Otherwise a compromised agent could talk its way into more privilege — and every
container escape in history started with a privilege expansion someone thought was harmless.

It is a pure function today, not a full policy-administration service.

---

Previous: [02 — The gate](02-the-gate.md) · Next: [04 — Taint labels](04-taint-labels.md)
