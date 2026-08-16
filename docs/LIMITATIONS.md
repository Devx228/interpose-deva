# Where CapGate fails

A defense that reports only its wins is not evidence, it is marketing. This page lists what
CapGate does **not** stop, what breaks it, and which parts of a recognised threat taxonomy it
leaves uncovered. Everything here is measured or demonstrable from the repository.

## 1. The measured frontier

`python bench/run_scenarios.py` reports both numbers, in both enforcement modes:

| Mode | Containment | False-block rate |
|---|---|---|
| Default | **75%** (12/16) | **10%** (1/10) |
| `--strict-integrity` | **100%** (16/16) | **50%** (5/10) |

Neither column is the answer on its own. Perfect containment is trivially achievable by
refusing everything, and a 50% false-block rate is unusable in practice.

**The gap between those rows is the honest state of the project.** Closing the integrity gap
costs five times the false blocks, because taint is currently session-wide: one untrusted read
marks the rest of the session untrusted, so a rule keyed on integrity refuses most later
writes. Value-level provenance
([design note](design-notes/VALUE_LEVEL_PROVENANCE.md)) is what would let both columns improve
together, which is why it is the next piece of work rather than a nice-to-have.

## 2. Attacks that get through by default

Four scenarios in the corpus are **uncontained** under default enforcement, and the harness
reports them as failures rather than omitting them:

| Scenario | Why it gets through |
|---|---|
| `injected-database-destruction` | Injected content triggers record deletion |
| `injected-file-overwrite` | Injected content drives an irreversible file write |
| `injected-fraudulent-payment` | Injected email initiates a payment |
| `injected-public-pr` | Injected content opens a pull request |

The common cause: **the lethal-trifecta rule is confidentiality-based.** It fires only when
data is at least `internal`, because its concern is data *escaping*. None of these leak
anything — the action itself is the harm. Confidentiality-based rules are structurally blind to
them.

Capability policy is the only default defense here, and it helps only if the operator thought
to deny that capability in advance. In these scenarios the agent is legitimately allowed to
write, which is exactly the realistic case.

`--strict-integrity` closes this by adding
[`check_untrusted_state_change`](../src/capgate/flow/rules.py): untrusted-influenced data may
not drive a state-changing sink, whatever its confidentiality. It is opt-in precisely because
of the utility cost in the table above.

## 3. Structural limitations

**Taint is session-wide, not per-value.** [`AgentContext`](../src/capgate/engine/context.py)
holds one `influence` label per session and joins every result into it. Joins only move one
direction, so the first secret-and-untrusted result poisons everything after it. Safe, and
imprecise. It is the direct cause of both the 10% and the 50%.

**Value-level provenance is absent on the MCP path.**
[`events.py`](../src/capgate/proxy/events.py) hardcodes `arg_provenance={}`, so per-value
tracking there is not merely coarse — it does not exist.

**The corpus is authored, not sampled.** 16 attacks written by the same person who wrote the
defense. That demonstrates the encoded flows are contained; it says nothing about flows nobody
thought of. No independent red team has attacked this.

**The scripted planner is not a model.** It obeys injections perfectly, which is the right
worst-case assumption for measuring *enforcement*, but it means these numbers say nothing about
how often a real model falls for an injection. That is a different question and deliberately not
answered here.

**Pins are trust-on-first-use.** A malicious tool definition present at first observation
becomes the accepted baseline. There is no re-approval workflow.

**Receipts have no external anchor.** The signed chain detects modification of retained
entries. It cannot detect deletion of the tail — truncate the last three receipts and the rest
still verifies — nor replacement of the log and key together.

**Receipt durability follows execution.** An allowed side effect completes before its receipt
is appended. A storage failure after the action cannot undo it.

**No real isolation.** gVisor and Firecracker exist as request builders tested against fake
runners. No process, filesystem, syscall, network, or VM isolation has been validated. Risky
tools block rather than running unsandboxed, which is safe but is not isolation.

**Two source enums do not map onto each other.** `classify_source` emits an `OriginKind` value
as a bare tag, and some are not `DataSourceKind` members — `OriginKind.WEB` yields `web`, which
matches no deny pair. Those tools rely on the trifecta rule alone.

**Single-call turns only.** The LangGraph adapter rejects parallel tool calls, because
`ToolNode` dispatches concurrently and thread scheduling is not a deterministic security order.

**No declassification.** Labels only ever become more restrictive. Long sessions therefore
accumulate restriction with no legitimate way to release it, which is a utility ceiling.

## 4. Assumptions that break it

CapGate's guarantees dissolve if any of these does not hold:

- **Tool metadata is correct.** Marking an external sender `sink: none`, or private data
  `confidentiality: public`, disables the defense for that tool. Metadata is trusted input.
- **Policy is correct.** Granting a capability the agent should not have is not detectable.
- **The host and CapGate process are uncompromised.** Nothing defends against an attacker who
  can edit policy, patch the process, or read memory.
- **The signing key is secret.** Key compromise makes receipts forgeable.
- **The downstream MCP server is not hostile.** The CLI launches it on the host; per-call
  routing does not contain it.

## 5. Threat taxonomy coverage

Mapped to OWASP. "Partial" means a meaningful class is covered and a meaningful class is not.

### OWASP LLM Top 10 (2025)

| Risk | Coverage | Notes |
|---|---|---|
| LLM01 Prompt Injection | **Partial — by design** | Does not prevent injection. Contains the resulting action. Exfiltration covered by default; destructive actions need `--strict-integrity`. |
| LLM02 Sensitive Information Disclosure | **Yes** | The lethal-trifecta rule is exactly this. Receipts hash payloads rather than storing them. |
| LLM05 Improper Output Handling | **Partial** | Tool arguments are schema-validated and provenance-labelled; rendered output is out of scope. |
| LLM06 Excessive Agency | **Yes** | Deny-by-default capability policy, plus human approval for flagged capabilities. |
| LLM08 Vector/Embedding Weaknesses | **No** | No RAG-specific handling beyond labelling retrievals untrusted. |
| LLM10 Unbounded Consumption | **Partial** | `SessionBudget` implements attempt/token/cost ledgers but is not wired into the CLI. |
| LLM03 Supply Chain · LLM04 Data Poisoning · LLM07 System Prompt Leakage · LLM09 Misinformation | **No** | Out of scope. |

### OWASP MCP Top 10 (beta)

| Risk | Coverage |
|---|---|
| MCP03 Tool Poisoning | **Yes** — definitions are hashed and pinned; changes block. TOFU limits apply. |
| MCP06 Intent / Flow Subversion | **Yes** — the core source-to-sink model. |
| MCP09 Shadow MCP Servers | **Partial** — process-local name-ownership checks; not shared across processes. |
| MCP10 Context Over-Sharing | **Yes** — confidentiality labels plus external-sink rules. |
| Excessive Privilege | **Yes** — capability policy. |
| Token Mismanagement · Command Injection · Insufficient Auth | **No** — credential handling and transport auth are out of scope. |

### OWASP Agentic (ASI) Top 10 (2026)

| Risk | Coverage |
|---|---|
| ASI01 Goal Hijack | **Partial** — the goal can be hijacked; the resulting action is contained. |
| ASI02 Tool Misuse | **Yes** |
| ASI03 Identity / Privilege Abuse | **Partial** — capability enforcement, but no agent identity system. |
| ASI05 Unexpected Code Execution | **Partial** — routed to a required sandbox that blocks when unavailable; no validated isolation. |
| ASI06 Memory / Context Poisoning | **Partial** — memory is labelled untrusted; no memory-specific defenses. |
| ASI07 Insecure Inter-Agent Comms | **No** — single-agent model only. |
| ASI08 Cascading Failures · ASI09 Human-Agent Trust · ASI10 Rogue Agents | **No** |

## 6. What would change these answers

In rough order of how much each would move the numbers:

1. **Value-level provenance** — the prerequisite for lowering false blocks *and* affording
   strict integrity. Everything else is downstream of this.
2. **An independent red team** — the corpus is authored by the defender, which caps what it can
   demonstrate.
3. **Explicit declassification** — releases accumulated restriction and lifts the utility
   ceiling.
4. **External receipt anchoring** — closes tail deletion.
5. **A privileged Linux environment** — the only way any isolation claim becomes real.

---

See also: [security model](SECURITY_MODEL.md) for the formal trust boundary,
[STATUS.md](../STATUS.md) for implementation state, and
[bench/reports/README.md](../bench/reports/README.md) for which measurements are quotable.
