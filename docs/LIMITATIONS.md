# Where CapGate fails

A defense that reports only its wins is not evidence, it is marketing. This page lists what
CapGate does **not** stop, what breaks it, and which parts of a recognised threat taxonomy it
leaves uncovered. Everything here is measured or demonstrable from the repository.

## 1. The measured frontier

`python bench/run_scenarios.py --matrix` reports both numbers in all four
provenance × enforcement combinations:

| Provenance | Rules | Containment | False-block rate |
|---|---|---|---|
| session-global | default | 76.5% (13/17) | 25.0% (3/12) |
| session-global | `--strict-integrity` | 100% (17/17) | 58.3% (7/12) |
| value-level | default | 76.5% (13/17) | 8.3% (1/12) |
| value-level | `--strict-integrity` | **100%** (17/17) | **8.3%** (1/12) |

Neither column is the answer on its own. Perfect containment is trivially achievable by
refusing everything, and a 58.3% false-block rate is unusable in practice.

Under session-global taint the two goals pull against each other; value-level provenance
([design note](design-notes/VALUE_LEVEL_PROVENANCE.md), now implemented) is the cell where
both hold at once. What the bottom row does **not** mean: the remaining false block is
structural, not fixable by more precision — a planner that reads untrusted content *raw* has a
genuinely influenced context, and the corpus keeps one such flow
(`email-summary-needs-comprehension`) refused in every mode so this cost stays visible. Its
quarantined counterpart (`email-triage-quarantined-extraction`) recovers the same workflow
through [audited, bandwidth-bounded declassification](design-notes/DECLASSIFICATION.md) — at
an explicit, receipted price of ~5.6 attacker-choosable bits. Precision is also **opt-in per
tool**: a flow nobody marked pass-through behaves exactly as session-global.

## 2. Attacks that get through by default

Four scenarios in the corpus are **uncontained** under default enforcement in *both*
provenance modes — precision does not change what the default rules can see. The harness
reports them under "uncontained by design" rather than omitting them:

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

**Session-global taint is still the default, and the fallback.**
[`AgentContext`](../src/capgate/engine/context.py) joins every raw result into one session
`influence` label. Value-level provenance improves on this only for tools explicitly marked
reference-returning, only in `value_level` mode, and only on the LangGraph path. Everything
unmarked — and every free-text argument the planner composes — still inherits the session
label. That fallback is deliberate (unknown lineage is untrusted lineage), but it means the
measured value-level numbers describe flows whose authors did the declaration work.

**References are pass-through only.** The planner cannot read a referenced value, so any task
that requires comprehending untrusted or secret content forfeits either the precision (read it
raw, inherit session taint) or the task. No quarantined-reader split exists.

**Value-level provenance is absent on the MCP path.**
[`events.py`](../src/capgate/proxy/events.py) hardcodes `arg_provenance={}`, so per-value
tracking there is not merely coarse — it does not exist. The proxy always runs session-global.

**The self-authored corpus is authored, not sampled.** 17 attacks written by the same person
who wrote the defense. That demonstrates the encoded flows are contained; it says nothing about
flows nobody thought of.

This is now *partly* addressed. `python bench/agentdojo_attacks.py` replays 26 injection tasks
authored by **AgentDojo's researchers**, using the `ground_truth()` call sequences they ship:

| Corpus | Author of the attacks | Default | `--strict-integrity` |
|---|---|---|---|
| `bench/scenarios.py` | this repository | 75% (12/16) | 100% (16/16) |
| AgentDojo injection tasks | AgentDojo researchers | **76.9%** (20/26) | **100%** (26/26) |

The close agreement between the two rows is the useful part: if the self-authored corpus had
been unconsciously fitted to the defense, it would score far better than a third-party one. It
does not. Both also fail on the same class — destructive and state-changing actions — which is
independent confirmation that the gap is structural rather than an artifact of who wrote the
tests.

The third-party corpus immediately earned its place by finding a **misconfiguration in our own
tool metadata**: `get_webpage` was classified as a harmless read when fetching an
attacker-supplied URL is outbound communication. That is exactly the failure mode §4 warns
about, and no self-authored attack had caught it.

Remaining honest limits: the attacks are third-party but the **tool security metadata is still
ours**, no model runs (so this is not an AgentDojo attack-success rate and no utility is
measured), 9 injection tasks ship no executable ground truth and are excluded, and **no human
red team has attacked this.**

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

**Declassification is narrow by design.** The only way a label moves down is a declared
extractor whose output fits closed domains (bool, bounded int, string enum) — never free
strings. Anything an author cannot honestly enumerate stays restricted, so long sessions of
free-text work still accumulate restriction; the utility ceiling is raised, not removed. The
stated residual: a conforming extraction still hands an attacker up to
`sum(log2(|domain|))` bits of steering per call. That number is in every receipt, but a
deployment that conditions dangerous decisions on extracted fields is spending those bits
whether it reads the receipts or not.

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

1. **An independent red team** — the corpus is authored by the defender, which caps what it
   can demonstrate. The most valuable surfaces to probe are now the reference mechanism and
   the declassification validator.
2. **A live quarantined extractor** — the corpus proves the mechanism with a scripted
   extractor; putting a real tool-less LLM in the quarantine seat (as
   `examples/quarantine_demo.py` sketches) and measuring it is the missing step between
   "sound design" and "works with a model in the loop".
3. **Richer declassification domains with honest accounting** — bounded-length structured
   text is the obvious demand and the obvious hazard; any extension must keep the bits
   number true.
4. **External receipt anchoring** — closes tail deletion.
5. **A privileged Linux environment** — the only way any isolation claim becomes real.

---

See also: [security model](SECURITY_MODEL.md) for the formal trust boundary,
[STATUS.md](../STATUS.md) for implementation state, and
[bench/reports/README.md](../bench/reports/README.md) for which measurements are quotable.
