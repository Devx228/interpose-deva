# Capability-Secure Agent Runtime — Full Implementation Spec (Stage 0 → Final)

> **Purpose:** A complete, build-ready implementation spec for all stages. Hand this to a coding agent
> (Codex / Claude Code) alongside `AGENT_RUNTIME_BUILD_PLAN.md` (the strategy doc). This file is the *how*;
> that file is the *why*. Read `## How To Use This Spec` first.
>
> **Project codename:** `capgate` (rename freely — systems-security register: capability/provenance/mediation).

---

## Reference Docs (consult, don't execute)
- `RESEARCH.md` — evidence, competitive analysis, threat models, benchmark *targets*. Consult when making a
  security-design decision or when you need the rationale/citation behind a choice. **Benchmark numbers in it
  are targets to reproduce, not facts to hardcode.**
- `AGENT_RUNTIME_BUILD_PLAN.md` — strategy and staging (the "why"); scope boundaries.
- **This file** — the build instructions (the "how"). Work from this.

---

## How To Use This Spec

- **Coding agents:** Build strictly stage by stage. Do not start a stage until the prior stage's
  **Exit Gate** passes. Within a stage, build modules in the listed order. The **taint engine (Stage 1)**
  and **sandbox (Stage 2)** must be designed *with* the human, not autopiloted — propose, explain tradeoffs,
  then implement in small reviewable pieces.
- **Core principle, never violate:** this is *deterministic enforcement*, not *detection*. We never primarily
  rely on a classifier/regex/LLM-judge to "spot bad prompts." We assume bad instructions get through and stop
  the dangerous *action*. If a task tempts you to write an injection *detector* as the main defense, stop.
- **Every change must keep the AgentDojo harness green and produce ASR/utility numbers.** No feature lands
  without its measured effect.
- **Language:** Python 3.11+. Type-hinted throughout. `ruff` + `mypy --strict` clean. `pytest` for everything.

---

## Mental Model (read once, internalize)

```
   Agent (LangGraph / OpenAI Agents SDK / CrewAI / Claude Code / any MCP client)
        │  speaks MCP (JSON-RPC) to reach its tools
        ▼
 ┌──────────────────────────────────────────────────────────┐
 │  capgate MCP PROXY  (primary, framework-agnostic surface) │
 │  intercepts: tool LIST, tool CALL (args), tool RESULT      │
 └──────────────────────────────────────────────────────────┘
        │  hands each event to →
        ▼
 ┌──────────────────────────────────────────────────────────┐
 │  CORE ENGINE (framework-independent — the real product)   │
 │   1 Taint/provenance  2 Capability policy                 │
 │   3 Source→sink (trifecta)  4 Sandbox  5 Signed receipts  │
 └──────────────────────────────────────────────────────────┘
        │  for frameworks that DON'T fully speak MCP:
        ▼
 ┌──────────────────────────────────────────────────────────┐
 │  THIN ADAPTERS (Stage 3, optional) — translate only,      │
 │  ZERO security logic: LangGraph, OpenAI SDK, Pydantic AI  │
 └──────────────────────────────────────────────────────────┘
```

**Hub-and-spoke.** Core engine = hub. MCP proxy = main spoke (reaches ~everyone, since the ecosystem is
converging on MCP). Adapters = thin extra spokes for stragglers. We build hub + MCP spoke first; that is
~90% of the value. Adapters never contain security logic.

---

## Repository Structure (final shape — create incrementally per stage)

```
capgate/
├── pyproject.toml                 # ruff, mypy, pytest, deps
├── README.md
├── AGENT_RUNTIME_BUILD_PLAN.md    # strategy doc (the "why")
├── IMPLEMENTATION_SPEC.md         # this file (the "how")
├── src/capgate/
│   ├── __init__.py
│   ├── proxy/                     # STAGE 0 — MCP interception
│   │   ├── server.py              #   capgate listens as an MCP server to the agent
│   │   ├── client.py              #   capgate is an MCP client to downstream servers
│   │   ├── session.py             #   per-connection state, request/response routing
│   │   └── events.py              #   normalized internal event types (ToolListEvent, ToolCallEvent, ToolResultEvent)
│   ├── receipts/                  # STAGE 0 — signed audit log
│   │   ├── model.py               #   Receipt dataclass + canonical serialization
│   │   ├── signer.py              #   Ed25519 sign + hash-chain
│   │   ├── store.py               #   append-only log (jsonl first, pluggable)
│   │   └── replay.py              #   deterministic replay from the log
│   ├── telemetry/                 # STAGE 0 — OTel / OpenInference spans
│   │   └── otel.py
│   ├── engine/                    # CORE — the decision pipeline
│   │   ├── pipeline.py            #   orchestrates: taint → policy → flow → (sandbox) → receipt
│   │   ├── decision.py            #   Decision type: ALLOW / BLOCK / REQUIRE_APPROVAL + reason
│   │   └── context.py             #   AgentContext: holds live taint state for a session
│   ├── taint/                     # STAGE 1 — provenance engine (THE NOVEL CORE)
│   │   ├── labels.py              #   Label = (confidentiality, integrity, source_tags)
│   │   ├── propagation.py         #   label propagation across values
│   │   ├── sources.py             #   classify incoming data → labels (untrusted-by-default rules)
│   │   └── tracker.py             #   per-session taint store keyed by value provenance
│   ├── policy/                    # STAGE 1 — capability DSL + enforcement
│   │   ├── dsl.py                 #   parse YAML policy → internal model
│   │   ├── model.py               #   Capability, Rule, ApprovalRule
│   │   ├── enforce.py             #   deterministic allow/block at each sink
│   │   ├── confinement.py         #   monotonic narrowing; optional z3 checks
│   │   └── templates/             #   least-privilege starter policies per agent archetype
│   ├── flow/                      # STAGE 1 — source→sink / trifecta
│   │   ├── sinks.py               #   sink taxonomy (network, email, shell, db-write, pr, payment…)
│   │   ├── sources.py             #   source taxonomy (secrets, pii, untrusted_web, tool_result…)
│   │   └── rules.py               #   deny source→sink pairs; the lethal-trifecta rule
│   ├── sandbox/                   # STAGE 2 — isolated execution
│   │   ├── base.py                #   Sandbox interface
│   │   ├── gvisor.py              #   gVisor backend
│   │   ├── microvm.py             #   Firecracker/Kata backend
│   │   ├── egress.py              #   deny-all + allowlist network control
│   │   └── limits.py              #   cpu/mem/timeout/output-size/syscall caps
│   ├── mcp_security/              # STAGE 2 — MCP-specific hardening
│   │   ├── pinning.py             #   hash tool descriptions; detect rug pulls
│   │   └── isolation.py           #   cross-server taint isolation, shadow-server detection
│   ├── dual_llm/                  # STAGE 3 — CaMeL-style quarantine mode
│   │   └── quarantine.py
│   ├── adapters/                  # STAGE 3 — thin shims (NO security logic)
│   │   ├── langgraph.py
│   │   ├── openai_agents.py
│   │   └── pydantic_ai.py
│   └── config.py                  # global config, key management, defaults (deny-by-default)
├── bench/                         # STAGE 0+ — evaluation harness
│   ├── agentdojo_runner.py        #   run AgentDojo with/without capgate; emit ASR + utility
│   ├── mcp_attacks.py             #   Invariant mcp-injection-experiments (whatsapp-takeover)
│   ├── adaptive.py                #   "Attacker Moves Second" adaptive re-runs
│   ├── redteam_loop.py            #   adversarial loop: found attacks → regression tests
│   └── reports/                   #   generated benchmark reports (committed)
└── tests/
    ├── unit/                      #   per-module
    ├── integration/               #   proxy ↔ engine ↔ downstream
    └── regression/                #   every discovered attack becomes a frozen test here
```

---

## Cross-Cutting Conventions

- **Deny-by-default, fail-closed.** Any error in the pipeline → BLOCK, never silent ALLOW.
- **No secrets in receipts.** Hash inputs/outputs; never store raw secret values.
- **Determinism.** Same inputs + same policy ⇒ same decision. No randomness in the enforcement path.
- **Decision object** is the universal currency between engine stages:
  ```python
  @dataclass(frozen=True)
  class Decision:
      verdict: Literal["ALLOW", "BLOCK", "REQUIRE_APPROVAL"]
      reason: str                 # human-readable, goes into the receipt
      rule_id: str | None         # which policy/flow rule fired
      labels: frozenset[str]      # taint labels on the decided value/action
  ```
- **Event object** is what the proxy emits to the engine:
  ```python
  @dataclass(frozen=True)
  class ToolCallEvent:
      session_id: str
      server: str                 # downstream MCP server name
      tool: str                   # tool name
      arguments: dict             # call args (may be tainted)
      arg_provenance: dict        # arg-path -> source info, for taint
  ```

---

## STAGE 0 — Foundation & Credibility

**Goal:** a working MCP proxy that forwards traffic, logs every call as a signed/hash-chained receipt,
emits OTel/OpenInference spans, and runs the AgentDojo harness to produce a *baseline* number.

**Why first:** everything downstream needs (a) the interception point and (b) a measurement loop. Skipping
this is why most projects' later numbers aren't credible.

### Modules & order

**0.1 `proxy/` — transparent MCP pass-through**
- `server.py`: implement an MCP server (JSON-RPC over stdio first; add SSE/HTTP later) that the agent
  connects to as if it were the real tool server.
- `client.py`: implement an MCP client that capgate uses to connect to the *real* downstream MCP server(s).
- `session.py`: for each agent connection, hold a session; route requests downstream and responses back.
- `events.py`: normalize the three intercept points into `ToolListEvent`, `ToolCallEvent`, `ToolResultEvent`.
- **Mode for Stage 0:** pass-through. Forward everything unchanged. The point is to *see* all traffic and
  prove the interception is lossless.
- **Interfaces:**
  ```python
  class Proxy:
      async def handle_list(self, e: ToolListEvent) -> ToolListResult: ...
      async def handle_call(self, e: ToolCallEvent) -> ToolResultEvent: ...
  ```
  In Stage 0 these just forward + emit a receipt. Later stages insert the engine pipeline before forwarding.

**0.2 `receipts/` — signed, hash-chained audit log**
- `model.py`: the receipt (see schema below). Canonical JSON serialization (sorted keys, no whitespace
  drift) so hashes are stable.
- `signer.py`: Ed25519 keypair (load from config; generate on first run, store securely). Sign the canonical
  bytes. Maintain `prev_receipt_hash` to chain.
- `store.py`: append-only `.jsonl` to start; interface so a DB backend can replace it.
- **Receipt schema:**
  ```json
  {
    "v": 1,
    "session_id": "...",
    "seq": 42,
    "ts": "2026-...Z",
    "server": "github-mcp",
    "tool": "create_issue",
    "verdict": "ALLOW",
    "rule_id": null,
    "reason": "passthrough (stage0)",
    "taint_labels": [],
    "args_hash": "sha256:...",
    "result_hash": "sha256:...",
    "prev_receipt_hash": "sha256:...",
    "signature": "ed25519:..."
  }
  ```

**0.3 `telemetry/otel.py` — spans**
- Wrap each intercepted call in an OpenTelemetry span using GenAI/OpenInference conventions
  (`execute_tool`, `invoke_agent`). Span attributes mirror the receipt (minus signature). This is what gives
  you "observability for free" — the same data feeds a tracing UI and the replay.

**0.4 `receipts/replay.py` — deterministic replay**
- `capgate replay <session_id>` reads the log and reconstructs the ordered sequence of calls/results/decisions.
- Verify the hash chain + signatures on replay; flag any tampering.

**0.5 `bench/agentdojo_runner.py` — the measurement loop**
- Integrate AgentDojo (arXiv:2406.13352). Run its task suites in two modes: **undefended** (agent → real
  tools) and **through capgate** (agent → proxy → real tools). In Stage 0 both should match (pass-through).
- AgentDojo's native benchmark tools are Python functions, not MCP servers. Until an MCP transport fixture
  exists, its `capgate` mode may use a **benchmark-only runtime mediation shim** that delegates the exact
  function call unchanged and emits the same production receipt format. Reports must label this path as
  `agentdojo-runtime`, never as MCP transport, and replay-verify one receipt per observed tool call.
- Emit two numbers: **utility** (task success rate) and **ASR** (attack success rate on the security cases).
- Record the exact model, case counts, observed tool-call count, verified receipt count, and chain-validity
  result so a cached or unmediated run cannot be mistaken for CapGate evidence.
- Commit a baseline report to `bench/reports/`.

### Stage 0 Exit Gate
- [ ] Agent runs end-to-end through the proxy with **zero behavioral difference** vs direct (pass-through correct).
- [ ] Every call produces a valid signed, hash-chained receipt; `replay` reconstructs the session and verifies the chain.
- [ ] AgentDojo runs through capgate and reproduces the **undefended baseline (~40% ASR, ~84% utility)**.
- [ ] OTel spans visible in a local collector.

---

## STAGE 1 — The Spine: Taint + Capability + Flow  *(hardest, highest-learning)*

**Goal:** deterministic data-flow enforcement that measurably blocks the injection→exfiltration chain.
This is where the proxy stops being pass-through and starts *deciding*.

> **Design-with-human gate:** before implementing `taint/propagation.py`, write a 1-page design note on the
> label lattice and propagation rules and review it. Do not autopilot this module — it is the novel core and
> the thing you must defend in an interview.

### 1A. Taint / Provenance Engine (`taint/`)

**1A.1 `labels.py` — the label model**
- A label is `(confidentiality, integrity, source_tags)`:
  - `confidentiality ∈ {public, internal, secret}` — how sensitive the data is.
  - `integrity ∈ {trusted, untrusted}` — whether it came from a source we trust to contain instructions.
  - `source_tags: frozenset[str]` — provenance breadcrumbs, e.g. `{"web", "mcp:github", "email"}`.
- Labels form a **lattice**; combining two values takes the **most restrictive** join:
  `confidentiality = max`, `integrity = untrusted if either untrusted`, `source_tags = union`.
- (Lineage: FIDES confidentiality/integrity labels; CaMeL data-flow separation.)

**1A.2 `sources.py` — classification (untrusted-by-default)**
- Map incoming data to initial labels. **Untrusted by default:**
  MCP tool *results*, MCP tool *descriptions* (tool-poisoning vector), web page content, email bodies,
  PDF/file uploads, RAG retrievals.
- **Trusted only when explicitly declared:** the system prompt, the user's direct instruction, signed config.

**1A.3 `propagation.py` — label flow**
- When a tool call's arguments derive from previously-labeled values, the call (and its result) inherit the
  joined label. Track derivation via `arg_provenance` from the proxy event.
- Start with **value-level** propagation (whole arguments/results carry labels). Note in the design that
  sub-string / field-level taint is a future refinement — don't over-engineer in Stage 1.

**1A.4 `tracker.py` — per-session taint store**
- Keyed by value identity/provenance; lets the engine ask "what is the label of the data feeding this sink?"
- Lives on `engine/context.py::AgentContext`.

### 1B. Capability Policy Engine (`policy/`)

**1B.1 `dsl.py` + `model.py` — the policy language**
- YAML → internal model. Grammar (keep minimal):
  ```yaml
  agent: research-agent
  can:        [ "read:web", "read:docs.company.public" ]
  cannot:     [ "send:email.external", "read:secrets", "exec:shell", "write:database.production" ]
  requires_approval: [ "create:github_issue", "send:slack" ]
  ```
- A capability string is `action:resource`. Matching supports prefix/glob on resource.

**1B.2 `enforce.py` — deterministic decision at each sink**
- For a `ToolCallEvent`, map tool → capability(s) it exercises. Decision precedence:
  1. matches `cannot` → **BLOCK**
  2. matches `requires_approval` → **REQUIRE_APPROVAL**
  3. matches `can` → **ALLOW**
  4. otherwise (deny-by-default) → **BLOCK**

**1B.3 `confinement.py` — monotonic narrowing (Progent pattern)**
- Dynamic policy updates may only *narrow* capabilities automatically; any *expansion* requires explicit
  human approval. Optionally encode the check with **z3** to prove an update is a narrowing.

**1B.4 `templates/` — least-privilege starters**
- Ship archetype policies (research-agent, coding-agent, email-agent) so adopters start locked-down.

### 1C. Source→Sink / Trifecta (`flow/`)

**1C.1 `sinks.py` / `sources.py` — taxonomies**
- Sinks: `network.external`, `email.external`, `shell.exec`, `db.write`, `github.pr`, `payment`, `file.write`, …
- Sources: `secrets`, `pii`, `untrusted_web`, `tool_result`, `customer_db`, `memory`, …

**1C.2 `rules.py` — deny pairs + the lethal-trifecta rule**
- Static deny pairs:
  ```yaml
  deny:
    - { from: secrets,       to: network.external }
    - { from: untrusted_web, to: shell.exec }
    - { from: customer_pii,  to: slack.public }
  ```
- **Lethal-trifecta rule (the headline defense):** BLOCK any sink call where the feeding data's label shows
  *both* `confidentiality ≥ internal` (private data) *and* `integrity == untrusted` (touched untrusted
  content) *and* the sink is externally-communicating. This operationalizes "never all three on one path."

### 1D. Wire the engine (`engine/pipeline.py`)
- Replace Stage 0 pass-through with: `taint.classify → policy.enforce → flow.check → (sandbox later) → receipt`.
- First BLOCK verdict short-circuits. Every path ends in a receipt (ALLOW or BLOCK with reason + rule_id).

### Stage 1 Exit Gate
- [ ] Targeted **ASR on AgentDojo < ~5%** (target Progent 1.0% / CaMeL near-zero).
- [ ] **Utility loss < ~15 points** vs the Stage 0 baseline.
- [ ] **Hard gate:** if ASR can't beat ~10%, taint propagation is leaky — fix before any new feature.
- [ ] Every BLOCK has a human-readable reason + rule_id in its receipt.

---

## STAGE 2 — Containment & MCP Hardening

**Goal:** real isolation (not string-filtering) for risky tools, resource limits against credit/DoS blowups,
and defeat of MCP-specific attacks (tool poisoning, rug pulls, cross-server shadowing).

### 2A. Sandboxed Execution Plane (`sandbox/`)

**2A.1 `base.py` — interface**
```python
class Sandbox(Protocol):
    async def run(self, spec: ExecSpec) -> ExecResult: ...   # isolated, limited, egress-controlled
```

**2A.2 backends**
- `gvisor.py`: gVisor (user-space kernel intercepting syscalls) — good default for many tools.
- `microvm.py`: Firecracker/Kata microVM — **required** for untrusted LLM-generated *code* (plain containers
  share the host kernel → insufficient). (References: E2B, microsandbox.)

**2A.3 `egress.py` — network control**
- **Deny-all egress by default**; explicit per-tool domain allowlist. This is the concrete defense that would
  have stopped EchoLeak/ForcedLeak-style exfiltration through an "allowed" domain.

**2A.4 `limits.py` — resource limits (the "don't blow up credits/DoS" piece)**
- Caps: CPU, memory, wall-clock timeout, **max tool-call count per session**, **max tokens/cost budget**,
  max output size, syscall limits. Maps to OWASP LLM10 Unbounded Consumption / denial-of-wallet.
- Also drop Linux capabilities, seccomp/AppArmor profile, ephemeral/read-only FS, block `~/.ssh`, `.env`,
  browser profiles.

### 2B. MCP-Specific Hardening (`mcp_security/`)

**2B.1 `pinning.py` — tool pinning / rug-pull detection**
- Hash each tool's description+schema on first sight; pin it. If a server later changes a tool's description
  (silent rug pull), flag/block and require re-approval. Defeats the `whatsapp-takeover` sleeper PoC.

**2B.2 `isolation.py` — cross-server isolation & shadow detection**
- Taint data per originating server; prevent one server's (untrusted) output from silently driving another
  server's privileged tool. Detect shadow/duplicate tool names across servers (shadowing attack).

### 2C. Wire sandbox into the pipeline
- After policy+flow ALLOW, if the tool is "risky" (shell/file/browser/code), route execution through the
  Sandbox instead of forwarding raw downstream. Receipt records sandbox profile + egress decisions.

### Stage 2 Exit Gate
- [ ] Defeat the Invariant `whatsapp-takeover` rug-pull PoC (pinning catches the description change).
- [ ] **Zero successful exfiltration** in a reproduced EchoLeak / GitHub-MCP toxic-agent-flow scenario.
- [ ] Resource limits demonstrably stop a runaway tool-call loop and a budget blowup.

---

## STAGE 3 — Hardening & Reach

**Goal:** robustness story under adaptive attack, framework-agnostic adoption, publishable results.

### 3A. Dual-LLM / Quarantine Mode (`dual_llm/quarantine.py`)
- CaMeL pattern for high-assurance flows: a **Privileged planner** LLM that never sees untrusted tokens +
  a **Quarantined extractor** LLM that processes untrusted content but has **no tool access**. The planner
  acts only on capability-checked, structured outputs. Offer as an opt-in mode (it costs tokens/utility).

### 3B. Adaptive Evaluation (`bench/adaptive.py`)
- Re-run AgentDojo under the **"The Attacker Moves Second"** methodology (adaptive attacks). Show deterministic
  enforcement holds ASR near-zero where a **classifier baseline collapses to >90% ASR** under the same attacks.
  This contrast *is* the landmark result.

### 3C. Adversarial Red-Team Loop (`bench/redteam_loop.py`)
- An LLM-driven attacker generates attempts against the running gateway. Every attack that *succeeds* is
  frozen into `tests/regression/` as a permanent test. Closed loop: defense ↔ attack ↔ measurement.

### 3D. Thin Adapters (`adapters/`) — NO security logic
- `langgraph.py` **first** (owner's strength): hook node/edge tool execution → feed engine → honor Decision.
- `openai_agents.py`: map onto guardrail/tripwire hooks.
- `pydantic_ai.py`: wrap tool calls.
- Each adapter only **translates** the framework's tool-call into a `ToolCallEvent` and applies the returned
  `Decision`. All taint/policy/flow/sandbox logic stays in the core.

### 3E. Benchmark Report
- Publish `bench/reports/REPORT.md`: undefended baseline vs capgate, static vs adaptive, utility cost, with
  honest caveats. This is the artifact that goes in the README and the interview.

### Stage 3 Landmark Exit Gate
- [ ] Deterministic enforcement holds **ASR near-zero under adaptive attack**.
- [ ] Demonstrated **classifier baseline → >90% ASR** under the same adaptive attacks (the contrast).
- [ ] LangGraph + OpenAI Agents SDK + Pydantic AI adapters working with **zero** security logic in them.
- [ ] Red-team loop running in CI; discovered attacks captured as regression tests.

---

## Decision Triggers (change course if…)
- **Utility loss consistently > 25%** → adopt FIDES-style *selective declassification* and AgentArmor-style
  *granular flow targeting* (reduce blanket restriction). Reducing utility cost is itself a novel contribution.
- **MCP adoption stalls** among target users → lead with the **LangGraph adapter** as the primary surface.
- **A major vendor open-sources an equivalent runtime** → differentiate on **sandbox depth + signed-receipt
  auditability + measured adaptive robustness**.

---

## Appendix A — Build Order Checklist (flat)
1. proxy pass-through (stdio) → 2. receipts (sign+chain) → 3. otel spans → 4. replay → 5. AgentDojo baseline
→ 6. taint labels+sources → 7. propagation → 8. tracker → 9. policy DSL+enforce → 10. confinement
→ 11. flow sinks/sources → 12. trifecta rule → 13. wire engine pipeline → **Stage 1 gate**
→ 14. sandbox base+gvisor → 15. microvm → 16. egress → 17. limits → 18. pinning → 19. cross-server isolation
→ 20. wire sandbox → **Stage 2 gate** → 21. dual-LLM mode → 22. adaptive bench → 23. red-team loop
→ 24. langgraph adapter → 25. openai/pydantic adapters → 26. report → **Stage 3 gate**.

## Appendix B — Test Strategy
- **Unit:** every module; taint join laws, policy precedence, hash-chain integrity, egress allowlist.
- **Integration:** agent ↔ proxy ↔ downstream; verify decisions + receipts end to end.
- **Regression:** every discovered/known attack (EchoLeak-style, GitHub-MCP toxic flow, whatsapp-takeover,
  AgentDojo security cases) frozen as a test that must stay BLOCKED forever.
- **Property tests:** label propagation never *loses* taint (monotonicity); deny-by-default holds on any error.

## Appendix C — Lineage & References (consult before inventing security designs)
- NCSC "Prompt injection is not SQL injection (it may be worse)" (Dec 2025)
- Microsoft MSRC indirect-prompt-injection defense-in-depth (Jul 2025); Spotlighting arXiv:2403.14720
- "The Attacker Moves Second" arXiv:2510.09023
- Lethal trifecta — Simon Willison (Jun 2025); Meta "Rule of Two" (Oct 2025)
- CaMeL arXiv:2503.18813 (ref code: github.com/google-research/camel-prompt-injection)
- FIDES arXiv:2505.23643 · Progent arXiv:2504.11703 · AgentArmor arXiv:2508.01249
- AgentDojo arXiv:2406.13352 (NeurIPS 2024); InjecAgent; Agent Security Bench (ASB); BIPIA; SEP
- Invariant mcp-injection-experiments (whatsapp-takeover) · Promptfoo (CI red-team)
- OWASP Agentic (ASI) Top 10 2026 · OWASP MCP Top 10 (beta) · OWASP LLM Top 10 2025
- Incidents: EchoLeak CVE-2025-32711 (CVSS 9.3) · ForcedLeak (CVSS 9.4, no CVE) · GitHub MCP toxic agent flow
- Tooling: OpenTelemetry GenAI semconv · Arize OpenInference · Microsoft Presidio · z3 · gVisor · Firecracker/Kata

## Appendix D — Hard Rules for Coding Agents (restate)
1. Deterministic enforcement, **never** detection-as-primary-defense.
2. Taint engine + sandbox = design-with-human, small reviewable pieces, no autopilot.
3. Framework-agnostic core; adapters translate only.
4. Every change keeps AgentDojo green and reports ASR/utility.
5. Deny-by-default, fail-closed, no raw secrets in receipts.
6. Respect each stage's Exit Gate before advancing.
7. Honest evaluation: adaptive results + utility cost; never claim completeness.
