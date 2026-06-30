# Capability-Secure Runtime for AI Agents — Build Plan & Reference

> **Audience:** This document is the single source of truth for building this project.
> It is written to be read by both the project owner and coding agents (Codex, Claude Code, etc.).
> Coding agents: read the entire `## Agent Operating Instructions` section before writing any code.

---

## 0. Project in a Nutshell

We are building a **Python runtime that sits between an AI agent and its tools** (primarily as a
**Model Context Protocol (MCP) proxy**) and prevents a compromised or manipulated agent from causing harm.

The core insight: **prompt injection cannot be reliably *detected*** — this is now the authoritative
position of the UK NCSC and Microsoft. LLMs do not enforce a boundary between "instructions" and "data";
to the model there is only ever the next token. Pattern-matching guardrails provably collapse under
adaptive attack. So instead of detecting bad input, we **architecturally contain what the agent can do**:

- **Track provenance (taint):** every value entering agent context is labeled by where it came from. MCP
  tool outputs, web pages, emails, PDFs, and RAG content are untrusted by default.
- **Enforce capabilities (least privilege):** every tool call is checked against an explicit policy
  (this agent may `read:web` but not `exec:shell` or `send:email.external`).
- **Block dangerous flows (the lethal trifecta):** never allow a single tainted path to combine
  private-data access + untrusted content + external communication.
- **Sandbox execution:** risky tools run in an isolated environment (gVisor / Firecracker microVM),
  deny-all network egress by default, ephemeral filesystem, resource limits.
- **Sign & replay:** every allowed/blocked action becomes a cryptographically signed, hash-chained
  audit receipt that can be deterministically replayed.

**Observability and manageability are byproducts, not separate features.** The signed receipt log +
OpenTelemetry traces *are* the observability layer. The capability policy engine *is* the management layer.

**What makes it premium (not "another MCP firewall"):** deterministic guarantees with **published
benchmark numbers** on AgentDojo, a genuinely novel **taint-propagation engine**, **signed replayable
receipts**, framework-agnostic reach, and 1:1 mapping to OWASP Agentic & MCP Top 10 categories.

---

## 1. Why This Matters (Threat Model & Grounding)

### The authoritative consensus
- **UK NCSC (Dec 2025):** current LLMs "do not enforce a security boundary between instructions and data
  inside a prompt"; prompt injection "may never be totally mitigated in the way that SQL injection... can be."
  → Mitigation must be **containment and impact reduction**, not prevention.
- **Microsoft (MSRC, Jul 2025):** indirect prompt injection is "an inherent risk... deterministic detection
  is still an open research problem." → Defense-in-depth: spotlighting, deterministic blocking of known
  exfiltration channels, information-flow control (their FIDES system).
- **"The Attacker Moves Second" (arXiv:2510.09023, Oct 2025):** broke 12 published defenses; classifier
  defenses that reported near-zero attack success went to **>90% ASR** under adaptive attack and 100% under
  human red-teaming. → Detection-based defense is structurally insufficient.
- **Meta "Rule of Two" (Oct 2025):** an unsupervised agent should satisfy **at most two** of
  {untrusted input, private-data access, state-change/external comms}.
- **Lethal trifecta (Simon Willison, Jun 2025):** private-data access + untrusted content + external
  communication = exfiltration risk. Our runtime operationalizes "never all three on one tainted path."

### Defenses that demonstrably work (our intellectual lineage — benchmark against these)
- **CaMeL (Google DeepMind, arXiv:2503.18813):** separates control flow from data flow; Privileged LLM
  never sees untrusted tokens + Quarantined LLM has no tool access; capability policies at tool-call time.
  Solved **77% of AgentDojo tasks with provable security vs 84% undefended** (~7pt utility cost, attacks → ~0).
- **FIDES (Microsoft, arXiv:2505.23643):** information-flow control with confidentiality/integrity labels +
  dynamic taint tracking; **deterministically stops all policy-violating prompt-injection attacks** in AgentDojo.
- **Progent (arXiv:2504.11703):** DSL for least-privilege tool policies; **ASR 39.9% → 1.0% on AgentDojo**,
  70.3% → 3.9% on Agent Security Bench, utility maintained.
- **AgentArmor (arXiv:2508.01249):** granular flow targeting; **72% utility (only 1pt below no-defense)** vs
  CaMeL 48% / Progent 64% — i.e. *reducing utility cost* is open contribution space (this is OUR opportunity).

### Real-world incidents to reproduce in the demo
- **EchoLeak** — Microsoft 365 Copilot zero-click, **CVE-2025-32711, CVSS 9.3** (Aim Labs). Exfiltration via
  auto-fetched reference-style Markdown image through an allowed proxy domain.
- **GitHub MCP "toxic agent flow"** (Invariant Labs, May 2025) — malicious public-repo issue coerced the
  agent into leaking private-repo data.
- **ForcedLeak** — Salesforce Agentforce (Noma Security), **CVSS 9.4, no CVE issued**. Injected via Web-to-Lead
  form; exfiltrated through an expired CSP-allowlisted domain repurchased for $5.

### Threat taxonomies we map to (for compliance positioning)
- **OWASP Agentic (ASI) Top 10 2026:** ASI01 Goal Hijack, ASI02 Tool Misuse, ASI03 Identity/Privilege Abuse,
  ASI05 Unexpected Code Execution, ASI06 Memory/Context Poisoning, ASI07 Insecure Inter-Agent Comms, ASI10 Rogue Agents.
- **OWASP MCP Top 10 (beta):** token mismanagement, excessive privilege, **tool poisoning (MCP03)**,
  command injection, **intent/flow subversion (MCP06)**, shadow MCP servers (MCP09), context over-sharing (MCP10).
- **OWASP LLM Top 10 2025:** LLM01 Prompt Injection (#1), LLM06 Excessive Agency, LLM10 Unbounded Consumption.

---

## 2. The Five Core Systems (What We Build)

These are the five components every coding agent should understand. They are listed in dependency order.

### 2.1 Taint / Provenance Engine  *(the hard, novel core — highest priority for depth)*
- Every value entering agent context gets a **label**: confidentiality level + integrity level + source tag.
- Sources marked **untrusted by default:** MCP tool outputs, web page content, email bodies, PDF/file uploads,
  RAG retrievals, MCP **tool *descriptions*** (these are an attack vector — tool poisoning).
- Labels **propagate** through the execution graph: if a tool call's arguments derive from tainted data, the
  result is tainted. This is custom label-propagation — no mature Python library does this for agents, so it
  is genuinely novel engineering.
- Inspired by FIDES (confidentiality/integrity labels) and CaMeL (data-flow separation).

### 2.2 Capability Policy Engine  *(deterministic least-privilege enforcement)*
- A small **DSL** over tool names + arguments. Each agent gets explicit allow/deny/require-approval rules.
- Example policy intent:
  ```yaml
  agent: research-agent
  can:
    - read:web
    - read:docs.company.public
  cannot:
    - send:email.external
    - read:secrets
    - exec:shell
    - write:database.production
  requires_approval:
    - create:github_issue
    - send:slack
  ```
- **Monotonic confinement** (Progent pattern): policy narrowing auto-applies; expansion requires explicit
  approval. Optionally back confinement checks with the **z3** SMT solver.
- Deterministic allow/block decision at **every tool call (sink)**.

### 2.3 Data-Flow / Source-to-Sink Enforcement  *(the trifecta rule)*
- Borrowed from appsec. Define **sources** (filesystem, DB, secrets, browser page, email, Slack, MCP tool
  response, memory) and **sinks** (network, email, shell, DB write, file write, GitHub PR, payment, external API).
- Deny dangerous source→sink pairs on tainted paths, e.g.:
  ```yaml
  deny:
    - from: secrets        to: network.external
    - from: untrusted_web  to: shell.exec
    - from: customer_pii   to: slack.public
  ```
- The trifecta rule: block any sink that can exfiltrate when the path carries both private data and untrusted-origin taint.

### 2.4 Sandboxed Execution Plane  *(real isolation + resource limits)*
- Risky tools (shell, file, browser, code execution) run **isolated**, not just string-filtered.
- Isolation: **gVisor** (user-space kernel intercepting syscalls) or **Firecracker / Kata microVMs** (the only
  production-safe layer for untrusted LLM-generated code — plain containers share the host kernel and are insufficient).
- Hardening: seccomp/AppArmor, drop Linux capabilities, **deny-all network egress with explicit allowlist**,
  ephemeral/read-only filesystem, no access to `~/.ssh`, `.env`, browser profiles.
- **Resource limits:** CPU, memory, wall-clock timeout, max output size, max syscalls — defends OWASP
  LLM10 Unbounded Consumption / denial-of-wallet.

### 2.5 Signed Action Receipts + Deterministic Replay  *(audit = observability)*
- Every allowed/blocked action emits a receipt:
  ```json
  {
    "agent": "coding-agent",
    "tool": "shell.exec",
    "command_hash": "...",
    "policy_decision": "allowed",
    "capability": "exec:test_only",
    "taint_labels": ["untrusted_web"],
    "inputs_hash": "...",
    "outputs_hash": "...",
    "timestamp": "...",
    "prev_receipt_hash": "...",
    "signature": "ed25519:..."
  }
  ```
- **Ed25519-signed, hash-chained** (Pipelock pattern), emitted from outside the agent trust boundary.
- Emit as **OpenTelemetry GenAI / OpenInference spans** (`execute_tool`, `invoke_agent`, `create_agent`)
  so the same data powers tracing dashboards and deterministic replay (`runtime replay run_123`).

---

## 3. Architecture

```
        Agent (any framework / MCP client)
                    │
                    ▼
        ┌───────────────────────────┐
        │   MCP Proxy (primary)     │  speaks JSON-RPC; sees tool
        │   intercepts every        │  descriptions, call args, results
        │   LLM call + tool call    │
        └───────────────────────────┘
                    │
   ┌────────────────┼────────────────────────────┐
   ▼                ▼                             ▼
[2.1 Taint]   [2.2 Capability]            [2.3 Source→Sink]
 provenance    least-privilege             trifecta rule
 labels        deterministic               flow enforcement
                    │
                    ▼
        [2.4 Sandbox execution plane]
         gVisor/Firecracker, deny-all egress,
         resource limits, ephemeral FS
                    │
                    ▼
        [2.5 Signed receipts + replay]
         Ed25519 hash-chained log → OTel/OpenInference spans
                    │
                    ▼
            (adversarial red-team loop tests the whole thing →
             every discovered attack becomes a regression test)
```

**Integration surfaces (build in this order):**
1. **MCP proxy** — primary surface (sees all three MCP attack surfaces: descriptions, args, results).
2. **LangGraph adapter** — node/edge interception (strongest lever given owner's LangGraph experience).
3. **OpenAI Agents SDK adapter** — guardrail/tripwire hooks.
4. **Pydantic AI adapter** — tool wrappers.

> **Do NOT become "a LangChain plugin."** The core must be framework-independent; adapters are thin shims.

**Python tooling for the hard parts:**
- Policy DSL → compiled to checks, optionally backed by **z3** SMT solver (or externalize via Oso/OPA-style engine).
- Sandbox → gVisor or Kata via container runtime; Firecracker via a Python control library. (References: E2B, microsandbox.)
- Taint → **custom label-propagation engine** (our novel contribution — no mature lib exists).
- PII/secrets → **Microsoft Presidio**.
- Tracing → **OpenTelemetry SDK + OpenInference** instrumentation.

---

## 4. Benchmarks & Evaluation (how we prove it works)

The killer demo is a **number**, produced from day one.

- **Primary benchmark: AgentDojo** (Debenedetti et al., arXiv:2406.13352, NeurIPS 2024) — 97 realistic tasks,
  629 security test cases, 4 suites. Reproduce the undefended baseline (~40% ASR, ~84% utility) first, then
  show your enforcement driving **targeted ASR toward 0** with utility loss reported honestly.
- **MCP attacks: Invariant `mcp-injection-experiments`** (the `whatsapp-takeover` sleeper rug pull).
- **Adaptive robustness:** re-run under the **"The Attacker Moves Second"** methodology to show deterministic
  enforcement holds where classifier baselines collapse to >90% ASR.
- **Other suites to consider:** InjecAgent, Agent Security Bench (ASB), BIPIA, SEP; newer dynamic benchmarks
  (e.g. AgentDyn) to avoid AgentDojo's static-task criticism.
- **CI red-teaming:** **Promptfoo** OWASP agentic presets, run on every PR.

**Target thresholds (per stage, below).** If you can't beat ~10% targeted ASR after Stage 1, the taint
propagation has gaps — fix before adding features. If utility loss is consistently >25%, pivot toward
FIDES-style selective declassification / AgentArmor-style granular targeting.

---

## 5. Staged Build Plan

> Each stage has an explicit, measurable exit criterion. Do not advance until it's met.
> Front-load the hardest, highest-learning components (taint engine, sandbox) — don't save them for last.

### Stage 0 — Foundation & Credibility  *(≈ weeks 1–3)*
**Goal:** a working MCP proxy that logs everything, and a benchmark harness that produces a baseline number.
- [ ] MCP proxy: intercept JSON-RPC, forward to downstream MCP server(s), pass-through mode first.
- [ ] Signed-receipt logging (Ed25519, hash-chained) for every intercepted call.
- [ ] Emit OpenTelemetry / OpenInference spans (`execute_tool`, `invoke_agent`).
- [ ] Wire in the **AgentDojo harness** so every change yields ASR + utility numbers.
- **Exit criterion:** reproduce the **undefended AgentDojo baseline (~40% ASR, ~84% utility)** and produce a
  signed, replayable trace of a full agent run.

### Stage 1 — The Spine: Taint + Capability  *(≈ weeks 4–10, the hardest stage)*
**Goal:** deterministic data-flow enforcement that measurably blocks injection→exfiltration.
- [ ] Taint/provenance label-propagation engine (confidentiality + integrity + source tag).
- [ ] Mark MCP tool outputs / web / email / PDF / RAG / tool-descriptions as untrusted by default.
- [ ] Capability policy DSL + deterministic allow/block at every sink.
- [ ] Implement the **lethal-trifecta rule** (block tainted private-data → external-sink paths).
- **Exit criterion:** **targeted ASR on AgentDojo < ~5%** (matching Progent 1.0% / CaMeL near-zero) with
  **utility loss < ~15 points**. (Hard gate: if you can't beat ~10% ASR, the propagation is leaky — fix it.)

### Stage 2 — Containment & MCP Hardening  *(≈ weeks 11–16)*
**Goal:** real isolation and defeat of MCP-specific attacks.
- [ ] Sandboxed execution plane (gVisor or Firecracker/Kata), deny-all egress + allowlist, ephemeral FS.
- [ ] Resource limits (CPU/mem/timeout/output-size) — defends unbounded consumption.
- [ ] MCP tool pinning (hash tool descriptions; detect rug pulls) + cross-server taint isolation.
- **Exit criterion:** defeat the `whatsapp-takeover` rug-pull PoC AND **zero successful exfiltration** in a
  reproduced EchoLeak / GitHub-MCP-style flow.

### Stage 3 — Hardening & Reach  *(≈ weeks 17+)*
**Goal:** robustness story + framework-agnostic adoption + publishable results.
- [ ] Dual-LLM / quarantine mode (CaMeL pattern) for high-assurance flows.
- [ ] Run adaptive attacks; publish a benchmark report.
- [ ] Ship adapters: **LangGraph first**, then OpenAI Agents SDK, then Pydantic AI.
- [ ] Adversarial red-team loop wired into CI (every found attack → regression test).
- **Landmark exit criterion:** deterministic enforcement holds ASR near-zero **under adaptive attack** while
  you demonstrate a **classifier baseline collapsing to >90% ASR** under the same attacks.

### Decision triggers (when to change course)
- Utility loss consistently **>25%** → pivot to FIDES-style selective declassification / AgentArmor-style
  granular flow targeting (reducing utility cost is itself a novel contribution).
- MCP adoption stalls among target users → lead with the **LangGraph adapter** instead of the MCP proxy.
- A major vendor open-sources an equivalent deterministic runtime → differentiate on **sandbox depth +
  signed-receipt auditability**.

---

## 6. Positioning

Frame as a **capability runtime / policy data-plane for agent actions** — "Envoy/Istio for AI agent actions,"
or "seccomp/AppArmor for agents." Lead with security-engineering vocabulary (least privilege, information-flow
control, confused-deputy prevention, source-to-sink, provenance, signed receipts, deterministic replay), NOT
"guardrails." Anchor to OWASP ASI/MCP Top 10 and cite CaMeL/FIDES/Progent as lineage. Pick a name in the
systems-security register (capability / provenance / mediation / sandbox connotation).

---

## 7. Agent Operating Instructions  *(READ BEFORE WRITING CODE)*

Coding agents (Codex, Claude Code, etc.) must follow these:

1. **The taint engine and sandbox are the point. Do NOT autopilot them.** These are the novel, defensible,
   high-learning parts. The project owner must understand and be able to defend every architectural decision
   here in an interview. Propose designs and explain tradeoffs; do not generate large opaque implementations.
2. **Build deterministic enforcement, not classifiers.** If you find yourself writing a regex/keyword/LLM-judge
   that "detects prompt injection," stop — that is the crowded, provably-insufficient approach this project
   explicitly rejects. Enforcement happens via taint + capability + flow rules at sinks.
3. **Framework-agnostic core.** Never couple core logic to LangChain/LangGraph/etc. Adapters are thin shims.
4. **Every stage must produce a number.** Wire the AgentDojo harness in Stage 0 and keep it green. No feature
   lands without its effect on ASR/utility measured.
5. **Honest evaluation.** Report adaptive-attack results, not just static ASR. Report utility cost honestly.
   Never claim a defense is complete — position as containment + auditability.
6. **Respect the exit criteria.** Do not advance stages until the measurable gate is met.
7. **Security hygiene in the code itself:** deny-by-default everywhere, fail-closed, no secrets in receipts
   (hash them), least-privilege defaults in every policy template.
8. **When unsure about a security design choice, consult the lineage papers** (CaMeL arXiv:2503.18813,
   FIDES arXiv:2505.23643, Progent arXiv:2504.11703, AgentArmor arXiv:2508.01249) rather than inventing.

---

## 8. Reference Index

- NCSC — "Prompt injection is not SQL injection (it may be worse)" (Dec 2025)
- Microsoft MSRC — indirect prompt injection defense-in-depth (Jul 2025); Spotlighting arXiv:2403.14720
- "The Attacker Moves Second" — arXiv:2510.09023
- Lethal trifecta — Simon Willison (Jun 2025)
- CaMeL — arXiv:2503.18813 (ref code: github.com/google-research/camel-prompt-injection)
- FIDES — arXiv:2505.23643
- Progent — arXiv:2504.11703
- AgentArmor — arXiv:2508.01249
- AgentDojo — arXiv:2406.13352 (NeurIPS 2024)
- Invariant `mcp-injection-experiments` (whatsapp-takeover PoC)
- OWASP Agentic (ASI) Top 10 2026; OWASP MCP Top 10 (beta); OWASP LLM Top 10 2025
- EchoLeak CVE-2025-32711 (CVSS 9.3); ForcedLeak (CVSS 9.4, no CVE); GitHub MCP toxic agent flow (Invariant, May 2025)
- Tooling: OpenTelemetry GenAI semantic conventions, Arize OpenInference, Microsoft Presidio, z3, gVisor, Firecracker/Kata, Promptfoo

> **Caveats to keep visible:** utility cost is real (CaMeL ~2.7–2.8× tokens, dropped to ~48% utility in one
> comparison); benchmarks are imperfect proxies (report adaptive results); no defense is complete; star counts
> and acquisitions (Invariant→Snyk, Promptfoo→OpenAI) are secondary-source estimates to re-verify before publishing.
