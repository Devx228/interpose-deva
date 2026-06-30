# RESEARCH — Capability-Secure Runtime for AI Agents

> **Role of this doc:** Evidence, competitive analysis, threat models, and benchmark targets. **Consult,
> don't execute.** Coding agents read this when making a security-design decision or when they need the
> rationale/citation behind a choice — not as a build instruction list.
>
> **Caveat on numbers:** benchmark figures (ASR/utility), star counts, and acquisitions are from papers and
> secondary sources as of mid-2026. Treat ASR/utility numbers as **targets to reproduce**, not facts to
> hardcode. Re-verify before publishing.

---

## TL;DR
- **Build a Python-native, framework-agnostic *capability runtime* — not another MCP firewall.** Deep spine =
  deterministic information-flow / taint tracking (mark untrusted sources, block flows to privileged sinks) +
  capability-token least-privilege + real tool sandboxing, fronted as an MCP proxy with adapters for
  LangGraph, OpenAI Agents SDK, Pydantic AI. Directly attacks the "lethal trifecta"; provably defensible
  where pattern-matching guardrails are not.
- **The white space is real.** Crowded = prompt/jailbreak classifiers and MCP scanning/routing gateways. What
  no production-grade OSS project does well = deterministic, framework-agnostic data-flow enforcement with
  signed, replayable receipts — the architecture research shows works but that exists today only as research
  prototypes (CaMeL, FIDES, Progent) or single-vendor tools.
- **Killer demo = a benchmark number.** Run on AgentDojo (97 tasks, 629 security cases) and under adaptive
  attack; show targeted ASR driven near-zero with quantified, modest utility loss; then show the sandbox
  blocking real egress exfiltration on an EchoLeak/GitHub-MCP-style reproduction.

---

## 1. Landscape / Competitive Analysis

**Enterprise (closed; model-/network-layer detection):** Cloudflare AI Security for Apps (reverse-proxy
prompt inspection, PII via Presidio), Cisco AI Defense, Google Cloud Model Armor, Akamai Firewall for AI,
Pangea/CrowdStrike AI Guard. All are detection/classification + policy-filter layers; none enforces
deterministic source-to-sink data-flow policy. Model Armor and PromptGuard were among defenses broken at
>90% ASR under adaptive attack.

**Open-source guardrail frameworks (crowded):** NVIDIA NeMo Guardrails (~6.5k stars; Colang rails;
probabilistic, prompt-shaped), Meta LlamaFirewall/PurpleLlama (PromptGuard 2 classifier, AlignmentCheck
experimental, CodeShield static analysis — explicitly "a final layer of defense"), OpenAI Agents SDK
guardrails and LangChain guardrails (framework-coupled, shallow vs a runtime).

**MCP gateways/firewalls (crowded on routing/scanning, thin on deterministic flow control):** Invariant
mcp-scan (~2k stars; Snyk-acquired; tool-poisoning scan, rug-pull pinning, cross-origin — static MCP hygiene,
not a general runtime), Lasso MCP Gateway (~270 stars; nascent), IBM ContextForge (~2.3–3.5k stars;
routing/federation/auth control plane, explicitly *not* a content/flow security model), Lunar.dev MCPX /
agentgateway (~700 stars; identity governance, routing — infrastructure, not flow enforcement), Microsoft MCP
Gateway (AKS), Docker MCP Gateway (container-per-server + signed images), Pipelock (open-source agent firewall
emitting Ed25519-signed, hash-chained receipts from outside the trust boundary — closest to a signed-receipt
standard, but single-vendor). Cisco announced MCP security tooling at RSA 2026 — the category is consolidating.

**Red-teaming/testing (mature; complementary):** Promptfoo (~22k stars; OpenAI-acquired Mar 2026; OWASP
agentic presets). Use as your evaluation harness, not a competitor.

**Verdict:** Crowded = prompt/jailbreak classifiers + MCP routing/auth gateways. White space = a
production-grade, framework-agnostic, **deterministic capability + data-flow runtime** with sandboxed tool
execution and signed/replayable traces. CaMeL/FIDES/Progent prove the approach; nobody shipped the landmark OSS.

---

## 2. The Real Technical Gaps
- **Capability-based least privilege** — solved in research (Progent's DSL + monotonic confinement, SMT-checked
  updates), unshipped in framework-agnostic OSS.
- **Data-flow / taint tracking** — *the* core gap. Mark untrusted sources (web, email, PDF, MCP tool
  descriptions AND outputs), block flows to privileged sinks. CaMeL/FIDES show this is the deterministic win.
- **Real sandboxing** — primitives are production-grade (gVisor; Firecracker/Kata microVMs — the only
  production-safe layer for untrusted LLM-generated code, since containers share the host kernel; seccomp/
  AppArmor; deny-all egress; ephemeral FS). Gap = binding these to agent-level capability + taint state.
- **Signed receipts + deterministic replay** — nascent; Pipelock's mediator-signed hash-chained log is the
  leading pattern; no ratified standard. OpenTelemetry GenAI semconv + Arize OpenInference provide the substrate.
- **Lethal trifecta** (Willison, Jun 2025): private-data access + untrusted content + external comms. Current
  best practice = avoid combining all three (Meta "Rule of Two"). A runtime that *tracks taint and enforces
  "never all three on one path"* operationalizes this — not buyable off the shelf today.

---

## 3. Authoritative Threat Models
- **OWASP Agentic (ASI) Top 10 2026** (released 9 Dec 2025): ASI01 Goal Hijack, ASI02 Tool Misuse, ASI03
  Identity/Privilege Abuse, ASI04 Agentic Supply Chain, ASI05 Unexpected Code Execution, ASI06 Memory/Context
  Poisoning, ASI07 Insecure Inter-Agent Comms, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation,
  ASI10 Rogue Agents.
- **OWASP MCP Top 10 (beta):** token mismanagement/secret exposure, excessive privilege, tool poisoning
  (MCP03), supply-chain tampering, command injection, intent/flow subversion (MCP06), insufficient auth,
  shadow MCP servers (MCP09), context over-sharing (MCP10). Palo Alto Unit 42 measured 78.3% ASR with five
  MCP servers on one agent.
- **OWASP LLM Top 10 2025:** LLM01 Prompt Injection (#1), LLM06 Excessive Agency, LLM10 Unbounded Consumption.
- **UK NCSC (Dec 2025):** LLMs do not enforce an instruction/data boundary ("there is only ever 'next token'");
  prompt injection may never be mitigated the way SQL injection is → containment, not prevention.
- **Microsoft (MSRC, Jul 2025):** indirect prompt injection is inherent; deterministic detection is an open
  problem → defense-in-depth (Spotlighting arXiv:2403.14720, Prompt Shields, deterministic blocking of known
  exfil channels, FIDES arXiv:2505.23643, Design Patterns arXiv:2506.08837).
- **NSA "MCP: Security Design Considerations" (May 2026):** treat the agentic setup as a connected system;
  recommends dedicated MCP scanning.

**Most important AND tractable to measure:** indirect prompt injection via tool output (ASI01/LLM01/MCP06),
data exfiltration through tool chaining (the trifecta), tool poisoning/rug pulls (MCP03). All measurable via
AgentDojo + Invariant's mcp-injection-experiments.

**Real-world anchors:** EchoLeak (M365 Copilot zero-click, CVE-2025-32711, CVSS 9.3; exfil via auto-fetched
Markdown image through an allowed proxy domain); GitHub MCP "toxic agent flow" (Invariant, May 2025; malicious
public-repo issue → private-repo leak); ForcedLeak (Salesforce Agentforce, CVSS 9.4, **no CVE**; injected via
Web-to-Lead form; exfil through an expired CSP-allowlisted domain repurchased for $5).

---

## 4. Defenses That Demonstrably Work (lineage — benchmark against these)
- **CaMeL** (Google DeepMind, arXiv:2503.18813): control/data-flow separation; Privileged LLM never sees
  untrusted tokens + Quarantined LLM with no tool access; capability policies at call time. **77% of AgentDojo
  tasks with provable security vs 84% undefended** (~7pt utility cost; attacks → ~0). Ref code:
  github.com/google-research/camel-prompt-injection.
- **FIDES** (Microsoft, arXiv:2505.23643): IFC with confidentiality/integrity labels + dynamic taint;
  **deterministically stops all policy-violating prompt-injection attacks** in AgentDojo.
- **Progent** (arXiv:2504.11703): least-privilege tool-policy DSL; **ASR 39.9% → 1.0% on AgentDojo**,
  70.3% → 3.9% on ASB; utility maintained.
- **AgentArmor** (arXiv:2508.01249): granular flow targeting; **72% utility (1pt below no-defense)** vs CaMeL
  48% / Progent 64% — i.e. *reducing utility cost* is open contribution space (our opportunity).
- **Guardrails provably insufficient:** "The Attacker Moves Second" (arXiv:2510.09023; 14 authors incl. Nasr,
  Carlini, Tramèr across OpenAI/Anthropic/Google DeepMind) broke 12 defenses; classifier defenses went from
  near-zero to **>90% ASR** adaptively, 100% under human red-teaming. Meta "Rule of Two" (Oct 2025): at most
  two of {untrusted input, private data, state-change/external comms}.

---

## 5. Architecture Recommendation (summary)
- **Primary surface:** transparent MCP proxy (sees tool descriptions, call args, results).
- **Core engine:** (1) provenance/taint labeling (FIDES-style), (2) capability policy DSL (Progent-style +
  monotonic confinement, optional z3), (3) dual/quarantined-LLM option (CaMeL), (4) sandboxed execution
  (gVisor/Firecracker, deny-all egress, ephemeral FS), (5) Ed25519-signed hash-chained receipts → OTel/
  OpenInference spans for replay.
- **Python tooling:** policy → small DSL, optional z3; sandbox → gVisor/Kata/Firecracker (refs E2B,
  microsandbox); taint → **custom label-propagation engine (no mature lib exists — the novel contribution)**;
  PII → Presidio; tracing → OpenTelemetry + OpenInference.
- **Adapters:** MCP proxy primary; thin shims for LangGraph (strongest lever), OpenAI Agents SDK, Pydantic AI.
  Do NOT become "a LangChain plugin" — core stays framework-independent.

---

## 6. Build Strategy & Benchmarks
- **Deep spine to defend first:** (1) indirect injection → exfiltration (the trifecta), (2) MCP tool
  poisoning/rug pulls/shadowing, (3) adaptive robustness.
- **Benchmarks:** AgentDojo (primary; arXiv:2406.13352); InjecAgent, ASB, BIPIA, SEP; Invariant
  mcp-injection-experiments (whatsapp-takeover); Promptfoo OWASP presets in CI; dynamic suites (AgentDyn) to
  counter AgentDojo's static-task criticism.
- **Targets:** reproduce undefended baseline (~40% ASR, ~84% utility) → drive targeted ASR <~5% with utility
  loss <~15pt → hold near-zero under adaptive attack while a classifier baseline collapses to >90%.

---

## 7. Positioning
Frame as a **capability runtime / policy data-plane for agent actions** — "Envoy/Istio for AI agent actions,"
"seccomp/AppArmor for agents." Lead with security-engineering vocabulary (least privilege, information-flow
control, confused-deputy prevention, source-to-sink, provenance, signed receipts, deterministic replay), not
"guardrails." Anchor to OWASP ASI/MCP Top 10; cite CaMeL/FIDES/Progent as lineage.

---

## Caveats (keep visible)
- **Utility cost is real:** CaMeL ~2.7–2.8× tokens, ~48% utility in one comparison; strict policies drop
  utility more. Part of the contribution is *reducing* this via granular targeting.
- **Benchmarks are imperfect proxies:** report adaptive results, not just static ASR.
- **No defense is complete:** depends on correct user policies; can cause approval fatigue. Position as
  containment + auditability, not a silver bullet.
- **Moving targets:** Invariant→Snyk, Promptfoo→OpenAI; star counts are secondary-source estimates.
- **Incident specifics:** EchoLeak = CVE-2025-32711 (CVSS 9.3); ForcedLeak = CVSS 9.4, **no CVE**. Don't overstate.

---

## Reference Index
NCSC "Prompt injection is not SQL injection" (Dec 2025) · Microsoft MSRC indirect-PI defense-in-depth (Jul
2025) + Spotlighting arXiv:2403.14720 · "The Attacker Moves Second" arXiv:2510.09023 · Lethal trifecta
(Willison, Jun 2025) · Meta "Rule of Two" (Oct 2025) · CaMeL arXiv:2503.18813 · FIDES arXiv:2505.23643 ·
Progent arXiv:2504.11703 · AgentArmor arXiv:2508.01249 · AgentDojo arXiv:2406.13352 (NeurIPS 2024) ·
Invariant mcp-injection-experiments · OWASP Agentic Top 10 2026 / MCP Top 10 beta / LLM Top 10 2025 · EchoLeak
CVE-2025-32711 · ForcedLeak (CVSS 9.4, no CVE) · GitHub MCP toxic agent flow (Invariant, May 2025) · Tooling:
OpenTelemetry GenAI semconv, Arize OpenInference, Microsoft Presidio, z3, gVisor, Firecracker/Kata, Promptfoo.
