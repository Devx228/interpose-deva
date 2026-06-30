# capgate build status — 2026-06-30 13:28 IST

## Stages

- Stage 0: **PARTIAL** — stdio MCP pass-through, Ed25519 hash-chained receipts, replay, AgentDojo runtime mediation, and in-memory OTel export are tested; representative baseline equivalence and collector visibility are not established.
- Stage 1: **PARTIAL** — taint labels/tracking, strict capability policy, static source-to-sink rules, lethal-trifecta enforcement, fail-closed proxy execution, and CLI policy loading work locally; explicit value-level provenance and the measured exit gate remain incomplete.
- Stage 2: **PARTIAL** — live `tools/list` pin/shadow checks, explicit risk routing, finite-limit and quota contracts, deny-default egress policy, fail-closed sandbox-call routing, and gVisor/Firecracker adapter plans are tested. There is no production runner, profile loader, controlled egress broker, or privileged Linux validation, so real isolation is not established.
- Stage 3: **PARTIAL** — a provider-independent no-token quarantine boundary, strict evidence-only adaptive comparator, and dependency-free LangGraph translation seam are unit-tested. No live dual-model flow, adaptive attack run, red-team loop, or working framework integration exists.

## Measured numbers

- AgentDojo undefended representative baseline: **ASR=NOT YET MEASURED, utility=NOT YET MEASURED** — retained reports cover one case and do not reproduce the benchmark baseline.
- AgentDojo through capgate representative result: **ASR=NOT YET MEASURED, utility=NOT YET MEASURED** — no paired case currently demonstrates a defense delta.
- Adaptive ASR: **NOT YET MEASURED** — the comparator exists, but no real paired attacker-moves-second reports have been produced.

### Real smoke evidence, not exit-gate numbers

- Post-routing offline ground-truth smoke: utility `1.0` over one utility case; one mediated, allowed, replay-verified call; ASR not applicable. The exact command and AgentDojo `0.1.35` version are embedded in [agentdojo-groundtruth-capgate-stage2-routing-20260630.json](bench/reports/agentdojo-groundtruth-capgate-stage2-routing-20260630.json).
- Current policy-integrated offline ground-truth smoke: utility `1.0` over one utility case; one observed, mediated, allowed, and replay-verified tool call. ASR is not applicable. The exact command and AgentDojo `0.1.35` version are embedded in [agentdojo-groundtruth-capgate-policy-20260630.json](bench/reports/agentdojo-groundtruth-capgate-policy-20260630.json).
- Historical corrected OCI one-case control and Stage 1 files both report ASR `0.0`, utility `1.0`; Stage 1 blocked zero calls. They are wiring evidence, not a defense result, and their exact producing commands were not retained. See [benchmark validity notes](bench/reports/README.md).
- A new paired OCI `user_task_0` + `injection_task_4` control was attempted on 2026-06-30. Sandbox DNS blocked the first attempt; the approved-network retry produced no output within the bounded three-minute window and was terminated. No report or number was produced, so the Stage 1 half was not run.

## Blockers

- The configured OCI endpoint is reachable only with elevated network permission in this environment, and the latest approved smoke call did not complete within the bounded window.
- A cost/time budget for the representative/full AgentDojo matrix is not specified.
- Existing AgentDojo run directories contain no retained raw result files, and historical JSON reports lack producing commands/code revisions.
- Git was initialized after the retained reports were produced, so their `code_revision` fields remain null; future runs can record a real commit revision.
- OTel is validated with an in-memory exporter, not a running local OTLP collector.
- Host is Darwin arm64. `runsc`, Firecracker, and Kata are unavailable; privileged Linux isolation and egress tests cannot run here.
- The [Stage 2 isolation design](docs/design-notes/STAGE2_ISOLATION.md) was approved by the project owner on 2026-06-30. Its real-runtime validation environment is still unavailable.

## What is real vs scaffolded

### Genuinely working and tested locally

- Line-delimited JSON-RPC tool-call proxy and downstream forwarding.
- Signed/hash-chained receipt-v2 creation, tamper detection, replay verification, and structured sandbox backend/outcome/image audit fields.
- OTel `execute_tool` spans through a configured in-memory exporter without raw arguments/results.
- Taint label lattice, untrusted-by-default classification, monotonic tracker, and conservative session influence.
- Strict YAML policy model, deny/approval/allow/default-deny precedence, confinement checks, and templates.
- Static source-to-sink deny pairs and lethal-trifecta decisions.
- Policy-before-flow pipeline and fail-closed handling for approval, decision errors, and downstream errors.
- Real CLI policy + tool-metadata loading; denied calls do not execute downstream and receive BLOCK receipts.
- AgentDojo native-runtime mediation with receipt-count/replay consistency checks.
- Live persistent MCP tool-definition pinning and shared-registry tool-shadow blocking on `tools/list`, including signed allow/block receipts.
- Explicit `trusted_direct` / `fixed_risky` / `generated_code` metadata with unknown/missing classifications blocked.
- Fail-closed proxy routing to injected, backend-attested sandbox executors; timeout, output overflow, failed exit, malformed response, missing backend, and budget exhaustion produce signed BLOCK receipts without raw fallback.
- Pure egress policy checks for canonical host/path/request contracts, prohibited IPs, CNAMEs, redirects, and DNS rebinding evidence.
- Finite sandbox-limit contracts and a locked session/token/cost reservation ledger.
- Shell-free gVisor and Firecracker request adapters tested through fake runners.
- Dual-model quarantine contracts that send raw content only to a tool-less extractor and expose only opaque field references/types to the privileged planner; every provider/schema/input error blocks.
- Offline adaptive comparison rejects static, unversioned, incompatible, incomplete, or non-receipted evidence and computes deltas only from supplied compatible measured reports.
- LangGraph-shaped tool-call translation and uniform non-ALLOW rejection with no security logic or framework dependency in the adapter seam.

### Partial, interface-only, or unvalidated

- Provenance at runtime boundaries uses conservative session-wide influence; `arg_provenance` is not populated from real value derivation.
- Tool descriptions are pinned but are not yet represented in the taint/provenance graph.
- Tool-definition pins persist atomically in a private SQLite file, but there is no explicit re-approval workflow. The production proxy is single-downstream, and cross-server provenance grants/ownership are not shared across independent proxy processes.
- The stock CLI has no production sandbox profile/runner configuration. A configured risky tool therefore blocks; fake-executor tests establish routing behavior only.
- The downstream MCP server is still launched directly on the host before per-call routing. A hostile server process itself is not contained.
- gVisor/Firecracker plans, filesystem restrictions, complete limit enforcement, digest binding, lifecycle cleanup, and egress enforcement are not validated against real runtimes.
- Egress is policy logic only; no controlled resolver/network broker enforces it.
- Receipt v2 signs sandbox backend, sanitized outcome, and pinned image digest when known, but profile ID, configured/observed limits, egress decisions, lifecycle state, and cleanup outcome are not yet represented.
- Execution still precedes final receipt append; a receipt-store failure after a side effect cannot currently roll the side effect back or prove a durable completion record.
- Dual-model quarantine has no live provider integration or trusted post-policy opaque-reference resolver.
- The LangGraph seam is not connected to LangGraph. A framework-neutral mediator must first be extracted from `ProxySession`; OpenAI Agents SDK and Pydantic AI seams are not implemented.
- The adaptive comparator validates evidence but does not generate adaptive attacks. Existing checked-in static reports are correctly rejected as `NOT YET MEASURED`.
- No working framework adapter, live adaptive evaluation, or automated red-team loop is present.

## Honest next steps to hit unmet exit gates

1. Diagnose provider latency with a bounded direct completion probe, agree a benchmark cost/time budget, then run a fresh identical Stage 0 undefended/mediated matrix with commands and raw artifacts retained.
2. Replace session-wide influence with explicit argument/result provenance plumbing and freeze utility regressions caused by over-tainting.
3. Run targeted attacks where the undefended control actually succeeds; only then measure Stage 1 ASR and utility delta.
4. Add a strict sandbox-profile loader and trusted runner, move the risky downstream launch boundary inside the selected sandbox, and bind configured image digests to verified runtime assets.
5. Implement the controlled DNS/egress broker and complete sandbox profile/limit/egress/lifecycle receipt metadata, then run the privileged Linux conformance, resource-exhaustion, and exfiltration suite.
6. Add an explicit pin re-approval workflow and share multi-server ownership/provenance state before running the rug-pull and shadow-server exit tests.
7. Extract a framework-neutral mediation service from `ProxySession`, then connect and version-test real LangGraph, OpenAI Agents SDK, and Pydantic AI wrappers without duplicating security logic.
8. Add live quarantine providers plus a trusted capability-checked opaque-value resolver; then implement the adaptive attacker/red-team loop and retain real paired reports.

## Local validation command

```bash
ruff check .
mypy --strict src tests
pytest
```

Current local result: Ruff passed, strict mypy passed across 76 source files, and pytest passed `320` tests.
