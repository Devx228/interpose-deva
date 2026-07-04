# CapGate build status — 2026-07-04 IST

## v0.1 milestone

**DONE — research-prototype scope.** CapGate now has a hardened stdio MCP tool-call boundary, an
offline end-to-end security demonstration, a public security model, a code-linked learning path,
and CI configuration. The milestone is intentionally narrower than the original four-stage
research roadmap.

The v0.1 claim is:

> A fail-closed MCP tool-call mediation prototype with capability and source-to-sink policy,
> persistent tool-definition pinning, and signed replayable audit receipts.

It is not a production release or evidence that every original stage is complete.

## Original roadmap stages

- Stage 0: **PARTIAL** — stdio MCP pass-through/mediation, Ed25519 hash-chained receipts, replay,
  AgentDojo runtime mediation, and in-memory OTel export are tested. A representative AgentDojo
  baseline and live collector validation are not established.
- Stage 1: **PARTIAL** — taint labels/tracking, strict capability policy, source-to-sink rules,
  lethal-trifecta enforcement, fail-closed execution, and CLI policy loading work locally. Runtime
  provenance remains conservative and representative ASR/utility gates are not measured.
- Stage 2: **PARTIAL** — tool-definition pins, process-local shadow checks, risk routing, limits,
  egress contracts, and gVisor/Firecracker request adapters are tested through pure logic or fake
  runners. Real isolation and controlled egress are not established.
- Stage 3: **PARTIAL** — a provider-independent quarantine boundary, evidence-only adaptive
  comparator, and LangGraph translation seam are unit-tested. No live dual-model flow, adaptive
  attack run, red-team loop, or working framework integration exists.

## Measured numbers

- AgentDojo undefended representative baseline: **ASR=NOT YET MEASURED,
  utility=NOT YET MEASURED**.
- AgentDojo through CapGate representative result: **ASR=NOT YET MEASURED,
  utility=NOT YET MEASURED**.
- Adaptive ASR: **NOT YET MEASURED**.

No current report may be used to claim a security-performance delta. See the
[report validity manifest](bench/reports/README.md).

### Reproducible local evidence, not benchmark evidence

Run:

```bash
.venv/bin/python examples/offline_demo/run.py
```

The demo uses the real CLI proxy path with an empty environment and temporary state. It verifies:

- accepted tool discovery and a private read are allowed;
- the private, untrusted result cannot flow to an external sink;
- the blocked send never reaches the downstream server;
- three signed/hash-chained receipts replay and contain no raw private marker;
- a changed tool definition is blocked after proxy restart; and
- a modified receipt fails signature verification.

Its output explicitly states that this is offline deterministic control validation, not AgentDojo
ASR or production-isolation evidence.

The retained AgentDojo ground-truth reports cover one utility case, one mediated/replay-verified
ALLOW, zero security cases, and therefore no ASR. They remain wiring evidence only.

## Security boundary hardening completed for v0.1

- Secure-mode resource, prompt, sampling, and custom JSON-RPC methods no longer bypass the policy
  boundary; they receive signed `proxy.unmediated_method` BLOCK receipts.
- Tool calls require a complete, successfully validated `tools/list` catalog. A later rejected
  catalog invalidates the accepted set before another call can execute.
- Tool requests and downstream responses now require supported fields, object arguments, matching
  typed IDs, JSON-RPC 2.0, and exactly one result or error. The receipt/taint representation cannot
  silently differ from a malformed transmitted payload.
- Receipt versions accept exact schemas only. Strict Base64 and Ed25519 lengths, recursive duplicate
  JSON-key rejection, and non-empty replay prevent modified artifacts from being reported valid.
- Offline AgentDojo ground-truth runs no longer read `.env`. New reports record `code_revision` only
  when Git HEAD exists and the nonignored Git worktree is clean; ignored files and the wider run
  environment remain outside that provenance field.

## What is genuinely working and tested locally

- Strict line-delimited JSON-RPC `tools/list` and `tools/call` mediation.
- Accepted-catalog enforcement, persistent SQLite definition pins, and process-local shadow checks.
- Deny/approval/allow/default-deny capability precedence and monotonic policy confinement.
- Confidentiality/integrity/source-tag joins, monotonic tracking, and conservative session influence.
- Static source-to-sink deny pairs and private-plus-untrusted external-sink blocking.
- Fail-closed handling for malformed protocol data, unmediated methods, approval, internal decision
  errors, downstream errors, unavailable sandbox routes, budget exhaustion, and malformed sandbox
  results.
- Ed25519-signed, hash-chained, versioned receipts with argument/result hashes, replay, and tamper
  detection.
- Bounded OTel decision metadata without raw arguments or results.
- Pure egress/canonicalization policy and locked session quota ledger.
- Shell-free gVisor and Firecracker request-plan adapters through injected fake runners.
- Tool-less quarantine extraction with planner-visible opaque references only.
- Evidence-validating adaptive comparator and dependency-free LangGraph translation seam.
- No-network offline security demo and pinned two-version CI workflow.

## Partial, interface-only, or unvalidated

- Real MCP calls do not populate value-level `arg_provenance`; prior tool results conservatively
  influence the entire session.
- Secure mode deliberately blocks unmediated MCP resource, prompt, sampling, and custom methods
  rather than implementing them.
- Tool requests carrying MCP `_meta` progress metadata are rejected in v0.1; that optional protocol
  surface has not yet been included in policy evaluation and signed argument evidence.
- Pins trust the first observed definition and have no explicit re-approval flow. Cross-process
  multi-server ownership/provenance is incomplete.
- The downstream MCP server is launched on the host. Per-call routing does not contain that process.
- The stock CLI has no production sandbox runner/profile or controlled DNS/egress broker.
- Trusted-direct downstream calls have no configured response timeout, and child stderr is not
  actively drained; a stalled or noisy downstream can hang a session.
- gVisor/Firecracker isolation, complete limits, digest binding, lifecycle cleanup, and egress
  enforcement have not been tested on a privileged Linux host.
- Receipt append happens after an allowed side effect; a store failure cannot roll the action back.
  The retained chain also has no external anchor that proves its tail was not deleted.
- The dual-model boundary has no live provider or trusted opaque-value resolver.
- The LangGraph seam is not connected to LangGraph; OpenAI Agents SDK and Pydantic AI adapters are
  absent.
- No live adaptive attack generator, automated red-team loop, or representative benchmark matrix is
  present.

## Current blockers

- No agreed provider/model cost and time budget for representative AgentDojo control and CapGate
  matrices.
- This host is Darwin arm64; `runsc`, Firecracker, Kata, KVM, and privileged Linux conformance are
  unavailable.
- No Linux runner/profile/egress-broker implementation exists to validate Stage 2 honestly.
- No external receipt checkpoint/key-custody design exists for log completeness and replacement
  resistance.
- No repository license has been selected. The code should not be described as open source until the
  owner chooses one.

## Ordered next steps

1. Review and commit this v0.1 slice, push it, and confirm both CI matrix jobs and the offline demo
   pass from the remote workflow.
2. Choose a license and create a `v0.1.0` research-prototype tag/release with the explicit nonclaims
   from the README.
3. Agree a benchmark provider/model/cost/time matrix, then run identical clean-revision undefended
   and CapGate AgentDojo cases whose control attack actually succeeds.
4. Add explicit argument/result provenance and freeze utility regressions caused by conservative
   session taint.
5. Move sandbox validation to a supported Linux host; implement the trusted runner and egress broker
   before claiming isolation.
6. Add pin re-approval and shared multi-server provenance, then integrate one real framework adapter.

## Local validation

```bash
.venv/bin/ruff check .
.venv/bin/mypy --strict src tests examples
.venv/bin/pytest -q
.venv/bin/python examples/offline_demo/run.py
```

Current result: Ruff passed, strict mypy passed, pytest passed **358 tests**, and the offline demo
completed with every control check true. CI is configured but has not been observed remotely for
this unpushed worktree.
