# CapGate build status — 2026-08-16 IST

## v0.1 milestone

**DONE — research-prototype scope.** CapGate now has a hardened stdio MCP tool-call boundary, a
framework-neutral synchronous mediator, a narrow real LangGraph `ToolNode` integration, two offline
end-to-end demonstrations, a public security model, a complete beginner guide, a code-linked
learning path, and CI configuration. The milestone remains narrower than the original four-stage
research roadmap.

The v0.1 claim is:

> A fail-closed tool-call mediation prototype exposed through a hardened MCP path and a tested
> LangGraph slice, with capability and source-to-sink policy, persistent MCP tool-definition
> pinning, and signed replayable audit receipts.

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
  comparator, and a narrow synchronous LangGraph `StateGraph`/`ToolNode` path are tested. No live
  dual-model flow, adaptive attack run, red-team loop, or broad framework compatibility exists.

## Measured numbers

### Offline scenario corpus — measured 2026-08-20

Produced by `python bench/run_scenarios.py --matrix`, reports at
[`bench/reports/scenario-corpus-latest.json`](bench/reports/scenario-corpus-latest.json) and
[`bench/reports/scenario-matrix-latest.json`](bench/reports/scenario-matrix-latest.json).
16 attacks, 11 benign flows; deterministic, no API key, no network. All 16 attacks breach
undefended, so none is vacuous, and each must block under the *specific* rule it was written
to exercise.

| Provenance | Rules | Containment | False-block rate |
|---|---|---|---|
| session-global | default | 75% (12/16) | 18.2% (2/11) |
| session-global | `--strict-integrity` | 100% (16/16) | 54.5% (6/11) |
| value-level | default | 75% (12/16) | 9.1% (1/11) |
| value-level | `--strict-integrity` | **100%** (16/16) | **9.1%** (1/11) |

Value-level provenance ([design note](docs/design-notes/VALUE_LEVEL_PROVENANCE.md), now
implemented) stores pass-through tool results behind unforgeable opaque references, so exact
lineage travels outside the model while everything unreferenced falls back to session
influence. That dissolves the coverage/utility tradeoff the 2026-08-17 status recorded: the
strict integrity rule previously cost half the benign corpus and now costs one flow —
`email-summary-needs-comprehension`, which is refused in every mode *by construction* because
the planner must read the untrusted email raw. A test asserts that residual is never quietly
recovered. The four destructive attacks remain uncontained under default rules in both
provenance modes and are reported as the known gap.

**This is not an ASR and is not comparable to published AgentDojo results.** It measures
whether enforcement holds against a scripted planner that obeys every injected instruction
perfectly — a worst-case attacker, not a sampled model. Because the corpus is authored rather
than sampled, it shows the encoded flows are contained, not that all real-world flows are.
See [`bench/reports/README.md`](bench/reports/README.md).

### AgentDojo — still unmeasured, now out of scope

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

The second local proof runs without an LLM or network:

```bash
.venv/bin/python examples/langgraph_security_demo.py
```

It uses a real compiled `StateGraph` and `ToolNode`. A harmless status call and private read execute;
the later private-plus-untrusted external send blocks under `flow.lethal_trifecta`; the sink handler
is not invoked; and three signed receipts replay without retaining the raw marker.

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
- Evidence-validating adaptive comparator plus a real, thin LangGraph `ToolNode` wrapper around the
  framework-neutral mediator.
- No-network MCP and LangGraph security demos and pinned two-version CI workflow.

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
- The LangGraph slice is synchronous, serializes calls per mediator, supports the standard
  `ToolMessage` path, and requires trusted labels for every top-level argument. It rejects
  multi-call turns, injected state/store/runtime arguments, Pydantic v1 or custom-transform tool
  schemas, non-idempotent normalization, and `Command` results; it has no sandbox executor,
  streaming/checkpoint/interrupt proof, or broad compatibility claim. Each isolated graph run must
  use a fresh mediator/context/session. OpenAI Agents SDK and Pydantic AI adapters are absent.
- No live adaptive attack generator, automated red-team loop, or representative benchmark matrix is
  present.

## Current blockers

- No predeclared, authorized provider/model/task matrix exists for a representative AgentDojo
  control and CapGate comparison.
- This host is Windows 11 (previously Darwin arm64); `runsc`, Firecracker, Kata, KVM, and
  privileged Linux conformance are unavailable. Sandbox isolation is now out of scope rather
  than blocked.
- No external receipt checkpoint/key-custody design exists for log completeness and replacement
  resistance.
- No repository license has been selected. The code should not be described as open source until the
  owner chooses one.

## Ordered next steps

1. ~~Add explicit argument/result provenance and freeze utility regressions caused by
   conservative session taint.~~ **Done 2026-08-20** — value-level provenance implemented and
   measured; the regression freeze is `tests/integration/test_scenarios.py`.
2. Choose a license and create a `v0.1.0` research-prototype tag/release with the explicit nonclaims
   from the README.
3. Agree a benchmark provider/model/cost/time matrix, then run identical clean-revision undefended
   and CapGate AgentDojo cases whose control attack actually succeeds.
4. A CaMeL-style quarantined reader, to soundly recover comprehension-plus-external-send flows —
   the one benign class value-level provenance cannot.
5. Move sandbox validation to a supported Linux host; implement the trusted runner and egress broker
   before claiming isolation.
6. Add pin re-approval and shared multi-server provenance, then generalize the tested LangGraph slice
   only from concrete use cases.

## Local validation

```bash
.venv/bin/ruff check .
.venv/bin/mypy --strict src tests examples
.venv/bin/pytest -q
.venv/bin/python examples/offline_demo/run.py
.venv/bin/python examples/langgraph_security_demo.py
```

Current result on Windows 11 / Python 3.13.2 (2026-08-20): Ruff passed, strict mypy passed
across 96 source files, pytest passed **461 tests with 4 skips**, and both credential-free
offline demos completed with every asserted control true. The skips are POSIX-only pin-store
permission and symlink tests. CI runs `ubuntu-latest` and `windows-latest` on Python 3.11 and
3.14; the first fully green remote run is commit `f7266a6`.

## Scope change — 2026-08-16

The project is now **LangGraph-focused**. The MCP proxy is **frozen**: it works, it is tested, and
it stays as the evidence that the engine is framework-neutral, but it is not being extended.
gVisor, Firecracker, the egress broker, paid AgentDojo runs, and the OpenAI Agents SDK and
Pydantic AI adapters are **out of scope**; risk-class routing and its no-downgrade rule remain.
Measurement moves to a deterministic offline scenario corpus driven by a scripted compromised
planner, reporting containment rate and false-block rate. See
[`learning/09-roadmap.md`](learning/09-roadmap.md).

### Completed since the last status

- **Human-in-the-loop approval.** `REQUIRE_APPROVAL` now suspends a checkpointed LangGraph run
  through `interrupt_for_approval` instead of silently blocking. A grant satisfies the
  capability gate only: the pipeline re-runs with `approved=True` and every remaining check
  still applies, so an approved call carrying private, untrusted-influenced data to an external
  sink is still blocked. Only the exact boolean `True` approves, no approver configured still
  blocks, and both outcomes are recorded as `policy.approval.granted` / `policy.approval.denied`
  in the signed chain.
- **Offline scenario corpus.** 12 attacks with undefended controls and 10 benign flows, each
  attack required to block under the specific rule it exercises. Runs in CI.

- **Cross-platform baseline.** Seven Windows-only test failures fixed — credential-free child
  environments now carry `SYSTEMROOT`, POSIX-only permission and symlink tests skip with stated
  reasons, a path assertion is separator-independent, and oversized parametrized test IDs are
  labelled (Windows caps environment variables at 32767 characters, which pytest's
  `PYTEST_CURRENT_TEST` exceeded). Windows added to the CI matrix.
- **`source_tags` validation.** Previously any list of strings was accepted, so a typo such as
  `secret` for `secrets` silently disabled a source-to-sink deny pair with no error. A bare tag
  must now name a `DataSourceKind`; free-form breadcrumbs must be namespaced (`mcp:mail`).
- **Enum disambiguation.** `taint.sources.SourceKind` is now `OriginKind`; `flow.sources.SourceKind`
  is now `DataSourceKind`.
- **Receipt-store tail caching.** `last_state` no longer re-parses the whole log per append;
  the cache is invalidated whenever the file size differs from the last scan.
- **Configurable deny pairs.** An optional `deny:` section in the tool-metadata file replaces the
  built-in defaults; omitting it keeps them.

### Known gap left deliberately unfixed

`classify_source` injects an `OriginKind` value as a bare source tag, and some of those values are
not `DataSourceKind` members — `OriginKind.WEB` yields `web`, which does not match the
`untrusted_web` → `shell.exec` deny pair. Those tools rely on the lethal-trifecta rule alone.
Mapping the enums would tighten enforcement and change which calls block, so it requires an
explicit decision rather than a silent change.
