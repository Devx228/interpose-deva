# Learn AI-agent security through CapGate

This path is for understanding the system well enough to change it, test it, and defend its design
in an interview. Work in order. For each module: read the small design surface, run the focused
tests, do the exercise, and answer the mastery questions without looking at the code.

All commands run locally from the repository root. They do not require an API key or network
access.

## 1. Start with the threat model

**Learn:** why prompt injection is treated as an assumed compromise and why authorization belongs
at the tool boundary.

Read:

- [`SECURITY_MODEL.md`](SECURITY_MODEL.md)
- [`STAGE1_TAINT_DESIGN.md`](../spec-docs/STAGE1_TAINT_DESIGN.md)
- [`STAGE2_ISOLATION.md`](design-notes/STAGE2_ISOLATION.md)
- [`STATUS.md`](../STATUS.md), especially "What is genuinely working and tested locally"

Run:

```bash
.venv/bin/python -m pytest -q tests/regression/test_exfiltration.py
```

Exercise: draw four boxes—agent, CapGate, downstream tool, protected systems. Mark every value and
process that may be hostile, then circle the trusted computing base.

Mastery questions:

- Why does CapGate block an unsafe action instead of deciding whether text "looks malicious"?
- Which assets remain exposed because the current downstream MCP server starts on the host?
- What is the difference between containment, prevention, and auditability?

## 2. Learn information-flow labels

**Learn:** confidentiality, integrity, provenance tags, lattice joins, and monotonic taint.

Read:

- [`taint/labels.py`](../src/capgate/taint/labels.py)
- [`taint/sources.py`](../src/capgate/taint/sources.py)
- [`taint/propagation.py`](../src/capgate/taint/propagation.py)
- [`taint/tracker.py`](../src/capgate/taint/tracker.py)
- [`engine/context.py`](../src/capgate/engine/context.py)

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/unit/test_taint.py \
  tests/unit/test_taint_tracker.py
```

Exercise: write a table for joining `public/trusted`, `internal/trusted`, and `secret/untrusted`
values. Predict each result before running the tests. Then explain why summarizing or copying a value
does not cleanse its label.

Mastery questions:

- Why must label join be commutative, associative, and idempotent?
- Why is unknown provenance untrusted but not automatically secret?
- Where does session-wide influence trade precision for safety in the current implementation?

## 3. Connect capabilities to data flow

**Learn:** least privilege, deny-by-default policy, approval as a non-executable verdict, static
source-to-sink rules, and the private-plus-untrusted external-sink rule.

Read:

- [`policy/model.py`](../src/capgate/policy/model.py)
- [`policy/dsl.py`](../src/capgate/policy/dsl.py)
- [`policy/enforce.py`](../src/capgate/policy/enforce.py)
- [`policy/confinement.py`](../src/capgate/policy/confinement.py)
- [`flow/rules.py`](../src/capgate/flow/rules.py)
- [`engine/pipeline.py`](../src/capgate/engine/pipeline.py)

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/unit/test_policy.py \
  tests/unit/test_flow.py \
  tests/unit/test_pipeline.py \
  tests/regression/test_exfiltration.py
```

Exercise: take the research-agent template and trace four requests: an explicit deny, an approval
rule, an explicit allow, and an unmatched capability. Record the verdict and rule ID. Then trace a
private, untrusted value to an external sink.

Mastery questions:

- Why is precedence `cannot` → `requires_approval` → `can` → default BLOCK?
- Why may policy narrowing happen automatically while expansion needs review?
- Why are capability and flow checks both needed?

## 4. Trace one MCP call through the proxy

**Learn:** JSON-RPC validation, accepted tool discovery, the deliberately narrow secure MCP surface,
and fail-closed handling before downstream execution.

Read:

- [`proxy/events.py`](../src/capgate/proxy/events.py)
- [`proxy/client.py`](../src/capgate/proxy/client.py)
- [`proxy/session.py`](../src/capgate/proxy/session.py)
- [`proxy/server.py`](../src/capgate/proxy/server.py)
- [`cli.py`](../src/capgate/cli.py)

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/unit/test_events.py \
  tests/unit/test_cli.py \
  tests/integration/test_proxy.py
```

Exercise: trace `tools/list`, an allowed `tools/call`, and a blocked `resources/read` from input to
response. For each path, identify validation, authorization, execution, and receipt creation.

Mastery questions:

- Why must a secure-mode tool be accepted by `tools/list` before it can execute?
- Why are only a few control methods forwarded while data and custom methods are blocked?
- What response-ID or result/error ambiguity could occur without strict JSON-RPC validation?

## 5. Understand signed receipts and replay

**Learn:** canonical serialization, payload hashes, Ed25519 signatures, hash chains, replay, and the
limits of tamper evidence.

Read:

- [`receipts/model.py`](../src/capgate/receipts/model.py)
- [`receipts/signer.py`](../src/capgate/receipts/signer.py)
- [`receipts/store.py`](../src/capgate/receipts/store.py)
- [`receipts/replay.py`](../src/capgate/receipts/replay.py)
- [`telemetry/otel.py`](../src/capgate/telemetry/otel.py)

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/unit/test_receipts.py \
  tests/unit/test_otel.py
```

Exercise: draw a three-receipt chain. Show exactly which previous hash is signed by each receipt.
Then describe what happens if an attacker changes the middle entry, deletes the final entry, or
replaces both the log and configured key.

Mastery questions:

- Why are arguments and results hashed instead of stored?
- What does a valid retained chain prove, and what does it not prove without an external anchor?
- Why can a receipt-store failure after execution leave an unaudited side effect?

## 6. Study MCP-specific attacks

**Learn:** tool poisoning, sleeper or rug-pull changes, first-seen pinning, shadow tools, and
cross-server provenance.

Read:

- [`mcp_security/pinning.py`](../src/capgate/mcp_security/pinning.py)
- [`mcp_security/store.py`](../src/capgate/mcp_security/store.py)
- [`mcp_security/isolation.py`](../src/capgate/mcp_security/isolation.py)

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/unit/test_pinning.py \
  tests/unit/test_pin_store.py \
  tests/unit/test_mcp_isolation.py
```

Exercise: model three cases: a malicious definition seen first, a definition changed after restart,
and the same tool name advertised by two servers. State which case CapGate blocks and which remains
a trust-on-first-use risk.

Mastery questions:

- Why must the description and input schema be pinned as well as the tool name?
- Why is first-seen pinning not an authenticity proof?
- Which ownership decisions are process-local today?

## 7. Learn containment engineering without overclaiming it

**Learn:** risk classification, no-downgrade routing, gVisor versus Firecracker, finite limits,
request-contract egress, DNS rebinding, and lifecycle cleanup.

Read:

- [`sandbox/base.py`](../src/capgate/sandbox/base.py)
- [`sandbox/limits.py`](../src/capgate/sandbox/limits.py)
- [`sandbox/egress.py`](../src/capgate/sandbox/egress.py)
- [`sandbox/gvisor.py`](../src/capgate/sandbox/gvisor.py)
- [`sandbox/microvm.py`](../src/capgate/sandbox/microvm.py)
- [`proxy/sandbox.py`](../src/capgate/proxy/sandbox.py)

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/unit/test_sandbox_base.py \
  tests/unit/test_sandbox_limits.py \
  tests/unit/test_egress.py \
  tests/unit/test_sandbox_backends.py \
  tests/unit/test_proxy_sandbox.py
```

Exercise: design profiles for a fixed browser tool and arbitrary generated Python. Choose a backend,
filesystem, egress contract, and limits for each. List the Linux tests needed before calling either
profile isolated.

Mastery questions:

- Why may a fixed risky program use gVisor while generated code requires a microVM?
- Why is a domain allowlist insufficient for private-data-bearing requests?
- Why do fake-runner tests prove routing contracts but not process or network isolation?

## 8. Separate untrusted tokens and evaluate evidence

**Learn:** a tool-less quarantined extractor, opaque planner references, thin framework adapters,
representative controls, ASR/utility evidence, and adaptive-comparison provenance.

Read:

- [`dual_llm/quarantine.py`](../src/capgate/dual_llm/quarantine.py)
- [`adapters/langgraph.py`](../src/capgate/adapters/langgraph.py)
- [`bench/agentdojo_runner.py`](../bench/agentdojo_runner.py)
- [`bench/adaptive.py`](../bench/adaptive.py)
- [`bench/reports/README.md`](../bench/reports/README.md)

Run:

```bash
.venv/bin/python -m pytest -q \
  tests/unit/test_quarantine.py \
  tests/unit/test_langgraph_adapter.py \
  tests/unit/test_benchmark.py \
  tests/unit/test_adaptive.py \
  tests/integration/test_agentdojo_runner.py
```

Exercise: compare three claims—"one utility task passed," "one attack did not succeed," and "the
defense reduced representative ASR." Write the evidence required for each and explain why only the
first claim is supported by the current offline smoke.

Mastery questions:

- Why must untrusted extracted values stay opaque to the privileged planner?
- Why is `VALIDATED` not equivalent to authorized tool execution?
- What provenance must match before two benchmark reports can support a defense delta?

## 9. Prove mastery with a teach-back

Run the complete local verification:

```bash
.venv/bin/ruff check .
.venv/bin/mypy --strict src tests examples
.venv/bin/python -m pytest -q
```

Run the offline demo:

```bash
.venv/bin/python examples/offline_demo/run.py
```

Then give a ten-minute explanation without notes:

1. State the attacker, protected assets, and why containment is the thesis.
2. Draw the MCP proxy, policy/flow pipeline, execution route, and receipt path.
3. Trace one allowed call and one blocked exfiltration attempt.
4. Explain three design tradeoffs: conservative taint, first-seen pins, and gVisor versus Firecracker.
5. State the nonclaims: no representative ASR, no adaptive result, no real Linux isolation, no live
   dual-model flow, and no working framework integration.

Final exercise: change one policy rule, predict the affected tests, add one regression test for a
new attack path, and explain why the test belongs at that layer. You understand the project when
you can predict the decision and rule ID before running it.

## Primary reading

Published results in these papers are research context, not CapGate measurements.

- [AgentDojo](https://arxiv.org/abs/2406.13352)
- [CaMeL](https://arxiv.org/abs/2503.18813)
- [Fides](https://arxiv.org/abs/2505.23643)
- [Progent](https://arxiv.org/abs/2504.11703)
- [OWASP LLM Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP LLM Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
