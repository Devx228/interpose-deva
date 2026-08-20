# CapGate v0.1 security model

CapGate v0.1 is a research prototype for deterministic mediation of MCP tool calls. It assumes
that an agent may follow hostile instructions and tries to contain the resulting action at the
tool boundary. It does not try to prove that a prompt is safe.

This document describes the intended secure mode: the proxy is started with both a capability
policy and tool-security metadata. Starting the proxy without those files enables Stage 0
pass-through behavior for measurement and debugging; pass-through mode is not a security control.

## Security objective

Before a tool action executes, CapGate should be able to answer:

1. Was the tool definition accepted through a complete `tools/list` exchange?
2. Does the agent's capability policy permit the action?
3. Did private data and untrusted influence reach a prohibited sink?
4. Does the tool require a sandbox backend, and is that exact backend available?
5. Can the decision be recorded without storing raw arguments or results?

The core goal is containment and auditability after agent compromise, not prompt-injection
detection or a claim that the model remains aligned.

## System and trust boundaries

```text
 Untrusted / potentially hostile                 Trusted control plane

 Agent or MCP client ── JSON-RPC ──> CapGate proxy
                                          │
 Tool descriptions and results ───────────┤ validate and pin definitions
                                          ├─ capability policy
                                          ├─ provenance and flow rules
                                          ├─ deterministic sandbox routing
                                          └─ receipt signer and audit store
                                                       │
                                                       ▼
                                        Downstream MCP server or sandbox
                                        (treat workload and output as hostile)
```

The model output, tool arguments, tool descriptions, tool results, uploaded or retrieved content,
generated code, and downstream workload are not trusted to make authorization decisions. Policy,
tool metadata, signing keys, pin state, and the CapGate process are trusted.

The current CLI launches its downstream MCP server directly on the host. Per-call sandbox routing
does not contain that server process. A hostile downstream server is therefore outside the security
guarantees of v0.1.

## Assets

CapGate is intended to protect:

- host files, processes, sockets, credentials, and local or cloud network access;
- private data made available to an agent or tool;
- downstream systems that tools can read from or modify;
- capability policies and trusted tool metadata;
- the receipt-signing key, receipt log, and persistent tool-pin database;
- per-session tool, token, cost, time, memory, process, and output budgets;
- the integrity of security decisions presented to operators.

## Attacker model

Assume an attacker may control or influence any of the following:

- indirect prompt content in web pages, email, files, RAG results, or tool output;
- model-generated tool names, arguments, and generated code;
- an MCP tool description or a later description change;
- malformed, duplicated, mismatched, or unexpected JSON-RPC messages;
- a downstream tool result, error, timeout, or crash;
- a workload running inside a future sandbox.

The design does not assume that text classifiers can reliably distinguish instructions from data.
It instead checks capabilities and information flow at the action boundary.

The attacker is not assumed to have arbitrary control of the trusted host, CapGate process, policy,
signing key, or pin database. Compromise of those trusted components can invalidate the guarantees
below.

## Trusted computing base

The v0.1 trusted computing base includes:

- the CapGate proxy, decision pipeline, quota ledger, receipt code, and configuration loader;
- the selected policy and tool-security metadata;
- Python, the operating system, and CapGate's cryptographic dependencies;
- the private signing key, configured public key, receipt storage, and SQLite pin store;
- for any future isolation claim, the Linux host, selected sandbox runtime, pinned images, trusted
  runner, controlled resolver, and egress broker.

OpenTelemetry export is best-effort observability, not part of the authorization boundary. An
exporter failure must not turn a durably receipted action into a different security decision.

## Supported MCP surface

Secure mode deliberately supports a narrow MCP surface.

| Message | Secure-mode behavior |
|---|---|
| `tools/list` | Validate the JSON-RPC exchange and tool definitions, apply persistent definition pins and process-local shadow checks, then record an ALLOW or BLOCK receipt. |
| `tools/call` | Require prior accepted discovery, validate the request and response, apply policy and flow decisions, route execution, then record the result. |
| Required control methods | Validate the envelope and required fields, then forward only `initialize`, `ping`, `logging/setLevel`, `notifications/initialized`, `notifications/cancelled`, `notifications/progress`, and `notifications/roots/list_changed`. |
| Other data or custom methods | BLOCK with `proxy.unmediated_method`; examples include unmediated resource, prompt, sampling, or application-specific methods. |

The forwarded control methods do not pass through the tool capability and flow pipeline. The
allowlist is intentionally explicit and small. Tool requests carrying optional MCP `_meta` progress
metadata are rejected because v0.1 does not yet bind that metadata into policy evaluation and
signed argument evidence. CapGate v0.1 is not a complete implementation of every MCP feature.

## Enforced invariants

The repository has local automated tests for these properties:

1. **Default deny.** Unknown tools, missing security metadata, malformed tool requests, undiscovered
   tools, unmediated methods, and decision errors do not execute in secure mode.
2. **Deterministic policy precedence.** A matching deny wins over approval, approval wins over
   allow, and an unmatched capability is blocked.
3. **Monotonic labels.** Combining provenance cannot lower confidentiality, restore trusted
   integrity, or remove source tags.
4. **Source-to-sink containment.** Private data influenced by untrusted content is blocked from
   configured external sinks; explicit static deny pairs are checked first.
5. **No sandbox downgrade.** Fixed risky tools route only to gVisor and generated code only to
   Firecracker. If the required executor is absent or fails, CapGate blocks instead of running on
   the host or a weaker backend.
6. **Bounded execution contracts.** Missing, invalid, exhausted, or unsupported resource limits
   block. Quota reservations count attempts and do not trust unverified usage to refund budget.
7. **Definition-change detection.** A tool's name, description, and input schema are canonically
   hashed. A later mismatch against the persisted first-seen pin is blocked.
8. **Tamper-evident retained history.** Receipts hash arguments and results, form an Ed25519-signed
   hash chain, use version-specific schemas, reject duplicate JSON keys, and fail replay on invalid
   signatures, broken links, or an absent session.
9. **Payload minimization.** Raw arguments, results, secrets, and tool output are not receipt or span
   attributes; bounded hashes and low-cardinality decision metadata are used instead.

## Fail-closed semantics

Before mediated tool execution, CapGate returns a BLOCK decision for policy denial,
approval-required actions, flow denial, invalid metadata, invalid JSON-RPC, incomplete discovery,
unavailable sandbox routing, budget exhaustion, and internal decision errors. Malformed allowlisted
control messages are also blocked before forwarding. Downstream tool and sandbox failures are
converted to sanitized errors and signed BLOCK receipts when receipt storage remains available.

`REQUIRE_APPROVAL` does not execute unless trusted code resolves it. The LangGraph adapter can
suspend the graph through `interrupt_for_approval` so a human answers; only the exact boolean
`True` approves. A grant satisfies the capability gate only — the pipeline is re-evaluated with
`approved=True` and every remaining check, including source-to-sink and lethal-trifecta rules,
still applies. An approved call carrying private, untrusted-influenced data to an external sink
is still blocked. With no approver configured, the verdict remains non-executable and must not
be treated as ALLOW.

Fail-closed does not mean transactional rollback. For a permitted downstream action, execution
currently occurs before the final receipt append. A receipt-store failure after a side effect cannot
undo that side effect; this is a documented durability gap.

## Claim matrix

"Locally verified" means covered by the repository's automated tests. It is not a production or
formal-security claim.

| Area | Status | Current claim |
|---|---|---|
| Stdio JSON-RPC MCP mediation | Locally verified | `tools/list` and `tools/call` are validated and mediated in secure mode; required control messages are allowlisted. |
| Capability and flow enforcement | Locally verified | Default-deny capability policy, conservative taint influence, static deny pairs, and the private-plus-untrusted external-sink rule execute before the tool call. |
| Signed receipts and replay | Locally verified | Retained receipts are payload-hashed, signed, chained, schema-checked, and replay-verified. |
| MCP definition pinning and shadow checks | Locally verified with limits | Definition changes persist across restarts; shadow checks are process-local and first observation is trusted. |
| OTel decision spans | Locally verified | An injected exporter receives bounded decision metadata without raw arguments or results. No live collector is claimed. |
| Sandbox routing, egress rules, and quotas | Contract-tested only | Pure routing, canonical request policy, and fake-runner adapters are tested. Real process, filesystem, network, syscall, or VM isolation is not established. |
| Dual-model quarantine | Unit-tested boundary only | Raw untrusted text stays with a tool-less extractor and the planner receives opaque references. No live provider or trusted value resolver is integrated. |
| LangGraph adapter | Locally verified narrow slice | A compiled `StateGraph` and real `ToolNode` use a thin wrapper around the framework-neutral synchronous mediator. Trusted labels are required for schema-normalized top-level arguments; multi-call turns are serialized into the planner's emission order (sequencing timeout fails closed, approval pausing refused in batches); injected state/store/runtime arguments, custom schema transforms, and non-idempotent normalization fail closed. The demo covers standard `ToolMessage` calls only; broad compatibility is not claimed. |
| Representative AgentDojo ASR and utility | **NOT YET MEASURED** | Retained local runs are wiring or utility smoke evidence, not representative protection results. |
| Adaptive robustness | **NOT YET MEASURED** | The evidence comparator rejects incompatible or static reports; no adaptive attack campaign has been run. |

See [`STATUS.md`](../STATUS.md) for the current implementation and measurement status.

## Residual risks and limitations

- **Session-wide taint is conservative, not precise lineage.** Real MCP calls do not yet populate
  `arg_provenance`; every observed tool result influences later calls in the session. This can
  over-block and does not establish field- or value-level provenance.
- **Pins use trust on first use.** A malicious definition present on first observation can become
  the accepted pin. There is no explicit re-approval workflow.
- **Shadow and provenance state is incomplete across processes.** Independent proxy processes do
  not share all server ownership and cross-server provenance decisions.
- **Receipt anchoring is only as strong as the anchor's storage.** With `--anchor-file`,
  anchored replay detects tail deletion and log-plus-key replacement relative to the recorded
  chain heads; an attacker who can rewrite the anchor file too defeats it, and no external
  custody is provisioned here. Without the flag, signatures and chaining detect modification within the
  retained log, but do not prove that a tail was not deleted or that an entire log and key were not
  replaced. There is no remote transparency log or external timestamp/notarization service.
- **Receipt durability follows execution.** A permitted side effect may complete before a receipt
  append fails. CapGate cannot roll back arbitrary external actions.
- **No real Linux isolation has been validated.** gVisor and Firecracker code currently constructs
  and tests execution plans through fake runners on macOS. The CLI has no production sandbox
  profile or trusted runner.
- **The downstream server process is host-launched.** Per-call routing does not contain a hostile MCP
  server that compromises the host before or outside a call.
- **Direct downstream availability bounds are incomplete.** Trusted-direct calls do not yet have a
  configured response timeout, and the stdio client's child stderr pipe is not actively drained. A
  stalled or noisy downstream can therefore hang or deadlock a session.
- **Policy and metadata correctness are trusted.** Missing metadata fails closed, but incorrect
  confidentiality, sink, capability, or risk labels can authorize an unsafe path.
- **Key compromise defeats receipt authenticity.** Local file permissions reduce accidental
  exposure; they do not provide hardware-backed custody or key rotation.
- **The secure MCP subset may reject legitimate clients.** Blocking unmediated resource, prompt,
  sampling, custom methods, and optional tool-request `_meta` is a deliberate compatibility tradeoff
  until those paths receive equivalent mediation.

## Research lineage

These references motivate the threat model and architecture; their published results are not
CapGate results.

- [AgentDojo](https://arxiv.org/abs/2406.13352)
- [CaMeL](https://arxiv.org/abs/2503.18813)
- [Fides](https://arxiv.org/abs/2505.23643)
- [Progent](https://arxiv.org/abs/2504.11703)
- [OWASP LLM Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP LLM Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
