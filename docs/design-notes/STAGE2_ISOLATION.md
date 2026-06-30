# Stage 2 isolation model

> **APPROVED by the project owner on 2026-06-30 for implementation**
>
> This document is a design proposal, not evidence that CapGate currently provides
> process, network, filesystem, or virtual-machine isolation.

## Decision summary

CapGate must make sandbox routing a deterministic policy decision after capability
and flow checks pass:

- Use **gVisor on Linux** for risky tools that run a fixed, pinned program over
  structured inputs, including constrained file, browser, and shell operations.
- Require a **Firecracker- or Kata-backed microVM** for arbitrary or untrusted
  LLM-generated code. Never downgrade these calls to gVisor, a plain container, or
  host execution when a microVM is unavailable.
- Block an unknown tool risk class. There is no unsandboxed fallback.
- Keep the orchestrator, policy engine, egress broker, quota ledger, receipt signer,
  and OTel exporter outside the sandbox trust boundary.

This routing favors gVisor's lower startup and operational cost where its syscall
interposition is sufficient, while reserving a hardware-virtualized boundary for
hostile generated code. A plain container is packaging, not the selected security
boundary, because it shares the host kernel.

## Threat boundary

Treat the agent, model output, tool inputs and outputs, tool process, generated code,
and any process with root inside the sandbox as hostile. The isolation plane must
protect the host, other sessions, ambient credentials, local/private networks, and
resource budgets if that hostile workload attempts filesystem escape, process abuse,
network exfiltration, or denial of service.

The trusted computing base includes CapGate's control plane, the Linux host and
kernel, the chosen gVisor/VMM runtime, pinned guest/base images, the egress broker,
and production policy. This design does not eliminate vulnerabilities in that trusted
base, hardware side channels, image supply-chain compromise, policy mistakes, or
exfiltration that an explicitly authorized destination and request contract genuinely
permit. Taint and source-to-sink checks remain mandatory before sandbox routing.

## Development and production environments

Darwin is a development surface for pure routing, policy, serialization, and backend
contract tests. It must not substitute macOS process controls or a desktop-container
VM for the production isolation claim.

Production is Linux with cgroup v2, namespaces, nftables or an equivalent enforced
network path, and either:

- gVisor `runsc`, with a pinned OCI image and no host network or host mounts; or
- Firecracker/Kata with hardware virtualization, a pinned immutable guest image, and
  a dedicated virtual network filtered outside the guest.

Firecracker offers a small VMM and strong guest boundary, but needs Linux KVM plus
image, networking, snapshot, and lifecycle machinery. Kata preserves OCI workflow
and can simplify orchestration, but adds a larger runtime stack and deployment
dependency. Either is acceptable as the microVM backend only after its boundary and
cleanup behavior pass the same Linux conformance suite.

## Network and DNS

The default profile has no egress route. Enabling network access requires a versioned,
per-tool policy; environment proxy variables alone are not an enforcement mechanism.

For an enabled profile:

1. The sandbox can reach only a CapGate-controlled egress path. Direct TCP, UDP,
   ICMP, Unix host sockets, cloud metadata endpoints, and local/private/link-local/
   loopback ranges remain blocked.
2. DNS goes only through a controlled resolver. The broker normalizes the requested
   hostname, rejects IP literals and disallowed names, checks every CNAME, rejects
   prohibited resolved ranges, pins the approved address for the connection, and
   revalidates redirects. TLS must verify the approved hostname and certificate.
3. An allowlist entry is exact by default. A suffix rule must be explicit and must
   not match the parent domain accidentally. No wildcard means `*.example.com`.
4. Allowed domains are not automatically safe exfiltration sinks. Networked tools
   that may handle private data require a tool-specific broker contract constraining
   protocol, method, path, headers, query, and body schema. Generic arbitrary HTTPS
   is not enabled for those tools.

The fourth rule is essential: a domain-only allowlist would not stop an EchoLeak-like
secret encoded into a URL sent through an otherwise allowed domain.

## Filesystem and secrets

- Boot from a digest-pinned, read-only image. Give each invocation a fresh,
  size-limited ephemeral workspace and discard it after termination.
- Do not bind-mount the project, host home, Docker/Podman socket, SSH agent, device
  nodes, browser profiles, cloud configuration, keychains, `.env`, `~/.ssh`, or the
  receipt-signing key. `/proc` and `/sys` must expose only guest/sandbox state.
- Copy only policy-declared input artifacts into the sandbox, read-only where
  possible. Never pass inherited host environment variables wholesale.
- Long-lived credentials stay outside the sandbox. A networked tool uses a
  tool-specific broker that applies scoped authentication after validating the
  request. A tool that cannot work without receiving an ambient secret is blocked
  until a separately reviewed secret-delivery design exists.

## Mandatory limits

Every production profile must contain finite, validated values; `unlimited`, missing,
negative, or backend-unsupported values make the profile invalid and the call BLOCK.

| Scope | Required limits | Enforcement owner |
|---|---|---|
| Invocation | CPU quota, memory and swap, process count, wall-clock deadline, writable bytes, stdout/stderr/result bytes | Linux runtime plus an external watchdog |
| Syscalls | Minimal syscall allowlist and an explicit total syscall/event budget when the backend can report it reliably | gVisor/seccomp or guest policy plus watchdog |
| Session | Maximum tool-call attempts, including blocked calls and retries | Trusted CapGate quota ledger |
| Model budget | Maximum input/output tokens and cost in integer micros | Trusted CapGate quota ledger |

The quota ledger atomically reserves budget before launch. Model calls reserve the
worst-case configured tokens/cost and reconcile downward only from trusted provider
usage; missing or untrusted usage never increases remaining budget. A limit breach
terminates the workload, closes streams, emits only a bounded diagnostic, and records
a BLOCK. Output overflow kills the invocation rather than merely truncating while it
continues. Exact syscall counting can be expensive and is backend-dependent; a
profile requesting it must be rejected if the selected backend cannot enforce or
observe it reliably.

## Fail-closed lifecycle

1. Capability and flow checks ALLOW; otherwise no sandbox is created.
2. Resolve the trusted risk class, backend, pinned image, egress policy, and complete
   finite limits. Atomically reserve session/model budget.
3. Create a fresh sandbox, install filesystem and network restrictions, then start
   the workload. The workload must never run before controls are active.
4. Bound all input, output, time, and usage collection outside the sandbox.
5. On startup, policy, broker, telemetry, timeout, kill, or cleanup error: prevent or
   terminate execution, mark the action BLOCK, and never retry on the host or a weaker
   backend.
6. Revoke network paths, destroy ephemeral state, and verify termination. A cleanup
   failure quarantines that worker from reuse and raises an operator-visible error.

Every attempted action, including pre-launch rejection and backend failure, must end
in a signed receipt. Receipt signing failure is itself fail-closed.

## Receipts and telemetry

Receipts are created outside the sandbox and add only bounded, sanitized metadata:

- requested and actual backend, versioned profile ID, and pinned image digest;
- configured limits, bounded observed usage, termination reason, and exit category;
- egress policy ID/hash, count of DNS/connection decisions, and stable rule IDs;
- ephemeral sandbox identifier, lifecycle state, and cleanup outcome.

Arguments, results, environment, secrets, URLs, request bodies, DNS answers, and raw
stdout/stderr are not receipt or span attributes; existing input/output hashes remain
the audit link. Destination details are hashed when correlation is required. OTel
spans mirror low-cardinality decision metadata and lifecycle timings, not sensitive
payloads. Receipt creation and signing remain mandatory and fail closed; OTel export
is best-effort and cannot turn a completed, durably receipted action into an outage.
No sandbox-controlled process can write receipts directly.

## Verification strategy

- **Unit:** deterministic risk routing; invalid/unsupported profile rejection; quota
  accounting; domain normalization, CNAME/redirect/rebinding and prohibited-IP cases;
  receipt/span redaction.
- **Backend contract:** run identical lifecycle tests against a fake backend, gVisor,
  and each microVM backend. An unavailable required capability must BLOCK.
- **Privileged Linux integration:** attempt host-file and secret reads, host socket and
  metadata access, direct DNS/egress, private-range access, namespace escape probes,
  fork/memory/CPU/output/syscall exhaustion, timeout, and post-kill persistence. Test
  concurrent sessions for cross-session filesystem and network isolation.
- **Regression:** reproduce EchoLeak/GitHub-MCP-style exfiltration through both a
  denied domain and an otherwise allowed domain carrying a disallowed request shape;
  preserve every successful bypass as a test.
- **Operations:** fault-inject runtime crashes, broker failure, receipt failure, and
  teardown failure; verify no weaker fallback and that the worker is quarantined.

Passing unit or mocked contract tests demonstrates interface behavior only. A Stage 2
isolation claim requires the privileged Linux tests against the actual production
runtime and pinned images, plus the Stage 2 attack and resource exit gates.

## Unvalidated guarantees and blockers on this host

Inspected on 2026-06-30: this host is Darwin 25.5.0 arm64. `runsc`, `firecracker`,
and `kata-runtime` are not present. Docker and Podman command-line clients are present,
but their daemon/VM state was not tested and, even if functional, would not validate
the selected Linux production boundaries.

Therefore none of the following is currently validated here: gVisor syscall
interposition; KVM/microVM isolation; cgroup enforcement; seccomp/AppArmor; Linux
namespace or nftables policy; controlled DNS/egress and rebinding resistance;
read-only/ephemeral mount isolation; hard resource termination; teardown/quarantine;
or correspondence between real runtime events and receipts/OTel. The required
blocker is a privileged Linux validation environment with the chosen runtimes,
hardware virtualization for the microVM path, controlled networking, pinned images,
and a safe attack-test target. Until that exists and the tests above pass, CapGate
must describe Stage 2 sandboxing as **design-only and unvalidated**, not isolation.

## Approved implementation decisions

- No downgrade: a missing required backend blocks; it never falls back to a plain
  container or host execution.
- Implement Firecracker before Kata for arbitrary or untrusted generated code.
- Keep the tool-specific egress broker requirement; domain allowlists alone are
  insufficient for private-data-bearing tools.
- Require every production profile to supply explicit finite limits. Do not invent
  permissive defaults when a field is missing.
- Treat syscall budgets as required only when the selected backend can enforce or
  reliably observe them; otherwise a profile requesting one is invalid.
- Signed receipts are mandatory. OTel export is best-effort after a local span is
  created, so an exporter outage does not become an availability kill switch.
