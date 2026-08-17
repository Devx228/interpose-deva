# Current status — 17 August 2026

Every number here is reproducible from the repo. If you cannot reproduce one, treat it as
wrong and fix this file rather than quoting it.

## Test and quality baseline

```
433 passed, 2 skipped        .venv\Scripts\python.exe -m pytest -q
All checks passed            ruff check .
Success (94 source files)    mypy --strict src tests examples
```

The 2 skips are POSIX-only permission and symlink tests on Windows. CI runs
`ubuntu-latest` + `windows-latest` × Python 3.11 and 3.14.

> **Caution when quoting the test count.** A reviewer correctly flagged that a large test
> count written by the defender risks being theater: it shows the code does what its author
> intended, not that the defense holds against an adversary. Fine as an engineering signal;
> weak as a security claim. Know which room you are in.

## Containment — two corpora

`bench/run_scenarios.py` (self-authored) and `bench/agentdojo_attacks.py` (third-party):

| Corpus | Attacks written by | Default | `--strict-integrity` |
|---|---|---|---|
| `bench/scenarios.py` — 16 attacks, 10 benign | this repository | 75% | 100% |
| AgentDojo injection tasks — 26 replayable | AgentDojo researchers | 76.9% | 100% |

False-block rate (self-authored benign set only): **10% default, 50% strict**.

**The agreement between the rows is the finding**, not the raw percentages. A self-authored
corpus unconsciously fitted to its own defense would score far better than a third-party one.
It does not, and both fail on the same structural class — destructive and state-changing
actions — which is independent evidence the gap is real.

The third-party corpus also caught a misconfiguration in our own tool metadata (`get_webpage`
classified as a harmless read when fetching an attacker-supplied URL is outbound
communication). No self-authored attack had found it.

## Known gap, deliberately left visible

Six third-party and four self-authored attacks are uncontained by default. All are the same
class: **destructive or state-changing actions that leak nothing**. The lethal-trifecta rule
requires `confidentiality >= internal`, so it is structurally blind to them.

`flow.untrusted_state_change` (opt-in, `--strict-integrity`) closes this. It is opt-in because
under session-wide taint it raises the false-block rate from 10% to 50%. **The two headline
critiques — lower false positives, broader coverage — therefore pull against each other, and
value-level provenance is the shared prerequisite for both.** That argument is now backed by
numbers rather than asserted.

## Overhead

```
decision only          0.036 ms median      (policy, labels, flow rules, routing)
receipt only           1.420 ms median      (canonical JSON, 2× SHA-256, Ed25519, append)
mediated end to end    1.438 ms median
```

Enforcement is essentially free; **97% of the cost is the audit trail**. Measured against a
synthetic no-work handler, so the ratio is worst-case; the absolute per-call figure transfers.

## Lattice laws

Property-tested with Hypothesis over generated labels: commutativity, associativity,
idempotence, identity, absorption, and monotonicity. If any failed, values could be combined
into a weaker label and the source-to-sink rules would be bypassable regardless of how they
were written.

## Real-model demos (nondeterministic, excluded from CI)

All via Ollama + `qwen2.5:7b`, zero cost:

- `examples/ollama_injection_demo.py` → `MODEL_ATTEMPTED_EXFILTRATION_CAPGATE_BLOCKED_IT`
- `examples/react_agent_demo.py` → stock `create_react_agent`, agent retried the exfiltration
  **four times**, blocked every time
- `examples/quarantine_demo.py` → CaMeL dual-LLM; injection reached the extractor and **not**
  the planner

Two findings worth repeating: `mistral:latest` is too weak to chain tool calls at all, and
**task framing decides everything** — asked to "summarise this email" a model reports the
injection back to the user; asked to "handle my inbox" the same model acts on it.

## Local AgentDojo baseline — settled, negative result

Real AgentDojo runs against local `qwen2.5:7b` over Ollama's OpenAI-compatible endpoint.
Retained at `bench/reports/agentdojo-local-qwen25-7b-*.json`:

| Run | Cases | Result |
|---|---|---|
| Utility, no attack | 5 user tasks | **utility 0.20** |
| Security, `direct` attack | 12 security cases | **ASR 0.00**, utility 0.33 |

**The undefended attack succeeds zero times out of twelve.** No attack succeeding without the
defense means there is nothing for CapGate to be shown reducing, so no defense-effect claim is
possible from this setup.

The cause is model capability: 0.2–0.33 utility against a published GPT-4o baseline of ~84%. An
agent that cannot complete the benign task generally cannot be steered into the malicious one.
A stronger local model is not available — 6 GB VRAM caps this at ~7B/Q4.

**Conclusion: a local 7B model cannot produce a meaningful AgentDojo baseline.** That is the
honest finding, it is now evidence rather than a guess, and it is the empirical case for
[BUDGET.md](BUDGET.md). The harness itself works end to end, so the moment a capable model is
available the run is one command.

## Not claimed

No representative AgentDojo ASR, no adaptive-attack robustness, no validated process/filesystem/
network/VM isolation, no live human red team. `docs/LIMITATIONS.md` is the full list, including
the OWASP LLM/MCP/ASI entries marked "No".
