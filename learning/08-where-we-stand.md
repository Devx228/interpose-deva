# 08 — Where we stand

Honest inventory, measured on this machine (Windows 11, Python 3.13.2) on 2026-08-16.

## Test baseline

```
396 passed, 3 skipped        pytest -q
All checks passed!           ruff check .
Success: no issues found     mypy --strict src tests examples
```

Both offline demos produce their expected output. The 3 skips are the two POSIX-only pin-store
tests and one pre-existing skip.

### What the first run looked like

The very first run on this machine was **369 passed, 5 failed, 1 skipped, 2 errors** — and every
one of the seven non-passing tests was a Windows portability issue, not a security-logic failure:

| Failure | Cause | Fix |
|---|---|---|
| Both offline demo tests | subprocess spawned with `env={}`; Windows needs `SYSTEMROOT` before `import asyncio` can load its extension modules | `credential_free_environment()` in [`tests/conftest.py`](../tests/conftest.py) — still carries no credentials, just the one variable the interpreter needs |
| `test_sqlite_store_uses_private_file_permissions` | Windows has no POSIX permission bits | skipped on Windows with a stated reason |
| `test_symlink_store_is_rejected` | symlinks need admin rights or developer mode | skips if symlink creation raises |
| `test_firecracker_builds_...request` | asserted a path ends with `/firecracker` | `Path(...).name == "firecracker"` |
| 2 × `test_quarantine.py` errors | pytest sets `PYTEST_CURRENT_TEST` to the test ID, and one parametrized case was a 32769-character string — Windows caps environment variables at 32767 | short explicit `pytest.param(..., id=...)` labels |

That last one is a nice debugging story: the failure had nothing to do with the code under test.
Windows is now in the CI matrix so none of these can come back.

## Measured containment

```bash
python bench/run_scenarios.py --matrix
```

```
cell                 containment   false-block
session/default            76.5%         25.0%
session/strict            100.0%         58.3%
value/default              76.5%          8.3%
value/strict              100.0%          8.3%
```

(29 scenarios: 17 attacks, 12 benign.) Corpus in [`bench/scenarios.py`](../bench/scenarios.py),
harness in [`bench/run_scenarios.py`](../bench/run_scenarios.py), invariants enforced by
[`tests/integration/test_scenarios.py`](../tests/integration/test_scenarios.py) and CI.

The session rows show the weakness below as numbers: closing the destructive-action gap
(`strict`) used to refuse half the benign corpus, because session-global taint gave the rule
no precision to work with. The value rows are the fix — chapter
[11](11-value-level-provenance.md) — and the one remaining false block is structural by
construction, not an accident.

## What is genuinely built and tested

| Area | Where | Status |
|---|---|---|
| Capability policy + precedence | [`policy/`](../src/capgate/policy/) | Working |
| Label lattice, joins, monotonicity | [`taint/`](../src/capgate/taint/) | Working |
| Source-to-sink + lethal trifecta | [`flow/`](../src/capgate/flow/) | Working |
| Decision pipeline, fail-closed | [`engine/pipeline.py`](../src/capgate/engine/pipeline.py) | Working |
| Framework-neutral mediator | [`engine/mediator.py`](../src/capgate/engine/mediator.py) | Working |
| Signed hash-chained receipts + replay | [`receipts/`](../src/capgate/receipts/) | Working |
| LangGraph `ToolNode` adapter | [`adapters/langgraph.py`](../src/capgate/adapters/langgraph.py) | Working, single-call turns only |
| MCP stdio proxy | [`proxy/`](../src/capgate/proxy/) | Working — **frozen**, not being extended |
| MCP tool-definition pinning (TOFU) | [`mcp_security/`](../src/capgate/mcp_security/) | Working |
| OTel decision spans | [`telemetry/otel.py`](../src/capgate/telemetry/otel.py) | Working with an injected exporter |
| Offline containment corpus | [`bench/scenarios.py`](../bench/scenarios.py) | 22 scenarios, deterministic, in CI |

## Built but never wired in

This is a pattern worth noticing — several well-tested modules have **zero callers** outside
their own tests:

| Module | State |
|---|---|
| [`sandbox/egress.py`](../src/capgate/sandbox/egress.py) | 338 lines, no caller anywhere |
| [`mcp_security/isolation.py`](../src/capgate/mcp_security/isolation.py) `CrossServerIsolation` | tested, never used by the proxy |
| [`telemetry/otel.py`](../src/capgate/telemetry/otel.py) `configure_telemetry` | never called by the CLI |
| [`sandbox/limits.py`](../src/capgate/sandbox/limits.py) `SessionBudget` | a `ProxySession` parameter the CLI never passes |
| `SandboxCallExecutor` | same — so risky tools always block in real use |

Verify it yourself:

```bash
grep -rn "EgressPolicy\|CrossServerIsolation\|configure_telemetry" --include=*.py src/
```

Not a crisis — the components are correct and tested. But "we have egress control" and "egress
control runs on every call" are very different claims, and only the second one counts.

## The one real weakness — now addressed, with honest edges

**Taint was session-global.** [`AgentContext`](../src/capgate/engine/context.py) holds a single
`influence` label for the entire session; every raw tool result joins into it, and joins only
move one direction — so the first `secret / untrusted` result used to poison the session
**permanently**. Safe (it over-approximates and never misses a real attack), but a control
that blocks legitimate work gets switched off, and a switched-off control provides zero
security.

Value-level provenance (chapter [11](11-value-level-provenance.md)) fixed this where it can be
fixed soundly: pass-through values travel behind unforgeable opaque references carrying exact
lineage. On the current corpus the strict integrity rule costs 8.3% false blocks instead of
58.3%, with containment held at 100% — and the comprehension-bound workflow that references
alone cannot recover has a priced, audited path through quarantined extraction (chapter
[12](12-declassification.md)).

The edges that remain, deliberately:

- Session influence is still the default and the fallback — precision is opt-in per tool
- References are pass-through only; comprehension-bound flows still inherit session taint,
  and one corpus scenario stays false-blocked in every mode to keep that cost visible
- The MCP path is untouched: [`events.py`](../src/capgate/proxy/events.py) hardcodes
  `arg_provenance={}`, so the proxy always runs session-global

## Recently fixed

**Unvalidated `source_tags`** — was a genuine security hole. `config.py` accepted any list of
strings, so `secret` instead of `secrets` silently disabled a deny-pair rule with no error
anywhere. Now [`is_valid_source_tag`](../src/capgate/flow/sources.py) requires a bare tag to name
a known `DataSourceKind`, while free-form breadcrumbs must be namespaced (`mcp:mail`).

**The duplicate `SourceKind` enums** are now `OriginKind` (taint — how much a value may be
trusted) and `DataSourceKind` (flow — what kind of data it is).

**Receipt store no longer re-parses the whole log on every append.** The tail state is cached
per session and invalidated when the file size no longer matches the last scan, so a second
writer still forces a fresh read.

**Deny pairs are configurable** via an optional `deny:` section in the tool-metadata file.
Omitting it keeps the built-in defaults.

## Still open

**The two enums do not map onto each other.** `classify_source` injects an `OriginKind` value
as a bare source tag, and some of those values are not `DataSourceKind` members — notably
`OriginKind.WEB` produces `web`, which does **not** match the `untrusted_web → shell.exec` deny
pair. Such tools rely on the trifecta rule alone. Mapping them would tighten enforcement but
changes which calls block, so it needs a deliberate decision.

**No downstream timeout.** [`proxy/client.py:64`](../src/capgate/proxy/client.py#L64) awaits
`readline()` forever, and the child's stderr pipe is created but never drained — a downstream
writing more than ~64KB to stderr deadlocks. (MCP path, which is frozen, but worth knowing.)

**No receipt-log locking.** Two processes appending to one log will produce colliding sequence
numbers. Single-process use is the supported case.

## Explicitly not claimed

Straight from [`STATUS.md`](../STATUS.md), and worth internalising:

- No representative AgentDojo ASR or utility number
- No adaptive-attack robustness result
- No real process, filesystem, syscall, network, or VM isolation — gVisor and Firecracker are
  request builders tested against fake runners
- No live dual-model provider flow
- No LangGraph compatibility beyond the tested synchronous single-call slice

The 16 checked-in benchmark reports in [`bench/reports/`](../bench/reports/) are **all** marked
invalid for defense claims in [their manifest](../bench/reports/README.md) — wrong ASR
direction in some, missing provenance in others, one case each.

This documentation discipline is the project's best feature and it is worth protecting. It is
much easier to defend "here is exactly what I proved and exactly what I did not" than to walk
back an overclaim under questioning.

---

Previous: [07 — Code walkthrough](07-code-walkthrough.md) · Next: [09 — Roadmap](09-roadmap.md)
