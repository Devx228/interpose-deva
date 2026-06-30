# capgate

`capgate` is a capability-secure agent runtime under staged development. It runs as a
line-delimited stdio JSON-RPC MCP proxy, enforces explicit capability and data-flow policy, and
records signed, hash-chained receipts for intercepted tool calls. The current Stage 2 slice also
pins MCP tool definitions, rejects process-local tool shadowing, and fail-closes risky execution
unless the exact required sandbox backend is injected.

The gVisor, Firecracker, egress, and resource-control code is currently interface- and
fake-runner-tested only. No production runner or privileged Linux conformance result exists, so
this repository does not yet claim real process, network, filesystem, or VM isolation.

Stage 3 currently includes a provider-independent dual-model quarantine boundary, an offline
adaptive-report validator, and a dependency-free LangGraph call-translation seam. These are tested
contracts, not live provider, adaptive-attack, or framework-integration claims.

## Install for development

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Run checks

```bash
ruff check .
mypy --strict src tests
pytest
```

## Run AgentDojo

Put credentials in `.env` using `.env.example` as the template. Do not commit `.env`.
For OCI/OpenAI-compatible access, set `OPENAI_BASE_URL`, `OPENAI_API_KEY`, and one of
the available OCI model IDs such as `oci/openai.gpt-5.4-mini`.

```bash
.venv/bin/python bench/agentdojo_runner.py \
  --mode undefended \
  --pipeline agentdojo \
  --model "${CAPGATE_AGENTDOJO_MODEL:-oci/openai.gpt-5.4-mini}" \
  --suite workspace \
  --benchmark-version v1.2.2 \
  --user-task user_task_0 \
  --injection-task injection_task_0 \
  --out bench/reports/agentdojo-baseline-smoke.json
```

For a local smoke test that exercises AgentDojo without an external LLM:

```bash
.venv/bin/python bench/agentdojo_runner.py \
  --mode undefended \
  --pipeline ground-truth \
  --attack none \
  --suite workspace \
  --benchmark-version v1.2.2 \
  --user-task user_task_0 \
  --out bench/reports/agentdojo-groundtruth-smoke.json
```

Use `--mode capgate` to mediate AgentDojo's native Python tool runtime. CapGate delegates the
tool call unchanged, writes a signed receipt, and replay-verifies every receipt before reporting.
The report identifies this benchmark-only path as `agentdojo-runtime`; it is not an MCP transport
claim. CapGate runs bypass AgentDojo's result cache so current receipts always back the numbers.
Add `--enforcement stage1` to enable the current deterministic source-to-sink rule; the default is
`stage0` pass-through for baseline comparisons.

## Run the proxy

```bash
capgate proxy \
  --receipt-log .capgate/receipts.jsonl \
  --tool-pin-db .capgate/tool-pins.sqlite3 \
  --downstream python path/to/downstream_mcp_server.py
```

The SQLite pin database atomically persists each server/tool description+schema hash across proxy
restarts. A changed definition or unavailable/corrupt pin store fails closed; re-approval tooling
is not implemented yet.

Without security configuration, the proxy remains Stage 0 pass-through. Enable the current Stage 1
capability and flow pipeline by supplying both files:

```bash
capgate proxy \
  --policy-file src/capgate/policy/templates/research-agent.yaml \
  --tool-metadata-file path/to/tool-metadata.yaml \
  --downstream python path/to/downstream_mcp_server.py
```

Tool metadata is strict YAML. Every callable tool needs an explicit capability, result label, and
trusted risk classification:

```yaml
tools:
  search:
    capability: read:web
    confidentiality: public
    integrity: untrusted
    risk_class: trusted_direct
    source_tags: [untrusted_web]
    sink: none
```

Valid risk classes are `trusted_direct`, `fixed_risky`, and `generated_code`. Direct execution is
never inferred from a missing value. `fixed_risky` requires gVisor and `generated_code` requires
Firecracker; because the stock CLI does not yet configure a production sandbox runner/profile,
those two classes currently BLOCK rather than falling back to the downstream host process.

Supplying only one configuration file, malformed metadata, an unknown tool, or a capability not
allowed by policy fails closed.

## Replay receipts

```bash
capgate replay <session-id> --receipt-log .capgate/receipts.jsonl
```

Receipt v2 keeps arguments/results hashed and signs optional structured sandbox backend, outcome,
and image-digest metadata. Replay verifies the chain and prints those audit fields when present.

## Validate adaptive evidence

`bench/adaptive.py` compares only already-produced paired reports carrying explicit
`attacker-moves-second` provenance, a non-empty matching code revision, compatible case identity,
finite ASR/utility evidence, and replay-verified CapGate mediation. Static or incomplete reports
exit with `NOT YET MEASURED` and do not create an output file.

```bash
.venv/bin/python bench/adaptive.py \
  --control path/to/adaptive-control.json \
  --capgate path/to/adaptive-capgate.json \
  --out bench/reports/adaptive-comparison.json
```
