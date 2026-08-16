# 07 — Code walkthrough

Concepts assembled. Now follow one real tool call through the actual code, in the LangGraph
path you will be working in.

## Run it first

```bash
python examples/langgraph_security_demo.py
```

Output (one line, reformatted here):

```json
{
  "public_status": "ALLOW",
  "read_private": "ALLOW",
  "send_external": "BLOCK",
  "send_rule_id": "flow.lethal_trifecta",
  "send_reached_sink": false,
  "receipt_count": 3,
  "receipts_replayed": true,
  "raw_marker_in_receipts": false,
  "model_api_used": false,
  "network_used": false
}
```

Three calls: harmless status → allowed. Private read → allowed. External send → **blocked, sink
never reached**. Three signed receipts that replay cleanly, with the private marker appearing
nowhere in the log.

No LLM. A scripted planner issues the calls, so the result is identical every run.

## The four layers

```
LangGraph StateGraph
        │
        ▼
  ToolNode  ──►  adapters/langgraph.py     translation only, zero security logic
        │
        ▼
  engine/mediator.py                        ordering: decide, execute, observe, receipt
        │
        ▼
  engine/pipeline.py                        the five questions
        │
        ▼
  receipts/signer.py                        hash, sign, chain, append
```

The critical property: **security decisions live in the engine, never in the adapter.** That is
why the same engine also drives an MCP proxy. An adapter that grew its own policy logic would
make the framework the security boundary — exactly what the project set out not to do.

---

## Layer 1 — the adapter

[`src/capgate/adapters/langgraph.py`](../src/capgate/adapters/langgraph.py)

Entry point is
[`build_secure_tool_node`](../src/capgate/adapters/langgraph.py#L62), which wraps a real
LangGraph `ToolNode` using its `wrap_tool_call` hook. Inside
[`wrap_tool_call`](../src/capgate/adapters/langgraph.py#L83), in order:

**Reject unsupported shapes.**
[`_require_single_tool_call_turn`](../src/capgate/adapters/langgraph.py#L192) rejects a turn
with parallel tool calls — thread scheduling is not a deterministic security order, so v0.1
refuses rather than guessing. (Fixing this properly is on the roadmap.) Tools using
`InjectedState`, `InjectedStore`, or `ToolRuntime` are rejected too: those values are added
*after* interception, so they would never appear in policy evaluation or receipt evidence.

**Normalise the arguments.**
[`_validated_tool_arguments`](../src/capgate/adapters/langgraph.py#L215) runs the args through
the tool's Pydantic schema — and then runs them through *again*, requiring an identical result:

```python
normalized = _json_object(schema.model_validate(arguments).model_dump(mode="json"))
repeated = _json_object(schema.model_validate(normalized).model_dump(mode="json"))
if repeated != normalized:
    raise ValueError("LangGraph tool argument normalization must be idempotent")
```

Why? If normalisation is not idempotent, the object you *audited* could differ from the object
the handler actually *receives*. The receipt would describe a call that never happened. Custom
validators and serializers are rejected for the same reason.

**Attach labels.** The caller supplies a trusted `label_arguments` function. Labels come from
controlled graph-input provenance — never guessed from keywords, never decided by asking a
model whether a value "looks sensitive."

**Build a framework-neutral event.**

```python
@dataclass(frozen=True)
class ToolCallEvent:
    session_id: str
    server: str
    tool: str
    arguments: JsonObject
    arg_provenance: dict[str, str]
    request_id: JsonValue
```

From here down, nothing knows LangGraph exists.

**Translate the outcome back.** On rejection the wrapper returns an error `ToolMessage` with
deliberately generic content and a minimal artifact:

```python
content="CapGate rejected this tool-call outcome."
artifact={"capgate": {"verdict": ..., "rule_id": ..., "execution_started": ...}}
```

Generic on purpose — a detailed rejection reason fed back into the conversation is an oracle
the attacker can use to probe the policy.

---

## Layer 2 — the mediator

[`src/capgate/engine/mediator.py`](../src/capgate/engine/mediator.py)

Owns the **ordering**, which is where security properties actually live.
[`_mediate_locked`](../src/capgate/engine/mediator.py#L63):

```python
if self._failed_closed:              # 1. earlier failure poisoned the session
    return self._rejected(...)
if event.session_id != self._context.session_id:   # 2. session identity
    return self._rejected(...)

argument_label_error = _record_argument_labels(...)  # 3. labels required
if argument_label_error is not None:
    return self._rejected(...)

decision = self._pipeline.decide(self._context, event)   # 4. DECIDE
if decision.verdict != "ALLOW":
    return self._rejected(event, decision, execution_started=False)

route = self._pipeline.route_execution(event.tool)       # 5. isolation route
if route.backend is not None:
    return self._rejected(...)   # sandbox required but unavailable -> block

result = execute()                                        # 6. NOW the tool runs
json_result = _json_result(result, result_to_json)        # 7. project to JSON
self._pipeline.observe_result(...)                        # 8. label the output
self._receipt_writer.write_tool_call(...)                 # 9. record
```

Read steps 4 and 6 together. **The decision completes before `execute()` is called.** A blocked
call never reaches the handler — that is the whole ballgame, and it is enforced by ordering, not
by a check inside the handler.

Steps 7–9 all set `self._failed_closed = True` on failure. Once the mediator cannot be sure what
happened, it refuses everything afterwards rather than continuing on untrustworthy state.

The `Lock` at [`mediator.py:41`](../src/capgate/engine/mediator.py#L41) serialises calls per
mediator so taint state cannot be updated concurrently.

---

## Layer 3 — the pipeline

[`src/capgate/engine/pipeline.py`](../src/capgate/engine/pipeline.py)

The five questions from [02](02-the-gate.md), in order:

```python
def _decide(self, event, argument_label) -> Decision:
    metadata = self._tool_metadata.get(event.tool)
    if metadata is None:                                    # Q1
        return BLOCK("engine.unknown_tool")

    if self._policy is not None:
        if metadata.capability is None:                     # Q1b
            return BLOCK("policy.missing_capability")
        policy_decision = enforce(self._policy, metadata.capability)   # Q2
        if policy_decision.verdict != "ALLOW":
            return policy_decision

    flow_decision = check_flow(argument_label, metadata.sink)          # Q3+Q4
    if flow_decision is not None:
        return flow_decision

    route = route_backend(metadata.risk_class)                         # Q5
    if route.decision.verdict != "ALLOW":
        return route.decision

    return Decision(verdict="ALLOW", reason="stage1 flow checks passed", ...)
```

First non-ALLOW wins. The whole thing is wrapped in the `try/except` from
[02](02-the-gate.md) so a crash blocks.

The argument label comes from one line at the top of
[`decide`](../src/capgate/engine/pipeline.py#L36):

```python
argument_label = context.label_for_call(tuple(event.arg_provenance.values()))
```

That is where the session-global taint problem from [04](04-taint-labels.md) enters. Fixing it
means making this line meaningful.

After execution, [`observe_result`](../src/capgate/engine/pipeline.py#L83) labels the output:

```python
result_label = propagate_tool_result(argument_label, metadata.result_label)
context.record_result(_provenance_id(result_event), result_label)
```

The result inherits the join of the arguments' label and the tool's declared result label —
so the taint from call 1 reaches call 3 in the walkthrough from [05](05-flow-and-trifecta.md).

---

## Layer 4 — receipts

[`src/capgate/receipts/signer.py`](../src/capgate/receipts/signer.py)

[`write_tool_call`](../src/capgate/receipts/signer.py#L115) reads the last sequence number,
builds a `Receipt` with hashed args and results, signs the canonical bytes, and appends.
Covered fully in [06](06-receipts.md).

---

## Trace the demo

Set up in [`examples/langgraph_security_demo.py`](../examples/langgraph_security_demo.py):

| Tool | Result label | Sink | Capability |
|---|---|---|---|
| `public_status` | public / trusted | none | `read:status` |
| `read_private` | secret / untrusted, tags `{private_demo, untrusted_web}` | none | `read:private` |
| `send_external` | public / trusted | `network.external` | `send:external` |

Policy: `can: [read:status, read:private, send:external]` — all three permitted.

**Call 1 `public_status`** — metadata found, policy ALLOW, session influence is bottom, sink
`none`, risk `trusted_direct`. → **ALLOW**, handler runs. Result label `public/trusted` joins
into influence: still `public/trusted`.

**Call 2 `read_private`** — policy ALLOW, sink `none`. → **ALLOW**, handler runs. Result label
`secret/untrusted` joins into influence, which becomes **`secret/untrusted`**.

**Call 3 `send_external`** — policy ALLOW (the agent genuinely holds `send:external`). Argument
label is now the poisoned session influence: `secret/untrusted`. Sink is `network.external`,
which is in `EXTERNAL_SINKS`. All three trifecta conditions met.

→ **BLOCK**, `flow.lethal_trifecta`, `execution_started=False`.

The demo then asserts what actually matters
([lines 124-149](../examples/langgraph_security_demo.py#L124-L149)):

```python
_require(executed_tools == ["public_status", "read_private"], "unexpected tools ran")
_require(external_sink_calls == 0, "blocked external sink executed")
_require(receipts[-1].rule_id == "flow.lethal_trifecta", ...)
_require(len(replay.receipts) == 3, "receipt replay count was unexpected")
_require(MARKER not in receipt_text, "raw private marker appeared in receipts")
```

Not "an error was returned." The sink function was **never called**, and the secret is **not in
the log**.

## The exercise

Open the demo and change one thing at a time. Predict the verdict and rule ID *before* running:

1. Change `send_external`'s sink to `SinkKind.NONE`. What happens, and what does that teach you
   about misconfiguration?
2. Change `read_private`'s result label to `Confidentiality.PUBLIC`. Which trifecta condition
   fails now?
3. Remove `send:external` from the policy's `can` list. Same block, different rule ID — which?
4. Swap the order of calls 2 and 3 in the planner. Does the send get through? Why?

Question 4 is the one that teaches you the most about the current design.

---

Previous: [06 — Receipts](06-receipts.md) · Next: [08 — Where we stand](08-where-we-stand.md)
