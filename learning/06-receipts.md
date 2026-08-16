# 06 — Receipts

Enforcement stops the bad action. Receipts prove what happened. In a real incident the second
one is what you actually get asked for.

## What a receipt is

Every decision — allowed *or* blocked — writes a signed record.
[`receipts/model.py:94-110`](../src/capgate/receipts/model.py#L94-L110):

```json
{
  "v": 2,
  "session_id": "a4f2...",
  "seq": 3,
  "ts": "2026-08-16T09:31:22Z",
  "server": "langgraph",
  "tool": "send_email",
  "verdict": "BLOCK",
  "rule_id": "flow.lethal_trifecta",
  "reason": "external sink blocked: private data influenced by untrusted content",
  "taint_labels": ["confidentiality:secret", "integrity:untrusted", "email"],
  "args_hash": "sha256:9f2a...",
  "result_hash": "sha256:1d84...",
  "prev_receipt_hash": "sha256:41bc...",
  "signature": "ed25519:..."
}
```

Three design choices, each worth understanding.

## 1. Arguments are hashed, never stored

```python
args_hash=hash_json(call_event.arguments),
result_hash=hash_json(result_event.result),
```

There is no `arguments` field. There is no `result` field.

**Why:** an audit log of exfiltration attempts that contains the exfiltrated data would be its
own breach. You would have built a searchable index of every secret the agent ever touched.

The hash still gives you what you need: prove two calls were identical, correlate a receipt
with an external event, detect that arguments changed between attempts — all without the log
holding the secret.

The demos verify this. [`langgraph_security_demo.py:149`](../examples/langgraph_security_demo.py#L149):

```python
_require(MARKER not in receipt_text, "raw private marker appeared in receipts")
```

A synthetic secret goes through the system and the test asserts it appears *nowhere* in the log.

**Honest limitation:** a hash is not encryption. If a value has low entropy — a 4-digit PIN, a
yes/no answer — anyone with the log can brute-force it. Receipt access stays sensitive.

## 2. Ed25519 signatures

[`receipts/signer.py`](../src/capgate/receipts/signer.py) generates a keypair on first run,
stores the private key with `0o600` permissions, and signs the canonical bytes of each receipt.

**Canonical** matters —
[`model.py:183-184`](../src/capgate/receipts/model.py#L183-L184):

```python
def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
```

Sorted keys, no whitespace. The same logical receipt must always produce the same bytes,
otherwise the hash changes when nothing meaningful did.

**What a signature proves:** these bytes were signed by the holder of this private key and have
not changed since.

**What it does not prove:** that the signer was uncompromised, or that the decision was correct.
A perfectly signed receipt can record a terrible policy decision.

## 3. Hash chaining

Each receipt contains the hash of the complete previous receipt, so they form a chain:

```
receipt 1 ─────┐
  prev: null   │ hash
               ▼
receipt 2 ─────┐
  prev: h(r1)  │ hash
               ▼
receipt 3
  prev: h(r2)
```

[`replay.py:58-67`](../src/capgate/receipts/replay.py#L58-L67):

```python
def verify_receipt_chain(receipts, verifier) -> None:
    prev_hash = None
    expected_seq = 1
    for receipt in receipts:
        if receipt.seq != expected_seq:
            raise ValueError(f"expected receipt seq {expected_seq}, got {receipt.seq}")
        if receipt.prev_receipt_hash != prev_hash:
            raise ValueError(f"receipt seq {receipt.seq} has an invalid previous hash")
        verifier.verify_receipt(receipt)
        prev_hash = receipt.receipt_hash()
        expected_seq += 1
```

Three independent checks: sequence numbers are consecutive, each link matches, each signature
verifies.

| Attack | Detected by |
|---|---|
| Edit any field of a receipt | signature |
| Delete a receipt from the middle | sequence + chain |
| Reorder receipts | sequence + chain |
| Insert a forged receipt | signature |

Try it:

```bash
capgate replay <session-id> \
  --receipt-log .capgate/receipts.jsonl \
  --public-key-file .capgate/ed25519.public
```

The offline demo does exactly this, then tampers with one field and asserts replay fails.

## What replay cannot prove — the interview question

This is the part worth being able to state unprompted.

**Tail deletion is undetectable.** Chop off the last three receipts and the remaining chain
verifies perfectly. Nothing in the log says how long it should be.

**Log-and-key replacement is undetectable.** An attacker with both files can regenerate a fully
valid chain saying whatever they like.

**A side effect can precede its receipt.** Look at the ordering in
[`mediator.py:131-181`](../src/capgate/engine/mediator.py#L131-L181): `execute()` runs, *then*
the receipt is written. If the store fails after a successful send, the email is gone and there
is no record. The code marks the session failed-closed so nothing further proceeds — but it
cannot un-send an email. Software cannot roll back the outside world.

**The fix for the first two** is an external anchor: publish the chain head somewhere you do not
control (a transparency log, a timestamping service, another team's storage). Then a truncated
log no longer matches the published head. This is not built — it's on the roadmap.

Being able to volunteer these limits is worth more than the feature itself. Anyone can say
"it's cryptographically signed." Knowing precisely what that does and does not buy you is the
senior answer.

## Schema versioning

[`model.py:137-146`](../src/capgate/receipts/model.py#L137-L146) accepts **exact** field sets
per version:

```python
if version == 1 and fields != _RECEIPT_FIELDS:
    raise ValueError("receipt v1 fields do not match the required schema")
if version == 2 and fields not in _V2_RECEIPT_FIELDS:
    raise ValueError("receipt v2 fields do not match the required schema")
```

Not "at least these fields" — exactly these. An extra field is an error.

Why so strict? An attacker who can add fields to a signed structure can sometimes shift meaning
without breaking verification. Exact schemas remove the question.

Same reasoning behind duplicate-key rejection in
[`store.py:54-60`](../src/capgate/receipts/store.py#L54-L60) — `{"verdict":"BLOCK","verdict":"ALLOW"}`
is legal JSON that different parsers read differently. Rejected outright.

## Known rough edges

Two real issues worth knowing about, both on the fix list:

**`last_state` re-reads the entire log on every write.**
[`store.py:46-51`](../src/capgate/receipts/store.py#L46-L51) parses every receipt in the file to
find the last sequence number — for every single append. That is O(n²) over a session.

**No locking.** Two processes appending to one log will interleave and produce duplicate
sequence numbers.

## Telemetry

[`telemetry/otel.py`](../src/capgate/telemetry/otel.py) emits an OpenTelemetry `execute_tool`
span per call, carrying the same decision metadata — and the same redaction rules.

Export is **best-effort** on purpose ([`otel.py:21-29`](../src/capgate/telemetry/otel.py#L21-L29)):
if the exporter throws, the failure is swallowed. A monitoring outage must not turn a durably
receipted, correctly handled call into an availability incident. Receipts are mandatory and
fail closed; telemetry is not.

---

Previous: [05 — Flow and the trifecta](05-flow-and-trifecta.md) · Next: [07 — Code walkthrough](07-code-walkthrough.md)
