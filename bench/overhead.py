"""Measure what CapGate costs per tool call.

A security layer that is slow does not get deployed, so the overhead is worth knowing and
worth publishing. This measures the mediated path against the same handler called directly,
and breaks the cost into its two parts:

- **decision** — metadata lookup, capability policy, label join, flow rules, risk routing.
  Pure computation, no I/O.
- **receipt** — canonical JSON, SHA-256 of arguments and result, Ed25519 signature, and an
  append to the JSONL log. This is where the time goes, and it is I/O plus a signature.

Reported as median and p95 over many iterations, because a mean hides the tail that actually
matters for a per-call cost.

The honest framing: this is a synthetic in-process handler, so the overhead is measured against
approximately zero work. A real tool call does I/O and a real agent turn waits on a model for
hundreds of milliseconds, so the *relative* cost in production is far smaller than the ratio
here. The absolute per-call numbers are the transferable part.

    python bench/overhead.py
    python bench/overhead.py --iterations 5000 --json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from capgate.engine.context import AgentContext  # noqa: E402
from capgate.engine.mediator import ToolCallMediator  # noqa: E402
from capgate.engine.pipeline import DecisionPipeline, ToolMetadata  # noqa: E402
from capgate.flow.sinks import SinkKind  # noqa: E402
from capgate.policy import parse_policy  # noqa: E402
from capgate.proxy.events import ToolCallEvent, ToolResultEvent  # noqa: E402
from capgate.receipts.signer import Ed25519Signer, ReceiptWriter  # noqa: E402
from capgate.receipts.store import JsonlReceiptStore  # noqa: E402
from capgate.sandbox.base import RiskClass  # noqa: E402
from capgate.taint.labels import Confidentiality, Integrity, Label  # noqa: E402

SESSION = "overhead-benchmark"
PAYLOAD = {"query": "quarterly revenue summary", "limit": 20}


def _pipeline() -> DecisionPipeline:
    return DecisionPipeline(
        {
            "search": ToolMetadata(
                result_label=Label(
                    Confidentiality.INTERNAL,
                    Integrity.UNTRUSTED,
                    frozenset({"tool_result"}),
                ),
                risk_class=RiskClass.TRUSTED_DIRECT,
                sink=SinkKind.NONE,
                capability="read:web",
            )
        },
        policy=parse_policy(
            "agent: overhead\ncan: [read:web]\ncannot: []\nrequires_approval: []\n"
        ),
    )


def _event(request_id: int) -> ToolCallEvent:
    return ToolCallEvent(
        session_id=SESSION,
        server="bench",
        tool="search",
        arguments=dict(PAYLOAD),
        arg_provenance={},
        request_id=request_id,
    )


def _time_loop(iterations: int, body: Callable[[int], None]) -> list[float]:
    samples: list[float] = []
    for index in range(iterations):
        start = time.perf_counter()
        body(index)
        samples.append((time.perf_counter() - start) * 1000.0)
    return samples


def _stats(samples: Sequence[float]) -> dict[str, float]:
    ordered = sorted(samples)
    return {
        "median_ms": round(statistics.median(ordered), 4),
        "p95_ms": round(ordered[int(len(ordered) * 0.95) - 1], 4),
        "mean_ms": round(statistics.fmean(ordered), 4),
    }


def measure(iterations: int, warmup: int) -> dict[str, Any]:
    def handler() -> dict[str, str]:
        return {"content": "synthetic result"}

    # 1. Baseline: the handler with nothing around it.
    baseline = _time_loop(iterations, lambda _i: (handler(), None)[1])

    # 2. Decision only: the full policy/flow/routing path, no receipt.
    pipeline = _pipeline()
    context = AgentContext(SESSION)
    decision_events = [_event(i) for i in range(iterations)]

    def decide(index: int) -> None:
        pipeline.decide(context, decision_events[index])

    for i in range(min(warmup, iterations)):
        decide(i)
    decision = _time_loop(iterations, decide)

    # 3. Receipt only: canonical JSON, two hashes, Ed25519 signature, append.
    with tempfile.TemporaryDirectory(prefix="capgate-overhead-") as directory:
        store = JsonlReceiptStore(Path(directory) / "receipts.jsonl")
        writer = ReceiptWriter(store=store, signer=Ed25519Signer.generate())
        allow = pipeline.decide(AgentContext(SESSION), _event(0))

        def receipt(index: int) -> None:
            event = decision_events[index]
            writer.write_tool_call(
                call_event=event,
                result_event=ToolResultEvent(
                    session_id=SESSION,
                    server="bench",
                    tool="search",
                    result={"content": "synthetic result"},
                    request_id=event.request_id,
                ),
                decision=allow,
            )

        for i in range(min(warmup, iterations)):
            receipt(i)
        receipt_samples = _time_loop(iterations, receipt)

    # 4. End to end: decision, execution, provenance, receipt, through the mediator.
    with tempfile.TemporaryDirectory(prefix="capgate-overhead-e2e-") as directory:
        store = JsonlReceiptStore(Path(directory) / "receipts.jsonl")
        mediator = ToolCallMediator(
            pipeline=_pipeline(),
            context=AgentContext(SESSION),
            receipt_writer=ReceiptWriter(
                store=store, signer=Ed25519Signer.generate()
            ),
        )

        def mediated(index: int) -> None:
            mediator.mediate(decision_events[index], handler)

        for i in range(min(warmup, iterations)):
            mediated(i)
        end_to_end = _time_loop(iterations, mediated)

    baseline_stats = _stats(baseline)
    e2e_stats = _stats(end_to_end)
    return {
        "iterations": iterations,
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "unmediated_handler": baseline_stats,
        "decision_only": _stats(decision),
        "receipt_only": _stats(receipt_samples),
        "mediated_end_to_end": e2e_stats,
        "overhead_median_ms": round(
            e2e_stats["median_ms"] - baseline_stats["median_ms"], 4
        ),
        "note": (
            "Measured against a synthetic in-process handler doing ~no work, so this is a "
            "worst-case ratio. A real tool call does I/O and a real agent turn waits on a "
            "model for hundreds of ms; the absolute per-call cost is the transferable number."
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    report = measure(args.iterations, args.warmup)

    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(report, sort_keys=True))
        return 0

    print(f"CapGate per-tool-call overhead  ({report['iterations']} iterations)")
    print("=" * 62)
    print(f"{'stage':<26}{'median':>10}{'p95':>10}")
    for key in ("unmediated_handler", "decision_only", "receipt_only", "mediated_end_to_end"):
        stage = report[key]
        print(f"{key:<26}{stage['median_ms']:>9.3f}ms{stage['p95_ms']:>9.3f}ms")
    print()
    print(f"added per call (median): {report['overhead_median_ms']:.3f} ms")
    print()
    print(report["note"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
