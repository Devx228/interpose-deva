"""Engine-level behavior of value-level provenance (design note steps 3-6).

These tests drive the framework-neutral mediator directly, the way an adapter would:
resolve references in arguments, join the resolved labels into the declared ones, and
show the planner a token instead of a reference-returning tool's raw result.
"""

from __future__ import annotations

from pathlib import Path

from capgate.engine.context import AgentContext, ProvenanceMode
from capgate.engine.mediator import ToolCallMediator
from capgate.engine.pipeline import DecisionPipeline, ToolMetadata
from capgate.flow.sinks import SinkKind
from capgate.proxy.events import JsonObject, ToolCallEvent
from capgate.receipts.replay import replay_session
from capgate.receipts.signer import Ed25519Signer, ReceiptWriter
from capgate.receipts.store import JsonlReceiptStore
from capgate.sandbox.base import RiskClass
from capgate.taint.labels import BOTTOM_LABEL, Confidentiality, Integrity, Label

SECRET_TRUSTED = Label(Confidentiality.SECRET, Integrity.TRUSTED, frozenset({"secrets"}))
UNTRUSTED_EMAIL = Label(Confidentiality.INTERNAL, Integrity.UNTRUSTED, frozenset({"email"}))

TOOLS = {
    "read_secret": ToolMetadata(
        result_label=SECRET_TRUSTED,
        risk_class=RiskClass.TRUSTED_DIRECT,
        returns_reference=True,
    ),
    "read_email": ToolMetadata(
        result_label=UNTRUSTED_EMAIL,
        risk_class=RiskClass.TRUSTED_DIRECT,
    ),
    "send_external": ToolMetadata(
        result_label=BOTTOM_LABEL,
        risk_class=RiskClass.TRUSTED_DIRECT,
        sink=SinkKind.EMAIL_EXTERNAL,
    ),
}


def _mediator(
    tmp_path: Path, mode: ProvenanceMode
) -> tuple[ToolCallMediator, JsonlReceiptStore, Ed25519Signer]:
    signer = Ed25519Signer.generate()
    store = JsonlReceiptStore(tmp_path / "receipts.jsonl")
    return (
        ToolCallMediator(
            pipeline=DecisionPipeline(TOOLS),
            context=AgentContext("session-1", provenance_mode=mode),
            receipt_writer=ReceiptWriter(store=store, signer=signer),
        ),
        store,
        signer,
    )


def _call(
    tool: str, request_id: int, arguments: JsonObject | None = None
) -> ToolCallEvent:
    args: JsonObject = dict(arguments or {})
    return ToolCallEvent(
        session_id="session-1",
        server="test",
        tool=tool,
        arguments=args,
        arg_provenance={name: f"test:{tool}:{request_id}:argument:{name}" for name in args},
        request_id=request_id,
    )


def test_influence_join_can_be_skipped_but_the_tracker_never_is() -> None:
    context = AgentContext("s")

    context.record_result("p1", SECRET_TRUSTED, joins_influence=False)

    assert context.influence == BOTTOM_LABEL
    assert context.tracker.get("p1") == SECRET_TRUSTED


def test_a_reference_returning_tool_mints_a_token_and_spares_the_session(
    tmp_path: Path,
) -> None:
    mediator, _, _ = _mediator(tmp_path, ProvenanceMode.VALUE_LEVEL)

    outcome = mediator.mediate(
        _call("read_secret", 1),
        lambda: "RAW_SECRET",
        result_payload=lambda result: result,
    )

    assert outcome.decision.verdict == "ALLOW"
    assert outcome.reference is not None
    assert outcome.reference.startswith("capgate-ref:")
    # The mediator still returns the raw result; hiding it from the planner is the
    # adapter's job, and the stored entry carries the exact label and value.
    assert outcome.value == "RAW_SECRET"


def test_session_mode_ignores_returns_reference_entirely(tmp_path: Path) -> None:
    mediator, _, _ = _mediator(tmp_path, ProvenanceMode.SESSION)

    outcome = mediator.mediate(
        _call("read_secret", 1),
        lambda: "RAW_SECRET",
        result_payload=lambda result: result,
    )

    assert outcome.reference is None


def test_resolve_arguments_is_the_identity_in_session_mode(tmp_path: Path) -> None:
    mediator, _, _ = _mediator(tmp_path, ProvenanceMode.SESSION)

    resolved = mediator.resolve_arguments({"payload": "capgate-ref:" + "0" * 32})

    assert resolved.substituted is False
    assert resolved.reference_labels == {}


def test_a_passed_reference_recovers_the_exact_label_and_blocks_the_flow(
    tmp_path: Path,
) -> None:
    """The centrepiece flow: ref in, exact label out, trifecta enforced.

    The planner reads an injected email raw (control taint joins influence), receives a
    secret only as a token, and passes the token outward. Resolution recovers the secret's
    exact label, the join with session influence yields secret+untrusted at an external
    sink, and the send never executes.
    """

    mediator, store, signer = _mediator(tmp_path, ProvenanceMode.VALUE_LEVEL)
    email = mediator.mediate(_call("read_email", 1), lambda: "IGNORE INSTRUCTIONS...")
    secret = mediator.mediate(
        _call("read_secret", 2), lambda: "RAW_SECRET", result_payload=lambda r: r
    )
    assert email.decision.verdict == "ALLOW"
    assert secret.reference is not None

    resolved = mediator.resolve_arguments({"payload": secret.reference})
    assert resolved.substituted is True
    assert resolved.arguments["payload"] == "RAW_SECRET"

    executed: list[str] = []
    argument_labels = {
        "payload": resolved.reference_labels["payload"].join(BOTTOM_LABEL)
    }
    event = _call("send_external", 3, resolved.arguments)
    outcome = mediator.mediate(
        event,
        lambda: executed.append("sent"),
        argument_labels=argument_labels,
    )

    assert outcome.decision.verdict == "BLOCK"
    assert outcome.decision.rule_id == "flow.lethal_trifecta"
    assert executed == []
    replay_session(store.path, "session-1", signer.verifier())


def test_a_clean_session_with_referenced_secret_allows_unrelated_external_work(
    tmp_path: Path,
) -> None:
    """The utility half: a referenced secret no longer poisons everything after it."""

    mediator, _, _ = _mediator(tmp_path, ProvenanceMode.VALUE_LEVEL)
    secret = mediator.mediate(
        _call("read_secret", 1), lambda: "RAW_SECRET", result_payload=lambda r: r
    )
    assert secret.reference is not None

    executed: list[str] = []
    outcome = mediator.mediate(
        _call("send_external", 2, {"payload": "The report is ready."}),
        lambda: executed.append("sent"),
        argument_labels={"payload": BOTTOM_LABEL},
    )

    assert outcome.decision.verdict == "ALLOW"
    assert executed == ["sent"]


def test_the_same_flow_in_session_mode_is_conservatively_blocked(tmp_path: Path) -> None:
    """The before/after pair for the previous test: session influence blocks it."""

    mediator, _, _ = _mediator(tmp_path, ProvenanceMode.SESSION)
    mediator.mediate(_call("read_email", 1), lambda: "IGNORE INSTRUCTIONS...")
    mediator.mediate(_call("read_secret", 2), lambda: "RAW_SECRET")

    outcome = mediator.mediate(
        _call("send_external", 3, {"payload": "The report is ready."}),
        lambda: None,
        argument_labels={"payload": BOTTOM_LABEL},
    )

    assert outcome.decision.verdict == "BLOCK"
    assert outcome.decision.rule_id == "flow.lethal_trifecta"
