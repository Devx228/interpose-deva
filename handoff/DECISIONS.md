# Decisions already made

These were reasoned through and are settled. Reopening them wastes the owner's remaining days.
If you think one is wrong, say why explicitly rather than quietly acting otherwise.

## Scope

**LangGraph is the focus.** All new work goes there.

**The MCP proxy is frozen, not deleted.** It works and is tested, and it is the *evidence* that
the engine is framework-neutral rather than "a LangChain plugin". Deleting it would remove the
strongest structural argument for the architecture. Do not extend it either.

**Cut:** gVisor / Firecracker / egress broker (unverifiable without privileged Linux), paid
AgentDojo runs, OpenAI Agents SDK and Pydantic AI adapters. Risk-class routing and its
no-downgrade rule stay.

## Architecture

**The core is framework-neutral and must stay that way.** `DecisionPipeline` and
`ToolCallMediator` import nothing from any agent framework. Adapters translate only — no
policy, taint, flow, or receipt logic in an adapter. A reviewer misread the framing as
LangGraph-coupled, which was a documentation bug, not an architecture one.

**No provider in the enforcement path, ever.** `langchain-ollama` is a separate `[ollama]`
extra used only by demos. The whole thesis is that authorization is deterministic and does not
ask a model whether something looks safe. Adding an LLM judge would build the thing this
project exists to argue against.

**Detection is not a defense.** No regex, keyword, or classifier for "spotting bad prompts"
anywhere in the enforcement path. This was reconfirmed when designing value-level provenance:
content matching was evaluated and **rejected as unsound in both directions** — an attacker
defeats it with any encoding, and it false-positives on coincidence.

## Security semantics

**Approval satisfies only the capability gate.** A human grant makes a `REQUIRE_APPROVAL`
verdict eligible to continue; the pipeline then re-runs with `approved=True` and every later
check still applies. An approved call carrying private untrusted data to an external sink is
still blocked. *Approval is permission to act, never permission to leak.*

**Only exact `True` approves.** A truthy string, an int, or a stray resume value all deny.
With no approver configured, an approval-required call still blocks — a verdict nobody can
answer must never behave like an allow.

**Unknown provenance is untrusted provenance.** Missing labels, unresolvable references, and
evicted store entries all fall back to the pessimistic session label. Never to "clean".

**Fail-closed everywhere**, including a bare `except Exception` in the decision path. That is
deliberate, not a smell.

## Measurement

**Every attack needs an undefended control.** An attack that does not breach without CapGate
proves nothing; the harness reports it as *vacuous* and fails the run.

**Every attack must block under the rule it exercises.** A coincidental block is not
containment. This caught a wrong assumption once already (EchoLeak-style scenarios block under
`flow.deny.secrets_to_network_external`, not the trifecta, because static deny pairs run first).

**Breach means the side effect happened** — the handler ran with the secret in its arguments —
not that an error was returned.

**Report containment and false-block together, always.** Refusing every call scores perfect
containment. Publishing only the flattering number is the failure mode this project exists to
avoid.

**Failures stay visible.** The corpus reports uncontained attacks rather than omitting them,
and tests freeze the known gap so it cannot widen or be quietly forgotten.

## Process

**Commit messages carry reasoning, not just changes.** `git log` is often the first thing a
reviewer reads. Each commit should build and pass on its own.

**The taint engine is design-with-human.** `AGENTS.md` and `EXECUTION_DIRECTIVE.md` both require
it: write a design note, get it reviewed, implement in small reviewable pieces. Do not autopilot
the novel core. `docs/design-notes/VALUE_LEVEL_PROVENANCE.md` exists for this reason.
