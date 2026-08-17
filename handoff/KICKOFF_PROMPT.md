# Kickoff prompt for a new session

Paste the block below verbatim as your first message in a fresh chat. It is written to be
pasted, not edited — it points the assistant at the handoff docs rather than repeating them,
so it stays correct as the project moves.

---

```
I'm continuing work on CapGate, a security runtime for AI agents. It lives at
D:\dev\interpose-deva (Windows, venv at .venv, Python 3.13).

Before doing anything, read these in order — they are written for exactly this handoff:

  handoff/README.md          start here
  handoff/GOALS.md           why this exists, deadline, hard constraints
  handoff/CURRENT_STATUS.md  every measured number and where it came from
  handoff/DECISIONS.md       settled choices — do NOT relitigate these
  handoff/NEXT_STEPS.md      what to do next, in priority order
  handoff/ENVIRONMENT.md     setup, how to run everything, known gotchas

Then confirm the baseline yourself before trusting anything:

  cd D:\dev\interpose-deva
  .venv\Scripts\python.exe -m pytest -q
  .venv\Scripts\python.exe bench/run_scenarios.py
  .venv\Scripts\python.exe bench/agentdojo_attacks.py

Tell me what you found, whether it matches CURRENT_STATUS.md, and what you plan to do
first. If a number disagrees with the docs, the docs are wrong — say so.

Four things that govern how I want you to work:

1. Never report a number you did not produce by running something. If a result is bad or
   a run is blocked, say so plainly and explain why. Documented failures are this
   project's strongest asset, not a weakness to hide.
2. Commits must credit me alone. No Co-Authored-By trailers, no mention of Claude or
   Anthropic anywhere in a commit message.
3. Deterministic enforcement only. Never add a classifier, regex, or LLM judge to the
   decision path — that is the approach this project exists to argue against.
4. Report containment and false-block rate together, always. Refusing every call would
   score perfect containment.

I have a resume submission around 22-23 August 2026, so prefer work that lands and is
verified before then. Work autonomously and take yes for routine decisions; ask me only
when a choice would materially change the direction.
```

---

## If the session is specifically about value-level provenance

Add this paragraph to the block above:

```
I want to work on value-level provenance (NEXT_STEPS item 1). Step 1 (ValueStore) is
already done in src/capgate/taint/values.py. Read
docs/design-notes/VALUE_LEVEL_PROVENANCE.md first — it compares four approaches, explains
why content matching was rejected as unsound, and lists four open questions. Proceed with
its recommended answers and record each decision in the note as you take it. The
deliverable is a measured before/after false-block rate with containment held constant.
```

## If the session is specifically about the paid AgentDojo run

Add this instead:

```
I want to run the real AgentDojo benchmark with a paid API model (see handoff/BUDGET.md).
Predeclare the suite, task list, injection list, model, and attack BEFORE running
anything, and run both arms — undefended and CapGate — over identical cases. Report
utility cost alongside ASR. If the undefended baseline shows near-zero attack success,
stop and tell me rather than expanding the matrix until a number appears.
```
