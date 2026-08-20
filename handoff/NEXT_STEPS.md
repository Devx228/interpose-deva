# Next steps, in priority order

Roughly 5–6 days remain before the resume submission (~22–23 Aug 2026). Ordered by value per
day, with the honest note that item 1 is the only one that moves a *number* rather than adding
evidence around the existing ones.

## 1. Value-level provenance — the centrepiece — ✅ DONE 2026-08-20

**Shipped as designed.** All six steps landed; the design note records each open-question
decision. Measured (`python bench/run_scenarios.py --matrix`): strict integrity now costs
9.1% false blocks instead of 54.5%, with containment held at 100% and the known default-mode
gap unchanged. The residual false block is comprehension-bound by construction and frozen by
test. Remaining sub-items below are historical context only.

**Why it dominates everything else:** it is the shared prerequisite for both outstanding
critiques. Lower the false-block rate *and* make `--strict-integrity` affordable by default.
Right now they trade against each other (10% → 50%) because taint is session-wide.

Design: [`docs/design-notes/VALUE_LEVEL_PROVENANCE.md`](../docs/design-notes/VALUE_LEVEL_PROVENANCE.md).
Recommended approach is reference-based propagation with a **pessimistic fallback**: exact
lineage where it can be proven, today's session influence where it cannot. Content matching was
evaluated and rejected as unsound.

Six steps, each landing green:

1. **`ValueStore`** — ✅ **DONE**, `src/capgate/taint/values.py`, 12 tests. Unforgeable
   references, resolution failure is never permissive.
2. **Reference encoding helpers** — partly done inside `values.py` (`is_reference`,
   `REFERENCE_PREFIX`).
3. **Resolution in the adapter** — walk the normalised argument object, replace references with
   values, collect their labels. Depth- and count-bounded. After schema normalisation, before
   the mediator sees the event.
4. **Populate `arg_provenance`** with the IDs resolution actually used, making
   `label_for_call` meaningful for real.
5. **Opt-in result storage** — a tool marked reference-returning stores its result and returns
   a reference. Default off; unmarked tools behave exactly as today.
6. **`AgentContext` mode flag** — `strict_session_influence` vs `value_level`, so the corpus can
   measure both.

Steps 1–4 change no observable behaviour. **Step 5 is the first that can alter a verdict** and
must land with attack *and* benign scenarios.

**The deliverable is a before/after number**: false-block rate under session-global vs
value-level, with containment held constant. That comparison *is* the result — it turns
"I found imprecision" into "I found it, measured it, fixed it, re-measured".

Four open questions are listed at the end of the design note. The owner has said to proceed
with the recommended answers; document each decision in the note as you take it.

## 2. Finish or abandon the local AgentDojo baseline

Status: in flight, incomplete. See CURRENT_STATUS.md.

**Decide honestly and quickly.** If the undefended ASR is ≈ 0 because `qwen2.5:7b` is too weak,
write that up as the finding — *"a local 7B model cannot produce a meaningful AgentDojo
baseline, so no defense-effect claim is possible without paid API access"* — and stop. That is a
legitimate, publishable negative result and costs an hour.

If undefended ASR is materially above zero, run the identical matrix through
`--mode capgate --enforcement stage1` and you have a real ASR reduction. Budget ~2 min/case;
scope the matrix to what fits overnight.

Do not expand the matrix hoping the number improves.

## 3. Cheap credibility items (a few hours total)

- **LICENSE.** The README still says none is chosen, which reads as abandoned on a repo people
  will open. MIT is the standard portfolio choice — the owner's call to make.
- **GitHub repo description and topics.** Currently empty.
- **A demo GIF or asciinema recording** in the README. People look before they read.

## 4. Deferred — real but not before the deadline

- **Independent adversarial testing by a human.** The reviewer's stated credibility ceiling.
  The AgentDojo third-party corpus addresses the *attack authorship* half; nobody outside the
  project has attacked it.
- **Explicit declassification.** Labels only ever get more restrictive, so long sessions
  accumulate restriction with no legitimate release. A hard utility ceiling.
- **Parallel multi-call turns.** ✅ **DONE 2026-08-20** — sequential mediation in emission
  order via a condition-variable sequencer, exactly as designed; the read-secret + send
  discriminating test is in `tests/integration/test_langgraph_parallel.py`.
- **External receipt anchoring.** ✅ **DONE 2026-08-20** — `receipts/anchor.py`,
  `--anchor-file` on proxy and replay; tail deletion, log+key replacement, and a deleted
  anchor trail all fail anchored replay. Remaining: hardened anchor/key custody.
- **Mapping the two source enums.** `OriginKind.WEB` emits a `web` tag that no deny pair
  matches. Fixing it tightens enforcement and changes which calls block, so it needs a
  deliberate decision.

## Do not

- Add features without tests, or expand surface area for its own sake.
- Chase a bigger test count as a headline.
- Quietly drop a bad result. Write it down and explain it.
