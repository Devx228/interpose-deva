# Goals and constraints

## Primary goal

A portfolio project strong enough to carry a placement application, and understood well enough
to defend in an interview. **Both halves matter.** A project the owner cannot explain cold is
worth less than a smaller one he can.

## Timeline

- Resume submission: **around 22–23 August 2026** (stated as "5–6 days" on 17 Aug).
- Placements follow shortly after.

Work that cannot land and be verified before the submission date should not be started without
saying so explicitly.

## Hard constraints

**No paid model APIs.** Not a preference — a rule. It shaped the entire measurement strategy:
deterministic scripted-planner corpora, third-party attack replay, and local models via Ollama.
Never propose work that requires OpenAI/Anthropic credits.

**Commits credit Devansh alone.** No `Co-Authored-By` trailers, no mention of Claude or
Anthropic in commit messages. `includeCoAuthoredBy: false` is set in `~/.claude/settings.json`,
but verify with `git log -1 --format='%B'` after the first commit on any new machine — seven
commits once had to be rewritten and force-pushed to fix this.

**Windows.** The dev machine is Windows 11. Several bugs have come from POSIX assumptions; see
[ENVIRONMENT.md](ENVIRONMENT.md).

## What "good" looks like here

The owner has asked more than once for the project to impress a reviewer. The honest position,
which has held up:

> The target is not "no criticism." It is *"the criticisms are now about things needing a red
> team or a month of work, not holes you should have caught."*

An external reviewer's pushback directly produced the destructive-action fix, the
containment/false-block frontier, and the third-party corpus. Optimising for a reviewer who
stops finding problems means optimising for one who has stopped being useful — and an
interviewer will find them instead, at a worse moment.

## Audience

**Hiring managers and the engineers who will interview him.** Not buyers, not investors. This
changes priorities: a documented failure surface demonstrates judgment, which is worth more here
than a tuned headline metric. But note the trap — that argument is *also* a convenient excuse to
never produce a hard number, and a reviewer caught exactly that. Both are needed.
