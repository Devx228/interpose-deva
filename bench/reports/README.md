# Benchmark report manifest

## Valid for their own narrow claim (2)

`scenario-corpus-latest.json` — produced by `python bench/run_scenarios.py`.
`scenario-matrix-latest.json` — produced by `python bench/run_scenarios.py --matrix`; the
same corpus run in all four provenance × integrity combinations. Its claim is the
*comparison between the cells* — how the containment/false-block pair moves when
value-level provenance replaces session-global taint — under the identical caveats below.

This is **not** an AgentDojo result and must never be described as an ASR. It measures a
different question, against a different attacker:

| It measures | It does not measure |
|---|---|
| Whether enforcement holds when the planner is fully adversarial | Whether any particular model falls for an injection |
| Containment: did the sink handler actually run with the secret? | Attack success rate on a published suite |
| False-block rate: was legitimate work refused? | Utility on AgentDojo tasks |

The planner is scripted and obeys every injected instruction perfectly, so it is a worst-case
attacker rather than a sampled one. Every scenario also runs **undefended** as a control; an
attack that does not breach undefended is reported as vacuous and fails the run, because a
control that never succeeds proves nothing about the defense.

Deterministic, no API key, no network. Because the corpus is authored rather than sampled, it
shows that the encoded flows are contained — not that all real-world flows are.

Read `containment_rate` and `false_block_rate` **together**. Containment alone is meaningless:
refusing every call scores a perfect containment rate.

---

## AgentDojo reports

AgentDojo `security_results` booleans mean that an injection succeeded. CapGate therefore computes
ASR as their arithmetic mean, not `1 - mean`.

None of the 16 checked-in AgentDojo JSON reports has a non-null code revision: two explicitly store
`code_revision=null`, and fourteen older reports omit the field. None supports a representative
ASR, representative utility, defense-effect, or adaptive-robustness claim. The current runner
records a revision only when Git HEAD exists and the nonignored Git worktree is clean; missing Git,
an unborn HEAD, or any staged, unstaged, nonignored untracked, or submodule change leaves the
revision null. Ignored local files and the wider run environment are not captured by this field.

## Current command/version-backed offline utility wiring only (2)

These retain their command and AgentDojo `0.1.35` version. Each covers one ground-truth utility
case, one allowed mediated/replay-verified call, no security case, and no ASR. The routing filename
marks a code checkpoint; it is not evidence of real Stage 2 sandbox isolation.

- `agentdojo-groundtruth-capgate-policy-20260630.json`
- `agentdojo-groundtruth-capgate-stage2-routing-20260630.json`

## Historical corrected one-case pair with no defense delta (2)

This pair uses the corrected ASR meaning, but both files report ASR `0.0` and utility `1.0` for one
case, while the Stage 1 run blocked zero calls. Producing commands, dependency versions, and code
revisions were not retained, so the pair is wiring history rather than defense evidence.

- `agentdojo-oci-mini-corrected-control.json`
- `agentdojo-oci-mini-corrected-stage1.json`

## Pre-ASR-correction files invalid for security comparison (4)

These reports inverted AgentDojo's security-result meaning. They are retained only as historical
debugging artifacts; their ASR fields must not be used.

- `agentdojo-oci-mini-smoke.json`
- `agentdojo-oci-mini-capgate-smoke.json`
- `agentdojo-oci-mini-capgate-mediated-smoke.json`
- `agentdojo-oci-mini-stage1-labels-smoke.json`

## Unpaired exploratory and legacy smoke files with insufficient provenance (8)

These files lack a reproducible matched comparison, retained command/version provenance, or both.
Their one-case values cannot establish a baseline or CapGate effect.

- `agentdojo-groundtruth-capgate-smoke.json`
- `agentdojo-groundtruth-smoke.json`
- `agentdojo-oci-mini-injecagent-control-smoke.json`
- `agentdojo-oci-mini-strong-control-smoke.json`
- `agentdojo-oci-mini-system-message-control-smoke.json`
- `agentdojo-oci-mini-undefended-current-smoke.json`
- `agentdojo-oci-mini-user24-control.json`
- `agentdojo-oci-nano-user24-control.json`

## Local-model AgentDojo runs — valid as a negative result only (2)

- `agentdojo-local-qwen25-7b-utility.json`
- `agentdojo-local-qwen25-7b-undefended.json`

Real AgentDojo runs against `qwen2.5:7b` served by Ollama's OpenAI-compatible endpoint.
Measured 2026-08-17: **utility 0.20** over 5 user tasks, and **ASR 0.00** over 12 security
cases with the `direct` attack.

These establish exactly one thing, and it is a negative: the undefended attack never succeeds,
so no defense effect is measurable against this model. They must not be quoted as evidence that
CapGate reduces ASR — there is no baseline to reduce. The cause is capability, not enforcement:
0.20–0.33 utility against a published GPT-4o baseline near 84% means the agent mostly cannot
complete the benign task either.

Useful for: showing the harness runs end to end against a local model, and justifying why a
paid-API run is required for a defense-effect claim.
