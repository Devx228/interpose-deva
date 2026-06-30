# Benchmark report validity

AgentDojo's `security_results` booleans mean that the injection succeeded. CapGate reports ASR as
the mean of those values.

Reports generated before the ASR correction on 2026-06-29 inverted this metric and are invalid for
security comparisons. The following historical smoke files are retained only as debugging artifacts:

- `agentdojo-oci-mini-smoke.json`
- `agentdojo-oci-mini-capgate-smoke.json`
- `agentdojo-oci-mini-capgate-mediated-smoke.json`
- `agentdojo-oci-mini-stage1-labels-smoke.json`

Use `agentdojo-oci-mini-corrected-control.json` and
`agentdojo-oci-mini-corrected-stage1.json` for the current paired one-case smoke result. A one-case
smoke is wiring evidence, not a representative ASR claim.

That pair is also not evidence of a defense effect: both runs have ASR `0.0`, and the Stage 1 run
blocked zero calls. The exact producing commands were not retained in those historical reports.

`agentdojo-groundtruth-capgate-policy-20260630.json` is the first report using the current policy-
integrated runner with command and AgentDojo-version provenance. It is an offline one-case utility
and receipt-wiring check (`utility=1.0`, no security cases), not an ASR result.

`agentdojo-groundtruth-capgate-stage2-routing-20260630.json` reruns that same offline one-case check
after explicit risk routing landed. It again produced `utility=1.0`, one mediated/replay-verified
tool call, and no security cases. It is regression evidence only; ASR remains not applicable.

An OCI paired run for `user_task_0` + `injection_task_4` was attempted on 2026-06-30. The provider
call did not finish within the bounded smoke window, so no report or benchmark number was produced.
