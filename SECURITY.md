# Security policy

## Prototype status

CapGate v0.1 is a research prototype. It is not a production security boundary and comes with no
guarantee that it will prevent prompt injection, data loss, code execution, privilege abuse, or
other attacks. Several important controls are contract-tested or design-only; see the
[security model](docs/SECURITY_MODEL.md) and [current status](STATUS.md) before evaluating or using
the project.

Do not place production credentials, sensitive data, or critical systems behind CapGate based only
on this repository's tests.

## Supported versions

| Version | Security support |
|---|---|
| Current `main` / `0.1.x` prototype | Best-effort review and fixes |
| Older snapshots or forks | Not supported by this project |

No response-time, remediation-time, or long-term maintenance commitment is promised.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/Devx228/interpose-deva/security/advisories/new)
to open a private security advisory. Please do not open a public issue with exploit details, secret
material, or unredacted receipt data.

Include, when possible:

- the affected commit and component;
- a concise impact statement and the violated security invariant;
- minimal reproduction steps or a focused test;
- whether the issue requires secure mode, pass-through mode, or an experimental component;
- sanitized logs with credentials, payloads, keys, and personal data removed;
- any safe mitigation you already identified.

Reports are reviewed on a best-effort basis. The project may ask for clarification, coordinate a
fix and disclosure date, or determine that the behavior is an already documented prototype
limitation.

## Research and disclosure expectations

- Test only systems and data you own or are explicitly authorized to test.
- Use local fixtures where possible; do not target third-party MCP servers, models, or accounts.
- Do not submit live credentials, private keys, raw secrets, or sensitive receipt contents.
- Allow a reasonable private coordination period before publishing an unpatched issue.
- Report vulnerabilities in third-party dependencies to their maintainers as well as explaining the
  CapGate impact.

## No bounty or safe-harbor promise

This project has no vulnerability-reward program and makes no promise of payment, reimbursement,
credit, legal safe harbor, or acceptance of a report. Responsible, authorized research is welcome,
but participation is voluntary and at the researcher's own risk.
