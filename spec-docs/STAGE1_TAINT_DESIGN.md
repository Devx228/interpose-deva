# Stage 1 Taint Label Design

Status: approved by the project owner on 2026-06-29. Labels, source classification, whole-value
propagation, monotonic tracking, and the first source-to-sink enforcement slice implement this model.

## Security objective

CapGate must preserve two facts about every value that can influence a tool call:

1. How confidential the value is.
2. Whether an untrusted source influenced it.

The enforcement layer will use those facts at sinks. It will not try to detect malicious text.
Labels describe provenance and handling constraints, not whether content "looks safe."

## Label

A label is:

```text
(confidentiality, integrity, source_tags)
```

Confidentiality is ordered from least to most restrictive:

```text
public < internal < secret
```

Integrity is ordered from most to least trusted for safe combination:

```text
trusted < untrusted
```

`source_tags` is a set of provenance identifiers such as `web`, `email`, or `mcp:github`.
Tags support explanation and source-to-sink rules; they do not change trust by themselves.

## Join

Combining values uses a least-upper-bound join:

- confidentiality: choose the more restrictive level;
- integrity: untrusted if either input is untrusted;
- source tags: set union.

The join must be commutative, associative, and idempotent. It must never reduce confidentiality,
turn untrusted data into trusted data, or discard a source tag. The bottom label is
`(public, trusted, {})`.

## Initial source classification

Trusted only when explicitly identified:

- authenticated direct user instruction;
- system prompt;
- signed configuration.

Untrusted by default:

- MCP tool descriptions;
- MCP tool results;
- web content;
- email bodies;
- file/PDF uploads;
- RAG retrievals;
- unknown or missing provenance.

"Trusted" means permitted to influence control flow under the configured trust boundary. It does
not mean benign. Authentication and authorization must establish whether a direct user instruction
belongs in the trusted category.

Source kind determines integrity, not confidentiality. Confidentiality must come from explicit
tool/data metadata. For example, a secret-store result is classified as `secret` by its registered
source metadata, while an ordinary web result begins as `public`. CapGate must not inspect content
with regexes or an LLM to guess confidentiality or trust.

## Propagation rules

1. Start with whole-value labels. Field- or substring-level tracking is deferred.
2. A deterministic local transformation receives the join of all influencing inputs.
3. A tool-call argument receives the join of every provenance value that produced it.
4. A tool result joins its registered source label with the labels of arguments that influenced it.
5. Model rewriting, summarization, or copying never cleanses taint.
6. Missing provenance is `public/untrusted/{unknown}` and therefore fails toward lower integrity.
7. No implicit declassification exists. Any future declassification must be an explicit,
   separately audited policy decision.

## Tradeoffs

Whole-value tracking is simple and hard to bypass, but it can over-taint large objects and reduce
utility. Field-level tracking could recover utility later but adds aliasing and serialization risks.
The first implementation chooses whole-value tracking so the security invariant is understandable
and testable before optimizing precision.

This model cannot infer secrets that were never labeled by source metadata. That limitation is
intentional: deterministic enforcement depends on explicit data contracts. Content detection may be
added as supplemental labeling, but never as the primary security boundary.

## Approved review decisions

- whole-value tracking is acceptable for the first Stage 1 benchmark;
- unknown provenance should be public plus untrusted, rather than confidential by default;
- direct user instructions are trusted only after authentication/authorization;
- tool-result confidentiality comes from explicit tool metadata;
- no declassification is allowed in the first enforcement pass.
