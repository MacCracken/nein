# ADR 0004: Provide Raw match variant as escape hatch

## Status

Accepted

## Context

nftables has hundreds of match expressions. Enumerating all of them in the
`Match` enum is impractical. Users need to express matches that nein doesn't
have typed variants for (e.g., `meta skuid`, `fib`, `numgen`).

## Decision

Provide `Match::Raw(String)` that emits its value verbatim into the rendered
rule. It is deliberately not validated — the caller is responsible for ensuring
the string is safe.

## Consequences

**Positive:**
- Users are never blocked by missing match types.
- New nftables features can be used immediately without a nein release.
- Keeps the `Match` enum focused on common, validated cases.

**Negative:**
- `Raw` bypasses all injection validation — security risk if user input flows in.
- Must be prominently documented as unsafe for untrusted input.
- Generated rules with `Raw` are harder to audit programmatically.
