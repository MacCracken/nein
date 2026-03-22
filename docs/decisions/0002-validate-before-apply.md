# ADR 0002: Validate all inputs before rendering

## Status

Accepted

## Context

String values (IP addresses, interface names, comments) are interpolated into
rendered nftables syntax. A malicious or malformed value could inject arbitrary
nft commands via characters like `;`, `{`, `}`, or newlines.

## Decision

All string inputs pass through the `validate` module before rendering. The
`Firewall::apply()` method calls `validate()` automatically. Dangerous
characters are rejected with an error.

Validation happens at apply-time (not construction-time) to keep the builder
API ergonomic. A `validate()` method is also exposed for manual checking.

## Consequences

**Positive:**
- Prevents nftables injection from user-controlled inputs.
- Centralised validation logic in one module.
- Non-breaking API — builders accept any string, validation is deferred.

**Negative:**
- Invalid input is only caught at validate/apply time, not at construction.
- The `Match::Raw` variant deliberately bypasses validation (documented risk).
- Callers who only use `render()` without `validate()` are not protected.
