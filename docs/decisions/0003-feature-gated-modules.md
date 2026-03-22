# ADR 0003: Feature-gate optional modules

## Status

Accepted

## Context

nein has many modules (NAT, policy, bridge, engine, mesh, config, geoip, MCP)
with different dependency requirements. Consumers like stiva only need bridge
and NAT; aegis only needs builder and geoip.

## Decision

Each optional module is behind a Cargo feature flag. Core types (rule, table,
chain, set, validate, error) are always available. The `tokio` dependency is
only pulled when the `apply` feature is enabled.

Default features include the most commonly needed modules. The `full` feature
enables everything.

## Consequences

**Positive:**
- Consumers only compile what they use.
- `tokio` is not forced on consumers who only render rules.
- Clear module boundaries with explicit opt-in.

**Negative:**
- Feature combinations must be tested (CI tests default, no-default, and all).
- Cross-feature dependencies (e.g., `inspect` requires `apply`) add complexity.
- `ChainRule::Nat` variant is gated behind `nat` feature, affecting deserialization.
