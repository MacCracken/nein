# ADR 0005: Unify filter and NAT rules via ChainRule enum

## Status

Accepted

## Context

nftables chains can contain both filter rules (match + verdict) and NAT rules
(DNAT, SNAT, masquerade, redirect). Initially, chains only held `Rule` objects.
NAT rules had to be wrapped in `Match::Raw(nat_rule.render())`, which bypassed
validation.

## Decision

Introduce `ChainRule` enum with `Rule(Rule)` and `Nat(NatRule)` variants.
Chains store `Vec<ChainRule>`. The `Chain::add_rule()` method wraps in
`ChainRule::Rule`, and `Chain::add_nat_rule()` wraps in `ChainRule::Nat`.

The `Nat` variant is gated behind `#[cfg(feature = "nat")]`.

## Consequences

**Positive:**
- NAT rules are validated alongside filter rules in `Firewall::validate()`.
- No more rendering NAT rules into `Raw` strings.
- Type-safe dispatch for render and validate via `ChainRule` methods.

**Negative:**
- `ChainRule` enum adds a layer of indirection.
- The `nat` feature gate on a variant means serialised chains with NAT rules
  can't be deserialised without the `nat` feature enabled.
