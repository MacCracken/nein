# ADR-007: Set-Based Isolation Rules

## Status: Accepted

## Context

Bridge isolation groups generated O(n^2) explicit rules — one per src/dst CIDR pair. With 10 CIDRs per group, that's 100 rules. PolicyEngine outbound host restrictions similarly generated O(ports * hosts) rules.

## Decision

Replace explicit per-pair rules with nftables named sets + set lookup matches:
- Each isolation group gets one `NftSet` (type `ipv4_addr`, flag `interval`) containing its CIDRs
- One rule per group: `ip saddr @set_name ip daddr @set_name accept`
- PolicyEngine outbound hosts use one named set per agent

## Consequences

- O(1) rules per group instead of O(n^2)
- nftables handles set membership efficiently in kernel space
- Sets require `interval` flag for CIDR ranges
- Rendered output changes (existing tests updated)
