# Roadmap

Completed phases (0-3) are documented in the [CHANGELOG](../../CHANGELOG.md).

## Phase 4 — Production Hardening

- [ ] Flowtables for hardware offload (high-performance NICs)
- [ ] nftables `define` variables for reusable constants
- [ ] Quota rules (byte-based rate limiting)
- [ ] Conntrack timeout policies per protocol
- [ ] Mark setting verdict (`meta mark set`, `ct mark set`)
- [ ] NAT port range mappings (`80-89 -> 8080-8089`)
- [ ] Rule insertion ordering (insert at position, not just append)
- [ ] Rule replacement operations (atomic update without delete+add)

## Phase 5 — Deep Protocol Support

- [ ] ICMP type + code matching (specific codes, not just type names)
- [ ] VLAN ID matching (802.1q)
- [ ] DSCP/ToS field matching
- [ ] IPv6 extension header matching
- [ ] Fragment header matching
- [ ] Packet type matching (broadcast, multicast, unicast)
- [ ] Enhanced logging (log level, group, queue, snaplen)
- [ ] Enhanced counters (bytes vs packets, named counters)

## Phase 6 — Ergonomics

- [ ] Bulk match builders (`.matching_ports(&[80, 443])`, `.matching_addrs(&[...])`)
- [ ] Set-based isolation rules (replace O(N^2) CIDR pairs with single set lookup)
- [ ] Set-based outbound host rules in PolicyEngine (replace O(N*M) with set)
- [ ] Declarative `Firewall` builder from struct literals
- [ ] `Table::delete()` / `Chain::delete()` methods
- [ ] Rule deduplication detection
- [ ] Validation at construction time (fail-fast builders)

## Phase 7 — Ecosystem Integration

- [ ] stiva container networking integration (in stiva repo)
- [ ] daimon agent runtime MCP handler wiring (in agnosticos repo)
- [ ] sutra playbook examples (TOML fleet configs)
- [ ] aegis host hardening profiles

## Phase 8 — QUIC Support (Network Evolution Tier 1)

QUIC uses UDP. nein must support UDP-based firewall rules for QUIC traffic alongside existing TCP rules.

- [ ] UDP port matching for QUIC connections (majra QUIC relay, daimon QUIC edge)
- [ ] QUIC-aware connection tracking (conntrack for UDP streams with QUIC connection IDs)
- [ ] Policy engine QUIC transport type (distinguish QUIC from plain UDP)
- [ ] stiva container networking: QUIC port forwarding rules
- [ ] Rate limiting for QUIC connection migration (prevent connection hijacking)

See [network-evolution.md](../../../../docs/development/network-evolution.md) in agnosticos for full architecture.
