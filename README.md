# Nein

> **Nein** (German: no — as in "access denied") — programmatic nftables firewall for AGNOS

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

Nein provides a type-safe Rust API for generating and applying nftables rules. It replaces raw `nft` command invocations and hand-written rulesets with composable, testable rule builders.

## Architecture

```
nein (this crate)
  └── nft binary (system dependency)

Consumers:
  stiva ──→ nein (container bridge/NAT, port mapping, isolation)
  daimon ──→ nein (service mesh network policy, agent access control)
  aegis ──→ nein (host firewall)
  sutra ──→ nein (fleet-wide firewall playbooks)
```

## Features

- **Type-safe rule builder** — `Rule`, `Match`, `Verdict` types compile to nftables syntax
- **NAT** — DNAT (port forwarding), SNAT, masquerade, redirect for container networking
- **Network policies** — service-level ingress/egress rules (like k8s NetworkPolicy)
- **Pre-built builders** — `basic_host_firewall()`, `container_bridge()`, `service_policy()`
- **Dry-run mode** — render rules without applying
- **Inspect** — query current firewall state
- **Tables, chains, families** — full nftables model (inet, ip, ip6, arp, bridge, netdev)

## Quick Start

```rust
use nein::{Firewall, builder};

// Basic host firewall (allow established + SSH, drop rest)
let fw = builder::basic_host_firewall();
println!("{}", fw.render());
fw.apply().await?;

// Container bridge networking
let fw = builder::container_bridge("br0", "172.17.0.0/16", "eth0");
fw.apply().await?;

// Custom rules
use nein::rule::{self, Match, Protocol};
use nein::table::{Table, Family};
use nein::chain::{Chain, ChainType, Hook, Policy};

let mut fw = Firewall::new().dry_run(true);
let mut table = Table::new("filter", Family::Inet);
let mut input = Chain::base("input", ChainType::Filter, Hook::Input, 0, Policy::Drop);

input.add_rule(rule::allow_established());
input.add_rule(rule::allow_tcp(22).comment("SSH"));
input.add_rule(rule::allow_tcp(8090).comment("daimon"));
input.add_rule(rule::allow_tcp(8088).comment("hoosh"));
input.add_rule(rule::deny_source("10.99.0.0/16"));

table.add_chain(input);
fw.add_table(table);
fw.apply().await?; // dry-run: prints but doesn't apply
```

### Network Policies (Agent-to-Agent)

```rust
use nein::policy::{self, Protocol};

// Allow hoosh to talk to daimon on port 8090
let policy = policy::agent_to_agent(
    "hoosh-to-daimon",
    "10.0.0.1",    // hoosh
    "10.0.0.2",    // daimon
    Protocol::Tcp,
    8090,
);
let rules = policy.to_rules();
```

### Container NAT

```rust
use nein::nat;

// Port forward host:8080 → container:80
let dnat = nat::port_forward(8080, "172.17.0.2", 80);

// Masquerade outbound container traffic
let masq = nat::container_masquerade("172.17.0.0/16", "eth0");
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `rules` | Core rule/table/chain types (default) |
| `nat` | NAT rules (DNAT, SNAT, masquerade) |
| `policy` | Network policy types |
| `inspect` | Query current firewall state |
| `full` | All features |

## Roadmap

### Phase 0 — Foundation
- [x] Scaffold with nftables type model
- [x] Rule builder with 10 match types and 8 verdicts
- [x] Table/chain rendering to nftables syntax
- [x] NAT rules (DNAT, SNAT, masquerade, redirect)
- [x] Network policies (ingress/egress, agent-to-agent)
- [x] Apply via `nft -f -` with stdin pipe
- [x] Pre-built builders (host firewall, container bridge, service policy)
- [x] Dry-run mode
- [x] Input validation to prevent nftables injection
- [x] Feature-gated modules (nat, policy, apply, inspect, builder, bridge)

### Phase 1 — Stiva Integration
- [x] Container bridge firewall (`BridgeFirewall`, `BridgeConfig`)
- [x] Port mapping lifecycle (add/remove per container, duplicate detection)
- [x] Network isolation between container groups (`IsolationGroup`, cross-CIDR)
- [x] Integration tests with real nftables (`NEIN_INTEGRATION=1`)
- [x] Criterion benchmarks (rule render, validate, bridge firewall, policy)

### Phase 2 — Daimon Integration (current)
- [x] Agent network policy engine (`PolicyEngine`, `AgentPolicy`, per-agent chains)
- [x] Dynamic rule operations (`add_rule`, `delete_rule`, `find_rules_by_comment`)
- [x] Service mesh sidecar proxy rules (`SidecarConfig`, Envoy defaults, transparent redirect)
- [x] MCP tool building blocks (`nein_status`, `nein_allow`, `nein_deny`, `nein_list` descriptors + request/response types)
- [x] 151 unit tests, 7 integration tests

### Phase 3 — Advanced
- [x] nftables named sets and verdict maps (`NftSet`, `NftMap`, integrated into `Table`)
- [x] IPv6 support (`SourceAddr6`, `DestAddr6`, `ip6 saddr/daddr`)
- [x] Rate limiting rules (`Match::Limit`, `rate_limit_tcp`)
- [x] Connection tracking helpers (`Match::CtHelper`)
- [x] Set membership matching (`Match::SetLookup`, `match_set`)
- [x] TOML firewall config files (`config` feature, `from_toml`/`to_toml`, round-trip)
- [x] GeoIP blocking (`geoip` feature, `GeoIpBlocklist`, country CIDR sets, dual-stack)
- [x] 255 unit tests, 7 integration tests

## Reference Code

| Source | What to Reference | Path | Maturity |
|--------|------------------|------|----------|
| **Kavach** | Seccomp/Landlock policy generation — similar pattern to nftables rule generation | `/home/macro/Repos/kavach/src/policy/` | **High** |
| **Agnosys** | Network namespace creation, existing nftables CORS/IP validation code | `userland/agnos-sys/src/` | **High** |
| **Stiva** | Container networking module — primary consumer of nein | `/home/macro/Repos/stiva/src/network.rs` | Scaffolded |
| **Daimon** `service_mesh` | Service mesh module — will use nein for network policy | `userland/agent-runtime/src/service_mesh.rs` | **Medium** (20 tests) |
| **Sutra Community** | nftables module patterns (if any playbook nft integration exists) | `/home/macro/Repos/sutra-community/` | Reference |

## License

GPL-3.0 — see [LICENSE](LICENSE) for details.
