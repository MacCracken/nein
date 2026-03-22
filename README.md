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

## Development

```sh
make check          # fmt + clippy + test + audit
make bench          # criterion benchmarks
make bench-track    # benchmark with historical tracking
make coverage       # code coverage report
make fuzz           # fuzz targets (requires nightly)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full development workflow, [docs/guides/testing.md](docs/guides/testing.md) for testing details.

## Roadmap

See [docs/development/roadmap.md](docs/development/roadmap.md) for the full roadmap. Completed work is documented in the [CHANGELOG](CHANGELOG.md).

## Documentation

- [Architecture overview](docs/architecture/overview.md)
- [Threat model](docs/development/threat-model.md)
- [Architecture decisions](docs/decisions/README.md)
- [Testing guide](docs/guides/testing.md)

## License

GPL-3.0-only — see [LICENSE](LICENSE) for details.
