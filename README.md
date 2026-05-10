# Nein

> **Nein** (German: no — as in "access denied") — programmatic nftables firewall for AGNOS

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

Nein generates nftables rulesets from composable, injection-safe primitives. Build tables, chains, and rules programmatically; validate before applying; render to `nft` syntax.

## Architecture

```
nein (this library)
  └── nft binary (system dependency, for `apply` consumers)

Consumers:
  stiva  ──→ nein (container bridge/NAT, port mapping, isolation)
  daimon ──→ nein (service mesh network policy, agent access control)
  aegis  ──→ nein (host firewall)
  sutra  ──→ nein (fleet-wide firewall playbooks)
```

## Modules (18)

| Module     | Purpose |
|------------|---------|
| `error`    | `NeinError` enum + packed Result helpers |
| `validate` | Injection-safe validators for identifiers, addresses, interfaces, comments, set elements |
| `rule`     | 30 Match variants, 13 Verdict variants, Rule struct, render/validate |
| `set`      | Named sets (ipv4_addr, ipv6_addr, inet_service, inet_proto, ifname) and verdict maps |
| `nat`      | DNAT, SNAT, masquerade, redirect, DnatRange with IPv6 bracketing |
| `chain`    | ChainType, Hook, Policy, Chain with regular and NAT rules |
| `table`    | Family, Define, Flowtable, CtTimeout, Table |
| `firewall` | Top-level manager — add_table, validate, render |
| `builder`  | Pre-built configurations: basic_host_firewall, container_bridge, service_policy |
| `policy`   | Kubernetes-style NetworkPolicy with ingress/egress rules |
| `geoip`    | Country-based blocking via interval sets (dual-stack IPv4/IPv6) |
| `mesh`     | Envoy-style sidecar proxy rules with UID/CIDR/port exclusions |
| `bridge`   | Container bridge with port mappings and O(1) set-based isolation groups |
| `engine`   | Multi-agent policy engine with dispatch chains and host restriction sets |
| `config`   | String→enum dispatchers for TOML/JSON/CLI configuration sources |
| `netns`    | Per-agent network namespace firewall builder (pairs with agnosys netns apply) |
| `apply`    | Execute rulesets via `nft -f -` (fork+pipe+execve); batch + incremental rule ops |
| `inspect`  | Query live firewall state — `status()` returns tables + rule count + raw ruleset |

## Quick Start

```cyrius
include "lib/nein.cyr"

fn main() {
    alloc_init();

    # Basic host firewall (allow established + SSH, drop rest)
    var fw = basic_host_firewall();
    var rendered = firewall_render(fw);
    syscall(1, 1, str_data(rendered), str_len(rendered));

    return 0;
}

var r = main();
syscall(60, r);
```

### Custom rules

```cyrius
var fw = firewall_new();
var t = table_new("filter", FAMILY_INET);
var input = chain_base("input", CHAIN_FILTER, HOOK_INPUT, 0, POLICY_DROP);

chain_add_rule(input, allow_established());
chain_add_rule(input, allow_tcp(22));
chain_add_rule(input, allow_tcp(8090));
chain_add_rule(input, deny_source("10.99.0.0/16"));

table_add_chain(t, input);
firewall_add_table(fw, t);

# Validate before rendering
if (is_err_result(firewall_validate(fw)) == 1) {
    # Input contained injection characters
    return 1;
}

var out = firewall_render(fw);
```

### Agent-to-agent policy

```cyrius
var np = agent_to_agent("hoosh-to-daimon", "10.0.0.1", "10.0.0.2", PROTO_TCP, 8090);
var rules = policy_to_rules(np);
```

### Container NAT

```cyrius
# Port forward host:8080 -> container:80
var dnat = port_forward(8080, "172.17.0.2", 80);

# Masquerade outbound container traffic
var masq = container_masquerade("172.17.0.0/16", "eth0");
```

### Multi-agent policy engine

```cyrius
var e = policy_engine_new();

var web = agent_policy_new("web", "10.100.1.2");
ap_allow_inbound(web, ps_tcp(80));
ap_allow_inbound(web, ps_tcp(443));
ap_allow_outbound(web, ps_quic(443));
pe_add_agent(e, web);

var fw = pe_to_firewall(e);  # Generates dispatch chains + per-agent in/out chains
```

## Security

Every string interpolated into rendered nftables syntax passes through
validators that reject dangerous characters (`;`, `{`, `}`, `|`, `\n`,
`` ` ``, `$`, `"`, NUL, CR) and enforce length limits. The `Raw` match
variant is the explicit escape hatch — not validated, caller's
responsibility (see [ADR-0004](docs/decisions/0004-raw-match-escape-hatch.md)).

The `nft` subprocess is invoked via a single pinned absolute path
(default `/usr/sbin/nft`); PATH is not consulted. Override on systems
with nft elsewhere:

```cyrius
nein_set_nft_path("/sbin/nft");        # Alpine / Void / embedded distros
```

See [SECURITY.md](SECURITY.md) and [docs/development/threat-model.md](docs/development/threat-model.md)
for the disclosure policy and full threat model.

## Development

```sh
cyrius deps                            # resolve dependencies into ./lib/
cyrius build src/main.cyr build/nein   # compile (x86_64)
cyrius build --aarch64 src/main.cyr build/nein-aarch64
cyrius test tests/nein.tcyr            # run test suite (585 assertions)
cyrius bench tests/nein.bcyr           # run benchmarks (31 benchmarks)
cyrius fuzz                            # 5 per-target fuzz drivers
```

Integration tests against a real nftables / netns live in
`tests/integration/` — run via `cyrius test tests/integration/*.tcyr`.
The pure-function assertions (path-pinning validation, parser shape)
work on any host; the live-apply assertions need root + nft, and fall
through the permission-denied class on non-permissive hosts.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.

## Deferred (blocked on upstream)

- `mcp` — blocked on [bote](https://github.com/MacCracken/bote) Cyrius port
- full TOML struct parsing — core config dispatchers shipped; full struct parsing scheduled for sutra port start

## Roadmap

See [docs/development/roadmap.md](docs/development/roadmap.md). Completed work documented in the [CHANGELOG](CHANGELOG.md).

## License

GPL-3.0-only — see [LICENSE](LICENSE).
