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

## Modules (21)

| Module     | Purpose |
|------------|---------|
| `error`    | `NeinError` enum + Result helpers |
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
| `netns`    | Per-agent network namespace firewall builder (pairs with agnodrm netns apply) |
| `apply`    | Execute rulesets via `nft -f -` (fork+pipe+execve); batch + incremental rule ops |
| `inspect`  | Query live firewall state — `status()` returns tables + rule count + raw ruleset |
| `diff`     | Live-rule diff + idempotent apply — converge the live ruleset onto a target plan with the minimal nft op set |
| `sign`     | Ed25519-signed rulesets — sign the rendered nft body, verify at-rest tampering before apply (added 1.6.1) |
| `mcp`      | MCP tool descriptors + handlers exposing nein's firewall ops over bote's Dispatcher/ToolRegistry (added 1.6.0) |

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

### Container bridge with isolation groups

```cyrius
var bf = bridge_firewall_new(bridge_config_new("br0", "172.17.0.0/16", "eth0"));

# Publish two containers
bf_add_port_mapping(bf, pm_tcp(8080, "172.17.0.2", 80));
bf_add_port_mapping(bf, pm_tcp(5432, "172.17.0.3", 5432));

# O(1) set-based isolation between tiers
var frontend = vec_new();
vec_push(frontend, "172.17.1.0/24");
bf_add_isolation_group(bf, isolation_group_new("frontend", frontend));

if (is_ok(bf_validate(bf)) == 1) {
    var out = firewall_render(bf_to_firewall(bf));
}
```

### GeoIP country blocking

```cyrius
var bl = geoip_new();

var xx = vec_new();
vec_push(xx, "198.51.100.0/24");
vec_push(xx, "203.0.113.0/24");
geoip_block_country(bl, country_block_v4("XX", xx));

# Dual-stack: IPv4 + IPv6 ranges for one country
var yy4 = vec_new(); vec_push(yy4, "192.0.2.0/24");
var yy6 = vec_new(); vec_push(yy6, "2001:db8::/32");
geoip_block_country(bl, country_block_dual("YY", yy4, yy6));

var out = firewall_render(geoip_to_firewall(bl));
```

### Anonymous set matches

```cyrius
# One rule, many ports: `tcp dport { 80, 443, 8080 }`
var ports = vec_new();
vec_push(ports, 80); vec_push(ports, 443); vec_push(ports, 8080);

var r = rule_new(verdict_accept());
var res = rule_matching_ports(r, PROTO_TCP, ports);

# Every element is validated up front — one bad address fails the whole
# call and leaves the rule untouched, rather than silently dropping it.
if (is_err_result(res) == 1) { return 1; }
```

### Dry run

```cyrius
var fw = basic_host_firewall();
firewall_set_dry_run(fw, 1);

# Validates and renders, but never spawns nft.
var r = apply_firewall(fw);

# nein_diff honors the same flag — it returns the ops it WOULD have applied.
var ops = payload(nein_diff(fw));
```

### Idempotent apply (live-rule diff)

```cyrius
# Build the target firewall.
var fw = basic_host_firewall();

# Converge the live ruleset onto the target. A chain already in sync emits
# no ops at all; a chain that differs is rebuilt — every live rule deleted and
# every target rule re-added IN ORDER. Rule order is nftables' evaluation
# semantics, so a minimal-delta append would silently reorder (fixed 1.6.10).
# All ops go out as one atomic `nft -f -` batch.
var r = nein_diff(fw);
if (is_ok(r) == 1) {
    var ops = payload(r);
    # vec_len(ops) == 0 means the live ruleset already matched the target.
}
```

`nein_diff` validates the whole target firewall before rendering anything, and
honors the dry-run flag — with `firewall_set_dry_run(fw, 1)` it returns the ops
it *would* have applied without touching nft.

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
cyrius lib sync                        # sync declared stdlib subset from pinned snapshot
cyrius deps                            # resolve git bundles into ./lib/
cyrius build src/main.cyr build/nein   # compile (x86_64)
cyrius build --aarch64 src/main.cyr build/nein-aarch64
cyrius tests                           # all suites (754 unit + 18 integration assertions)
cyrius bench tests/nein.bcyr           # run benchmarks (48 benchmarks)
cyrius fuzz                            # 5 per-target fuzz drivers
```

Dependencies do not auto-resolve — `cyrius lib sync` copies the declared
`[deps].stdlib` subset out of the pinned toolchain snapshot, then
`cyrius deps` clones the git bundles. Why each entry is declared, and why
the order matters, is written up in
[docs/development/dependencies.md](docs/development/dependencies.md).

Integration tests against a real nftables / netns live in
`tests/integration/` — run via `cyrius test tests/integration/*.tcyr`.
The pure-function assertions (path-pinning validation, parser shape)
work on any host; the live-apply assertions need root + nft, and fall
through the permission-denied class on non-permissive hosts.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow.

## Deferred

- full TOML struct parsing — core config dispatchers shipped; full struct parsing scheduled for sutra port start

## Roadmap

See [docs/development/roadmap.md](docs/development/roadmap.md). Completed work documented in the [CHANGELOG](CHANGELOG.md).

## License

GPL-3.0-only — see [LICENSE](LICENSE).
