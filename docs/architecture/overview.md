# Architecture Overview

Last refresh: **2026-05-10** (v1.1.4).

## Design Philosophy

nein is a **type-safe nftables rule generator** for the AGNOS ecosystem.
It provides Cyrius values that map to nftables concepts (tables, chains,
rules, sets, NAT, policies) and renders them to nftables syntax for
application via `nft -f -` (fork + pipe + execve from `src/lib/apply.cyr`).

Key principles:

- **Type safety over string templating.** Enum variants (per ADR-0008)
  for match types, verdicts, protocols, families, and hooks prevent
  invalid combinations at construction. The Cyrius type-check arc
  (default-on at v5.10.26+) adds a second layer at the
  `(s: cstring): i64` interface boundary on validators and
  constructors — a wrong-type arg fails the build, not the rule.
- **Validate before apply.** All caller-supplied strings flow through
  `validate_*` in `src/lib/validate.cyr` before rendering. `apply_firewall`
  calls `firewall_validate` automatically; `add_rule_live` and friends
  validate each parameter before interpolation.
- **Feature-gated modules** (per ADR-0003). Consumers pull in only what
  they need. Core types (rule, table, chain, set, validate) are always
  available; NAT, policy, bridge, engine, mesh, config, geoip, and netns
  are optional. The `mcp` module is blocked on the bote Cyrius port
  (roadmap v2.0.0).
- **Render, don't execute** (per ADR-0001). Most of the library is pure
  rule generation. Only `src/lib/apply.cyr` shells out to `nft`.
  `firewall_render` is observable before any apply, so callers can size
  the ruleset and refuse if implausible.

## Module Map

The on-disk layout (paths relative to repo root):

```
src/
  main.cyr            — top-level include graph + main() entry
  lib/
    error.cyr         — NeinError enum + nein_ok/nein_err/nein_err_code
    validate.cyr      — 8 public validators (security boundary)
    rule.cyr          — Match (30 variants), Verdict (13 variants), Rule
    set.cyr           — NftSet, NftMap (named sets + verdict maps)
    nat.cyr           — DNAT, SNAT, masquerade, redirect, DnatRange
    chain.cyr         — Chain, ChainType, Hook, Policy, ChainRule (ADR-0005)
    table.cyr         — Table, Family, Define, Flowtable, CtTimeout
    firewall.cyr      — Top-level Firewall manager (add_table, validate, render)
    builder.cyr       — Pre-built configs (basic_host_firewall, container_bridge, service_policy)
    policy.cyr        — Kubernetes-style NetworkPolicy
    geoip.cyr         — Country-CIDR interval sets (dual-stack)
    mesh.cyr          — Envoy sidecar redirect rules
    bridge.cyr        — Container bridge (port maps + isolation groups, ADR-0007)
    engine.cyr        — Multi-agent PolicyEngine (dispatch chains + per-agent in/out)
    config.cyr        — String→enum dispatchers for TOML/JSON/CLI inputs
    netns.cyr         — Per-agent network namespace firewall builder
    apply.cyr         — nft execution layer (fork+pipe+execve)
    inspect.cyr       — Live firewall status parser
```

Each `.cyr` file is `include`d from `src/main.cyr` in dependency order:
core (error, validate) → primitive types (rule, set, nat, chain, table)
→ aggregator (firewall) → feature modules → integrators (apply, inspect).

## Data Flow

```
caller's Cyrius code (e.g. stiva, daimon, aegis, sutra)
        │
        ▼
  construction:  firewall_new() → table_new() → chain_base() →
                 chain_add_rule(rule_new(verdict_accept()))
        │
        ▼
  validation:    firewall_validate(fw)  ──→  Err(ERR_INVALID_RULE) if bad
        │
        ▼
  rendering:     firewall_render(fw)    ──→  Str of nftables syntax
        │
        ▼
  apply:         apply_firewall(fw)     ──→  fork → pipe → execve /sbin/nft -f -
                                              │
                                              └─→ stderr drained, exit observed,
                                                  Ok(0) / Err(ERR_NFT_FAILED|PERMISSION_DENIED)
```

The apply layer is the only path that touches privileges; everything
else is pure rendering and can run with no permissions.

## Type Boundary

The public-fn surface is tracked in
[`docs/api-surface.snapshot`](../api-surface.snapshot) (348 fns as of
v1.1.3). The CI gate fails on unexplained adds or removes.

Conventions:

- **`cstring`** — null-terminated C string. Used at the API boundary
  for caller-supplied identifiers (table/chain names, addresses,
  interface names, comments, raw nftables fragments).
- **`Str`** — Cyrius value type (data ptr + length pair). Used
  internally for built rulesets and string-builder outputs. The only
  public fn taking `Str` is `apply_ruleset_str`.
- **`i64`** — port numbers, handles, enum discriminants, struct
  pointers (Cyrius doesn't distinguish pointer types).

The cstring boundary is the security surface — see threat model T-1.

## Rendering Idioms

Three CLAUDE.md-mandated idioms structure nein's internal code. v1.3.0
audited and confirmed adoption across the library.

### `str_builder` over manual offset-tracked writes

Every module that renders nftables grammar uses `str_builder_*` from
the stdlib for accumulation, not manual `var buf[N]` + offset
arithmetic. Call counts as of v1.3.0:

| Module | `str_builder_*` calls | Module | `str_builder_*` calls |
|--------|----------------------|--------|----------------------|
| table | 54 | netns | 26 |
| apply | 41 | bridge | 28 |
| engine | 39 | chain | 18 |
| policy | 10 |  | |

Modules with zero `str_builder` usage — `validate`, `config`, `builder`
— don't render strings: validate scans bytes, config dispatches enums,
builder composes pre-built values. The match holds.

Three legitimate `var buf[N]` patterns remain:
- `pipe_in/err/out[16]` in `apply.cyr` — fd pairs returned by
  `sys_pipe` (4 bytes × 2 fds; required syscall ABI shape)
- `errbuf/buf[4096]` in `apply.cyr` — `sys_read` capture targets for
  stderr/stdout draining (required for pipe semantics)
- `buf[20]` in `_sb_add_hex` (`rule.cyr`) — reverse-write scratch for
  hex digits, copied into a str_builder at the end (correct usage)

The CI security-scan gate flags any new `var buf[≥4096]` for review;
≥ 65536 fails the build.

### Vec-of-pointers over hashmap for known-bounded sets

When the consumer-facing API exposes indexed iteration over a small,
bounded collection (e.g. agents in a `PolicyEngine`, isolation groups
in a `BridgeFirewall`), nein uses a Vec of pointer-sized handles with
a linear `_find_index` lookup, not a hashmap. Hashing is justified
only when the collection grows unbounded or lookups dominate.

Concrete instances:

- `engine.cyr` — `_pe_find_index(pe, agent_id)` walks the agent vec
  linearly. PolicyEngine instances typically carry < 100 agents; the
  vec stays warm in L1 cache and the dispatch chains generated downstream
  are also vec-ordered, so iteration locality matches.
- `bridge.cyr` — `bf_add_port_mapping(bf, pm)` linear-scans for
  duplicate `(host_port, protocol)` pairs. Same reasoning: small,
  bounded, lookup-rare relative to iteration.

This is ADR-0008-adjacent (typed enums over strings — same theme of
"prefer concrete over indexed") and is consistent with the CLAUDE.md
rule. It is not promoted to its own ADR because the pattern is
self-documenting at the call sites.

## Consumer Integration

The library has four declared downstream consumers in the AGNOS
ecosystem, each pulling a subset of the module surface:

| Consumer | Module surface | Purpose |
|----------|---------------|---------|
| **stiva** | bridge, nat | Container bridge networking, port mappings |
| **daimon** | engine, mesh, policy | Service-mesh network policy, agent access control |
| **aegis** | builder, geoip, firewall | Host firewall + GeoIP blocking |
| **sutra** | config, builder | Fleet-wide firewall playbooks (blocked on full TOML, roadmap v2.0.0) |

As of v1.1.4 none of these have wired the nein dep in their
`cyrius.cyml` yet — the integration work is part of each consumer's
own roadmap. The `dist/nein.cyr` single-file bundle (roadmap v1.2.0)
will be the canonical consumption form.

## Architectural Decisions

The decision history lives in [`docs/decisions/`](../decisions/) as ADRs.
The ones with on-going relevance:

| ADR | Decision | Module |
|-----|----------|--------|
| 0001 | Render rules as strings, execute via `nft` stdin | apply |
| 0002 | Validate all inputs before rendering | validate, firewall |
| 0003 | Feature-gate optional modules | (all) |
| 0004 | `Raw` match variant as injection-conscious escape hatch | rule |
| 0005 | Unify filter and NAT rules via ChainRule | chain |
| 0006 | Named sets and maps rendered inside table blocks | set, table |
| 0007 | Set-based isolation rules (O(1) lookup vs N² rules) | bridge |
| 0008 | Typed enums over strings for closed sets | (all) |
| 0009 | Non-exhaustive public structs for forward-compat | (all) |
