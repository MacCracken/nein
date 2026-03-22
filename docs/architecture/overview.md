# Architecture Overview

## Design Philosophy

nein is a **type-safe nftables rule generator** for the AGNOS ecosystem. It
provides Rust types that map to nftables concepts (tables, chains, rules, sets,
NAT, policies) and renders them to nftables syntax for application via
`nft -f -`.

Key principles:

- **Type safety over string templating** — enum variants for match types,
  verdicts, protocols, and hooks prevent invalid combinations at compile time.
- **Validate before apply** — all string inputs are validated for injection
  characters before rendering. `Firewall::apply()` calls `validate()`
  automatically.
- **Feature-gated modules** — consumers pull in only what they need. Core types
  (rule, table, chain, set) are always available; NAT, policy, bridge, engine,
  mesh, config, geoip, and MCP are optional.
- **Render, don't execute** — most of the library is pure rule generation. Only
  the `apply` module (behind the `apply` feature) executes `nft` commands.

## Module Map

```
nein::rule       — Rule, Match, Verdict, Protocol (core building blocks)
nein::table      — Table, Family
nein::chain      — Chain, ChainType, Hook, Policy, ChainRule
nein::set        — NftSet, NftMap, SetType, SetFlag
nein::validate   — Input validation for all string fields

nein::nat        — NatRule (DNAT, SNAT, masquerade, redirect)
nein::policy     — NetworkPolicy (k8s-style ingress/egress)
nein::builder    — Pre-built configurations (host firewall, container bridge)
nein::bridge     — BridgeFirewall (port mappings, isolation groups)
nein::engine     — PolicyEngine (per-agent network policy management)
nein::mesh       — SidecarConfig (Envoy transparent proxy rules)
nein::geoip      — GeoIpBlocklist (country CIDR set blocking)
nein::config     — TOML firewall config (from_toml, to_toml)
nein::mcp        — MCP tool descriptors and request/response types
nein::apply      — nft command execution (apply, flush, add, delete)
nein::inspect    — Live firewall status queries
```

## Data Flow

```
Config / API calls
        │
        ▼
   Firewall (tables → chains → rules)
        │
        ▼
    validate()  ──→  NeinError if invalid
        │
        ▼
     render()   ──→  nftables syntax string
        │
        ▼
  apply_ruleset() ──→ nft -f - (stdin pipe)
```

## Consumer Integration

| Consumer | Module | Purpose |
|----------|--------|---------|
| stiva | bridge, nat | Container bridge networking, port mappings |
| daimon | engine, mesh, policy | Agent network policy, service mesh |
| aegis | builder, geoip | Host firewall, GeoIP blocking |
| sutra | config | Fleet-wide firewall playbooks via TOML |
