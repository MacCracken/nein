# Changelog

All notable changes to nein are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] — 2026-04-13

Complete rewrite from Rust to Cyrius. Rust source preserved in `rust-old/` for reference.

### Added

**18 modules ported with full API parity:**

- **error** — `NeinError` enum (7 variants), packed Result helpers (`nein_ok`, `nein_err`, `err_code`)
- **validate** — 8 injection-safe validators (identifier, addr, iface, ct_state, comment, log_prefix, nft_element, family)
- **rule** — 30 Match variants, 13 Verdict variants, Rule struct with render + validate. `RejectReason`, `Protocol`, `RateUnit`, `QuotaMode`, `QuotaUnit`, `PktType`, `Ipv6ExtHdr`, `CmpOp`, `LogLevel` sub-enums
- **set** — Named sets (ipv4_addr, ipv6_addr, inet_service, inet_proto, ifname) with interval/timeout/constant flags; verdict maps with Accept/Drop/Jump
- **nat** — DNAT, SNAT, Masquerade, Redirect, DnatRange with IPv6 bracket wrapping; `port_forward`, `port_range_forward`, `container_masquerade` helpers
- **chain** — ChainType, Hook, Policy; base and regular chains; ChainRule wrapper dispatches rule vs NAT rendering
- **table** — Family, Define, Flowtable, CtTimeout; render order: defines → flowtables → ct_timeouts → sets → maps → chains
- **firewall** — Top-level manager with add_table, render, full-tree validate
- **builder** — `basic_host_firewall`, `container_bridge`, `service_policy` pre-built configurations
- **policy** — NetworkPolicy with ingress/egress rules, "any" peer handling, `agent_to_agent` convenience
- **geoip** — Country-based blocking with interval sets, dual-stack IPv4/IPv6, ISO 3166-1 alpha-2 validation
- **mesh** — Envoy sidecar rules with UID/CIDR/port exclusions, configurable inbound/outbound ports, transparent TCP redirect
- **bridge** — BridgeFirewall with port mappings, O(1) set-based isolation groups, duplicate port detection
- **engine** — Multi-agent PolicyEngine with dispatch chains, per-agent in/out chains, O(1) host restriction sets; `Transport` enum (TCP/UDP/QUIC); `PortSpec` helpers
- **config** — String→enum dispatchers for TOML/JSON/CLI configuration sources (16 enum types)
- **netns** — `NamespaceFirewall` builder for per-agent network namespace rulesets (established/loopback/DNS defaults + inbound/outbound port allow-lists and host restrictions); pairs with agnosys's `netns_apply_nftables_ruleset` for in-namespace apply
- **apply** — execute rulesets via `nft -f -` using fork+pipe+execve (synchronous); batch ops (`apply_ruleset_str`, `apply_firewall`, `flush_ruleset`); table/chain ops (`flush_table`, `delete_table`, `flush_chain`, `delete_chain`); incremental rule ops (`add_rule_live`, `insert_rule_live`, `add_rule_after_live`, `replace_rule_live`, `delete_rule_live`); `list_ruleset`, `list_ruleset_with_handles`
- **inspect** — `status()` returns `FirewallStatus { tables, total_rules, raw_ruleset }` parsed from live `nft list ruleset` output

### Testing

- 580 test assertions across 42 test groups (was 409 in Rust era)
- 31 benchmarks covering validators, rule rendering, full firewall generation, multi-agent engine, and namespace firewall
- Apply path smoke-tested end-to-end: non-root `list_ruleset` returns `Err` cleanly (no crash, no hang)
- Fuzz harness covering validators, rule rendering, NAT, and config dispatchers

### Performance (Cyrius)

| Benchmark | Time |
|-----------|------|
| `validate_*` (injection checks) | 450ns–1us |
| `rule_render/simple` | 1us |
| `rule_render/complex` (6 matches + comment) | 3us |
| `nat_dnat_render` | 1us |
| `basic_host_firewall` (full render) | 13us |
| `container_bridge` | 21us |
| `mesh_render` | 24us |
| `bridge_render` (port mappings + iso) | 48us |
| `geoip_render` | 11us |
| `engine_10_agents_render` | 400us |
| `netns_render` | 34us |

### Changed

- **Language**: Rust → Cyrius (sovereign systems language, compiled by cc3)
- **Code size**: ~7,913 LOC Rust → ~3,553 LOC Cyrius (55% reduction across ported modules)
- **Dependencies**: serde/thiserror/tracing/tokio → cyrius stdlib + agnosys/agnostik deps
- **Error handling**: `Result<T, NeinError>` → stdlib tagged Result (`Ok`/`Err`/`is_err_result`/`payload`)
- **Feature gates**: Cargo `#[cfg(feature = ...)]` → cyrius preprocessor `#ifdef`
- **TOML support**: Scoped to string→enum dispatchers (full struct parsing awaits sutra port)

### Deferred (blocked on upstream)

- `mcp` — blocked on [bote](https://github.com/MacCracken/bote) Cyrius port
- Full TOML struct parsing — blocked on sutra port start (only consumer)

### Security

All validators preserved from Rust: dangerous-character rejection (`; { } | \n \r \0 \` $`), quote filtering for comments/log prefixes/set elements, length limits (identifiers 64, interfaces 15, comments 128, log prefixes 64). `Match::Raw` remains the explicit, documented escape hatch.

## [0.90.0] — 2026-04-02

### Added

#### Phase 4 — Production Hardening
- **Define variables**: `Define` struct for `define $VAR = value;` inside tables
- **Flowtables**: `Flowtable` struct for hardware offload (`flowtable ft { hook ingress priority 0; devices = { eth0 }; }`)
- **Conntrack timeout policies**: `CtTimeout` struct with per-protocol timeout tuning (`ct timeout name { protocol tcp; policy = { established: 7200 }; }`)
- **Quota rules**: `QuotaMode`/`QuotaUnit` enums + `Match::Quota` for byte-based rate limiting (`quota over 25 mbytes`)
- **Mark setting verdicts**: `Verdict::SetMark(u32)`, `Verdict::SetCtMark(u32)` for packet/conntrack marking
- **NAT port range mappings**: `NatRule::DnatRange` + `port_range_forward()` for range-to-range DNAT (`80-89 -> 8080-8089`)
- **Rule insertion ordering**: `insert_rule()` (beginning of chain), `add_rule_after()` (after handle)
- **Rule replacement**: `replace_rule()` for atomic handle-based rule updates
- **Chain operations**: `flush_chain()`, `delete_chain()` in apply module
- `Table` struct extended with `defines`, `flowtables`, `ct_timeouts` fields
- Render order: defines, flowtables, ct_timeouts, sets, maps, chains

#### Phase 5 — Deep Protocol Support
- **ICMP type+code**: `Match::IcmpTypeCode(String, u8)`, `Match::Icmpv6TypeCode(String, u8)`
- **VLAN ID matching**: `Match::VlanId(u16)` — validated 0-4094
- **DSCP/ToS matching**: `Match::Dscp(u8)` — validated 0-63
- **IPv6 extension headers**: `Ipv6ExtHdr` enum + `Match::Ipv6ExtHdrExists` (hbh, rt, frag, dst, mh, auth)
- **Fragment matching**: `Match::FragOff { mask, op, value }` with typed `CmpOp` enum
- **Packet type matching**: `PktType` enum + `Match::PktType` (unicast, broadcast, multicast)
- **Enhanced logging**: `LogLevel` enum + `Verdict::LogAdvanced { prefix, level, group, snaplen }`
- **Named counters**: `Verdict::CounterNamed(String)` for `counter name "name"` references

#### Phase 6 — Ergonomics
- **Bulk match builders**: `Rule::matching_ports()`, `matching_addrs()`, `matching_addrs6()` — anonymous set syntax with input validation
- **Set-based isolation**: bridge isolation groups now use O(1) nftables set lookups instead of O(n^2) explicit rules
- **Set-based outbound hosts**: PolicyEngine outbound host restrictions use named sets instead of O(n*M) rules
- **Rule deduplication**: `Firewall::deduplicate()` removes adjacent duplicate rules

#### Phase 7 — Ecosystem Integration
- **daimon**: `firewall` feature wires `nein_status`/`nein_allow`/`nein_deny`/`nein_list` MCP tools into daimon's handler registry
- **aegis**: `firewall` feature adds `isolate_agent()`, `rate_limit_agent()`, `hardened_host()` firewall profiles
- **sutra**: `nein` module implementing `SutraModule` trait with `apply`/`check`/`flush` actions for fleet firewall configs
- **stiva**: container port mapping NAT rules now applied to nftables via `nft -f -` on container connect

#### Phase 8 — QUIC Support
- **Transport enum**: `Transport::Tcp`/`Udp`/`Quic` in PolicyEngine — QUIC maps to UDP protocol with semantic distinction in policy comments
- **QUIC rate limiting**: `rate_limit_quic()` convenience function with 2x burst for connection migration protection
- `rate_limit_udp()` convenience function
- `PortSpec::quic(port)` constructor

#### Production Firewall Completeness
- **Reject with reason**: `Verdict::RejectWith(RejectReason)` — TCP RST, ICMP host/port/net/admin-unreachable, ICMPx admin-prohibited
- **Connection count limiting**: `Match::ConnLimit(u32)` for per-source connection count (`ct count over N`)

#### v1.0 Readiness
- **Serde roundtrip tests**: 19 tests across all modules (rule, table, nat, engine types)
- **Config module**: TOML parsing for all Phase 4-8 types (defines, flowtables, ct_timeouts, quota, dscp, vlan, frag, pkttype, log_advanced, counter_named, set_mark, reject_with, conn_limit)
- **Doc-tests**: 6 doc-tests on key entry points (lib.rs, rule.rs, builder.rs, engine.rs, bridge.rs, netns.rs)
- **Scale benchmarks**: 1000-rule firewall (176µs render, 82µs validate), 100-agent engine (548µs to_firewall, 320µs render)
- **ADRs**: 3 new records — set-based isolation (007), typed enums over strings (008), non-exhaustive structs (009)
- **Tracing**: added structured logging to bridge, mesh, geoip, engine, policy, config, inspect modules

### Changed
- `bote` dependency changed from path to crates.io `v0.91`
- `agnosys` dependency changed from path to git tag `v0.50.0`
- `criterion` upgraded from `0.5` to `0.8` (`black_box` migrated to `std::hint::black_box`)
- `validate_addr()` now parses actual IP/CIDR via `std::net::IpAddr` instead of character-set-only checks
- `validate_family()` added — closed set validation for nftables address families
- All `apply.rs` incremental functions validate `family` param against closed set
- `Rule::render()` rewritten with `write!` to single buffer (was `Vec<String>` + `join`) — **60% faster rendering**
- `Chain::render()`, `Table::render()` use `write!` with pre-allocation
- `mcp::build_allow_rule`/`build_deny_rule` now validate `table` and `chain` fields
- `port_range_forward()` uses `saturating_sub`/`saturating_add` to prevent overflow
- `#[non_exhaustive]` added to all public enums and structs
- `#[must_use]` added to ~70 pure/builder functions
- `#[inline]` added to hot-path functions (`Rule::new`, `render`, `matching`)
- `Hash` derived on all public enums and value structs
- `Serialize`/`Deserialize` added to `Firewall`, `PolicyEngine`, `GeoIpBlocklist`, `BridgeFirewall`, `FirewallStatus`, `RuleHandle`
- `PartialEq`/`Eq` added to all config and MCP types
- Makefile, bench-track.sh, CI workflows switched from `--all-features` to `--features full`
- `deny.toml` updated with `allow-git` for agnosys GitHub URL
- SECURITY.md updated with v0.90.0 support, new attack surfaces, standards compliance section
- Threat model updated with incremental apply injection, MCP tool input, supply chain sections

### Fixed
- `mcp.rs` formatting (was only `cargo fmt` failure at session start)
- `config.rs` redundant `let mut chain = chain;` re-binding
- `apply.rs` incremental functions now validate all parameters before interpolation (security)
- `matching_addrs()`/`matching_addrs6()` now validate each address before embedding in `Raw` (security)
- `rate_limit_quic()` burst uses `saturating_mul` to prevent overflow
- `CtTimeout` validates protocol is TCP/UDP only, l3proto is Ip/Ip6 only
- `Flowtable` validates at least one device is present
- CI `cargo test --doc` now uses `--features full` so feature-gated doc-tests run
- Release workflow `sed` patterns fixed for `#[cfg(feature = "netns")]` stripping
- Release workflow uses `--allow-dirty` for publish after stripping private deps

### Performance
- `rule_render`: 305 ns → 123 ns (**-60%**)
- `rule_complex_render`: 497 ns → 268 ns (**-46%**)
- `bridge_large_render`: 45.4 µs → 27.0 µs (**-41%**)
- `engine_10_agents_render`: 40.8 µs → 14.9 µs (**-63%**)
- `mesh_render`: 2.96 µs → 1.22 µs (**-59%**)
- Bridge isolation: O(n^2) → O(1) per group via nftables sets
- PolicyEngine outbound hosts: O(ports * hosts) → O(ports) via named sets
- Scale: 1000-rule render 176µs, 100-agent engine 548µs

### Tests
- 396 unit tests, 7 integration tests, 6 doc-tests = **409 total** (up from 217 unit tests)

## [0.24.3] — 2026-03-24

### Added
- **`netns` feature**: agent network namespace firewall integration via agnosys
  - `NamespaceFirewall` builder — type-safe nftables rulesets for agent namespaces (established/related, loopback, DNS, inbound/outbound ports, host restrictions)
  - `apply_to_namespace()` — renders and applies firewall inside a namespace via `agnosys::netns::apply_nftables_ruleset`
  - 15 unit tests, doctest
  - Feature-gated behind `dep:agnosys` (optional path dependency, not included in `full` or `default` — agnosys is `publish = false`)

### Changed
- `full` feature no longer enables all features — excludes `netns` since agnosys is a private crate
- CI (`ci.yml`): `--all-features` replaced with `--features full` across all jobs (clippy, test, MSRV, coverage, benchmarks, docs) to avoid requiring private path dependencies
- `deny.toml`: switched from `all-features = true` to `features = ["full"]` for the same reason

## [0.22.3] — 2026-03-22

### Added
- Benchmark tracking script (`scripts/bench-track.sh`) — records criterion results to `benchmarks/history.tsv` with version, commit, and timestamp for historical performance tracking
- Expanded benchmarks: 22 criterion benchmarks covering all modules (rule render/validate, complex rules with IPv6/rate-limit/TCP-flags, NAT, host firewall, bridge small/large, engine 10 agents, policy, mesh, geoip 10 countries, set 1000 elements, TOML parse)
- 6 architecture decision records (ADRs) in `docs/decisions/`: render-not-execute, validate-before-apply, feature-gated-modules, raw-match-escape-hatch, chain-rule-enum, sets-in-tables
- Future roadmap (`docs/development/roadmap.md`): Phases 4-7 (production hardening, deep protocol support, ergonomics, ecosystem integration)
- Development section in README with quick-reference commands
- Documentation links in README (architecture, threat model, ADRs, testing guide)

### Changed
- Version bump for stiva 0.22.3 ecosystem release
- README roadmap replaced with link to `docs/development/roadmap.md` — completed phases removed (in CHANGELOG)
- `Makefile` adds `bench-track` target
- `CONTRIBUTING.md` expanded with benchmark tracking workflow
- `docs/guides/testing.md` expanded with historical benchmark tracking

## [0.21.3] — 2026-03-22

### Added

#### Publishing Infrastructure
- CI/CD pipeline (`.github/workflows/ci.yml`): 10-job pipeline — lint (3x feature combos), security audit, cargo-deny, test, test-minimal, MSRV, coverage (codecov), benchmarks (artifact upload), documentation (-D warnings), semver checks (PRs)
- Release automation (`.github/workflows/release.yml`): triadic version verification (VERSION + Cargo.toml + git tag), publish to crates.io, create GitHub release
- Community files: `CONTRIBUTING.md`, `SECURITY.md` (threat model, disclosure policy), `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1), `codecov.yml` (80% project, 75% patch)
- 4 runnable examples: `host_firewall`, `container_bridge`, `policy_engine`, `geoip_blocklist` (feature-gated)
- 3 fuzz targets: `fuzz_rule_render`, `fuzz_toml_config`, `fuzz_validation` (libfuzzer)
- Supply chain: `supply-chain/config.toml`, `supply-chain/audits.toml` (cargo-vet)
- Documentation: `docs/architecture/overview.md`, `docs/development/threat-model.md`, `docs/guides/testing.md`
- Expanded `Makefile`: coverage, fuzz, clippy --all-features, doc with -D warnings
- `Cargo.toml`: publish excludes, example entries with required-features
- Expanded `lib.rs` module documentation with feature table

#### Firewall Features
- **TCP flags matching**: `Match::TcpFlags` renders as `tcp flags { syn, fin }`
- **ICMP type matching**: `Match::IcmpType`, `Match::Icmpv6Type` for fine-grained ICMP filtering
- **Packet mark matching**: `Match::MetaMark` for `meta mark` matching
- **IPv6 DNAT fix**: brackets around IPv6 addresses in DNAT rendering (`dnat to [addr]:port`)
- Improved config parse error messages — all parsers now list valid options on error

#### Phase 3 — Advanced
- **Named sets and maps** (core): `NftSet` with element types (ipv4_addr, ipv6_addr, inet_service, inet_proto, ifname), flags (constant, interval, timeout). `NftMap` verdict maps. Integrated into `Table` — sets/maps render before chains
- **IPv6 support**: `Match::SourceAddr6`/`DestAddr6` for `ip6 saddr`/`ip6 daddr`. `deny_source6()` convenience function. `validate_addr` accepts IPv6 notation
- **Rate limiting**: `Match::Limit { rate, unit, burst }` renders as `limit rate N/unit burst M packets`. `RateUnit` enum (second/minute/hour/day). `rate_limit_tcp()` convenience
- **Connection tracking helpers**: `Match::CtHelper` renders as `ct helper "name"` with identifier validation
- **Set membership matching**: `Match::SetLookup { field, set_name }` renders as `field @setname`. `match_set()` convenience
- **TOML config** (`config` feature): `from_toml()`/`to_toml()` for firewall config files. Tagged union match types, all verdict/family/hook/chain_type variants. Round-trip serialization for sutra playbooks
- **GeoIP blocking** (`geoip` feature): `GeoIpBlocklist` with `CountryBlock` entries. Generates nftables interval sets per country + drop rules. Dual-stack (IPv4 + IPv6 in separate tables). Country code validation (ISO 3166-1 alpha-2)
- `validate_nft_element()` for set/map element validation
- `Eq` added to `ChainRule`, `Chain`, `Table`, `NetworkPolicy`
- `Clone` added to `Firewall`
- MCP `build_allow_rule`/`build_deny_rule` now validate source CIDRs
- 255 unit tests, 7 integration tests

#### Phase 2 — Daimon Integration
- **Agent policy engine** (`engine` feature): `PolicyEngine` manages per-agent network policies with `AgentPolicy`, `PortSpec`. Generates unified firewall with dispatch chains that jump to per-agent `{id}_in`/`{id}_out` chains. Supports inbound/outbound port control, outbound host restrictions, established/loopback toggles
- **Dynamic rule operations** in `apply` module: `add_rule()`, `delete_rule()` for incremental rule management; `list_ruleset_with_handles()`, `find_rules_by_comment()`, `parse_rules_with_handles()` for rule discovery by comment prefix; `flush_table()`, `delete_table()` for table-level operations
- **Service mesh sidecar proxy** (`mesh` feature): `SidecarConfig` with Envoy defaults (ports 15006/15001, UID 1337). Generates transparent TCP redirect rules with UID-based proxy bypass, CIDR exclusions, port exclusions for both inbound and outbound interception
- **MCP tool building blocks** (`mcp` feature): `ToolDescriptor`, `ToolResult`, request/response types for `nein_status`, `nein_allow`, `nein_deny`, `nein_list`. Includes `build_allow_rule()` and `build_deny_rule()` helpers, `tool_descriptors()` for MCP registration

#### Phase 1 — Stiva Integration
- **Bridge module** (`bridge` feature): `BridgeConfig`, `BridgeFirewall`, `PortMapping`, `IsolationGroup` — full container bridge firewall management
- Port mapping lifecycle: `add_port_mapping` (with duplicate detection), `remove_port_mapping`
- Network isolation groups with cross-CIDR intra-group traffic rules
- Integration tests (`tests/integration.rs`) — 7 tests gated behind `NEIN_INTEGRATION=1` env var, require root + nft
- Criterion benchmarks (`benches/benchmarks.rs`) — rule render, validate, NAT render, host firewall, bridge firewall (small/large), policy, 100-rule validation

#### Phase 0 — Foundation
- Input validation module (`validate`) — rejects dangerous characters in addresses, interface names, identifiers, comments, and log prefixes to prevent nftables injection
- `Firewall::validate()` — walks all tables/chains/rules, called automatically before `apply()`
- `Rule::validate()` and `NatRule::validate()` for per-rule validation
- `NetworkPolicy::validate()` — checks policy name and peer addresses
- `ChainRule` enum — chains now natively hold both filter rules (`Rule`) and NAT rules (`NatRule`)
- `Chain::add_nat_rule()` for direct NAT rule insertion without `Match::Raw` workaround
- `Verdict` implements `Display`
- `Firewall::tables()` accessor
- `DPortRange(lo, hi)` validation rejects inverted ranges
- `PartialEq`/`Eq` derives on `Rule`, `Match`, `Table`, `Chain`, `NatRule`, `ChainRule`, `NetworkPolicy`, `PolicyRule`, `PolicyPort`
- **Bridge module** (`bridge` feature): `BridgeConfig`, `BridgeFirewall`, `PortMapping`, `IsolationGroup` — full container bridge firewall management
- Port mapping lifecycle: `add_port_mapping` (with duplicate detection), `remove_port_mapping`
- Network isolation groups with cross-CIDR intra-group traffic rules
- Integration tests (`tests/integration.rs`) — 7 tests gated behind `NEIN_INTEGRATION=1` env var, require root + nft
- Criterion benchmarks (`benches/benchmarks.rs`) — rule render, validate, NAT render, host firewall, bridge firewall (small/large), policy, 100-rule validation
- 70 unit tests, 6 integration tests (up from 24)

### Fixed
- Zombie process in `apply_ruleset` — child is now always waited on, even if stdin write fails
- `inspect::status()` no longer swallows errors — propagates `list_ruleset` failures via `?`
- `container_bridge` builder no longer wraps NAT rules through `Match::Raw`, eliminating a validation bypass

### Changed
- Feature flags now gate modules: `nat`, `policy`, `inspect`, `apply`, `builder`, `bridge` (previously decorative)
- `tokio` is optional, gated behind the `apply` feature
- Default features: `nat`, `policy`, `apply`, `builder`, `bridge`
- Removed unused `rules` feature (core types always compiled)

### Removed
- Unused dependencies: `anyhow`, `serde_json`, `toml`, `chrono`, `uuid`, `nix`
- Unused `validate_nft_value` function
- Unused `_agent_dest` parameter from `builder::service_policy()`

### Security
- `Match::Raw` documented as unvalidated escape hatch — must not receive user-controlled input
- `Firewall::flush()` documented as flushing the entire host ruleset, not just owned tables
