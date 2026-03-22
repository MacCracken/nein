# Changelog

All notable changes to nein are documented here.

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
