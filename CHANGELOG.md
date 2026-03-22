# Changelog

All notable changes to nein are documented here.

## [0.21.3] — 2026-03-22

### Added
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
- 51 unit tests (up from 24)

### Fixed
- Zombie process in `apply_ruleset` — child is now always waited on, even if stdin write fails
- `inspect::status()` no longer swallows errors — propagates `list_ruleset` failures via `?`
- `container_bridge` builder no longer wraps NAT rules through `Match::Raw`, eliminating a validation bypass

### Changed
- Feature flags now gate modules: `nat`, `policy`, `inspect`, `apply`, `builder` (previously decorative)
- `tokio` is optional, gated behind the `apply` feature
- Default features: `nat`, `policy`, `apply`, `builder`
- Removed unused `rules` feature (core types always compiled)

### Removed
- Unused dependencies: `anyhow`, `serde_json`, `toml`, `chrono`, `uuid`, `nix`
- Unused `validate_nft_value` function
- Unused `_agent_dest` parameter from `builder::service_policy()`

### Security
- `Match::Raw` documented as unvalidated escape hatch — must not receive user-controlled input
- `Firewall::flush()` documented as flushing the entire host ruleset, not just owned tables
