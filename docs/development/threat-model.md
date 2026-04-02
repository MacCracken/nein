# Threat Model

## Attack Surface

nein generates nftables rules from Rust types and applies them via the `nft`
command. The primary threats are:

### 1. nftables Syntax Injection

**Threat:** An attacker controls a string value (IP address, interface name,
comment) that is interpolated into the rendered nftables ruleset, injecting
arbitrary nft commands.

**Mitigation:** The `validate` module checks all string inputs against an
allowlist of safe characters. Dangerous characters (`;`, `{`, `}`, `|`, `\n`,
`\r`, `\0`, `` ` ``, `$`, `"`) are rejected. IP addresses are further
validated via `std::net::IpAddr::parse()` for semantic correctness.
`Firewall::apply()` calls `validate()` before rendering.

**Residual risk:** `Match::Raw` bypasses validation. It is documented as
requiring trusted input only. The convenience builders `matching_addrs()` and
`matching_addrs6()` use `Raw` internally but validate each address before
embedding.

### 2. Incremental Apply Injection

**Threat:** Functions like `add_rule()`, `insert_rule()`, `replace_rule()` take
string parameters that are interpolated into nft commands. An attacker-controlled
`family`, `table`, `chain`, or `rule` parameter could inject nft commands.

**Mitigation:** All incremental apply functions validate parameters before
interpolation:
- `family` is validated against a closed set (`inet`, `ip`, `ip6`, `arp`,
  `bridge`, `netdev`) via `validate_family()`.
- `table` and `chain` are validated as identifiers (alphanumeric + `_` + `-`,
  max 64 chars).
- `rule` bodies are validated via `validate_nft_element()` which rejects
  dangerous characters.
- `handle` values are typed `u64`, no injection possible.

### 3. Privilege Escalation

**Threat:** nein spawns `nft` which requires root or `CAP_NET_ADMIN`. A
compromised caller could use nein to modify firewall rules.

**Mitigation:** nein does not manage privileges. Callers are responsible for
running with appropriate capabilities. The library returns
`NeinError::PermissionDenied` if `nft` fails with permission errors.

### 4. Denial of Service via Rule Explosion

**Threat:** A configuration with many agents, ports, or isolation groups
generates a large number of rules, overwhelming the nftables subsystem.

**Mitigation:** Bridge isolation and PolicyEngine outbound hosts use nftables
named sets (O(1) lookup) instead of explicit per-pair rules. The
`Firewall::tables()` accessor allows inspection before applying.
`Firewall::deduplicate()` can remove redundant rules.

### 5. TOML Config Injection

**Threat:** Malformed TOML input to `config::from_toml()` produces unexpected
rules.

**Mitigation:** TOML parsing is handled by the `toml` crate. Invalid structure
returns `NeinError::Parse`. Valid TOML that produces invalid rules is caught by
`validate()` before apply.

### 6. Child Process Handling

**Threat:** The `nft` child process is not waited on, creating zombie processes
or resource leaks.

**Mitigation:** `apply::run_nft_stdin()` always calls `wait_with_output()`,
even if the stdin write fails.

### 7. MCP Tool Input

**Threat:** MCP tool handlers (`nein_allow`, `nein_deny`) receive JSON input
from agents. Malicious input could inject nft commands.

**Mitigation:** `build_allow_rule()` and `build_deny_rule()` validate `table`,
`chain` (as identifiers), `source` (as address), and `protocol` (closed set
`tcp`/`udp`) before constructing rule strings.

## Supply Chain

- `cargo audit` — checks all dependencies against the RustSec advisory database
- `cargo deny check` — enforces license allowlist, bans wildcards, denies
  unknown registries/git sources
- No `unsafe` code in the library
- Fuzz targets cover rule rendering, TOML parsing, and validation
