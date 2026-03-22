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
`\r`, `\0`, `` ` ``, `$`, `"`) are rejected. `Firewall::apply()` calls
`validate()` before rendering.

**Residual risk:** `Match::Raw` bypasses validation. It is documented as
requiring trusted input only.

### 2. Privilege Escalation

**Threat:** nein spawns `nft` which requires root or `CAP_NET_ADMIN`. A
compromised caller could use nein to modify firewall rules.

**Mitigation:** nein does not manage privileges. Callers are responsible for
running with appropriate capabilities. The library returns
`NeinError::PermissionDenied` if `nft` fails with permission errors.

### 3. Denial of Service via Rule Explosion

**Threat:** A configuration with many agents, ports, or isolation groups
generates O(N^2) or O(N*M) rules, overwhelming the nftables subsystem.

**Mitigation:** Callers should monitor rule counts. The `Firewall::tables()`
accessor allows inspection before applying.

### 4. TOML Config Injection

**Threat:** Malformed TOML input to `config::from_toml()` produces unexpected
rules.

**Mitigation:** TOML parsing is handled by the `toml` crate. Invalid structure
returns `NeinError::Parse`. Valid TOML that produces invalid rules is caught by
`validate()` before apply.

### 5. Child Process Handling

**Threat:** The `nft` child process is not waited on, creating zombie processes
or resource leaks.

**Mitigation:** `apply::run_nft_stdin()` always calls `wait_with_output()`,
even if the stdin write fails.
