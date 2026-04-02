# Security Policy

## Scope

nein is a programmatic nftables firewall library that generates and applies
firewall rules via the `nft` command. It runs with elevated privileges
(root or `CAP_NET_ADMIN`).

The primary security-relevant surface areas are:

- **nftables injection** — string values (addresses, interface names, comments)
  interpolated into rendered nftables syntax. All values pass through the
  `validate` module to reject dangerous characters (`;`, `{`, `}`, newlines,
  etc.) before rendering. IP addresses are parsed with `std::net::IpAddr` for
  semantic validation beyond character filtering.
- **Incremental apply operations** — `add_rule`, `insert_rule`, `replace_rule`,
  etc. validate all parameters (family against closed set, table/chain as
  identifiers, rule body as nft element) before interpolation into nft commands.
- **Privilege escalation** — nein spawns `nft` as a child process. The library
  itself does not manage privileges; callers are responsible for capability
  management.
- **TOML config parsing** — the `config` feature deserialises TOML into firewall
  rules. Malformed input is rejected at parse time; valid TOML that produces
  invalid rules is caught at `validate()` time.
- **`Match::Raw` bypass** — the `Raw` match variant emits strings verbatim
  without validation. It must only receive trusted, hard-coded values. The
  convenience builders `matching_addrs()` and `matching_addrs6()` use `Raw`
  internally but validate each address before embedding.
- **Bulk builders** — `matching_ports()` uses typed `u16` values (no injection
  risk). `matching_addrs()`/`matching_addrs6()` validate each address via
  `validate_addr()` before constructing the anonymous set expression.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.90.x  | Yes       |
| 0.24.x  | Yes       |
| < 0.24  | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in nein, please report it responsibly:

1. **Email** [security@agnos.dev](mailto:security@agnos.dev) with a description
   of the issue, steps to reproduce, and any relevant context.
2. **Do not** open a public issue for security vulnerabilities.
3. You will receive an acknowledgment within **48 hours**.
4. We follow a **90-day disclosure timeline**. We will work with you to
   coordinate public disclosure after a fix is available.

## Security Design

- All user-facing string inputs are validated before rendering into nftables
  syntax (`validate` module).
- IP addresses and CIDRs are parsed with `std::net::IpAddr` for semantic
  validity, not just character filtering.
- nftables address families are validated against a closed set (`inet`, `ip`,
  `ip6`, `arp`, `bridge`, `netdev`).
- `Firewall::apply()` calls `validate()` automatically before executing.
- No `unsafe` code in the library.
- No `unwrap()` or `panic!()` in library code.
- Child processes (`nft`) are always waited on to prevent zombie processes.
- Fuzz testing (`make fuzz`) targets rule rendering, TOML parsing, and
  validation paths.
- `#[non_exhaustive]` on all public enums and structs for forward compatibility.

## Standards Compliance

nein generates nftables rulesets compatible with the Linux netfilter subsystem.
Relevant standards and references:

- **nftables** — [nftables wiki](https://wiki.nftables.org/) (Linux kernel
  netfilter framework)
- **OWASP** — input validation follows OWASP injection prevention guidelines:
  allowlist-based validation, parameterised input via typed enums
- **CIS Benchmarks** — the `aegis::firewall::hardened_host()` profile aligns
  with CIS Linux hardening recommendations (default deny inbound, allow
  established, SSH, ICMP echo)
- **CVE-free** — no known CVEs. Supply chain audited via `cargo audit` and
  `cargo deny check` (advisory database, license compliance, source verification)
- **License** — GPL-3.0-only, compatible with Linux kernel ecosystem
