# Security Policy

## Scope

nein is a programmatic nftables firewall library that generates and applies
firewall rules via the `nft` command. It runs with elevated privileges
(root or `CAP_NET_ADMIN`).

The primary security-relevant surface areas are:

- **nftables injection** — string values (addresses, interface names, comments)
  interpolated into rendered nftables syntax. All values pass through the
  `validate` module to reject dangerous characters (`;`, `{`, `}`, newlines,
  etc.) before rendering.
- **Privilege escalation** — nein spawns `nft` as a child process. The library
  itself does not manage privileges; callers are responsible for capability
  management.
- **TOML config parsing** — the `config` feature deserialises TOML into firewall
  rules. Malformed input is rejected at parse time; valid TOML that produces
  invalid rules is caught at `validate()` time.
- **`Match::Raw` bypass** — the `Raw` match variant emits strings verbatim
  without validation. It must only receive trusted, hard-coded values.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.21.x  | Yes       |
| < 0.21  | No        |

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
- `Firewall::apply()` calls `validate()` automatically before executing.
- No `unsafe` code in the library.
- Child processes (`nft`) are always waited on to prevent zombie processes.
- Fuzz testing (`make fuzz`) targets rule rendering, TOML parsing, and
  validation paths.
