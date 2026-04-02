//! Input validation for values interpolated into nftables rules.
//!
//! All strings that end up in rendered nftables syntax pass through these
//! validators to prevent injection of arbitrary nft commands.

use crate::error::NeinError;

/// Characters that could inject nftables commands or break syntax.
const DANGEROUS_CHARS: &[char] = &[';', '{', '}', '|', '\n', '\r', '\0', '`', '$'];

/// Validate an nftables identifier (table name, chain name).
///
/// Must be non-empty, alphanumeric plus `_` and `-`, and at most 64 chars.
pub fn validate_identifier(s: &str) -> Result<(), NeinError> {
    if s.is_empty() {
        return Err(NeinError::InvalidRule(
            "identifier must not be empty".into(),
        ));
    }
    if s.len() > 64 {
        return Err(NeinError::InvalidRule(format!(
            "identifier too long ({} chars, max 64): {s}",
            s.len()
        )));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(NeinError::InvalidRule(format!(
            "identifier contains invalid characters: {s}"
        )));
    }
    Ok(())
}

/// Validate an IP address or CIDR string.
///
/// Parses the string as a valid IPv4/IPv6 address or CIDR block.
/// Rejects malformed addresses and dangerous injection characters.
pub fn validate_addr(s: &str) -> Result<(), NeinError> {
    if s.is_empty() {
        return Err(NeinError::InvalidRule("address must not be empty".into()));
    }
    // Fast reject: only allow characters valid in IP/CIDR notation
    if !s
        .chars()
        .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/'))
    {
        return Err(NeinError::InvalidRule(format!(
            "address contains invalid characters: {s}"
        )));
    }
    // Parse as IP or CIDR
    if let Some((addr_part, prefix_part)) = s.split_once('/') {
        addr_part
            .parse::<std::net::IpAddr>()
            .map_err(|_| NeinError::InvalidRule(format!("invalid IP in CIDR: {s}")))?;
        let prefix: u8 = prefix_part
            .parse()
            .map_err(|_| NeinError::InvalidRule(format!("invalid prefix length in CIDR: {s}")))?;
        let max = if addr_part.contains(':') { 128 } else { 32 };
        if prefix > max {
            return Err(NeinError::InvalidRule(format!(
                "prefix length {prefix} exceeds max {max} for {s}"
            )));
        }
    } else {
        s.parse::<std::net::IpAddr>()
            .map_err(|_| NeinError::InvalidRule(format!("invalid IP address: {s}")))?;
    }
    Ok(())
}

/// Validate an nftables address family string.
///
/// Must be one of: inet, ip, ip6, arp, bridge, netdev.
pub fn validate_family(s: &str) -> Result<(), NeinError> {
    const VALID_FAMILIES: &[&str] = &["inet", "ip", "ip6", "arp", "bridge", "netdev"];
    if !VALID_FAMILIES.contains(&s) {
        return Err(NeinError::InvalidRule(format!(
            "unknown address family: {s} (valid: inet, ip, ip6, arp, bridge, netdev)"
        )));
    }
    Ok(())
}

/// Validate a network interface name.
///
/// Linux interface names: up to 15 chars, alphanumeric plus `-`, `_`, `.`.
pub fn validate_iface(s: &str) -> Result<(), NeinError> {
    if s.is_empty() {
        return Err(NeinError::InvalidRule(
            "interface name must not be empty".into(),
        ));
    }
    if s.len() > 15 {
        return Err(NeinError::InvalidRule(format!(
            "interface name too long ({} chars, max 15): {s}",
            s.len()
        )));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(NeinError::InvalidRule(format!(
            "interface name contains invalid characters: {s}"
        )));
    }
    Ok(())
}

/// Validate a connection tracking state name.
///
/// Must be a known ct state keyword.
pub fn validate_ct_state(s: &str) -> Result<(), NeinError> {
    const VALID_STATES: &[&str] = &["new", "established", "related", "invalid", "untracked"];
    if !VALID_STATES.contains(&s) {
        return Err(NeinError::InvalidRule(format!("unknown ct state: {s}")));
    }
    Ok(())
}

/// Validate a comment string.
///
/// Rejects double quotes (used as delimiter in nft syntax) and dangerous chars.
pub fn validate_comment(s: &str) -> Result<(), NeinError> {
    if s.contains('"') {
        return Err(NeinError::InvalidRule(
            "comment must not contain double quotes".into(),
        ));
    }
    for c in DANGEROUS_CHARS {
        if s.contains(*c) {
            return Err(NeinError::InvalidRule(format!(
                "comment contains dangerous character: {c:?}"
            )));
        }
    }
    if s.len() > 128 {
        return Err(NeinError::InvalidRule(format!(
            "comment too long ({} chars, max 128)",
            s.len()
        )));
    }
    Ok(())
}

/// Validate a log prefix string.
///
/// Same constraints as comments — no quotes, no dangerous chars, max 64 chars
/// (nftables limit).
pub fn validate_log_prefix(s: &str) -> Result<(), NeinError> {
    if s.contains('"') {
        return Err(NeinError::InvalidRule(
            "log prefix must not contain double quotes".into(),
        ));
    }
    for c in DANGEROUS_CHARS {
        if s.contains(*c) {
            return Err(NeinError::InvalidRule(format!(
                "log prefix contains dangerous character: {c:?}"
            )));
        }
    }
    if s.len() > 64 {
        return Err(NeinError::InvalidRule(format!(
            "log prefix too long ({} chars, max 64)",
            s.len()
        )));
    }
    Ok(())
}

/// Validate a set/map element string.
///
/// Allows the characters needed for IP addresses, ports, CIDR notation, and
/// interface names. Rejects dangerous injection characters.
pub fn validate_nft_element(s: &str) -> Result<(), NeinError> {
    if s.is_empty() {
        return Err(NeinError::InvalidRule("element must not be empty".into()));
    }
    for c in DANGEROUS_CHARS {
        if s.contains(*c) {
            return Err(NeinError::InvalidRule(format!(
                "element contains dangerous character: {c:?}"
            )));
        }
    }
    if s.contains('"') {
        return Err(NeinError::InvalidRule(
            "element must not contain double quotes".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_identifiers() {
        assert!(validate_identifier("filter").is_ok());
        assert!(validate_identifier("my_table").is_ok());
        assert!(validate_identifier("agnos-policy").is_ok());
    }

    #[test]
    fn invalid_identifiers() {
        assert!(validate_identifier("").is_err());
        assert!(validate_identifier("evil;drop").is_err());
        assert!(validate_identifier("has space").is_err());
        assert!(validate_identifier("has{brace").is_err());
        assert!(validate_identifier(&"a".repeat(65)).is_err());
    }

    #[test]
    fn valid_addresses() {
        assert!(validate_addr("10.0.0.1").is_ok());
        assert!(validate_addr("192.168.0.0/16").is_ok());
        assert!(validate_addr("172.17.0.2").is_ok());
        assert!(validate_addr("::1").is_ok());
        assert!(validate_addr("fe80::/10").is_ok());
    }

    #[test]
    fn invalid_addresses() {
        assert!(validate_addr("").is_err());
        assert!(validate_addr("10.0.0.1; drop").is_err());
        assert!(validate_addr("evil").is_err());
    }

    #[test]
    fn valid_ifaces() {
        assert!(validate_iface("eth0").is_ok());
        assert!(validate_iface("br-container").is_ok());
        assert!(validate_iface("veth1.2").is_ok());
        assert!(validate_iface("lo").is_ok());
    }

    #[test]
    fn invalid_ifaces() {
        assert!(validate_iface("").is_err());
        assert!(validate_iface("evil;drop").is_err());
        assert!(validate_iface(&"a".repeat(16)).is_err());
    }

    #[test]
    fn valid_ct_states() {
        assert!(validate_ct_state("established").is_ok());
        assert!(validate_ct_state("related").is_ok());
        assert!(validate_ct_state("new").is_ok());
    }

    #[test]
    fn invalid_ct_states() {
        assert!(validate_ct_state("bogus").is_err());
        assert!(validate_ct_state("established; drop").is_err());
    }

    #[test]
    fn valid_comments() {
        assert!(validate_comment("SSH access").is_ok());
        assert!(validate_comment("container port 8080->80").is_ok());
    }

    #[test]
    fn invalid_comments() {
        assert!(validate_comment("has \"quotes\"").is_err());
        assert!(validate_comment("has;semicolon").is_err());
        assert!(validate_comment(&"x".repeat(129)).is_err());
    }

    #[test]
    fn valid_log_prefix() {
        assert!(validate_log_prefix("NEIN_DROP: ").is_ok());
        assert!(validate_log_prefix("fw-input ").is_ok());
    }

    #[test]
    fn invalid_log_prefix() {
        assert!(validate_log_prefix("has\"quote").is_err());
        assert!(validate_log_prefix("has;semi").is_err());
        assert!(validate_log_prefix(&"x".repeat(65)).is_err());
    }

    #[test]
    fn injection_attempt() {
        assert!(validate_addr("10.0.0.1\n; flush ruleset").is_err());
        assert!(validate_iface("eth0; drop").is_err());
        assert!(validate_identifier("table\0evil").is_err());
    }

    #[test]
    fn ct_state_untracked() {
        assert!(validate_ct_state("untracked").is_ok());
    }

    #[test]
    fn ct_state_invalid() {
        assert!(validate_ct_state("invalid").is_ok());
    }

    #[test]
    fn ct_state_new() {
        assert!(validate_ct_state("new").is_ok());
    }

    #[test]
    fn identifier_max_length() {
        assert!(validate_identifier(&"a".repeat(64)).is_ok());
        assert!(validate_identifier(&"a".repeat(65)).is_err());
    }

    #[test]
    fn identifier_numeric_start() {
        // Digits at start are valid for nft identifiers
        assert!(validate_identifier("0eth0").is_ok());
        assert!(validate_identifier("123").is_ok());
    }

    #[test]
    fn iface_max_length() {
        assert!(validate_iface(&"a".repeat(15)).is_ok());
        assert!(validate_iface(&"a".repeat(16)).is_err());
    }

    #[test]
    fn addr_ipv6_full() {
        assert!(validate_addr("2001:0db8:85a3:0000:0000:8a2e:0370:7334").is_ok());
    }

    #[test]
    fn comment_max_length() {
        assert!(validate_comment(&"a".repeat(128)).is_ok());
        assert!(validate_comment(&"a".repeat(129)).is_err());
    }

    #[test]
    fn log_prefix_max_length() {
        assert!(validate_log_prefix(&"a".repeat(64)).is_ok());
        assert!(validate_log_prefix(&"a".repeat(65)).is_err());
    }

    #[test]
    fn valid_nft_elements() {
        assert!(validate_nft_element("10.0.0.1").is_ok());
        assert!(validate_nft_element("80").is_ok());
        assert!(validate_nft_element("192.168.0.0/16").is_ok());
        assert!(validate_nft_element("::1").is_ok());
    }

    #[test]
    fn invalid_nft_elements() {
        assert!(validate_nft_element("").is_err());
        assert!(validate_nft_element("evil;inject").is_err());
        assert!(validate_nft_element("has\"quote").is_err());
        assert!(validate_nft_element("has\nnewline").is_err());
    }

    #[test]
    fn dangerous_chars_all() {
        for c in [';', '{', '}', '|', '\n', '\r', '\0', '`', '$'] {
            let s = format!("test{c}val");
            assert!(validate_comment(&s).is_err(), "should reject {c:?}");
            assert!(validate_log_prefix(&s).is_err(), "should reject {c:?}");
        }
    }

    #[test]
    fn valid_families() {
        for f in ["inet", "ip", "ip6", "arp", "bridge", "netdev"] {
            assert!(validate_family(f).is_ok(), "should accept {f}");
        }
    }

    #[test]
    fn invalid_families() {
        assert!(validate_family("").is_err());
        assert!(validate_family("ipv4").is_err());
        assert!(validate_family("filter").is_err());
        assert!(validate_family("inet; drop").is_err());
    }
}
