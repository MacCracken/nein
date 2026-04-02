//! nftables rules — match expressions and verdicts.

use crate::error::NeinError;
use crate::validate;
use serde::{Deserialize, Serialize};

/// A firewall rule verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Verdict {
    Accept,
    Drop,
    Reject,
    Jump(String),
    GoTo(String),
    Return,
    Log(Option<String>),
    Counter,
    /// Set packet mark (`meta mark set {value}`).
    SetMark(u32),
    /// Set conntrack mark (`ct mark set {value}`).
    SetCtMark(u32),
    /// Enhanced log with level, group, and snaplen options.
    ///
    /// Renders as `log prefix "{prefix}" level {level} group {group} snaplen {snaplen}`.
    /// All fields are optional except prefix is part of the base.
    LogAdvanced {
        prefix: Option<String>,
        level: Option<LogLevel>,
        group: Option<u16>,
        snaplen: Option<u32>,
    },
    /// Named counter reference.
    ///
    /// Renders as `counter name "{name}"`.
    CounterNamed(String),
}

/// IP protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Icmp => write!(f, "icmp"),
            Self::Icmpv6 => write!(f, "icmpv6"),
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accept => write!(f, "accept"),
            Self::Drop => write!(f, "drop"),
            Self::Reject => write!(f, "reject"),
            Self::Jump(chain) => write!(f, "jump {chain}"),
            Self::GoTo(chain) => write!(f, "goto {chain}"),
            Self::Return => write!(f, "return"),
            Self::Log(Some(p)) => write!(f, "log prefix \"{p}\""),
            Self::Log(None) => write!(f, "log"),
            Self::Counter => write!(f, "counter"),
            Self::SetMark(val) => write!(f, "meta mark set {val}"),
            Self::SetCtMark(val) => write!(f, "ct mark set {val}"),
            Self::LogAdvanced {
                prefix,
                level,
                group,
                snaplen,
            } => {
                write!(f, "log")?;
                if let Some(p) = prefix {
                    write!(f, " prefix \"{p}\"")?;
                }
                if let Some(l) = level {
                    write!(f, " level {l}")?;
                }
                if let Some(g) = group {
                    write!(f, " group {g}")?;
                }
                if let Some(s) = snaplen {
                    write!(f, " snaplen {s}")?;
                }
                Ok(())
            }
            Self::CounterNamed(name) => write!(f, "counter name \"{name}\""),
        }
    }
}

/// Rate limit time unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RateUnit {
    Second,
    Minute,
    Hour,
    Day,
}

impl std::fmt::Display for RateUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Second => write!(f, "second"),
            Self::Minute => write!(f, "minute"),
            Self::Hour => write!(f, "hour"),
            Self::Day => write!(f, "day"),
        }
    }
}

/// Quota direction (over or until a threshold).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum QuotaMode {
    /// Match when quota is exceeded.
    Over,
    /// Match while quota remains.
    Until,
}

impl std::fmt::Display for QuotaMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Over => write!(f, "over"),
            Self::Until => write!(f, "until"),
        }
    }
}

/// Byte unit for quota rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum QuotaUnit {
    Bytes,
    KBytes,
    MBytes,
    GBytes,
}

impl std::fmt::Display for QuotaUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bytes => write!(f, "bytes"),
            Self::KBytes => write!(f, "kbytes"),
            Self::MBytes => write!(f, "mbytes"),
            Self::GBytes => write!(f, "gbytes"),
        }
    }
}

/// Packet type for meta matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PktType {
    Unicast,
    Broadcast,
    Multicast,
}

impl std::fmt::Display for PktType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unicast => write!(f, "unicast"),
            Self::Broadcast => write!(f, "broadcast"),
            Self::Multicast => write!(f, "multicast"),
        }
    }
}

/// IPv6 extension header type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Ipv6ExtHdr {
    HopByHop,
    Routing,
    Fragment,
    Destination,
    Mobility,
    Authentication,
}

impl std::fmt::Display for Ipv6ExtHdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HopByHop => write!(f, "hbh"),
            Self::Routing => write!(f, "rt"),
            Self::Fragment => write!(f, "frag"),
            Self::Destination => write!(f, "dst"),
            Self::Mobility => write!(f, "mh"),
            Self::Authentication => write!(f, "auth"),
        }
    }
}

/// Comparison operator for bitfield matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

impl std::fmt::Display for CmpOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eq => write!(f, "=="),
            Self::Ne => write!(f, "!="),
            Self::Lt => write!(f, "<"),
            Self::Gt => write!(f, ">"),
            Self::Le => write!(f, "<="),
            Self::Ge => write!(f, ">="),
        }
    }
}

/// Log level for enhanced logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum LogLevel {
    Emerg,
    Alert,
    Crit,
    Err,
    Warn,
    Notice,
    Info,
    Debug,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Emerg => write!(f, "emerg"),
            Self::Alert => write!(f, "alert"),
            Self::Crit => write!(f, "crit"),
            Self::Err => write!(f, "err"),
            Self::Warn => write!(f, "warn"),
            Self::Notice => write!(f, "notice"),
            Self::Info => write!(f, "info"),
            Self::Debug => write!(f, "debug"),
        }
    }
}

/// A match expression in a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Match {
    /// Match source IPv4 address/CIDR (`ip saddr`).
    SourceAddr(String),
    /// Match destination IPv4 address/CIDR (`ip daddr`).
    DestAddr(String),
    /// Match source IPv6 address/CIDR (`ip6 saddr`).
    SourceAddr6(String),
    /// Match destination IPv6 address/CIDR (`ip6 daddr`).
    DestAddr6(String),
    /// Match protocol.
    Protocol(Protocol),
    /// Match destination port.
    DPort(u16),
    /// Match source port.
    SPort(u16),
    /// Match destination port range.
    DPortRange(u16, u16),
    /// Match input interface.
    Iif(String),
    /// Match output interface.
    Oif(String),
    /// Match connection state.
    CtState(Vec<String>),
    /// Rate limit — match only if under the specified rate.
    ///
    /// Renders as `limit rate {rate}/{unit} burst {burst} packets`.
    Limit {
        rate: u32,
        unit: RateUnit,
        burst: u32,
    },
    /// Match against a named set (`@setname`).
    ///
    /// `field` is the selector (e.g., "ip saddr", "tcp dport").
    /// `set_name` is the name of the set defined in the same table.
    SetLookup { field: String, set_name: String },
    /// Match connection tracking helper.
    CtHelper(String),
    /// Match TCP flags (e.g., `syn`, `ack`, `fin`, `rst`, `psh`, `urg`).
    ///
    /// Renders as `tcp flags { flag1, flag2 }`.
    TcpFlags(Vec<String>),
    /// Match ICMP type (e.g., `echo-request`, `echo-reply`, `destination-unreachable`).
    ///
    /// Renders as `icmp type {type_name}`.
    IcmpType(String),
    /// Match ICMPv6 type.
    ///
    /// Renders as `icmpv6 type {type_name}`.
    Icmpv6Type(String),
    /// Match or set packet mark (`meta mark`).
    ///
    /// Renders as `meta mark {value}`.
    MetaMark(u32),
    /// Byte-based quota match.
    ///
    /// Renders as `quota {mode} {amount} {unit}`.
    Quota {
        mode: QuotaMode,
        amount: u64,
        unit: QuotaUnit,
    },
    /// Flow offload to a named flowtable.
    ///
    /// Renders as `flow offload @{name}`.
    FlowOffload(String),
    /// Set conntrack timeout for matching packets.
    ///
    /// Renders as `ct timeout set "{name}"`.
    CtTimeoutSet(String),
    /// Match ICMP type and code.
    ///
    /// Renders as `icmp type {type_name} icmp code {code}`.
    IcmpTypeCode(String, u8),
    /// Match ICMPv6 type and code.
    ///
    /// Renders as `icmpv6 type {type_name} icmpv6 code {code}`.
    Icmpv6TypeCode(String, u8),
    /// Match 802.1q VLAN ID.
    ///
    /// Renders as `vlan id {id}`.
    VlanId(u16),
    /// Match DSCP (Differentiated Services Code Point).
    ///
    /// Renders as `ip dscp {value}`. Values 0-63.
    Dscp(u8),
    /// Match IPv6 extension header presence.
    ///
    /// Renders as `exthdr {type} exists`.
    Ipv6ExtHdrExists(Ipv6ExtHdr),
    /// Match IP fragment flags.
    ///
    /// Renders as `ip frag-off & 0x{mask:x} {op} 0x{value:x}`.
    /// Common: more-fragments (`0x2000 != 0`), is-fragment (`0x1fff != 0`).
    FragOff { mask: u16, op: CmpOp, value: u16 },
    /// Match packet type (unicast, broadcast, multicast).
    ///
    /// Renders as `meta pkttype {type}`.
    PktType(PktType),
    /// Raw nft expression (escape hatch).
    ///
    /// # Security
    ///
    /// This variant is **not validated** — the string is emitted verbatim into
    /// the rendered nftables ruleset. Only use with trusted, hard-coded values.
    /// Never pass user-controlled input through `Raw` without prior sanitization.
    Raw(String),
}

/// An nftables rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub matches: Vec<Match>,
    pub verdict: Verdict,
    #[serde(default)]
    pub comment: Option<String>,
}

impl Rule {
    /// Create a new rule with a verdict.
    #[must_use]
    #[inline]
    pub fn new(verdict: Verdict) -> Self {
        Self {
            matches: vec![],
            verdict,
            comment: None,
        }
    }

    /// Add a match expression.
    #[must_use]
    #[inline]
    pub fn matching(mut self, m: Match) -> Self {
        self.matches.push(m);
        self
    }

    /// Add a comment.
    #[must_use]
    pub fn comment(mut self, c: &str) -> Self {
        self.comment = Some(c.to_string());
        self
    }

    /// Add a protocol match with multiple destination ports.
    ///
    /// Renders as `{proto} dport { port1, port2, ... }` using nftables
    /// anonymous set syntax.
    #[must_use]
    pub fn matching_ports(mut self, proto: Protocol, ports: &[u16]) -> Self {
        let port_list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        self.matches.push(Match::Protocol(proto));
        self.matches
            .push(Match::Raw(format!("dport {{ {} }}", port_list.join(", "))));
        self
    }

    /// Add multiple source IPv4 address matches using anonymous set syntax.
    ///
    /// Renders as `ip saddr { addr1, addr2, ... }`.
    #[must_use]
    pub fn matching_addrs(mut self, addrs: &[&str]) -> Self {
        self.matches
            .push(Match::Raw(format!("ip saddr {{ {} }}", addrs.join(", "))));
        self
    }

    /// Add multiple source IPv6 address matches using anonymous set syntax.
    ///
    /// Renders as `ip6 saddr { addr1, addr2, ... }`.
    #[must_use]
    pub fn matching_addrs6(mut self, addrs: &[&str]) -> Self {
        self.matches
            .push(Match::Raw(format!("ip6 saddr {{ {} }}", addrs.join(", "))));
        self
    }

    /// Validate all string fields in this rule for dangerous input.
    ///
    /// `Raw` matches are skipped — they are the caller's responsibility.
    pub fn validate(&self) -> Result<(), NeinError> {
        for m in &self.matches {
            match m {
                Match::SourceAddr(addr)
                | Match::DestAddr(addr)
                | Match::SourceAddr6(addr)
                | Match::DestAddr6(addr) => {
                    validate::validate_addr(addr)?;
                }
                Match::Iif(iface) | Match::Oif(iface) => {
                    validate::validate_iface(iface)?;
                }
                Match::CtState(states) => {
                    for s in states {
                        validate::validate_ct_state(s)?;
                    }
                }
                Match::CtHelper(helper) => {
                    validate::validate_identifier(helper)?;
                }
                Match::SetLookup { field, set_name } => {
                    validate::validate_nft_element(field)?;
                    validate::validate_identifier(set_name)?;
                }
                Match::TcpFlags(flags) => {
                    for flag in flags {
                        validate::validate_identifier(flag)?;
                    }
                }
                Match::IcmpType(t) | Match::Icmpv6Type(t) => {
                    validate::validate_identifier(t)?;
                }
                Match::Limit { .. }
                | Match::MetaMark(_)
                | Match::Quota { .. }
                | Match::Ipv6ExtHdrExists(_)
                | Match::PktType(_) => {
                    // Typed values, no injection possible.
                }
                Match::Dscp(val) => {
                    if *val > 63 {
                        return Err(NeinError::InvalidRule(format!(
                            "DSCP value {val} exceeds max 63"
                        )));
                    }
                }
                Match::VlanId(id) => {
                    if *id > 4094 {
                        return Err(NeinError::InvalidRule(format!(
                            "VLAN ID {id} exceeds max 4094"
                        )));
                    }
                }
                Match::FlowOffload(name) | Match::CtTimeoutSet(name) => {
                    validate::validate_identifier(name)?;
                }
                Match::IcmpTypeCode(t, _) | Match::Icmpv6TypeCode(t, _) => {
                    validate::validate_identifier(t)?;
                }
                Match::FragOff { .. } => {
                    // All fields are typed (u16, CmpOp, u16), no injection possible.
                }
                Match::Raw(_) => {
                    // Deliberately not validated — caller's responsibility.
                }
                Match::DPortRange(lo, hi) if lo > hi => {
                    return Err(NeinError::InvalidRule(format!(
                        "port range start ({lo}) must not exceed end ({hi})"
                    )));
                }
                Match::Protocol(_) | Match::DPort(_) | Match::SPort(_) | Match::DPortRange(..) => {
                    // Typed values, no string injection possible.
                }
            }
        }

        match &self.verdict {
            Verdict::Jump(chain) | Verdict::GoTo(chain) => {
                validate::validate_identifier(chain)?;
            }
            Verdict::Log(Some(prefix)) => {
                validate::validate_log_prefix(prefix)?;
            }
            Verdict::LogAdvanced {
                prefix: Some(p), ..
            } => {
                validate::validate_log_prefix(p)?;
            }
            Verdict::CounterNamed(name) => {
                validate::validate_identifier(name)?;
            }
            _ => {}
        }

        if let Some(comment) = &self.comment {
            validate::validate_comment(comment)?;
        }

        Ok(())
    }

    /// Render this rule as nftables syntax.
    #[must_use]
    #[inline]
    pub fn render(&self) -> String {
        use std::fmt::Write;

        let mut out = String::with_capacity(64);

        for m in &self.matches {
            if !out.is_empty() {
                out.push(' ');
            }
            match m {
                Match::SourceAddr(addr) => write!(out, "ip saddr {addr}"),
                Match::DestAddr(addr) => write!(out, "ip daddr {addr}"),
                Match::SourceAddr6(addr) => write!(out, "ip6 saddr {addr}"),
                Match::DestAddr6(addr) => write!(out, "ip6 daddr {addr}"),
                Match::Protocol(proto) => write!(out, "{proto}"),
                Match::DPort(port) => write!(out, "dport {port}"),
                Match::SPort(port) => write!(out, "sport {port}"),
                Match::DPortRange(lo, hi) => write!(out, "dport {lo}-{hi}"),
                Match::Iif(iface) => write!(out, "iif \"{iface}\""),
                Match::Oif(iface) => write!(out, "oif \"{iface}\""),
                Match::CtState(states) => write!(out, "ct state {{ {} }}", states.join(", ")),
                Match::Limit { rate, unit, burst } => {
                    write!(out, "limit rate {rate}/{unit} burst {burst} packets")
                }
                Match::SetLookup { field, set_name } => write!(out, "{field} @{set_name}"),
                Match::CtHelper(helper) => write!(out, "ct helper \"{helper}\""),
                Match::TcpFlags(flags) => {
                    write!(out, "tcp flags {{ {} }}", flags.join(", "))
                }
                Match::IcmpType(t) => write!(out, "icmp type {t}"),
                Match::Icmpv6Type(t) => write!(out, "icmpv6 type {t}"),
                Match::MetaMark(val) => write!(out, "meta mark {val}"),
                Match::Quota { mode, amount, unit } => {
                    write!(out, "quota {mode} {amount} {unit}")
                }
                Match::FlowOffload(name) => write!(out, "flow offload @{name}"),
                Match::CtTimeoutSet(name) => write!(out, "ct timeout set \"{name}\""),
                Match::IcmpTypeCode(t, code) => {
                    write!(out, "icmp type {t} icmp code {code}")
                }
                Match::Icmpv6TypeCode(t, code) => {
                    write!(out, "icmpv6 type {t} icmpv6 code {code}")
                }
                Match::VlanId(id) => write!(out, "vlan id {id}"),
                Match::Dscp(val) => write!(out, "ip dscp {val}"),
                Match::Ipv6ExtHdrExists(hdr) => write!(out, "exthdr {hdr} exists"),
                Match::FragOff { mask, op, value } => {
                    write!(out, "ip frag-off & 0x{mask:x} {op} 0x{value:x}")
                }
                Match::PktType(pt) => write!(out, "meta pkttype {pt}"),
                Match::Raw(expr) => write!(out, "{expr}"),
            }
            .unwrap();
        }

        if !out.is_empty() {
            out.push(' ');
        }
        write!(out, "{}", self.verdict).unwrap();

        if let Some(comment) = &self.comment {
            write!(out, " comment \"{comment}\"").unwrap();
        }

        out
    }
}

/// Convenience: allow TCP port.
#[must_use]
pub fn allow_tcp(port: u16) -> Rule {
    Rule::new(Verdict::Accept)
        .matching(Match::Protocol(Protocol::Tcp))
        .matching(Match::DPort(port))
}

/// Convenience: allow UDP port.
#[must_use]
pub fn allow_udp(port: u16) -> Rule {
    Rule::new(Verdict::Accept)
        .matching(Match::Protocol(Protocol::Udp))
        .matching(Match::DPort(port))
}

/// Convenience: allow established/related connections.
#[must_use]
pub fn allow_established() -> Rule {
    Rule::new(Verdict::Accept)
        .matching(Match::CtState(vec!["established".into(), "related".into()]))
}

/// Convenience: drop from source CIDR.
#[must_use]
pub fn deny_source(cidr: &str) -> Rule {
    Rule::new(Verdict::Drop).matching(Match::SourceAddr(cidr.to_string()))
}

/// Convenience: allow specific source to specific port (service policy).
#[must_use]
pub fn allow_service(source_cidr: &str, protocol: Protocol, port: u16) -> Rule {
    Rule::new(Verdict::Accept)
        .matching(Match::SourceAddr(source_cidr.to_string()))
        .matching(Match::Protocol(protocol))
        .matching(Match::DPort(port))
}

/// Convenience: rate-limited accept on a TCP port.
#[must_use]
pub fn rate_limit_tcp(port: u16, rate: u32, unit: RateUnit) -> Rule {
    Rule::new(Verdict::Accept)
        .matching(Match::Protocol(Protocol::Tcp))
        .matching(Match::DPort(port))
        .matching(Match::Limit {
            rate,
            unit,
            burst: rate,
        })
}

/// Convenience: drop traffic from an IPv6 source.
#[must_use]
pub fn deny_source6(cidr: &str) -> Rule {
    Rule::new(Verdict::Drop).matching(Match::SourceAddr6(cidr.to_string()))
}

/// Convenience: match against a named set.
#[must_use]
pub fn match_set(field: &str, set_name: &str) -> Match {
    Match::SetLookup {
        field: field.to_string(),
        set_name: set_name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_allow_tcp() {
        let rule = allow_tcp(443);
        assert_eq!(rule.render(), "tcp dport 443 accept");
    }

    #[test]
    fn render_deny_source() {
        let rule = deny_source("10.0.0.0/8");
        assert_eq!(rule.render(), "ip saddr 10.0.0.0/8 drop");
    }

    #[test]
    fn render_established() {
        let rule = allow_established();
        assert_eq!(rule.render(), "ct state { established, related } accept");
    }

    #[test]
    fn render_service_policy() {
        let rule = allow_service("192.168.1.0/24", Protocol::Tcp, 8090);
        assert_eq!(
            rule.render(),
            "ip saddr 192.168.1.0/24 tcp dport 8090 accept"
        );
    }

    #[test]
    fn render_with_comment() {
        let rule = allow_tcp(22).comment("SSH access");
        assert_eq!(rule.render(), "tcp dport 22 accept comment \"SSH access\"");
    }

    #[test]
    fn render_jump() {
        let rule = Rule::new(Verdict::Jump("container_rules".to_string()))
            .matching(Match::Oif("br0".to_string()));
        assert_eq!(rule.render(), "oif \"br0\" jump container_rules");
    }

    #[test]
    fn render_log() {
        let rule = Rule::new(Verdict::Log(Some("NEIN_DROP: ".into())))
            .matching(Match::Protocol(Protocol::Tcp));
        assert_eq!(rule.render(), "tcp log prefix \"NEIN_DROP: \"");
    }

    #[test]
    fn render_reject() {
        let rule = Rule::new(Verdict::Reject);
        assert_eq!(rule.render(), "reject");
    }

    #[test]
    fn render_goto() {
        let rule = Rule::new(Verdict::GoTo("other_chain".into()));
        assert_eq!(rule.render(), "goto other_chain");
    }

    #[test]
    fn render_return() {
        let rule = Rule::new(Verdict::Return);
        assert_eq!(rule.render(), "return");
    }

    #[test]
    fn render_counter() {
        let rule = Rule::new(Verdict::Counter)
            .matching(Match::Protocol(Protocol::Tcp))
            .matching(Match::DPort(80));
        assert_eq!(rule.render(), "tcp dport 80 counter");
    }

    #[test]
    fn render_log_no_prefix() {
        let rule = Rule::new(Verdict::Log(None));
        assert_eq!(rule.render(), "log");
    }

    #[test]
    fn render_sport() {
        let rule = Rule::new(Verdict::Accept)
            .matching(Match::Protocol(Protocol::Tcp))
            .matching(Match::SPort(1024));
        assert_eq!(rule.render(), "tcp sport 1024 accept");
    }

    #[test]
    fn render_dport_range() {
        let rule = Rule::new(Verdict::Accept)
            .matching(Match::Protocol(Protocol::Tcp))
            .matching(Match::DPortRange(8000, 9000));
        assert_eq!(rule.render(), "tcp dport 8000-9000 accept");
    }

    #[test]
    fn render_dest_addr() {
        let rule = Rule::new(Verdict::Drop).matching(Match::DestAddr("10.0.0.1".into()));
        assert_eq!(rule.render(), "ip daddr 10.0.0.1 drop");
    }

    #[test]
    fn protocol_display() {
        assert_eq!(Protocol::Icmp.to_string(), "icmp");
        assert_eq!(Protocol::Icmpv6.to_string(), "icmpv6");
    }

    #[test]
    fn validate_goto_target() {
        let rule = Rule::new(Verdict::GoTo("valid_chain".into()));
        assert!(rule.validate().is_ok());
        let rule = Rule::new(Verdict::GoTo("bad;chain".into()));
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_log_prefix() {
        let rule = Rule::new(Verdict::Log(Some("GOOD: ".into())));
        assert!(rule.validate().is_ok());
        let rule = Rule::new(Verdict::Log(Some("bad;prefix".into())));
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_good_rule() {
        let rule = allow_service("10.0.0.0/8", Protocol::Tcp, 80);
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_bad_addr() {
        let rule = deny_source("10.0.0.1; flush ruleset");
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_bad_iface() {
        let rule = Rule::new(Verdict::Accept).matching(Match::Iif("eth0; drop".to_string()));
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_bad_comment() {
        let rule = allow_tcp(22).comment("has \"quotes\"");
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_bad_jump_target() {
        let rule = Rule::new(Verdict::Jump("evil;chain".to_string()));
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_port_range_valid() {
        let rule = Rule::new(Verdict::Accept).matching(Match::DPortRange(80, 443));
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_port_range_equal() {
        let rule = Rule::new(Verdict::Accept).matching(Match::DPortRange(80, 80));
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_port_range_inverted() {
        let rule = Rule::new(Verdict::Accept).matching(Match::DPortRange(443, 80));
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_raw_skipped() {
        let rule =
            Rule::new(Verdict::Accept).matching(Match::Raw("anything goes here;{}".to_string()));
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn render_multiple_matches_same_type() {
        // Two DPort matches — unusual but nftables will error, we just render faithfully
        let rule = Rule::new(Verdict::Accept)
            .matching(Match::Protocol(Protocol::Tcp))
            .matching(Match::DPort(80))
            .matching(Match::DPort(443));
        let rendered = rule.render();
        assert!(rendered.contains("dport 80"));
        assert!(rendered.contains("dport 443"));
    }

    #[test]
    fn validate_port_range_edge_single_port() {
        let rule = Rule::new(Verdict::Accept).matching(Match::DPortRange(1, 1));
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_port_range_edge_max() {
        let rule = Rule::new(Verdict::Accept).matching(Match::DPortRange(65535, 65535));
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_port_range_full() {
        let rule = Rule::new(Verdict::Accept).matching(Match::DPortRange(1, 65535));
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn render_allow_udp() {
        let rule = allow_udp(53);
        assert_eq!(rule.render(), "udp dport 53 accept");
    }

    #[test]
    fn render_icmp() {
        let rule = Rule::new(Verdict::Accept).matching(Match::Protocol(Protocol::Icmp));
        assert_eq!(rule.render(), "icmp accept");
    }

    #[test]
    fn render_icmpv6() {
        let rule = Rule::new(Verdict::Accept).matching(Match::Protocol(Protocol::Icmpv6));
        assert_eq!(rule.render(), "icmpv6 accept");
    }

    #[test]
    fn verdict_display_all_variants() {
        assert_eq!(Verdict::Accept.to_string(), "accept");
        assert_eq!(Verdict::Drop.to_string(), "drop");
        assert_eq!(Verdict::Reject.to_string(), "reject");
        assert_eq!(Verdict::Return.to_string(), "return");
        assert_eq!(Verdict::Counter.to_string(), "counter");
        assert_eq!(Verdict::Log(None).to_string(), "log");
        assert_eq!(
            Verdict::Log(Some("TEST: ".into())).to_string(),
            "log prefix \"TEST: \""
        );
        assert_eq!(Verdict::Jump("chain1".into()).to_string(), "jump chain1");
        assert_eq!(Verdict::GoTo("chain2".into()).to_string(), "goto chain2");
    }

    #[test]
    fn validate_dest_addr() {
        let good = Rule::new(Verdict::Drop).matching(Match::DestAddr("10.0.0.0/8".into()));
        assert!(good.validate().is_ok());
        let bad = Rule::new(Verdict::Drop).matching(Match::DestAddr("evil;addr".into()));
        assert!(bad.validate().is_err());
    }

    // -- IPv6 tests --

    #[test]
    fn render_source_addr6() {
        let rule = Rule::new(Verdict::Accept).matching(Match::SourceAddr6("fe80::/10".into()));
        assert_eq!(rule.render(), "ip6 saddr fe80::/10 accept");
    }

    #[test]
    fn render_dest_addr6() {
        let rule = Rule::new(Verdict::Drop).matching(Match::DestAddr6("::1".into()));
        assert_eq!(rule.render(), "ip6 daddr ::1 drop");
    }

    #[test]
    fn validate_addr6() {
        let good = Rule::new(Verdict::Accept).matching(Match::SourceAddr6("fe80::/10".into()));
        assert!(good.validate().is_ok());
        let bad = Rule::new(Verdict::Accept).matching(Match::SourceAddr6("evil;addr".into()));
        assert!(bad.validate().is_err());
    }

    #[test]
    fn render_deny_source6() {
        let rule = deny_source6("2001:db8::/32");
        assert_eq!(rule.render(), "ip6 saddr 2001:db8::/32 drop");
    }

    // -- Rate limiting tests --

    #[test]
    fn render_limit() {
        let rule = Rule::new(Verdict::Accept).matching(Match::Limit {
            rate: 10,
            unit: RateUnit::Second,
            burst: 20,
        });
        assert_eq!(
            rule.render(),
            "limit rate 10/second burst 20 packets accept"
        );
    }

    #[test]
    fn render_rate_limit_tcp() {
        let rule = rate_limit_tcp(22, 3, RateUnit::Minute);
        let rendered = rule.render();
        assert!(rendered.contains("tcp dport 22"));
        assert!(rendered.contains("limit rate 3/minute burst 3 packets"));
        assert!(rendered.contains("accept"));
    }

    #[test]
    fn rate_unit_display() {
        assert_eq!(RateUnit::Second.to_string(), "second");
        assert_eq!(RateUnit::Minute.to_string(), "minute");
        assert_eq!(RateUnit::Hour.to_string(), "hour");
        assert_eq!(RateUnit::Day.to_string(), "day");
    }

    #[test]
    fn validate_limit() {
        let rule = Rule::new(Verdict::Accept).matching(Match::Limit {
            rate: 100,
            unit: RateUnit::Hour,
            burst: 10,
        });
        assert!(rule.validate().is_ok());
    }

    // -- Set lookup tests --

    #[test]
    fn render_set_lookup() {
        let rule = Rule::new(Verdict::Drop).matching(match_set("ip saddr", "blocklist"));
        assert_eq!(rule.render(), "ip saddr @blocklist drop");
    }

    #[test]
    fn validate_set_lookup() {
        let good = Rule::new(Verdict::Accept).matching(match_set("tcp dport", "allowed_ports"));
        assert!(good.validate().is_ok());
        let bad = Rule::new(Verdict::Accept).matching(Match::SetLookup {
            field: "ip saddr".into(),
            set_name: "bad;set".into(),
        });
        assert!(bad.validate().is_err());
    }

    // -- CT helper tests --

    #[test]
    fn render_ct_helper() {
        let rule = Rule::new(Verdict::Accept).matching(Match::CtHelper("ftp".into()));
        assert_eq!(rule.render(), "ct helper \"ftp\" accept");
    }

    #[test]
    fn validate_ct_helper() {
        let good = Rule::new(Verdict::Accept).matching(Match::CtHelper("ftp".into()));
        assert!(good.validate().is_ok());
        let bad = Rule::new(Verdict::Accept).matching(Match::CtHelper("bad;helper".into()));
        assert!(bad.validate().is_err());
    }

    // -- TCP flags tests --

    #[test]
    fn render_tcp_flags() {
        let rule =
            Rule::new(Verdict::Drop).matching(Match::TcpFlags(vec!["syn".into(), "fin".into()]));
        assert_eq!(rule.render(), "tcp flags { syn, fin } drop");
    }

    #[test]
    fn validate_tcp_flags() {
        let good =
            Rule::new(Verdict::Drop).matching(Match::TcpFlags(vec!["syn".into(), "ack".into()]));
        assert!(good.validate().is_ok());
        let bad = Rule::new(Verdict::Drop).matching(Match::TcpFlags(vec!["bad;flag".into()]));
        assert!(bad.validate().is_err());
    }

    // -- ICMP type tests --

    #[test]
    fn render_icmp_type() {
        let rule = Rule::new(Verdict::Accept).matching(Match::IcmpType("echo-request".into()));
        assert_eq!(rule.render(), "icmp type echo-request accept");
    }

    #[test]
    fn render_icmpv6_type() {
        let rule = Rule::new(Verdict::Accept).matching(Match::Icmpv6Type("echo-request".into()));
        assert_eq!(rule.render(), "icmpv6 type echo-request accept");
    }

    #[test]
    fn validate_icmp_type() {
        let good = Rule::new(Verdict::Accept).matching(Match::IcmpType("echo-reply".into()));
        assert!(good.validate().is_ok());
        let bad = Rule::new(Verdict::Accept).matching(Match::IcmpType("bad;type".into()));
        assert!(bad.validate().is_err());
    }

    // -- Meta mark tests --

    #[test]
    fn render_meta_mark() {
        let rule = Rule::new(Verdict::Accept).matching(Match::MetaMark(0x1));
        assert_eq!(rule.render(), "meta mark 1 accept");
    }

    #[test]
    fn render_meta_mark_hex() {
        let rule = Rule::new(Verdict::Drop).matching(Match::MetaMark(255));
        assert_eq!(rule.render(), "meta mark 255 drop");
    }

    #[test]
    fn validate_meta_mark() {
        let rule = Rule::new(Verdict::Accept).matching(Match::MetaMark(42));
        assert!(rule.validate().is_ok());
    }

    // -- Quota tests --

    #[test]
    fn render_quota_over() {
        let rule = Rule::new(Verdict::Drop).matching(Match::Quota {
            mode: QuotaMode::Over,
            amount: 25,
            unit: QuotaUnit::MBytes,
        });
        assert_eq!(rule.render(), "quota over 25 mbytes drop");
    }

    #[test]
    fn render_quota_until() {
        let rule = Rule::new(Verdict::Accept).matching(Match::Quota {
            mode: QuotaMode::Until,
            amount: 100,
            unit: QuotaUnit::GBytes,
        });
        assert_eq!(rule.render(), "quota until 100 gbytes accept");
    }

    #[test]
    fn validate_quota() {
        let rule = Rule::new(Verdict::Accept).matching(Match::Quota {
            mode: QuotaMode::Over,
            amount: 1,
            unit: QuotaUnit::Bytes,
        });
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn quota_mode_display() {
        assert_eq!(QuotaMode::Over.to_string(), "over");
        assert_eq!(QuotaMode::Until.to_string(), "until");
    }

    #[test]
    fn quota_unit_display() {
        assert_eq!(QuotaUnit::Bytes.to_string(), "bytes");
        assert_eq!(QuotaUnit::KBytes.to_string(), "kbytes");
        assert_eq!(QuotaUnit::MBytes.to_string(), "mbytes");
        assert_eq!(QuotaUnit::GBytes.to_string(), "gbytes");
    }

    // -- Flow offload tests --

    #[test]
    fn render_flow_offload() {
        let rule = Rule::new(Verdict::Accept).matching(Match::FlowOffload("ft".into()));
        assert_eq!(rule.render(), "flow offload @ft accept");
    }

    #[test]
    fn validate_flow_offload_good() {
        let rule = Rule::new(Verdict::Accept).matching(Match::FlowOffload("myft".into()));
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_flow_offload_bad() {
        let rule = Rule::new(Verdict::Accept).matching(Match::FlowOffload("bad;ft".into()));
        assert!(rule.validate().is_err());
    }

    // -- CtTimeoutSet tests --

    #[test]
    fn render_ct_timeout_set() {
        let rule = Rule::new(Verdict::Accept).matching(Match::CtTimeoutSet("tcp-long".into()));
        assert_eq!(rule.render(), "ct timeout set \"tcp-long\" accept");
    }

    #[test]
    fn validate_ct_timeout_set_good() {
        let rule = Rule::new(Verdict::Accept).matching(Match::CtTimeoutSet("my-timeout".into()));
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_ct_timeout_set_bad() {
        let rule = Rule::new(Verdict::Accept).matching(Match::CtTimeoutSet("evil;timeout".into()));
        assert!(rule.validate().is_err());
    }

    // -- Mark setting verdict tests --

    #[test]
    fn render_set_mark() {
        let rule = Rule::new(Verdict::SetMark(42))
            .matching(Match::Protocol(Protocol::Tcp))
            .matching(Match::DPort(80));
        assert_eq!(rule.render(), "tcp dport 80 meta mark set 42");
    }

    #[test]
    fn render_set_ct_mark() {
        let rule = Rule::new(Verdict::SetCtMark(0xff));
        assert_eq!(rule.render(), "ct mark set 255");
    }

    #[test]
    fn verdict_set_mark_display() {
        assert_eq!(Verdict::SetMark(1).to_string(), "meta mark set 1");
        assert_eq!(Verdict::SetCtMark(42).to_string(), "ct mark set 42");
    }

    // -- Phase 5: ICMP type+code --

    #[test]
    fn render_icmp_type_code() {
        let rule = Rule::new(Verdict::Drop).matching(Match::IcmpTypeCode("echo-request".into(), 0));
        assert_eq!(rule.render(), "icmp type echo-request icmp code 0 drop");
    }

    #[test]
    fn render_icmpv6_type_code() {
        let rule =
            Rule::new(Verdict::Drop).matching(Match::Icmpv6TypeCode("echo-request".into(), 0));
        assert_eq!(rule.render(), "icmpv6 type echo-request icmpv6 code 0 drop");
    }

    #[test]
    fn validate_icmp_type_code_good() {
        let rule = Rule::new(Verdict::Drop).matching(Match::IcmpTypeCode("echo-reply".into(), 3));
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_icmp_type_code_bad() {
        let rule = Rule::new(Verdict::Drop).matching(Match::IcmpTypeCode("bad;type".into(), 0));
        assert!(rule.validate().is_err());
    }

    // -- Phase 5: VLAN ID --

    #[test]
    fn render_vlan_id() {
        let rule = Rule::new(Verdict::Accept).matching(Match::VlanId(100));
        assert_eq!(rule.render(), "vlan id 100 accept");
    }

    #[test]
    fn validate_vlan_id_good() {
        assert!(
            Rule::new(Verdict::Accept)
                .matching(Match::VlanId(0))
                .validate()
                .is_ok()
        );
        assert!(
            Rule::new(Verdict::Accept)
                .matching(Match::VlanId(4094))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validate_vlan_id_out_of_range() {
        assert!(
            Rule::new(Verdict::Accept)
                .matching(Match::VlanId(4095))
                .validate()
                .is_err()
        );
        assert!(
            Rule::new(Verdict::Accept)
                .matching(Match::VlanId(65535))
                .validate()
                .is_err()
        );
    }

    // -- Phase 5: DSCP --

    #[test]
    fn render_dscp() {
        let rule = Rule::new(Verdict::Accept).matching(Match::Dscp(46));
        assert_eq!(rule.render(), "ip dscp 46 accept");
    }

    #[test]
    fn validate_dscp_good() {
        assert!(
            Rule::new(Verdict::Accept)
                .matching(Match::Dscp(0))
                .validate()
                .is_ok()
        );
        assert!(
            Rule::new(Verdict::Accept)
                .matching(Match::Dscp(63))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validate_dscp_out_of_range() {
        assert!(
            Rule::new(Verdict::Accept)
                .matching(Match::Dscp(64))
                .validate()
                .is_err()
        );
        assert!(
            Rule::new(Verdict::Accept)
                .matching(Match::Dscp(255))
                .validate()
                .is_err()
        );
    }

    // -- Phase 5: IPv6 extension headers --

    #[test]
    fn render_ipv6_ext_hdr() {
        let rule = Rule::new(Verdict::Drop).matching(Match::Ipv6ExtHdrExists(Ipv6ExtHdr::Routing));
        assert_eq!(rule.render(), "exthdr rt exists drop");
    }

    #[test]
    fn ipv6_ext_hdr_display() {
        assert_eq!(Ipv6ExtHdr::HopByHop.to_string(), "hbh");
        assert_eq!(Ipv6ExtHdr::Routing.to_string(), "rt");
        assert_eq!(Ipv6ExtHdr::Fragment.to_string(), "frag");
        assert_eq!(Ipv6ExtHdr::Destination.to_string(), "dst");
        assert_eq!(Ipv6ExtHdr::Mobility.to_string(), "mh");
        assert_eq!(Ipv6ExtHdr::Authentication.to_string(), "auth");
    }

    #[test]
    fn validate_ipv6_ext_hdr() {
        let rule = Rule::new(Verdict::Drop).matching(Match::Ipv6ExtHdrExists(Ipv6ExtHdr::Fragment));
        assert!(rule.validate().is_ok());
    }

    // -- Phase 5: Fragment matching --

    #[test]
    fn render_frag_more_fragments() {
        let rule = Rule::new(Verdict::Drop).matching(Match::FragOff {
            mask: 0x2000,
            op: CmpOp::Ne,
            value: 0,
        });
        assert_eq!(rule.render(), "ip frag-off & 0x2000 != 0x0 drop");
    }

    #[test]
    fn render_frag_is_fragment() {
        let rule = Rule::new(Verdict::Drop).matching(Match::FragOff {
            mask: 0x1fff,
            op: CmpOp::Ne,
            value: 0,
        });
        assert_eq!(rule.render(), "ip frag-off & 0x1fff != 0x0 drop");
    }

    #[test]
    fn validate_frag_good() {
        let rule = Rule::new(Verdict::Drop).matching(Match::FragOff {
            mask: 0x2000,
            op: CmpOp::Ne,
            value: 0,
        });
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn cmp_op_display() {
        assert_eq!(CmpOp::Eq.to_string(), "==");
        assert_eq!(CmpOp::Ne.to_string(), "!=");
        assert_eq!(CmpOp::Lt.to_string(), "<");
        assert_eq!(CmpOp::Gt.to_string(), ">");
        assert_eq!(CmpOp::Le.to_string(), "<=");
        assert_eq!(CmpOp::Ge.to_string(), ">=");
    }

    // -- Phase 5: Packet type --

    #[test]
    fn render_pkt_type_broadcast() {
        let rule = Rule::new(Verdict::Drop).matching(Match::PktType(PktType::Broadcast));
        assert_eq!(rule.render(), "meta pkttype broadcast drop");
    }

    #[test]
    fn render_pkt_type_multicast() {
        let rule = Rule::new(Verdict::Accept).matching(Match::PktType(PktType::Multicast));
        assert_eq!(rule.render(), "meta pkttype multicast accept");
    }

    #[test]
    fn pkt_type_display() {
        assert_eq!(PktType::Unicast.to_string(), "unicast");
        assert_eq!(PktType::Broadcast.to_string(), "broadcast");
        assert_eq!(PktType::Multicast.to_string(), "multicast");
    }

    // -- Phase 5: Enhanced logging --

    #[test]
    fn render_log_advanced_full() {
        let rule = Rule::new(Verdict::LogAdvanced {
            prefix: Some("NEIN: ".into()),
            level: Some(LogLevel::Warn),
            group: Some(1),
            snaplen: Some(128),
        });
        assert_eq!(
            rule.render(),
            "log prefix \"NEIN: \" level warn group 1 snaplen 128"
        );
    }

    #[test]
    fn render_log_advanced_level_only() {
        let rule = Rule::new(Verdict::LogAdvanced {
            prefix: None,
            level: Some(LogLevel::Debug),
            group: None,
            snaplen: None,
        });
        assert_eq!(rule.render(), "log level debug");
    }

    #[test]
    fn render_log_advanced_group_only() {
        let rule = Rule::new(Verdict::LogAdvanced {
            prefix: None,
            level: None,
            group: Some(5),
            snaplen: None,
        });
        assert_eq!(rule.render(), "log group 5");
    }

    #[test]
    fn render_log_advanced_bare() {
        let rule = Rule::new(Verdict::LogAdvanced {
            prefix: None,
            level: None,
            group: None,
            snaplen: None,
        });
        assert_eq!(rule.render(), "log");
    }

    #[test]
    fn validate_log_advanced_good() {
        let rule = Rule::new(Verdict::LogAdvanced {
            prefix: Some("TEST: ".into()),
            level: Some(LogLevel::Info),
            group: None,
            snaplen: None,
        });
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_log_advanced_bad_prefix() {
        let rule = Rule::new(Verdict::LogAdvanced {
            prefix: Some("bad;prefix".into()),
            level: None,
            group: None,
            snaplen: None,
        });
        assert!(rule.validate().is_err());
    }

    #[test]
    fn log_level_display() {
        assert_eq!(LogLevel::Emerg.to_string(), "emerg");
        assert_eq!(LogLevel::Alert.to_string(), "alert");
        assert_eq!(LogLevel::Crit.to_string(), "crit");
        assert_eq!(LogLevel::Err.to_string(), "err");
        assert_eq!(LogLevel::Warn.to_string(), "warn");
        assert_eq!(LogLevel::Notice.to_string(), "notice");
        assert_eq!(LogLevel::Info.to_string(), "info");
        assert_eq!(LogLevel::Debug.to_string(), "debug");
    }

    // -- Phase 5: Enhanced counters --

    #[test]
    fn render_counter_named() {
        let rule = Rule::new(Verdict::CounterNamed("http_hits".into()))
            .matching(Match::Protocol(Protocol::Tcp))
            .matching(Match::DPort(80));
        assert_eq!(rule.render(), "tcp dport 80 counter name \"http_hits\"");
    }

    #[test]
    fn validate_counter_named_good() {
        let rule = Rule::new(Verdict::CounterNamed("my-counter".into()));
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_counter_named_bad() {
        let rule = Rule::new(Verdict::CounterNamed("bad;counter".into()));
        assert!(rule.validate().is_err());
    }

    // -- Phase 6: Bulk match builders --

    #[test]
    fn matching_ports() {
        let rule = Rule::new(Verdict::Accept).matching_ports(Protocol::Tcp, &[80, 443, 8080]);
        let rendered = rule.render();
        assert_eq!(rendered, "tcp dport { 80, 443, 8080 } accept");
    }

    #[test]
    fn matching_addrs() {
        let rule = Rule::new(Verdict::Drop).matching_addrs(&["10.0.0.0/8", "192.168.0.0/16"]);
        assert_eq!(
            rule.render(),
            "ip saddr { 10.0.0.0/8, 192.168.0.0/16 } drop"
        );
    }

    #[test]
    fn matching_addrs6() {
        let rule = Rule::new(Verdict::Drop).matching_addrs6(&["fe80::/10", "::1"]);
        assert_eq!(rule.render(), "ip6 saddr { fe80::/10, ::1 } drop");
    }
}
