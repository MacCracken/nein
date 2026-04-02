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
                Match::Limit { .. } | Match::MetaMark(_) => {
                    // Typed values, no injection possible.
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
}
