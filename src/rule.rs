//! nftables rules — match expressions and verdicts.

use serde::{Deserialize, Serialize};

/// A firewall rule verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// A match expression in a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Match {
    /// Match source IP/CIDR.
    SourceAddr(String),
    /// Match destination IP/CIDR.
    DestAddr(String),
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
    /// Raw nft expression (escape hatch).
    Raw(String),
}

/// An nftables rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub matches: Vec<Match>,
    pub verdict: Verdict,
    #[serde(default)]
    pub comment: Option<String>,
}

impl Rule {
    /// Create a new rule with a verdict.
    pub fn new(verdict: Verdict) -> Self {
        Self {
            matches: vec![],
            verdict,
            comment: None,
        }
    }

    /// Add a match expression.
    pub fn matching(mut self, m: Match) -> Self {
        self.matches.push(m);
        self
    }

    /// Add a comment.
    pub fn comment(mut self, c: &str) -> Self {
        self.comment = Some(c.to_string());
        self
    }

    /// Render this rule as nftables syntax.
    pub fn render(&self) -> String {
        let mut parts: Vec<String> = vec![];

        for m in &self.matches {
            parts.push(match m {
                Match::SourceAddr(addr) => format!("ip saddr {addr}"),
                Match::DestAddr(addr) => format!("ip daddr {addr}"),
                Match::Protocol(proto) => format!("{proto}"),
                Match::DPort(port) => format!("dport {port}"),
                Match::SPort(port) => format!("sport {port}"),
                Match::DPortRange(lo, hi) => format!("dport {lo}-{hi}"),
                Match::Iif(iface) => format!("iif \"{iface}\""),
                Match::Oif(iface) => format!("oif \"{iface}\""),
                Match::CtState(states) => format!("ct state {{ {} }}", states.join(", ")),
                Match::Raw(expr) => expr.clone(),
            });
        }

        let verdict = match &self.verdict {
            Verdict::Accept => "accept".to_string(),
            Verdict::Drop => "drop".to_string(),
            Verdict::Reject => "reject".to_string(),
            Verdict::Jump(chain) => format!("jump {chain}"),
            Verdict::GoTo(chain) => format!("goto {chain}"),
            Verdict::Return => "return".to_string(),
            Verdict::Log(prefix) => match prefix {
                Some(p) => format!("log prefix \"{p}\""),
                None => "log".to_string(),
            },
            Verdict::Counter => "counter".to_string(),
        };
        parts.push(verdict);

        if let Some(comment) = &self.comment {
            parts.push(format!("comment \"{comment}\""));
        }

        parts.join(" ")
    }
}

/// Convenience: allow TCP port.
pub fn allow_tcp(port: u16) -> Rule {
    Rule::new(Verdict::Accept)
        .matching(Match::Protocol(Protocol::Tcp))
        .matching(Match::DPort(port))
}

/// Convenience: allow UDP port.
pub fn allow_udp(port: u16) -> Rule {
    Rule::new(Verdict::Accept)
        .matching(Match::Protocol(Protocol::Udp))
        .matching(Match::DPort(port))
}

/// Convenience: allow established/related connections.
pub fn allow_established() -> Rule {
    Rule::new(Verdict::Accept)
        .matching(Match::CtState(vec!["established".into(), "related".into()]))
}

/// Convenience: drop from source CIDR.
pub fn deny_source(cidr: &str) -> Rule {
    Rule::new(Verdict::Drop)
        .matching(Match::SourceAddr(cidr.to_string()))
}

/// Convenience: allow specific source to specific port (service policy).
pub fn allow_service(source_cidr: &str, protocol: Protocol, port: u16) -> Rule {
    Rule::new(Verdict::Accept)
        .matching(Match::SourceAddr(source_cidr.to_string()))
        .matching(Match::Protocol(protocol))
        .matching(Match::DPort(port))
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
        assert_eq!(rule.render(), "ip saddr 192.168.1.0/24 tcp dport 8090 accept");
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
}
