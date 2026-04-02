//! NAT rules — SNAT, DNAT, masquerade for container networking.

use crate::error::NeinError;
use crate::validate;
use serde::{Deserialize, Serialize};

/// A NAT rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NatRule {
    /// Destination NAT (port forwarding).
    Dnat {
        protocol: crate::rule::Protocol,
        dest_port: u16,
        to_addr: String,
        to_port: u16,
        comment: Option<String>,
    },
    /// Source NAT (outbound).
    Snat {
        source_cidr: String,
        to_addr: String,
        comment: Option<String>,
    },
    /// Masquerade (dynamic SNAT for outbound container traffic).
    Masquerade {
        source_cidr: String,
        oif: Option<String>,
        comment: Option<String>,
    },
    /// Redirect (local port redirect).
    Redirect {
        protocol: crate::rule::Protocol,
        dest_port: u16,
        to_port: u16,
        comment: Option<String>,
    },
    /// Destination NAT with port range mapping.
    ///
    /// Maps a range of host ports to a range of container ports.
    /// Source and destination ranges must be the same size.
    DnatRange {
        protocol: crate::rule::Protocol,
        dest_port_start: u16,
        dest_port_end: u16,
        to_addr: String,
        to_port_start: u16,
        to_port_end: u16,
        comment: Option<String>,
    },
}

impl NatRule {
    /// Validate all string fields for dangerous input.
    pub fn validate(&self) -> Result<(), NeinError> {
        match self {
            Self::Dnat {
                to_addr, comment, ..
            } => {
                validate::validate_addr(to_addr)?;
                if let Some(c) = comment {
                    validate::validate_comment(c)?;
                }
            }
            Self::Snat {
                source_cidr,
                to_addr,
                comment,
                ..
            } => {
                validate::validate_addr(source_cidr)?;
                validate::validate_addr(to_addr)?;
                if let Some(c) = comment {
                    validate::validate_comment(c)?;
                }
            }
            Self::Masquerade {
                source_cidr,
                oif,
                comment,
                ..
            } => {
                validate::validate_addr(source_cidr)?;
                if let Some(iface) = oif {
                    validate::validate_iface(iface)?;
                }
                if let Some(c) = comment {
                    validate::validate_comment(c)?;
                }
            }
            Self::Redirect { comment, .. } => {
                if let Some(c) = comment {
                    validate::validate_comment(c)?;
                }
            }
            Self::DnatRange {
                dest_port_start,
                dest_port_end,
                to_addr,
                to_port_start,
                to_port_end,
                comment,
                ..
            } => {
                validate::validate_addr(to_addr)?;
                if dest_port_start > dest_port_end {
                    return Err(NeinError::InvalidRule(format!(
                        "dest port range start ({dest_port_start}) exceeds end ({dest_port_end})"
                    )));
                }
                if to_port_start > to_port_end {
                    return Err(NeinError::InvalidRule(format!(
                        "to port range start ({to_port_start}) exceeds end ({to_port_end})"
                    )));
                }
                if (dest_port_end - dest_port_start) != (to_port_end - to_port_start) {
                    return Err(NeinError::InvalidRule(
                        "source and destination port ranges must be the same size".into(),
                    ));
                }
                if let Some(c) = comment {
                    validate::validate_comment(c)?;
                }
            }
        }
        Ok(())
    }

    /// Render as nftables syntax.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Dnat {
                protocol,
                dest_port,
                to_addr,
                to_port,
                comment,
            } => {
                // Bracket IPv6 addresses to avoid ambiguity with port separator
                let addr_str = if to_addr.contains(':') {
                    format!("[{to_addr}]")
                } else {
                    to_addr.clone()
                };
                let mut r = format!("{protocol} dport {dest_port} dnat to {addr_str}:{to_port}");
                if let Some(c) = comment {
                    r.push_str(&format!(" comment \"{c}\""));
                }
                r
            }
            Self::Snat {
                source_cidr,
                to_addr,
                comment,
            } => {
                let mut r = format!("ip saddr {source_cidr} snat to {to_addr}");
                if let Some(c) = comment {
                    r.push_str(&format!(" comment \"{c}\""));
                }
                r
            }
            Self::Masquerade {
                source_cidr,
                oif,
                comment,
            } => {
                let mut r = format!("ip saddr {source_cidr}");
                if let Some(iface) = oif {
                    r.push_str(&format!(" oif \"{iface}\""));
                }
                r.push_str(" masquerade");
                if let Some(c) = comment {
                    r.push_str(&format!(" comment \"{c}\""));
                }
                r
            }
            Self::Redirect {
                protocol,
                dest_port,
                to_port,
                comment,
            } => {
                let mut r = format!("{protocol} dport {dest_port} redirect to :{to_port}");
                if let Some(c) = comment {
                    r.push_str(&format!(" comment \"{c}\""));
                }
                r
            }
            Self::DnatRange {
                protocol,
                dest_port_start,
                dest_port_end,
                to_addr,
                to_port_start,
                to_port_end,
                comment,
            } => {
                let addr_str = if to_addr.contains(':') {
                    format!("[{to_addr}]")
                } else {
                    to_addr.clone()
                };
                let mut r = format!(
                    "{protocol} dport {dest_port_start}-{dest_port_end} dnat to {addr_str}:{to_port_start}-{to_port_end}"
                );
                if let Some(c) = comment {
                    r.push_str(&format!(" comment \"{c}\""));
                }
                r
            }
        }
    }
}

/// Convenience: port forward (DNAT) for container port mapping.
#[must_use]
pub fn port_forward(host_port: u16, container_addr: &str, container_port: u16) -> NatRule {
    NatRule::Dnat {
        protocol: crate::rule::Protocol::Tcp,
        dest_port: host_port,
        to_addr: container_addr.to_string(),
        to_port: container_port,
        comment: Some(format!("container port {host_port}->{container_port}")),
    }
}

/// Convenience: port range forward (DNAT) for container port range mapping.
///
/// Maps `host_start..=host_end` to `container_addr:container_start..=container_start+(host_end-host_start)`.
#[must_use]
pub fn port_range_forward(
    host_start: u16,
    host_end: u16,
    container_addr: &str,
    container_start: u16,
) -> NatRule {
    let range_size = host_end.saturating_sub(host_start);
    let container_end = container_start.saturating_add(range_size);
    NatRule::DnatRange {
        protocol: crate::rule::Protocol::Tcp,
        dest_port_start: host_start,
        dest_port_end: host_end,
        to_addr: container_addr.to_string(),
        to_port_start: container_start,
        to_port_end: container_end,
        comment: Some(format!(
            "container ports {host_start}-{host_end}->{container_start}-{container_end}"
        )),
    }
}

/// Convenience: masquerade for container outbound traffic.
#[must_use]
pub fn container_masquerade(subnet: &str, outbound_iface: &str) -> NatRule {
    NatRule::Masquerade {
        source_cidr: subnet.to_string(),
        oif: Some(outbound_iface.to_string()),
        comment: Some("container outbound NAT".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_dnat() {
        let rule = port_forward(8080, "172.17.0.2", 80);
        assert_eq!(
            rule.render(),
            "tcp dport 8080 dnat to 172.17.0.2:80 comment \"container port 8080->80\""
        );
    }

    #[test]
    fn render_masquerade() {
        let rule = container_masquerade("172.17.0.0/16", "eth0");
        assert_eq!(
            rule.render(),
            "ip saddr 172.17.0.0/16 oif \"eth0\" masquerade comment \"container outbound NAT\""
        );
    }

    #[test]
    fn render_redirect() {
        let rule = NatRule::Redirect {
            protocol: crate::rule::Protocol::Tcp,
            dest_port: 80,
            to_port: 8080,
            comment: None,
        };
        assert_eq!(rule.render(), "tcp dport 80 redirect to :8080");
    }

    #[test]
    fn validate_good_dnat() {
        let rule = port_forward(8080, "172.17.0.2", 80);
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_bad_addr() {
        let rule = NatRule::Snat {
            source_cidr: "10.0.0.0/8; drop".to_string(),
            to_addr: "1.2.3.4".to_string(),
            comment: None,
        };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_bad_iface() {
        let rule = NatRule::Masquerade {
            source_cidr: "10.0.0.0/8".to_string(),
            oif: Some("eth0; drop".to_string()),
            comment: None,
        };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn render_snat() {
        let rule = NatRule::Snat {
            source_cidr: "10.0.0.0/8".to_string(),
            to_addr: "1.2.3.4".to_string(),
            comment: None,
        };
        assert_eq!(rule.render(), "ip saddr 10.0.0.0/8 snat to 1.2.3.4");
    }

    #[test]
    fn render_snat_with_comment() {
        let rule = NatRule::Snat {
            source_cidr: "10.0.0.0/8".to_string(),
            to_addr: "1.2.3.4".to_string(),
            comment: Some("outbound SNAT".to_string()),
        };
        let rendered = rule.render();
        assert!(rendered.contains("snat to 1.2.3.4"));
        assert!(rendered.contains("comment \"outbound SNAT\""));
    }

    #[test]
    fn render_dnat_with_comment() {
        let rule = NatRule::Dnat {
            protocol: crate::rule::Protocol::Tcp,
            dest_port: 443,
            to_addr: "10.0.0.1".to_string(),
            to_port: 8443,
            comment: Some("TLS forward".to_string()),
        };
        let rendered = rule.render();
        assert!(rendered.contains("dnat to 10.0.0.1:8443"));
        assert!(rendered.contains("comment \"TLS forward\""));
    }

    #[test]
    fn render_redirect_with_comment() {
        let rule = NatRule::Redirect {
            protocol: crate::rule::Protocol::Tcp,
            dest_port: 80,
            to_port: 8080,
            comment: Some("local redirect".to_string()),
        };
        let rendered = rule.render();
        assert!(rendered.contains("redirect to :8080"));
        assert!(rendered.contains("comment \"local redirect\""));
    }

    #[test]
    fn render_masquerade_no_oif() {
        let rule = NatRule::Masquerade {
            source_cidr: "10.0.0.0/8".to_string(),
            oif: None,
            comment: None,
        };
        assert_eq!(rule.render(), "ip saddr 10.0.0.0/8 masquerade");
    }

    #[test]
    fn render_masquerade_with_comment() {
        let rule = NatRule::Masquerade {
            source_cidr: "10.0.0.0/8".to_string(),
            oif: Some("eth0".to_string()),
            comment: Some("NAT out".to_string()),
        };
        let rendered = rule.render();
        assert!(rendered.contains("masquerade"));
        assert!(rendered.contains("comment \"NAT out\""));
    }

    #[test]
    fn validate_snat() {
        let good = NatRule::Snat {
            source_cidr: "10.0.0.0/8".to_string(),
            to_addr: "1.2.3.4".to_string(),
            comment: None,
        };
        assert!(good.validate().is_ok());

        let bad = NatRule::Snat {
            source_cidr: "10.0.0.0/8".to_string(),
            to_addr: "bad;addr".to_string(),
            comment: None,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn validate_redirect_comment() {
        let good = NatRule::Redirect {
            protocol: crate::rule::Protocol::Tcp,
            dest_port: 80,
            to_port: 8080,
            comment: Some("valid".to_string()),
        };
        assert!(good.validate().is_ok());

        let bad = NatRule::Redirect {
            protocol: crate::rule::Protocol::Tcp,
            dest_port: 80,
            to_port: 8080,
            comment: Some("bad;comment".to_string()),
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn validate_masquerade_comment() {
        let bad = NatRule::Masquerade {
            source_cidr: "10.0.0.0/8".to_string(),
            oif: None,
            comment: Some("bad;comment".to_string()),
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn validate_dnat_comment() {
        let bad = NatRule::Dnat {
            protocol: crate::rule::Protocol::Tcp,
            dest_port: 80,
            to_addr: "10.0.0.1".to_string(),
            to_port: 8080,
            comment: Some("bad;comment".to_string()),
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn render_dnat_ipv6_brackets() {
        let rule = NatRule::Dnat {
            protocol: crate::rule::Protocol::Tcp,
            dest_port: 443,
            to_addr: "2001:db8::1".to_string(),
            to_port: 8443,
            comment: None,
        };
        assert_eq!(rule.render(), "tcp dport 443 dnat to [2001:db8::1]:8443");
    }

    #[test]
    fn render_dnat_ipv4_no_brackets() {
        let rule = NatRule::Dnat {
            protocol: crate::rule::Protocol::Tcp,
            dest_port: 80,
            to_addr: "10.0.0.1".to_string(),
            to_port: 8080,
            comment: None,
        };
        assert_eq!(rule.render(), "tcp dport 80 dnat to 10.0.0.1:8080");
    }

    // -- DnatRange tests --

    #[test]
    fn render_dnat_range() {
        let rule = port_range_forward(80, 89, "172.17.0.2", 8080);
        let rendered = rule.render();
        assert!(rendered.contains("tcp dport 80-89 dnat to 172.17.0.2:8080-8089"));
    }

    #[test]
    fn render_dnat_range_ipv6() {
        let rule = NatRule::DnatRange {
            protocol: crate::rule::Protocol::Tcp,
            dest_port_start: 80,
            dest_port_end: 89,
            to_addr: "2001:db8::1".to_string(),
            to_port_start: 8080,
            to_port_end: 8089,
            comment: None,
        };
        assert_eq!(
            rule.render(),
            "tcp dport 80-89 dnat to [2001:db8::1]:8080-8089"
        );
    }

    #[test]
    fn render_dnat_range_with_comment() {
        let rule = NatRule::DnatRange {
            protocol: crate::rule::Protocol::Tcp,
            dest_port_start: 80,
            dest_port_end: 89,
            to_addr: "10.0.0.1".to_string(),
            to_port_start: 8080,
            to_port_end: 8089,
            comment: Some("web range".to_string()),
        };
        let rendered = rule.render();
        assert!(rendered.contains("comment \"web range\""));
    }

    #[test]
    fn validate_dnat_range_good() {
        let rule = port_range_forward(80, 89, "172.17.0.2", 8080);
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_dnat_range_bad_addr() {
        let rule = NatRule::DnatRange {
            protocol: crate::rule::Protocol::Tcp,
            dest_port_start: 80,
            dest_port_end: 89,
            to_addr: "evil;addr".to_string(),
            to_port_start: 8080,
            to_port_end: 8089,
            comment: None,
        };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_dnat_range_inverted_dest() {
        let rule = NatRule::DnatRange {
            protocol: crate::rule::Protocol::Tcp,
            dest_port_start: 89,
            dest_port_end: 80,
            to_addr: "10.0.0.1".to_string(),
            to_port_start: 8080,
            to_port_end: 8089,
            comment: None,
        };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_dnat_range_size_mismatch() {
        let rule = NatRule::DnatRange {
            protocol: crate::rule::Protocol::Tcp,
            dest_port_start: 80,
            dest_port_end: 89,
            to_addr: "10.0.0.1".to_string(),
            to_port_start: 8080,
            to_port_end: 8085,
            comment: None,
        };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_dnat_range_bad_comment() {
        let rule = NatRule::DnatRange {
            protocol: crate::rule::Protocol::Tcp,
            dest_port_start: 80,
            dest_port_end: 89,
            to_addr: "10.0.0.1".to_string(),
            to_port_start: 8080,
            to_port_end: 8089,
            comment: Some("bad;comment".to_string()),
        };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_dnat_range_single_port() {
        let rule = NatRule::DnatRange {
            protocol: crate::rule::Protocol::Tcp,
            dest_port_start: 80,
            dest_port_end: 80,
            to_addr: "10.0.0.1".to_string(),
            to_port_start: 8080,
            to_port_end: 8080,
            comment: None,
        };
        assert!(rule.validate().is_ok());
    }
}
