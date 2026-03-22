//! NAT rules — SNAT, DNAT, masquerade for container networking.

use crate::error::NeinError;
use crate::validate;
use serde::{Deserialize, Serialize};

/// A NAT rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        }
        Ok(())
    }

    /// Render as nftables syntax.
    pub fn render(&self) -> String {
        match self {
            Self::Dnat {
                protocol,
                dest_port,
                to_addr,
                to_port,
                comment,
            } => {
                let mut r = format!("{protocol} dport {dest_port} dnat to {to_addr}:{to_port}");
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
        }
    }
}

/// Convenience: port forward (DNAT) for container port mapping.
pub fn port_forward(host_port: u16, container_addr: &str, container_port: u16) -> NatRule {
    NatRule::Dnat {
        protocol: crate::rule::Protocol::Tcp,
        dest_port: host_port,
        to_addr: container_addr.to_string(),
        to_port: container_port,
        comment: Some(format!("container port {host_port}->{container_port}")),
    }
}

/// Convenience: masquerade for container outbound traffic.
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
}
