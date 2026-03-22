//! NAT rules — SNAT, DNAT, masquerade for container networking.

use serde::{Deserialize, Serialize};

/// A NAT rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Render as nftables syntax.
    pub fn render(&self) -> String {
        match self {
            Self::Dnat { protocol, dest_port, to_addr, to_port, comment } => {
                let mut r = format!("{protocol} dport {dest_port} dnat to {to_addr}:{to_port}");
                if let Some(c) = comment {
                    r.push_str(&format!(" comment \"{c}\""));
                }
                r
            }
            Self::Snat { source_cidr, to_addr, comment } => {
                let mut r = format!("ip saddr {source_cidr} snat to {to_addr}");
                if let Some(c) = comment {
                    r.push_str(&format!(" comment \"{c}\""));
                }
                r
            }
            Self::Masquerade { source_cidr, oif, comment } => {
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
            Self::Redirect { protocol, dest_port, to_port, comment } => {
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
}
