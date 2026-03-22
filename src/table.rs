//! nftables tables.

use crate::chain::Chain;
use serde::{Deserialize, Serialize};

/// nftables address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Family {
    Inet,
    Ip,
    Ip6,
    Arp,
    Bridge,
    Netdev,
}

impl std::fmt::Display for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inet => write!(f, "inet"),
            Self::Ip => write!(f, "ip"),
            Self::Ip6 => write!(f, "ip6"),
            Self::Arp => write!(f, "arp"),
            Self::Bridge => write!(f, "bridge"),
            Self::Netdev => write!(f, "netdev"),
        }
    }
}

/// An nftables table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Table {
    pub name: String,
    pub family: Family,
    pub chains: Vec<Chain>,
}

impl Table {
    /// Create a new table.
    pub fn new(name: &str, family: Family) -> Self {
        Self {
            name: name.to_string(),
            family,
            chains: vec![],
        }
    }

    /// Add a chain to this table.
    pub fn add_chain(&mut self, chain: Chain) {
        self.chains.push(chain);
    }

    /// Render this table as nftables syntax.
    pub fn render(&self) -> String {
        let mut out = format!("table {} {} {{\n", self.family, self.name);
        for chain in &self.chains {
            out.push_str(&chain.render());
        }
        out.push_str("}\n");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_render_empty() {
        let table = Table::new("filter", Family::Inet);
        let rendered = table.render();
        assert!(rendered.contains("table inet filter"));
        assert!(rendered.contains('}'));
    }

    #[test]
    fn family_display() {
        assert_eq!(Family::Inet.to_string(), "inet");
        assert_eq!(Family::Ip.to_string(), "ip");
        assert_eq!(Family::Ip6.to_string(), "ip6");
        assert_eq!(Family::Arp.to_string(), "arp");
        assert_eq!(Family::Bridge.to_string(), "bridge");
        assert_eq!(Family::Netdev.to_string(), "netdev");
    }
}
