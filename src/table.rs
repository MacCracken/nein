//! nftables tables.

use crate::chain::Chain;
use crate::set::{NftMap, NftSet};
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Table {
    pub name: String,
    pub family: Family,
    pub chains: Vec<Chain>,
    #[serde(default)]
    pub sets: Vec<NftSet>,
    #[serde(default)]
    pub maps: Vec<NftMap>,
}

impl Table {
    /// Create a new table.
    pub fn new(name: &str, family: Family) -> Self {
        Self {
            name: name.to_string(),
            family,
            chains: vec![],
            sets: vec![],
            maps: vec![],
        }
    }

    /// Add a chain to this table.
    pub fn add_chain(&mut self, chain: Chain) {
        self.chains.push(chain);
    }

    /// Add a named set to this table.
    pub fn add_set(&mut self, set: NftSet) {
        self.sets.push(set);
    }

    /// Add a verdict map to this table.
    pub fn add_map(&mut self, map: NftMap) {
        self.maps.push(map);
    }

    /// Render this table as nftables syntax.
    pub fn render(&self) -> String {
        let mut out = format!("table {} {} {{\n", self.family, self.name);
        for set in &self.sets {
            out.push_str(&set.render());
        }
        for map in &self.maps {
            out.push_str(&map.render());
        }
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
    use crate::set::{MapVerdict, SetType};

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

    #[test]
    fn table_with_set() {
        let mut table = Table::new("filter", Family::Inet);
        table.add_set(
            NftSet::new("blocklist", SetType::Ipv4Addr).elements(&["10.0.0.1", "10.0.0.2"]),
        );
        let rendered = table.render();
        assert!(rendered.contains("set blocklist"));
        assert!(rendered.contains("10.0.0.1, 10.0.0.2"));
    }

    #[test]
    fn table_with_map() {
        let mut table = Table::new("filter", Family::Inet);
        table.add_map(
            NftMap::new("portmap", SetType::InetService)
                .entry("80", MapVerdict::Jump("web".into())),
        );
        let rendered = table.render();
        assert!(rendered.contains("map portmap"));
        assert!(rendered.contains("80 : jump web"));
    }

    #[test]
    fn table_render_order() {
        let mut table = Table::new("filter", Family::Inet);
        table.add_set(NftSet::new("myset", SetType::Ipv4Addr));
        table.add_map(NftMap::new("mymap", SetType::InetService));
        table.add_chain(crate::chain::Chain::regular("mychain"));

        let rendered = table.render();
        // Sets before maps before chains
        let set_pos = rendered.find("set myset").unwrap();
        let map_pos = rendered.find("map mymap").unwrap();
        let chain_pos = rendered.find("chain mychain").unwrap();
        assert!(set_pos < map_pos);
        assert!(map_pos < chain_pos);
    }
}
