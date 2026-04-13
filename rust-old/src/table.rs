//! nftables tables.

use crate::chain::{Chain, Hook};
use crate::error::NeinError;
use crate::rule::Protocol;
use crate::set::{NftMap, NftSet};
use crate::validate;
use serde::{Deserialize, Serialize};

/// nftables address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
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

// -- Define --

/// An nftables `define` variable.
///
/// Renders as `define $name = value;` inside a table block.
/// Useful for reusable constants (IPs, ports, interface names).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Define {
    pub name: String,
    pub value: String,
}

impl Define {
    /// Create a new define variable.
    #[must_use]
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    /// Validate the define name and value.
    pub fn validate(&self) -> Result<(), NeinError> {
        validate::validate_identifier(&self.name)?;
        validate::validate_nft_element(&self.value)?;
        Ok(())
    }

    /// Render as nftables syntax.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(32);
        let _ = writeln!(out, "  define ${} = {};", self.name, self.value);
        out
    }
}

// -- Flowtable --

/// An nftables flowtable for hardware offload.
///
/// Flowtables enable connection tracking offload to hardware on
/// supported NICs, significantly improving throughput for established
/// connections.
///
/// # Example
///
/// ```text
/// flowtable ft {
///     hook ingress priority filter;
///     devices = { eth0, eth1 };
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Flowtable {
    pub name: String,
    pub hook: Hook,
    pub priority: i32,
    pub devices: Vec<String>,
}

impl Flowtable {
    /// Create a new flowtable.
    #[must_use]
    pub fn new(name: &str, priority: i32, devices: Vec<String>) -> Self {
        Self {
            name: name.to_string(),
            hook: Hook::Ingress,
            priority,
            devices,
        }
    }

    /// Validate flowtable fields.
    pub fn validate(&self) -> Result<(), NeinError> {
        validate::validate_identifier(&self.name)?;
        if self.hook != Hook::Ingress {
            return Err(NeinError::InvalidRule(
                "flowtable hook must be ingress".into(),
            ));
        }
        if self.devices.is_empty() {
            return Err(NeinError::InvalidRule(
                "flowtable requires at least one device".into(),
            ));
        }
        for dev in &self.devices {
            validate::validate_iface(dev)?;
        }
        Ok(())
    }

    /// Render as nftables syntax.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write;

        let mut out = String::with_capacity(128);
        let _ = writeln!(out, "  flowtable {} {{", self.name);
        let _ = writeln!(out, "    hook {} priority {};", self.hook, self.priority);
        if !self.devices.is_empty() {
            let _ = writeln!(out, "    devices = {{ {} }};", self.devices.join(", "));
        }
        out.push_str("  }\n");
        out
    }
}

// -- CtTimeout --

/// A conntrack timeout policy.
///
/// Allows per-protocol timeout tuning for connection tracking states.
///
/// # Example
///
/// ```text
/// ct timeout my-tcp-timeout {
///     protocol tcp;
///     l3proto ip;
///     policy = { established: 7200, close_wait: 60 };
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CtTimeout {
    pub name: String,
    pub protocol: Protocol,
    pub l3proto: Option<Family>,
    /// State name → timeout in seconds.
    pub policy: Vec<(String, u32)>,
}

impl CtTimeout {
    /// Create a new conntrack timeout policy.
    #[must_use]
    pub fn new(name: &str, protocol: Protocol) -> Self {
        Self {
            name: name.to_string(),
            protocol,
            l3proto: None,
            policy: vec![],
        }
    }

    /// Set the L3 protocol (ip or ip6).
    #[must_use]
    pub fn l3proto(mut self, family: Family) -> Self {
        self.l3proto = Some(family);
        self
    }

    /// Add a timeout entry.
    #[must_use]
    pub fn timeout(mut self, state: &str, seconds: u32) -> Self {
        self.policy.push((state.to_string(), seconds));
        self
    }

    /// Validate conntrack timeout fields.
    pub fn validate(&self) -> Result<(), NeinError> {
        validate::validate_identifier(&self.name)?;
        if !matches!(self.protocol, Protocol::Tcp | Protocol::Udp) {
            return Err(NeinError::InvalidRule(format!(
                "ct timeout protocol must be tcp or udp, got {}",
                self.protocol
            )));
        }
        if let Some(l3) = &self.l3proto
            && !matches!(l3, Family::Ip | Family::Ip6)
        {
            return Err(NeinError::InvalidRule(format!(
                "ct timeout l3proto must be ip or ip6, got {l3}"
            )));
        }
        for (state, _) in &self.policy {
            validate::validate_identifier(state)?;
        }
        Ok(())
    }

    /// Render as nftables syntax.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write;

        let mut out = String::with_capacity(128);
        let _ = writeln!(out, "  ct timeout {} {{", self.name);
        let _ = writeln!(out, "    protocol {};", self.protocol);
        if let Some(l3) = &self.l3proto {
            let _ = writeln!(out, "    l3proto {};", l3);
        }
        if !self.policy.is_empty() {
            let entries: Vec<String> = self
                .policy
                .iter()
                .map(|(state, secs)| format!("{state}: {secs}"))
                .collect();
            let _ = writeln!(out, "    policy = {{ {} }};", entries.join(", "));
        }
        out.push_str("  }\n");
        out
    }
}

// -- Table --

/// An nftables table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Table {
    pub name: String,
    pub family: Family,
    #[serde(default)]
    pub defines: Vec<Define>,
    #[serde(default)]
    pub flowtables: Vec<Flowtable>,
    #[serde(default)]
    pub ct_timeouts: Vec<CtTimeout>,
    pub chains: Vec<Chain>,
    #[serde(default)]
    pub sets: Vec<NftSet>,
    #[serde(default)]
    pub maps: Vec<NftMap>,
}

impl Table {
    /// Create a new table.
    #[must_use]
    pub fn new(name: &str, family: Family) -> Self {
        Self {
            name: name.to_string(),
            family,
            defines: vec![],
            flowtables: vec![],
            ct_timeouts: vec![],
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

    /// Add a define variable to this table.
    pub fn add_define(&mut self, define: Define) {
        self.defines.push(define);
    }

    /// Add a flowtable to this table.
    pub fn add_flowtable(&mut self, ft: Flowtable) {
        self.flowtables.push(ft);
    }

    /// Add a conntrack timeout policy to this table.
    pub fn add_ct_timeout(&mut self, ct: CtTimeout) {
        self.ct_timeouts.push(ct);
    }

    /// Render this table as nftables syntax.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write;

        let mut out = String::with_capacity(256);
        let _ = writeln!(out, "table {} {} {{", self.family, self.name);
        for define in &self.defines {
            out.push_str(&define.render());
        }
        for ft in &self.flowtables {
            out.push_str(&ft.render());
        }
        for ct in &self.ct_timeouts {
            out.push_str(&ct.render());
        }
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
        table.add_define(Define::new("WAN", "eth0"));
        table.add_flowtable(Flowtable::new("ft", 0, vec!["eth0".into()]));
        table.add_ct_timeout(CtTimeout::new("tcp-timeout", Protocol::Tcp));
        table.add_set(NftSet::new("myset", SetType::Ipv4Addr));
        table.add_map(NftMap::new("mymap", SetType::InetService));
        table.add_chain(crate::chain::Chain::regular("mychain"));

        let rendered = table.render();
        let def_pos = rendered.find("define $WAN").unwrap();
        let ft_pos = rendered.find("flowtable ft").unwrap();
        let ct_pos = rendered.find("ct timeout tcp-timeout").unwrap();
        let set_pos = rendered.find("set myset").unwrap();
        let map_pos = rendered.find("map mymap").unwrap();
        let chain_pos = rendered.find("chain mychain").unwrap();
        assert!(def_pos < ft_pos);
        assert!(ft_pos < ct_pos);
        assert!(ct_pos < set_pos);
        assert!(set_pos < map_pos);
        assert!(map_pos < chain_pos);
    }

    // -- Define tests --

    #[test]
    fn define_render() {
        let d = Define::new("WAN", "eth0");
        assert_eq!(d.render(), "  define $WAN = eth0;\n");
    }

    #[test]
    fn define_validate_good() {
        assert!(Define::new("MY_VAR", "10.0.0.1").validate().is_ok());
    }

    #[test]
    fn define_validate_bad_name() {
        assert!(Define::new("bad;name", "value").validate().is_err());
    }

    #[test]
    fn define_validate_bad_value() {
        assert!(Define::new("ok", "evil;inject").validate().is_err());
    }

    #[test]
    fn table_with_define() {
        let mut table = Table::new("filter", Family::Inet);
        table.add_define(Define::new("LAN", "192.168.0.0/16"));
        let rendered = table.render();
        assert!(rendered.contains("define $LAN = 192.168.0.0/16;"));
    }

    // -- Flowtable tests --

    #[test]
    fn flowtable_render() {
        let ft = Flowtable::new("ft", 0, vec!["eth0".into(), "eth1".into()]);
        let rendered = ft.render();
        assert!(rendered.contains("flowtable ft {"));
        assert!(rendered.contains("hook ingress priority 0;"));
        assert!(rendered.contains("devices = { eth0, eth1 };"));
    }

    #[test]
    fn flowtable_render_no_devices() {
        let ft = Flowtable::new("ft", -10, vec![]);
        let rendered = ft.render();
        assert!(rendered.contains("hook ingress priority -10;"));
        assert!(!rendered.contains("devices"));
    }

    #[test]
    fn flowtable_validate_empty_devices() {
        let ft = Flowtable::new("ft", 0, vec![]);
        assert!(ft.validate().is_err());
    }

    #[test]
    fn ct_timeout_validate_bad_protocol() {
        let ct = CtTimeout::new("t", Protocol::Icmp);
        assert!(ct.validate().is_err());
    }

    #[test]
    fn ct_timeout_validate_bad_l3proto() {
        let ct = CtTimeout::new("t", Protocol::Tcp).l3proto(Family::Bridge);
        assert!(ct.validate().is_err());
    }

    #[test]
    fn flowtable_validate_good() {
        let ft = Flowtable::new("ft", 0, vec!["eth0".into()]);
        assert!(ft.validate().is_ok());
    }

    #[test]
    fn flowtable_validate_bad_name() {
        let ft = Flowtable::new("bad;ft", 0, vec!["eth0".into()]);
        assert!(ft.validate().is_err());
    }

    #[test]
    fn flowtable_validate_bad_device() {
        let ft = Flowtable::new("ft", 0, vec!["evil;dev".into()]);
        assert!(ft.validate().is_err());
    }

    #[test]
    fn flowtable_validate_bad_hook() {
        let mut ft = Flowtable::new("ft", 0, vec!["eth0".into()]);
        ft.hook = Hook::Input;
        assert!(ft.validate().is_err());
    }

    #[test]
    fn table_with_flowtable() {
        let mut table = Table::new("filter", Family::Inet);
        table.add_flowtable(Flowtable::new("ft", 0, vec!["eth0".into()]));
        let rendered = table.render();
        assert!(rendered.contains("flowtable ft {"));
    }

    // -- CtTimeout tests --

    #[test]
    fn ct_timeout_render() {
        let ct = CtTimeout::new("tcp-long", Protocol::Tcp)
            .l3proto(Family::Ip)
            .timeout("established", 7200)
            .timeout("close_wait", 60);
        let rendered = ct.render();
        assert!(rendered.contains("ct timeout tcp-long {"));
        assert!(rendered.contains("protocol tcp;"));
        assert!(rendered.contains("l3proto ip;"));
        assert!(rendered.contains("policy = { established: 7200, close_wait: 60 };"));
    }

    #[test]
    fn ct_timeout_render_no_l3proto() {
        let ct = CtTimeout::new("udp-short", Protocol::Udp).timeout("unreplied", 30);
        let rendered = ct.render();
        assert!(rendered.contains("protocol udp;"));
        assert!(!rendered.contains("l3proto"));
        assert!(rendered.contains("policy = { unreplied: 30 };"));
    }

    #[test]
    fn ct_timeout_render_no_policy() {
        let ct = CtTimeout::new("empty", Protocol::Tcp);
        let rendered = ct.render();
        assert!(!rendered.contains("policy"));
    }

    #[test]
    fn ct_timeout_validate_good() {
        let ct = CtTimeout::new("my-timeout", Protocol::Tcp).timeout("established", 3600);
        assert!(ct.validate().is_ok());
    }

    #[test]
    fn ct_timeout_validate_bad_name() {
        let ct = CtTimeout::new("bad;name", Protocol::Tcp);
        assert!(ct.validate().is_err());
    }

    #[test]
    fn ct_timeout_validate_bad_state() {
        let ct = CtTimeout::new("ok", Protocol::Tcp).timeout("evil;state", 100);
        assert!(ct.validate().is_err());
    }

    #[test]
    fn table_with_ct_timeout() {
        let mut table = Table::new("filter", Family::Inet);
        table.add_ct_timeout(
            CtTimeout::new("tcp-long", Protocol::Tcp)
                .l3proto(Family::Ip)
                .timeout("established", 7200),
        );
        let rendered = table.render();
        assert!(rendered.contains("ct timeout tcp-long {"));
    }

    // -- Serde roundtrip tests --

    #[test]
    fn define_serde_roundtrip() {
        let d = Define::new("WAN", "eth0");
        let json = serde_json::to_string(&d).unwrap();
        let back: Define = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn flowtable_serde_roundtrip() {
        let ft = Flowtable::new("ft", 0, vec!["eth0".into(), "eth1".into()]);
        let json = serde_json::to_string(&ft).unwrap();
        let back: Flowtable = serde_json::from_str(&json).unwrap();
        assert_eq!(ft, back);
    }

    #[test]
    fn ct_timeout_serde_roundtrip() {
        let ct = CtTimeout::new("tcp-long", Protocol::Tcp)
            .l3proto(Family::Ip)
            .timeout("established", 7200)
            .timeout("close_wait", 60);
        let json = serde_json::to_string(&ct).unwrap();
        let back: CtTimeout = serde_json::from_str(&json).unwrap();
        assert_eq!(ct, back);
    }

    #[test]
    fn table_serde_roundtrip() {
        let mut table = Table::new("filter", Family::Inet);
        table.add_define(Define::new("LAN", "192.168.0.0/16"));
        let json = serde_json::to_string(&table).unwrap();
        let back: Table = serde_json::from_str(&json).unwrap();
        assert_eq!(table, back);
    }
}
