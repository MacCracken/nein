//! Container bridge firewall management.
//!
//! Manages the nftables ruleset for a container bridge network: forwarding,
//! NAT (masquerade + port mappings), and network isolation between groups.
//!
//! # Examples
//!
//! ```rust
//! use nein::bridge::{BridgeConfig, BridgeFirewall, PortMapping};
//!
//! let mut bf = BridgeFirewall::new(BridgeConfig::new("br0", "172.17.0.0/16", "eth0"));
//! bf.add_port_mapping(PortMapping::tcp(8080, "172.17.0.2", 80)).unwrap();
//!
//! let fw = bf.to_firewall();
//! fw.validate().unwrap();
//! let rendered = fw.render();
//! assert!(rendered.contains("dnat to 172.17.0.2:80"));
//! assert!(rendered.contains("masquerade"));
//! ```

use crate::Firewall;
use crate::chain::{Chain, ChainType, Hook, Policy};
use crate::error::NeinError;
use crate::nat::{self, NatRule};
use crate::rule::{self, Match, Protocol, Rule, Verdict};
use crate::set::{NftSet, SetFlag, SetType};
use crate::table::{Family, Table};
use crate::validate;
use serde::{Deserialize, Serialize};

/// Configuration for a container bridge network.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BridgeConfig {
    /// Bridge interface name (e.g., "br0", "nein0").
    pub bridge_name: String,
    /// Bridge subnet in CIDR notation (e.g., "172.17.0.0/16").
    pub subnet: String,
    /// Outbound interface for masqueraded traffic (e.g., "eth0").
    pub outbound_iface: String,
    /// nftables table name prefix (default: "nein").
    pub table_prefix: String,
}

impl BridgeConfig {
    /// Create a new bridge configuration.
    #[must_use]
    pub fn new(bridge_name: &str, subnet: &str, outbound_iface: &str) -> Self {
        Self {
            bridge_name: bridge_name.to_string(),
            subnet: subnet.to_string(),
            outbound_iface: outbound_iface.to_string(),
            table_prefix: "nein".to_string(),
        }
    }

    /// Set a custom table name prefix.
    #[must_use]
    pub fn table_prefix(mut self, prefix: &str) -> Self {
        self.table_prefix = prefix.to_string();
        self
    }

    /// Validate all fields.
    pub fn validate(&self) -> Result<(), NeinError> {
        validate::validate_iface(&self.bridge_name)?;
        validate::validate_addr(&self.subnet)?;
        validate::validate_iface(&self.outbound_iface)?;
        validate::validate_identifier(&self.table_prefix)?;
        Ok(())
    }
}

/// A port mapping for a container.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PortMapping {
    /// Port on the host.
    pub host_port: u16,
    /// Container IP address.
    pub container_addr: String,
    /// Port inside the container.
    pub container_port: u16,
    /// Protocol (TCP or UDP).
    pub protocol: Protocol,
}

impl PortMapping {
    /// Create a TCP port mapping.
    #[must_use]
    pub fn tcp(host_port: u16, container_addr: &str, container_port: u16) -> Self {
        Self {
            host_port,
            container_addr: container_addr.to_string(),
            container_port,
            protocol: Protocol::Tcp,
        }
    }

    /// Create a UDP port mapping.
    #[must_use]
    pub fn udp(host_port: u16, container_addr: &str, container_port: u16) -> Self {
        Self {
            host_port,
            container_addr: container_addr.to_string(),
            container_port,
            protocol: Protocol::Udp,
        }
    }

    /// Validate fields.
    pub fn validate(&self) -> Result<(), NeinError> {
        validate::validate_addr(&self.container_addr)?;
        Ok(())
    }

    /// Convert to a DNAT NatRule.
    fn to_nat_rule(&self) -> NatRule {
        NatRule::Dnat {
            protocol: self.protocol,
            dest_port: self.host_port,
            to_addr: self.container_addr.clone(),
            to_port: self.container_port,
            comment: Some(format!(
                "portmap {}:{} -> {}:{}",
                self.protocol, self.host_port, self.container_addr, self.container_port
            )),
        }
    }

    /// Convert to a forward-allow filter rule.
    fn to_forward_rule(&self) -> Rule {
        Rule::new(Verdict::Accept)
            .matching(Match::DestAddr(self.container_addr.clone()))
            .matching(Match::Protocol(self.protocol))
            .matching(Match::DPort(self.container_port))
            .comment(&format!(
                "allow portmap -> {}:{}",
                self.container_addr, self.container_port
            ))
    }
}

/// A network isolation group.
///
/// Containers in the same group can communicate. Traffic between different
/// groups is dropped unless explicitly allowed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct IsolationGroup {
    /// Group name (used in chain names and comments).
    pub name: String,
    /// CIDRs belonging to this group.
    pub cidrs: Vec<String>,
}

impl IsolationGroup {
    /// Create a new isolation group.
    #[must_use]
    pub fn new(name: &str, cidrs: Vec<String>) -> Self {
        Self {
            name: name.to_string(),
            cidrs,
        }
    }

    /// Validate fields.
    pub fn validate(&self) -> Result<(), NeinError> {
        validate::validate_identifier(&self.name)?;
        for cidr in &self.cidrs {
            validate::validate_addr(cidr)?;
        }
        Ok(())
    }
}

/// Manages nftables rules for a container bridge network.
///
/// Tracks port mappings and isolation groups, and generates a complete
/// nftables `Firewall` via [`to_firewall`](Self::to_firewall).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BridgeFirewall {
    config: BridgeConfig,
    port_mappings: Vec<PortMapping>,
    isolation_groups: Vec<IsolationGroup>,
}

impl BridgeFirewall {
    /// Create a new bridge firewall manager.
    #[must_use]
    pub fn new(config: BridgeConfig) -> Self {
        Self {
            config,
            port_mappings: vec![],
            isolation_groups: vec![],
        }
    }

    /// Access the bridge configuration.
    #[must_use]
    pub fn config(&self) -> &BridgeConfig {
        &self.config
    }

    // -- Port mapping lifecycle --

    /// Add a port mapping. Returns the index of the new mapping.
    ///
    /// Returns an error if a mapping for the same host port and protocol
    /// already exists.
    pub fn add_port_mapping(&mut self, mapping: PortMapping) -> Result<usize, NeinError> {
        if self
            .port_mappings
            .iter()
            .any(|m| m.host_port == mapping.host_port && m.protocol == mapping.protocol)
        {
            tracing::warn!(
                host_port = mapping.host_port,
                protocol = %mapping.protocol,
                "duplicate port mapping rejected"
            );
            return Err(NeinError::InvalidRule(format!(
                "duplicate port mapping: {} port {}",
                mapping.protocol, mapping.host_port
            )));
        }
        self.port_mappings.push(mapping);
        Ok(self.port_mappings.len() - 1)
    }

    /// Remove a port mapping by host port and protocol.
    ///
    /// Returns the removed mapping, or `None` if not found.
    pub fn remove_port_mapping(
        &mut self,
        host_port: u16,
        protocol: Protocol,
    ) -> Option<PortMapping> {
        if let Some(idx) = self
            .port_mappings
            .iter()
            .position(|m| m.host_port == host_port && m.protocol == protocol)
        {
            tracing::debug!(host_port, %protocol, "removed port mapping");
            Some(self.port_mappings.remove(idx))
        } else {
            tracing::debug!(host_port, %protocol, "port mapping not found for removal");
            None
        }
    }

    /// Access current port mappings.
    #[must_use]
    pub fn port_mappings(&self) -> &[PortMapping] {
        &self.port_mappings
    }

    // -- Isolation groups --

    /// Add a network isolation group.
    pub fn add_isolation_group(&mut self, group: IsolationGroup) {
        self.isolation_groups.push(group);
    }

    /// Access current isolation groups.
    #[must_use]
    pub fn isolation_groups(&self) -> &[IsolationGroup] {
        &self.isolation_groups
    }

    // -- Validation --

    /// Validate all configuration, port mappings, and isolation groups.
    pub fn validate(&self) -> Result<(), NeinError> {
        self.config.validate()?;
        for pm in &self.port_mappings {
            pm.validate()?;
        }
        for group in &self.isolation_groups {
            group.validate()?;
        }
        Ok(())
    }

    // -- Firewall generation --

    /// Generate the complete nftables `Firewall` for this bridge.
    ///
    /// Produces two tables:
    /// - `{prefix}_filter` (inet): forward chain with established, bridge
    ///   forwarding, isolation rules, and port-mapping forward allows.
    /// - `{prefix}_nat` (ip): prerouting DNAT for port mappings,
    ///   postrouting masquerade for outbound.
    #[must_use]
    pub fn to_firewall(&self) -> Firewall {
        tracing::debug!(
            bridge = %self.config.bridge_name,
            port_mappings = self.port_mappings.len(),
            isolation_groups = self.isolation_groups.len(),
            "generating bridge firewall"
        );
        let mut fw = Firewall::new();

        fw.add_table(self.build_filter_table());
        fw.add_table(self.build_nat_table());

        fw
    }

    fn build_filter_table(&self) -> Table {
        let cfg = &self.config;
        let mut table = Table::new(&format!("{}_filter", cfg.table_prefix), Family::Inet);

        let mut forward = Chain::base("forward", ChainType::Filter, Hook::Forward, 0, Policy::Drop);

        // Allow established/related
        forward.add_rule(rule::allow_established());

        // Port mapping forward allows
        for pm in &self.port_mappings {
            forward.add_rule(pm.to_forward_rule());
        }

        if self.isolation_groups.is_empty() {
            // No isolation: allow all bridge traffic
            forward.add_rule(
                Rule::new(Verdict::Accept)
                    .matching(Match::Iif(cfg.bridge_name.clone()))
                    .matching(Match::Oif(cfg.outbound_iface.clone()))
                    .comment("bridge to outbound"),
            );
            forward.add_rule(
                Rule::new(Verdict::Accept)
                    .matching(Match::Iif(cfg.bridge_name.clone()))
                    .matching(Match::Oif(cfg.bridge_name.clone()))
                    .comment("intra-bridge"),
            );
        } else {
            // Allow bridge → outbound for all groups
            forward.add_rule(
                Rule::new(Verdict::Accept)
                    .matching(Match::Iif(cfg.bridge_name.clone()))
                    .matching(Match::Oif(cfg.outbound_iface.clone()))
                    .comment("bridge to outbound"),
            );

            // Per-group: allow intra-group traffic via set lookup (O(1) per group)
            for group in &self.isolation_groups {
                if group.cidrs.is_empty() {
                    continue;
                }
                let set_name = format!("iso_{}", group.name);
                let mut set = NftSet::new(&set_name, SetType::Ipv4Addr).flag(SetFlag::Interval);
                for cidr in &group.cidrs {
                    set = set.element(cidr);
                }
                table.add_set(set);

                forward.add_rule(
                    Rule::new(Verdict::Accept)
                        .matching(Match::SetLookup {
                            field: "ip saddr".to_string(),
                            set_name: set_name.clone(),
                        })
                        .matching(Match::SetLookup {
                            field: "ip daddr".to_string(),
                            set_name: set_name.clone(),
                        })
                        .comment(&format!("intra-group: {}", group.name)),
                );
            }

            // Inter-group bridge traffic is dropped by the chain's default policy.
        }

        table.add_chain(forward);
        table
    }

    fn build_nat_table(&self) -> Table {
        let cfg = &self.config;
        let mut table = Table::new(&format!("{}_nat", cfg.table_prefix), Family::Ip);

        // Prerouting: DNAT for port mappings
        if !self.port_mappings.is_empty() {
            let mut prerouting = Chain::base(
                "prerouting",
                ChainType::Nat,
                Hook::Prerouting,
                -100,
                Policy::Accept,
            );
            for pm in &self.port_mappings {
                prerouting.add_nat_rule(pm.to_nat_rule());
            }
            table.add_chain(prerouting);
        }

        // Postrouting: masquerade outbound
        let mut postrouting = Chain::base(
            "postrouting",
            ChainType::Nat,
            Hook::Postrouting,
            100,
            Policy::Accept,
        );
        postrouting.add_nat_rule(nat::container_masquerade(&cfg.subnet, &cfg.outbound_iface));
        table.add_chain(postrouting);

        table
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> BridgeConfig {
        BridgeConfig::new("br0", "172.17.0.0/16", "eth0")
    }

    #[test]
    fn bridge_config_validate() {
        assert!(test_config().validate().is_ok());
    }

    #[test]
    fn bridge_config_bad_iface() {
        let cfg = BridgeConfig::new("evil;iface", "172.17.0.0/16", "eth0");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn bridge_config_custom_prefix() {
        let cfg = BridgeConfig::new("br0", "172.17.0.0/16", "eth0").table_prefix("stiva");
        assert_eq!(cfg.table_prefix, "stiva");
    }

    #[test]
    fn port_mapping_tcp() {
        let pm = PortMapping::tcp(8080, "172.17.0.2", 80);
        assert_eq!(pm.protocol, Protocol::Tcp);
        assert!(pm.validate().is_ok());
    }

    #[test]
    fn port_mapping_bad_addr() {
        let pm = PortMapping::tcp(8080, "evil;addr", 80);
        assert!(pm.validate().is_err());
    }

    #[test]
    fn add_remove_port_mapping() {
        let mut bf = BridgeFirewall::new(test_config());
        assert!(bf.port_mappings().is_empty());

        bf.add_port_mapping(PortMapping::tcp(8080, "172.17.0.2", 80))
            .unwrap();
        bf.add_port_mapping(PortMapping::tcp(8443, "172.17.0.2", 443))
            .unwrap();
        bf.add_port_mapping(PortMapping::udp(5353, "172.17.0.3", 53))
            .unwrap();
        assert_eq!(bf.port_mappings().len(), 3);

        let removed = bf.remove_port_mapping(8080, Protocol::Tcp);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().container_port, 80);
        assert_eq!(bf.port_mappings().len(), 2);

        // Remove non-existent
        assert!(bf.remove_port_mapping(9999, Protocol::Tcp).is_none());
    }

    #[test]
    fn render_no_mappings_no_isolation() {
        let bf = BridgeFirewall::new(test_config());
        let fw = bf.to_firewall();
        let rendered = fw.render();

        assert!(rendered.contains("table inet nein_filter"));
        assert!(rendered.contains("table ip nein_nat"));
        assert!(rendered.contains("bridge to outbound"));
        assert!(rendered.contains("intra-bridge"));
        assert!(rendered.contains("masquerade"));
        // No prerouting chain when no port mappings
        assert!(!rendered.contains("prerouting"));
    }

    #[test]
    fn render_with_port_mappings() {
        let mut bf = BridgeFirewall::new(test_config());
        bf.add_port_mapping(PortMapping::tcp(8080, "172.17.0.2", 80))
            .unwrap();
        bf.add_port_mapping(PortMapping::udp(5353, "172.17.0.3", 53))
            .unwrap();

        let fw = bf.to_firewall();
        let rendered = fw.render();

        // DNAT rules in prerouting
        assert!(rendered.contains("dnat to 172.17.0.2:80"));
        assert!(rendered.contains("dnat to 172.17.0.3:53"));
        // Forward allows for mapped ports
        assert!(rendered.contains("ip daddr 172.17.0.2"));
        assert!(rendered.contains("dport 80"));
        assert!(rendered.contains("ip daddr 172.17.0.3"));
        assert!(rendered.contains("dport 53"));
    }

    #[test]
    fn render_with_isolation() {
        let mut bf = BridgeFirewall::new(test_config());
        bf.add_isolation_group(IsolationGroup::new(
            "frontend",
            vec!["172.17.1.0/24".into()],
        ));
        bf.add_isolation_group(IsolationGroup::new("backend", vec!["172.17.2.0/24".into()]));

        let fw = bf.to_firewall();
        let rendered = fw.render();

        // Set-based isolation: one set + one rule per group
        assert!(rendered.contains("set iso_frontend"));
        assert!(rendered.contains("set iso_backend"));
        assert!(rendered.contains("intra-group: frontend"));
        assert!(rendered.contains("intra-group: backend"));
        assert!(rendered.contains("bridge to outbound"));
        // No generic intra-bridge rule when isolation is active
        assert!(!rendered.contains("intra-bridge"));
    }

    #[test]
    fn validate_full() {
        let mut bf = BridgeFirewall::new(test_config());
        bf.add_port_mapping(PortMapping::tcp(8080, "172.17.0.2", 80))
            .unwrap();
        bf.add_isolation_group(IsolationGroup::new("web", vec!["172.17.1.0/24".into()]));
        assert!(bf.validate().is_ok());
    }

    #[test]
    fn validate_bad_group() {
        let mut bf = BridgeFirewall::new(test_config());
        bf.add_isolation_group(IsolationGroup::new(
            "bad;name",
            vec!["172.17.1.0/24".into()],
        ));
        assert!(bf.validate().is_err());
    }

    #[test]
    fn validate_bad_group_cidr() {
        let mut bf = BridgeFirewall::new(test_config());
        bf.add_isolation_group(IsolationGroup::new("web", vec!["not-a-cidr".into()]));
        assert!(bf.validate().is_err());
    }

    #[test]
    fn firewall_validates() {
        let mut bf = BridgeFirewall::new(test_config());
        bf.add_port_mapping(PortMapping::tcp(8080, "172.17.0.2", 80))
            .unwrap();
        let fw = bf.to_firewall();
        assert!(fw.validate().is_ok());
    }

    #[test]
    fn custom_table_prefix() {
        let cfg = test_config().table_prefix("stiva");
        let bf = BridgeFirewall::new(cfg);
        let rendered = bf.to_firewall().render();
        assert!(rendered.contains("table inet stiva_filter"));
        assert!(rendered.contains("table ip stiva_nat"));
    }

    #[test]
    fn port_mapping_after_removal_renders_correctly() {
        let mut bf = BridgeFirewall::new(test_config());
        bf.add_port_mapping(PortMapping::tcp(8080, "172.17.0.2", 80))
            .unwrap();
        bf.add_port_mapping(PortMapping::tcp(8443, "172.17.0.2", 443))
            .unwrap();
        bf.remove_port_mapping(8080, Protocol::Tcp);

        let rendered = bf.to_firewall().render();
        assert!(!rendered.contains("dnat to 172.17.0.2:80"));
        assert!(rendered.contains("dnat to 172.17.0.2:443"));
    }

    #[test]
    fn duplicate_port_mapping_rejected() {
        let mut bf = BridgeFirewall::new(test_config());
        bf.add_port_mapping(PortMapping::tcp(8080, "172.17.0.2", 80))
            .unwrap();
        // Same host port + protocol = error
        let result = bf.add_port_mapping(PortMapping::tcp(8080, "172.17.0.3", 90));
        assert!(result.is_err());
        // Different protocol on same port = ok
        bf.add_port_mapping(PortMapping::udp(8080, "172.17.0.2", 80))
            .unwrap();
    }

    #[test]
    fn empty_isolation_group() {
        let mut bf = BridgeFirewall::new(test_config());
        bf.add_isolation_group(IsolationGroup::new("empty", vec![]));

        let rendered = bf.to_firewall().render();
        // Should still have outbound rule, no intra-group rules
        assert!(rendered.contains("bridge to outbound"));
        assert!(!rendered.contains("intra-group"));
    }

    #[test]
    fn multi_cidr_isolation_group() {
        let mut bf = BridgeFirewall::new(test_config());
        bf.add_isolation_group(IsolationGroup::new(
            "web",
            vec!["172.17.1.0/24".into(), "172.17.2.0/24".into()],
        ));

        let rendered = bf.to_firewall().render();

        // Set-based: one set with both CIDRs, one rule (not 4)
        assert!(rendered.contains("set iso_web"));
        assert!(rendered.contains("172.17.1.0/24, 172.17.2.0/24"));
        assert_eq!(rendered.matches("intra-group: web").count(), 1);
        // Set lookup for both saddr and daddr
        assert!(rendered.contains("ip saddr @iso_web"));
        assert!(rendered.contains("ip daddr @iso_web"));
    }

    #[test]
    fn isolation_with_port_mappings() {
        let mut bf = BridgeFirewall::new(test_config());
        bf.add_port_mapping(PortMapping::tcp(8080, "172.17.1.5", 80))
            .unwrap();
        bf.add_isolation_group(IsolationGroup::new("web", vec!["172.17.1.0/24".into()]));

        let rendered = bf.to_firewall().render();
        // Both port mapping forward allow AND isolation rules should be present
        assert!(rendered.contains("allow portmap -> 172.17.1.5:80"));
        assert!(rendered.contains("intra-group: web"));
        assert!(rendered.contains("dnat to 172.17.1.5:80"));
    }
}
