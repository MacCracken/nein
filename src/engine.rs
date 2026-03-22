//! Agent network policy engine.
//!
//! Manages network policies across multiple agents, generating a coherent
//! nftables firewall from all active policies. Supports agent lifecycle
//! (add/remove) with automatic rule generation and cleanup.

use crate::Firewall;
use crate::chain::{Chain, ChainType, Hook, Policy};
use crate::error::NeinError;
use crate::rule::{Match, Protocol, Rule, Verdict};
use crate::table::{Family, Table};
use crate::validate;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Network policy for a single agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPolicy {
    /// Agent identifier (used in table/chain names and comments).
    pub agent_id: String,
    /// Agent's IP address or CIDR.
    pub agent_addr: String,
    /// Allowed inbound ports (empty = deny all inbound).
    pub allowed_inbound: Vec<PortSpec>,
    /// Allowed outbound ports (empty = deny all outbound).
    pub allowed_outbound: Vec<PortSpec>,
    /// Allowed outbound host CIDRs (empty = allow all destinations).
    pub allowed_outbound_hosts: Vec<String>,
    /// Whether to allow established/related connections.
    pub allow_established: bool,
    /// Whether to allow loopback traffic.
    pub allow_loopback: bool,
}

/// A port specification for policy rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortSpec {
    pub protocol: Protocol,
    pub port: u16,
}

impl PortSpec {
    pub fn tcp(port: u16) -> Self {
        Self {
            protocol: Protocol::Tcp,
            port,
        }
    }

    pub fn udp(port: u16) -> Self {
        Self {
            protocol: Protocol::Udp,
            port,
        }
    }
}

impl AgentPolicy {
    /// Create a new agent policy with sensible defaults.
    ///
    /// Defaults: allow established, allow loopback, deny all inbound/outbound.
    pub fn new(agent_id: &str, agent_addr: &str) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            agent_addr: agent_addr.to_string(),
            allowed_inbound: vec![],
            allowed_outbound: vec![],
            allowed_outbound_hosts: vec![],
            allow_established: true,
            allow_loopback: true,
        }
    }

    /// Add an allowed inbound port.
    pub fn allow_inbound(mut self, spec: PortSpec) -> Self {
        self.allowed_inbound.push(spec);
        self
    }

    /// Add an allowed outbound port.
    pub fn allow_outbound(mut self, spec: PortSpec) -> Self {
        self.allowed_outbound.push(spec);
        self
    }

    /// Add an allowed outbound host CIDR.
    pub fn allow_outbound_host(mut self, cidr: &str) -> Self {
        self.allowed_outbound_hosts.push(cidr.to_string());
        self
    }

    /// Validate all fields.
    pub fn validate(&self) -> Result<(), NeinError> {
        validate::validate_identifier(&self.agent_id)?;
        validate::validate_addr(&self.agent_addr)?;
        for cidr in &self.allowed_outbound_hosts {
            validate::validate_addr(cidr)?;
        }
        Ok(())
    }

    /// Generate nftables rules for this agent's inbound chain.
    fn build_inbound_rules(&self) -> Vec<Rule> {
        let mut rules = vec![];

        if self.allow_established {
            rules.push(crate::rule::allow_established());
        }

        if self.allow_loopback {
            rules.push(
                Rule::new(Verdict::Accept)
                    .matching(Match::Iif("lo".to_string()))
                    .comment(&format!("{} loopback", self.agent_id)),
            );
        }

        for spec in &self.allowed_inbound {
            rules.push(
                Rule::new(Verdict::Accept)
                    .matching(Match::Protocol(spec.protocol))
                    .matching(Match::DPort(spec.port))
                    .comment(&format!(
                        "{} inbound {}:{}",
                        self.agent_id, spec.protocol, spec.port
                    )),
            );
        }

        rules
    }

    /// Generate nftables rules for this agent's outbound chain.
    fn build_outbound_rules(&self) -> Vec<Rule> {
        let mut rules = vec![];

        if self.allow_established {
            rules.push(crate::rule::allow_established());
        }

        if self.allow_loopback {
            rules.push(
                Rule::new(Verdict::Accept)
                    .matching(Match::Oif("lo".to_string()))
                    .comment(&format!("{} loopback out", self.agent_id)),
            );
        }

        // DNS is typically always allowed for outbound
        for spec in &self.allowed_outbound {
            let mut rule = Rule::new(Verdict::Accept)
                .matching(Match::Protocol(spec.protocol))
                .matching(Match::DPort(spec.port));

            // If outbound hosts are restricted, add dest filter
            if !self.allowed_outbound_hosts.is_empty() {
                for host in &self.allowed_outbound_hosts {
                    let host_rule = rule
                        .clone()
                        .matching(Match::DestAddr(host.clone()))
                        .comment(&format!(
                            "{} outbound {}:{} -> {}",
                            self.agent_id, spec.protocol, spec.port, host
                        ));
                    rules.push(host_rule);
                }
                continue;
            }

            rule = rule.comment(&format!(
                "{} outbound {}:{}",
                self.agent_id, spec.protocol, spec.port
            ));
            rules.push(rule);
        }

        rules
    }
}

/// Manages network policies for multiple agents.
///
/// Generates a unified nftables `Firewall` with per-agent chains for
/// inbound and outbound traffic control.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    /// Active agent policies, keyed by agent ID.
    agents: BTreeMap<String, AgentPolicy>,
    /// nftables table name (default: "nein_agents").
    table_name: String,
}

impl PolicyEngine {
    /// Create a new policy engine.
    pub fn new() -> Self {
        Self {
            agents: BTreeMap::new(),
            table_name: "nein_agents".to_string(),
        }
    }

    /// Set a custom table name.
    pub fn table_name(mut self, name: &str) -> Self {
        self.table_name = name.to_string();
        self
    }

    /// Add or update an agent's policy. Returns the previous policy if updating.
    pub fn add_agent(&mut self, policy: AgentPolicy) -> Option<AgentPolicy> {
        let id = policy.agent_id.clone();
        let prev = self.agents.insert(id.clone(), policy);
        if prev.is_some() {
            tracing::info!(agent_id = %id, "updated agent policy");
        } else {
            tracing::info!(agent_id = %id, "added agent policy");
        }
        prev
    }

    /// Remove an agent's policy. Returns the removed policy.
    pub fn remove_agent(&mut self, agent_id: &str) -> Option<AgentPolicy> {
        let removed = self.agents.remove(agent_id);
        if removed.is_some() {
            tracing::info!(agent_id, "removed agent policy");
        } else {
            tracing::debug!(agent_id, "agent not found for removal");
        }
        removed
    }

    /// Get an agent's current policy.
    pub fn get_agent(&self, agent_id: &str) -> Option<&AgentPolicy> {
        self.agents.get(agent_id)
    }

    /// List all active agent IDs.
    pub fn agent_ids(&self) -> Vec<&str> {
        self.agents.keys().map(|s| s.as_str()).collect()
    }

    /// Number of active agents.
    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }

    /// Validate all agent policies.
    pub fn validate(&self) -> Result<(), NeinError> {
        validate::validate_identifier(&self.table_name)?;
        for policy in self.agents.values() {
            policy.validate()?;
        }
        Ok(())
    }

    /// Generate the complete nftables `Firewall` for all agent policies.
    ///
    /// Creates a single inet table with:
    /// - A dispatch `input` chain that jumps to per-agent inbound chains
    /// - A dispatch `output` chain that jumps to per-agent outbound chains
    /// - Per-agent `{agent_id}_in` and `{agent_id}_out` chains
    pub fn to_firewall(&self) -> Firewall {
        let mut fw = Firewall::new();

        if self.agents.is_empty() {
            return fw;
        }

        let mut table = Table::new(&self.table_name, Family::Inet);

        // Dispatch chains
        let mut input = Chain::base("input", ChainType::Filter, Hook::Input, 0, Policy::Drop);
        let mut output = Chain::base("output", ChainType::Filter, Hook::Output, 0, Policy::Drop);

        for (agent_id, policy) in &self.agents {
            // Jump to per-agent chains based on dest/source addr
            input.add_rule(
                Rule::new(Verdict::Jump(format!("{agent_id}_in")))
                    .matching(Match::DestAddr(policy.agent_addr.clone()))
                    .comment(&format!("dispatch inbound to {agent_id}")),
            );
            output.add_rule(
                Rule::new(Verdict::Jump(format!("{agent_id}_out")))
                    .matching(Match::SourceAddr(policy.agent_addr.clone()))
                    .comment(&format!("dispatch outbound from {agent_id}")),
            );

            // Per-agent inbound chain
            let mut in_chain = Chain::regular(&format!("{agent_id}_in"));
            for rule in policy.build_inbound_rules() {
                in_chain.add_rule(rule);
            }
            // Default: drop (return to base chain which drops)
            in_chain.add_rule(
                Rule::new(Verdict::Drop).comment(&format!("{agent_id} default deny inbound")),
            );
            table.add_chain(in_chain);

            // Per-agent outbound chain
            let mut out_chain = Chain::regular(&format!("{agent_id}_out"));
            for rule in policy.build_outbound_rules() {
                out_chain.add_rule(rule);
            }
            out_chain.add_rule(
                Rule::new(Verdict::Drop).comment(&format!("{agent_id} default deny outbound")),
            );
            table.add_chain(out_chain);
        }

        table.add_chain(input);
        table.add_chain(output);
        fw.add_table(table);
        fw
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_engine() {
        let engine = PolicyEngine::new();
        assert_eq!(engine.agent_count(), 0);
        let fw = engine.to_firewall();
        assert_eq!(fw.render(), "");
    }

    #[test]
    fn add_remove_agent() {
        let mut engine = PolicyEngine::new();
        let policy = AgentPolicy::new("agent-1", "10.100.0.2");
        assert!(engine.add_agent(policy).is_none());
        assert_eq!(engine.agent_count(), 1);
        assert!(engine.get_agent("agent-1").is_some());
        assert_eq!(engine.agent_ids(), vec!["agent-1"]);

        let removed = engine.remove_agent("agent-1");
        assert!(removed.is_some());
        assert_eq!(engine.agent_count(), 0);
    }

    #[test]
    fn update_agent_policy() {
        let mut engine = PolicyEngine::new();
        let p1 = AgentPolicy::new("agent-1", "10.100.0.2");
        let p2 = AgentPolicy::new("agent-1", "10.100.0.3");
        assert!(engine.add_agent(p1).is_none());
        let old = engine.add_agent(p2);
        assert!(old.is_some());
        assert_eq!(old.unwrap().agent_addr, "10.100.0.2");
        assert_eq!(
            engine.get_agent("agent-1").unwrap().agent_addr,
            "10.100.0.3"
        );
    }

    #[test]
    fn remove_nonexistent() {
        let mut engine = PolicyEngine::new();
        assert!(engine.remove_agent("ghost").is_none());
    }

    #[test]
    fn single_agent_default_deny() {
        let mut engine = PolicyEngine::new();
        engine.add_agent(AgentPolicy::new("agent-1", "10.100.0.2"));

        let fw = engine.to_firewall();
        let rendered = fw.render();

        assert!(rendered.contains("table inet nein_agents"));
        assert!(rendered.contains("chain agent-1_in"));
        assert!(rendered.contains("chain agent-1_out"));
        assert!(rendered.contains("dispatch inbound to agent-1"));
        assert!(rendered.contains("dispatch outbound from agent-1"));
        assert!(rendered.contains("default deny inbound"));
        assert!(rendered.contains("default deny outbound"));
        // Established + loopback by default
        assert!(rendered.contains("ct state { established, related }"));
        assert!(rendered.contains("lo"));
    }

    #[test]
    fn agent_with_inbound_ports() {
        let mut engine = PolicyEngine::new();
        let policy = AgentPolicy::new("web", "10.100.1.2")
            .allow_inbound(PortSpec::tcp(80))
            .allow_inbound(PortSpec::tcp(443));
        engine.add_agent(policy);

        let rendered = engine.to_firewall().render();
        assert!(rendered.contains("web inbound tcp:80"));
        assert!(rendered.contains("web inbound tcp:443"));
        assert!(rendered.contains("dport 80"));
        assert!(rendered.contains("dport 443"));
    }

    #[test]
    fn agent_with_outbound_ports() {
        let mut engine = PolicyEngine::new();
        let policy = AgentPolicy::new("worker", "10.100.1.3")
            .allow_outbound(PortSpec::tcp(443))
            .allow_outbound(PortSpec::udp(53));
        engine.add_agent(policy);

        let rendered = engine.to_firewall().render();
        assert!(rendered.contains("worker outbound tcp:443"));
        assert!(rendered.contains("worker outbound udp:53"));
    }

    #[test]
    fn agent_with_outbound_host_restrictions() {
        let mut engine = PolicyEngine::new();
        let policy = AgentPolicy::new("restricted", "10.100.1.4")
            .allow_outbound(PortSpec::tcp(443))
            .allow_outbound_host("1.2.3.0/24")
            .allow_outbound_host("4.5.6.0/24");
        engine.add_agent(policy);

        let rendered = engine.to_firewall().render();
        // Should have dest-restricted rules
        assert!(rendered.contains("ip daddr 1.2.3.0/24"));
        assert!(rendered.contains("ip daddr 4.5.6.0/24"));
        assert!(rendered.contains("restricted outbound tcp:443 -> 1.2.3.0/24"));
        assert!(rendered.contains("restricted outbound tcp:443 -> 4.5.6.0/24"));
    }

    #[test]
    fn agent_no_established() {
        let mut engine = PolicyEngine::new();
        let mut policy = AgentPolicy::new("strict", "10.100.1.5");
        policy.allow_established = false;
        policy.allow_loopback = false;
        engine.add_agent(policy);

        let rendered = engine.to_firewall().render();
        assert!(!rendered.contains("ct state"));
        assert!(!rendered.contains("iif \"lo\""));
    }

    #[test]
    fn multiple_agents() {
        let mut engine = PolicyEngine::new();
        engine.add_agent(AgentPolicy::new("web", "10.100.1.2").allow_inbound(PortSpec::tcp(80)));
        engine.add_agent(AgentPolicy::new("db", "10.100.1.3").allow_inbound(PortSpec::tcp(5432)));

        let fw = engine.to_firewall();
        let rendered = fw.render();

        assert!(rendered.contains("chain web_in"));
        assert!(rendered.contains("chain db_in"));
        assert!(rendered.contains("chain web_out"));
        assert!(rendered.contains("chain db_out"));
        assert!(rendered.contains("dport 80"));
        assert!(rendered.contains("dport 5432"));
        assert_eq!(fw.tables().len(), 1);
    }

    #[test]
    fn custom_table_name() {
        let mut engine = PolicyEngine::new().table_name("daimon_policy");
        engine.add_agent(AgentPolicy::new("a", "10.0.0.1"));
        let rendered = engine.to_firewall().render();
        assert!(rendered.contains("table inet daimon_policy"));
    }

    #[test]
    fn validate_good() {
        let mut engine = PolicyEngine::new();
        engine.add_agent(
            AgentPolicy::new("agent-1", "10.100.0.2")
                .allow_inbound(PortSpec::tcp(80))
                .allow_outbound_host("1.2.3.0/24"),
        );
        assert!(engine.validate().is_ok());
    }

    #[test]
    fn validate_bad_agent_id() {
        let mut engine = PolicyEngine::new();
        engine.add_agent(AgentPolicy::new("bad;id", "10.100.0.2"));
        assert!(engine.validate().is_err());
    }

    #[test]
    fn validate_bad_agent_addr() {
        let mut engine = PolicyEngine::new();
        engine.add_agent(AgentPolicy::new("ok-id", "not-an-addr"));
        assert!(engine.validate().is_err());
    }

    #[test]
    fn validate_bad_outbound_host() {
        let mut engine = PolicyEngine::new();
        engine.add_agent(AgentPolicy::new("ok-id", "10.0.0.1").allow_outbound_host("evil;host"));
        assert!(engine.validate().is_err());
    }

    #[test]
    fn validate_bad_table_name() {
        let engine = PolicyEngine::new().table_name("bad;table");
        assert!(engine.validate().is_err());
    }

    #[test]
    fn firewall_validates() {
        let mut engine = PolicyEngine::new();
        engine.add_agent(
            AgentPolicy::new("web", "10.100.1.2")
                .allow_inbound(PortSpec::tcp(80))
                .allow_outbound(PortSpec::tcp(443)),
        );
        let fw = engine.to_firewall();
        assert!(fw.validate().is_ok());
    }

    #[test]
    fn default_impl() {
        let engine = PolicyEngine::default();
        assert_eq!(engine.agent_count(), 0);
    }

    #[test]
    fn agent_lifecycle_render_consistency() {
        let mut engine = PolicyEngine::new();
        engine.add_agent(AgentPolicy::new("a", "10.0.0.1").allow_inbound(PortSpec::tcp(80)));
        engine.add_agent(AgentPolicy::new("b", "10.0.0.2").allow_inbound(PortSpec::tcp(443)));
        let with_both = engine.to_firewall().render();

        engine.remove_agent("a");
        let without_a = engine.to_firewall().render();

        assert!(with_both.contains("chain a_in"));
        assert!(!without_a.contains("chain a_in"));
        assert!(without_a.contains("chain b_in"));
    }

    #[test]
    fn outbound_hosts_cross_ports() {
        // 2 ports × 2 hosts = 4 outbound rules
        let mut engine = PolicyEngine::new();
        engine.add_agent(
            AgentPolicy::new("api", "10.0.0.1")
                .allow_outbound(PortSpec::tcp(443))
                .allow_outbound(PortSpec::tcp(80))
                .allow_outbound_host("1.2.3.0/24")
                .allow_outbound_host("4.5.6.0/24"),
        );

        let rendered = engine.to_firewall().render();
        // 4 outbound rules (2 ports × 2 hosts)
        assert_eq!(rendered.matches("api outbound tcp:").count(), 4);
        assert!(rendered.contains("tcp:443 -> 1.2.3.0/24"));
        assert!(rendered.contains("tcp:443 -> 4.5.6.0/24"));
        assert!(rendered.contains("tcp:80 -> 1.2.3.0/24"));
        assert!(rendered.contains("tcp:80 -> 4.5.6.0/24"));
    }

    #[test]
    fn no_established_with_outbound_hosts() {
        let mut engine = PolicyEngine::new();
        let mut policy = AgentPolicy::new("locked", "10.0.0.1")
            .allow_outbound(PortSpec::tcp(443))
            .allow_outbound_host("1.2.3.0/24");
        policy.allow_established = false;
        policy.allow_loopback = false;
        engine.add_agent(policy);

        let rendered = engine.to_firewall().render();
        assert!(!rendered.contains("ct state"));
        assert!(!rendered.contains("\"lo\""));
        // Still has the host-restricted outbound rule
        assert!(rendered.contains("tcp:443 -> 1.2.3.0/24"));
    }

    #[test]
    fn port_spec_udp() {
        let spec = PortSpec::udp(53);
        assert_eq!(spec.protocol, Protocol::Udp);
        assert_eq!(spec.port, 53);
    }

    #[test]
    fn agent_policy_builder_chain() {
        let policy = AgentPolicy::new("test", "10.0.0.1")
            .allow_inbound(PortSpec::tcp(80))
            .allow_inbound(PortSpec::udp(53))
            .allow_outbound(PortSpec::tcp(443))
            .allow_outbound_host("1.0.0.0/8");
        assert_eq!(policy.allowed_inbound.len(), 2);
        assert_eq!(policy.allowed_outbound.len(), 1);
        assert_eq!(policy.allowed_outbound_hosts.len(), 1);
    }
}
