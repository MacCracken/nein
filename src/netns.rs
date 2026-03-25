//! Network namespace firewall integration.
//!
//! Bridges nein's firewall engine with agnosys network namespace primitives.
//! Builds type-safe nftables rulesets for agent namespaces and applies them
//! via `agnosys::netns::apply_nftables_ruleset`.
//!
//! # Example
//!
//! ```rust,no_run
//! use nein::netns::NamespaceFirewall;
//! use nein::engine::{AgentPolicy, PortSpec};
//!
//! let config = agnosys::netns::NetNamespaceConfig::for_agent("my-agent");
//! let handle = agnosys::netns::create_agent_netns(&config).unwrap();
//!
//! let fw = NamespaceFirewall::for_agent(&config)
//!     .allow_inbound(PortSpec::tcp(8080))
//!     .allow_outbound(PortSpec::tcp(443))
//!     .allow_outbound(PortSpec::udp(53))
//!     .build();
//!
//! // Apply inside the namespace
//! nein::netns::apply_to_namespace(&handle, &fw).unwrap();
//! ```

use crate::Firewall;
use crate::chain::{Chain, ChainType, Hook, Policy};
use crate::engine::PortSpec;
use crate::error::NeinError;
use crate::rule::{self, Match, Protocol, Rule, Verdict};
use crate::table::{Family, Table};

/// Builds a [`Firewall`] tailored for an agent network namespace.
///
/// Generates an `inet` table named `agnos_agent` with input/output base
/// chains, established/related tracking, loopback access, and DNS resolution
/// by default.
#[derive(Debug, Clone)]
pub struct NamespaceFirewall {
    agent_name: String,
    allowed_inbound: Vec<PortSpec>,
    allowed_outbound: Vec<PortSpec>,
    allowed_outbound_hosts: Vec<String>,
    allow_established: bool,
    allow_loopback: bool,
    allow_dns: bool,
    inbound_policy: Policy,
    outbound_policy: Policy,
}

impl NamespaceFirewall {
    /// Create a builder from an agnosys namespace config.
    ///
    /// Defaults: drop inbound, accept outbound, allow established/related,
    /// allow loopback, allow DNS (UDP 53).
    #[must_use]
    pub fn for_agent(config: &agnosys::netns::NetNamespaceConfig) -> Self {
        Self {
            agent_name: config.name.clone(),
            allowed_inbound: Vec::new(),
            allowed_outbound: Vec::new(),
            allowed_outbound_hosts: Vec::new(),
            allow_established: true,
            allow_loopback: true,
            allow_dns: true,
            inbound_policy: Policy::Drop,
            outbound_policy: Policy::Accept,
        }
    }

    /// Create a builder from just an agent name.
    #[must_use]
    pub fn new(agent_name: &str) -> Self {
        Self {
            agent_name: agent_name.to_string(),
            allowed_inbound: Vec::new(),
            allowed_outbound: Vec::new(),
            allowed_outbound_hosts: Vec::new(),
            allow_established: true,
            allow_loopback: true,
            allow_dns: true,
            inbound_policy: Policy::Drop,
            outbound_policy: Policy::Accept,
        }
    }

    /// Allow an inbound port.
    #[must_use]
    pub fn allow_inbound(mut self, spec: PortSpec) -> Self {
        self.allowed_inbound.push(spec);
        self
    }

    /// Allow an outbound port.
    #[must_use]
    pub fn allow_outbound(mut self, spec: PortSpec) -> Self {
        self.allowed_outbound.push(spec);
        self
    }

    /// Restrict outbound traffic to specific host CIDRs.
    #[must_use]
    pub fn allow_outbound_host(mut self, cidr: &str) -> Self {
        self.allowed_outbound_hosts.push(cidr.to_string());
        self
    }

    /// Set the default inbound policy (default: Drop).
    #[must_use]
    pub fn inbound_policy(mut self, policy: Policy) -> Self {
        self.inbound_policy = policy;
        self
    }

    /// Set the default outbound policy (default: Accept).
    #[must_use]
    pub fn outbound_policy(mut self, policy: Policy) -> Self {
        self.outbound_policy = policy;
        self
    }

    /// Disable established/related connection tracking.
    #[must_use]
    pub fn no_established(mut self) -> Self {
        self.allow_established = false;
        self
    }

    /// Disable loopback access.
    #[must_use]
    pub fn no_loopback(mut self) -> Self {
        self.allow_loopback = false;
        self
    }

    /// Disable automatic DNS (UDP 53) allow rule.
    #[must_use]
    pub fn no_dns(mut self) -> Self {
        self.allow_dns = false;
        self
    }

    /// Build the [`Firewall`] for this namespace.
    #[must_use]
    pub fn build(&self) -> Firewall {
        let mut fw = Firewall::new();
        let mut table = Table::new("agnos_agent", Family::Inet);

        // Input chain (inbound traffic)
        let mut input = Chain::base(
            "input",
            ChainType::Filter,
            Hook::Input,
            0,
            self.inbound_policy,
        );

        if self.allow_established {
            input.add_rule(rule::allow_established());
        }
        if self.allow_loopback {
            input.add_rule(
                Rule::new(Verdict::Accept)
                    .matching(Match::Iif("lo".to_string()))
                    .comment(&format!("{} loopback", self.agent_name)),
            );
        }
        for spec in &self.allowed_inbound {
            let mut r = Rule::new(Verdict::Accept)
                .matching(Match::Protocol(spec.protocol))
                .matching(Match::DPort(spec.port));
            r = r.comment(&format!(
                "{} inbound {}:{}",
                self.agent_name, spec.protocol, spec.port
            ));
            input.add_rule(r);
        }

        // Output chain (outbound traffic)
        let mut output = Chain::base(
            "output",
            ChainType::Filter,
            Hook::Output,
            0,
            self.outbound_policy,
        );

        if self.allow_established {
            output.add_rule(rule::allow_established());
        }
        if self.allow_loopback {
            output.add_rule(
                Rule::new(Verdict::Accept)
                    .matching(Match::Oif("lo".to_string()))
                    .comment(&format!("{} loopback out", self.agent_name)),
            );
        }
        if self.allow_dns {
            output.add_rule(
                Rule::new(Verdict::Accept)
                    .matching(Match::Protocol(Protocol::Udp))
                    .matching(Match::DPort(53))
                    .comment(&format!("{} dns", self.agent_name)),
            );
        }
        for spec in &self.allowed_outbound {
            if !self.allowed_outbound_hosts.is_empty() {
                for host in &self.allowed_outbound_hosts {
                    output.add_rule(
                        Rule::new(Verdict::Accept)
                            .matching(Match::Protocol(spec.protocol))
                            .matching(Match::DPort(spec.port))
                            .matching(Match::DestAddr(host.clone()))
                            .comment(&format!(
                                "{} outbound {}:{} -> {}",
                                self.agent_name, spec.protocol, spec.port, host
                            )),
                    );
                }
            } else {
                output.add_rule(
                    Rule::new(Verdict::Accept)
                        .matching(Match::Protocol(spec.protocol))
                        .matching(Match::DPort(spec.port))
                        .comment(&format!(
                            "{} outbound {}:{}",
                            self.agent_name, spec.protocol, spec.port
                        )),
                );
            }
        }

        table.add_chain(input);
        table.add_chain(output);
        fw.add_table(table);
        fw
    }
}

/// Apply a [`Firewall`] inside an agent network namespace.
///
/// Renders the firewall and delegates to
/// [`agnosys::netns::apply_nftables_ruleset`].
pub fn apply_to_namespace(
    handle: &agnosys::netns::NetNamespaceHandle,
    firewall: &Firewall,
) -> Result<(), NeinError> {
    firewall.validate()?;
    let ruleset = firewall.render();
    agnosys::netns::apply_nftables_ruleset(handle, &ruleset).map_err(|e| {
        NeinError::NftFailed(format!(
            "failed to apply ruleset to namespace '{}': {}",
            handle.name, e
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> agnosys::netns::NetNamespaceConfig {
        agnosys::netns::NetNamespaceConfig::for_agent("test-agent")
    }

    #[test]
    fn default_build_renders() {
        let fw = NamespaceFirewall::for_agent(&default_config()).build();
        let rendered = fw.render();
        assert!(rendered.contains("table inet agnos_agent"));
        assert!(rendered.contains("chain input"));
        assert!(rendered.contains("chain output"));
        assert!(rendered.contains("policy drop"));
        assert!(rendered.contains("policy accept"));
        assert!(rendered.contains("ct state { established, related }"));
        assert!(rendered.contains("\"lo\""));
        assert!(rendered.contains("dport 53"));
    }

    #[test]
    fn default_build_validates() {
        let fw = NamespaceFirewall::for_agent(&default_config()).build();
        assert!(fw.validate().is_ok());
    }

    #[test]
    fn inbound_ports() {
        let fw = NamespaceFirewall::for_agent(&default_config())
            .allow_inbound(PortSpec::tcp(8080))
            .allow_inbound(PortSpec::tcp(443))
            .build();
        let rendered = fw.render();
        assert!(rendered.contains("dport 8080"));
        assert!(rendered.contains("dport 443"));
        assert!(rendered.contains("test-agent inbound tcp:8080"));
        assert!(rendered.contains("test-agent inbound tcp:443"));
    }

    #[test]
    fn outbound_ports() {
        let fw = NamespaceFirewall::for_agent(&default_config())
            .allow_outbound(PortSpec::tcp(443))
            .allow_outbound(PortSpec::udp(123))
            .build();
        let rendered = fw.render();
        assert!(rendered.contains("test-agent outbound tcp:443"));
        assert!(rendered.contains("test-agent outbound udp:123"));
    }

    #[test]
    fn outbound_host_restriction() {
        let fw = NamespaceFirewall::for_agent(&default_config())
            .allow_outbound(PortSpec::tcp(443))
            .allow_outbound_host("1.2.3.0/24")
            .allow_outbound_host("4.5.6.0/24")
            .build();
        let rendered = fw.render();
        assert!(rendered.contains("ip daddr 1.2.3.0/24"));
        assert!(rendered.contains("ip daddr 4.5.6.0/24"));
        assert!(rendered.contains("tcp:443 -> 1.2.3.0/24"));
        assert!(rendered.contains("tcp:443 -> 4.5.6.0/24"));
    }

    #[test]
    fn outbound_hosts_cross_ports() {
        let fw = NamespaceFirewall::for_agent(&default_config())
            .allow_outbound(PortSpec::tcp(443))
            .allow_outbound(PortSpec::tcp(80))
            .allow_outbound_host("10.0.0.0/8")
            .build();
        let rendered = fw.render();
        assert_eq!(rendered.matches("test-agent outbound tcp:").count(), 2);
        assert!(rendered.contains("tcp:443 -> 10.0.0.0/8"));
        assert!(rendered.contains("tcp:80 -> 10.0.0.0/8"));
    }

    #[test]
    fn no_established() {
        let fw = NamespaceFirewall::for_agent(&default_config())
            .no_established()
            .build();
        let rendered = fw.render();
        assert!(!rendered.contains("ct state"));
    }

    #[test]
    fn no_loopback() {
        let fw = NamespaceFirewall::for_agent(&default_config())
            .no_loopback()
            .build();
        let rendered = fw.render();
        assert!(!rendered.contains("\"lo\""));
    }

    #[test]
    fn no_dns() {
        let fw = NamespaceFirewall::for_agent(&default_config())
            .no_dns()
            .build();
        let rendered = fw.render();
        assert!(!rendered.contains("dport 53"));
    }

    #[test]
    fn custom_policies() {
        let fw = NamespaceFirewall::for_agent(&default_config())
            .inbound_policy(Policy::Accept)
            .outbound_policy(Policy::Drop)
            .build();
        let rendered = fw.render();
        // Input chain has accept, output has drop
        let input_idx = rendered.find("chain input").unwrap();
        let output_idx = rendered.find("chain output").unwrap();
        let between_input_output = &rendered[input_idx..output_idx];
        assert!(between_input_output.contains("policy accept"));
        let after_output = &rendered[output_idx..];
        assert!(after_output.contains("policy drop"));
    }

    #[test]
    fn new_from_name() {
        let fw = NamespaceFirewall::new("my-agent")
            .allow_inbound(PortSpec::tcp(22))
            .build();
        let rendered = fw.render();
        assert!(rendered.contains("my-agent inbound tcp:22"));
    }

    #[test]
    fn fully_locked_down() {
        let fw = NamespaceFirewall::for_agent(&default_config())
            .no_established()
            .no_loopback()
            .no_dns()
            .inbound_policy(Policy::Drop)
            .outbound_policy(Policy::Drop)
            .build();
        let rendered = fw.render();
        assert!(!rendered.contains("ct state"));
        assert!(!rendered.contains("\"lo\""));
        assert!(!rendered.contains("dport 53"));
        // Both policies drop
        assert_eq!(rendered.matches("policy drop").count(), 2);
    }

    #[test]
    fn clone_and_debug() {
        let builder = NamespaceFirewall::for_agent(&default_config());
        let cloned = builder.clone();
        assert_eq!(cloned.agent_name, "test-agent");
        let dbg = format!("{:?}", builder);
        assert!(dbg.contains("NamespaceFirewall"));
    }

    #[test]
    fn matches_old_agnosys_output_structure() {
        // Verify the nein-generated ruleset has the same structural elements
        // that the old agnosys generate_nftables_ruleset() produced
        let fw = NamespaceFirewall::for_agent(&default_config()).build();
        let rendered = fw.render();

        // Table structure
        assert!(rendered.contains("table inet agnos_agent"));

        // Input chain with drop policy
        assert!(rendered.contains("chain input"));
        assert!(rendered.contains("policy drop"));

        // Output chain with accept policy
        assert!(rendered.contains("chain output"));
        assert!(rendered.contains("policy accept"));

        // Established/related
        assert!(rendered.contains("ct state { established, related }"));

        // Loopback
        assert!(rendered.contains("\"lo\""));

        // DNS
        assert!(rendered.contains("dport 53"));
    }

    #[test]
    fn validates_ok() {
        let fw = NamespaceFirewall::for_agent(&default_config())
            .allow_inbound(PortSpec::tcp(80))
            .allow_outbound(PortSpec::tcp(443))
            .allow_outbound_host("10.0.0.0/8")
            .build();
        assert!(fw.validate().is_ok());
    }
}
