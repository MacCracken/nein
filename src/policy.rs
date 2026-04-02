//! Network policies — service-level access control for agents and containers.

use crate::error::NeinError;
use crate::rule::{Match, Protocol, Rule, Verdict};
use crate::validate;
use serde::{Deserialize, Serialize};

/// A network policy (like k8s NetworkPolicy but for AGNOS agents/containers).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NetworkPolicy {
    pub name: String,
    /// Target (agent ID, container ID, or CIDR).
    pub target: String,
    /// Allowed ingress rules.
    pub ingress: Vec<PolicyRule>,
    /// Allowed egress rules.
    pub egress: Vec<PolicyRule>,
    /// Default action for unmatched traffic.
    pub default_action: PolicyAction,
}

/// A policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PolicyRule {
    /// Source/destination (agent ID, CIDR, or "any").
    pub peer: String,
    /// Allowed ports.
    pub ports: Vec<PolicyPort>,
}

/// A port in a policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PolicyPort {
    pub protocol: Protocol,
    pub port: u16,
}

/// Default policy action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PolicyAction {
    Allow,
    Deny,
}

impl NetworkPolicy {
    /// Validate all string fields in this policy.
    ///
    /// Checks that the policy name is a valid identifier and that peer
    /// addresses (when not "any") are valid address strings.
    pub fn validate(&self) -> Result<(), NeinError> {
        validate::validate_identifier(&self.name)?;
        for rule in self.ingress.iter().chain(self.egress.iter()) {
            if rule.peer != "any" {
                validate::validate_addr(&rule.peer)?;
            }
        }
        Ok(())
    }

    /// Convert this policy to nftables rules.
    #[must_use]
    pub fn to_rules(&self) -> Vec<Rule> {
        let mut rules = vec![];

        // Ingress rules
        for ingress in &self.ingress {
            for port in &ingress.ports {
                let mut rule = Rule::new(Verdict::Accept)
                    .matching(Match::Protocol(port.protocol))
                    .matching(Match::DPort(port.port));

                if ingress.peer != "any" {
                    rule = rule.matching(Match::SourceAddr(ingress.peer.clone()));
                }

                rule = rule.comment(&format!(
                    "policy:{} ingress from {}",
                    self.name, ingress.peer
                ));
                rules.push(rule);
            }
        }

        // Egress rules
        for egress in &self.egress {
            for port in &egress.ports {
                let mut rule = Rule::new(Verdict::Accept)
                    .matching(Match::Protocol(port.protocol))
                    .matching(Match::DPort(port.port));

                if egress.peer != "any" {
                    rule = rule.matching(Match::DestAddr(egress.peer.clone()));
                }

                rule = rule.comment(&format!("policy:{} egress to {}", self.name, egress.peer));
                rules.push(rule);
            }
        }

        rules
    }
}

/// Convenience: allow agent A to talk to agent B on a port.
#[must_use]
pub fn agent_to_agent(
    name: &str,
    source: &str,
    dest: &str,
    protocol: Protocol,
    port: u16,
) -> NetworkPolicy {
    NetworkPolicy {
        name: name.to_string(),
        target: dest.to_string(),
        ingress: vec![PolicyRule {
            peer: source.to_string(),
            ports: vec![PolicyPort { protocol, port }],
        }],
        egress: vec![],
        default_action: PolicyAction::Deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_policy_to_rules() {
        let policy = agent_to_agent(
            "hoosh-to-daimon",
            "10.0.0.1",
            "10.0.0.2",
            Protocol::Tcp,
            8090,
        );
        let rules = policy.to_rules();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].render().contains("ip saddr 10.0.0.1"));
        assert!(rules[0].render().contains("dport 8090"));
        assert!(rules[0].render().contains("accept"));
    }

    #[test]
    fn validate_good_policy() {
        let policy = agent_to_agent("allow-web", "10.0.0.1", "10.0.0.2", Protocol::Tcp, 80);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn validate_bad_policy_name() {
        let policy = agent_to_agent("evil;name", "10.0.0.1", "10.0.0.2", Protocol::Tcp, 80);
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_bad_peer() {
        let policy = agent_to_agent("allow-web", "10.0.0.1; drop", "10.0.0.2", Protocol::Tcp, 80);
        assert!(policy.validate().is_err());
    }

    #[test]
    fn egress_rules() {
        let policy = NetworkPolicy {
            name: "egress-test".to_string(),
            target: "10.0.0.1".to_string(),
            ingress: vec![],
            egress: vec![PolicyRule {
                peer: "10.0.0.2".to_string(),
                ports: vec![PolicyPort {
                    protocol: Protocol::Tcp,
                    port: 443,
                }],
            }],
            default_action: PolicyAction::Deny,
        };
        let rules = policy.to_rules();
        assert_eq!(rules.len(), 1);
        let rendered = rules[0].render();
        assert!(rendered.contains("ip daddr 10.0.0.2"));
        assert!(rendered.contains("dport 443"));
        assert!(rendered.contains("egress to 10.0.0.2"));
    }

    #[test]
    fn egress_any_dest() {
        let policy = NetworkPolicy {
            name: "egress-any".to_string(),
            target: "10.0.0.1".to_string(),
            ingress: vec![],
            egress: vec![PolicyRule {
                peer: "any".to_string(),
                ports: vec![PolicyPort {
                    protocol: Protocol::Tcp,
                    port: 80,
                }],
            }],
            default_action: PolicyAction::Allow,
        };
        let rules = policy.to_rules();
        assert_eq!(rules.len(), 1);
        // "any" dest should not add ip daddr match
        assert!(!rules[0].render().contains("daddr"));
    }

    #[test]
    fn policy_any_source() {
        let policy = NetworkPolicy {
            name: "public-web".to_string(),
            target: "webserver".to_string(),
            ingress: vec![PolicyRule {
                peer: "any".to_string(),
                ports: vec![
                    PolicyPort {
                        protocol: Protocol::Tcp,
                        port: 80,
                    },
                    PolicyPort {
                        protocol: Protocol::Tcp,
                        port: 443,
                    },
                ],
            }],
            egress: vec![],
            default_action: PolicyAction::Deny,
        };
        let rules = policy.to_rules();
        assert_eq!(rules.len(), 2);
        // "any" source should not add ip saddr match
        assert!(!rules[0].render().contains("saddr"));
    }
}
