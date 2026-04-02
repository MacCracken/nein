//! nftables chains.

use crate::error::NeinError;
use crate::rule::Rule;
use serde::{Deserialize, Serialize};

/// Chain type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ChainType {
    Filter,
    Nat,
    Route,
}

impl std::fmt::Display for ChainType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Filter => write!(f, "filter"),
            Self::Nat => write!(f, "nat"),
            Self::Route => write!(f, "route"),
        }
    }
}

/// Chain hook point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Hook {
    Prerouting,
    Input,
    Forward,
    Output,
    Postrouting,
    Ingress,
}

impl std::fmt::Display for Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prerouting => write!(f, "prerouting"),
            Self::Input => write!(f, "input"),
            Self::Forward => write!(f, "forward"),
            Self::Output => write!(f, "output"),
            Self::Postrouting => write!(f, "postrouting"),
            Self::Ingress => write!(f, "ingress"),
        }
    }
}

/// Default chain policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Policy {
    Accept,
    Drop,
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accept => write!(f, "accept"),
            Self::Drop => write!(f, "drop"),
        }
    }
}

/// An entry in a chain — either a filter rule or a NAT rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ChainRule {
    /// A standard filter/routing rule.
    Rule(Rule),
    /// A NAT rule (DNAT, SNAT, masquerade, redirect).
    #[cfg(feature = "nat")]
    Nat(crate::nat::NatRule),
}

impl ChainRule {
    /// Render this chain rule as nftables syntax.
    #[must_use]
    #[inline]
    pub fn render(&self) -> String {
        match self {
            Self::Rule(r) => r.render(),
            #[cfg(feature = "nat")]
            Self::Nat(n) => n.render(),
        }
    }

    /// Validate this chain rule for dangerous input.
    pub fn validate(&self) -> Result<(), NeinError> {
        match self {
            Self::Rule(r) => r.validate(),
            #[cfg(feature = "nat")]
            Self::Nat(n) => n.validate(),
        }
    }
}

impl From<Rule> for ChainRule {
    fn from(r: Rule) -> Self {
        Self::Rule(r)
    }
}

#[cfg(feature = "nat")]
impl From<crate::nat::NatRule> for ChainRule {
    fn from(n: crate::nat::NatRule) -> Self {
        Self::Nat(n)
    }
}

/// An nftables chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chain {
    pub name: String,
    pub chain_type: Option<ChainType>,
    pub hook: Option<Hook>,
    pub priority: Option<i32>,
    pub policy: Option<Policy>,
    pub rules: Vec<ChainRule>,
}

impl Chain {
    /// Create a base chain (attached to a hook).
    #[must_use]
    pub fn base(
        name: &str,
        chain_type: ChainType,
        hook: Hook,
        priority: i32,
        policy: Policy,
    ) -> Self {
        Self {
            name: name.to_string(),
            chain_type: Some(chain_type),
            hook: Some(hook),
            priority: Some(priority),
            policy: Some(policy),
            rules: vec![],
        }
    }

    /// Create a regular (non-base) chain.
    #[must_use]
    pub fn regular(name: &str) -> Self {
        Self {
            name: name.to_string(),
            chain_type: None,
            hook: None,
            priority: None,
            policy: None,
            rules: vec![],
        }
    }

    /// Add a rule to this chain.
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(ChainRule::Rule(rule));
    }

    /// Add a NAT rule to this chain.
    #[cfg(feature = "nat")]
    pub fn add_nat_rule(&mut self, rule: crate::nat::NatRule) {
        self.rules.push(ChainRule::Nat(rule));
    }

    /// Render this chain as nftables syntax.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write;

        let mut out = String::with_capacity(128);
        let _ = writeln!(out, "  chain {} {{", self.name);
        if let (Some(ct), Some(hook), Some(prio), Some(pol)) =
            (&self.chain_type, &self.hook, &self.priority, &self.policy)
        {
            let _ = writeln!(
                out,
                "    type {ct} hook {hook} priority {prio}; policy {pol};"
            );
        }
        for rule in &self.rules {
            let _ = writeln!(out, "    {}", rule.render());
        }
        out.push_str("  }\n");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_chain_render() {
        let chain = Chain::base("input", ChainType::Filter, Hook::Input, 0, Policy::Drop);
        let rendered = chain.render();
        assert!(rendered.contains("type filter hook input priority 0; policy drop;"));
    }

    #[test]
    fn regular_chain_render() {
        let chain = Chain::regular("my_chain");
        let rendered = chain.render();
        assert!(rendered.contains("chain my_chain"));
        assert!(!rendered.contains("type"));
    }

    #[test]
    fn chain_type_display() {
        assert_eq!(ChainType::Filter.to_string(), "filter");
        assert_eq!(ChainType::Nat.to_string(), "nat");
        assert_eq!(ChainType::Route.to_string(), "route");
    }

    #[test]
    fn hook_display() {
        assert_eq!(Hook::Prerouting.to_string(), "prerouting");
        assert_eq!(Hook::Input.to_string(), "input");
        assert_eq!(Hook::Forward.to_string(), "forward");
        assert_eq!(Hook::Output.to_string(), "output");
        assert_eq!(Hook::Postrouting.to_string(), "postrouting");
        assert_eq!(Hook::Ingress.to_string(), "ingress");
    }

    #[test]
    fn policy_display() {
        assert_eq!(Policy::Accept.to_string(), "accept");
        assert_eq!(Policy::Drop.to_string(), "drop");
    }

    #[test]
    fn chain_rule_validate_dispatches() {
        use crate::rule::{Match, Rule, Verdict};
        let good = ChainRule::Rule(Rule::new(Verdict::Accept));
        assert!(good.validate().is_ok());

        let bad = ChainRule::Rule(
            Rule::new(Verdict::Accept).matching(Match::SourceAddr("evil;addr".into())),
        );
        assert!(bad.validate().is_err());
    }

    #[cfg(feature = "nat")]
    #[test]
    fn chain_rule_nat_render() {
        let nat_rule = crate::nat::NatRule::Redirect {
            protocol: crate::rule::Protocol::Tcp,
            dest_port: 80,
            to_port: 8080,
            comment: None,
        };
        let cr = ChainRule::Nat(nat_rule);
        assert_eq!(cr.render(), "tcp dport 80 redirect to :8080");
    }

    #[cfg(feature = "nat")]
    #[test]
    fn chain_add_nat_rule() {
        let mut chain = Chain::regular("nat_chain");
        chain.add_nat_rule(crate::nat::NatRule::Redirect {
            protocol: crate::rule::Protocol::Tcp,
            dest_port: 80,
            to_port: 8080,
            comment: None,
        });
        assert_eq!(chain.rules.len(), 1);
        let rendered = chain.render();
        assert!(rendered.contains("redirect to :8080"));
    }
}
