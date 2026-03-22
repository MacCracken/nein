//! nftables chains.

use crate::rule::Rule;
use serde::{Deserialize, Serialize};

/// Chain type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// An nftables chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    pub name: String,
    pub chain_type: Option<ChainType>,
    pub hook: Option<Hook>,
    pub priority: Option<i32>,
    pub policy: Option<Policy>,
    pub rules: Vec<Rule>,
}

impl Chain {
    /// Create a base chain (attached to a hook).
    pub fn base(name: &str, chain_type: ChainType, hook: Hook, priority: i32, policy: Policy) -> Self {
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
        self.rules.push(rule);
    }

    /// Render this chain as nftables syntax.
    pub fn render(&self) -> String {
        let mut out = format!("  chain {} {{\n", self.name);
        if let (Some(ct), Some(hook), Some(prio), Some(pol)) =
            (&self.chain_type, &self.hook, &self.priority, &self.policy)
        {
            out.push_str(&format!("    type {} hook {} priority {}; policy {};\n", ct, hook, prio, pol));
        }
        for rule in &self.rules {
            out.push_str(&format!("    {}\n", rule.render()));
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
}
