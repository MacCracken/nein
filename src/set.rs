//! nftables named sets and maps.
//!
//! Sets group elements (IPs, ports, interfaces) for efficient matching.
//! Maps associate keys with verdicts or values for dynamic dispatch.

use crate::error::NeinError;
use crate::validate;
use serde::{Deserialize, Serialize};

/// Element type for a named set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SetType {
    Ipv4Addr,
    Ipv6Addr,
    InetService,
    InetProto,
    IfName,
}

impl std::fmt::Display for SetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4Addr => write!(f, "ipv4_addr"),
            Self::Ipv6Addr => write!(f, "ipv6_addr"),
            Self::InetService => write!(f, "inet_service"),
            Self::InetProto => write!(f, "inet_proto"),
            Self::IfName => write!(f, "ifname"),
        }
    }
}

/// Set flags controlling behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SetFlag {
    Constant,
    Interval,
    Timeout,
}

impl std::fmt::Display for SetFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Constant => write!(f, "constant"),
            Self::Interval => write!(f, "interval"),
            Self::Timeout => write!(f, "timeout"),
        }
    }
}

/// A named nftables set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftSet {
    /// Set name.
    pub name: String,
    /// Element type.
    pub set_type: SetType,
    /// Optional flags.
    pub flags: Vec<SetFlag>,
    /// Elements (IP addresses, ports, etc. as strings).
    pub elements: Vec<String>,
}

impl NftSet {
    /// Create a new named set.
    pub fn new(name: &str, set_type: SetType) -> Self {
        Self {
            name: name.to_string(),
            set_type,
            flags: vec![],
            elements: vec![],
        }
    }

    /// Add a flag.
    pub fn flag(mut self, flag: SetFlag) -> Self {
        self.flags.push(flag);
        self
    }

    /// Add an element.
    pub fn element(mut self, elem: &str) -> Self {
        self.elements.push(elem.to_string());
        self
    }

    /// Add multiple elements.
    pub fn elements(mut self, elems: &[&str]) -> Self {
        self.elements.extend(elems.iter().map(|s| s.to_string()));
        self
    }

    /// Validate set name and elements.
    pub fn validate(&self) -> Result<(), NeinError> {
        validate::validate_identifier(&self.name)?;
        for elem in &self.elements {
            validate::validate_nft_element(elem)?;
        }
        Ok(())
    }

    /// Render as nftables set definition (inside a table block).
    pub fn render(&self) -> String {
        let mut out = format!("  set {} {{\n", self.name);
        out.push_str(&format!("    type {};\n", self.set_type));
        if !self.flags.is_empty() {
            let flags: Vec<String> = self.flags.iter().map(|f| f.to_string()).collect();
            out.push_str(&format!("    flags {};\n", flags.join(", ")));
        }
        if !self.elements.is_empty() {
            out.push_str(&format!(
                "    elements = {{ {} }};\n",
                self.elements.join(", ")
            ));
        }
        out.push_str("  }\n");
        out
    }
}

/// Verdict for a map entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MapVerdict {
    Accept,
    Drop,
    Jump(String),
}

impl std::fmt::Display for MapVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accept => write!(f, "accept"),
            Self::Drop => write!(f, "drop"),
            Self::Jump(chain) => write!(f, "jump {chain}"),
        }
    }
}

/// A named nftables verdict map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftMap {
    /// Map name.
    pub name: String,
    /// Key type.
    pub key_type: SetType,
    /// Entries: key → verdict.
    pub entries: Vec<(String, MapVerdict)>,
}

impl NftMap {
    /// Create a new verdict map.
    pub fn new(name: &str, key_type: SetType) -> Self {
        Self {
            name: name.to_string(),
            key_type,
            entries: vec![],
        }
    }

    /// Add an entry.
    pub fn entry(mut self, key: &str, verdict: MapVerdict) -> Self {
        self.entries.push((key.to_string(), verdict));
        self
    }

    /// Validate map name and entries.
    pub fn validate(&self) -> Result<(), NeinError> {
        validate::validate_identifier(&self.name)?;
        for (key, verdict) in &self.entries {
            validate::validate_nft_element(key)?;
            if let MapVerdict::Jump(chain) = verdict {
                validate::validate_identifier(chain)?;
            }
        }
        Ok(())
    }

    /// Render as nftables map definition (inside a table block).
    pub fn render(&self) -> String {
        let mut out = format!("  map {} {{\n", self.name);
        out.push_str(&format!("    type {} : verdict;\n", self.key_type));
        if !self.entries.is_empty() {
            let entries: Vec<String> = self
                .entries
                .iter()
                .map(|(k, v)| format!("{k} : {v}"))
                .collect();
            out.push_str(&format!("    elements = {{ {} }};\n", entries.join(", ")));
        }
        out.push_str("  }\n");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_render_basic() {
        let set = NftSet::new("blocklist", SetType::Ipv4Addr).elements(&[
            "10.0.0.1",
            "10.0.0.2",
            "192.168.1.0/24",
        ]);
        let rendered = set.render();
        assert!(rendered.contains("set blocklist"));
        assert!(rendered.contains("type ipv4_addr"));
        assert!(rendered.contains("10.0.0.1, 10.0.0.2, 192.168.1.0/24"));
    }

    #[test]
    fn set_render_with_flags() {
        let set = NftSet::new("ratelimit", SetType::Ipv4Addr)
            .flag(SetFlag::Interval)
            .flag(SetFlag::Timeout);
        let rendered = set.render();
        assert!(rendered.contains("flags interval, timeout"));
    }

    #[test]
    fn set_render_empty() {
        let set = NftSet::new("empty", SetType::InetService);
        let rendered = set.render();
        assert!(rendered.contains("set empty"));
        assert!(rendered.contains("type inet_service"));
        assert!(!rendered.contains("elements"));
    }

    #[test]
    fn set_render_ports() {
        let set = NftSet::new("webports", SetType::InetService).elements(&["80", "443", "8080"]);
        let rendered = set.render();
        assert!(rendered.contains("80, 443, 8080"));
    }

    #[test]
    fn set_validate_good() {
        let set = NftSet::new("test", SetType::Ipv4Addr).elements(&["10.0.0.1", "192.168.0.0/16"]);
        assert!(set.validate().is_ok());
    }

    #[test]
    fn set_validate_bad_name() {
        let set = NftSet::new("bad;name", SetType::Ipv4Addr);
        assert!(set.validate().is_err());
    }

    #[test]
    fn set_validate_bad_element() {
        let set = NftSet::new("test", SetType::Ipv4Addr).element("evil;inject");
        assert!(set.validate().is_err());
    }

    #[test]
    fn set_type_display() {
        assert_eq!(SetType::Ipv4Addr.to_string(), "ipv4_addr");
        assert_eq!(SetType::Ipv6Addr.to_string(), "ipv6_addr");
        assert_eq!(SetType::InetService.to_string(), "inet_service");
        assert_eq!(SetType::InetProto.to_string(), "inet_proto");
        assert_eq!(SetType::IfName.to_string(), "ifname");
    }

    #[test]
    fn set_flag_display() {
        assert_eq!(SetFlag::Constant.to_string(), "constant");
        assert_eq!(SetFlag::Interval.to_string(), "interval");
        assert_eq!(SetFlag::Timeout.to_string(), "timeout");
    }

    #[test]
    fn map_render_basic() {
        let map = NftMap::new("country_verdict", SetType::Ipv4Addr)
            .entry("10.0.0.0/8", MapVerdict::Accept)
            .entry("192.168.0.0/16", MapVerdict::Drop);
        let rendered = map.render();
        assert!(rendered.contains("map country_verdict"));
        assert!(rendered.contains("type ipv4_addr : verdict"));
        assert!(rendered.contains("10.0.0.0/8 : accept"));
        assert!(rendered.contains("192.168.0.0/16 : drop"));
    }

    #[test]
    fn map_render_jump() {
        let map = NftMap::new("dispatch", SetType::InetService)
            .entry("80", MapVerdict::Jump("web_chain".into()))
            .entry("22", MapVerdict::Jump("ssh_chain".into()));
        let rendered = map.render();
        assert!(rendered.contains("80 : jump web_chain"));
        assert!(rendered.contains("22 : jump ssh_chain"));
    }

    #[test]
    fn map_render_empty() {
        let map = NftMap::new("empty", SetType::Ipv4Addr);
        let rendered = map.render();
        assert!(rendered.contains("map empty"));
        assert!(!rendered.contains("elements"));
    }

    #[test]
    fn map_validate_good() {
        let map = NftMap::new("test", SetType::Ipv4Addr)
            .entry("10.0.0.1", MapVerdict::Accept)
            .entry("10.0.0.2", MapVerdict::Jump("mychain".into()));
        assert!(map.validate().is_ok());
    }

    #[test]
    fn map_validate_bad_name() {
        let map = NftMap::new("bad;name", SetType::Ipv4Addr);
        assert!(map.validate().is_err());
    }

    #[test]
    fn map_validate_bad_key() {
        let map = NftMap::new("test", SetType::Ipv4Addr).entry("evil;key", MapVerdict::Accept);
        assert!(map.validate().is_err());
    }

    #[test]
    fn map_validate_bad_jump_target() {
        let map = NftMap::new("test", SetType::Ipv4Addr)
            .entry("10.0.0.1", MapVerdict::Jump("bad;chain".into()));
        assert!(map.validate().is_err());
    }

    #[test]
    fn map_verdict_display() {
        assert_eq!(MapVerdict::Accept.to_string(), "accept");
        assert_eq!(MapVerdict::Drop.to_string(), "drop");
        assert_eq!(MapVerdict::Jump("chain1".into()).to_string(), "jump chain1");
    }

    #[test]
    fn set_single_element() {
        let set = NftSet::new("single", SetType::Ipv4Addr).element("10.0.0.1");
        let rendered = set.render();
        assert!(rendered.contains("elements = { 10.0.0.1 }"));
    }

    #[test]
    fn set_ipv6() {
        let set = NftSet::new("v6block", SetType::Ipv6Addr).elements(&["::1", "fe80::/10"]);
        let rendered = set.render();
        assert!(rendered.contains("type ipv6_addr"));
        assert!(rendered.contains("::1, fe80::/10"));
    }
}
