//! TOML firewall configuration.
//!
//! Parse firewall rulesets from TOML files and serialize them back.
//! Designed for sutra fleet-wide firewall playbooks.
//!
//! # Example TOML
//!
//! ```toml
//! [[tables]]
//! name = "filter"
//! family = "inet"
//!
//! [[tables.chains]]
//! name = "input"
//! chain_type = "filter"
//! hook = "input"
//! priority = 0
//! policy = "drop"
//!
//! [[tables.chains.rules]]
//! matches = [{ type = "ct_state", states = ["established", "related"] }]
//! verdict = "accept"
//!
//! [[tables.chains.rules]]
//! matches = [{ type = "protocol", value = "tcp" }, { type = "dport", port = 22 }]
//! verdict = "accept"
//! comment = "SSH"
//! ```

use crate::Firewall;
use crate::chain::{Chain, ChainType, Hook, Policy};
use crate::error::NeinError;
use crate::rule::{Match, Protocol, RateUnit, Rule, Verdict};
use crate::table::{Family, Table};
use serde::{Deserialize, Serialize};

/// Top-level TOML firewall config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    #[serde(default)]
    pub tables: Vec<TableConfig>,
}

/// Table configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableConfig {
    pub name: String,
    pub family: String,
    #[serde(default)]
    pub chains: Vec<ChainConfig>,
}

/// Chain configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub name: String,
    #[serde(default)]
    pub chain_type: Option<String>,
    #[serde(default)]
    pub hook: Option<String>,
    #[serde(default)]
    pub priority: Option<i32>,
    #[serde(default)]
    pub policy: Option<String>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

/// Rule configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    #[serde(default)]
    pub matches: Vec<MatchConfig>,
    pub verdict: String,
    #[serde(default)]
    pub verdict_chain: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// Match configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MatchConfig {
    #[serde(rename = "source_addr")]
    SourceAddr { addr: String },
    #[serde(rename = "dest_addr")]
    DestAddr { addr: String },
    #[serde(rename = "source_addr6")]
    SourceAddr6 { addr: String },
    #[serde(rename = "dest_addr6")]
    DestAddr6 { addr: String },
    #[serde(rename = "protocol")]
    Protocol { value: String },
    #[serde(rename = "dport")]
    DPort { port: u16 },
    #[serde(rename = "sport")]
    SPort { port: u16 },
    #[serde(rename = "dport_range")]
    DPortRange { low: u16, high: u16 },
    #[serde(rename = "iif")]
    Iif { iface: String },
    #[serde(rename = "oif")]
    Oif { iface: String },
    #[serde(rename = "ct_state")]
    CtState { states: Vec<String> },
    #[serde(rename = "ct_helper")]
    CtHelper { helper: String },
    #[serde(rename = "limit")]
    Limit {
        rate: u32,
        unit: String,
        #[serde(default)]
        burst: Option<u32>,
    },
    #[serde(rename = "set_lookup")]
    SetLookup { field: String, set_name: String },
    #[serde(rename = "tcp_flags")]
    TcpFlags { flags: Vec<String> },
    #[serde(rename = "icmp_type")]
    IcmpType { icmp_type: String },
    #[serde(rename = "icmpv6_type")]
    Icmpv6Type { icmp_type: String },
    #[serde(rename = "meta_mark")]
    MetaMark { value: u32 },
    #[serde(rename = "raw")]
    Raw { expr: String },
}

/// Parse a TOML string into a `Firewall`.
pub fn from_toml(toml_str: &str) -> Result<Firewall, NeinError> {
    let config: FirewallConfig =
        toml::from_str(toml_str).map_err(|e| NeinError::Parse(e.to_string()))?;
    config_to_firewall(&config)
}

/// Serialize a `FirewallConfig` to TOML.
pub fn to_toml(config: &FirewallConfig) -> Result<String, NeinError> {
    toml::to_string_pretty(config).map_err(|e| NeinError::Parse(e.to_string()))
}

fn config_to_firewall(config: &FirewallConfig) -> Result<Firewall, NeinError> {
    let mut fw = Firewall::new();
    for tc in &config.tables {
        fw.add_table(parse_table(tc)?);
    }
    Ok(fw)
}

fn parse_table(tc: &TableConfig) -> Result<Table, NeinError> {
    let family = parse_family(&tc.family)?;
    let mut table = Table::new(&tc.name, family);
    for cc in &tc.chains {
        table.add_chain(parse_chain(cc)?);
    }
    Ok(table)
}

fn parse_chain(cc: &ChainConfig) -> Result<Chain, NeinError> {
    let chain = if let (Some(ct), Some(hook), Some(prio), Some(pol)) =
        (&cc.chain_type, &cc.hook, &cc.priority, &cc.policy)
    {
        Chain::base(
            &cc.name,
            parse_chain_type(ct)?,
            parse_hook(hook)?,
            *prio,
            parse_policy(pol)?,
        )
    } else {
        Chain::regular(&cc.name)
    };

    let mut chain = chain;
    for rc in &cc.rules {
        chain.add_rule(parse_rule(rc)?);
    }
    Ok(chain)
}

fn parse_rule(rc: &RuleConfig) -> Result<Rule, NeinError> {
    let verdict = parse_verdict(&rc.verdict, &rc.verdict_chain)?;
    let mut rule = Rule::new(verdict);
    for mc in &rc.matches {
        rule = rule.matching(parse_match(mc)?);
    }
    if let Some(c) = &rc.comment {
        rule = rule.comment(c);
    }
    Ok(rule)
}

fn parse_match(mc: &MatchConfig) -> Result<Match, NeinError> {
    Ok(match mc {
        MatchConfig::SourceAddr { addr } => Match::SourceAddr(addr.clone()),
        MatchConfig::DestAddr { addr } => Match::DestAddr(addr.clone()),
        MatchConfig::SourceAddr6 { addr } => Match::SourceAddr6(addr.clone()),
        MatchConfig::DestAddr6 { addr } => Match::DestAddr6(addr.clone()),
        MatchConfig::Protocol { value } => Match::Protocol(parse_protocol(value)?),
        MatchConfig::DPort { port } => Match::DPort(*port),
        MatchConfig::SPort { port } => Match::SPort(*port),
        MatchConfig::DPortRange { low, high } => Match::DPortRange(*low, *high),
        MatchConfig::Iif { iface } => Match::Iif(iface.clone()),
        MatchConfig::Oif { iface } => Match::Oif(iface.clone()),
        MatchConfig::CtState { states } => Match::CtState(states.clone()),
        MatchConfig::CtHelper { helper } => Match::CtHelper(helper.clone()),
        MatchConfig::Limit { rate, unit, burst } => Match::Limit {
            rate: *rate,
            unit: parse_rate_unit(unit)?,
            burst: burst.unwrap_or(*rate),
        },
        MatchConfig::SetLookup { field, set_name } => Match::SetLookup {
            field: field.clone(),
            set_name: set_name.clone(),
        },
        MatchConfig::TcpFlags { flags } => Match::TcpFlags(flags.clone()),
        MatchConfig::IcmpType { icmp_type } => Match::IcmpType(icmp_type.clone()),
        MatchConfig::Icmpv6Type { icmp_type } => Match::Icmpv6Type(icmp_type.clone()),
        MatchConfig::MetaMark { value } => Match::MetaMark(*value),
        MatchConfig::Raw { expr } => Match::Raw(expr.clone()),
    })
}

fn parse_family(s: &str) -> Result<Family, NeinError> {
    match s {
        "inet" => Ok(Family::Inet),
        "ip" => Ok(Family::Ip),
        "ip6" => Ok(Family::Ip6),
        "arp" => Ok(Family::Arp),
        "bridge" => Ok(Family::Bridge),
        "netdev" => Ok(Family::Netdev),
        _ => Err(NeinError::Parse(format!(
            "unknown family: {s} (valid: inet, ip, ip6, arp, bridge, netdev)"
        ))),
    }
}

fn parse_chain_type(s: &str) -> Result<ChainType, NeinError> {
    match s {
        "filter" => Ok(ChainType::Filter),
        "nat" => Ok(ChainType::Nat),
        "route" => Ok(ChainType::Route),
        _ => Err(NeinError::Parse(format!(
            "unknown chain type: {s} (valid: filter, nat, route)"
        ))),
    }
}

fn parse_hook(s: &str) -> Result<Hook, NeinError> {
    match s {
        "prerouting" => Ok(Hook::Prerouting),
        "input" => Ok(Hook::Input),
        "forward" => Ok(Hook::Forward),
        "output" => Ok(Hook::Output),
        "postrouting" => Ok(Hook::Postrouting),
        "ingress" => Ok(Hook::Ingress),
        _ => Err(NeinError::Parse(format!(
            "unknown hook: {s} (valid: prerouting, input, forward, output, postrouting, ingress)"
        ))),
    }
}

fn parse_policy(s: &str) -> Result<Policy, NeinError> {
    match s {
        "accept" => Ok(Policy::Accept),
        "drop" => Ok(Policy::Drop),
        _ => Err(NeinError::Parse(format!(
            "unknown policy: {s} (valid: accept, drop)"
        ))),
    }
}

fn parse_verdict(s: &str, chain: &Option<String>) -> Result<Verdict, NeinError> {
    match s {
        "accept" => Ok(Verdict::Accept),
        "drop" => Ok(Verdict::Drop),
        "reject" => Ok(Verdict::Reject),
        "return" => Ok(Verdict::Return),
        "counter" => Ok(Verdict::Counter),
        "log" => Ok(Verdict::Log(None)),
        "jump" => Ok(Verdict::Jump(
            chain
                .as_ref()
                .ok_or_else(|| NeinError::Parse("jump requires verdict_chain".into()))?
                .clone(),
        )),
        "goto" => Ok(Verdict::GoTo(
            chain
                .as_ref()
                .ok_or_else(|| NeinError::Parse("goto requires verdict_chain".into()))?
                .clone(),
        )),
        _ => Err(NeinError::Parse(format!(
            "unknown verdict: {s} (valid: accept, drop, reject, return, counter, log, jump, goto)"
        ))),
    }
}

fn parse_protocol(s: &str) -> Result<Protocol, NeinError> {
    match s {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "icmp" => Ok(Protocol::Icmp),
        "icmpv6" => Ok(Protocol::Icmpv6),
        _ => Err(NeinError::Parse(format!(
            "unknown protocol: {s} (valid: tcp, udp, icmp, icmpv6)"
        ))),
    }
}

fn parse_rate_unit(s: &str) -> Result<RateUnit, NeinError> {
    match s {
        "second" => Ok(RateUnit::Second),
        "minute" => Ok(RateUnit::Minute),
        "hour" => Ok(RateUnit::Hour),
        "day" => Ok(RateUnit::Day),
        _ => Err(NeinError::Parse(format!(
            "unknown rate unit: {s} (valid: second, minute, hour, day)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_firewall() {
        let toml = r#"
[[tables]]
name = "filter"
family = "inet"

[[tables.chains]]
name = "input"
chain_type = "filter"
hook = "input"
priority = 0
policy = "drop"

[[tables.chains.rules]]
matches = [{ type = "ct_state", states = ["established", "related"] }]
verdict = "accept"

[[tables.chains.rules]]
matches = [{ type = "protocol", value = "tcp" }, { type = "dport", port = 22 }]
verdict = "accept"
comment = "SSH"
"#;
        let fw = from_toml(toml).unwrap();
        let rendered = fw.render();
        assert!(rendered.contains("table inet filter"));
        assert!(rendered.contains("policy drop"));
        assert!(rendered.contains("ct state { established, related } accept"));
        assert!(rendered.contains("tcp dport 22 accept"));
        assert!(rendered.contains("comment \"SSH\""));
    }

    #[test]
    fn parse_regular_chain() {
        let toml = r#"
[[tables]]
name = "test"
family = "inet"

[[tables.chains]]
name = "custom"

[[tables.chains.rules]]
verdict = "accept"
"#;
        let fw = from_toml(toml).unwrap();
        let rendered = fw.render();
        assert!(rendered.contains("chain custom"));
        assert!(!rendered.contains("type filter"));
    }

    #[test]
    fn parse_ipv6_rules() {
        let toml = r#"
[[tables]]
name = "v6"
family = "ip6"

[[tables.chains]]
name = "input"
chain_type = "filter"
hook = "input"
priority = 0
policy = "drop"

[[tables.chains.rules]]
matches = [{ type = "source_addr6", addr = "fe80::/10" }]
verdict = "accept"
"#;
        let fw = from_toml(toml).unwrap();
        let rendered = fw.render();
        assert!(rendered.contains("ip6 saddr fe80::/10"));
    }

    #[test]
    fn parse_rate_limit() {
        let toml = r#"
[[tables]]
name = "filter"
family = "inet"

[[tables.chains]]
name = "input"
chain_type = "filter"
hook = "input"
priority = 0
policy = "drop"

[[tables.chains.rules]]
matches = [
    { type = "protocol", value = "tcp" },
    { type = "dport", port = 22 },
    { type = "limit", rate = 3, unit = "minute" }
]
verdict = "accept"
comment = "SSH rate limited"
"#;
        let fw = from_toml(toml).unwrap();
        let rendered = fw.render();
        assert!(rendered.contains("limit rate 3/minute burst 3 packets"));
    }

    #[test]
    fn parse_set_lookup() {
        let toml = r#"
[[tables]]
name = "filter"
family = "inet"

[[tables.chains]]
name = "input"

[[tables.chains.rules]]
matches = [{ type = "set_lookup", field = "ip saddr", set_name = "blocklist" }]
verdict = "drop"
"#;
        let fw = from_toml(toml).unwrap();
        let rendered = fw.render();
        assert!(rendered.contains("ip saddr @blocklist drop"));
    }

    #[test]
    fn parse_jump_verdict() {
        let toml = r#"
[[tables]]
name = "filter"
family = "inet"

[[tables.chains]]
name = "input"

[[tables.chains.rules]]
matches = [{ type = "iif", iface = "eth0" }]
verdict = "jump"
verdict_chain = "eth0_rules"
"#;
        let fw = from_toml(toml).unwrap();
        let rendered = fw.render();
        assert!(rendered.contains("jump eth0_rules"));
    }

    #[test]
    fn parse_all_match_types() {
        let toml = r#"
[[tables]]
name = "test"
family = "inet"

[[tables.chains]]
name = "c"

[[tables.chains.rules]]
matches = [{ type = "source_addr", addr = "10.0.0.0/8" }]
verdict = "accept"

[[tables.chains.rules]]
matches = [{ type = "dest_addr", addr = "192.168.0.0/16" }]
verdict = "drop"

[[tables.chains.rules]]
matches = [{ type = "sport", port = 1024 }]
verdict = "accept"

[[tables.chains.rules]]
matches = [{ type = "dport_range", low = 8000, high = 9000 }]
verdict = "accept"

[[tables.chains.rules]]
matches = [{ type = "oif", iface = "eth0" }]
verdict = "accept"

[[tables.chains.rules]]
matches = [{ type = "ct_helper", helper = "ftp" }]
verdict = "accept"

[[tables.chains.rules]]
matches = [{ type = "raw", expr = "meta mark 0x1" }]
verdict = "accept"
"#;
        let fw = from_toml(toml).unwrap();
        let rendered = fw.render();
        assert!(rendered.contains("ip saddr 10.0.0.0/8"));
        assert!(rendered.contains("ip daddr 192.168.0.0/16"));
        assert!(rendered.contains("sport 1024"));
        assert!(rendered.contains("dport 8000-9000"));
        assert!(rendered.contains("oif \"eth0\""));
        assert!(rendered.contains("ct helper \"ftp\""));
        assert!(rendered.contains("meta mark 0x1"));
    }

    #[test]
    fn parse_error_bad_family() {
        let toml = r#"
[[tables]]
name = "test"
family = "unknown"
"#;
        assert!(from_toml(toml).is_err());
    }

    #[test]
    fn parse_error_bad_verdict() {
        let toml = r#"
[[tables]]
name = "test"
family = "inet"

[[tables.chains]]
name = "c"

[[tables.chains.rules]]
verdict = "explode"
"#;
        assert!(from_toml(toml).is_err());
    }

    #[test]
    fn parse_error_jump_no_chain() {
        let toml = r#"
[[tables]]
name = "test"
family = "inet"

[[tables.chains]]
name = "c"

[[tables.chains.rules]]
verdict = "jump"
"#;
        assert!(from_toml(toml).is_err());
    }

    #[test]
    fn parse_error_bad_toml() {
        assert!(from_toml("not valid toml [[[").is_err());
    }

    #[test]
    fn parse_empty_config() {
        let fw = from_toml("").unwrap();
        assert_eq!(fw.render(), "");
    }

    #[test]
    fn serialize_config() {
        let config = FirewallConfig {
            tables: vec![TableConfig {
                name: "filter".to_string(),
                family: "inet".to_string(),
                chains: vec![ChainConfig {
                    name: "input".to_string(),
                    chain_type: Some("filter".to_string()),
                    hook: Some("input".to_string()),
                    priority: Some(0),
                    policy: Some("drop".to_string()),
                    rules: vec![RuleConfig {
                        matches: vec![MatchConfig::Protocol {
                            value: "tcp".to_string(),
                        }],
                        verdict: "accept".to_string(),
                        verdict_chain: None,
                        comment: Some("allow TCP".to_string()),
                    }],
                }],
            }],
        };
        let toml_str = to_toml(&config).unwrap();
        assert!(toml_str.contains("name = \"filter\""));
        assert!(toml_str.contains("family = \"inet\""));

        // Round-trip: parse back
        let fw = from_toml(&toml_str).unwrap();
        assert!(fw.render().contains("table inet filter"));
    }

    #[test]
    fn parse_all_verdicts() {
        for (verdict, expected) in [
            ("accept", "accept"),
            ("drop", "drop"),
            ("reject", "reject"),
            ("return", "return"),
            ("counter", "counter"),
            ("log", "log"),
        ] {
            let toml = format!(
                r#"
[[tables]]
name = "test"
family = "inet"
[[tables.chains]]
name = "c"
[[tables.chains.rules]]
verdict = "{verdict}"
"#
            );
            let fw = from_toml(&toml).unwrap();
            assert!(fw.render().contains(expected));
        }
    }

    #[test]
    fn parse_all_families() {
        for (family, expected) in [
            ("inet", "inet"),
            ("ip", "ip"),
            ("ip6", "ip6"),
            ("arp", "arp"),
            ("bridge", "bridge"),
            ("netdev", "netdev"),
        ] {
            let toml = format!(
                r#"
[[tables]]
name = "test"
family = "{family}"
"#
            );
            let fw = from_toml(&toml).unwrap();
            assert!(fw.render().contains(&format!("table {expected} test")));
        }
    }

    #[test]
    fn parse_goto_verdict() {
        let toml = r#"
[[tables]]
name = "test"
family = "inet"
[[tables.chains]]
name = "c"
[[tables.chains.rules]]
verdict = "goto"
verdict_chain = "other"
"#;
        let fw = from_toml(toml).unwrap();
        assert!(fw.render().contains("goto other"));
    }

    #[test]
    fn parse_limit_with_burst() {
        let toml = r#"
[[tables]]
name = "test"
family = "inet"
[[tables.chains]]
name = "c"
[[tables.chains.rules]]
matches = [{ type = "limit", rate = 10, unit = "second", burst = 50 }]
verdict = "accept"
"#;
        let fw = from_toml(toml).unwrap();
        assert!(
            fw.render()
                .contains("limit rate 10/second burst 50 packets")
        );
    }
}
