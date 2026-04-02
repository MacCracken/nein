//! Service mesh sidecar proxy rules.
//!
//! Generates nftables rules for transparent proxy redirection through
//! an Envoy or similar sidecar proxy. Supports inbound and outbound
//! interception with configurable exclusions.

use crate::Firewall;
use crate::chain::{Chain, ChainType, Hook, Policy};
use crate::error::NeinError;
use crate::rule::{Match, Protocol, Rule, Verdict};
use crate::table::{Family, Table};
use crate::validate;
use serde::{Deserialize, Serialize};

/// Configuration for sidecar proxy traffic interception.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SidecarConfig {
    /// Local port where the proxy listens for redirected inbound traffic.
    pub inbound_port: u16,
    /// Local port where the proxy listens for redirected outbound traffic.
    pub outbound_port: u16,
    /// UID of the proxy process (traffic from this UID bypasses redirection).
    pub proxy_uid: u32,
    /// CIDRs to exclude from outbound interception (e.g., "127.0.0.0/8").
    pub exclude_outbound_cidrs: Vec<String>,
    /// Ports to exclude from outbound interception (e.g., health check ports).
    pub exclude_outbound_ports: Vec<u16>,
    /// Ports to exclude from inbound interception.
    pub exclude_inbound_ports: Vec<u16>,
    /// nftables table name (default: "nein_mesh").
    pub table_name: String,
}

impl SidecarConfig {
    /// Create a new sidecar config with standard Envoy defaults.
    ///
    /// - Inbound port: 15006
    /// - Outbound port: 15001
    /// - Proxy UID: 1337 (Istio convention)
    /// - Excludes localhost (127.0.0.0/8) from outbound
    #[must_use]
    pub fn envoy() -> Self {
        Self {
            inbound_port: 15006,
            outbound_port: 15001,
            proxy_uid: 1337,
            exclude_outbound_cidrs: vec!["127.0.0.0/8".to_string()],
            exclude_outbound_ports: vec![],
            exclude_inbound_ports: vec![],
            table_name: "nein_mesh".to_string(),
        }
    }

    /// Set custom inbound proxy port.
    #[must_use]
    pub fn inbound_port(mut self, port: u16) -> Self {
        self.inbound_port = port;
        self
    }

    /// Set custom outbound proxy port.
    #[must_use]
    pub fn outbound_port(mut self, port: u16) -> Self {
        self.outbound_port = port;
        self
    }

    /// Set the proxy process UID.
    #[must_use]
    pub fn proxy_uid(mut self, uid: u32) -> Self {
        self.proxy_uid = uid;
        self
    }

    /// Add a CIDR to exclude from outbound interception.
    #[must_use]
    pub fn exclude_outbound_cidr(mut self, cidr: &str) -> Self {
        self.exclude_outbound_cidrs.push(cidr.to_string());
        self
    }

    /// Add a port to exclude from outbound interception.
    #[must_use]
    pub fn exclude_outbound_port(mut self, port: u16) -> Self {
        self.exclude_outbound_ports.push(port);
        self
    }

    /// Add a port to exclude from inbound interception.
    #[must_use]
    pub fn exclude_inbound_port(mut self, port: u16) -> Self {
        self.exclude_inbound_ports.push(port);
        self
    }

    /// Set custom table name.
    #[must_use]
    pub fn table_name(mut self, name: &str) -> Self {
        self.table_name = name.to_string();
        self
    }

    /// Validate all fields.
    pub fn validate(&self) -> Result<(), NeinError> {
        validate::validate_identifier(&self.table_name)?;
        for cidr in &self.exclude_outbound_cidrs {
            validate::validate_addr(cidr)?;
        }
        Ok(())
    }

    /// Generate the nftables `Firewall` for sidecar proxy interception.
    ///
    /// Produces a nat table with:
    /// - `mesh_outbound` (output chain): redirects outbound TCP to the proxy,
    ///   skipping proxy's own traffic and excluded CIDRs/ports.
    /// - `mesh_inbound` (prerouting chain): redirects inbound TCP to the proxy,
    ///   skipping excluded ports.
    #[must_use]
    pub fn to_firewall(&self) -> Firewall {
        let mut fw = Firewall::new();
        let mut table = Table::new(&self.table_name, Family::Ip);

        table.add_chain(self.build_outbound_chain());
        table.add_chain(self.build_inbound_chain());

        fw.add_table(table);
        fw
    }

    fn build_outbound_chain(&self) -> Chain {
        let mut chain = Chain::base(
            "mesh_outbound",
            ChainType::Nat,
            Hook::Output,
            -100,
            Policy::Accept,
        );

        // Skip proxy's own traffic (avoid redirect loop)
        chain.add_rule(
            Rule::new(Verdict::Return)
                .matching(Match::Raw(format!("meta skuid {}", self.proxy_uid)))
                .comment("skip proxy traffic"),
        );

        // Skip excluded CIDRs
        for cidr in &self.exclude_outbound_cidrs {
            chain.add_rule(
                Rule::new(Verdict::Return)
                    .matching(Match::DestAddr(cidr.clone()))
                    .comment(&format!("skip outbound {cidr}")),
            );
        }

        // Skip excluded ports
        for port in &self.exclude_outbound_ports {
            chain.add_rule(
                Rule::new(Verdict::Return)
                    .matching(Match::Protocol(Protocol::Tcp))
                    .matching(Match::DPort(*port))
                    .comment(&format!("skip outbound port {port}")),
            );
        }

        // Redirect all remaining outbound TCP to proxy
        chain.add_rule(
            Rule::new(Verdict::Accept)
                .matching(Match::Raw(format!(
                    "tcp dport != {} redirect to :{}",
                    self.outbound_port, self.outbound_port
                )))
                .comment("redirect outbound to proxy"),
        );

        chain
    }

    fn build_inbound_chain(&self) -> Chain {
        let mut chain = Chain::base(
            "mesh_inbound",
            ChainType::Nat,
            Hook::Prerouting,
            -100,
            Policy::Accept,
        );

        // Skip excluded inbound ports
        for port in &self.exclude_inbound_ports {
            chain.add_rule(
                Rule::new(Verdict::Return)
                    .matching(Match::Protocol(Protocol::Tcp))
                    .matching(Match::DPort(*port))
                    .comment(&format!("skip inbound port {port}")),
            );
        }

        // Redirect all remaining inbound TCP to proxy
        chain.add_rule(
            Rule::new(Verdict::Accept)
                .matching(Match::Raw(format!(
                    "tcp dport != {} redirect to :{}",
                    self.inbound_port, self.inbound_port
                )))
                .comment("redirect inbound to proxy"),
        );

        chain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envoy_defaults() {
        let cfg = SidecarConfig::envoy();
        assert_eq!(cfg.inbound_port, 15006);
        assert_eq!(cfg.outbound_port, 15001);
        assert_eq!(cfg.proxy_uid, 1337);
        assert_eq!(cfg.exclude_outbound_cidrs, vec!["127.0.0.0/8"]);
    }

    #[test]
    fn render_envoy_defaults() {
        let fw = SidecarConfig::envoy().to_firewall();
        let rendered = fw.render();

        assert!(rendered.contains("table ip nein_mesh"));
        assert!(rendered.contains("chain mesh_outbound"));
        assert!(rendered.contains("chain mesh_inbound"));
        // Proxy UID skip
        assert!(rendered.contains("meta skuid 1337"));
        assert!(rendered.contains("skip proxy traffic"));
        // Localhost skip
        assert!(rendered.contains("ip daddr 127.0.0.0/8"));
        assert!(rendered.contains("skip outbound 127.0.0.0/8"));
        // Outbound redirect
        assert!(rendered.contains("redirect to :15001"));
        // Inbound redirect
        assert!(rendered.contains("redirect to :15006"));
    }

    #[test]
    fn custom_ports() {
        let cfg = SidecarConfig::envoy()
            .inbound_port(20000)
            .outbound_port(20001)
            .proxy_uid(5000);
        let rendered = cfg.to_firewall().render();

        assert!(rendered.contains("meta skuid 5000"));
        assert!(rendered.contains("redirect to :20001"));
        assert!(rendered.contains("redirect to :20000"));
    }

    #[test]
    fn exclude_outbound_ports() {
        let cfg = SidecarConfig::envoy()
            .exclude_outbound_port(9090)
            .exclude_outbound_port(8081);
        let rendered = cfg.to_firewall().render();

        assert!(rendered.contains("skip outbound port 9090"));
        assert!(rendered.contains("skip outbound port 8081"));
        assert!(rendered.contains("dport 9090"));
    }

    #[test]
    fn exclude_inbound_ports() {
        let cfg = SidecarConfig::envoy()
            .exclude_inbound_port(15090)
            .exclude_inbound_port(15021);
        let rendered = cfg.to_firewall().render();

        assert!(rendered.contains("skip inbound port 15090"));
        assert!(rendered.contains("skip inbound port 15021"));
    }

    #[test]
    fn exclude_outbound_cidrs() {
        let cfg = SidecarConfig::envoy()
            .exclude_outbound_cidr("10.0.0.0/8")
            .exclude_outbound_cidr("169.254.0.0/16");
        let rendered = cfg.to_firewall().render();

        assert!(rendered.contains("skip outbound 10.0.0.0/8"));
        assert!(rendered.contains("skip outbound 169.254.0.0/16"));
    }

    #[test]
    fn custom_table_name() {
        let cfg = SidecarConfig::envoy().table_name("daimon_mesh");
        let rendered = cfg.to_firewall().render();
        assert!(rendered.contains("table ip daimon_mesh"));
    }

    #[test]
    fn validate_good() {
        assert!(SidecarConfig::envoy().validate().is_ok());
    }

    #[test]
    fn validate_bad_table() {
        let cfg = SidecarConfig::envoy().table_name("bad;name");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_bad_cidr() {
        let cfg = SidecarConfig::envoy().exclude_outbound_cidr("evil;cidr");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn firewall_validates() {
        let fw = SidecarConfig::envoy()
            .exclude_outbound_port(9090)
            .exclude_inbound_port(15090)
            .to_firewall();
        assert!(fw.validate().is_ok());
    }

    #[test]
    fn combined_exclusions() {
        let cfg = SidecarConfig::envoy()
            .exclude_outbound_cidr("10.0.0.0/8")
            .exclude_outbound_port(9090)
            .exclude_inbound_port(15090)
            .exclude_inbound_port(15021);
        let rendered = cfg.to_firewall().render();

        // Outbound chain has: UID skip, 2 CIDR skips, 1 port skip, redirect
        assert!(rendered.contains("skip proxy traffic"));
        assert!(rendered.contains("skip outbound 127.0.0.0/8"));
        assert!(rendered.contains("skip outbound 10.0.0.0/8"));
        assert!(rendered.contains("skip outbound port 9090"));
        assert!(rendered.contains("redirect to :15001"));

        // Inbound chain has: 2 port skips, redirect
        assert!(rendered.contains("skip inbound port 15090"));
        assert!(rendered.contains("skip inbound port 15021"));
        assert!(rendered.contains("redirect to :15006"));
    }

    #[test]
    fn no_exclusions() {
        let mut cfg = SidecarConfig::envoy();
        cfg.exclude_outbound_cidrs.clear();
        let rendered = cfg.to_firewall().render();

        // Should still have UID skip and redirects, just no CIDR/port skips
        assert!(rendered.contains("meta skuid 1337"));
        assert!(rendered.contains("redirect to :15001"));
        assert!(rendered.contains("redirect to :15006"));
        assert!(!rendered.contains("skip outbound 127"));
    }
}
