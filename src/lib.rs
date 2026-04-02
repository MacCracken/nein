//! # Nein — Programmatic nftables Firewall
//!
//! Nein (German: no — as in "access denied") provides a type-safe Rust API
//! for generating and applying nftables rules. It replaces raw nft command
//! invocations with a composable rule builder.
//!
//! ## Features
//!
//! | Feature   | Module     | Description |
//! |-----------|------------|-------------|
//! | *(core)*  | `rule`, `table`, `chain`, `set`, `validate` | Always available — rule builder, rendering, validation |
//! | `nat`     | `nat`      | NAT rules (DNAT, SNAT, masquerade, redirect) |
//! | `policy`  | `policy`   | Kubernetes-style network policies |
//! | `apply`   | `apply`    | Execute nftables via `nft` command (requires tokio) |
//! | `inspect` | `inspect`  | Query live firewall state |
//! | `builder` | `builder`  | Pre-built firewall configurations |
//! | `bridge`  | `bridge`   | Container bridge firewall with port mappings and isolation |
//! | `engine`  | `engine`   | Per-agent network policy engine |
//! | `mesh`    | `mesh`     | Service mesh sidecar proxy rules (Envoy) |
//! | `mcp`     | `mcp`      | MCP tool descriptors and request/response types |
//! | `config`  | `config`   | TOML firewall configuration (parse and serialize) |
//! | `geoip`   | `geoip`    | GeoIP country-based blocking with nftables sets |
//! | `netns`   | `netns`    | Agent network namespace firewall (requires agnosys) |
//!
//! ## Consumers
//!
//! - **stiva** — container bridge/NAT, port mapping, network isolation
//! - **daimon** — service mesh network policy, agent access control
//! - **aegis** — host firewall rules
//! - **sutra** — fleet-wide firewall playbooks

pub mod chain;
pub mod rule;
pub mod set;
pub mod table;
pub mod validate;

#[cfg(feature = "nat")]
pub mod nat;

#[cfg(feature = "policy")]
pub mod policy;

#[cfg(feature = "apply")]
pub mod apply;

#[cfg(feature = "inspect")]
pub mod inspect;

#[cfg(feature = "builder")]
pub mod builder;

#[cfg(feature = "bridge")]
pub mod bridge;

#[cfg(feature = "engine")]
pub mod engine;

#[cfg(feature = "mesh")]
pub mod mesh;

#[cfg(feature = "mcp")]
pub mod mcp;

#[cfg(feature = "config")]
pub mod config;

#[cfg(feature = "geoip")]
pub mod geoip;

#[cfg(feature = "netns")]
pub mod netns;

mod error;
pub use error::NeinError;

/// Top-level firewall manager.
#[derive(Debug, Clone)]
pub struct Firewall {
    tables: Vec<table::Table>,
    dry_run: bool,
}

impl Firewall {
    /// Create a new firewall manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tables: vec![],
            dry_run: false,
        }
    }

    /// Enable dry-run mode (generate rules but don't apply).
    #[must_use]
    pub fn dry_run(mut self, enabled: bool) -> Self {
        self.dry_run = enabled;
        self
    }

    /// Add a table.
    pub fn add_table(&mut self, table: table::Table) {
        self.tables.push(table);
    }

    /// Generate the nftables ruleset as a string.
    #[must_use]
    pub fn render(&self) -> String {
        let mut output = String::with_capacity(self.tables.len() * 256);
        for table in &self.tables {
            output.push_str(&table.render());
            output.push('\n');
        }
        output
    }

    /// Access the tables in this firewall.
    #[must_use]
    pub fn tables(&self) -> &[table::Table] {
        &self.tables
    }

    /// Validate all tables, chains, and rules for dangerous input.
    ///
    /// Called automatically by [`apply`] before executing. You can also call
    /// it manually to check a ruleset without applying.
    pub fn validate(&self) -> Result<(), NeinError> {
        tracing::debug!(tables = self.tables.len(), "validating firewall");
        for table in &self.tables {
            validate::validate_identifier(&table.name)?;
            for define in &table.defines {
                define.validate()?;
            }
            for ft in &table.flowtables {
                ft.validate()?;
            }
            for ct in &table.ct_timeouts {
                ct.validate()?;
            }
            for set in &table.sets {
                set.validate()?;
            }
            for map in &table.maps {
                map.validate()?;
            }
            for chain in &table.chains {
                validate::validate_identifier(&chain.name)?;
                for entry in &chain.rules {
                    entry.validate()?;
                }
            }
        }
        tracing::debug!("firewall validation passed");
        Ok(())
    }

    /// Apply the ruleset via `nft -f`.
    ///
    /// Validates all rule inputs before applying. In dry-run mode, logs the
    /// ruleset size but does not execute.
    #[cfg(feature = "apply")]
    pub async fn apply(&self) -> Result<(), NeinError> {
        self.validate()?;
        let ruleset = self.render();
        if self.dry_run {
            tracing::info!(bytes = ruleset.len(), "dry-run: skipping apply");
            return Ok(());
        }
        tracing::info!(
            tables = self.tables.len(),
            bytes = ruleset.len(),
            "applying firewall"
        );
        apply::apply_ruleset(&ruleset).await
    }

    /// Flush all nftables rules (reset to empty).
    ///
    /// **Warning:** this flushes the *entire* nftables ruleset on the host,
    /// not just tables managed by this `Firewall` instance. Use with caution
    /// on systems with rules managed by other tools.
    #[cfg(feature = "apply")]
    pub async fn flush(&self) -> Result<(), NeinError> {
        if self.dry_run {
            tracing::info!("dry-run: would flush all rules");
            return Ok(());
        }
        apply::flush_ruleset().await
    }
}

impl Default for Firewall {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_default() {
        let fw = Firewall::new();
        assert!(fw.tables.is_empty());
        assert!(!fw.dry_run);
    }

    #[test]
    fn firewall_dry_run() {
        let fw = Firewall::new().dry_run(true);
        assert!(fw.dry_run);
    }

    #[test]
    fn render_empty() {
        let fw = Firewall::new();
        assert_eq!(fw.render(), "");
    }

    #[test]
    fn validate_empty() {
        let fw = Firewall::new();
        assert!(fw.validate().is_ok());
    }

    #[test]
    fn validate_rejects_bad_table_name() {
        let mut fw = Firewall::new();
        fw.add_table(table::Table::new("evil;drop", table::Family::Inet));
        assert!(fw.validate().is_err());
    }

    #[test]
    fn firewall_default_impl() {
        let fw = Firewall::default();
        assert!(fw.tables.is_empty());
    }

    #[test]
    fn firewall_tables_accessor() {
        let mut fw = Firewall::new();
        assert!(fw.tables().is_empty());
        fw.add_table(table::Table::new("test", table::Family::Inet));
        assert_eq!(fw.tables().len(), 1);
        assert_eq!(fw.tables()[0].name, "test");
    }

    #[test]
    fn firewall_clone() {
        let mut fw = Firewall::new().dry_run(true);
        fw.add_table(table::Table::new("test", table::Family::Inet));
        let fw2 = fw.clone();
        assert_eq!(fw.render(), fw2.render());
        assert_eq!(fw.tables().len(), fw2.tables().len());
    }

    #[test]
    fn firewall_multiple_tables() {
        let mut fw = Firewall::new();
        fw.add_table(table::Table::new("t1", table::Family::Inet));
        fw.add_table(table::Table::new("t2", table::Family::Ip));
        let rendered = fw.render();
        assert!(rendered.contains("table inet t1"));
        assert!(rendered.contains("table ip t2"));
        assert_eq!(fw.tables().len(), 2);
    }

    #[test]
    fn validate_rejects_bad_chain_name() {
        let mut fw = Firewall::new();
        let mut table = table::Table::new("good", table::Family::Inet);
        table.add_chain(chain::Chain::regular("bad;chain"));
        fw.add_table(table);
        assert!(fw.validate().is_err());
    }
}
