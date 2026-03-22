//! # Nein — Programmatic nftables Firewall
//!
//! Nein (German: no — as in "access denied") provides a type-safe Rust API
//! for generating and applying nftables rules. It replaces raw nft command
//! invocations with a composable rule builder.
//!
//! ## Consumers
//!
//! - **stiva** — container bridge/NAT, port mapping, network isolation
//! - **daimon** — service mesh network policy, agent access control
//! - **aegis** — host firewall rules
//! - **sutra** — fleet-wide firewall playbooks

pub mod rule;
pub mod table;
pub mod chain;
pub mod nat;
pub mod policy;
pub mod apply;
pub mod inspect;
pub mod builder;

mod error;
pub use error::NeinError;

/// Top-level firewall manager.
pub struct Firewall {
    tables: Vec<table::Table>,
    dry_run: bool,
}

impl Firewall {
    /// Create a new firewall manager.
    pub fn new() -> Self {
        Self {
            tables: vec![],
            dry_run: false,
        }
    }

    /// Enable dry-run mode (generate rules but don't apply).
    pub fn dry_run(mut self, enabled: bool) -> Self {
        self.dry_run = enabled;
        self
    }

    /// Add a table.
    pub fn add_table(&mut self, table: table::Table) {
        self.tables.push(table);
    }

    /// Generate the nftables ruleset as a string.
    pub fn render(&self) -> String {
        let mut output = String::new();
        for table in &self.tables {
            output.push_str(&table.render());
            output.push('\n');
        }
        output
    }

    /// Apply the ruleset via `nft -f`.
    pub async fn apply(&self) -> Result<(), NeinError> {
        let ruleset = self.render();
        if self.dry_run {
            tracing::info!("dry-run: would apply {} bytes of nft rules", ruleset.len());
            return Ok(());
        }
        apply::apply_ruleset(&ruleset).await
    }

    /// Flush all rules (reset to empty).
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
}
