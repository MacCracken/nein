//! Inspect current firewall state.

use crate::error::NeinError;
use serde::{Deserialize, Serialize};

/// Summary of current firewall state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FirewallStatus {
    pub tables: Vec<String>,
    pub total_rules: usize,
    pub raw_ruleset: String,
}

/// Get current firewall status.
pub async fn status() -> Result<FirewallStatus, NeinError> {
    tracing::debug!("querying firewall status");
    let raw = crate::apply::list_ruleset().await?;

    let tables: Vec<String> = raw
        .lines()
        .filter(|l| l.starts_with("table "))
        .map(|l| l.trim_end_matches(" {").to_string())
        .collect();

    let total_rules = raw
        .lines()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.is_empty()
                && !trimmed.starts_with("table ")
                && !trimmed.starts_with("chain ")
                && !trimmed.starts_with("type ")
                && trimmed != "}"
        })
        .count();

    Ok(FirewallStatus {
        tables,
        total_rules,
        raw_ruleset: raw,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn module_exists() {
        // Requires root for real nft queries
    }
}
