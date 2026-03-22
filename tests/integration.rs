//! Integration tests for nein — require root and real nftables.
//!
//! Run with: `NEIN_INTEGRATION=1 cargo test --test integration`
//!
//! These tests modify live nftables rules. They flush the ruleset before and
//! after each test. Do NOT run on production systems.

#![cfg(feature = "apply")]

use nein::Firewall;
use nein::builder;
use nein::chain::{Chain, ChainType, Hook, Policy};
use nein::rule::{self, Match, Verdict};
use nein::table::{Family, Table};

fn should_run() -> bool {
    std::env::var("NEIN_INTEGRATION").is_ok()
}

/// Flush rules, run the test body, flush again on completion.
async fn with_clean_nft<F, Fut>(f: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    nein::apply::flush_ruleset().await.expect("pre-flush");
    f().await;
    nein::apply::flush_ruleset().await.expect("post-flush");
}

#[tokio::test]
async fn apply_basic_host_firewall() {
    if !should_run() {
        return;
    }

    with_clean_nft(|| async {
        let fw = builder::basic_host_firewall();
        fw.apply().await.expect("apply basic host firewall");

        let raw = nein::apply::list_ruleset().await.expect("list ruleset");
        assert!(raw.contains("table inet filter"));
        assert!(raw.contains("chain input"));
        assert!(raw.contains("policy drop"));
    })
    .await;
}

#[tokio::test]
async fn apply_and_flush() {
    if !should_run() {
        return;
    }

    with_clean_nft(|| async {
        let fw = builder::basic_host_firewall();
        fw.apply().await.expect("apply");

        let raw = nein::apply::list_ruleset().await.expect("list");
        assert!(raw.contains("table inet filter"));

        nein::apply::flush_ruleset().await.expect("flush");

        let raw = nein::apply::list_ruleset().await.expect("list after flush");
        assert!(!raw.contains("table inet filter"));
    })
    .await;
}

#[tokio::test]
async fn apply_container_bridge() {
    if !should_run() {
        return;
    }

    with_clean_nft(|| async {
        let fw = builder::container_bridge("br-test", "172.99.0.0/16", "lo");
        fw.apply().await.expect("apply container bridge");

        let raw = nein::apply::list_ruleset().await.expect("list");
        assert!(raw.contains("table inet filter"));
        assert!(raw.contains("table ip nat"));
        assert!(raw.contains("masquerade"));
    })
    .await;
}

#[tokio::test]
async fn apply_custom_rules() {
    if !should_run() {
        return;
    }

    with_clean_nft(|| async {
        let mut fw = Firewall::new();
        let mut table = Table::new("nein_test", Family::Inet);
        let mut chain = Chain::base("input", ChainType::Filter, Hook::Input, 0, Policy::Accept);
        chain.add_rule(rule::allow_tcp(9999).comment("integration test rule"));
        table.add_chain(chain);
        fw.add_table(table);

        fw.apply().await.expect("apply custom rules");

        let raw = nein::apply::list_ruleset().await.expect("list");
        assert!(raw.contains("nein_test"));
        assert!(raw.contains("dport 9999"));
    })
    .await;
}

#[cfg(feature = "inspect")]
#[tokio::test]
async fn inspect_status() {
    if !should_run() {
        return;
    }

    with_clean_nft(|| async {
        let fw = builder::basic_host_firewall();
        fw.apply().await.expect("apply");

        let status = nein::inspect::status().await.expect("inspect status");
        assert!(!status.tables.is_empty());
        assert!(status.total_rules > 0);
        assert!(status.raw_ruleset.contains("table"));
    })
    .await;
}

#[tokio::test]
async fn dry_run_does_not_apply() {
    if !should_run() {
        return;
    }

    with_clean_nft(|| async {
        let fw = builder::basic_host_firewall().dry_run(true);
        fw.apply().await.expect("dry-run apply");

        let raw = nein::apply::list_ruleset().await.expect("list");
        // Ruleset should be empty — dry-run doesn't execute
        assert!(!raw.contains("table inet filter"));
    })
    .await;
}

#[tokio::test]
async fn validate_rejects_before_apply() {
    if !should_run() {
        return;
    }

    with_clean_nft(|| async {
        let mut fw = Firewall::new();
        let mut table = Table::new("valid_table", Family::Inet);
        let mut chain = Chain::base("input", ChainType::Filter, Hook::Input, 0, Policy::Accept);
        // Rule with bad address — should fail validation, not reach nft
        chain.add_rule(
            nein::rule::Rule::new(Verdict::Accept).matching(Match::SourceAddr("not valid!".into())),
        );
        table.add_chain(chain);
        fw.add_table(table);

        let result = fw.apply().await;
        assert!(result.is_err());

        // Nothing should have been applied
        let raw = nein::apply::list_ruleset().await.expect("list");
        assert!(!raw.contains("valid_table"));
    })
    .await;
}
