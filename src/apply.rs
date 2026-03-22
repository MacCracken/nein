//! Apply nftables rules via the nft command.
//!
//! Provides both batch operations (`apply_ruleset`, `flush_ruleset`) and
//! incremental operations (`add_rule`, `delete_rule`) for dynamic rule
//! management during agent lifecycle events.

use crate::error::NeinError;

/// Apply a ruleset string via `nft -f -`.
pub async fn apply_ruleset(ruleset: &str) -> Result<(), NeinError> {
    run_nft_stdin(ruleset).await
}

/// Flush all nftables rules.
pub async fn flush_ruleset() -> Result<(), NeinError> {
    run_nft_stdin("flush ruleset\n").await
}

/// Flush a specific table.
pub async fn flush_table(family: &str, table: &str) -> Result<(), NeinError> {
    run_nft_stdin(&format!("flush table {family} {table}\n")).await
}

/// Delete a specific table.
pub async fn delete_table(family: &str, table: &str) -> Result<(), NeinError> {
    run_nft_stdin(&format!("delete table {family} {table}\n")).await
}

/// Add an individual rule to an existing chain.
///
/// The rule string should be the nftables rule body (matches + verdict),
/// without the leading `add rule` prefix.
pub async fn add_rule(family: &str, table: &str, chain: &str, rule: &str) -> Result<(), NeinError> {
    run_nft_stdin(&format!("add rule {family} {table} {chain} {rule}\n")).await
}

/// Delete a rule by its handle number.
///
/// Handles can be obtained from [`list_ruleset_with_handles`].
pub async fn delete_rule(
    family: &str,
    table: &str,
    chain: &str,
    handle: u64,
) -> Result<(), NeinError> {
    run_nft_stdin(&format!(
        "delete rule {family} {table} {chain} handle {handle}\n"
    ))
    .await
}

/// List current ruleset (for inspection).
pub async fn list_ruleset() -> Result<String, NeinError> {
    run_nft_cmd(&["list", "ruleset"]).await
}

/// List current ruleset with rule handles (`nft -a list ruleset`).
///
/// Each rule line will include `# handle N` at the end.
pub async fn list_ruleset_with_handles() -> Result<String, NeinError> {
    run_nft_cmd(&["-a", "list", "ruleset"]).await
}

/// A rule handle found in the live ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHandle {
    pub table: String,
    pub chain: String,
    pub handle: u64,
    pub rule_text: String,
}

/// Find rules by comment prefix in the live ruleset.
///
/// Parses `nft -a list ruleset` output and returns handles for rules
/// whose text contains the given comment prefix. Useful for removing
/// all rules associated with a specific agent.
pub async fn find_rules_by_comment(
    family: &str,
    table: &str,
    comment_prefix: &str,
) -> Result<Vec<RuleHandle>, NeinError> {
    let raw = run_nft_cmd(&["-a", "list", "table", family, table]).await?;
    Ok(parse_rules_with_handles(&raw, comment_prefix))
}

/// Parse `nft -a` output, extracting rules matching a comment prefix.
///
/// This is a pure function for testability.
pub fn parse_rules_with_handles(nft_output: &str, comment_prefix: &str) -> Vec<RuleHandle> {
    let mut results = vec![];
    let mut current_table = String::new();
    let mut current_chain = String::new();

    for line in nft_output.lines() {
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix("table ") {
            current_table = rest.trim_end_matches(" {").to_string();
        } else if let Some(rest) = trimmed.strip_prefix("chain ") {
            current_chain = rest.trim_end_matches(" {").to_string();
        } else if trimmed.contains(&format!("comment \"{}", comment_prefix))
            && trimmed.contains("# handle ")
            && let Some(handle) = extract_handle(trimmed)
        {
            let rule_text = trimmed
                .split(" # handle ")
                .next()
                .unwrap_or(trimmed)
                .to_string();
            results.push(RuleHandle {
                table: current_table.clone(),
                chain: current_chain.clone(),
                handle,
                rule_text,
            });
        }
    }

    results
}

fn extract_handle(line: &str) -> Option<u64> {
    line.rsplit("# handle ").next()?.trim().parse().ok()
}

/// Run an nft command with stdin input.
async fn run_nft_stdin(input: &str) -> Result<(), NeinError> {
    use tokio::process::Command;

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(map_spawn_error)?;

    let write_err = if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(input.as_bytes()).await.err()
    } else {
        None
    };

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| NeinError::NftFailed(e.to_string()))?;

    if let Some(e) = write_err
        && output.status.success()
    {
        return Err(NeinError::NftFailed(format!(
            "failed to write to nft stdin: {e}"
        )));
    }

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NeinError::NftFailed(stderr.to_string()));
    }

    Ok(())
}

/// Run an nft command with arguments and return stdout.
async fn run_nft_cmd(args: &[&str]) -> Result<String, NeinError> {
    use tokio::process::Command;

    let output = Command::new("nft")
        .args(args)
        .output()
        .await
        .map_err(map_spawn_error)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NeinError::NftFailed(stderr.to_string()));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn map_spawn_error(e: std::io::Error) -> NeinError {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        NeinError::PermissionDenied
    } else {
        NeinError::NftFailed(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_handles_basic() {
        let output = r#"table inet nein_agents {
    chain web_in {
        ct state { established, related } accept # handle 4
        tcp dport 80 accept comment "web inbound tcp:80" # handle 5
        drop comment "web default deny inbound" # handle 6
    }
    chain web_out {
        ct state { established, related } accept # handle 7
        drop comment "web default deny outbound" # handle 8
    }
}"#;

        let results = parse_rules_with_handles(output, "web ");
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].handle, 5);
        assert_eq!(results[0].chain, "web_in");
        assert!(results[0].rule_text.contains("dport 80"));
        assert_eq!(results[1].handle, 6);
        assert_eq!(results[2].handle, 8);
    }

    #[test]
    fn parse_handles_no_match() {
        let output = r#"table inet test {
    chain input {
        tcp dport 22 accept comment "ssh" # handle 3
    }
}"#;
        let results = parse_rules_with_handles(output, "web ");
        assert!(results.is_empty());
    }

    #[test]
    fn parse_handles_empty() {
        let results = parse_rules_with_handles("", "anything");
        assert!(results.is_empty());
    }

    #[test]
    fn extract_handle_works() {
        assert_eq!(extract_handle("tcp dport 80 accept # handle 42"), Some(42));
        assert_eq!(extract_handle("no handle here"), None);
    }

    #[test]
    fn parse_handles_multiple_tables() {
        let output = r#"table inet t1 {
    chain c1 {
        tcp dport 80 accept comment "agent-1 inbound tcp:80" # handle 10
    }
}
table inet t2 {
    chain c2 {
        tcp dport 443 accept comment "agent-1 outbound tcp:443" # handle 20
    }
}"#;
        let results = parse_rules_with_handles(output, "agent-1 ");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].table, "inet t1");
        assert_eq!(results[0].handle, 10);
        assert_eq!(results[1].table, "inet t2");
        assert_eq!(results[1].handle, 20);
    }

    #[test]
    fn extract_handle_large() {
        assert_eq!(
            extract_handle("rule text # handle 18446744073709551615"),
            Some(u64::MAX)
        );
    }

    #[test]
    fn extract_handle_zero() {
        assert_eq!(extract_handle("rule text # handle 0"), Some(0));
    }

    #[test]
    fn extract_handle_malformed() {
        assert_eq!(extract_handle("# handle notanumber"), None);
        assert_eq!(extract_handle("# handle "), None);
        assert_eq!(extract_handle("# handle -1"), None);
    }

    #[test]
    fn parse_handles_extra_whitespace() {
        let output = "table inet t1 {\n    chain c1 {\n        tcp dport 80 accept comment \"agent-1 test\" # handle 5\n    }\n}";
        let results = parse_rules_with_handles(output, "agent-1 ");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].handle, 5);
    }

    #[test]
    fn parse_handles_rule_text_extraction() {
        let output = r#"table inet t {
    chain c {
        ip saddr 10.0.0.0/8 tcp dport 443 accept comment "agent-x outbound" # handle 99
    }
}"#;
        let results = parse_rules_with_handles(output, "agent-x ");
        assert_eq!(results.len(), 1);
        assert!(results[0].rule_text.contains("ip saddr 10.0.0.0/8"));
        assert!(!results[0].rule_text.contains("# handle"));
    }

    #[test]
    fn rule_handle_eq() {
        let a = RuleHandle {
            table: "t".into(),
            chain: "c".into(),
            handle: 1,
            rule_text: "r".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
