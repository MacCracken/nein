//! Apply nftables rules via the nft command.

use crate::error::NeinError;

/// Apply a ruleset string via `nft -f -`.
pub async fn apply_ruleset(ruleset: &str) -> Result<(), NeinError> {
    use tokio::process::Command;

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                NeinError::PermissionDenied
            } else {
                NeinError::NftFailed(e.to_string())
            }
        })?;

    // Write the ruleset to nft's stdin
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(ruleset.as_bytes()).await
            .map_err(|e| NeinError::NftFailed(format!("failed to write to nft stdin: {e}")))?;
        // Drop stdin to close the pipe so nft reads EOF
    }

    let output = child.wait_with_output()
        .await
        .map_err(|e| NeinError::NftFailed(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NeinError::NftFailed(stderr.to_string()));
    }

    Ok(())
}

/// Flush all nftables rules.
pub async fn flush_ruleset() -> Result<(), NeinError> {
    apply_ruleset("flush ruleset\n").await
}

/// List current ruleset (for inspection).
pub async fn list_ruleset() -> Result<String, NeinError> {
    use tokio::process::Command;

    let output = Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .await
        .map_err(|e| NeinError::NftFailed(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NeinError::NftFailed(stderr.to_string()));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(test)]
mod tests {
    // apply tests require root + nft, so we test rendering instead
    // See integration tests for real nft invocation tests

    #[test]
    fn module_exists() {
        // Compilation check
    }
}
