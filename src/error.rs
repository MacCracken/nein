//! Error types for nein.

use thiserror::Error;

/// Errors returned by nein operations.
#[derive(Debug, Error)]
pub enum NeinError {
    /// The `nft` command failed with an error message.
    #[error("nft command failed: {0}")]
    NftFailed(String),

    /// A rule, match, or verdict contains invalid input.
    #[error("invalid rule: {0}")]
    InvalidRule(String),

    /// A referenced table was not found.
    #[error("table not found: {0}")]
    TableNotFound(String),

    /// A referenced chain was not found.
    #[error("chain not found: {0}")]
    ChainNotFound(String),

    /// The `nft` command requires root or `CAP_NET_ADMIN`.
    #[error("permission denied: nft requires root or CAP_NET_ADMIN")]
    PermissionDenied,

    /// A configuration or input could not be parsed.
    #[error("parse error: {0}")]
    Parse(String),

    /// An underlying I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
