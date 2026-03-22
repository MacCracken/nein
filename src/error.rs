use thiserror::Error;

#[derive(Debug, Error)]
pub enum NeinError {
    #[error("nft command failed: {0}")]
    NftFailed(String),

    #[error("invalid rule: {0}")]
    InvalidRule(String),

    #[error("table not found: {0}")]
    TableNotFound(String),

    #[error("chain not found: {0}")]
    ChainNotFound(String),

    #[error("permission denied: nft requires root or CAP_NET_ADMIN")]
    PermissionDenied,

    #[error("parse error: {0}")]
    Parse(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
