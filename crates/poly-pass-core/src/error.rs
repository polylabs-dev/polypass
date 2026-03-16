use thiserror::Error;

#[derive(Debug, Error)]
pub enum PassError {
    #[error("Crypto: {0}")]
    Crypto(String),
    #[error("Vault key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("Decrypt failed: tag verification")]
    TagVerification,
    #[error("RBAC denied: {0}")]
    AccessDenied(String),
    #[error("Credential not found: {0}")]
    NotFound(String),
    #[error("Vault key rotation: {0}")]
    KeyRotation(String),
    #[error("Import: {0}")]
    Import(String),
    #[error("Breach check: {0}")]
    BreachCheck(String),
    #[error("TOTP: {0}")]
    Totp(String),
    #[error("Graph: {0}")]
    Graph(String),
    #[error("Serialization: {0}")]
    Serialization(String),
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Quota exceeded")]
    QuotaExceeded,
    #[error("Invalid key length")]
    InvalidKeyLength,
}
