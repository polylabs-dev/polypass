pub mod vault;
pub mod encrypt;
pub mod rbac;
pub mod share;
pub mod audit;
pub mod breach;
pub mod totp;
pub mod import;

pub use vault::*;
pub use encrypt::*;
pub use rbac::*;
pub use share::*;
pub use audit::*;

pub type VaultKey = [u8; 32];
pub type CredentialKey = [u8; 32];
pub type Nonce = [u8; 12];
pub type UserId = Vec<u8>;
