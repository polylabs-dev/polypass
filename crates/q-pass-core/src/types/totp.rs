use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TotpAlgorithm {
    HmacSha1 = 0,
    HmacSha256 = 1,
    HmacSha512 = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TotpConfig {
    #[zeroize(skip)]
    pub credential_id: String,
    pub secret: Vec<u8>,
    #[zeroize(skip)]
    pub algorithm: u8,
    #[zeroize(skip)]
    pub digits: u8,
    #[zeroize(skip)]
    pub period: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpCode {
    pub code: String,
    pub valid_from: u64,
    pub valid_until: u64,
    pub remaining_seconds: u32,
}
