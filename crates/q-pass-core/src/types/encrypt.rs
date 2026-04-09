use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedCredential {
    pub credential_id: [u8; 16],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub aad: Vec<u8>,
    pub tag: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct WrappedVaultKey {
    pub kem_ciphertext: Vec<u8>,
    pub wrapped_key: Vec<u8>,
    pub nonce: [u8; 12],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultKeyRotation {
    pub old_key_hash: [u8; 32],
    pub new_key_hash: [u8; 32],
    pub rewrapped_count: u32,
    pub rotated_at: u64,
}
