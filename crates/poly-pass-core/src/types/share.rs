use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ShareState {
    Pending = 0,
    Accepted = 1,
    Revoked = 2,
    Expired = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedVaultNode {
    pub vault_id: String,
    pub name: String,
    pub owner_id: String,
    pub member_count: u32,
    pub credential_count: u32,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ShareInvite {
    pub invite_id: String,
    pub from_user_id: String,
    pub to_user_id: String,
    pub credential_id: String,
    #[zeroize(skip)]
    pub rewrapped_key: Vec<u8>,
    pub permission_mask: u64,
    pub expires_at: u64,
    #[zeroize(skip)]
    pub state: u8,
    #[zeroize(skip)]
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareMemberEdge {
    pub edge_id: [u8; 16],
    pub permission_mask: u64,
    pub joined_at: u64,
    pub invited_by: String,
}
