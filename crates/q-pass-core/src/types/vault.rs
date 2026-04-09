use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Classification {
    Personal = 0,
    Sensitive = 1,
    Critical = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CredentialState {
    Active = 0,
    Expired = 1,
    Rotated = 2,
    Compromised = 3,
    Deleted = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialNode {
    pub credential_id: String,
    pub user_id: String,
    pub url_domain: String,
    pub username_hash: String,
    pub password_encrypted: String,
    pub notes_encrypted: String,
    pub totp_seed: String,
    pub passkey_credential_id: String,
    pub classification: u8,
    pub state: u8,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderNode {
    pub folder_id: String,
    pub user_id: String,
    pub name: String,
    pub icon: u16,
    pub parent_folder_id: String,
    pub credential_count: u32,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagNode {
    pub tag_id: String,
    pub user_id: String,
    pub name: String,
    pub color: u32,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainsEdge {
    pub edge_id: [u8; 16],
    pub added_at: u64,
    pub position: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaggedWithEdge {
    pub edge_id: [u8; 16],
    pub tagged_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialHistoryEdge {
    pub edge_id: [u8; 16],
    pub previous_password_hash: [u8; 32],
    pub rotated_at: u64,
    pub rotation_reason: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSnapshot {
    pub user_id: String,
    pub credential_count: usize,
    pub folder_count: usize,
    pub breached_count: usize,
    pub weak_count: usize,
    pub avg_strength: u8,
    pub timestamp: u64,
}
