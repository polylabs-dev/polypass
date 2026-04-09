use serde::{Deserialize, Serialize};

pub const PERM_READ: u64 = 0x01;
pub const PERM_DECRYPT: u64 = 0x02;
pub const PERM_WRITE: u64 = 0x04;
pub const PERM_SHARE: u64 = 0x08;
pub const PERM_DELETE: u64 = 0x10;
pub const PERM_ADMIN: u64 = 0x20;
pub const PERM_AUDIT: u64 = 0x40;
pub const PERM_EXPORT: u64 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RbacRole {
    Viewer = 0,
    User = 1,
    Manager = 2,
    Admin = 3,
    Owner = 4,
    Custom = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RbacDecision {
    Allow = 0,
    Deny = 1,
    Escalate = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleNode {
    pub role_id: String,
    pub org_id: String,
    pub name: String,
    pub description: String,
    pub permission_mask: u64,
    pub inherits_from: Vec<String>,
    pub max_vault_access: u32,
    pub max_credential_access: u32,
    pub created_by: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalNode {
    pub principal_id: String,
    pub org_id: String,
    pub display_name_hash: String,
    pub email_hash: String,
    pub signing_pubkey: String,
    pub active: bool,
    pub mfa_required: bool,
    pub last_auth_at: u64,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgNode {
    pub org_id: String,
    pub name: String,
    pub parent_org_id: String,
    pub policy_mask: u64,
    pub max_members: u32,
    pub member_count: u32,
    pub vault_count: u32,
    pub sso_provider: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HasRoleEdge {
    pub edge_id: [u8; 16],
    pub role_id: String,
    pub granted_at: u64,
    pub granted_by: String,
    pub expires_at: u64,
    pub scope_vault_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleInheritsEdge {
    pub edge_id: [u8; 16],
    pub priority: u8,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgMemberEdge {
    pub edge_id: [u8; 16],
    pub joined_at: u64,
    pub department: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacAuditEntry {
    pub entry_id: String,
    pub principal_id: String,
    pub action: String,
    pub resource_id: String,
    pub resource_type: String,
    pub decision: u8,
    pub effective_mask: u64,
    pub reason: String,
    pub timestamp: u64,
}

impl RbacRole {
    pub fn default_mask(&self) -> u64 {
        match self {
            RbacRole::Viewer => PERM_READ,
            RbacRole::User => PERM_READ | PERM_DECRYPT | PERM_WRITE,
            RbacRole::Manager => PERM_READ | PERM_DECRYPT | PERM_WRITE | PERM_SHARE | PERM_ADMIN,
            RbacRole::Admin => PERM_READ | PERM_DECRYPT | PERM_WRITE | PERM_SHARE | PERM_DELETE | PERM_ADMIN | PERM_AUDIT,
            RbacRole::Owner => 0xFF,
            RbacRole::Custom => 0,
        }
    }
}
