use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub user_id: String,
    pub action: String,
    pub resource_id: String,
    pub resource_type: String,
    pub ip_hash: String,
    pub device_hash: String,
    pub timestamp: u64,
    pub success: bool,
    pub detail: String,
}
