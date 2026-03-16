use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachCheckResult {
    pub credential_id: String,
    pub is_breached: bool,
    pub breach_count: u32,
    pub first_seen: Option<u64>,
    pub last_seen: Option<u64>,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachBatchResult {
    pub checked: u32,
    pub breached: u32,
    pub results: Vec<BreachCheckResult>,
    pub checked_at: u64,
}
