use std::collections::HashMap;

use crate::types::vault::*;

#[derive(Debug, Default, Clone)]
pub struct OverlayData {
    pub breach_status: u8,
    pub password_age_days: u32,
    pub strength_score: u8,
    pub last_used_ns: u64,
    pub autofill_count: u64,
}

pub struct VaultRegistry {
    credentials: HashMap<String, CredentialNode>,
    folders: HashMap<String, FolderNode>,
    tags: HashMap<String, TagNode>,
    contains_edges: Vec<(String, String, ContainsEdge)>,
    tagged_edges: Vec<(String, String, TaggedWithEdge)>,
    history_edges: Vec<(String, String, CredentialHistoryEdge)>,
    overlays: HashMap<String, OverlayData>,
}

impl VaultRegistry {
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
            folders: HashMap::new(),
            tags: HashMap::new(),
            contains_edges: Vec::new(),
            tagged_edges: Vec::new(),
            history_edges: Vec::new(),
            overlays: HashMap::new(),
        }
    }

    pub fn insert_credential(&mut self, cred: CredentialNode) {
        let id = cred.credential_id.clone();
        self.overlays.entry(id.clone()).or_default();
        self.credentials.insert(id, cred);
    }

    pub fn get_credential(&self, id: &str) -> Option<&CredentialNode> {
        self.credentials.get(id)
    }

    pub fn get_credential_mut(&mut self, id: &str) -> Option<&mut CredentialNode> {
        self.credentials.get_mut(id)
    }

    pub fn remove_credential(&mut self, id: &str) -> Option<CredentialNode> {
        self.overlays.remove(id);
        self.credentials.remove(id)
    }

    pub fn credentials_for_user(&self, user_id: &str) -> Vec<&CredentialNode> {
        self.credentials
            .values()
            .filter(|c| c.user_id == user_id)
            .collect()
    }

    pub fn insert_folder(&mut self, folder: FolderNode) {
        self.folders.insert(folder.folder_id.clone(), folder);
    }

    pub fn get_folder(&self, id: &str) -> Option<&FolderNode> {
        self.folders.get(id)
    }

    pub fn folders_for_user(&self, user_id: &str) -> Vec<&FolderNode> {
        self.folders
            .values()
            .filter(|f| f.user_id == user_id)
            .collect()
    }

    pub fn insert_tag(&mut self, tag: TagNode) {
        self.tags.insert(tag.tag_id.clone(), tag);
    }

    pub fn connect_contains(&mut self, from: &str, to: &str, edge: ContainsEdge) {
        self.contains_edges.push((from.to_string(), to.to_string(), edge));
    }

    pub fn connect_tagged(&mut self, from: &str, to: &str, edge: TaggedWithEdge) {
        self.tagged_edges.push((from.to_string(), to.to_string(), edge));
    }

    pub fn add_history(&mut self, cred_id: &str, edge: CredentialHistoryEdge) {
        self.history_edges
            .push((cred_id.to_string(), cred_id.to_string(), edge));
    }

    pub fn overlay(&self, id: &str) -> Option<&OverlayData> {
        self.overlays.get(id)
    }

    pub fn overlay_mut(&mut self, id: &str) -> Option<&mut OverlayData> {
        self.overlays.get_mut(id)
    }

    pub fn set_breach_status(&mut self, id: &str, status: u8) {
        if let Some(o) = self.overlays.get_mut(id) {
            o.breach_status = status;
        }
    }

    pub fn set_strength(&mut self, id: &str, score: u8) {
        if let Some(o) = self.overlays.get_mut(id) {
            o.strength_score = score;
        }
    }

    pub fn record_autofill(&mut self, id: &str, now_ns: u64) {
        if let Some(o) = self.overlays.get_mut(id) {
            o.autofill_count += 1;
            o.last_used_ns = now_ns;
        }
    }

    pub fn snapshot(&self, user_id: &str) -> VaultSnapshot {
        let creds = self.credentials_for_user(user_id);
        let folders = self.folders_for_user(user_id);

        let mut breached = 0;
        let mut weak = 0;
        let mut total_strength: u64 = 0;

        for c in &creds {
            if let Some(o) = self.overlays.get(&c.credential_id) {
                if o.breach_status > 0 {
                    breached += 1;
                }
                if o.strength_score < 50 {
                    weak += 1;
                }
                total_strength += o.strength_score as u64;
            }
        }

        let avg_strength = if !creds.is_empty() {
            (total_strength / creds.len() as u64) as u8
        } else {
            0
        };

        VaultSnapshot {
            user_id: user_id.to_string(),
            credential_count: creds.len(),
            folder_count: folders.len(),
            breached_count: breached,
            weak_count: weak,
            avg_strength,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }

    pub fn credential_count(&self) -> usize {
        self.credentials.len()
    }
}

impl Default for VaultRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cred(id: &str, user: &str, domain: &str) -> CredentialNode {
        CredentialNode {
            credential_id: id.to_string(),
            user_id: user.to_string(),
            url_domain: domain.to_string(),
            username_hash: "hash".to_string(),
            password_encrypted: "enc".to_string(),
            notes_encrypted: String::new(),
            totp_seed: String::new(),
            passkey_credential_id: String::new(),
            classification: 0,
            state: 0,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    #[test]
    fn test_insert_and_get() {
        let mut reg = VaultRegistry::new();
        reg.insert_credential(make_cred("c1", "u1", "github.com"));
        assert!(reg.get_credential("c1").is_some());
        assert_eq!(reg.credential_count(), 1);
    }

    #[test]
    fn test_credentials_for_user() {
        let mut reg = VaultRegistry::new();
        reg.insert_credential(make_cred("c1", "u1", "github.com"));
        reg.insert_credential(make_cred("c2", "u1", "google.com"));
        reg.insert_credential(make_cred("c3", "u2", "gitlab.com"));
        assert_eq!(reg.credentials_for_user("u1").len(), 2);
        assert_eq!(reg.credentials_for_user("u2").len(), 1);
    }

    #[test]
    fn test_overlay_operations() {
        let mut reg = VaultRegistry::new();
        reg.insert_credential(make_cred("c1", "u1", "github.com"));
        reg.set_strength("c1", 85);
        reg.set_breach_status("c1", 1);
        reg.record_autofill("c1", 999);

        let o = reg.overlay("c1").unwrap();
        assert_eq!(o.strength_score, 85);
        assert_eq!(o.breach_status, 1);
        assert_eq!(o.autofill_count, 1);
    }

    #[test]
    fn test_snapshot() {
        let mut reg = VaultRegistry::new();
        reg.insert_credential(make_cred("c1", "u1", "a.com"));
        reg.set_strength("c1", 80);
        reg.insert_credential(make_cred("c2", "u1", "b.com"));
        reg.set_strength("c2", 40);
        reg.set_breach_status("c2", 1);

        let snap = reg.snapshot("u1");
        assert_eq!(snap.credential_count, 2);
        assert_eq!(snap.breached_count, 1);
        assert_eq!(snap.weak_count, 1);
        assert_eq!(snap.avg_strength, 60);
    }
}
