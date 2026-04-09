use crate::crypto::vault_crypto;
use crate::error::PassError;
use crate::graph::vault_registry::VaultRegistry;
use crate::types::vault::*;

pub fn create_credential(
    registry: &mut VaultRegistry,
    user_id: &str,
    url_domain: &str,
    username_hash: &str,
    password_encrypted: &str,
    notes_encrypted: &str,
    totp_seed: &str,
    classification: u8,
    strength: u8,
) -> Result<CredentialNode, PassError> {
    if url_domain.is_empty() {
        return Err(PassError::Graph("domain required".into()));
    }
    if password_encrypted.is_empty() {
        return Err(PassError::Graph("encrypted password required".into()));
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut seed_input = Vec::new();
    seed_input.extend_from_slice(user_id.as_bytes());
    seed_input.extend_from_slice(url_domain.as_bytes());
    seed_input.extend_from_slice(&now_ms.to_le_bytes());
    let cred_id_hash = vault_crypto::sha3_512_truncated_32(&seed_input);
    let credential_id = hex::encode(&cred_id_hash[..16]);

    let cred = CredentialNode {
        credential_id: credential_id.clone(),
        user_id: user_id.to_string(),
        url_domain: url_domain.to_string(),
        username_hash: username_hash.to_string(),
        password_encrypted: password_encrypted.to_string(),
        notes_encrypted: notes_encrypted.to_string(),
        totp_seed: totp_seed.to_string(),
        passkey_credential_id: String::new(),
        classification,
        state: CredentialState::Active as u8,
        created_at: now_ms,
        updated_at: now_ms,
    };

    registry.insert_credential(cred.clone());
    registry.set_strength(&credential_id, strength);

    Ok(cred)
}

pub fn create_folder(
    registry: &mut VaultRegistry,
    user_id: &str,
    name: &str,
    parent_folder_id: &str,
    icon: u16,
) -> Result<FolderNode, PassError> {
    if name.is_empty() {
        return Err(PassError::Graph("folder name required".into()));
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut seed = Vec::new();
    seed.extend_from_slice(user_id.as_bytes());
    seed.extend_from_slice(name.as_bytes());
    seed.extend_from_slice(&now_ms.to_le_bytes());
    let id_hash = vault_crypto::sha3_512_truncated_32(&seed);
    let folder_id = hex::encode(&id_hash[..16]);

    let folder = FolderNode {
        folder_id: folder_id.clone(),
        user_id: user_id.to_string(),
        name: name.to_string(),
        icon,
        parent_folder_id: parent_folder_id.to_string(),
        credential_count: 0,
        created_at: now_ms,
        updated_at: now_ms,
    };

    registry.insert_folder(folder.clone());

    if !parent_folder_id.is_empty() {
        let edge_seed = vault_crypto::sha3_512_truncated_32(
            &[parent_folder_id.as_bytes(), folder_id.as_bytes()].concat(),
        );
        let mut edge_id = [0u8; 16];
        edge_id.copy_from_slice(&edge_seed[..16]);
        registry.connect_contains(
            parent_folder_id,
            &folder_id,
            ContainsEdge {
                edge_id,
                added_at: now_ms,
                position: 0,
            },
        );
    }

    Ok(folder)
}

pub fn update_breach_status(
    registry: &mut VaultRegistry,
    credential_id: &str,
    is_breached: bool,
) -> Result<(), PassError> {
    if registry.get_credential(credential_id).is_none() {
        return Err(PassError::NotFound(credential_id.to_string()));
    }
    registry.set_breach_status(credential_id, if is_breached { 1 } else { 0 });

    if is_breached {
        if let Some(cred) = registry.get_credential_mut(credential_id) {
            cred.state = CredentialState::Compromised as u8;
        }
    }

    Ok(())
}

pub fn record_autofill(registry: &mut VaultRegistry, credential_id: &str) -> Result<(), PassError> {
    if registry.get_credential(credential_id).is_none() {
        return Err(PassError::NotFound(credential_id.to_string()));
    }
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    registry.record_autofill(credential_id, now_ns);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_credential() {
        let mut reg = VaultRegistry::new();
        let cred = create_credential(
            &mut reg, "user1", "github.com", "hash", "enc_pw", "", "", 0, 80,
        )
        .unwrap();
        assert!(!cred.credential_id.is_empty());
        assert_eq!(cred.url_domain, "github.com");
        assert_eq!(reg.credential_count(), 1);
    }

    #[test]
    fn test_create_folder() {
        let mut reg = VaultRegistry::new();
        let folder = create_folder(&mut reg, "user1", "Social", "", 0).unwrap();
        assert!(!folder.folder_id.is_empty());
        assert_eq!(folder.name, "Social");
    }

    #[test]
    fn test_breach_status() {
        let mut reg = VaultRegistry::new();
        let cred = create_credential(
            &mut reg, "user1", "test.com", "h", "pw", "", "", 0, 50,
        )
        .unwrap();

        update_breach_status(&mut reg, &cred.credential_id, true).unwrap();
        let o = reg.overlay(&cred.credential_id).unwrap();
        assert_eq!(o.breach_status, 1);

        let c = reg.get_credential(&cred.credential_id).unwrap();
        assert_eq!(c.state, CredentialState::Compromised as u8);
    }
}
