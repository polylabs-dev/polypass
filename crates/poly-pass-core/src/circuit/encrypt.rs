use crate::crypto::vault_crypto;
use crate::error::PassError;
use crate::types::encrypt::{EncryptedCredential, VaultKeyRotation};
use crate::types::VaultKey;

pub fn encrypt_credential(
    vault_key: &VaultKey,
    credential_id: &[u8; 16],
    plaintext: &[u8],
    classification: u8,
    user_id: &[u8],
) -> Result<EncryptedCredential, PassError> {
    if vault_key == &[0u8; 32] {
        return Err(PassError::Crypto("vault key is zero".into()));
    }
    if plaintext.is_empty() || plaintext.len() > 65536 {
        return Err(PassError::Crypto("plaintext out of bounds".into()));
    }
    if classification > 2 {
        return Err(PassError::Crypto("invalid classification".into()));
    }

    let cred_key = vault_crypto::derive_credential_key(vault_key, credential_id)?;
    let nonce = vault_crypto::generate_nonce();
    let aad = vault_crypto::build_credential_aad(credential_id, classification, user_id);

    let (ciphertext, tag) = vault_crypto::aes_gcm_encrypt(&cred_key, &nonce, plaintext, &aad)?;

    Ok(EncryptedCredential {
        credential_id: *credential_id,
        nonce,
        ciphertext,
        aad,
        tag,
    })
}

pub fn decrypt_credential(
    vault_key: &VaultKey,
    encrypted: &EncryptedCredential,
    _user_id: &[u8],
) -> Result<Vec<u8>, PassError> {
    if vault_key == &[0u8; 32] {
        return Err(PassError::Crypto("vault key is zero".into()));
    }

    let cred_key = vault_crypto::derive_credential_key(vault_key, &encrypted.credential_id)?;

    vault_crypto::aes_gcm_decrypt(
        &cred_key,
        &encrypted.nonce,
        &encrypted.ciphertext,
        &encrypted.aad,
        &encrypted.tag,
    )
}

pub fn rotate_vault_key(
    old_vault_key: &VaultKey,
    new_master_seed: &[u8; 32],
    new_epoch: u32,
    encrypted_credentials: &[EncryptedCredential],
    user_id: &[u8],
) -> Result<(VaultKeyRotation, Vec<EncryptedCredential>), PassError> {
    let new_vault_key = vault_crypto::derive_vault_key(new_master_seed, new_epoch)?;

    let old_hash = vault_crypto::sha3_512_truncated_32(old_vault_key);
    let new_hash = vault_crypto::sha3_512_truncated_32(&new_vault_key);

    let mut rewrapped = Vec::with_capacity(encrypted_credentials.len());

    for enc in encrypted_credentials {
        let plaintext = decrypt_credential(old_vault_key, enc, user_id)?;
        let re_encrypted = encrypt_credential(
            &new_vault_key,
            &enc.credential_id,
            &plaintext,
            0,
            user_id,
        )?;
        rewrapped.push(re_encrypted);
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let rotation = VaultKeyRotation {
        old_key_hash: old_hash,
        new_key_hash: new_hash,
        rewrapped_count: rewrapped.len() as u32,
        rotated_at: now_ms,
    };

    Ok((rotation, rewrapped))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let vk = [0xAAu8; 32];
        let cid = [0x01u8; 16];
        let uid = b"user1";
        let plaintext = b"password123";

        let enc = encrypt_credential(&vk, &cid, plaintext, 0, uid).unwrap();
        assert!(!enc.ciphertext.is_empty());
        assert_eq!(enc.credential_id, cid);
        assert_ne!(enc.nonce, [0u8; 12]);

        let pt = decrypt_credential(&vk, &enc, uid).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_encrypt_zero_key_fails() {
        let result = encrypt_credential(&[0u8; 32], &[1u8; 16], b"test", 0, b"u");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_empty_plaintext_fails() {
        let result = encrypt_credential(&[0xAAu8; 32], &[1u8; 16], b"", 0, b"u");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let vk = [0xAAu8; 32];
        let wrong = [0xBBu8; 32];
        let enc = encrypt_credential(&vk, &[1u8; 16], b"secret", 0, b"u").unwrap();
        let result = decrypt_credential(&wrong, &enc, b"u");
        assert!(result.is_err());
    }

    #[test]
    fn test_key_rotation() {
        let old_key = [0xAAu8; 32];
        let new_seed = [0xBBu8; 32];
        let uid = b"user1";
        let cid = [0x01u8; 16];

        let enc = encrypt_credential(&old_key, &cid, b"secret", 0, uid).unwrap();

        let (rotation, rewrapped) =
            rotate_vault_key(&old_key, &new_seed, 1, &[enc], uid).unwrap();

        assert_eq!(rotation.rewrapped_count, 1);
        assert_ne!(rotation.old_key_hash, rotation.new_key_hash);

        let new_key = vault_crypto::derive_vault_key(&new_seed, 1).unwrap();
        let pt = decrypt_credential(&new_key, &rewrapped[0], uid).unwrap();
        assert_eq!(pt, b"secret");
    }
}
