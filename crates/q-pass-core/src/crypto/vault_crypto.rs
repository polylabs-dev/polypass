use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce as AesNonce,
};
use hkdf::Hkdf;
use sha3::{Digest, Sha3_512};
use zeroize::Zeroize;

use crate::error::PassError;
use crate::types::{CredentialKey, Nonce, VaultKey};

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha3_512_truncated_32(data: &[u8]) -> [u8; 32] {
    let full = sha3_512(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

pub fn hkdf_sha3(ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, PassError> {
    let hk = Hkdf::<Sha3_512>::new(None, ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm)
        .map_err(|e| PassError::KeyDerivation(e.to_string()))?;
    Ok(okm)
}

pub fn derive_credential_key(
    vault_key: &VaultKey,
    credential_id: &[u8; 16],
) -> Result<CredentialKey, PassError> {
    let mut info = Vec::with_capacity(9 + 16);
    info.extend_from_slice(b"cred-key:");
    info.extend_from_slice(credential_id);
    let okm = hkdf_sha3(vault_key, &info, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    Ok(key)
}

pub fn derive_vault_key(master_seed: &[u8; 32], vault_epoch: u32) -> Result<VaultKey, PassError> {
    let info = format!("vault-key:epoch:{}", vault_epoch);
    let okm = hkdf_sha3(master_seed, info.as_bytes(), 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    Ok(key)
}

pub fn aes_gcm_encrypt(
    key: &[u8; 32],
    nonce: &Nonce,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), PassError> {
    let cipher = Aes256Gcm::new(key.into());
    let aes_nonce = AesNonce::from_slice(nonce);

    let ciphertext = cipher
        .encrypt(aes_nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
        .map_err(|e| PassError::Crypto(e.to_string()))?;

    if ciphertext.len() < 16 {
        return Err(PassError::Crypto("ciphertext too short".into()));
    }
    let tag_start = ciphertext.len() - 16;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ciphertext[tag_start..]);
    let ct = ciphertext[..tag_start].to_vec();

    Ok((ct, tag))
}

pub fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce: &Nonce,
    ciphertext: &[u8],
    aad: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, PassError> {
    let cipher = Aes256Gcm::new(key.into());
    let aes_nonce = AesNonce::from_slice(nonce);

    let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + 16);
    ct_with_tag.extend_from_slice(ciphertext);
    ct_with_tag.extend_from_slice(tag);

    let mut plaintext = cipher
        .decrypt(aes_nonce, aes_gcm::aead::Payload { msg: &ct_with_tag, aad })
        .map_err(|_| PassError::TagVerification)?;

    let result = plaintext.clone();
    plaintext.zeroize();
    Ok(result)
}

pub fn generate_nonce() -> Nonce {
    let mut nonce = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

pub fn build_credential_aad(credential_id: &[u8; 16], classification: u8, user_id: &[u8]) -> Vec<u8> {
    let user_hash = sha3_512_truncated_32(user_id);
    let mut aad = Vec::with_capacity(16 + 1 + 32);
    aad.extend_from_slice(credential_id);
    aad.push(classification);
    aad.extend_from_slice(&user_hash);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0xAAu8; 32];
        let nonce = generate_nonce();
        let plaintext = b"password123";
        let aad = b"test-aad";

        let (ct, tag) = aes_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let pt = aes_gcm_decrypt(&key, &nonce, &ct, aad, &tag).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_derive_credential_key() {
        let vault_key = [0xBBu8; 32];
        let cred_id = [0x01u8; 16];
        let key = derive_credential_key(&vault_key, &cred_id).unwrap();
        assert_ne!(key, [0u8; 32]);
        assert_ne!(key, vault_key);
    }

    #[test]
    fn test_derive_vault_key_deterministic() {
        let seed = [0xCCu8; 32];
        let k1 = derive_vault_key(&seed, 0).unwrap();
        let k2 = derive_vault_key(&seed, 0).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_vault_key_epoch_differs() {
        let seed = [0xCCu8; 32];
        let k0 = derive_vault_key(&seed, 0).unwrap();
        let k1 = derive_vault_key(&seed, 1).unwrap();
        assert_ne!(k0, k1);
    }

    #[test]
    fn test_sha3_512() {
        let h = sha3_512(b"hello");
        assert_ne!(h, [0u8; 64]);
    }

    #[test]
    fn test_sha3_512_truncated_32() {
        let h = sha3_512_truncated_32(b"hello");
        assert_ne!(h, [0u8; 32]);
        let full = sha3_512(b"hello");
        assert_eq!(h, full[..32]);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = [0xAAu8; 32];
        let nonce = generate_nonce();
        let plaintext = b"secret";
        let aad = b"aad";

        let (ct, tag) = aes_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();

        let wrong_key = [0xBBu8; 32];
        let result = aes_gcm_decrypt(&wrong_key, &nonce, &ct, aad, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_credential_aad_deterministic() {
        let cred_id = [0x01u8; 16];
        let user_id = b"user@polyqlabs.dev";
        let aad1 = build_credential_aad(&cred_id, 3, user_id);
        let aad2 = build_credential_aad(&cred_id, 3, user_id);
        assert_eq!(aad1, aad2);
        assert_eq!(aad1.len(), 16 + 1 + 32);
    }

    #[test]
    fn test_different_credential_ids_yield_different_keys() {
        let vault_key = [0xBBu8; 32];
        let id1 = [0x01u8; 16];
        let id2 = [0x02u8; 16];
        let k1 = derive_credential_key(&vault_key, &id1).unwrap();
        let k2 = derive_credential_key(&vault_key, &id2).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_vault_key_rotation_preserves_decryption() {
        let seed = [0xCCu8; 32];
        let nonce = generate_nonce();
        let plaintext = b"critical-credential-data";
        let aad = b"vault-epoch-0";

        let vk0 = derive_vault_key(&seed, 0).unwrap();
        let (ct, tag) = aes_gcm_encrypt(&vk0, &nonce, plaintext, aad).unwrap();

        let vk0_again = derive_vault_key(&seed, 0).unwrap();
        let pt = aes_gcm_decrypt(&vk0_again, &nonce, &ct, aad, &tag).unwrap();
        assert_eq!(pt, plaintext);

        let vk1 = derive_vault_key(&seed, 1).unwrap();
        let result = aes_gcm_decrypt(&vk1, &nonce, &ct, aad, &tag);
        assert!(result.is_err(), "epoch 1 key must not decrypt epoch 0 data");
    }

    #[test]
    fn test_hkdf_sha3_output_length() {
        let ikm = [0xABu8; 32];
        let out16 = hkdf_sha3(&ikm, b"16-byte", 16).unwrap();
        assert_eq!(out16.len(), 16);
        let out64 = hkdf_sha3(&ikm, b"64-byte", 64).unwrap();
        assert_eq!(out64.len(), 64);
    }

    #[test]
    fn test_generate_nonce_unique() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2, "sequential nonces must differ");
    }
}
