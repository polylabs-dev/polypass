use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn poly_pass_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[wasm_bindgen]
pub fn derive_vault_key_hex(master_seed: &[u8], epoch: u32) -> Result<String, JsValue> {
    if master_seed.len() != 32 {
        return Err(JsValue::from_str("master_seed must be 32 bytes"));
    }
    let seed: &[u8; 32] = master_seed.try_into().unwrap();
    match poly_pass_core::crypto::derive_vault_key(seed, epoch) {
        Ok(key) => Ok(hex::encode(key)),
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

#[wasm_bindgen]
pub fn encrypt_credential(
    vault_key: &[u8],
    credential_id: &[u8],
    plaintext: &[u8],
    user_id: &[u8],
    classification: u8,
) -> Result<JsValue, JsValue> {
    if vault_key.len() != 32 {
        return Err(JsValue::from_str("vault_key must be 32 bytes"));
    }
    if credential_id.len() != 16 {
        return Err(JsValue::from_str("credential_id must be 16 bytes"));
    }

    let vk: &[u8; 32] = vault_key.try_into().unwrap();
    let cid: &[u8; 16] = credential_id.try_into().unwrap();

    let cred_key = poly_pass_core::crypto::derive_credential_key(vk, cid)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let nonce = poly_pass_core::crypto::generate_nonce();
    let aad = poly_pass_core::crypto::build_credential_aad(cid, classification, user_id);

    let (ct, tag) = poly_pass_core::crypto::aes_gcm_encrypt(&cred_key, &nonce, plaintext, &aad)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = serde_json::json!({
        "ciphertext": hex::encode(&ct),
        "tag": hex::encode(tag),
        "nonce": hex::encode(nonce),
    });

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn sha3_512_hex(data: &[u8]) -> String {
    hex::encode(poly_pass_core::crypto::sha3_512(data))
}
