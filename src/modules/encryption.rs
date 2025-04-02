use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};

pub async fn decrypt_message(
    encrypted_buffer: &[u8],
    key_buffer: &[u8],
) -> Result<Vec<u8>, String> {
    if encrypted_buffer.len() < 12 {
        return Err("Encrypted buffer is too short".to_string());
    }
    
    let iv = &encrypted_buffer[0..12];
    let cipher_text_buffer = &encrypted_buffer[12..];

    let key = Key::<Aes256Gcm>::from_slice(key_buffer);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(iv);

    match cipher.decrypt(nonce, cipher_text_buffer) {
        Ok(result) => Ok(result),
        Err(e) => Err(format!("Decryption failed: {:?}", e)),
    }
}