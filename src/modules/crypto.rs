use pqc_dilithium::verify;
use sha2::{Digest, Sha256};

pub fn verify_signature(signature: &str, public_key: &str, data: &str) -> bool {
    let pub_key = hex::decode(public_key).ok();
    let sig = hex::decode(signature).ok();
    
    pub_key.zip(sig).map_or(false, |(pk, s)| {
        verify(&s, data.as_bytes(), &pk).is_ok()
    })
}
pub fn sha256_hash(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}