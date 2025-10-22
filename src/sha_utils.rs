use sha2::{Digest, Sha256};

pub fn sha256(s: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(s);
    hasher.finalize().to_vec()
}
