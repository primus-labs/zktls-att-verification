use sha2::{Digest, Sha256};

pub fn sha256(s: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(s);
    hasher.finalize().to_vec()
}

pub fn sha256_with_salt(s: &str, salt: &str) -> anyhow::Result<Vec<u8>> {
    let salt = salt.strip_prefix("0x").unwrap_or(salt);
    let salt = hex::decode(salt)?;

    let mut hasher = Sha256::new();
    hasher.update(s);
    hasher.update(&salt);
    Ok(hasher.finalize().to_vec())
}
