use anyhow::Result;
use hex::FromHex;
use secp256k1::{ecdsa, Message, PublicKey, Secp256k1, VerifyOnly};
use tiny_keccak::{Hasher, Keccak};

// encode `u64` into bytes
pub fn encode_packed_u64(n: u64) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![];
    for i in 0..8 {
        bytes.push((n >> ((7 - i) * 8)) as u8);
    }
    bytes
}

// encode `address` into bytes
pub fn encode_packed_address(addr: &str) -> Result<Vec<u8>> {
    let addr = addr.strip_prefix("0x").unwrap_or(addr);
    let addr_bytes: [u8; 20] = <[u8; 20]>::from_hex(addr)?;
    Ok(addr_bytes.to_vec())
}

// compute `keccak` hash
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

// convert public key to ethereum address
fn public_key_to_address(public_key: &PublicKey) -> Result<Vec<u8>> {
    let public_key_bytes = public_key.serialize_uncompressed();
    let public_key_hash = keccak256(&public_key_bytes[1..]);
    let address = &public_key_hash[12..];
    Ok(address.to_vec())
}

// struct `ECDSASignature` definition
pub struct ECDSASignature {
    secp256k1: Secp256k1<VerifyOnly>, // `Secp256k1`, it can only be used for verification
    signature: ecdsa::RecoverableSignature, // signature for public key recovery
}

// `ECDSASignature` implementation
impl ECDSASignature {
    // construct `ECDSASignature` from hex-string, leading `0x` is optional
    pub fn from_hex(signature: &str) -> Result<ECDSASignature> {
        let secp = Secp256k1::<VerifyOnly>::verification_only();
        let sig_hex = signature.strip_prefix("0x").unwrap_or(signature);
        let sig_bytes = <[u8; 65]>::from_hex(sig_hex)?;
        let v = i32::from((sig_bytes[64] - 27) % 4);
        let recovery_id = ecdsa::RecoveryId::from_i32(v)?;
        let sig = ecdsa::RecoverableSignature::from_compact(&sig_bytes[..64], recovery_id)?;

        Ok(Self {
            secp256k1: secp,
            signature: sig,
        })
    }

    // recover public key
    pub fn recover(&self, hash: &[u8]) -> Result<Vec<u8>> {
        let hash = Message::from_digest_slice(hash)?;
        let public_key = self.secp256k1.recover_ecdsa(&hash, &self.signature)?;
        let address = public_key_to_address(&public_key)?;
        Ok(address)
    }
}
