use crate::verification_data::{PrivateData, VerifyingData};
use anyhow::{anyhow, Result};
use hex::FromHex;
use secp256k1::{ecdsa, Message, PublicKey, Secp256k1, Verification};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestData {
    pub url: String,
    pub header: String,
    pub method: String,
    pub body: String,
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseResolve {
    pub keyName: String,
    pub parseType: String,
    pub parsePath: String,
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestor {
    pub attestorAddr: String,
    pub url: String,
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicData {
    pub recipient: String,
    pub request: RequestData,
    pub reponseResolve: Vec<ResponseResolve>,
    pub data: String,
    pub attConditions: String,
    pub timestamp: u64,
    pub additionParams: String,
    pub attestors: Vec<Attestor>,
    pub signatures: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationData {
    pub public_data: PublicData,
    pub private_data: PrivateData,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationConfig {
    pub attestor_addr: String,
    pub url: Vec<String>,
}

fn encode_packed_u64(n: u64) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![];
    for i in 0..8 {
        bytes.push((n >> (7 - i) * 8) as u8);
    }
    bytes
}

fn encode_packed_address(addr: &str) -> Vec<u8> {
    let addr = addr.strip_prefix("0x").unwrap_or(addr);
    let addr_bytes: [u8; 20] = <[u8; 20]>::from_hex(addr).unwrap();
    addr_bytes.to_vec()
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

fn public_key_to_address(public_key: &PublicKey) -> Result<Vec<u8>> {
    let public_key_bytes = public_key.serialize_uncompressed();
    let public_key_hash = keccak256(&public_key_bytes[1..]);
    let address = &public_key_hash[12..];
    Ok(address.to_vec())
}
impl RequestData {
    pub fn encode_packed(&self) -> Vec<u8> {
        let mut packed: Vec<u8> = vec![];
        packed.extend(self.url.as_bytes());
        packed.extend(self.header.as_bytes());
        packed.extend(self.method.as_bytes());
        packed.extend(self.body.as_bytes());
        packed
    }

    pub fn hash(&self) -> Vec<u8> {
        keccak256(&self.encode_packed()).to_vec()
    }
}

impl ResponseResolve {
    pub fn encode_packed(&self) -> Vec<u8> {
        let mut packed: Vec<u8> = vec![];
        packed.extend(self.keyName.as_bytes());
        packed.extend(self.parseType.as_bytes());
        packed.extend(self.parsePath.as_bytes());
        packed
    }

    pub fn hash(&self) -> Vec<u8> {
        keccak256(&self.encode_packed()).to_vec()
    }
}

impl PublicData {
    pub fn encode_packed(&self) -> Vec<u8> {
        let mut packed: Vec<u8> = vec![];
        packed.extend(encode_packed_address(&self.recipient));
        packed.extend(self.request.hash());
        for rr in self.reponseResolve.iter() {
            packed.extend(rr.hash());
        }
        packed.extend(self.data.as_bytes());
        packed.extend(self.attConditions.as_bytes());
        packed.extend(encode_packed_u64(self.timestamp));
        packed.extend(self.additionParams.as_bytes());
        packed
    }

    pub fn hash(&self) -> Vec<u8> {
        keccak256(&self.encode_packed()).to_vec()
    }

    pub fn verify_signature(&self, signer_addr: &str) -> Result<()> {
        let secp = Secp256k1::new();
        let hash = Message::from_digest_slice(&self.hash())?;
        let sig_hex = &self.signatures[0];
        let sig_hex = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
        let sig_bytes = <[u8; 65]>::from_hex(sig_hex).unwrap();
        let v = i32::from((sig_bytes[64] - 27) % 4);
        let recovery_id = ecdsa::RecoveryId::from_i32(v)?;
        let sig = ecdsa::RecoverableSignature::from_compact(&sig_bytes[..64], recovery_id)?;
        let public_key = secp.recover_ecdsa(&hash, &sig)?;
        let address = public_key_to_address(&public_key)?;
        println!("address: {}", hex::encode(&address));
        
        let signer_addr = signer_addr.strip_prefix("0x").unwrap_or(signer_addr);
        let signer_addr = hex::decode(&signer_addr)?;
        if signer_addr == address {
            return Ok(());
        }

        Err(anyhow!("fail to verify signature"))
    }

    pub fn verify_url(&self, allowed_urls: &[String]) -> Result<()> {
        for url in allowed_urls.iter() {
            if url == &self.request.url {
                return Ok(());
            }
        }
        Err(anyhow!("fail to check url"))
    }
}
