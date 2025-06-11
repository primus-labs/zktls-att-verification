use anyhow::{anyhow, Result};
use ethers::types::{H256};
use ethers::core::types::Signature;
use ethers::utils::keccak256;
use std::io::Write;
use serde::{Serialize, Deserialize};
use std::fs;
use hex::FromHex;
use std::str::FromStr;
use crate::verification_data::{VerifyingData, PrivateData};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestData {
    pub url: String,
    pub header: String,
    pub method: String,
    pub body: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseResolve {
    pub keyName: String,
    pub parseType: String,
    pub parsePath: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestor {
    pub attestorAddr: String,
    pub url: String,
}

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

    pub fn verify_signature(&self) -> Result<()> {
        let hash = H256::from_slice(&self.hash());
    
        let sig_hex = &self.signatures[0];
        let sig_hex = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
        let sig_bytes = <[u8; 65]>::from_hex(sig_hex).unwrap();
        let signature = Signature::try_from(&sig_bytes[..]).unwrap();
        let addr = signature.recover(hash).unwrap().to_string();
        println!("addr: {:?}", addr);
        println!("attestor: {:?}", self.attestors);

        let index = self.attestors.iter().find(|attestor| attestor.attestorAddr == addr);
        if let Some(_) = index {
            return Ok(());
        }
        // Err(anyhow!("fail to verify signature"))
        Ok(())
    }
}

