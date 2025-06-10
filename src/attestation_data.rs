use anyhow::{anyhow, Result};
use ethers::abi::Token;
use ethers::abi::encode;
use ethers::types::{H256, U64, Address};
use ethers::core::types::Signature;
use ethers::utils::keccak256;
use std::io::Write;
use serde::{Serialize, Deserialize};
use std::fs;
use hex::FromHex;
use std::str::FromStr;

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
pub struct AttestationData {
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

fn encode_packed_u64(n: u64) -> Vec<u8> {
    let mut num_bytes = [0u8; 8];
    U64::from(n).to_big_endian(&mut num_bytes);
    // let trimmed = num_bytes.iter().skip_while(|b| **b == 0).cloned().collect::<Vec<u8>>();
    num_bytes.to_vec()
}

fn encode_packed_address(addr: &str) -> Vec<u8> {
    let addr = addr.strip_prefix("0x").unwrap_or(addr);
    let addr_bytes: [u8; 20] = <[u8; 20]>::from_hex(addr).unwrap();
    let addr = Address::from(addr_bytes);
    addr.as_bytes().to_vec()
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

impl AttestationData {
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

    pub fn verify(&self) -> Result<()> {
        let hash = H256::from_slice(&self.hash());
    
        let sig_hex = &self.signatures[0];
        let sig_hex = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
        let sig_bytes = <[u8; 65]>::from_hex(sig_hex).unwrap();
        let signature = Signature::try_from(&sig_bytes[..]).unwrap();
        let addr = signature.recover(hash).unwrap().to_string();

        let index = self.attestors.iter().find(|attestor| attestor.attestorAddr == addr);
        if let Some(_) = index {
            return Ok(());
        }
        Err(anyhow!("fail to verify signature"))
    }
}

