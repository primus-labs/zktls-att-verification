use crate::verification_data::{PrivateData, VerifyingData, JsonData};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use crate::ecdsa_utils::{ECDSASignature, encode_packed_address, encode_packed_u64, keccak256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestData {
    pub url: String,
    pub header: String,
    pub method: String,
    pub body: String,
}

impl RequestData {
    fn encode_packed(&self) -> Vec<u8> {
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

#[allow(non_snake_case)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseResolve {
    pub keyName: String,
    pub parseType: String,
    pub parsePath: String,
}

impl ResponseResolve {
    fn encode_packed(&self) -> Vec<u8> {
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

impl PublicData {
    fn encode_packed(&self) -> Result<Vec<u8>> {
        let mut packed: Vec<u8> = vec![];
        packed.extend(encode_packed_address(&self.recipient)?);
        packed.extend(self.request.hash());
        for rr in self.reponseResolve.iter() {
            packed.extend(rr.hash());
        }
        packed.extend(self.data.as_bytes());
        packed.extend(self.attConditions.as_bytes());
        packed.extend(encode_packed_u64(self.timestamp));
        packed.extend(self.additionParams.as_bytes());
        Ok(packed)
    }

    pub fn hash(&self) -> Result<Vec<u8>> {
        Ok(keccak256(&self.encode_packed()?).to_vec())
    }

    fn verify_signature(&self, signer_addr: &str) -> Result<()> {
        let ecdsa_signature = ECDSASignature::new(&self.signatures[0])?;
        let address = ecdsa_signature.recover(&self.hash()?)?;

        let signer_addr = signer_addr.strip_prefix("0x").unwrap_or(signer_addr);
        let signer_addr = hex::decode(&signer_addr)?;
        if signer_addr == address {
            return Ok(());
        }

        Err(anyhow!("fail to verify signature"))
    }

    fn verify_aes_ciphertext(&self, aes_key: &str) -> Result<Vec<JsonData>> {
        let json_value: serde_json::Value = serde_json::from_str(&self.data)?;
        let data = &json_value["CompleteHttpResponseCiphertext"];
        let data = data.as_str().ok_or(anyhow!("parse CompleteHttpResponseCiphertext error"))?;
        let verifying_data: VerifyingData = serde_json::from_str(&data)?;
        let json_data_vec = verifying_data.verify(aes_key)?;
        Ok(json_data_vec)
    }

    fn verify_url(&self, allowed_urls: &[String]) -> Result<()> {
        for url in allowed_urls.iter() {
            if url == &self.request.url {
                return Ok(());
            }
        }
        Err(anyhow!("fail to check url"))
    }

    pub fn verify(&self, config: &AttestationConfig, aes_key: &str) -> Result<Vec<JsonData>> {
        self.verify_url(&config.url)?;
        self.verify_signature(&config.attestor_addr)?;
        self.verify_aes_ciphertext(aes_key)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationData {
    pub public_data: PublicData,
    pub private_data: PrivateData,
}

impl AttestationData {
    pub fn verify(&self, config: &AttestationConfig) -> Result<Vec<JsonData>> {
        self.public_data.verify(config, &self.private_data.aes_key)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationConfig {
    pub attestor_addr: String,
    pub url: Vec<String>,
}

