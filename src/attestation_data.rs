use crate::ecdsa_utils::{encode_packed_address, encode_packed_u64, keccak256, ECDSASignature};
use crate::tls_data::{JsonData, PrivateData, TLSData, TLSDataOpt};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

// `RequestData` definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestData {
    pub url: String,    // http request url
    pub header: String, // http request header
    pub method: String, // http request method
    pub body: String,   // http request body
}

// `RequestData` definition
impl RequestData {
    // encode `RequestData` as abi.encodePacked in solidity
    fn encode_packed(&self) -> Vec<u8> {
        let mut packed: Vec<u8> = vec![];
        packed.extend(self.url.as_bytes());
        packed.extend(self.header.as_bytes());
        packed.extend(self.method.as_bytes());
        packed.extend(self.body.as_bytes());
        packed
    }

    // compute keccak hash
    pub fn hash(&self) -> Vec<u8> {
        keccak256(&self.encode_packed()).to_vec()
    }
}

// `ResponseResolve` definition
#[allow(non_snake_case)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseResolve {
    pub keyName: String,
    pub parseType: String,
    pub parsePath: String,
}

// `ResponseResolve` implementations
impl ResponseResolve {
    // encode `ResponseResolve` as abi.encodePacked in solidity
    fn encode_packed(&self) -> Vec<u8> {
        let mut packed: Vec<u8> = vec![];
        packed.extend(self.keyName.as_bytes());
        packed.extend(self.parseType.as_bytes());
        packed.extend(self.parsePath.as_bytes());
        packed
    }

    // compute keccak hash
    pub fn hash(&self) -> Vec<u8> {
        keccak256(&self.encode_packed()).to_vec()
    }
}

// `Attestor` definition
#[allow(non_snake_case)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestor {
    pub attestorAddr: String, // the address of the attestor
    pub url: String,          // the url of the attestation
}

// `PublicData` definition
#[allow(non_snake_case)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicData {
    pub recipient: String,                    // recipient address
    pub request: RequestData,                 // request data
    pub reponseResolve: Vec<ResponseResolve>, // response resolve
    pub data: String,                         // attestation data
    pub attConditions: String,                // attestation conditio
    pub timestamp: u64,                       // attestation timestamp
    pub additionParams: String,               // addition params
    pub attestors: Vec<Attestor>,             // allowed attestor collection
    pub signatures: Vec<String>,              // the signature of the attestation
}

// `PublicData` implementations
impl PublicData {
    // encode `PublicData` as abi.encodePacked in solidity
    fn encode_packed(&self) -> Result<Vec<u8>> {
        let mut packed: Vec<u8> = vec![];
        packed.extend(encode_packed_address(&self.recipient)?);
        packed.extend(self.request.hash());
        if self.reponseResolve.len() == 1 {
            packed.extend(self.reponseResolve[0].hash());
        } else {
            let mut vec = vec![];
            for rr in self.reponseResolve.iter() {
                vec.extend(rr.encode_packed());
            }
            packed.extend(keccak256(&vec).to_vec());
        }
        packed.extend(self.data.as_bytes());
        packed.extend(self.attConditions.as_bytes());
        packed.extend(encode_packed_u64(self.timestamp));
        packed.extend(self.additionParams.as_bytes());
        Ok(packed)
    }

    // compute keccak hash
    pub fn hash(&self) -> Result<Vec<u8>> {
        Ok(keccak256(&self.encode_packed()?).to_vec())
    }

    // verify ecdsa signature by recovering signer address
    // and comparing with given address
    fn verify_signature(&self, signer_addr: &str) -> Result<()> {
        let ecdsa_signature = ECDSASignature::from_hex(&self.signatures[0])?;
        let address = ecdsa_signature.recover(&self.hash()?)?;

        let signer_addr = signer_addr.strip_prefix("0x").unwrap_or(signer_addr);
        let signer_addr = hex::decode(signer_addr)?;
        if signer_addr == address {
            return Ok(());
        }

        Err(anyhow!("fail to verify signature"))
    }

    // verify aes ciphertext: decrypt aes ciphertext
    // and check whether it is a valid json string
    fn verify_aes_ciphertext(&self, aes_key: &str) -> Result<Vec<JsonData>> {
        let json_value: serde_json::Value = serde_json::from_str(&self.data)?;
        let mut json_data_vec: Vec<JsonData> = vec![];
        if json_value.get("CompleteHttpResponseCiphertext").is_some() {
            let data = &json_value["CompleteHttpResponseCiphertext"];
            let data = data
                .as_str()
                .ok_or(anyhow!("parse CompleteHttpResponseCiphertext error"))?;
            let tls_data: TLSData = serde_json::from_str(data)?;
            json_data_vec = tls_data.verify(aes_key)?;
        } else if json_value.get("PartialHttpResponseCiphertext").is_some() {
            let data = &json_value["PartialHttpResponseCiphertext"];
            let data = data
                .as_str()
                .ok_or(anyhow!("parse PartialHttpResponseCiphertext error"))?;
            let tls_data_opt: TLSDataOpt = serde_json::from_str(data)?;
            json_data_vec = tls_data_opt.verify(aes_key)?;
        }

        Ok(json_data_vec)
    }

    // check whether the attestation url is in the allowed url list
    fn verify_url(&self, allowed_urls: &[String]) -> Result<()> {
        for url in allowed_urls.iter() {
            if self.request.url.starts_with(url) {
                return Ok(());
            }
        }
        Err(anyhow!("fail to check url"))
    }

    // verify the attestation, including attestation url, ecdsa signature and aes ciphertext
    pub fn verify(&self, config: &AttestationConfig, aes_key: &str) -> Result<Vec<JsonData>> {
        self.verify_url(&config.url)?;
        self.verify_signature(&config.attestor_addr)?;
        self.verify_aes_ciphertext(aes_key)
    }
}

// `AttestationData` definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationData {
    pub public_data: PublicData,   // public data
    pub private_data: PrivateData, // private data, including aes key
}

// `AttestiongData`` implementations
impl AttestationData {
    // verify the attestation
    pub fn verify(&self, config: &AttestationConfig) -> Result<Vec<JsonData>> {
        self.public_data.verify(config, &self.private_data.aes_key)
    }
}

// `AttestationConfig` definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationConfig {
    pub attestor_addr: String, // the attestor address
    pub url: Vec<String>,      // the attestation url
}

pub fn verify_attestation_data(
    data: &str,
    config: &str,
) -> Result<(AttestationData, AttestationConfig, Vec<JsonData>)> {
    let attestation_data: AttestationData = serde_json::from_str(data)?;
    let attestation_config: AttestationConfig = serde_json::from_str(config)?;
    // verify attestation data according to attestation config
    let messages = attestation_data.verify(&attestation_config)?;
    Ok((attestation_data, attestation_config, messages))
}
