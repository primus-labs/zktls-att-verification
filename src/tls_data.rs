use crate::aes_utils::{Aes128Encryptor, BlockInfo};
use crate::sha_utils::{sha256, sha256_with_salt};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

// `serde_json::Value` wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonData {
    pub msg: serde_json::Value,
}

// implement trait `FromStr` for `JsonData`
impl FromStr for JsonData {
    // construct `JsonData` from json-string
    fn from_str(msg: &str) -> Result<Self> {
        let msg: serde_json::Value = serde_json::from_str(msg)?;
        Ok(JsonData { msg })
    }

    type Err = anyhow::Error;
}

// `JsonData` implementations
impl JsonData {
    // get json values by json path
    pub fn get_json_values(&self, json_paths: &[&str]) -> Result<Vec<String>> {
        let mut vec: Vec<String> = vec![];
        for json_path in json_paths.iter() {
            let results = jsonpath_lib::select(&self.msg, json_path)?;
            for result in results.iter() {
                vec.push(result.to_string());
            }
        }
        Ok(vec)
    }
}

#[derive(Debug, Clone)]
pub enum VerificationType {
    AESDecryption(String),
    HashComparsion(Vec<PlainJsonResponse>),
    SalttedHashComparsion(Vec<PlainJsonResponseWithSalt>),
}

impl VerificationType {
    pub fn new(verification_type: &str, private_data: &PrivateData) -> Result<Self> {
        match verification_type {
            "AES_DECRYPTION" => {
                let Some(aes_key) = &private_data.aes_key else {
                    return Err(anyhow::anyhow!("aes key is empty"));
                };
                Ok(VerificationType::AESDecryption(aes_key.clone()))
            }
            "HASH_COMPARSION" => {
                let Some(plain_json_response) = &private_data.plain_json_response else {
                    return Err(anyhow::anyhow!("plain json response is empty"));
                };
                Ok(VerificationType::HashComparsion(
                    plain_json_response.clone(),
                ))
            }
            "SALTTED_HASH_COMPARSION" => {
                let Some(plain_json_response_with_salt) =
                    &private_data.plain_json_response_with_salt
                else {
                    return Err(anyhow::anyhow!("plain json response with salt is empty"));
                };
                Ok(VerificationType::SalttedHashComparsion(
                    plain_json_response_with_salt.clone(),
                ))
            }
            _ => Err(anyhow::anyhow!(
                "unsupported verification type {}",
                verification_type
            )),
        }
    }
}
// TLS Record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TLSRecord {
    pub ciphertext: String,                  // tls record ciphertext
    pub nonce: String,                       // tls record nonce
    pub json_block_positions: Vec<Vec<u32>>, // positions to find json block
}

// HTTP Packet
#[derive(Debug, Serialize, Deserialize)]
pub struct HTTPPacket {
    pub records: Vec<TLSRecord>, // TLS Records, constructing full http packet
}

// TLS Data to verify for full prove
#[derive(Debug, Serialize, Deserialize)]
pub struct TLSData {
    pub packets: Vec<HTTPPacket>, // HTTP Packet
}

// `TLSData` implementations
impl TLSData {
    // implement verify interface for TLSData
    pub fn verify(&self, verification_type: &VerificationType) -> Result<Vec<JsonData>> {
        match verification_type {
            VerificationType::AESDecryption(aes_key) => self.verify_aes(aes_key),
            _ => {
                return Err(anyhow::anyhow!(
                    "unsupported verification type: {:?}",
                    verification_type
                ));
            }
        }
    }

    // implement verify interface for TLSData
    pub fn verify_aes(&self, aes_key: &str) -> Result<Vec<JsonData>> {
        let mut result = vec![];
        let cipher = Aes128Encryptor::from_hex(aes_key)?;

        for packet in self.packets.iter() {
            let mut complete_json = String::new();
            for record in packet.records.iter() {
                let nonce = hex::decode(&record.nonce)?;
                let ciphertext = hex::decode(&record.ciphertext)?;
                let ciphertext_len = ciphertext.len();

                let counters = cipher.compute_continuous_counters(&nonce, ciphertext_len)?;
                let plaintext = counters
                    .iter()
                    .zip(ciphertext.iter())
                    .map(|(c1, c2)| c1 ^ c2)
                    .collect::<Vec<u8>>();
                let plaintext = String::from_utf8(plaintext)?;

                let mut json_payload = String::new();
                for positions in record.json_block_positions.iter() {
                    let text: String = plaintext
                        .chars()
                        .skip(positions[0] as usize)
                        .take((positions[1] - positions[0] + 1) as usize)
                        .collect();
                    json_payload += &text;
                }
                complete_json += &json_payload;
            }
            let json_data = JsonData::from_str(&complete_json)?;
            result.push(json_data);
        }
        Ok(result)
    }
}

// `PlainJsonResponse` definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlainJsonResponse {
    pub id: String,
    pub content: String,
}

// `PlainJsonResponseWithSalt` definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlainJsonResponseWithSalt {
    pub id: String,
    pub salt: String,
    pub content: String,
}
// `PrivateData` definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateData {
    pub aes_key: Option<String>,                             // aes key
    pub plain_json_response: Option<Vec<PlainJsonResponse>>, // plain json response
    pub plain_json_response_with_salt: Option<Vec<PlainJsonResponseWithSalt>>, // plain json response with salt
}

// `FullTLSData` definitions
#[derive(Debug, Serialize, Deserialize)]
pub struct FullTLSData {
    pub verification_type: String, // verification type
    pub tls_data: TLSData,         // tls data
    pub private_data: PrivateData, // private data, including aes key
}

// `FullTLSData` implementations
impl FullTLSData {
    pub fn verify(&self) -> Result<Vec<JsonData>> {
        let verification_type = VerificationType::new(&self.verification_type, &self.private_data)?;
        self.tls_data.verify(&verification_type)
    }
}

// TLS record data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TLSRecordOpt {
    pub ciphertext: String, // ciphertext in tls record, it is concated according to field `blocks`
    pub nonce: String,      // nonce for decrypting the ciphertext
    pub blocks: Vec<BlockInfo>, // show how to construct the ciphertext. Note the length of ciphertext and the sum of the length of all bytes in all blocks should be equal
}

// HTTP packet data
#[derive(Debug, Serialize, Deserialize)]
pub struct HTTPPacketOpt {
    pub records: Vec<TLSRecordOpt>, // TLS Records, construct partial http packet
}

// Data to verify for partial prove
#[derive(Debug, Serialize, Deserialize)]
pub struct TLSDataOpt {
    pub packets: Vec<HTTPPacketOpt>, // partial HTTP Packet
}

// `TLSDataOpt` implementations
impl TLSDataOpt {
    // implement verify interface for TLSDataOpt
    pub fn verify(&self, verification_type: &VerificationType) -> Result<Vec<JsonData>> {
        match verification_type {
            VerificationType::AESDecryption(aes_key) => self.verify_aes(aes_key),
            _ => {
                return Err(anyhow::anyhow!(
                    "unsupported verification type: {:?}",
                    verification_type
                ));
            }
        }
    }

    // implement verify interface for TLSDataOpt
    pub fn verify_aes(&self, aes_key: &str) -> Result<Vec<JsonData>> {
        let mut result = vec![];
        let cipher = Aes128Encryptor::from_hex(aes_key)?;

        for packet in self.packets.iter() {
            let mut complete_json = String::new();
            for record in packet.records.iter() {
                let nonce = hex::decode(&record.nonce)?;
                let ciphertext = hex::decode(&record.ciphertext)?;

                let counters =
                    cipher.compute_selective_counters(&nonce, &record.blocks, ciphertext.len())?;
                assert!(ciphertext.len() == counters.len());

                let decrypted_msg: Vec<u8> = counters
                    .iter()
                    .zip(ciphertext.iter())
                    .map(|(a, b)| a ^ b)
                    .collect();
                let text = String::from_utf8(decrypted_msg)?;
                complete_json += &text;
            }
            let json_data = JsonData::from_str(&complete_json)?;
            result.push(json_data);
        }
        Ok(result)
    }
}

// `PartialTLSData` definitions
#[derive(Debug, Serialize, Deserialize)]
pub struct PartialTLSData {
    pub verification_type: String, // verification type
    pub tls_data: TLSDataOpt,      // tls data opt
    pub private_data: PrivateData, // private data, including aes key
}

// `PartialTLSData` implementations
impl PartialTLSData {
    pub fn verify(&self) -> Result<Vec<JsonData>> {
        let verification_type = VerificationType::new(&self.verification_type, &self.private_data)?;
        self.tls_data.verify(&verification_type)
    }
}

// `TLSDataHash`definitions
#[derive(Debug, Serialize, Deserialize)]
pub struct TLSDataHash {
    pub hashes: serde_json::Value,
}

impl FromStr for TLSDataHash {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let hashes: serde_json::Value = serde_json::Value::from_str(s)?;
        Ok(Self { hashes })
    }
}

impl TLSDataHash {
    pub fn verify(&self, verification_type: &VerificationType) -> Result<Vec<JsonData>> {
        let mut vec = vec![];
        match verification_type {
            VerificationType::HashComparsion(plain_json_response) => {
                for response in plain_json_response.iter() {
                    let expected_hash = sha256(&response.content);
                    let committed_hash = match self.hashes.get(&response.id) {
                        Some(hash) => {
                            let hash = hash.to_string();
                            let hash = hash.trim_matches('"');

                            let h = hash.strip_prefix("0x").unwrap_or(&hash);
                            hex::decode(&h)?
                        }
                        None => return Err(anyhow::anyhow!("hash not find by {}", response.id)),
                    };
                    if expected_hash != committed_hash {
                        return Err(anyhow::anyhow!("check json response hash failed"));
                    }

                    let json_data: JsonData = JsonData::from_str(&response.content)?;
                    vec.push(json_data);
                }
            }
            VerificationType::SalttedHashComparsion(plain_json_response) => {
                for response in plain_json_response.iter() {
                    let expected_hash = sha256_with_salt(&response.content, &response.salt)?;
                    let committed_hash = match self.hashes.get(&response.id) {
                        Some(hash) => {
                            let hash = hash.to_string();
                            let hash = hash.trim_matches('"');

                            let h = hash.strip_prefix("0x").unwrap_or(&hash);
                            hex::decode(&h)?
                        }
                        None => return Err(anyhow::anyhow!("hash not find by {}", response.id)),
                    };
                    if expected_hash != committed_hash {
                        return Err(anyhow::anyhow!("check json response hash failed"));
                    }

                    let json_data: JsonData = JsonData::from_str(&response.content)?;
                    vec.push(json_data);
                }
            }
            _ => {
                return Err(anyhow::anyhow!("unsupported verification type"));
            }
        };
        Ok(vec)
    }
}
