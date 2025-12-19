use crate::aes_utils::{Aes128Encryptor, BlockInfo};
use crate::grumpkin_utils;
use crate::secp256k1_utils;
use crate::sha_utils::{sha256, sha256_with_salt};
use anyhow::Result;
use ark_ec::PrimeGroup;
use ark_grumpkin::{Fr, Projective};
use num_bigint::BigUint;
use num_traits::Num;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::ops::Mul;
use std::str::FromStr;

const SECP256K1_BATCH_SIZE: usize = 255;
const GRUMPKIN_BATCH_SIZE: usize = 253;
const SECP256K1_H_POINT: &str = "04bd582ae432692458aef5c1e015db2fea76680058a4996ddd2bcbd3847bdfd0da38a29b2d21557940272b71963cea0f09802283bf44034b63e8c14cee6a6e71aa";
const GRUMPKIN_H_POINT: &str = "042c2b3f8b8ed443db8604f0bc915726d2fdcc477f376d1c296025f2c8abdfd0d71d3000a60e38d450723887a1ff33863efefc92fc7849a88343997f38b7c49338";

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
pub enum CurveType {
    SECP256K1,
    GRUMPKIN,
}

#[derive(Debug, Clone)]
pub enum VerificationType {
    AESDecryption(String, String),
    HashComparsion(String, String),
    SalttedHashComparsion(String, String, String),
    CommitmentComparsion(CurveType, String, String, Vec<String>),
}

impl VerificationType {
    pub fn new(verification_type: &str, private_data: &PrivateData) -> Result<Self> {
        match verification_type {
            "AES_DECRYPTION" => {
                let Some(aes_key) = &private_data.aes_key else {
                    return Err(anyhow::anyhow!("aes key is empty"));
                };
                Ok(VerificationType::AESDecryption(
                    private_data.id.clone(),
                    aes_key.clone(),
                ))
            }
            "HASH_COMPARISON" => {
                let Some(content) = &private_data.content else {
                    return Err(anyhow::anyhow!("content is empty"));
                };
                Ok(VerificationType::HashComparsion(
                    private_data.id.clone(),
                    content.clone(),
                ))
            }
            "SALTED_HASH_COMPARISON" => {
                let Some(content) = &private_data.content else {
                    return Err(anyhow::anyhow!("content is empty"));
                };
                let Some(salt) = &private_data.salt else {
                    return Err(anyhow::anyhow!("salt is empty"));
                };
                Ok(VerificationType::SalttedHashComparsion(
                    private_data.id.clone(),
                    content.clone(),
                    salt.clone(),
                ))
            }
            "SECP256K1_COMMITMENT" => {
                let Some(content) = &private_data.content else {
                    return Err(anyhow::anyhow!("content is empty"));
                };
                let Some(random) = &private_data.random else {
                    return Err(anyhow::anyhow!("random is empty"));
                };
                Ok(VerificationType::CommitmentComparsion(
                    CurveType::SECP256K1,
                    private_data.id.clone(),
                    content.clone(),
                    random.clone(),
                ))
            }
            "GRUMPKIN_COMMITMENT" => {
                let Some(content) = &private_data.content else {
                    return Err(anyhow::anyhow!("content is empty"));
                };
                let Some(random) = &private_data.random else {
                    return Err(anyhow::anyhow!("random is empty"));
                };
                Ok(VerificationType::CommitmentComparsion(
                    CurveType::GRUMPKIN,
                    private_data.id.clone(),
                    content.clone(),
                    random.clone(),
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
    pub ciphertext: String,                          // tls record ciphertext
    pub nonce: String,                               // tls record nonce
    pub json_block_positions: Option<Vec<Vec<u32>>>, // positions to find json block
    pub blocks: Option<Vec<BlockInfo>>, // show how to construct the ciphertext. Note the length of ciphertext and the sum of the length of all bytes in all blocks should be equal
}

// HTTP Packet
#[derive(Debug, Serialize, Deserialize)]
pub struct HTTPPacket {
    pub records: Vec<TLSRecord>, // TLS Records, constructing full http packet
}

// TLS Data to verify for full prove
#[derive(Debug, Serialize, Deserialize)]
pub struct TLSData {
    pub packet: HTTPPacket, // HTTP Packet
}

// `TLSData` implementations
impl TLSData {
    // implement verify interface for TLSData
    pub fn verify(&self, verification_type: &VerificationType) -> Result<JsonData> {
        match verification_type {
            VerificationType::AESDecryption(_, aes_key) => match self.is_redacted() {
                Ok(true) => self.verify_aes_redacted(aes_key),
                Ok(false) => self.verify_aes_all(aes_key),
                Err(e) => Err(e),
            },
            _ => {
                return Err(anyhow::anyhow!(
                    "unsupported verification type: {:?}",
                    verification_type
                ));
            }
        }
    }

    pub fn is_redacted(&self) -> Result<bool> {
        let first_record = &self.packet.records[0];
        if let Some(_) = &first_record.blocks {
            Ok(true)
        } else if let Some(_) = &first_record.json_block_positions {
            Ok(false)
        } else {
            Err(anyhow::anyhow!(
                "cant not find blocks and json_block_positions"
            ))
        }
    }

    // implement verify interface for TLSDataOpt
    pub fn verify_aes_redacted(&self, aes_key: &str) -> Result<JsonData> {
        let cipher = Aes128Encryptor::from_hex(aes_key)?;

        let mut complete_json = String::new();
        for record in self.packet.records.iter() {
            let nonce = hex::decode(&record.nonce)?;
            let ciphertext = hex::decode(&record.ciphertext)?;

            let counters = cipher.compute_selective_counters(
                &nonce,
                &record
                    .blocks
                    .clone()
                    .ok_or(anyhow::anyhow!("can not find blocks"))?,
                ciphertext.len(),
            )?;
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
        Ok(json_data)
    }
    // implement verify interface for TLSData
    pub fn verify_aes_all(&self, aes_key: &str) -> Result<JsonData> {
        let cipher = Aes128Encryptor::from_hex(aes_key)?;

        let mut complete_json = String::new();
        for record in self.packet.records.iter() {
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
            for positions in record
                .json_block_positions
                .clone()
                .ok_or(anyhow::anyhow!("can not find json block positions"))?
                .iter()
            {
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
        Ok(json_data)
    }
}

// `PrivateData` definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateData {
    pub id: String,
    pub aes_key: Option<String>, // aes key
    pub content: Option<String>,
    pub salt: Option<String>,
    pub random: Option<Vec<String>>,
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
    pub fn verify(&self) -> Result<JsonData> {
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
    pub fn verify(&self, verification_type: &VerificationType) -> Result<JsonData> {
        let json_data = match verification_type {
            VerificationType::HashComparsion(id, content) => {
                let expected_hash = sha256(&content);
                let committed_hash = match self.hashes.get(&id) {
                    Some(hash) => {
                        let hash = hash.to_string();
                        let hash = hash.trim_matches('"');

                        let h = hash.strip_prefix("0x").unwrap_or(&hash);
                        hex::decode(&h)?
                    }
                    None => return Err(anyhow::anyhow!("hash not find by {}", id)),
                };
                if expected_hash != committed_hash {
                    return Err(anyhow::anyhow!("check json response hash failed"));
                }

                let json_data: JsonData = JsonData::from_str(&content)?;
                json_data
            }
            VerificationType::SalttedHashComparsion(id, content, salt) => {
                let expected_hash = sha256_with_salt(&content, &salt)?;
                let committed_hash = match self.hashes.get(&id) {
                    Some(hash) => {
                        let hash = hash.to_string();
                        let hash = hash.trim_matches('"');

                        let h = hash.strip_prefix("0x").unwrap_or(&hash);
                        hex::decode(&h)?
                    }
                    None => return Err(anyhow::anyhow!("hash not find by {}", id)),
                };
                if expected_hash != committed_hash {
                    return Err(anyhow::anyhow!("check json response hash failed"));
                }

                let json_data: JsonData = JsonData::from_str(&content)?;
                json_data
            }
            VerificationType::CommitmentComparsion(curve_type, id, content, random) => {
                let (h_point, batch_size) = match curve_type {
                    CurveType::SECP256K1 => (SECP256K1_H_POINT, SECP256K1_BATCH_SIZE),
                    CurveType::GRUMPKIN => (GRUMPKIN_H_POINT, GRUMPKIN_BATCH_SIZE),
                };
                let Some(coms) = self.hashes.get(&id) else {
                    return Err(anyhow::anyhow!("commitment not found"));
                };
                let coms: Vec<String> = serde_json::from_str(coms.as_str().unwrap())?;
                match curve_type {
                    CurveType::SECP256K1 => {
                        let h_bytes = hex::decode(h_point)?;
                        let h = PublicKey::from_slice(&h_bytes)?;
                        let msgs: Vec<SecretKey> =
                            secp256k1_utils::split_json_response(&content, batch_size);
                        let rnds: Vec<Scalar> = secp256k1_utils::convert_random(&random);
                        let coms: Vec<PublicKey> = secp256k1_utils::convert_commitment(&coms);
                        let msg_rnd_com: Vec<((SecretKey, Scalar), PublicKey)> = msgs
                            .into_iter()
                            .zip(rnds.into_iter())
                            .zip(coms.into_iter())
                            .collect();

                        let secp = Secp256k1::new();
                        for ((msg, rnd), com) in msg_rnd_com.into_iter() {
                            let m_g = PublicKey::from_secret_key(&secp, &msg);
                            let r_h = h.mul_tweak(&secp, &rnd).unwrap();
                            let expected_com = m_g.combine(&r_h).unwrap();
                            if expected_com != com {
                                return Err(anyhow::anyhow!("check commitment failed"));
                            }
                        }
                    }
                    CurveType::GRUMPKIN => {
                        let msgs = grumpkin_utils::split_json_response(&content, batch_size)?;
                        let rnds = grumpkin_utils::convert_random(&random)?;
                        let coms = grumpkin_utils::convert_commitment(&coms)?;
                        let msg_rnd_com: Vec<((Fr, Fr), Projective)> = msgs
                            .into_iter()
                            .zip(rnds.into_iter())
                            .zip(coms.into_iter())
                            .collect();
                        let g = Projective::generator();
                        let h = grumpkin_utils::hex2point(h_point)?;
                        for ((msg, rnd), com) in msg_rnd_com.iter() {
                            let m_g = g.mul(msg);
                            let r_h = h.mul(rnd);
                            let expected_com = m_g + r_h;
                            if &expected_com != com {
                                return Err(anyhow::anyhow!("check commitment failed"));
                            }
                        }
                    }
                }

                let json_data: JsonData = JsonData::from_str(&content)?;
                json_data
            }
            _ => {
                return Err(anyhow::anyhow!("unsupported verification type"));
            }
        };
        Ok(json_data)
    }
}
