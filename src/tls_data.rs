use crate::aes_utils::{Aes128Encryptor, BlockInfo};
use anyhow::{anyhow, Result};
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
                let result = result
                    .as_str()
                    .ok_or(anyhow!("get json path {} error", json_path))?;
                vec.push(result.to_string());
            }
        }
        Ok(vec)
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
    pub fn verify(&self, aes_key: &str) -> Result<Vec<JsonData>> {
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

// `PrivateData` definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateData {
    pub aes_key: String, // aes key
}

// `FullTLSData` definitions
#[derive(Debug, Serialize, Deserialize)]
pub struct FullTLSData {
    pub tls_data: TLSData,         // tls data
    pub private_data: PrivateData, // private data, including aes key
}

// `FullTLSData` implementations
impl FullTLSData {
    pub fn verify(&self) -> Result<Vec<JsonData>> {
        self.tls_data.verify(&self.private_data.aes_key)
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
    pub fn verify(&self, aes_key: &str) -> Result<Vec<String>> {
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
            result.push(complete_json);
        }
        Ok(result)
    }
}

// `PartialTLSData` definitions
#[derive(Debug, Serialize, Deserialize)]
pub struct PartialTLSData {
    pub tls_data: TLSDataOpt,      // tls data opt
    pub private_data: PrivateData, // private data, including aes key
}

// `PartialTLSData` implementations
impl PartialTLSData {
    pub fn verify(&self) -> Result<Vec<String>> {
        self.tls_data.verify(&self.private_data.aes_key)
    }
}
