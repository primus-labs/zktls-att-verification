use serde::{Deserialize, Serialize};
use anyhow::Result;
use crate::aes_utils::{BlockInfo, Aes128Encryptor};

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonData {
    pub msg: serde_json::Value,
}

impl JsonData {
    pub fn new(msg: &str) -> JsonData {
        let msg: serde_json::Value = serde_json::from_str(msg).unwrap();
        JsonData { msg }
    }

    pub fn get_json_values(&self, json_paths: &[&str]) -> Vec<String> {
        let mut vec: Vec<String> = vec![];
        for json_path in json_paths.iter() {
            let results = jsonpath_lib::select(&self.msg, json_path).unwrap();
            for result in results.iter() {
                let result = result.as_str().unwrap();
                vec.push(result.to_string());
            }
        }
        vec
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

impl TLSData {
    // implement verify interface for VerifyingData
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
            let json_data = JsonData::new(&complete_json);
            result.push(json_data);
        }
        Ok(result)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateData {
    pub aes_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FullTLSData {
    pub tls_data: TLSData,
    pub private_data: PrivateData,
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

impl TLSDataOpt {
    // implement verify interface for VerifyingDataOpt
    pub fn verify(&self, aes_key: &str) -> Result<Vec<JsonData>> {
        let mut result = vec![];
        let cipher = Aes128Encryptor::from_hex(aes_key)?;

        for packet in self.packets.iter() {
            let mut complete_json = String::new();
            for record in packet.records.iter() {
                let nonce = hex::decode(&record.nonce)?;
                let ciphertext = hex::decode(&record.ciphertext)?;

                let counters = cipher.compute_selective_counters(&nonce, &record.blocks, ciphertext.len())?;
                assert!(ciphertext.len() == counters.len());

                let decrypted_msg: Vec<u8> = counters
                    .iter()
                    .zip(ciphertext.iter())
                    .map(|(a, b)| a ^ b)
                    .collect();
                let text = String::from_utf8(decrypted_msg)?;
                complete_json += &text;
            }
            let json_data = JsonData::new(&complete_json);
            result.push(json_data);
        }
        Ok(result)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartialTLSData {
    pub tls_data: TLSDataOpt,
    pub private_data: PrivateData,
}
