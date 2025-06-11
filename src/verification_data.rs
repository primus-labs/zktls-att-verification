use serde::{Deserialize, Serialize};

// TLS Record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TLSRecord {
    pub ciphertext: String,          // tls record ciphertext
    pub nonce: String,               // tls record nonce
    pub json_block_positions: Vec<Vec<u32>>,    // positions to find json block
}

// HTTP Packet
#[derive(Debug, Serialize, Deserialize)]
pub struct HTTPPacket {
    pub records: Vec<TLSRecord>, // TLS Records, constructing full http packet
}

// Data to verify for full prove
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyingData {
    pub packets: Vec<HTTPPacket>, // HTTP Packet
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateData {
    pub aes_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FullData {
    pub verifying_data: VerifyingData,
    pub private_data: PrivateData,
}

// AES Counter block info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockInfo {
    pub id: usize,     // block id
    pub mask: Vec<u8>, // block mask, 1u8 indicate this char is extracted
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
    pub records: Vec<TLSRecordOpt>,   // TLS Records, construct partial http packet
}

// Data to verify for partial prove
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyingDataOpt {
    pub packets: Vec<HTTPPacketOpt>, // partial HTTP Packet
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PartialData {
    pub verifying_data: VerifyingDataOpt,
    pub private_data: PrivateData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonData {
    pub msg: serde_json::Value,
}

// AES key wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct AesKeyVec {
    pub aes_keys: Vec<String>,
}

// plaintext wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct PacketMessageVec {
    pub packet_messages: Vec<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonMessageVec {
    pub json_messages: Vec<String>,
}

// signature wrapper
#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureVec {
    pub signatures: Vec<String>,
}

// tls record wrapper for partial prove
#[derive(Debug, Serialize, Deserialize)]
pub struct PacketRecordOptVec {
    pub packet_records: Vec<Vec<TLSRecordOpt>>,
}

// tls record wrapper for full prove
#[derive(Debug, Serialize, Deserialize)]
pub struct PacketRecordVec {
    pub packet_records: Vec<Vec<TLSRecord>>,
}

impl AesKeyVec {
    // AesKeyVec constructor
    pub fn new(aes_keys: Vec<String>) -> AesKeyVec {
        AesKeyVec { aes_keys }
    }
}

impl SignatureVec {
    // SignatureVec constructor
    pub fn new(signatures: Vec<String>) -> SignatureVec {
        SignatureVec { signatures }
    }
}

impl PacketMessageVec {
    // PacketMessageVec constructor
    pub fn new(packet_messages: Vec<Vec<String>>) -> PacketMessageVec {
        PacketMessageVec { packet_messages }
    }
}

impl PacketRecordVec {
    // PacketRecordVec constructor
    pub fn new(packet_records: Vec<Vec<TLSRecord>>) -> PacketRecordVec {
        PacketRecordVec { packet_records }
    }
}

impl PacketRecordOptVec {
    // PacketRecordOptVec constructor
    pub fn new(packet_records: Vec<Vec<TLSRecordOpt>>) -> PacketRecordOptVec {
        PacketRecordOptVec { packet_records }
    }
}

impl JsonMessageVec {
    pub fn new(json_messages: Vec<String>) -> JsonMessageVec {
        JsonMessageVec { json_messages }
    }
}

impl JsonData {
    pub fn new(msg: &str) -> JsonData {
        let msg: serde_json::Value = serde_json::from_str(msg).unwrap();
        JsonData { msg }
    }
}
