pub mod aes_utils;
pub mod ciphertext_verification;
pub mod ecdsa_utils;
pub mod signature_verification;
pub mod verification_data;
pub mod attestation_data;

use anyhow::Result;
use verification_data::{
    AesKeyVec, PacketMessageVec, PacketRecordOptVec, PacketRecordVec, SignatureVec, VerifyingData,
    VerifyingDataOpt, TLSRecord,
};

impl VerifyingData {
    // implement verify interface for VerifyingData
    pub fn verify(&self) -> Result<Vec<String>> {
        // verify aes ciphertext
        self.verify_ciphertext()
    }

    // get aes keys
    pub fn get_aes_keys(&self) -> String {
        let aes_keys = AesKeyVec::new(self.packets.iter().map(|p| p.aes_key.clone()).collect());
        serde_json::to_string(&aes_keys).unwrap()
    }

    // get signatures
    pub fn get_signatures(&self) -> String {
        let signatures = SignatureVec::new(
            self.packets
                .iter()
                .map(|p| p.ecdsa_signature.clone())
                .collect(),
        );
        serde_json::to_string(&signatures).unwrap()
    }

    // get messages
    pub fn get_messages(&self) -> String {
        let messages = PacketMessageVec::new(
            self.packets
                .iter()
                .map(|p| p.record_messages.clone())
                .collect(),
        );

        serde_json::to_string(&messages).unwrap()
    }

    // get json value
    pub fn get_json_values(&self, json_paths: &[&str]) -> Vec<String> {
        let mut vec: Vec<String> = vec![];
        for p in self.packets.iter() {
            let message_records = p.record_messages.iter().zip(p.records.iter()).collect::<Vec<(&String, &TLSRecord)>>();
            let mut json_msg = String::new();
            for (message, record) in message_records.into_iter() {
                let m = hex::decode(&message).unwrap();
                let s = String::from_utf8_lossy(&m);
                for positions in record.json_block_positions.iter() {
                    let substr = s.chars().skip(positions[0] as usize).take((positions[1] - positions[0] + 1) as usize).collect::<String>();
                    json_msg += &substr;
                }
            }

            let json_values = serde_json::from_str(&json_msg).unwrap();
            for json_path in json_paths.iter() {
                let results = jsonpath_lib::select(&json_values, json_path).unwrap();
                for result in results.iter() {
                    let result = result.as_str().unwrap();
                    vec.push(result.to_string());
                }
            }
        }
        vec
    }

    // get records
    pub fn get_records(&self) -> String {
        let records =
            PacketRecordVec::new(self.packets.iter().map(|p| p.records.clone()).collect());
        serde_json::to_string(&records).unwrap()
    }
}

impl VerifyingDataOpt {
    // implement verify interface for VerifyingDataOpt
    pub fn verify(&self) -> Result<()> {
        // verify aes ciphertext
        self.verify_ciphertext()?;
        Ok(())
    }

    // get aes keys
    pub fn get_aes_keys(&self) -> String {
        let aes_keys = AesKeyVec::new(self.packets.iter().map(|p| p.aes_key.clone()).collect());

        serde_json::to_string(&aes_keys).unwrap()
    }
    
    // get signatures
    pub fn get_signatures(&self) -> String {
        let signatures = SignatureVec::new(
            self.packets
                .iter()
                .map(|p| p.ecdsa_signature.clone())
                .collect(),
        );

        serde_json::to_string(&signatures).unwrap()
    }

    // get messages
    pub fn get_messages(&self) -> String {
        let messages = PacketMessageVec::new(
            self.packets
                .iter()
                .map(|p| p.record_messages.clone())
                .collect(),
        );

        serde_json::to_string(&messages).unwrap()
    }

    // get records
    pub fn get_records(&self) -> String {
        let records =
            PacketRecordOptVec::new(self.packets.iter().map(|p| p.records.clone()).collect());

        serde_json::to_string(&records).unwrap()
    }
}
