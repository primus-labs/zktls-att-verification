pub mod aes_utils;
pub mod attestation_data;
pub mod ciphertext_verification;
pub mod ecdsa_utils;
pub mod signature_verification;
pub mod verification_data;

use anyhow::Result;
use attestation_data::{AttestationData, AttestationConfig, PublicData};
use verification_data::{
    AesKeyVec, JsonData, PacketMessageVec, PacketRecordOptVec, PacketRecordVec, SignatureVec,
    TLSRecord, VerifyingData, VerifyingDataOpt,
};

impl JsonData {
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

impl VerifyingData {
    // implement verify interface for VerifyingData
    pub fn verify(&self, aes_key: &str) -> Result<Vec<JsonData>> {
        // verify aes ciphertext
        self.verify_ciphertext(aes_key)
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
    pub fn verify(&self, aes_key: &str) -> Result<()> {
        // verify aes ciphertext
        self.verify_ciphertext(aes_key)?;
        Ok(())
    }

    // get records
    pub fn get_records(&self) -> String {
        let records =
            PacketRecordOptVec::new(self.packets.iter().map(|p| p.records.clone()).collect());

        serde_json::to_string(&records).unwrap()
    }
}

impl PublicData {
    pub fn verify(&self, config: &AttestationConfig, aes_key: &str) -> Result<(Vec<JsonData>, String)> {
        self.verify_signature(&config.attestor_addr)?;
        self.verify_url(&config.url)?;

        let json_value: serde_json::Value = serde_json::from_str(&self.data).unwrap();
        let data = &json_value["CompleteHttpResponseCiphertext"];
        let data = data.as_str().unwrap();
        let verifying_data: VerifyingData = serde_json::from_str(&data).unwrap();
        let json_data_vec = verifying_data.verify(aes_key)?;
        let records = verifying_data.get_records();
        Ok((json_data_vec, records))
    }
}

impl AttestationData {
    pub fn verify(&self, config: &AttestationConfig) -> Result<(Vec<JsonData>, String)> {
        self.public_data.verify(config, &self.private_data.aes_key)
    }
}
