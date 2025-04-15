pub mod aes_utils;
pub mod ciphertext_verification;
pub mod ecdsa_utils;
pub mod signature_verification;
pub mod verification_data;

use anyhow::Result;
use verification_data::{
    AesKeyVec, PacketMessageVec, PacketRecordOptVec, PacketRecordVec, SignatureVec, VerifyingData,
    VerifyingDataOpt,
};

impl VerifyingData {
    // implement verify interface for VerifyingData
    pub fn verify(&self, verifying_key: &str) -> Result<()> {
        // verify ecdsa signature
        self.verify_signature(verifying_key)?;

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

    // get records
    pub fn get_records(&self) -> String {
        let records =
            PacketRecordVec::new(self.packets.iter().map(|p| p.records.clone()).collect());
        serde_json::to_string(&records).unwrap()
    }
}

impl VerifyingDataOpt {
    // implement verify interface for VerifyingDataOpt
    pub fn verify(&self, verifying_key: &str) -> Result<()> {
        // verify ecdsa signature
        self.verify_signature(verifying_key)?;

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
