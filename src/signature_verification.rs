use crate::ecdsa_utils::ECDSAVerifier;
use crate::verification_data::{VerifyingData, VerifyingDataOpt};
use anyhow::Result;

impl VerifyingData {
    pub fn verify_signature(&self, verifying_key: &str) -> Result<bool> {
        let verifier = ECDSAVerifier::from_hex(verifying_key)?;

        for packet in self.packets.iter() {
            let ecdsa_signature = &packet.ecdsa_signature;
            let mut signed_data = vec![];

            for record in packet.records.iter() {
                let nonce = hex::decode(&record.nonce)?;
                let ciphertext = hex::decode(&record.ciphertext)?;
                let tag = hex::decode(&record.tag)?;

                signed_data.extend(&nonce);
                signed_data.extend(&ciphertext);
                signed_data.extend(&tag);
            }

            let result = verifier.verify(signed_data, ecdsa_signature)?;
            if !result {
                return Ok(false);
            }
        }
        return Ok(true);
    }
}

impl VerifyingDataOpt {
    pub fn verify_signature(&self, verifying_key: &str) -> Result<bool> {
        let verifier = ECDSAVerifier::from_hex(verifying_key)?;

        for packet in self.packets.iter() {
            let ecdsa_signature = &packet.ecdsa_signature;
            let mut signed_data = vec![];

            for record in packet.records.iter() {
                let nonce = hex::decode(&record.nonce)?;
                let ciphertext = hex::decode(&record.ciphertext)?;

                signed_data.extend(&nonce);
                signed_data.extend(&ciphertext);
            }

            let result = verifier.verify(signed_data, ecdsa_signature)?;
            if !result {
                return Ok(false);
            }
        }
        return Ok(true);
    }
}
