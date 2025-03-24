use crate::ecdsa_utils::ECDSAVerifier;
use crate::verification_data::{VerifyingData, VerifyingDataOpt};
use anyhow::Result;

impl VerifyingData {
    // verify ecdsa signature for VerifyingData
    // the format of the message to be signed should be:
    // [record0_nonce, record0_ciphertext, record0_tag, ..., recordN_nonce, recordN_ciphertext, recordN_tag]
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
    // verifying ecdsa signature for VerifyingDataOpt
    // the format of the message to be signed should be:
    // [record0_nonce, record0_ciphertext, ..., recordN_nonce, recordN_ciphertext]
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
