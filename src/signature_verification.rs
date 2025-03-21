use crate::ecdsa_utils::ECDSAVerifier;
use crate::verification_data::{VerifyingData, VerifyingDataOpt};

impl VerifyingData {
    pub fn verify_signature(&self, verifying_key: &str) -> bool {
        let verifier = ECDSAVerifier::from_hex(verifying_key);

        for packet in self.packets.iter() {
            let ecdsa_signature = &packet.ecdsa_signature;
            let mut signed_data = vec![];

            for record in packet.records.iter() {
                let nonce = hex::decode(&record.nonce).unwrap();
                let ciphertext = hex::decode(&record.ciphertext).unwrap();
                let tag = hex::decode(&record.tag).unwrap();

                signed_data.extend(&nonce);
                signed_data.extend(&ciphertext);
                signed_data.extend(&tag);
            }

            let result = verifier.verify(signed_data, ecdsa_signature);
            if !result {
                return false;
            }
        }
        return true;
    }
}

impl VerifyingDataOpt {
    pub fn verify_signature(&self, verifying_key: &str) -> bool {
        let verifier = ECDSAVerifier::from_hex(verifying_key);

        for packet in self.packets.iter() {
            let ecdsa_signature = &packet.ecdsa_signature;
            let mut signed_data = vec![];

            for record in packet.records.iter() {
                let nonce = hex::decode(&record.nonce).unwrap();
                let ciphertext = hex::decode(&record.ciphertext).unwrap();

                signed_data.extend(&nonce);
                signed_data.extend(&ciphertext);
            }

            let result = verifier.verify(signed_data, ecdsa_signature);
            if !result {
                return false;
            }
        }
        return true;
    }
}
