pub mod aes_utils;
pub mod ciphertext_verification;
pub mod ecdsa_utils;
pub mod signature_verification;
pub mod verification_data;

use anyhow::Result;
use verification_data::{VerifyingData, VerifyingDataOpt};

impl VerifyingData {
    // implement verify interface for VerifyingData
    pub fn verify(&self, verifying_key: &str) -> Result<bool> {
        // verify ecdsa signature
        let result = self.verify_signature(verifying_key)?;
        if !result {
            return Ok(false);
        }

        // verify aes ciphertext
        let result = self.verify_ciphertext()?;
        if !result {
            return Ok(false);
        }
        Ok(true)
    }
}

impl VerifyingDataOpt {
    // implement verify interface for VerifyingDataOpt
    pub fn verify(&self, verifying_key: &str) -> Result<bool> {
        // verify ecdsa signature
        let result = self.verify_signature(verifying_key)?;
        if !result {
            return Ok(false);
        }

        // verify aes ciphertext
        let result = self.verify_ciphertext()?;
        if !result {
            return Ok(false);
        }
        Ok(true)
    }
}
