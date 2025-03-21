pub mod aes_utils;
pub mod ciphertext_verification;
pub mod ecdsa_utils;
pub mod signature_verification;
pub mod verification_data;

use verification_data::{VerifyingData, VerifyingDataOpt};
use anyhow::Result;

impl VerifyingData {
    pub fn verify(&self, verifying_key: &str) -> Result<bool> {
        let result = self.verify_signature(verifying_key)?;
        if !result {
            return Ok(false);
        }

        let result = self.verify_ciphertext()?;
        if !result {
            return Ok(false);
        }
        Ok(true)
    }
}

impl VerifyingDataOpt {
    pub fn verify(&self, verifying_key: &str) -> Result<bool> {
        let result = self.verify_signature(verifying_key)?;
        if !result {
            return Ok(false);
        }

        let result = self.verify_ciphertext()?;
        if !result {
            return Ok(false);
        }
        Ok(true)
    }
}
