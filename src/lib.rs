pub mod aes_utils;
pub mod ciphertext_verification;
pub mod ecdsa_utils;
pub mod signature_verification;
pub mod verification_data;

use anyhow::Result;
use verification_data::{VerifyingData, VerifyingDataOpt};

impl VerifyingData {
    // implement verify interface for VerifyingData
    pub fn verify(&self, verifying_key: &str) -> Result<()> {
        // verify ecdsa signature
        self.verify_signature(verifying_key)?;

        // verify aes ciphertext
        self.verify_ciphertext()?;
        Ok(())
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
}
