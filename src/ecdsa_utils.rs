use anyhow::Result;
use hex;
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use std::str::FromStr;

pub struct ECDSASigner {
    signing_key: SigningKey,
}

pub struct ECDSAVerifier {
    verifying_key: VerifyingKey,
}

impl ECDSASigner {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<ECDSASigner> {
        let key: SigningKey = SigningKey::from_bytes(&bytes)?;
        Ok(ECDSASigner { signing_key: key })
    }

    pub fn from_hex(bytes: &str) -> Result<ECDSASigner> {
        let bytes = hex::decode(bytes)?;
        Self::from_bytes(bytes)
    }

    pub fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>> {
        let signature: Signature = self.signing_key.try_sign(&message)?;
        Ok(signature.to_vec())
    }
}

impl ECDSAVerifier {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<ECDSAVerifier> {
        let key: VerifyingKey = VerifyingKey::from_sec1_bytes(&bytes)?;
        Ok(ECDSAVerifier { verifying_key: key })
    }

    pub fn from_hex(bytes: &str) -> Result<ECDSAVerifier> {
        let bytes = hex::decode(bytes)?;
        Self::from_bytes(bytes)
    }

    pub fn verify(&self, message: Vec<u8>, signature: &str) -> Result<bool> {
        let signature = Signature::from_str(signature)?;
        match self.verifying_key.verify(&message, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
