use anyhow::Result;
use hex;
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use rand::RngCore;
use std::str::FromStr;

// ECDSASigner
pub struct ECDSASigner {
    signing_key: SigningKey,
}

// ECDSAVerifier
pub struct ECDSAVerifier {
    verifying_key: VerifyingKey,
}

impl ECDSASigner {
    // construct ECDSASigner from random bytes
    pub fn new() -> Result<ECDSASigner> {
        let mut key: [u8; 32] = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self::from_bytes(key.to_vec())
    }

    // construct ECDSASigner from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<ECDSASigner> {
        let key: SigningKey = SigningKey::from_bytes(&bytes)?;
        Ok(ECDSASigner { signing_key: key })
    }

    // construct ECDSASigner from hex
    pub fn from_hex(bytes: &str) -> Result<ECDSASigner> {
        let bytes = hex::decode(bytes)?;
        Self::from_bytes(bytes)
    }

    // output signing key in bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    // output signing key in hex
    pub fn to_hex(&self) -> String {
        hex::encode(&self.to_bytes())
    }

    // sign message using underlying signing key
    pub fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>> {
        let signature: Signature = self.signing_key.try_sign(&message)?;
        Ok(signature.to_vec())
    }
}

impl ECDSAVerifier {
    // construct ECDSAVerifier from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<ECDSAVerifier> {
        let key: VerifyingKey = VerifyingKey::from_sec1_bytes(&bytes)?;
        Ok(ECDSAVerifier { verifying_key: key })
    }

    // construct ECDSAVerifier from hex
    pub fn from_hex(bytes: &str) -> Result<ECDSAVerifier> {
        let bytes = hex::decode(bytes)?;
        Self::from_bytes(bytes)
    }

    // construct ECDSAVerifier from ECDSASigner
    pub fn from_signer(signer: &ECDSASigner) -> Result<ECDSAVerifier> {
        let signing_key = signer.to_bytes();
        let signing_key = SigningKey::from_bytes(&signing_key)?;

        let verifying_key: VerifyingKey = VerifyingKey::from(signing_key);
        Ok(ECDSAVerifier { verifying_key })
    }

    // output verifying key in bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }

    // output verifying key in hex
    pub fn to_hex(&self) -> String {
        hex::encode(&self.to_bytes())
    }

    // verify signature using underlying verifying key
    pub fn verify(&self, message: Vec<u8>, signature: &str) -> Result<bool> {
        let signature = Signature::from_str(signature)?;
        match self.verifying_key.verify(&message, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
