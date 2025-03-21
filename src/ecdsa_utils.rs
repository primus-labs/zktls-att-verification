use hex;
use k256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::{Signer, Verifier}};
use std::str::FromStr;

pub struct ECDSASigner {
    signing_key: SigningKey
}

pub struct ECDSAVerifier {
    verifying_key: VerifyingKey
}


impl ECDSASigner {
    pub fn from_bytes(bytes: Vec<u8>) -> ECDSASigner {
        let key: SigningKey = SigningKey::from_bytes(&bytes).unwrap();
        ECDSASigner {
            signing_key: key
        }
    }

    pub fn from_hex(bytes: &str) -> ECDSASigner {
        let bytes = hex::decode(bytes).unwrap();
        Self::from_bytes(bytes)
    }

    pub fn sign(&self, message: Vec<u8>) -> Vec<u8> {
        let signature: Signature = self.signing_key.try_sign(&message).unwrap();
        signature.to_vec()
    }
}

impl ECDSAVerifier {
    pub fn from_bytes(bytes: Vec<u8>) -> ECDSAVerifier {
        let key: VerifyingKey = VerifyingKey::from_sec1_bytes(&bytes).unwrap();
        ECDSAVerifier {
            verifying_key: key
        }
    }

    pub fn from_hex(bytes: &str) -> ECDSAVerifier {
        let bytes = hex::decode(bytes).unwrap();
        Self::from_bytes(bytes)
    }

    pub fn verify(&self, message: Vec<u8>, signature: &str) -> bool {
        println!("verify signature: {}", signature);
        let signature = Signature::from_str(signature).unwrap();
        match self.verifying_key.verify(&message, &signature) {
            Ok(()) => true,
            Err(_) => false,
        }
    }
}
