use aes::{cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit}, Aes128};
use anyhow::{Result};

// Aes128Encryptor
pub struct Aes128Encryptor {
    cipher: Aes128,
}

impl Aes128Encryptor {
    // construct Aes128Encryptor from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let cipher = Aes128::new_from_slice(&bytes)?;
        Ok(Self { cipher })
    }

    // construct Aes128Encryptor from hex
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        Self::from_bytes(bytes)
    }

    // encrypt one block
    pub fn encrypt(&self, msg: &mut [u8]) -> Result<Vec<u8>> {
        let mut msg = *GenericArray::from_slice(msg);
        self.cipher.encrypt_block(&mut msg);
        Ok(msg.to_vec())
    }
}
