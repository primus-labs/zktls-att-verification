use aes::{cipher::generic_array::GenericArray, cipher::BlockEncrypt, Aes128};
use aes_gcm::aead::KeyInit;
use aes_gcm::{AeadInPlace, Aes128Gcm, Nonce};
use anyhow::{anyhow, Result};

// Aes128GcmDecryptor
pub struct Aes128GcmDecryptor {
    cipher: Aes128Gcm,
}

impl Aes128GcmDecryptor {
    // contruct Aes128GcmDecryptor from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let cipher =
            Aes128Gcm::new_from_slice(&bytes).map_err(|e| anyhow!("new aes128gcm error: {}", e))?;
        Ok(Self { cipher })
    }

    // construct Aes128GcmDecryptor from hex
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        Self::from_bytes(bytes)
    }

    // decrypt ciphertext
    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce: [u8; 12] = nonce.try_into()?;
        let nonce = Nonce::from(nonce);
        self.cipher
            .decrypt_in_place_detached(&nonce, aad, ciphertext, tag.into())
            .map_err(|e| anyhow!("decrypt error: {}", e))?;
        Ok(ciphertext.to_vec())
    }
}

// Aes128Encryptor
pub struct Aes128Encryptor {
    cipher: Aes128,
}

impl Aes128Encryptor {
    // construct Aes128Encryptor from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let aes_key = GenericArray::from_slice(&bytes);
        let cipher = Aes128::new(aes_key);
        Ok(Self { cipher })
    }

    // construct Aes128Encryptor from hex
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        Self::from_bytes(bytes)
    }

    // encrypt one block
    pub fn encrypt(&self, msg: &mut Vec<u8>) -> Result<Vec<u8>> {
        let mut msg = *GenericArray::from_slice(msg);
        self.cipher.encrypt_block(&mut msg);
        Ok(msg.to_vec())
    }
}
