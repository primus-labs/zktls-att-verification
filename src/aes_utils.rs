use aes_gcm::aead::KeyInit;
use aes_gcm::{Aes128Gcm, AeadInPlace, Nonce};
use aes::{Aes128, cipher::BlockEncrypt, cipher::generic_array::GenericArray};
use anyhow::{anyhow, Result};

pub struct Aes128GcmDecryptor {
    cipher: Aes128Gcm
}

impl Aes128GcmDecryptor {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let cipher = Aes128Gcm::new_from_slice(&bytes).map_err(|e| anyhow!("new aes128gcm error: {}", e))?;
        Ok(Self {
            cipher
        })
    }

    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        Self::from_bytes(bytes)
    }

    pub fn decrypt(&self, nonce: &[u8], aad: &[u8], ciphertext: &mut [u8], tag: &[u8]) -> Result<Vec<u8>> { 
        let nonce: [u8; 12] = nonce.try_into()?;
        let nonce = Nonce::from(nonce);
        self.cipher.decrypt_in_place_detached(&nonce, aad, ciphertext, tag.into()).map_err(|e| anyhow!("decrypt error: {}", e))?;
        Ok(ciphertext.to_vec())
    }

}


pub struct Aes128Encryptor {
    cipher: Aes128
}

impl Aes128Encryptor {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let aes_key = GenericArray::from_slice(&bytes);
        let cipher = Aes128::new(aes_key);
        Ok(Self {
            cipher
        })
    }

    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        Self::from_bytes(bytes)
    }

    pub fn encrypt(&self, msg: &mut Vec<u8>) -> Result<Vec<u8>>{
        let mut msg = *GenericArray::from_slice(msg);
        self.cipher.encrypt_block(&mut msg);
        Ok(msg.to_vec())
    }
    
}
