use aes_gcm::aead::KeyInit;
use aes_gcm::{Aes128Gcm, AeadInPlace, Nonce};
use aes::{Aes128, cipher::BlockEncrypt, cipher::generic_array::GenericArray};

pub struct Aes128GcmDecryptor {
    cipher: Aes128Gcm
}

impl Aes128GcmDecryptor {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let cipher = Aes128Gcm::new_from_slice(&bytes).unwrap();
        Self {
            cipher
        }
    }

    pub fn from_hex(hex: &str) -> Self {
        let bytes = hex::decode(hex).unwrap();
        Self::from_bytes(bytes)
    }

    pub fn decrypt(&self, nonce: &[u8], aad: &[u8], ciphertext: &mut [u8], tag: &[u8]) -> Vec<u8> { 
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let nonce = Nonce::from(nonce);
        self.cipher.decrypt_in_place_detached(&nonce, aad, ciphertext, tag.into()).unwrap();
        ciphertext.to_vec()
    }

}


pub struct Aes128Encryptor {
    cipher: Aes128
}

impl Aes128Encryptor {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let aes_key = GenericArray::from_slice(&bytes);
        let cipher = Aes128::new(aes_key);
        Self {
            cipher
        }
    }

    pub fn from_hex(hex: &str) -> Self {
        let bytes = hex::decode(hex).unwrap();
        Self::from_bytes(bytes)
    }

    pub fn encrypt(&self, msg: &mut Vec<u8>) -> Vec<u8>{
        let mut msg = *GenericArray::from_slice(msg);
        self.cipher.encrypt_block(&mut msg);
        msg.to_vec()
    }
    
}
