use aes::{cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit}, Aes128};
use serde::{Deserialize, Serialize};
use anyhow::{Result};

// AES Counter block info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockInfo {
    pub id: usize,     // block id
    pub mask: Vec<u8>, // block mask, 1u8 indicate this char is extracted
}

// increase the varying part of nonce
fn incr_nonce(nonce: &mut [u8; 4]) {
    let mut index: i8 = 3;
    while index >= 0 {
        if nonce[index as usize] == 255u8 {
            nonce[index as usize] = 0;
            index -= 1;
        } else {
            nonce[index as usize] += 1;
            break;
        }
    }
}


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
    fn encrypt(&self, msg: &mut [u8]) -> Result<Vec<u8>> {
        let mut msg = *GenericArray::from_slice(msg);
        self.cipher.encrypt_block(&mut msg);
        Ok(msg.to_vec())
    }

    pub fn compute_continuous_counters(
        &self,
        nonce: &[u8],
        len: usize,
    ) -> Result<Vec<u8>> {
        let mut result: Vec<u8> = vec![];
        let mut nonce_index: [u8; 4] = [0u8; 4];
    
        incr_nonce(&mut nonce_index);
        while result.len() < len {
            incr_nonce(&mut nonce_index);
            let mut full_nonce = nonce.to_vec();
            full_nonce.extend(nonce_index);
    
            let encrypted_counter = self.encrypt(&mut full_nonce)?;
            result.extend(encrypted_counter);
        }
        if result.len() != len {
            result = result[..len].to_vec()
        }
        Ok(result)
    }

    // compute necessary counter according `blocks`
    pub fn compute_selective_counters(
        &self,
        nonce: &[u8],
        blocks: &[BlockInfo],
        len: usize,
    ) -> Result<Vec<u8>> {
        let mut result: Vec<u8> = vec![];
        let mut nonce_index: [u8; 4] = [0u8; 4];
    
        let block_len: Vec<usize> = blocks
            .iter()
            .map(|info| info.mask.iter().sum::<u8>() as usize)
            .collect();
        let all_len: usize = block_len.iter().sum();
        assert!(all_len == len);
    
        let mut block_index: usize = 0;
        incr_nonce(&mut nonce_index);
        while result.len() < len {
            incr_nonce(&mut nonce_index);
            let nonce_u32: u32 = u32::from_be_bytes(nonce_index);
            if nonce_u32 as usize == blocks[block_index].id + 2 {
                let mask = &blocks[block_index].mask;
                let mut full_nonce = nonce.to_vec();
                full_nonce.extend(nonce_index);
    
                let full_nonce = self.encrypt(&mut full_nonce)?;
                let masked_data: Vec<u8> = full_nonce
                    .into_iter()
                    .zip(mask.iter())
                    .filter(|(_a, b)| *b == &1u8)
                    .map(|(a, _b)| a)
                    .collect();
                result.extend(masked_data);
    
                block_index += 1;
            }
        }
        Ok(result)
    }
}
