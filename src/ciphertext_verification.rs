use crate::aes_utils::{Aes128Encryptor};
use crate::verification_data::{
    BlockInfo, JsonData, VerifyingData, VerifyingDataOpt,
};
use anyhow::{Result};

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

impl VerifyingData {
    // verify full http packet ciphertext
    pub fn verify_ciphertext(&self, aes_key: &str) -> Result<Vec<JsonData>> {
        let mut result = vec![];
        let cipher = Aes128Encryptor::from_hex(aes_key)?;

        for packet in self.packets.iter() {
            let mut complete_json = String::new();
            for record in packet.records.iter() {
                let nonce = hex::decode(&record.nonce)?;
                let ciphertext = hex::decode(&record.ciphertext)?;
                let ciphertext_len = ciphertext.len();

                let mut nonce_index: [u8; 4] = [0u8; 4];
                incr_nonce(&mut nonce_index);

                let mut counters = vec![];
                while counters.len() < ciphertext_len {
                    incr_nonce(&mut nonce_index);
                    let mut full_nonce = nonce.clone();
                    full_nonce.extend(nonce_index);
                    let full_nonce = cipher.encrypt(&mut full_nonce)?;
                    counters.extend(full_nonce);
                }

                counters = counters[..ciphertext_len].to_vec();

                let plaintext = counters
                    .iter()
                    .zip(ciphertext.iter())
                    .map(|(c1, c2)| c1 ^ c2)
                    .collect::<Vec<u8>>();
                let plaintext = String::from_utf8(plaintext)?;

                let mut json_payload = String::new();
                for positions in record.json_block_positions.iter() {
                    let text: String = plaintext
                        .chars()
                        .skip(positions[0] as usize)
                        .take((positions[1] - positions[0] + 1) as usize)
                        .collect();
                    json_payload += &text;
                }
                complete_json += &json_payload;
            }
            let json_data = JsonData::new(&complete_json);
            result.push(json_data);
        }
        Ok(result)
    }
}

// compute necessary counter according `blocks`
fn compute_counter(
    cipher: &Aes128Encryptor,
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

            let full_nonce = cipher.encrypt(&mut full_nonce)?;
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

impl VerifyingDataOpt {
    // verify partial http packet`
    pub fn verify_ciphertext(&self, aes_key: &str) -> Result<Vec<JsonData>> {
        let mut result = vec![];
        let cipher = Aes128Encryptor::from_hex(aes_key)?;

        for packet in self.packets.iter() {
            let mut complete_json = String::new();
            for record in packet.records.iter() {
                let nonce = hex::decode(&record.nonce)?;
                let ciphertext = hex::decode(&record.ciphertext)?;

                let counters = compute_counter(&cipher, &nonce, &record.blocks, ciphertext.len())?;
                assert!(ciphertext.len() == counters.len());

                let decrypted_msg: Vec<u8> = counters
                    .iter()
                    .zip(ciphertext.iter())
                    .map(|(a, b)| a ^ b)
                    .collect();
                let text = String::from_utf8(decrypted_msg)?;
                complete_json += &text;
            }
            let json_data = JsonData::new(&complete_json);
            result.push(json_data);
        }
        Ok(result)
    }
}
