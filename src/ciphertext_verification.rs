use crate::aes_utils::{Aes128Encryptor, Aes128GcmDecryptor};
use crate::verification_data::{BlockInfo, VerifyingData, VerifyingDataOpt};
use anyhow::Result;

impl VerifyingData {
    // verify full http packet ciphertext
    pub fn verify_ciphertext(&self) -> Result<bool> {
        let mut all_packet = vec![];
        for packet in self.packets.iter() {
            let mut packet_msg: String = String::new();
            let aes_key = &packet.aes_key;
            let cipher = Aes128GcmDecryptor::from_hex(&aes_key)?;

            for record in packet.records.iter() {
                let nonce = hex::decode(&record.nonce)?;

                let aad = hex::decode(&record.aad)?;
                let tag = hex::decode(&record.tag)?;
                let mut ciphertext = hex::decode(&record.ciphertext)?;

                let decrypted_msg = cipher.decrypt(&nonce, &aad, &mut ciphertext, &tag)?;

                let msg = String::from_utf8_lossy(decrypted_msg.as_slice());
                packet_msg += &msg;
            }

            all_packet.push(packet_msg);
        }
        Ok(true)
    }
}

// increase the varying part of nonce
fn incr_nonce(nonce: &mut [u8; 4]) {
    let mut index: i8 = 3;
    while index >= 0 {
        if nonce[index as usize] == 255u8 {
            nonce[index as usize] = 0;
            index -= 1;
        } else {
            nonce[index as usize] = nonce[index as usize] + 1;
            break;
        }
    }
}

// compute necessary counter according `blocks`
fn compute_counter(
    cipher: &Aes128Encryptor,
    nonce: &Vec<u8>,
    blocks: &Vec<BlockInfo>,
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
            let mut full_nonce = nonce.clone();
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
    pub fn verify_ciphertext(&self) -> Result<bool> {
        let mut all_packet = vec![];
        for packet in self.packets.iter() {
            let mut packet_msg: String = String::new();
            let aes_key = &packet.aes_key;

            let cipher = Aes128Encryptor::from_hex(aes_key)?;

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
                let decrypted_msg = String::from_utf8_lossy(&decrypted_msg);
                packet_msg += &decrypted_msg;
            }
            all_packet.push(packet_msg);
        }
        Ok(true)
    }
}
