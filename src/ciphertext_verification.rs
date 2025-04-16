use crate::aes_utils::{Aes128Encryptor, Aes128GcmDecryptor};
use crate::verification_data::{BlockInfo, TLSRecordOpt, VerifyingData, VerifyingDataOpt};
use anyhow::{anyhow, Result};

impl VerifyingData {
    // verify full http packet ciphertext
    pub fn verify_ciphertext(&self) -> Result<()> {
        for packet in self.packets.iter() {
            let aes_key = &packet.aes_key;
            let cipher = Aes128GcmDecryptor::from_hex(aes_key)?;

            if packet.record_messages.len() != packet.records.len() {
                return Err(anyhow!(
                    "the length of record_messages and records are not the same"
                ));
            }

            let message_record = packet.record_messages.iter().zip(packet.records.iter());
            for (message, record) in message_record.into_iter() {
                let nonce = hex::decode(&record.nonce)?;

                let aad = hex::decode(&record.aad)?;
                let tag = hex::decode(&record.tag)?;
                let mut ciphertext = hex::decode(&record.ciphertext)?;

                cipher.decrypt(&nonce, &aad, &mut ciphertext, &tag)?;
                let hex_msg = hex::encode(&ciphertext);
                if hex_msg != *message {
                    return Err(anyhow!("check plaintext failed"));
                }
            }
        }
        Ok(())
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
            nonce[index as usize] += 1;
            break;
        }
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
    pub fn verify_ciphertext(&self) -> Result<()> {
        for packet in self.packets.iter() {
            let aes_key = &packet.aes_key;
            let cipher = Aes128Encryptor::from_hex(aes_key)?;

            if packet.record_messages.len() != packet.records.len() {
                return Err(anyhow!(
                    "the length of record_messages and records are not the same"
                ));
            }

            let message_record: Vec<(&String, &TLSRecordOpt)> = packet
                .record_messages
                .iter()
                .zip(packet.records.iter())
                .collect();
            for (record_msg, record) in message_record.into_iter() {
                let nonce = hex::decode(&record.nonce)?;
                let ciphertext = hex::decode(&record.ciphertext)?;

                let counters = compute_counter(&cipher, &nonce, &record.blocks, ciphertext.len())?;
                assert!(ciphertext.len() == counters.len());

                let decrypted_msg: Vec<u8> = counters
                    .iter()
                    .zip(ciphertext.iter())
                    .map(|(a, b)| a ^ b)
                    .collect();
                let hex_msg = hex::encode(&decrypted_msg);
                if *record_msg != hex_msg {
                    return Err(anyhow!("check plaintext failed"));
                }
            }
        }
        Ok(())
    }
}
