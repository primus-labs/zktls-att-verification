use serde::{Serialize, Deserialize};
use aes_gcm::aead::KeyInit;
use aes_gcm::{Aes128Gcm, AeadInPlace, Nonce};
use hex;
use aes::{Aes128, cipher::BlockEncrypt, cipher::generic_array::GenericArray};

// TLS Record
#[derive(Debug, Serialize, Deserialize)]
pub struct TLSRecord {
    pub ciphertext: String, // tls record ciphertext
    pub nonce: String,  // tls record nonce
    pub aad: String,   // tls associated data
    pub tag: String,   // tls record tag
    pub blocks_to_redact: Vec<u32>,   // blocks to redact
    pub blocks_to_extract: Vec<u32>  // blocks to extract
}

// HTTP Packet
#[derive(Debug, Serialize, Deserialize)]
pub struct HTTPPacket {
    pub aes_key: String,  // aes key for encrypting/decrypting
    pub records: Vec<TLSRecord>,  // TLS Records, constructing full http packet
}

// Data to verify
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyingData {
    pub packets: Vec<HTTPPacket> // HTTP Packet 
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockInfo {
    pub id: usize,   // block id
    pub mask: Vec<u8>  // block mask, 1u8 indicate this char is extracted
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TLSRecordOpt {
    pub ciphertext: String,  // ciphertext in tls record, it is concated according to field `blocks`
    pub nonce: String,  // nonce for decrypting the ciphertext
    pub blocks: Vec<BlockInfo> // show how to construct the ciphertext. Note the length of ciphertext and the sum of the length of all bytes in all blocks should be equal
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HTTPPacketOpt {
    pub aes_key: String,  // aes key for decrypting http packet
    pub records: Vec<TLSRecordOpt>  // TLS Records, construct partial http packet
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyingDataOpt {
    pub packets: Vec<HTTPPacketOpt> // partial HTTP Packet
}

// verify full http packet ciphertext, see `examples/full_http_responses.json` for the format of `json_content`
pub fn verify_full_http_packet_ciphertext(json_content: String) -> Vec<String> {
    let verifying_data: VerifyingData = serde_json::from_str(&json_content).unwrap();

    let mut all_packet = vec![];
    for packet in verifying_data.packets.iter() {
        let mut packet_msg: String = String::new();
        let aes_key = &packet.aes_key;
        let aes_key = hex::decode(aes_key).unwrap();
        
        let cipher = Aes128Gcm::new_from_slice(&aes_key).unwrap();

        for record in packet.records.iter() {
            let nonce = hex::decode(&record.nonce).unwrap();
            let nonce: [u8; 12] = nonce.try_into().unwrap();
            let nonce = Nonce::from(nonce);
            let aad = hex::decode(&record.aad).unwrap();
            let tag = hex::decode(&record.tag).unwrap();
            let mut ciphertext = hex::decode(&record.ciphertext).unwrap();

            cipher.decrypt_in_place_detached(&nonce, aad.as_slice(), &mut ciphertext, tag.as_slice().into()).unwrap();

            let msg = String::from_utf8_lossy(ciphertext.as_slice());
            packet_msg += &msg;
        }

        all_packet.push(packet_msg);
    }
    all_packet
}

// increase the varying part of nonce
fn incr_nonce(nonce: &mut [u8; 4]) {
    let mut index: i8 = 3;
    while index >= 0 {
        if nonce[index as usize] == 255u8 {
            nonce[index as usize] = 0;
            index -= 1;
        }
        else {
            nonce[index as usize] = nonce[index as usize] + 1;
            break;
        }
    }
}

// compute necessary counter according `blocks`
fn compute_counter(cipher: &Aes128, nonce: &Vec<u8>, blocks: &Vec<BlockInfo>, len: usize) -> Vec<u8>{
    let mut result: Vec<u8> = vec![];
    let mut nonce_index: [u8; 4] = [0u8; 4];

    let block_len: Vec<usize> = blocks.iter().map(|info| info.mask.iter().sum::<u8>() as usize).collect();
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

            let mut full_nonce = *GenericArray::from_slice(full_nonce.as_slice());
            cipher.encrypt_block(&mut full_nonce);
            let masked_data: Vec<u8> = full_nonce.into_iter().zip(mask.iter()).filter(|(_a, b)| *b == &1u8).map(|(a, _b)| a).collect();
            result.extend(masked_data);

            block_index += 1;
        }
    }
    result
}

// verify partial http packet, See `examples/partial_http_responses.json` for the format of `json_content`
pub fn verify_partial_http_packet_ciphertext(json_content: String) -> Vec<String> {
    let verifying_data: VerifyingDataOpt = serde_json::from_str(&json_content).unwrap();

    let mut all_packet = vec![];
    for packet in verifying_data.packets.iter() {
        let mut packet_msg: String = String::new();
        let aes_key = &packet.aes_key;
        let aes_key = hex::decode(aes_key).unwrap();
        let aes_key = GenericArray::from_slice(&aes_key);

        let cipher = Aes128::new(aes_key);

        for record in packet.records.iter() {
            let nonce = hex::decode(&record.nonce).unwrap();
            let ciphertext = hex::decode(&record.ciphertext).unwrap();

            let counters = compute_counter(&cipher, &nonce, &record.blocks, ciphertext.len());
            assert!(ciphertext.len() == counters.len());

            let decrypted_msg: Vec<u8> = counters.iter().zip(ciphertext.iter()).map(|(a, b)| a ^ b).collect();
            let decrypted_msg = String::from_utf8_lossy(&decrypted_msg);
            packet_msg += &decrypted_msg;

        }
        all_packet.push(packet_msg);
    }
    all_packet
}
