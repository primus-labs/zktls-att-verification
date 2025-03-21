use zktls_att_verification::verification_data;
use verification_data::{VerifyingData, VerifyingDataOpt};
use std::fs;
use aes::{Aes128, cipher::{KeyInit, BlockEncrypt, BlockDecrypt, generic_array::GenericArray}};
use rand::RngCore;

fn test_full_aes_verification(verifying_key: &str) {
    let json_content = fs::read_to_string("./examples/full_http_responses.json").unwrap();
    println!("jsonContent: {}", json_content);
    let verifying_data: VerifyingData = serde_json::from_str(&json_content).unwrap();
    let msg = verifying_data.verify_ciphertext();
    for m in msg.iter() {
        println!("decrypted msg: {}", m);
    }
    let result = verifying_data.verify_signature(verifying_key);
    println!("verify signature: {}", result);
}

fn test_partial_aes_verification(verifying_key: &str) {
    let json_content = fs::read_to_string("./examples/partial_http_responses.json").unwrap();
    println!("jsonContent: {}", json_content);
    let verifying_data: VerifyingDataOpt = serde_json::from_str(&json_content).unwrap();
    let msg = verifying_data.verify_ciphertext();
    for m in msg.iter() {
        println!("decrypted msg: {}", m);
    }
    let result = verifying_data.verify_signature(verifying_key);
    println!("verify signature: {}", result);
}

fn _test_aes_ecb() {
    let mut key: [u8; 16] = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    println!("key: {:?}", key);
    let key = GenericArray::from_slice(&key);

    let mut msg: [u8; 16] = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut msg);
    println!("msg: {:?}", msg);
    let mut msg = *GenericArray::from_slice(&msg);

    let cipher = Aes128::new(key);
    cipher.encrypt_block(&mut msg);
    println!("ciphertext: {:?}", msg);

    cipher.decrypt_block(&mut msg);
    println!("decrypted: {:?}", msg);
}

fn main() {
    let public_key = fs::read_to_string("examples/verifying_key_k256.txt").unwrap();
    test_full_aes_verification(&public_key);
    // test_aes_ecb();
    test_partial_aes_verification(&public_key);
}
