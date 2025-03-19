mod aes_verification;
use std::fs;
use aes::{Aes128, cipher::{KeyInit, BlockEncrypt, BlockDecrypt, generic_array::GenericArray}};
use rand::RngCore;

fn test_full_aes_verification() {
    let json_content = fs::read_to_string("./examples/full_http_responses.json").unwrap();
    println!("jsonContent: {}", json_content);
    let msg = aes_verification::verify_full_http_packet_ciphertext(json_content);
    for m in msg.iter() {
        println!("decrypted msg: {}", m);
    }
}

fn test_partial_aes_verification() {
    let json_content = fs::read_to_string("./examples/partial_http_responses.json").unwrap();
    println!("jsonContent: {}", json_content);
    let msg = aes_verification::verify_partial_http_packet_ciphertext(json_content);
    for m in msg.iter() {
        println!("decrypted msg: {}", m);
    }
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
    test_full_aes_verification();
    // test_aes_ecb();
    test_partial_aes_verification();
}
