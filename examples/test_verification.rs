use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use anyhow::Result;
use rand::RngCore;
use std::fs;
use verification_data::{VerifyingData, VerifyingDataOpt};
use zktls_att_verification::verification_data;

fn test_full_aes_verification(verifying_key: &str) -> Result<()> {
    let json_content = fs::read_to_string("./data/full_http_responses.json")?;
    println!("jsonContent: {}", json_content);
    let verifying_data: VerifyingData = serde_json::from_str(&json_content)?;
    let result = verifying_data.verify(verifying_key)?;
    println!("verify signature: {}", result);
    Ok(())
}

fn test_partial_aes_verification(verifying_key: &str) -> Result<()> {
    let json_content = fs::read_to_string("./data/partial_http_responses.json")?;
    println!("jsonContent: {}", json_content);
    let verifying_data: VerifyingDataOpt = serde_json::from_str(&json_content)?;
    let result = verifying_data.verify(verifying_key)?;
    println!("verify signature: {}", result);
    Ok(())
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

fn main() -> Result<()> {
    let public_key = fs::read_to_string("keys/verifying_key_k256.txt")?;
    test_full_aes_verification(&public_key)?;
    // test_aes_ecb();
    test_partial_aes_verification(&public_key)?;
    Ok(())
}
