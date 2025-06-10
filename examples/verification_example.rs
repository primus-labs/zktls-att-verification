use anyhow::Result;
use std::fs;
use verification_data::{VerifyingData, VerifyingDataOpt};
use zktls_att_verification::verification_data;

// verify ecdsa signature and aes ciphertext for full http response
fn test_full_aes_verification(verifying_key: &str) -> Result<()> {
    // load full http response
    let json_content = fs::read_to_string("./data/full_http_responses.json")?;
    println!("jsonContent: {}", json_content);

    let verifying_data: VerifyingData = serde_json::from_str(&json_content)?;
    // verify full http response
    match verifying_data.verify() {
        Ok(vec) => {
            println!("verify passed: {:?}", vec);
        }
        Err(e) => println!("verify failed: {}", e),
    };

    let aes_keys = verifying_data.get_aes_keys();
    let signatures = verifying_data.get_signatures();
    let messages = verifying_data.get_messages();
    let records = verifying_data.get_records();

    println!("aes keys: {}", aes_keys);
    println!("signatures: {}", signatures);
    println!("messages: {}", messages);
    println!("records: {}", records);

    Ok(())
}

// verify ecdsa signature and aes ciphertext for partial http response
fn test_partial_aes_verification(verifying_key: &str) -> Result<()> {
    // load partial http response
    let json_content = fs::read_to_string("./data/partial_http_responses.json")?;
    println!("jsonContent: {}", json_content);

    let verifying_data: VerifyingDataOpt = serde_json::from_str(&json_content)?;
    // verify parital http response
    match verifying_data.verify() {
        Ok(()) => println!("verify passed"),
        Err(e) => println!("verify failed: {}", e),
    };

    let aes_keys = verifying_data.get_aes_keys();
    let signatures = verifying_data.get_signatures();
    let messages = verifying_data.get_messages();
    let records = verifying_data.get_records();

    println!("aes keys: {}", aes_keys);
    println!("signatures: {}", signatures);
    println!("messages: {}", messages);
    println!("recrods: {}", records);

    Ok(())
}

fn main() -> Result<()> {
    // load verifying key
    let public_key = fs::read_to_string("keys/verifying_k256.key")?;

    // verify full http response
    test_full_aes_verification(&public_key)?;

    // verify partial http response
    test_partial_aes_verification(&public_key)?;

    Ok(())
}
