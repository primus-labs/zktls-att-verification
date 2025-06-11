use anyhow::Result;
use std::fs;
use verification_data::{FullData, PartialData};
use zktls_att_verification::verification_data;

// verify ecdsa signature and aes ciphertext for full http response
fn test_full_aes_verification() -> Result<()> {
    // load full http response
    let json_content = fs::read_to_string("./data/full_http_responses.json")?;
    println!("jsonContent: {}", json_content);

    let full_data: FullData = serde_json::from_str(&json_content)?;
    // verify full http response
    match full_data.verifying_data.verify(&full_data.private_data.aes_key) {
        Ok(vec) => {
            println!("verify passed: {:?}", vec);
        }
        Err(e) => println!("verify failed: {}", e),
    };

    let records = full_data.verifying_data.get_records();

    println!("records: {}", records);

    Ok(())
}

// verify ecdsa signature and aes ciphertext for partial http response
fn test_partial_aes_verification() -> Result<()> {
    // load partial http response
    let json_content = fs::read_to_string("./data/partial_http_responses.json")?;
    println!("jsonContent: {}", json_content);

    let partial_data: PartialData = serde_json::from_str(&json_content)?;
    // verify parital http response
    match partial_data.verifying_data.verify(&partial_data.private_data.aes_key) {
        Ok(()) => println!("verify passed"),
        Err(e) => println!("verify failed: {}", e),
    };

    let records = partial_data.verifying_data.get_records();

    println!("recrods: {}", records);

    Ok(())
}

fn main() -> Result<()> {
    // verify full http response
    test_full_aes_verification()?;

    // verify partial http response
    test_partial_aes_verification()?;

    Ok(())
}
