use anyhow::Result;
use std::fs;
use tls_data::{FullTLSData, PartialTLSData};
use zktls_att_verification::tls_data;

// verify ecdsa signature and aes ciphertext for full http response
fn test_full_aes_verification() -> Result<()> {
    // load full http response
    let json_content = fs::read_to_string("./data/full_http_responses.json")?;
    println!("jsonContent: {}", json_content);

    let full_data: FullTLSData = serde_json::from_str(&json_content)?;
    // verify full http response
    match full_data
        .verify()
    {
        Ok(vec) => {
            println!("verify passed: {:?}", vec);
        }
        Err(e) => println!("verify failed: {}", e),
    };

    Ok(())
}

// verify ecdsa signature and aes ciphertext for partial http response
fn test_partial_aes_verification() -> Result<()> {
    // load partial http response
    let json_content = fs::read_to_string("./data/partial_http_responses.json")?;
    println!("jsonContent: {}", json_content);

    let partial_data: PartialTLSData = serde_json::from_str(&json_content)?;
    // verify parital http response
    match partial_data
        .verify()
    {
        Ok(vec) => println!("verify passed: {:?}", vec),
        Err(e) => println!("verify failed: {}", e),
    };

    Ok(())
}

fn main() -> Result<()> {
    // verify full http response
    test_full_aes_verification()?;

    // verify partial http response
    test_partial_aes_verification()?;

    Ok(())
}
