use zktls_att_verification::verification_data;
use verification_data::{VerifyingDataOpt};
use std::fs;
use std::time::Instant;
use anyhow::Result;

fn test_partial_aes_verification(verifying_key: &str, filename: &str) -> Result<()>{
    let now = Instant::now();
    for _ in 0..10000 {
        let json_content = fs::read_to_string(filename)?;
        let verifying_data: VerifyingDataOpt = serde_json::from_str(&json_content)?;
        let _msg = verifying_data.verify_ciphertext();
        let _result = verifying_data.verify_signature(verifying_key);
    }
    println!("test partial cost: {}", Instant::now().duration_since(now).as_millis());
    Ok(())
}

fn main() -> Result<()>{
    let public_key = fs::read_to_string("examples/verifying_key_k256.txt")?;
    test_partial_aes_verification(&public_key, "./benches/bench16.json")?;
    test_partial_aes_verification(&public_key, "./benches/bench256.json")?;
    test_partial_aes_verification(&public_key, "./benches/bench1024.json")?;
    test_partial_aes_verification(&public_key, "./benches/bench2048.json")?;
    Ok(())
}
