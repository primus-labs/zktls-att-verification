use anyhow::Result;
use attestation_data::{AttestationConfig, PublicData};
use std::fs;
use zktls_att_verification::attestation_data;

fn main() -> Result<()> {
    // read attestion data
    let public_data = fs::read_to_string("data/attestation_data_without_aes.json")?;
    let public_data: PublicData = serde_json::from_str(&public_data)?;

    // read attestation config
    let attestation_config = fs::read_to_string("data/config_without_aes.json")?;
    let attestation_config: AttestationConfig = serde_json::from_str(&attestation_config)?;

    // verify attestation data according to attestation config
    public_data.verify_without_aes(&attestation_config)?;

    println!("verify ok");
    Ok(())
}
