use anyhow::Result;
use attestation_data::{AttestationData, AttestationConfig};
use std::fs;
use zktls_att_verification::attestation_data;

fn main() -> Result<()> {
    let attestation_data = fs::read_to_string("data/attestation_data.json")?;
    let attestation_data: AttestationData = serde_json::from_str(&attestation_data)?;

    let attestation_config = fs::read_to_string("data/config.json")?;
    let attestation_config: AttestationConfig = serde_json::from_str(&attestation_config)?;

    let messages = attestation_data.verify(&attestation_config)?;

    let mut json_paths = vec![];
    json_paths.push("$.data.spotVol");
    json_paths.push("$.data.spotNeed");
    let json_value = messages[0].get_json_values(&json_paths);
    println!("json value:{:?}", json_value);

    Ok(())
}
