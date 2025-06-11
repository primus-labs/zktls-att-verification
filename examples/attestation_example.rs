use anyhow::Result;
use attestation_data::AttestationData;
use hex::FromHex;
use std::fs;
use zktls_att_verification::attestation_data;

fn main() -> Result<()> {
    let attestation_data = fs::read_to_string("data/attestation_data.json")?;
    let attestation_data: AttestationData = serde_json::from_str(&attestation_data)?;
    let (messages, records) = attestation_data.verify()?;

    let mut json_paths = vec![];
    json_paths.push("$.data.spotVol");
    json_paths.push("$.data.spotNeed");
    let json_value = messages[0].get_json_values(&json_paths);
    println!("json value:{:?}", json_value);
    println!("records: {}", records);

    Ok(())
}
