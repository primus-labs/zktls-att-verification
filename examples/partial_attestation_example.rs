use anyhow::Result;
use attestation_data::verify_attestation_data;
use std::fs;
use zktls_att_verification::attestation_data;

fn main() -> Result<()> {
    // read attestion data
    let attestation_data = fs::read_to_string("data/partial_attestation_data.json")?;
    // read attestation config
    let attestation_config = fs::read_to_string("data/partial_config.json")?;

    let (_attestation_data, _attestation_config, messages) =
        verify_attestation_data(&attestation_data, &attestation_config)?;

    // get json values by json paths in decrypted json string
    let mut json_paths = vec![];
    json_paths.push("$.data.user.result.legacy.followers_count"); // number
    json_paths.push("$.data.user.result.core.screen_name"); // string

    let json_value = messages[0].get_json_values(&json_paths);
    println!("json value:{:?}", json_value);

    Ok(())
}
