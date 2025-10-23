use anyhow::Result;
use attestation_data::verify_attestation_data;
use std::fs;
use zktls_att_verification::attestation_data;

fn main() -> Result<()> {
    // read attestion data
    let attestation_data = fs::read_to_string("data/attestation_data_hash_with_salt.json").unwrap();
    // read attestation config
    let attestation_config = fs::read_to_string("data/config.json")?;

    let (_attestation_data, _attestation_config, messages) =
        verify_attestation_data(&attestation_data, &attestation_config).unwrap();

    // get json values by json paths in decrypted json string
    let mut json_paths = vec![];
    json_paths.push("$.data[*].baseCcy");
    json_paths.push("$.data[*].instIdCode");

    for i in 0..messages[0].len() {
        let json_value = messages[0][i].get_json_values(&json_paths);
        println!("json value:{:?}", json_value);
    }

    Ok(())
}
