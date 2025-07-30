use anyhow::Result;
use attestation_data::{AttestationConfig, AttestationData};
use std::fs;
use zktls_att_verification::attestation_data;

fn main() -> Result<()> {
    // read attestion data
    let attestation_data = fs::read_to_string("data/attestation_data.json")?;
    let attestation_data: AttestationData = serde_json::from_str(&attestation_data)?;

    // read attestation config
    let attestation_config = fs::read_to_string("data/config.json")?;
    let attestation_config: AttestationConfig = serde_json::from_str(&attestation_config)?;

    // verify attestation data according to attestation config
    let messages = attestation_data.verify(&attestation_config)?;

    // get json values by json paths in decrypted json string
    let mut json_paths = vec![];
    json_paths.push("$.data.spotVol"); // string
    json_paths.push("$.data.b1NextLevel"); // number
    json_paths.push("$.data.spotFree.show"); // boolean
    json_paths.push("$.data.vipGift[*].itemInfos[0].cardParamDto.noticeMsgParamDto"); // null
    json_paths.push("$.data.spotFree");  // object
    json_paths.push("$.data.spotFree.coinNameList");  // array

    let json_value = messages[0].get_json_values(&json_paths);
    println!("json value:{:?}", json_value);

    Ok(())
}
