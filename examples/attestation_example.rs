use std::fs;
use anyhow::Result;
use hex::FromHex;
use ethers::types::{H256, Signature};
use attestation_data::PublicData;
use zktls_att_verification::attestation_data;

fn main() -> Result<()> {
    let public_data = fs::read_to_string("public_data.json")?;
    let public_data: PublicData = serde_json::from_str(&public_data)?;
    public_data.verify()?;


    Ok(())
}
