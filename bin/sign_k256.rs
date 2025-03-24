use anyhow::Result;
use hex;
use std::fs;
use zktls_att_verification::ecdsa_utils::ECDSASigner;

use structopt::StructOpt;
#[derive(StructOpt)]
struct Cli {
    #[structopt(long, short)]
    msg_file: String,

    #[structopt(long, short)]
    key_file: String,
}

fn main() -> Result<()> {
    let args = Cli::from_args();
    let key_file = &args.key_file;
    let msg_file = &args.msg_file;

    // load signing key
    let signing_key = fs::read_to_string(key_file)?;
    let signing_key = signing_key.trim();
    let signer = ECDSASigner::from_hex(&signing_key)?;

    // load message to be signed
    let msg_content = fs::read_to_string(msg_file)?;
    let msg_content = msg_content.trim();
    let message = hex::decode(&msg_content)?;

    // sign message
    let signature = signer.sign(message)?;
    let signature_hex = hex::encode(&signature);
    println!("signature: {}", signature_hex);
    Ok(())
}
