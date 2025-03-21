use std::fs;
use hex;
use k256::ecdsa::{SigningKey, Signature, signature::{Signer}};
use anyhow::Result;

use structopt::{StructOpt};
#[derive(StructOpt)]
struct Cli {
    #[structopt(long, short)]
    msg_file: String,
    
    #[structopt(long, short)]
    key_file: String
}

fn main() -> Result<()> {
    let args = Cli::from_args();
    println!("msg file {}", args.msg_file);
    println!("key file {}", args.key_file);

    let key_content = fs::read_to_string(args.key_file)?;
    let key = hex::decode(&key_content)?;
    let signing_key: SigningKey = SigningKey::from_bytes(&key)?;
    println!("sign key {}:{:?}", signing_key.to_bytes().len(), signing_key.to_bytes());

    let msg_content = fs::read_to_string(args.msg_file)?;
    let msg_content = msg_content.trim();
    let message = hex::decode(&msg_content)?;
    let signature: Signature = signing_key.try_sign(&message)?;
    println!("signature {}: {:?}", signature.to_vec().len(), signature.to_vec());

    let signature_hex = hex::encode(&signature.to_vec());
    println!("hex {}", signature_hex);
	Ok(())
}
