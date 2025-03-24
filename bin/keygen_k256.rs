use anyhow::Result;
use std::fs::File;
use std::io::Write;
use structopt::StructOpt;
use zktls_att_verification::ecdsa_utils::{ECDSASigner, ECDSAVerifier};

#[derive(StructOpt)]
struct Cli {
    #[structopt(short, long)]
    key_dir: String,
}

fn main() -> Result<()> {
    let args = Cli::from_args();
    let key_dir = &args.key_dir;

    // generate signing key
    let signer = ECDSASigner::new()?;
    let signing_key = signer.to_hex();
    let mut signing_key_file = File::create_new(String::from(key_dir) + "/signing_k256.key")?;
    write!(signing_key_file, "{}", signing_key)?;

    // generate verifying key
    let verifier = ECDSAVerifier::from_signer(&signer)?;
    let verifying_key = verifier.to_hex();
    let mut verifying_key_file = File::create_new(String::from(key_dir) + "/verifying_k256.key")?;
    write!(verifying_key_file, "{}", verifying_key)?;

    Ok(())
}
