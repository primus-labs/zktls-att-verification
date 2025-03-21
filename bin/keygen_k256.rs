use rand::{RngCore};
use std::fs::File;
use std::io::{Write};
use hex;
use k256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::{Signer, Verifier}};

fn main() {
    let mut key: [u8; 16] = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    let signing_key: SigningKey = SigningKey::from_bytes(&key.to_vec()).unwrap();
    println!("sign key {}:{:?}", signing_key.to_bytes().len(), signing_key.to_bytes());
    let mut signing_key_file = File::create_new("examples/signing_key_k256.txt").unwrap();
    write!(signing_key_file, "{}", hex::encode(signing_key.to_bytes())).unwrap();

    let verifying_key: VerifyingKey = VerifyingKey::from(&signing_key);
    println!("verifying key {}: {:?}", verifying_key.to_bytes().len(), verifying_key.to_bytes());
    let mut verifying_key_file = File::create_new("examples/verifying_key_k256.txt").unwrap();
    write!(verifying_key_file, "{}", hex::encode(verifying_key.to_bytes())).unwrap();

    let message = b"Hello, ECDSA";
    let signature: Signature = signing_key.try_sign(&message.to_vec()).unwrap();
    println!("signature {}: {:?}", signature.to_vec().len(), signature.to_vec());

    verifying_key.verify(&message.to_vec(), &signature).unwrap();
}
