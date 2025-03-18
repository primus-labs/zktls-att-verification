mod aes_verification;
use std::fs;

fn test_aes_verification() {
    let json_content = fs::read_to_string("./examples/full_http_responses.json").unwrap();
    println!("jsonContent: {}", json_content);
    let msg = aes_verification::verify_full_http_packet_ciphertext(json_content);
    for m in msg.iter() {
        println!("decrypted msg: {}", m);
    }
}

fn main() {
    test_aes_verification();
}
