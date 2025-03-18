use serde::{Serialize, Deserialize};
use aes_gcm::aead::KeyInit;
use aes_gcm::{Aes128Gcm, AeadInPlace, Nonce};
use hex;

// TLS Record
#[derive(Debug, Serialize, Deserialize)]
pub struct TLSRecord {
    pub ciphertext: String, // tls record ciphertext
    pub nonce: String,  // tls record nonce
    pub aad: String,   // tls associated data
    pub tag: String,   // tls record tag
    pub blocks_to_redact: Vec<u32>,   // blocks to redact
    pub blocks_to_extract: Vec<u32>  // blocks to extract
}

// Http Response
#[derive(Debug, Serialize, Deserialize)]
pub struct HttpResponse {
    pub aes_key: String,  // aes key for encrypting/decrypting
    pub records: Vec<TLSRecord>,  // TLS Records, constructing full http response
}

// Data to verify
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyingData {
    pub responses: Vec<HttpResponse> // Http Responses
}

// verify full http response ciphertext
pub fn verify_full_http_response_ciphertext(json_content: String) -> Vec<String> {
    let verifying_data: VerifyingData = serde_json::from_str(&json_content).unwrap();

    let mut all_response = vec![];
    for response in verifying_data.responses.iter() {
        let mut response_msg: String = String::new();
        let aes_key = &response.aes_key;
        let aes_key = hex::decode(aes_key).unwrap();
        
        let cipher = Aes128Gcm::new_from_slice(&aes_key).unwrap();

        for record in response.records.iter() {
            let nonce = hex::decode(&record.nonce).unwrap();
            let nonce: [u8; 12] = nonce.try_into().unwrap();
            let nonce = Nonce::from(nonce);
            let aad = hex::decode(&record.aad).unwrap();
            let tag = hex::decode(&record.tag).unwrap();
            let mut ciphertext = hex::decode(&record.ciphertext).unwrap();

            cipher.decrypt_in_place_detached(&nonce, aad.as_slice(), &mut ciphertext, tag.as_slice().into()).unwrap();

            let msg = String::from_utf8_lossy(ciphertext.as_slice());
            response_msg += &msg;
        }

        all_response.push(response_msg);
    }
    all_response
}

