use num_bigint::BigUint;
use num_traits::Num;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

fn add_secret_keys(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    let c = (a + b) % n;

    c
}

fn biguint_to_key(c: BigUint) -> SecretKey {
    let mut bytes = c.to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    SecretKey::from_slice(&bytes).unwrap()
}

pub fn convert_random(random: &Vec<String>) -> Vec<Scalar> {
    let mut vec = vec![];
    for rnd in random.iter() {
        let bytes = hex::decode(rnd).unwrap();
        let bytes: [u8; 32] = bytes.try_into().unwrap();
        vec.push(Scalar::from_be_bytes(bytes).unwrap());
    }
    vec
}

pub fn convert_commitment(coms: &Vec<String>) -> Vec<PublicKey> {
    let mut vec = vec![];
    for com in coms.iter() {
        let bytes = hex::decode(com).unwrap();
        vec.push(PublicKey::from_slice(&bytes).unwrap());
    }
    vec
}

fn generate_exp(batch_size: usize) -> Vec<BigUint> {
    let mut vec = vec![];
    for i in 0..batch_size {
        let j = i / 8;
        let k = i % 8;
        let mut bytes = [0u8; 32];
        bytes[31 - j] |= 1u8 << k;

        let sk = BigUint::from_bytes_be(&bytes);
        vec.push(sk);
    }
    vec
}

pub fn split_json_response(json_response: &String, batch_size: usize) -> Vec<SecretKey> {
    println!("json response: {}", json_response);
    let mut vec = vec![];
    let mut bytes = json_response.as_bytes().to_vec();
    bytes.reverse();
    let mut bits = vec![];
    for byte in bytes.iter() {
        for i in 0..8 {
            let b = (byte >> i) & 1u8;
            bits.push(b != 0u8);
        }
    }

    let exp = generate_exp(batch_size);
    let n = BigUint::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap();

    let chunk_len = (bits.len() + batch_size - 1) / batch_size;
    let mut index = 0usize;
    for i in 0..chunk_len {
        let mut sk = BigUint::from_bytes_be(&[0u8; 32]);
        for j in 0..batch_size {
            if bits[index] {
                sk = add_secret_keys(&sk, &exp[j], &n);
            }
            index += 1;
            if index >= bits.len() {
                break;
            }
        }
        println!("sk: {:?}", sk);
        let sk = biguint_to_key(sk);
        vec.push(sk);
    }
    vec
}
