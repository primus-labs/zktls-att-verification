use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::{CurveConfig, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger256, PrimeField};
use ark_grumpkin::{Affine, Fq, Fr, GrumpkinConfig, Projective};
use hex::FromHex;

pub fn hex2point(hex_str: &str) -> anyhow::Result<Projective> {
    let bytes = Vec::from_hex(hex_str)?;
    if bytes.len() != 65 {
        return Err(anyhow::anyhow!("hex length error"));
    }
    if bytes[0] != 4u8 {
        return Err(anyhow::anyhow!("hex data error"));
    }
    let x = &bytes[1..33];
    let y = &bytes[33..65];

    let x = Fq::from_be_bytes_mod_order(x);
    let y = Fq::from_be_bytes_mod_order(y);
    let point_affine = Affine::new(x, y);
    if !point_affine.is_on_curve() {
        return Err(anyhow::anyhow!("not on curve"));
    }
    if !point_affine.is_in_correct_subgroup_assuming_on_curve() {
        return Err(anyhow::anyhow!("not in correct subgroup"));
    }
    let point_proj = Projective::from(point_affine);
    Ok(point_proj)
}

pub fn bytes2scalar(bytes: [u8; 32]) -> anyhow::Result<Fr> {
    let mut limbs = [0u64; 4];
    for (i, chunk) in bytes.chunks(8).rev().enumerate() {
        limbs[i] = u64::from_be_bytes(chunk.try_into().unwrap());
    }
    let bigint = BigInteger256::new(limbs);
    let scalar = Fr::from(bigint);
    Ok(scalar)
}

pub fn hex2scalar(hex_str: &str) -> anyhow::Result<Fr> {
    let bytes = <[u8; 32]>::from_hex(hex_str)?;
    bytes2scalar(bytes)
}

pub fn convert_random(random: &Vec<String>) -> anyhow::Result<Vec<Fr>> {
    let mut vec = vec![];
    for rnd in random.iter() {
        let scalar = hex2scalar(rnd)?;
        vec.push(scalar);
    }
    Ok(vec)
}

pub fn convert_commitment(coms: &Vec<String>) -> anyhow::Result<Vec<Projective>> {
    let mut vec = vec![];
    for com in coms.iter() {
        let point = hex2point(com)?;
        vec.push(point);
    }
    Ok(vec)
}

fn generate_exp(batch_size: usize) -> anyhow::Result<Vec<Fr>> {
    let mut vec = vec![];
    for i in 0..batch_size {
        let j = i / 8;
        let k = i % 8;
        let mut bytes = [0u8; 32];
        bytes[31 - j] |= 1u8 << k;

        let sk = bytes2scalar(bytes)?;
        vec.push(sk);
    }
    Ok(vec)
}

pub fn split_json_response(json_response: &String, batch_size: usize) -> anyhow::Result<Vec<Fr>> {
    println!("grumpkin Fq {}", Fq::MODULUS);
    println!("grumpkin Fr: {}", Fr::MODULUS);
    println!("grumpkin a: {:?}", GrumpkinConfig::COEFF_A);
    println!("grumpkin b: {:?}", GrumpkinConfig::COEFF_B);
    let g = Projective::generator().into_affine();
    println!("grumpkin x: {:?}", g.x);
    println!("grumpkin y: {:?}", g.y);

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

    let exp = generate_exp(batch_size)?;

    let chunk_len = (bits.len() + batch_size - 1) / batch_size;
    let mut index = 0usize;
    for _ in 0..chunk_len {
        let mut sk = bytes2scalar([0u8; 32])?;
        for j in 0..batch_size {
            if bits[index] {
                sk = sk + &exp[j];
            }
            index += 1;
            if index >= bits.len() {
                break;
            }
        }
        vec.push(sk);
    }
    Ok(vec)
}
