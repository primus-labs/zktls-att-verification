use criterion::{criterion_group, criterion_main, Criterion};
use std::fs;
use verification_data::VerifyingDataOpt;
use zktls_att_verification::verification_data;

// verify partial http response
fn partial_verification(verifying_key: &str, verifying_data: &VerifyingDataOpt) {
    verifying_data.verify(verifying_key).unwrap();
}

// load verifying key
fn get_verifying_key() -> String {
    fs::read_to_string("keys/verifying_k256.key").unwrap()
}

// load verifying data
fn get_verifying_data(filename: &str) -> VerifyingDataOpt {
    let json_content = fs::read_to_string(filename).unwrap();
    let verifying_data: VerifyingDataOpt = serde_json::from_str(&json_content).unwrap();
    verifying_data
}

// benchmark verification for partial http response with size 16 Bytes
fn benchmark_verification_16(c: &mut Criterion) {
    let verifying_key = get_verifying_key();
    let verifying_data = get_verifying_data("./data/bench16.json");
    c.bench_function("benchmark_verification_16", |b| {
        b.iter(|| partial_verification(&verifying_key, &verifying_data))
    });
}

// benchmark verification for partial http response with size 256 Bytes
fn benchmark_verification_256(c: &mut Criterion) {
    let verifying_key = get_verifying_key();
    let verifying_data = get_verifying_data("./data/bench256.json");
    c.bench_function("benchmark_verification_256", |b| {
        b.iter(|| partial_verification(&verifying_key, &verifying_data))
    });
}

// benchmark verification for partial http response with size 1024 Bytes
fn benchmark_verification_1024(c: &mut Criterion) {
    let verifying_key = get_verifying_key();
    let verifying_data = get_verifying_data("./data/bench1024.json");
    c.bench_function("benchmark_verification_1024", |b| {
        b.iter(|| partial_verification(&verifying_key, &verifying_data))
    });
}

// benchmark verification for partial http response with size 2048 Bytes
fn benchmark_verification_2048(c: &mut Criterion) {
    let verifying_key = get_verifying_key();
    let verifying_data = get_verifying_data("./data/bench2048.json");
    c.bench_function("benchmark_verification_2048", |b| {
        b.iter(|| partial_verification(&verifying_key, &verifying_data))
    });
}

criterion_group!(
    benches,
    benchmark_verification_16,
    benchmark_verification_256,
    benchmark_verification_1024,
    benchmark_verification_2048
);
criterion_main!(benches);
