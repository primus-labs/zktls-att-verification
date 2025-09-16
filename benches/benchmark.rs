use criterion::{criterion_group, criterion_main, Criterion};
use std::fs;
use tls_data::PartialTLSData;
use zktls_att_verification::tls_data;

// verify partial http response
fn partial_verification(partial_tls_data: &PartialTLSData) {
    partial_tls_data
        .tls_data
        .verify(&partial_tls_data.private_data.aes_key)
        .unwrap();
}

// load partial tls data
fn get_partial_tls_data(filename: &str) -> PartialTLSData {
    let json_content = fs::read_to_string(filename).unwrap();
    let partial_tls_data: PartialTLSData = serde_json::from_str(&json_content).unwrap();
    partial_tls_data
}

// benchmark verification for partial http response with size 16 Bytes
fn benchmark_verification_16(c: &mut Criterion) {
    let partial_tls_data = get_partial_tls_data("./data/bench16.json");
    c.bench_function("benchmark_verification_16", |b| {
        b.iter(|| partial_verification(&partial_tls_data))
    });
}

// benchmark verification for partial http response with size 256 Bytes
fn benchmark_verification_256(c: &mut Criterion) {
    let partial_tls_data = get_partial_tls_data("./data/bench256.json");
    c.bench_function("benchmark_verification_256", |b| {
        b.iter(|| partial_verification(&partial_tls_data))
    });
}

// benchmark verification for partial http response with size 1024 Bytes
fn benchmark_verification_1024(c: &mut Criterion) {
    let partial_tls_data = get_partial_tls_data("./data/bench1024.json");
    c.bench_function("benchmark_verification_1024", |b| {
        b.iter(|| partial_verification(&partial_tls_data))
    });
}

// benchmark verification for partial http response with size 2048 Bytes
fn benchmark_verification_2048(c: &mut Criterion) {
    let partial_tls_data = get_partial_tls_data("./data/bench2048.json");
    c.bench_function("benchmark_verification_2048", |b| {
        b.iter(|| partial_verification(&partial_tls_data))
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
