# zkTLS-Att-Verification

## Introduction
This Repository provides functionality for verifying ECDSA signature and AES ciphertext. For ECDSA signature, the underlying elliptic curve is Secp256k1. The AES ciphertext is outputed using AES-128-GCM.

## Compile

```bash
cargo build --release
```
## Usage

### KeyGen
To generate ECDSA signing key and verifying key, you can do as following:
```bash
mkdir <KEY_DIR>
./target/release/keygen_k256 --key-dir <KEY_DIR>
```

**key-dir**:  the output directory where signing key and verifying key will be put.

### Sign Message
To Sign message, you can do as following:
```bash
./target/release/sign_k256 --key-file <SIGNING_KEY_FILE> --msg-file <MSG_FILE>
```
**key-file**: the file storing the signing key.

**msg-file**: the file storing the message, the content of the file should be hex-encoded.

## Example
There is an example `examples/verification_example.rs`, demostrating how to verifying ecdsa signature and aes ciphertext. Build the example and run as following:
```bash
cargo build --release --example verification_example
./target/release/examples/verification_example
```

## Benchmark
The benchmark file is located in `benchch`. Build the bench program and run as following:
```bash
cargo bench --bench benchmark
```
