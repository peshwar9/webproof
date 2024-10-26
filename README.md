# WebProof

WebProof is a Rust library that provides a mechanism for generating and verifying cryptographic proofs for web content. It allows users to create tamper-evident proofs of web content at a specific point in time, which can be later verified for authenticity and integrity.

## Features

- Generate cryptographic proofs for arbitrary content
- Verify the authenticity and integrity of generated proofs
- Asynchronous API for efficient operation
- Built on robust cryptographic primitives (Ed25519)

## What does this code repository do?

This repository contains the implementation of the WebProof library, which includes:

1. A function to generate cryptographic proofs (`generate_webproof`)
2. A function to verify these proofs (`verify_webproof`)
3. Helper functions for session ID generation
4. Test suites to ensure the correct functioning of the library
5. An example application demonstrating how to use the library with real-time Ethereum price data

## How to test and use it?

### Prerequisites

- Rust and Cargo (latest stable version)

### Testing

To run the test suite:

```
cargo test
```

This will run both the unit tests and integration tests.

### Usage

To use WebProof in your project, add it to your `Cargo.toml`:
```
[dependencies]

webproof = { git = "https://github.com/yourusername/webproof.git" }
```

Then, in your Rust code:
```
use webproof::{generate_webproof, verify_webproof};
use ring::signature::{Ed25519KeyPair, KeyPair};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
// Generate a key pair
let rng = ring::rand::SystemRandom::new();
let key_pair = Ed25519KeyPair::generate_pkcs8(&rng)?;
let key_pair = Ed25519KeyPair::from_pkcs8(key_pair.as_ref())?;
// Generate a proof
let content = "Hello, WebProof!";
let proof = generate_webproof(content, &key_pair).await?;
// Verify the proof
let public_key = key_pair.public_key();
let is_valid = verify_webproof(&proof, public_key.as_ref())?;
println!("Proof is valid: {}", is_valid);
Ok(())
}

```
To run the Ethereum price example:
```
cargo run --example ethereum_price
```

This will fetch the current Ethereum price, generate a proof, and verify it.

## Design details of how WebProof is implemented

WebProof uses the following components:

1. **Ed25519 Signatures**: We use the Ed25519 signature scheme for its security and efficiency.

2. **Proof Structure**: A proof consists of:
   - Session ID: A random identifier for the proof session
   - Timestamp: The time at which the proof was generated
   - Content: The actual data being proved
   - Signature: An Ed25519 signature of the above components

3. **Proof Generation**:
   - Generate a random session ID
   - Get the current timestamp
   - Combine session ID, timestamp, and content into a string
   - Sign this string using the Ed25519 private key
   - Encode the signature using Base64
   - Combine all components into the final proof string

4. **Proof Verification**:
   - Split the proof into its components
   - Decode the Base64 signature
   - Reconstruct the signed string from session ID, timestamp, and content
   - Verify the signature using the Ed25519 public key

## Future improvements planned

1. **Blockchain Integration**: Implement anchoring of proofs in a public blockchain for additional security and immutability.

2. **Time-based Verification**: Add functionality to verify if a proof was generated within a specific time range.

3. **Batch Proofs**: Implement the ability to generate and verify proofs for multiple pieces of content in a single operation.

4. **Proof Revocation**: Develop a mechanism to revoke proofs if necessary.

5. **Alternative Signature Schemes**: Add support for other signature schemes beyond Ed25519.

6. **Web API**: Create a RESTful API wrapper around the library for easy integration with web services.

7. **Performance Optimizations**: Implement caching and other optimizations for improved performance in high-volume scenarios.

8. **Formal Verification**: Conduct formal verification of the cryptographic implementations to ensure their correctness.

Contributions to any of these improvements are welcome!

## License

[MIT License](LICENSE)
