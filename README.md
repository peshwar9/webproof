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

## Quick Start

Here's a simple example of how to use WebProofs:
```
use webproof::{WebProofGenerator, WebContentExtractor, TlsConnection, verify_webproof};
use async_trait::async_trait;
use std::sync::Arc;

// Implement a simple TLS connection
struct SimpleTlsConnection;

impl TlsConnection for SimpleTlsConnection {
    fn negotiated_cipher_suite(&self) -> Option<String> {
        Some("TLS_AES_256_GCM_SHA384".to_string())
    }
}

// Implement a basic content extractor
struct SimpleContentExtractor;

#[async_trait]
impl WebContentExtractor for SimpleContentExtractor {
    async fn extract_content(&self, _tls_connection: &dyn TlsConnection) -> Result<String, Box<dyn std::error::Error>> {
        Ok("Hello, WebProof!".to_string())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a simple TLS connection
    let tls_connection = Arc::new(SimpleTlsConnection);

    // Set up the content extractor
    let content_extractor = SimpleContentExtractor;

    // Create the WebProofGenerator
    let proof_generator = WebProofGenerator::new(tls_connection, content_extractor)?;

    // Generate a proof
    let proof = proof_generator.generate_webproof().await?;

    // Get the public key
    let public_key = proof_generator.public_key()?;

    // Verify the proof
    let is_valid = verify_webproof(&proof, &public_key)?;

    println!("Proof is valid: {}", is_valid);
    println!("Generated proof: {}", proof);

    Ok(())
}
```
This example demonstrates:
- Implementing a `TlsConnection` to provide TLS session information.
- Creating a `WebContentExtractor` to define how content is fetched and formatted.
- Using `WebProofGenerator` to create proofs based on the TLS connection and extracted content.
- Generating and verifying a web proof.

For more detailed examples, including real-world scenarios like weather data attestation, check out the `examples/` directory.

To run the Ethereum price example:
```
cargo run --example ethereum_price
```

This will fetch the current Ethereum price, generate a proof, and verify it.

To run the weather attestation example:
```
WEATHER_KEY=<your_openweathermap_api_key> cargo run --example weather_attestation
```

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

## Future possible improvements

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
