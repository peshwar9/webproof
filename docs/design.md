# WebProofs Technical Design

## 1. WebProof Generation Process

WebProofs are generated through the following steps:

1.1. TLS Session Information Extraction
   - The `TlsConnection` trait provides the `negotiated_cipher_suite()` method.
   - This cipher suite is used as a unique identifier for the TLS session.

1.2. Key Pair Derivation
   ```rust
   fn derive_keypair_from_session(&self, session_id: &[u8]) -> Result<Ed25519KeyPair, Unspecified> {
       let mut seed_data = session_id.to_vec();
       seed_data.extend_from_slice(self.id.as_bytes());
       let seed = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &seed_data), b"WEBPROOF_KEY");
       Ed25519KeyPair::from_seed_unchecked(seed.as_ref()).map_err(|_| Unspecified)
   }
   ```
   - A unique key pair is derived for each WebProofGenerator instance.
   - The seed combines the TLS session ID and a unique generator ID.

1.3. Content Extraction
   - The `WebContentExtractor` trait's `extract_content()` method is called to obtain the content to be proved.

1.4. Proof Assembly
   ```rust
   let session_id = self.extract_session_id()?;
   let timestamp = Utc::now().timestamp();
   let content = self.content_extractor.extract_content(&*self.tls_connection).await?;
   let proof_string = format!("{}|{}|{}", general_purpose::STANDARD.encode(&session_id), timestamp, content);
   ```
   - The proof combines the encoded session ID, a timestamp, and the extracted content.

1.5. Signing
   ```rust
   let signature = key_pair.sign(proof_string.as_bytes());
   ```
   - The assembled proof is signed using the derived key pair.

1.6. Encoding
   ```rust
   let encoded_signature = general_purpose::STANDARD.encode(signature.as_ref());
   Ok(format!("{}|{}", proof_string, encoded_signature))
   ```
   - The final proof string includes the proof content and the encoded signature.

## 2. Implementing WebContentExtractor

Developers can create custom content extractors by implementing the `WebContentExtractor` trait:

```rust
#[async_trait]
pub trait WebContentExtractor {
    async fn extract_content(&self, tls_connection: &dyn TlsConnection) -> Result<String, Box<dyn std::error::Error>>;
}
```

Example implementation:

```rust
struct CustomExtractor;

#[async_trait]
impl WebContentExtractor for CustomExtractor {
    async fn extract_content(&self, tls_connection: &dyn TlsConnection) -> Result<String, Box<dyn std::error::Error>> {
        // 1. Fetch raw data
        let raw_data = fetch_data_from_source().await?;

        // 2. Process the data
        let processed_data = process_raw_data(raw_data)?;

        // 3. Serialize to a string
        let content_string = serde_json::to_string(&processed_data)?;

        Ok(content_string)
    }
}
```

Key considerations:
- The extractor should produce a deterministic string representation of the content.
- Error handling is crucial for robustness.
- The `tls_connection` parameter can be used if the extraction process depends on TLS session information.

## 3. Using the Library for Content Attestation

3.1. Setup

```rust
use webproof::{WebProofGenerator, TlsConnection, WebContentExtractor};
use std::sync::Arc;

// Implement TlsConnection
struct MyTlsConnection;
impl TlsConnection for MyTlsConnection {
    fn negotiated_cipher_suite(&self) -> Option<String> {
        Some("TLS_AES_256_GCM_SHA384".to_string())
    }
}

// Create a WebProofGenerator
let tls_connection = Arc::new(MyTlsConnection);
let content_extractor = CustomExtractor;
let generator = WebProofGenerator::new(tls_connection, content_extractor)?;
```

3.2. Generating a Proof

```rust
let proof = generator.generate_webproof().await?;
let public_key = generator.public_key()?;
```

3.3. Verifying a Proof

```rust
use webproof::verify_webproof;

let is_valid = verify_webproof(&proof, &public_key)?;
assert!(is_valid);
```

## 4. Best Practices for Developers

4.1. Content Serialization
- Use a consistent serialization method (e.g., JSON) in your `WebContentExtractor`.
- Consider including a version identifier if your content structure might change over time.

4.2. Error Handling
- Implement comprehensive error handling in your extractor to deal with network issues, parsing errors, etc.
- Use custom error types for more granular error reporting.

4.3. Testing
- Write unit tests for your `WebContentExtractor` implementation.
- Create integration tests that use your extractor with the `WebProofGenerator`.

4.4. Security Considerations
- Be cautious about including sensitive information in the extracted content.
- Ensure that your content extraction process doesn't introduce vulnerabilities (e.g., SSRF).

4.5. Performance
- For large or complex data structures, consider optimizing your extraction and serialization process.
- Use asynchronous operations where appropriate to improve responsiveness.

By following these guidelines, developers can effectively use the WebProofs library to create cryptographic attestations of their custom content structures.

