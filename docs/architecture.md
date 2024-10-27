# WebProofs Architecture

## Note on Terminology

"WebProofs" as described in this document refers to our project's specific approach to web content verification. It is not an industry-standard term but rather our interpretation and implementation of a system for proving web content integrity using TLS session information.

## Overview

WebProofs is a lightweight system designed to generate cryptographic proofs of web content integrity and origin, leveraging information from TLS sessions. This document outlines the architecture of WebProofs and compares it with similar systems like zkTLS and TLSNotary.

## Core Components

1. TlsConnection
   - Trait defining the interface for TLS connection information
   - Key method: `negotiated_cipher_suite()`

2. WebContentExtractor
   - Trait for extracting web content
   - Key method: `extract_content()`

3. WebProofGenerator
   - Main struct for generating web proofs
   - Uses TlsConnection and WebContentExtractor
   - Key methods:
     - `new()`
     - `generate_webproof()`
     - `public_key()`

4. Verification Function
   - `verify_webproof()`: Standalone function for verifying generated proofs

## Proof Generation Process

1. TLS Session Information Extraction
   - Obtain cipher suite information from TLS connection

2. Key Pair Derivation
   - Use TLS session information and a unique generator ID to derive a key pair

3. Content Extraction
   - Extract web content using the WebContentExtractor

4. Proof Assembly
   - Combine session ID, timestamp, and content

5. Signing
   - Sign the assembled proof with the derived key pair

6. Encoding
   - Encode the proof and signature for transmission

## Verification Process

1. Proof Parsing
   - Parse the encoded proof into its components

2. Signature Verification
   - Verify the signature using the provided public key

## Comparison with Other Systems

### WebProofs vs. zkTLS

| Aspect | WebProofs | zkTLS |
|--------|-----------|-------|
| Cryptographic Technique | Standard digital signatures | Zero-knowledge proofs |
| Privacy | Basic TLS privacy | Enhanced privacy guarantees |
| Complexity | Low | High |
| Use Cases | Simple web content verification | Advanced privacy-preserving TLS proofs |
| Performance | Lightweight | Computationally intensive |

Key Differences:
- WebProofs focuses on content integrity, while zkTLS emphasizes session privacy
- zkTLS offers more advanced privacy features but at the cost of higher complexity

### WebProofs vs. TLSNotary

| Aspect | WebProofs | TLSNotary |
|--------|-----------|-----------|
| Third-Party Involvement | None | Requires a notary server |
| TLS Session Coverage | Partial (uses cipher suite) | Complete session |
| Cryptographic Approach | Session-based key derivation | Multi-party computation |
| Server Compatibility | Works with standard servers | Works with unmodified servers, requires special client |
| Proof Strength | Content-focused | Entire TLS session |

Key Differences:
- WebProofs is simpler and doesn't require third-party involvement
- TLSNotary provides stronger guarantees about the entire TLS session
- WebProofs focuses on content, while TLSNotary proves the authenticity of the whole communication

## Strengths and Limitations

Strengths of WebProofs:
- Lightweight and easy to implement
- Works with standard HTTPS servers without modification
- Provides a simple way to verify web content integrity

Limitations of WebProofs:
- Does not provide guarantees for the entire TLS session
- Less privacy-preserving compared to zkTLS
- Lacks the strong notarization features of TLSNotary

## Future Enhancements

Potential areas for improvement:
1. Implement multi-party computation for stronger session guarantees
2. Enhance privacy features
3. Improve timestamp verification mechanism
4. Expand coverage to more aspects of the TLS session

## Conclusion

WebProofs offers a balanced approach to web content verification, prioritizing simplicity and ease of implementation. While it may not provide the advanced features of systems like zkTLS or TLSNotary, it serves as an effective solution for basic web content integrity verification.
