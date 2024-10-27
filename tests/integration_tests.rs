use webproof::{
    TlsConnection,
    WebContentExtractor,
    WebProofGenerator,
    verify_webproof,
};

use std::sync::Arc;
use async_trait::async_trait;

struct MockTlsConnection {
    cipher_suite: Option<String>,
}

impl TlsConnection for MockTlsConnection {
    fn negotiated_cipher_suite(&self) -> Option<String> {
        self.cipher_suite.clone()
    }
}

struct MockContentExtractor;

#[async_trait]
impl WebContentExtractor for MockContentExtractor {
    async fn extract_content(&self, _tls_connection: &dyn TlsConnection) -> Result<String, Box<dyn std::error::Error>> {
        Ok("Mock web content".to_string())
    }
}

fn setup_mock_tls_connection() -> Arc<dyn TlsConnection> {
    Arc::new(MockTlsConnection {
        cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
    })
}

#[tokio::test]
async fn test_generate_and_verify_valid_webproof() {
    let tls_connection = setup_mock_tls_connection();
    let content_extractor = MockContentExtractor;
    let generator = WebProofGenerator::new(tls_connection, content_extractor)
        .expect("Failed to create WebProofGenerator");

    let proof = generator.generate_webproof().await.unwrap();
    let public_key = generator.public_key().unwrap();

    assert!(verify_webproof(&proof, &public_key).unwrap());
}

#[tokio::test]
async fn test_invalid_proof() -> Result<(), Box<dyn std::error::Error>> {
    let tls_connection = setup_mock_tls_connection();
    let content_extractor = MockContentExtractor;
    let generator = WebProofGenerator::new(tls_connection.clone(), content_extractor)?;

    let mut proof = generator.generate_webproof().await?;

    // Tamper with the proof
    proof.push_str("x");

    let public_key = generator.public_key()?;

    let is_valid = verify_webproof(&proof, &public_key)?;

    assert!(!is_valid, "Tampered proof should not be valid");
    Ok(())
}

#[tokio::test]
async fn test_different_content_invalid() -> Result<(), Box<dyn std::error::Error>> {
    let tls_connection = setup_mock_tls_connection();
    let content_extractor = MockContentExtractor;
    let generator = WebProofGenerator::new(tls_connection.clone(), content_extractor)?;

    let proof = generator.generate_webproof().await?;
    let original_public_key = generator.public_key()?;

    // Create a new generator with different content
    struct DifferentContentExtractor;
    
    #[async_trait]
    impl WebContentExtractor for DifferentContentExtractor {
        async fn extract_content(&self, _tls_connection: &dyn TlsConnection) -> Result<String, Box<dyn std::error::Error>> {
            Ok("Different content".to_string())
        }
    }

    let different_generator = WebProofGenerator::new(tls_connection, DifferentContentExtractor)?;
    let different_public_key = different_generator.public_key()?;

    // Debug prints
    println!("Original public key: {:?}", original_public_key);
    println!("Different public key: {:?}", different_public_key);
    println!("Proof: {}", proof);

    let is_valid_original = verify_webproof(&proof, &original_public_key)?;
    let is_valid_different = verify_webproof(&proof, &different_public_key)?;

    println!("Is valid with original key: {}", is_valid_original);
    println!("Is valid with different key: {}", is_valid_different);

    assert!(is_valid_original, "Proof should be valid with the original public key");
    assert!(!is_valid_different, "Proof should not be valid with a different public key");
    Ok(())
}
