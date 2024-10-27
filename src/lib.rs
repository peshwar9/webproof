use ring::signature::{Ed25519KeyPair, VerificationAlgorithm, ED25519, KeyPair};
use ring::error::Unspecified;
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use std::sync::Arc;
use async_trait::async_trait;
use uuid::Uuid;

pub trait TlsConnection: Send + Sync {
    fn negotiated_cipher_suite(&self) -> Option<String>;
}

#[async_trait]
pub trait WebContentExtractor {
    async fn extract_content(&self, tls_connection: &dyn TlsConnection) -> Result<String, Box<dyn std::error::Error>>;
}

pub struct WebProofGenerator<T: WebContentExtractor> {
    tls_connection: Arc<dyn TlsConnection>,
    content_extractor: T,
    id: Uuid,
}

impl<T: WebContentExtractor> WebProofGenerator<T> {
    pub fn new(tls_connection: Arc<dyn TlsConnection>, content_extractor: T) -> Result<Self, Box<dyn std::error::Error>> {
        tls_connection.negotiated_cipher_suite()
            .ok_or("No cipher suite negotiated")?;

        Ok(Self {
            tls_connection,
            content_extractor,
            id: Uuid::new_v4(),
        })
    }

    pub async fn generate_webproof(&self) -> Result<String, Box<dyn std::error::Error>> {
        let session_id = self.extract_session_id()?;
        let key_pair = self.derive_keypair_from_session(&session_id)
            .map_err(|e| format!("Key derivation error: {:?}", e))?;
        let timestamp = Utc::now().timestamp();
        
        let content = self.content_extractor.extract_content(&*self.tls_connection).await?;
        
        let proof_string = format!("{}|{}|{}", general_purpose::STANDARD.encode(&session_id), timestamp, content);
        let signature = key_pair.sign(proof_string.as_bytes());
        let encoded_signature = general_purpose::STANDARD.encode(signature.as_ref());
        
        Ok(format!("{}|{}", proof_string, encoded_signature))
    }

    fn extract_session_id(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        self.tls_connection.negotiated_cipher_suite()
            .ok_or_else(|| "No cipher suite negotiated".into())
            .map(|s| s.as_bytes().to_vec())
    }

    fn derive_keypair_from_session(&self, session_id: &[u8]) -> Result<Ed25519KeyPair, Unspecified> {
        let mut seed_data = session_id.to_vec();
        seed_data.extend_from_slice(self.id.as_bytes());
        let seed = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &seed_data), b"WEBPROOF_KEY");
        Ed25519KeyPair::from_seed_unchecked(seed.as_ref()).map_err(|_| Unspecified)
    }

    pub fn public_key(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let session_id = self.extract_session_id()?;
        let key_pair = self.derive_keypair_from_session(&session_id)
            .map_err(|e| format!("Key derivation error: {:?}", e))?;
        Ok(key_pair.public_key().as_ref().to_vec())
    }
}

pub fn verify_webproof(
    proof: &str,
    public_key: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = proof.split('|').collect();
    if parts.len() != 4 {
        return Ok(false);
    }
    
    let (encoded_session_id, timestamp, content, encoded_signature) = (parts[0], parts[1], parts[2], parts[3]);
    let signature_bytes = match general_purpose::STANDARD.decode(encoded_signature) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(false),
    };
    
    let proof_string = format!("{}|{}|{}", encoded_session_id, timestamp, content);
    match ED25519.verify(
        public_key.into(),
        proof_string.as_bytes().into(),
        signature_bytes.as_slice().into()
    ) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[tokio::test]
    async fn test_generate_and_verify_webproof() {
        let tls_connection = Arc::new(MockTlsConnection {
            cipher_suite: Some("TLS_AES_256_GCM_SHA384".to_string()),
        });
        let content_extractor = MockContentExtractor;
        let generator = WebProofGenerator::new(tls_connection, content_extractor)
            .expect("Failed to create WebProofGenerator");

        let proof = generator.generate_webproof().await.unwrap();
        let public_key = generator.public_key().unwrap();

        assert!(verify_webproof(&proof, &public_key).unwrap());
    }
}
