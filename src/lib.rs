use ring::signature::{Ed25519KeyPair, VerificationAlgorithm, ED25519, KeyPair};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;

pub async fn generate_webproof(
    content: &str,
    key_pair: &Ed25519KeyPair,
) -> Result<String, Box<dyn std::error::Error>> {
    let session_id = generate_session_id();
    let timestamp = Utc::now().timestamp();
    
    let proof_string = format!("{}|{}|{}", session_id, timestamp, content);
    let signature = key_pair.sign(proof_string.as_bytes());
    let encoded_signature = general_purpose::STANDARD.encode(signature.as_ref());
    
    Ok(format!("{}|{}", proof_string, encoded_signature))
}

pub fn verify_webproof(
    proof: &str,
    public_key: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = proof.split('|').collect();
    if parts.len() != 4 {
        return Ok(false); // Changed from Err to Ok(false)
    }
    
    let (session_id, timestamp, content, encoded_signature) = (parts[0], parts[1], parts[2], parts[3]);
    let signature_bytes = match general_purpose::STANDARD.decode(encoded_signature) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(false), // Return false if decoding fails
    };
    
    let proof_string = format!("{}|{}|{}", session_id, timestamp, content);
    match ED25519.verify(
        public_key.into(),
        proof_string.as_bytes().into(),
        signature_bytes.as_slice().into()
    ) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn generate_session_id() -> String {
    use rand::Rng;
    let random_bytes: Vec<u8> = (0..16).map(|_| rand::thread_rng().gen()).collect();
    general_purpose::STANDARD.encode(&random_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair; // Add this line

    #[tokio::test]
    async fn test_generate_and_verify_webproof() {
        let rng = SystemRandom::new();
        let key_pair = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(key_pair.as_ref()).unwrap();

        let content = "Test content";
        let proof = generate_webproof(content, &key_pair).await.unwrap();
        
        let public_key = key_pair.public_key();
        let is_valid = verify_webproof(&proof, public_key.as_ref()).unwrap();

        assert!(is_valid);
    }
}
