use webproof::{generate_webproof, verify_webproof, derive_keypair_from_session};
use ed25519_dalek::{Signature, Verifier};
use chrono::Utc;

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_generate_and_verify_valid_webproof() {
        let eth_price = 1234.56;
        let session_id = b"test-session-id";

        let webproof = generate_webproof(eth_price, session_id).unwrap();
        let is_valid = verify_webproof(&webproof, 300).unwrap();

        assert!(is_valid, "Valid webproof should be verified successfully");
    }

    #[test]
    fn test_verify_expired_webproof() {
        let eth_price = 1234.56;
        let session_id = b"test-session-id";

        let webproof = generate_webproof(eth_price, session_id).unwrap();
        
        // Sleep for 2 seconds to make the proof "old"
        sleep(Duration::from_secs(2));

        let is_valid = verify_webproof(&webproof, 1).unwrap();

        assert!(!is_valid, "Expired webproof should not be verified");
    }

    #[test]
    fn test_verify_tampered_webproof() {
        let eth_price = 1234.56;
        let session_id = b"test-session-id";

        let mut webproof = generate_webproof(eth_price, session_id).unwrap();
        
        // Tamper with the price in the webproof
        webproof = webproof.replace("1234.56", "5678.90");

        let is_valid = verify_webproof(&webproof, 300).unwrap();

        assert!(!is_valid, "Tampered webproof should not be verified");
    }

    #[test]
    fn test_verify_webproof_with_invalid_format() {
        let invalid_webproof = "This is not a valid webproof".to_string();

        let result = verify_webproof(&invalid_webproof, 300);

        assert!(result.is_err(), "Invalid format should return an error");
    }

    #[test]
    fn test_generate_unique_proofs() {
        let eth_price = 1234.56;
        let session_id_1 = b"test-session-id-1";
        let session_id_2 = b"test-session-id-2";

        let webproof_1 = generate_webproof(eth_price, session_id_1).unwrap();
        let webproof_2 = generate_webproof(eth_price, session_id_2).unwrap();

        assert_ne!(webproof_1, webproof_2, "Proofs should be unique for different session IDs");
    }

    #[test]
    fn test_verify_webproof_with_different_session_id() {
        let eth_price = 1234.56;
        let session_id_1 = b"test-session-id-1";
        let session_id_2 = b"test-session-id-2";

        let webproof = generate_webproof(eth_price, session_id_1).unwrap();
        
        // Attempt to verify with a different session ID
        let keypair = derive_keypair_from_session(session_id_2, b"some-salt");
        let parts: Vec<&str> = webproof.split(". ").collect();
        let message = format!("{}. {}. {}", parts[0], parts[1], parts[2]);
        let signature = Signature::from_bytes(&hex::decode(&parts[4][11..]).unwrap()).unwrap();

        let is_valid = keypair.public.verify(message.as_bytes(), &signature).is_ok();

        assert!(!is_valid, "Webproof should not be valid with a different session ID");
    }
}