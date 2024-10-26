use ed25519_dalek::{Keypair, Signer, Verifier, PublicKey, Signature, SecretKey};
use sha2::{Sha256, Digest};
use chrono::{Utc, DateTime};
use rand::{rngs::OsRng, RngCore};
use std::error::Error;

// Derive a keypair from session ID and a random salt
pub fn derive_keypair_from_session(session_id: &[u8], salt: &[u8]) -> Keypair {
    let mut hasher = Sha256::new();
    hasher.update(session_id);
    hasher.update(salt);
    let seed = hasher.finalize();
    let secret = SecretKey::from_bytes(&seed[..32]).expect("Failed to create secret key");
    let public = (&secret).into();
    Keypair { secret, public }
}

pub fn generate_webproof(price: f64, session_id: &[u8]) -> Result<String, Box<dyn Error>> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let keypair = derive_keypair_from_session(session_id, &salt);
    
    let timestamp: DateTime<Utc> = Utc::now();
    
    let message = format!(
        "The current price of Ethereum is: ${:.2}. Timestamp: {}. Salt: {}",
        price,
        timestamp.to_rfc3339(),
        hex::encode(salt)
    );
    
    let signature = keypair.sign(message.as_bytes());

    let signature_hex = hex::encode(signature.to_bytes());
    let public_key_hex = hex::encode(keypair.public.to_bytes());

    Ok(format!("{}. Session Public Key: {}. Signature: {}", message, public_key_hex, signature_hex))
}

pub fn verify_webproof(webproof: &str, max_age_seconds: i64) -> Result<bool, Box<dyn Error>> {
    let parts: Vec<&str> = webproof.split(". ").collect();
    if parts.len() != 5 {
        return Err("Invalid webproof format".into());
    }

    let price_part = parts[0];
    let timestamp_part = parts[1];
    let salt_part = parts[2];
    let public_key_part = parts[3];
    let signature_part = parts[4];

    let timestamp_str = timestamp_part.strip_prefix("Timestamp: ")
        .ok_or("Invalid timestamp format")?;
    let timestamp = DateTime::parse_from_rfc3339(timestamp_str)?;

    let now = Utc::now();
    if (now.timestamp() - timestamp.timestamp()) > max_age_seconds {
        return Ok(false);
    }

    let message = format!("{}. {}. {}", price_part, timestamp_part, salt_part);

    let public_key = PublicKey::from_bytes(&hex::decode(public_key_part.strip_prefix("Session Public Key: ")
        .ok_or("Invalid public key format")?)?)?;
    let signature = Signature::from_bytes(&hex::decode(signature_part.strip_prefix("Signature: ")
        .ok_or("Invalid signature format")?)?)?;

    Ok(public_key.verify(message.as_bytes(), &signature).is_ok())
}
