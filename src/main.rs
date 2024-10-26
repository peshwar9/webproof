use rustls::{ClientConfig, ClientConnection, ServerName, Stream, RootCertStore};
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use webpki_roots;
use serde_json::Value;
use std::collections::HashMap;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use hex;
use ed25519_dalek::{Keypair, Signer, Verifier, PublicKey, Signature, SecretKey};
use chrono::{Utc, DateTime};
use rand::{rngs::OsRng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};

fn fetch_eth_price(session_store: &mut HashMap<String, Vec<u8>>) -> Result<(f64, Vec<u8>), Box<dyn Error>> {
    // Define the URL to fetch the Ethereum price from CoinGecko
    let url = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd";

    // Connect to the CoinGecko API using TCP
    let mut socket = TcpStream::connect("api.coingecko.com:443")?;

    // Set up TLS connection
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        })
    );

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Create a new ClientConnection
    let server_name = ServerName::try_from("api.coingecko.com")?;
    let mut connection = ClientConnection::new(Arc::new(config), server_name)?;

    // Create a Stream
    let mut tls_stream = Stream::new(&mut connection, &mut socket);

    // Perform the TLS handshake
    tls_stream.flush()?;

    // Now that the handshake is complete, we can export the session ID
    let mut session_id = [0u8; 32];
    tls_stream.conn.export_keying_material(&mut session_id, b"EXPORTER-WebProof-Session-ID", Some(&[]))?;

    // Send the HTTP GET request
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: api.coingecko.com\r\nConnection: close\r\n\r\n",
        url
    );
    tls_stream.write_all(request.as_bytes())?;

    // Read the response
    let mut response = Vec::new();
    tls_stream.read_to_end(&mut response)?;

    // Convert response to string
    let response_str = String::from_utf8_lossy(&response);

    // Print the full response for debugging
    println!("Full response:\n{}", response_str);

    // Split the response into headers and body
    let parts: Vec<&str> = response_str.split("\r\n\r\n").collect();
    if parts.len() < 2 {
        return Err("Invalid response format".into());
    }

    // Extract the body and handle chunked encoding
    let body = parts[1];
    let json_body = body.lines()
        .filter(|line| !line.trim().is_empty() && !line.trim().chars().all(|c| c.is_digit(16)))
        .collect::<Vec<&str>>()
        .join("");

    // Extract the Ethereum price from the JSON response
    let json_response: Value = serde_json::from_str(&json_body)?;
    if let Some(price) = json_response["ethereum"]["usd"].as_f64() {
        // Store the session ID for future use
        session_store.insert("api.coingecko.com".to_string(), session_id.to_vec());
        Ok((price, session_id.to_vec()))
    } else {
        Err("Failed to extract Ethereum price".into())
    }
}

// Derive a keypair from session ID and a random salt
fn derive_keypair_from_session(session_id: &[u8], salt: &[u8]) -> Keypair {
    let mut hasher = Sha256::new();
    hasher.update(session_id);
    hasher.update(salt);
    let seed = hasher.finalize();
    let secret = SecretKey::from_bytes(&seed[..32]).expect("Failed to create secret key");
    let public = (&secret).into();
    Keypair { secret, public }
}

fn generate_webproof(price: f64, session_id: &[u8]) -> Result<String, Box<dyn Error>> {
    // Generate a random salt
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let keypair = derive_keypair_from_session(session_id, &salt);
    
    // Get current timestamp
    let timestamp: DateTime<Utc> = Utc::now();
    
    // Create the message containing the Ethereum price, timestamp, and salt
    let message = format!(
        "The current price of Ethereum is: ${:.2}. Timestamp: {}. Salt: {}",
        price,
        timestamp.to_rfc3339(),
        hex::encode(salt)
    );
    
    // Sign the message
    let signature = keypair.sign(message.as_bytes());

    // Convert signature and public key to hex strings
    let signature_hex = hex::encode(signature.to_bytes());
    let public_key_hex = hex::encode(keypair.public.to_bytes());

    // Format the web proof
    Ok(format!("{}. Session Public Key: {}. Signature: {}", message, public_key_hex, signature_hex))
}

fn verify_webproof(webproof: &str, max_age_seconds: i64) -> Result<bool, Box<dyn Error>> {
    // Split the webproof into its components
    let parts: Vec<&str> = webproof.split(". ").collect();
    if parts.len() != 5 {
        return Err("Invalid webproof format".into());
    }

    let price_part = parts[0];
    let timestamp_part = parts[1];
    let salt_part = parts[2];
    let public_key_part = parts[3];
    let signature_part = parts[4];

    // Extract timestamp
    let timestamp_str = timestamp_part.strip_prefix("Timestamp: ")
        .ok_or("Invalid timestamp format")?;
    let timestamp = DateTime::parse_from_rfc3339(timestamp_str)?;

    // Check if the proof is not too old
    let now = Utc::now();
    if (now.timestamp() - timestamp.timestamp()) > max_age_seconds {
        return Ok(false);
    }

    // Reconstruct the message
    let message = format!("{}. {}. {}", price_part, timestamp_part, salt_part);

    // Extract public key and signature
    let public_key = PublicKey::from_bytes(&hex::decode(public_key_part.strip_prefix("Session Public Key: ")
        .ok_or("Invalid public key format")?)?)?;
    let signature = Signature::from_bytes(&hex::decode(signature_part.strip_prefix("Signature: ")
        .ok_or("Invalid signature format")?)?)?;

    // Verify the signature
    Ok(public_key.verify(message.as_bytes(), &signature).is_ok())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Simulate fetching Ethereum price and session ID
    let eth_price = 1234.56;
    let session_id = b"some-unique-session-id";

    // Generate a web proof
    let webproof = generate_webproof(eth_price, session_id)?;
    println!("Generated WebProof: {}", webproof);

    // Verify the web proof (allowing proofs up to 5 minutes old)
    let is_valid = verify_webproof(&webproof, 300)?;
    println!("WebProof is valid: {}", is_valid);

    Ok(())
}
