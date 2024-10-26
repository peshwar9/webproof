use rustls::{ClientConfig, ClientConnection, ServerName, Stream, RootCertStore};
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use webpki_roots;
use serde_json::Value;
use std::collections::HashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;

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

fn generate_webproof(price: f64, session_id: &[u8]) -> String {
    let message = format!("The current price of Ethereum is: ${:.2}", price);
    
    // Create HMAC-SHA256 instance
    let mut mac = Hmac::<Sha256>::new_from_slice(session_id)
        .expect("HMAC can take key of any size");

    // Add message to HMAC
    mac.update(message.as_bytes());

    // Calculate HMAC
    let result = mac.finalize();
    let signature = result.into_bytes();

    // Convert signature to hex string
    let signature_hex = signature.iter().map(|b| format!("{:02x}", b)).collect::<String>();

    format!("{}. Signature: {}", message, signature_hex)
}

fn main() -> Result<(), Box<dyn Error>> {
    // Store sessions in a HashMap
    let mut session_store: HashMap<String, Vec<u8>> = HashMap::new();

    // Fetch the Ethereum price and session ID
    let (eth_price, session_id) = fetch_eth_price(&mut session_store)?;

    // Generate a web proof based on the fetched price and session ID
    let webproof = generate_webproof(eth_price, &session_id);

    // Print the web proof
    println!("{}", webproof);

    Ok(())
}
