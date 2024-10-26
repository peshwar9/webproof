use webproof::{generate_webproof, verify_webproof};
use ring::signature::{Ed25519KeyPair, KeyPair};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let eth_price = 1234.56;
    let rng = ring::rand::SystemRandom::new();
    let key_pair = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| format!("Key generation error: {:?}", e))?;
    let key_pair = Ed25519KeyPair::from_pkcs8(key_pair.as_ref()).map_err(|e| format!("Key parsing error: {:?}", e))?;

    let webproof = generate_webproof(&eth_price.to_string(), &key_pair).await?;
    println!("Generated WebProof: {}", webproof);

    let public_key = key_pair.public_key();
    let is_valid = verify_webproof(&webproof, public_key.as_ref())?;
    println!("WebProof is valid: {}", is_valid);

    Ok(())
}
