// examples/ethereum_price.rs

use webproof::{generate_webproof, verify_webproof};
use ring::signature::{Ed25519KeyPair, KeyPair};
use reqwest;
use serde_json::Value;

async fn fetch_ethereum_price() -> Result<String, Box<dyn std::error::Error>> {
    let url = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd";
    let resp: Value = reqwest::get(url).await?.json().await?;
    let price = resp["ethereum"]["usd"].as_f64().ok_or("Failed to parse price")?;
    Ok(price.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| format!("Key generation error: {:?}", e))?;
    let key_pair = Ed25519KeyPair::from_pkcs8(key_pair.as_ref())
        .map_err(|e| format!("Key parsing error: {:?}", e))?;

    let eth_price = fetch_ethereum_price().await?;
    
    let proof = generate_webproof(&eth_price, &key_pair).await?;
    
    println!("Generated Ethereum price proof: {}", proof);
    
    let public_key = key_pair.public_key();
    let is_valid = verify_webproof(&proof, public_key.as_ref())?;
    
    println!("Verified Ethereum price: ${}", eth_price);
    println!("Proof is valid: {}", is_valid);
    
    Ok(())
}
