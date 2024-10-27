use webproof::{WebProofGenerator, WebContentExtractor, TlsConnection};
use async_trait::async_trait;
use std::sync::Arc;
use reqwest::Client;
use serde_json::Value;

struct EthereumPriceExtractor;

#[async_trait]
impl WebContentExtractor for EthereumPriceExtractor {
    async fn extract_content(&self, _tls_connection: &dyn TlsConnection) -> Result<String, Box<dyn std::error::Error>> {
        let url = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd";
        let response = reqwest::get(url).await?;
        let json: Value = response.json().await?;
        let eth_price = json["ethereum"]["usd"].as_f64().ok_or("Failed to parse Ethereum price")?;
        Ok(format!("Ethereum Price: ${:.2}", eth_price))
    }
}

// Implement a simple TlsConnection for this example
struct SimpleTlsConnection;

impl TlsConnection for SimpleTlsConnection {
    fn negotiated_cipher_suite(&self) -> Option<String> {
        Some("TLS_AES_256_GCM_SHA384".to_string())
    }
}

async fn fetch_ethereum_price() -> Result<f64, Box<dyn std::error::Error>> {
    let client = Client::new();

    let url = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd";
    let response = client.get(url).send().await?;
    let json: Value = response.json().await?;
    let eth_price = json["ethereum"]["usd"].as_f64().ok_or("Failed to parse Ethereum price")?;
    
    Ok(eth_price)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Fetch the price
    let price = fetch_ethereum_price().await?;
    println!("Ethereum Price: ${:.2}", price);

    // Create a simple TlsConnection
    let tls_connection = Arc::new(SimpleTlsConnection);

    // Set up the extractor and proof generator
    let content_extractor = EthereumPriceExtractor;
    let proof_generator = WebProofGenerator::new(tls_connection, content_extractor)?;

    // Generate the web proof
    let proof = proof_generator.generate_webproof().await?;
    println!("Generated Web Proof: {}", proof);

    Ok(())
}
