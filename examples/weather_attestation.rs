use webproof::{WebProofGenerator, WebContentExtractor, TlsConnection};
use async_trait::async_trait;
use std::sync::Arc;
use reqwest::Client;
use serde_json::Value;
use std::env;

struct WeatherDataExtractor;

#[async_trait]
impl WebContentExtractor for WeatherDataExtractor {
    async fn extract_content(&self, _tls_connection: &dyn TlsConnection) -> Result<String, Box<dyn std::error::Error>> {
        let api_key = env::var("WEATHER_KEY").map_err(|_| "WEATHER_KEY environment variable not set")?;
        println!("API Key: {}", api_key); // Be careful with this line, remove it after debugging
        let city = "London"; // You can make this configurable
        let url = format!("https://api.openweathermap.org/data/2.5/weather?q={}&appid={}&units=metric", city, api_key);
        
        // Print the URL with partially obscured API key
        let obscured_url = url.replace(&api_key, &format!("{}...", &api_key[..5]));
        println!("Requesting URL: {}", obscured_url);

        let client = Client::new();
        let response = client.get(&url).send().await?;
        
        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(format!("API request failed with status: {}. Response: {}", status, error_text).into());
        }
        
        let text = response.text().await?;
        println!("Raw API response: {}", text); // Debug print
        
        let json: Value = serde_json::from_str(&text)?;
        
        if let Some(error_msg) = json.get("message") {
            return Err(format!("API error: {}", error_msg).into());
        }
        
        let temperature = json["main"]["temp"]
            .as_f64()
            .ok_or("Failed to parse temperature")?;
        let description = json["weather"][0]["description"]
            .as_str()
            .ok_or("Failed to parse weather description")?;
        
        Ok(format!("Weather in {}: {:.1}°C, {}", city, temperature, description))
    }
}

struct SimpleTlsConnection;

impl TlsConnection for SimpleTlsConnection {
    fn negotiated_cipher_suite(&self) -> Option<String> {
        Some("TLS_AES_256_GCM_SHA384".to_string())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a simple TLS connection
    let tls_connection = Arc::new(SimpleTlsConnection);

    // Set up the extractor and proof generator
    let content_extractor = WeatherDataExtractor;
    let proof_generator = WebProofGenerator::new(tls_connection, content_extractor)?;

    // Generate the web proof
    let proof = match proof_generator.generate_webproof().await {
        Ok(p) => p,
        Err(e) => {
            println!("Error generating proof: {}", e);
            return Err(e);
        }
    };
    let public_key = proof_generator.public_key()?;

    println!("Weather Data:");
    println!("{}", proof.split('|').nth(2).unwrap_or("Failed to extract weather data"));
    println!("\nGenerated Web Proof: {}", proof);

    // Verify the proof
    let is_valid = webproof::verify_webproof(&proof, &public_key)?;
    println!("\nProof verification result: {}", if is_valid { "Valid" } else { "Invalid" });

    Ok(())
}
