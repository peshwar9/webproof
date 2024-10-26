use webproof::{generate_webproof, verify_webproof};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let eth_price = 1234.56;
    let session_id = b"some-unique-session-id";

    let webproof = generate_webproof(eth_price, session_id)?;
    println!("Generated WebProof: {}", webproof);

    let is_valid = verify_webproof(&webproof, 300)?;
    println!("WebProof is valid: {}", is_valid);

    Ok(())
}
