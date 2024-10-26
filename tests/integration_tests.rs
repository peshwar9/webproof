use webproof::{generate_webproof, verify_webproof};
use ring::signature::{Ed25519KeyPair, KeyPair};
use ring::rand::SystemRandom;

#[tokio::test]
async fn test_generate_and_verify_valid_webproof() {
    let rng = SystemRandom::new();
    let key_pair = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(key_pair.as_ref()).unwrap();

    let test_content = "Test web content";
    
    let proof = generate_webproof(test_content, &key_pair)
        .await
        .expect("Failed to generate webproof");

    let public_key = key_pair.public_key();
    let is_valid = verify_webproof(&proof, public_key.as_ref())
        .expect("Failed to verify webproof");

    assert!(is_valid);
}

#[tokio::test]
async fn test_invalid_proof() {
    let rng = SystemRandom::new();
    let key_pair = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(key_pair.as_ref()).unwrap();

    let test_content = "Test web content";
    
    let mut proof = generate_webproof(test_content, &key_pair)
        .await
        .expect("Failed to generate webproof");

    // Tamper with the proof
    proof.push('x');

    let public_key = key_pair.public_key();
    let is_valid = verify_webproof(&proof, public_key.as_ref())
        .expect("Failed to verify webproof");

    assert!(!is_valid, "Tampered proof should not be valid");
}
