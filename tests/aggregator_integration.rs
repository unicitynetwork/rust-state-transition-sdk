use unicity_sdk::client::aggregator::AggregatorClient;
use unicity_sdk::crypto::KeyPair;
use unicity_sdk::types::commitment::{Commitment, MintCommitment};
use unicity_sdk::types::predicate::UnmaskedPredicate;
use unicity_sdk::types::token::{TokenState, TokenType};
use unicity_sdk::types::transaction::MintTransactionData;

#[tokio::test]
#[ignore] // Run with: cargo test --test aggregator_integration -- --ignored --nocapture
async fn test_aggregator_payload_format() {
    // Use the test aggregator
    let aggregator_url = std::env::var("AGGREGATOR_URL")
        .unwrap_or_else(|_| "https://goggregator-test.unicity.network".to_string());

    println!("Testing against aggregator: {}", aggregator_url);

    let client = AggregatorClient::new(aggregator_url).expect("Failed to create client");

    // Generate test keys
    let key_pair = KeyPair::generate().expect("Failed to generate key pair");
    let public_key = key_pair.public_key().clone();
    let signing_key = key_pair.secret_key();

    // Create a test mint commitment
    let predicate = UnmaskedPredicate::new(public_key.clone());
    let target_state =
        TokenState::from_predicate(&predicate, None).expect("Failed to create state");

    let mint_data = MintTransactionData::new(
        TokenType::new(vec![1, 2, 3, 4]),
        target_state,
        Some(vec![5, 6, 7, 8]),
        None,
    );

    let commitment =
        MintCommitment::create(mint_data, signing_key).expect("Failed to create commitment");

    println!("Created commitment with:");
    println!(
        "  - Request ID: {}",
        hex::encode(commitment.request_id().as_data_hash().imprint())
    );
    println!(
        "  - Transaction Hash: {}",
        hex::encode(commitment.transaction_hash().imprint())
    );
    println!(
        "  - Authenticator Algorithm: {}",
        commitment.authenticator().algorithm
    );
    println!(
        "  - State Hash: {}",
        hex::encode(commitment.authenticator().state_hash.imprint())
    );

    // Submit the commitment
    println!("\nSubmitting commitment to aggregator...");
    match client.submit_commitment(&commitment).await {
        Ok(response) => {
            println!("✅ Successfully submitted commitment!");
            println!("Response status: {}", response.status);
            if let Some(msg) = response.message {
                println!("Message: {}", msg);
            }
        }
        Err(e) => {
            println!("❌ Failed to submit commitment: {:?}", e);

            // Check if it's just a validation error (which means the format was accepted)
            if let unicity_sdk::error::SdkError::JsonRpc { code, message } = &e {
                println!("JSON-RPC Error - Code: {}, Message: {}", code, message);
                println!("This is likely a validation error, which means the payload format was accepted!");
            } else {
                println!("This could be a format issue or network error");
            }
        }
    }

    // Test get_block_height to ensure basic connectivity
    match client.get_block_height().await {
        Ok(height) => {
            println!("✅ Current block height: {}", height);
        }
        Err(e) => {
            println!("❌ Failed to get block height: {:?}", e);
        }
    }

    // Test health check
    match client.health_check().await {
        Ok(healthy) => {
            println!(
                "✅ Health check: {}",
                if healthy { "HEALTHY" } else { "UNHEALTHY" }
            );
        }
        Err(e) => {
            println!("❌ Failed health check: {:?}", e);
        }
    }
}

#[tokio::test]
#[ignore] // Run with: cargo test --test aggregator_integration -- --ignored --nocapture
async fn test_json_payload_structure() {
    use unicity_sdk::client::aggregator::AuthenticatorDto;
    use unicity_sdk::types::commitment::Authenticator;
    use unicity_sdk::types::primitives::{DataHash, Signature};

    // Create test data
    let key_pair = KeyPair::generate().expect("Failed to generate key pair");
    let public_key = key_pair.public_key().clone();
    let signature = Signature::new([0u8; 65]);

    // Create proper 32-byte hash
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&[1, 2, 3]);
    let hash_bytes = hasher.finalize().to_vec();
    let state_hash = DataHash::sha256(hash_bytes);

    // Create authenticator
    let authenticator = Authenticator::new(public_key.clone(), signature, state_hash.clone());
    let dto = AuthenticatorDto::from(&authenticator);

    // Verify the DTO has all required fields
    assert_eq!(dto.algorithm, "secp256k1");
    assert_eq!(dto.public_key.len(), 66); // 33 bytes hex encoded
    assert_eq!(dto.signature.len(), 130); // 65 bytes hex encoded

    println!("State hash imprint bytes: {:?}", state_hash.imprint());
    println!("State hash hex: {}", dto.state_hash);
    println!("State hash hex length: {}", dto.state_hash.len());

    assert_eq!(dto.state_hash.len(), 68); // 34 bytes (2 algo + 32 hash) hex encoded

    println!("✅ AuthenticatorDto structure is correct:");
    println!("  - algorithm: {}", dto.algorithm);
    println!(
        "  - public_key: {} (length: {})",
        &dto.public_key[..10],
        dto.public_key.len()
    );
    println!(
        "  - signature: {} (length: {})",
        &dto.signature[..10],
        dto.signature.len()
    );
    println!(
        "  - state_hash: {} (length: {})",
        &dto.state_hash[..10],
        dto.state_hash.len()
    );

    // Test JSON serialization
    let json = serde_json::to_string_pretty(&dto).expect("Failed to serialize");
    println!("\nJSON payload structure:");
    println!("{}", json);

    // Verify all expected fields are present in JSON
    assert!(json.contains("\"algorithm\""));
    assert!(json.contains("\"publicKey\""));
    assert!(json.contains("\"signature\""));
    assert!(json.contains("\"stateHash\""));

    println!("\n✅ All required fields present in JSON payload");
}
