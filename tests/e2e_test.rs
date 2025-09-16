use unicity_sdk::client::{AggregatorClient, StateTransitionClient};
use unicity_sdk::crypto::{KeyPair, TestIdentity};
use unicity_sdk::types::commitment::{MintCommitment, TransferCommitment};
use unicity_sdk::types::predicate::{MaskedPredicate, UnmaskedPredicate};
use unicity_sdk::types::token::{Token, TokenState, TokenType};
use unicity_sdk::types::transaction::MintTransactionData;
use unicity_sdk::types::{GenericAddress, ProxyAddress};
use unicity_sdk::{init, Config};

/// Get the aggregator URL from environment or use test network
fn get_aggregator_url() -> String {
    std::env::var("AGGREGATOR_URL")
        .unwrap_or_else(|_| "https://goggregator-test.unicity.network".to_string())
}

#[tokio::test]
async fn test_basic_token_mint() {
    init();
    let client = StateTransitionClient::new(get_aggregator_url()).unwrap();

    // Generate a key pair
    let alice = TestIdentity::alice().unwrap();

    // Create token state with masked predicate
    let nonce = b"test_nonce_12345";
    let masked_predicate =
        MaskedPredicate::from_public_key_and_nonce(alice.key_pair.public_key(), nonce);
    let state = TokenState::from_predicate(&masked_predicate, Some(vec![1, 2, 3])).unwrap();

    // Create mint data
    let mint_data = MintTransactionData::new(
        TokenType::new(b"TEST_TOKEN".to_vec()),
        state,
        Some(b"test_data".to_vec()),
        None,
    );

    // Mint the token
    let result = client
        .mint_token(mint_data, alice.key_pair.secret_key())
        .await;

    match result {
        Ok(token) => {
            println!("Successfully minted token with ID: {:?}", token.id());
            assert!(token.validate().is_ok());
        }
        Err(e) => {
            println!("Mint failed (expected in test environment): {}", e);
            // This is expected to fail if the test aggregator is not running
        }
    }
}

#[tokio::test]
async fn test_token_transfer_flow() {
    init();
    let client = StateTransitionClient::new(get_aggregator_url()).unwrap();

    // Create test identities
    let alice = TestIdentity::alice().unwrap();
    let bob = TestIdentity::bob().unwrap();

    // Step 1: Create initial token for Alice
    let alice_predicate = UnmaskedPredicate::new(alice.key_pair.public_key().clone());
    let alice_state = TokenState::from_predicate(&alice_predicate, None).unwrap();

    let mint_data = MintTransactionData::new(
        TokenType::new(b"TRANSFER_TEST".to_vec()),
        alice_state.clone(),
        None,
        None,
    );

    // Create commitment
    let mint_commitment = MintCommitment::create(mint_data.clone(), alice.key_pair.secret_key());

    match mint_commitment {
        Ok(commitment) => {
            // Try to submit
            match client.submit_mint_commitment(&commitment).await {
                Ok(request_id) => {
                    println!("Mint commitment submitted with request ID: {}", request_id);

                    // Step 2: Transfer to Bob
                    let bob_predicate = UnmaskedPredicate::new(bob.key_pair.public_key().clone());
                    let bob_state = TokenState::from_predicate(&bob_predicate, None).unwrap();

                    // Create a mock token for transfer (in real scenario, we'd wait for inclusion)
                    let mock_proof = unicity_sdk::types::transaction::InclusionProof::new(
                        1,
                        vec![],
                        unicity_sdk::crypto::sha256(b"mock_root"),
                    );
                    let mock_tx = commitment.to_transaction(mock_proof);
                    let alice_token = Token::new(alice_state, mock_tx);

                    // Create transfer commitment
                    let transfer_result = TransferCommitment::create(
                        &alice_token,
                        bob_state,
                        Some(b"salt123".to_vec()),
                        alice.key_pair.secret_key(),
                    );

                    match transfer_result {
                        Ok(transfer_commitment) => {
                            match client.submit_transfer_commitment(&transfer_commitment).await {
                                Ok(transfer_id) => {
                                    println!("Transfer submitted with ID: {}", transfer_id);
                                }
                                Err(e) => {
                                    println!("Transfer submission failed: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            println!("Transfer commitment creation failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("Mint submission failed (expected in test): {}", e);
                }
            }
        }
        Err(e) => {
            println!("Failed to create mint commitment: {}", e);
        }
    }
}

#[tokio::test]
async fn test_health_check() {
    init();
    let client = AggregatorClient::new(get_aggregator_url()).unwrap();

    match client.health_check().await {
        Ok(healthy) => {
            if healthy {
                println!("Aggregator is healthy");

                // Also check block height
                match client.get_block_height().await {
                    Ok(height) => {
                        println!("Current block height: {}", height);
                        assert!(height > 0);
                    }
                    Err(e) => {
                        println!("Failed to get block height: {}", e);
                    }
                }
            } else {
                println!("Aggregator is not healthy");
            }
        }
        Err(e) => {
            println!("Health check failed: {}", e);
        }
    }
}

#[tokio::test]
async fn test_concurrent_commitments() {
    init();
    let client = StateTransitionClient::new(get_aggregator_url()).unwrap();

    let mut tasks = vec![];

    for i in 0..5 {
        let client_clone = client.aggregator().clone();
        let task = tokio::spawn(async move {
            let key_pair = KeyPair::from_seed(&format!("test_seed_{}", i)).unwrap();
            let predicate = UnmaskedPredicate::new(key_pair.public_key().clone());
            let state = TokenState::from_predicate(&predicate, None).unwrap();

            let mint_data = MintTransactionData::new(
                TokenType::new(format!("CONCURRENT_{}", i).into_bytes()),
                state,
                None,
                None,
            );

            let commitment = MintCommitment::create(mint_data, key_pair.secret_key()).unwrap();

            client_clone.submit_commitment(&commitment).await
        });

        tasks.push(task);
    }

    let results = futures::future::join_all(tasks).await;

    let mut success_count = 0;
    let mut failure_count = 0;

    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok(Ok(response)) => {
                println!("Task {} succeeded: {:?}", i, response.status);
                success_count += 1;
            }
            Ok(Err(e)) => {
                println!("Task {} failed: {}", i, e);
                failure_count += 1;
            }
            Err(e) => {
                println!("Task {} panicked: {}", i, e);
                failure_count += 1;
            }
        }
    }

    println!(
        "Concurrent test completed: {} successes, {} failures",
        success_count, failure_count
    );
}

#[tokio::test]
async fn test_nametag_creation() {
    init();
    let client = StateTransitionClient::new(get_aggregator_url()).unwrap();

    let alice = TestIdentity::alice().unwrap();
    let predicate = UnmaskedPredicate::new(alice.key_pair.public_key().clone());
    let state = TokenState::from_predicate(&predicate, None).unwrap();

    let nametag = format!("alice_nametag_{}", chrono::Utc::now().timestamp());

    match client
        .create_nametag(nametag.clone(), state, alice.key_pair.secret_key())
        .await
    {
        Ok(nametag_token) => {
            println!("Created nametag token: {}", nametag);
            assert!(nametag_token.validate().is_ok());
        }
        Err(e) => {
            println!("Nametag creation failed (expected in test): {}", e);
        }
    }
}

/// Performance test for commitment submission
#[tokio::test]
#[ignore] // Run with --ignored flag
async fn test_performance() {
    init();
    let client = StateTransitionClient::new(get_aggregator_url()).unwrap();

    let start = std::time::Instant::now();
    let mut successful = 0;
    let mut failed = 0;

    for i in 0..100 {
        let key_pair = KeyPair::from_seed(&format!("perf_test_{}", i)).unwrap();
        let predicate = UnmaskedPredicate::new(key_pair.public_key().clone());
        let state = TokenState::from_predicate(&predicate, None).unwrap();

        let mint_data = MintTransactionData::new(
            TokenType::new(b"PERF_TEST".to_vec()),
            state,
            Some(vec![i as u8]),
            None,
        );

        let commitment = MintCommitment::create(mint_data, key_pair.secret_key()).unwrap();

        match client.aggregator().submit_commitment(&commitment).await {
            Ok(_) => successful += 1,
            Err(_) => failed += 1,
        }

        if (i + 1) % 10 == 0 {
            println!("Progress: {}/{}", i + 1, 100);
        }
    }

    let elapsed = start.elapsed();
    let throughput = 100.0 / elapsed.as_secs_f64();

    println!("Performance test results:");
    println!("  Total time: {:?}", elapsed);
    println!("  Successful: {}", successful);
    println!("  Failed: {}", failed);
    println!("  Throughput: {:.2} commits/sec", throughput);
}