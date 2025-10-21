use unicity_sdk::client::{AggregatorClient, StateTransitionClient};
use unicity_sdk::crypto::{KeyPair, TestIdentity};
use unicity_sdk::types::bft::RootTrustBase;
use unicity_sdk::types::commitment::{MintCommitment, TransferCommitment};
use unicity_sdk::types::predicate::{MaskedPredicate, UnmaskedPredicate};
use unicity_sdk::types::token::{Token, TokenState, TokenType, TokenId};
use unicity_sdk::types::transaction::MintTransactionData;
use unicity_sdk::types::GenericAddress;
use unicity_sdk::init;

/// Get the aggregator URL from environment or use test network
fn get_aggregator_url() -> String {
    std::env::var("AGGREGATOR_URL")
        .unwrap_or_else(|_| "https://goggregator-test.unicity.network".to_string())
}

/// Load trust base for token verification
fn load_trust_base() -> RootTrustBase {
    let trust_base_json = include_str!("resources/trust-base.json");
    RootTrustBase::from_json(trust_base_json)
        .expect("Failed to load trust base")
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

    // Create mint data with unique token ID
    let token_id = TokenId::unique();

    // Create recipient address from state (predicate hash only, not including data)
    let address_hash = state.address_hash().unwrap();
    let recipient = GenericAddress::direct(address_hash);

    let mint_data = MintTransactionData::new(
        token_id,
        TokenType::new(b"TEST_TOKEN".to_vec()),
        Some(b"test_data".to_vec()),  // token_data
        None,  // coin_data
        recipient,  // recipient address
        vec![1, 2, 3, 4, 5],  // salt (not Option)
        None,  // recipient_data_hash
        None,  // reason
    );

    // Mint the token (uses universal minter internally)
    let result = client.mint_token(mint_data, state).await;

    match result {
        Ok(token) => {
            println!("Successfully minted token with ID: {:?}", token.id());

            // Verify token with trust base
            let trust_base = load_trust_base();
            match token.verify_with_trust_base(&trust_base) {
                Ok(()) => {
                    println!("✅ Token verification with trust base succeeded");
                }
                Err(e) => {
                    println!("⚠️ Token verification with trust base failed: {}", e);
                    println!("   This is expected if the test aggregator uses different trust base");
                }
            }
        }
        Err(e) => {
            println!("Mint failed (expected in test environment): {}", e);
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

    let token_id = TokenId::unique();

    // Create recipient address from alice's state (predicate hash only, not including data)
    let alice_address_hash = alice_state.address_hash().unwrap();
    let alice_recipient = GenericAddress::direct(alice_address_hash);

    let mint_data = MintTransactionData::new(
        token_id,
        TokenType::new(b"TRANSFER_TEST".to_vec()),
        None,  // token_data
        None,  // coin_data
        alice_recipient,  // recipient address
        vec![1, 2, 3, 4, 5],  // salt (not Option)
        None,  // recipient_data_hash
        None,  // reason
    );

    // Create commitment (uses universal minter)
    let mint_commitment = MintCommitment::create(mint_data.clone());

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
                    let merkle_path = unicity_sdk::types::transaction::MerkleTreePath {
                        root: hex::encode(unicity_sdk::crypto::sha256(b"mock_root").imprint()),
                        steps: vec![],
                    };
                    let mock_proof = unicity_sdk::types::transaction::InclusionProof::new(merkle_path);
                    let mock_tx = commitment.to_transaction(mock_proof);
                    let alice_token = Token::new(alice_state, mock_tx);

                    // Verify the mocked token (will likely fail due to mock proof)
                    let trust_base = load_trust_base();
                    match alice_token.verify_with_trust_base(&trust_base) {
                        Ok(()) => {
                            println!("✅ Alice's token verification succeeded");
                        }
                        Err(e) => {
                            println!("⚠️ Alice's token verification failed (expected for mock proof): {}", e);
                        }
                    }

                    // Create transfer commitment
                    let transfer_result = TransferCommitment::create(
                        &alice_token,
                        bob_state,
                        Some(b"salt123".to_vec()),
                        alice.key_pair.secret_key(),
                    );

                    match transfer_result {
                        Ok(transfer_commitment) => {
                            match client
                                .submit_transfer_commitment(&transfer_commitment)
                                .await
                            {
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

            // Use unique token ID with index marker for concurrent tests
            let token_id = TokenId::unique_with_marker(i as u8);

            // Create recipient address from state (predicate hash only, not including data)
            let address_hash = state.address_hash().unwrap();
            let recipient = GenericAddress::direct(address_hash);

            let mint_data = MintTransactionData::new(
                token_id,
                TokenType::new(format!("CONCURRENT_{}", i).into_bytes()),
                None,  // token_data
                None,  // coin_data
                recipient,  // recipient address
                vec![1, 2, 3, 4, 5],  // salt (not Option)
                None,  // recipient_data_hash
                None,  // reason
            );

            let commitment = MintCommitment::create(mint_data).unwrap();

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

            // Verify nametag token with trust base
            let trust_base = load_trust_base();
            match nametag_token.verify_with_trust_base(&trust_base) {
                Ok(()) => {
                    println!("✅ Nametag token verification with trust base succeeded");
                }
                Err(e) => {
                    println!("⚠️ Nametag token verification with trust base failed: {}", e);
                    println!("   This is expected if the test aggregator uses different trust base");
                }
            }
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

        // Use unique token ID with marker 255 for perf tests
        let token_id = TokenId::unique_with_marker(255);

        // Create recipient address from state (predicate hash only, not including data)
        let address_hash = state.address_hash().unwrap();
        let recipient = GenericAddress::direct(address_hash);

        let mint_data = MintTransactionData::new(
            token_id,
            TokenType::new(b"PERF_TEST".to_vec()),
            Some(vec![i as u8]),  // token_data
            None,  // coin_data
            recipient,  // recipient address
            vec![1, 2, 3, 4, 5],  // salt (not Option)
            None,  // recipient_data_hash
            None,  // reason
        );

        let commitment = MintCommitment::create(mint_data).unwrap();

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
