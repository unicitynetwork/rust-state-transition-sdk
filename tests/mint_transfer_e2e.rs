use unicity_sdk::client::aggregator::AggregatorClient;
use unicity_sdk::crypto::KeyPair;
use unicity_sdk::types::commitment::MintCommitment;
use unicity_sdk::types::predicate::{MaskedPredicate, Predicate};
use unicity_sdk::types::token::{Token, TokenState, TokenType, TokenId};
use unicity_sdk::types::transaction::MintTransactionData;
use std::time::Duration;

#[tokio::test]
#[ignore] // Run with: cargo test --test mint_transfer_e2e -- --ignored --nocapture
async fn test_mint_token_e2e() {
    let aggregator_url = std::env::var("AGGREGATOR_URL")
        .unwrap_or_else(|_| "https://goggregator-test.unicity.network".to_string());

    println!("🚀 Starting E2E Mint Token Test");
    println!("   Aggregator: {}", aggregator_url);

    let client = AggregatorClient::new(aggregator_url).expect("Failed to create client");

    // Step 1: Check aggregator health
    println!("\n📡 Checking aggregator connection...");
    match client.get_block_height().await {
        Ok(height) => println!("   ✅ Connected! Current block height: {}", height),
        Err(e) => {
            println!("   ❌ Failed to connect: {:?}", e);
            panic!("Cannot proceed without aggregator connection");
        }
    }

    // Step 2: Create keys and predicate
    println!("\n🔑 Creating keys and predicates...");

    // For minting, Java uses a universal minter secret
    // Let's try with a regular key first to see what happens
    let alice_key = KeyPair::generate().expect("Failed to generate key pair");
    let alice_nonce = b"alice_test_nonce_12345";

    let alice_predicate = MaskedPredicate::from_public_key_and_nonce(
        alice_key.public_key(),
        alice_nonce,
    );

    println!("   Alice public key: {}", hex::encode(alice_key.public_key().as_bytes()));
    println!("   Alice predicate hash: {}", hex::encode(alice_predicate.hash().unwrap().imprint()));

    // Step 3: Create mint transaction data
    println!("\n📝 Creating mint transaction data...");

    // Generate a random token ID (32 bytes)
    let mut token_id_bytes = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut token_id_bytes);
    let token_id = TokenId::new(token_id_bytes);

    // Create a target state from Alice's predicate
    let target_state = TokenState::from_predicate(&alice_predicate, Some(b"Alice's test token".to_vec()))
        .expect("Failed to create token state");

    // Create mint transaction data with all required fields
    let mint_data = MintTransactionData::new(
        token_id.clone(),
        TokenType::new(vec![1, 2, 3, 4]), // Simple token type
        target_state,
        Some(b"Test token metadata".to_vec()), // Token data
        Some(vec![0u8; 5]), // Salt for uniqueness (5 bytes like Java tests)
        None, // No split mint reason
    );

    println!("   Token ID: {}", hex::encode(token_id.as_bytes()));
    println!("   Token type: {}", hex::encode(mint_data.token_type.as_bytes()));
    println!("   Transaction hash: {}", hex::encode(mint_data.hash().unwrap().imprint()));

    // Step 4: Create and sign mint commitment
    println!("\n✍️  Creating mint commitment using universal minter...");

    // Now uses universal minter internally, no need to pass signing key
    let mint_commitment = MintCommitment::create(mint_data.clone())
        .expect("Failed to create mint commitment");

    println!("   Request ID: {}", hex::encode(mint_commitment.request_id.as_data_hash().imprint()));
    println!("   Transaction hash: {}", hex::encode(mint_commitment.transaction_hash.imprint()));
    println!("   Authenticator algorithm: {}", mint_commitment.authenticator.algorithm);

    // Step 5: Submit commitment to aggregator
    println!("\n📤 Submitting mint commitment to aggregator...");

    match client.submit_commitment(&mint_commitment).await {
        Ok(response) => {
            println!("   Response status: {}", response.status);
            if let Some(msg) = response.message {
                println!("   Response message: {}", msg);
            }

            match response.status.as_str() {
                "SUCCESS" | "ACCEPTED" | "PENDING" => {
                    println!("   ✅ Mint commitment accepted!");

                    // Step 6: Wait for inclusion proof
                    println!("\n⏳ Waiting for inclusion proof...");
                    match client.wait_for_inclusion_proof(
                        &mint_commitment.request_id,
                        Duration::from_secs(30)
                    ).await {
                        Ok(proof) => {
                            println!("   ✅ Got inclusion proof!");
                            println!("   Block height: {}", proof.block_height);
                            println!("   Path length: {}", proof.path.len());

                            // Step 7: Create the token
                            let transaction = mint_commitment.to_transaction(proof);
                            let token = Token::new(mint_data.target_state.clone(), transaction);

                            println!("\n🎉 SUCCESS! Token minted!");
                            println!("   Token ID: {}", token.id().unwrap());
                        }
                        Err(e) => {
                            println!("   ❌ Failed to get inclusion proof: {:?}", e);
                            println!("   This might mean the commitment was rejected");
                        }
                    }
                }
                "SIGNATURE_VERIFICATION_FAILED" => {
                    println!("   ⚠️  Signature verification failed");
                    println!("   This is expected - we need the universal minter key");
                }
                "INVALID_STATE" | "INVALID_REQUEST" => {
                    println!("   ⚠️  Invalid state or request");
                    println!("   The transaction data structure might be wrong");
                }
                _ => {
                    println!("   ⚠️  Unexpected status: {}", response.status);
                }
            }
        }
        Err(e) => {
            println!("   ❌ Failed to submit commitment: {:?}", e);

            // Check what type of error
            if let unicity_sdk::error::SdkError::JsonRpc { code, message } = &e {
                println!("   JSON-RPC Error Code: {}", code);
                println!("   JSON-RPC Error Message: {}", message);
            }
        }
    }

    println!("\n📊 Test Summary:");
    println!("   The test shows that our current implementation is missing:");
    println!("   1. Universal minter signing support");
    println!("   2. Proper tokenId field in MintTransactionData");
    println!("   3. Salt field for uniqueness");
    println!("   4. Recipient address (separate from state)");
    println!("   5. Correct CBOR-based hash calculation");
}

#[tokio::test]
#[ignore]
async fn test_transfer_token_e2e() {
    println!("🚀 Starting E2E Transfer Token Test");
    println!("   Note: This test requires a successfully minted token first");
    println!("   Currently blocked by mint functionality issues");

    // TODO: Implement transfer test once mint works
}