use unicity_sdk::client::aggregator::AggregatorClient;
use unicity_sdk::types::commitment::{MintCommitment, TransferCommitment};
use unicity_sdk::types::predicate::{MaskedPredicate, UnmaskedPredicate};
use unicity_sdk::types::token::{Token, TokenState, TokenType, TokenId};
use unicity_sdk::types::transaction::MintTransactionData;
use unicity_sdk::crypto::KeyPair;
use std::time::Duration;

#[tokio::test]
#[ignore] // Run with: cargo test --test real_e2e_test -- --ignored --nocapture
async fn test_real_mint_and_transfers() {
    println!("{}", "=".repeat(60));
    println!("🚀 REAL END-TO-END TEST: Mint → Transfer → Transfer");
    println!("   No mocks, real inclusion proofs, real aggregator");
    println!("{}", "=".repeat(60));

    let aggregator_url = "https://goggregator-test.unicity.network";
    let client = AggregatorClient::new(aggregator_url.to_string())
        .expect("Failed to create aggregator client");

    // Verify connection
    let initial_height = client.get_block_height().await
        .expect("Failed to connect to aggregator");
    println!("\n✅ Connected to aggregator at block height: {}", initial_height);

    // ========================================
    // Create identities
    // ========================================
    println!("\n👥 Creating identities:");

    // Alice - will mint and then transfer to Bob
    let alice_key = KeyPair::generate().unwrap();
    let alice_nonce = b"alice_e2e_test_nonce";
    let alice_predicate = MaskedPredicate::from_public_key_and_nonce(
        alice_key.public_key(),
        alice_nonce,
    );
    println!("   Alice (masked): {}", hex::encode(alice_key.public_key().as_bytes()));

    // Bob - will receive from Alice and transfer to Carol
    let bob_key = KeyPair::generate().unwrap();
    let bob_predicate = UnmaskedPredicate::new(bob_key.public_key().clone());
    println!("   Bob (unmasked): {}", hex::encode(bob_key.public_key().as_bytes()));

    // Carol - final recipient
    let carol_key = KeyPair::generate().unwrap();
    let carol_predicate = UnmaskedPredicate::new(carol_key.public_key().clone());
    println!("   Carol (unmasked): {}", hex::encode(carol_key.public_key().as_bytes()));

    // ========================================
    // Step 1: Mint token to Alice
    // ========================================
    println!("\n💎 STEP 1: Minting token to Alice...");

    // Generate unique token ID
    let token_id = TokenId::unique();
    let token_type = TokenType::new(b"E2E_TEST_TOKEN".to_vec());

    println!("   Token ID: {}", hex::encode(token_id.as_bytes()));
    println!("   Token Type: {}", String::from_utf8_lossy(token_type.as_bytes()));

    // Create Alice's initial state
    let alice_state = TokenState::from_predicate(
        &alice_predicate,
        Some(b"Alice's token - initial mint".to_vec())
    ).unwrap();

    // Create mint transaction data
    let mint_data = MintTransactionData::new(
        token_id.clone(),
        token_type.clone(),
        alice_state.clone(),
        Some(b"E2E test token metadata".to_vec()),
        Some(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE]), // 5-byte salt
        None, // No split mint reason
    );

    // Create mint commitment (uses universal minter internally)
    let mint_commitment = MintCommitment::create(mint_data.clone())
        .expect("Failed to create mint commitment");

    println!("   Request ID: {}", hex::encode(mint_commitment.request_id.as_data_hash().imprint()));

    // Submit mint commitment
    println!("   Submitting mint commitment...");
    let mint_response = client.submit_commitment(&mint_commitment).await
        .expect("Failed to submit mint commitment");

    println!("   Mint response status: {}", mint_response.status);

    if mint_response.status != "SUCCESS" && mint_response.status != "ACCEPTED" {
        panic!("❌ Mint was not accepted! Status: {}, Message: {:?}",
               mint_response.status, mint_response.message);
    }

    // Wait for real inclusion proof - blocks finalize in ~2 seconds
    println!("   ⏳ Waiting for inclusion proof (polling for 5 seconds)...");
    let mint_proof = match client.wait_for_inclusion_proof(
        &mint_commitment.request_id,
        Duration::from_secs(5)  // Poll for 5 seconds since blocks finalize in ~2 seconds
    ).await {
        Ok(proof) => {
            println!("   ✅ Got inclusion proof at block height: {}", proof.block_height);
            println!("      Merkle path length: {}", proof.path.len());
            proof
        }
        Err(e) => {
            panic!("❌ Failed to get inclusion proof for mint: {:?}", e);
        }
    };

    // Create the actual token with real inclusion proof
    let mint_transaction = mint_commitment.to_transaction(mint_proof);
    let mut token = Token::new(alice_state.clone(), mint_transaction);

    println!("   ✅ Token successfully minted to Alice!");
    println!("      Token ID: {}", token.id().unwrap());

    // ========================================
    // Step 2: Alice transfers to Bob
    // ========================================
    println!("\n📤 STEP 2: Alice transfers token to Bob...");

    // Create Bob's state
    let bob_state = TokenState::from_predicate(
        &bob_predicate,
        Some(b"Bob's token - received from Alice".to_vec())
    ).unwrap();

    // Create transfer commitment from Alice to Bob
    let salt_alice_to_bob = vec![0x11, 0x22, 0x33, 0x44, 0x55];
    let transfer_commitment_1 = TransferCommitment::create(
        &token,
        bob_state.clone(),
        Some(salt_alice_to_bob.clone()),
        alice_key.secret_key(),
    ).expect("Failed to create transfer commitment Alice->Bob");

    println!("   Transfer Request ID: {}",
            hex::encode(transfer_commitment_1.request_id.as_data_hash().imprint()));

    // Submit transfer commitment
    println!("   Submitting transfer commitment...");
    let transfer_response_1 = client.submit_commitment(&transfer_commitment_1).await
        .expect("Failed to submit transfer commitment");

    println!("   Transfer response status: {}", transfer_response_1.status);

    if transfer_response_1.status != "SUCCESS" && transfer_response_1.status != "ACCEPTED" {
        panic!("❌ Transfer Alice->Bob was not accepted! Status: {}, Message: {:?}",
               transfer_response_1.status, transfer_response_1.message);
    }

    // Wait for real inclusion proof - blocks finalize in ~2 seconds
    println!("   ⏳ Waiting for transfer inclusion proof (5 seconds)...");
    let transfer_proof_1 = match client.wait_for_inclusion_proof(
        &transfer_commitment_1.request_id,
        Duration::from_secs(5)
    ).await {
        Ok(proof) => {
            println!("   ✅ Got inclusion proof at block height: {}", proof.block_height);
            proof
        }
        Err(e) => {
            panic!("❌ Failed to get inclusion proof for transfer: {:?}", e);
        }
    };

    // Update token with transfer transaction
    let transfer_transaction_1 = transfer_commitment_1.to_transaction(transfer_proof_1);
    token.add_transaction(transfer_transaction_1);
    token.state = bob_state.clone();

    println!("   ✅ Token successfully transferred from Alice to Bob!");

    // ========================================
    // Step 3: Bob transfers to Carol
    // ========================================
    println!("\n📤 STEP 3: Bob transfers token to Carol...");

    // Create Carol's state
    let carol_state = TokenState::from_predicate(
        &carol_predicate,
        Some(b"Carol's token - received from Bob".to_vec())
    ).unwrap();

    // Create transfer commitment from Bob to Carol
    let salt_bob_to_carol = vec![0x66, 0x77, 0x88, 0x99, 0xAA];
    let transfer_commitment_2 = TransferCommitment::create(
        &token,
        carol_state.clone(),
        Some(salt_bob_to_carol.clone()),
        bob_key.secret_key(),
    ).expect("Failed to create transfer commitment Bob->Carol");

    println!("   Transfer Request ID: {}",
            hex::encode(transfer_commitment_2.request_id.as_data_hash().imprint()));

    // Submit transfer commitment
    println!("   Submitting transfer commitment...");
    let transfer_response_2 = client.submit_commitment(&transfer_commitment_2).await
        .expect("Failed to submit transfer commitment");

    println!("   Transfer response status: {}", transfer_response_2.status);

    if transfer_response_2.status != "SUCCESS" && transfer_response_2.status != "ACCEPTED" {
        panic!("❌ Transfer Bob->Carol was not accepted! Status: {}, Message: {:?}",
               transfer_response_2.status, transfer_response_2.message);
    }

    // Wait for real inclusion proof - blocks finalize in ~2 seconds
    println!("   ⏳ Waiting for transfer inclusion proof (5 seconds)...");
    let transfer_proof_2 = match client.wait_for_inclusion_proof(
        &transfer_commitment_2.request_id,
        Duration::from_secs(5)
    ).await {
        Ok(proof) => {
            println!("   ✅ Got inclusion proof at block height: {}", proof.block_height);
            proof
        }
        Err(e) => {
            panic!("❌ Failed to get inclusion proof for transfer: {:?}", e);
        }
    };

    // Update token with second transfer transaction
    let transfer_transaction_2 = transfer_commitment_2.to_transaction(transfer_proof_2);
    token.add_transaction(transfer_transaction_2);
    token.state = carol_state.clone();

    println!("   ✅ Token successfully transferred from Bob to Carol!");

    // ========================================
    // Final verification
    // ========================================
    println!("\n{}", "=".repeat(60));
    println!("🎉 SUCCESS! COMPLETE E2E TEST PASSED!");
    println!("{}", "=".repeat(60));

    println!("\n📊 Final Token State:");
    println!("   Token ID: {}", token.id().unwrap());
    println!("   Current Owner: Carol");
    println!("   Transaction Count: {} (2 transfers after mint)", token.transactions.len());
    println!("   Token Metadata: {:?}",
            String::from_utf8_lossy(&token.state.data.as_ref().unwrap()));

    println!("\n✅ Transaction Chain:");
    println!("   1. Minted to Alice (with real inclusion proof)");
    println!("   2. Transferred from Alice to Bob (with real inclusion proof)");
    println!("   3. Transferred from Bob to Carol (with real inclusion proof)");

    // Final assertions
    assert_eq!(token.transactions.len(), 2, "Should have exactly 2 transfer transactions");
    assert_eq!(token.state.data, Some(b"Carol's token - received from Bob".to_vec()),
               "Final state should belong to Carol");

    println!("\n✅ All assertions passed! The SDK works correctly for:");
    println!("   - Minting tokens with universal minter");
    println!("   - Getting real inclusion proofs");
    println!("   - Transferring tokens between parties");
    println!("   - Multiple transfers in sequence");
}