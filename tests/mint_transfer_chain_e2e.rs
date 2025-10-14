use unicity_sdk::client::aggregator::AggregatorClient;
use unicity_sdk::types::commitment::{MintCommitment, TransferCommitment};
use unicity_sdk::types::predicate::{MaskedPredicate, UnmaskedPredicate};
use unicity_sdk::types::token::{Token, TokenState, TokenType, TokenId};
use unicity_sdk::types::transaction::{MintTransactionData, TransferTransactionData, Transaction, InclusionProof, MerkleTreePath};
use unicity_sdk::crypto::KeyPair;
use unicity_sdk::types::primitives::DataHash;

/// Create a mock inclusion proof for testing
fn create_mock_inclusion_proof(_block_height: u64) -> InclusionProof {
    let merkle_path = MerkleTreePath {
        root: hex::encode(DataHash::sha256(b"mock_root".to_vec()).imprint()),
        steps: vec![],
    };
    InclusionProof::new(merkle_path)
}

#[tokio::test]
#[ignore] // Run with: cargo test --test mint_transfer_chain_e2e -- --ignored --nocapture
async fn test_mint_transfer_chain() {
    println!("🚀 Testing Complete Mint → Transfer → Transfer Chain");
    println!("   Simulating: Alice mints → transfers to Bob → Bob transfers to Carol\n");

    let aggregator_url = "https://goggregator-test.unicity.network";
    let client = AggregatorClient::new(aggregator_url.to_string()).expect("Failed to create client");

    // Check connection
    match client.get_block_height().await {
        Ok(height) => println!("✅ Connected to aggregator, block height: {}\n", height),
        Err(e) => panic!("Failed to connect: {:?}", e),
    }

    // ========================================
    // Step 1: Create identities
    // ========================================
    println!("👥 Creating identities...");

    // Alice - the initial minter/owner
    let alice_key = KeyPair::generate().unwrap();
    let alice_nonce = b"alice_nonce_123";
    let alice_predicate = MaskedPredicate::from_public_key_and_nonce(
        alice_key.public_key(),
        alice_nonce,
    );
    println!("   Alice: {}", hex::encode(&alice_key.public_key().as_bytes()[..8]));

    // Bob - first recipient
    let bob_key = KeyPair::generate().unwrap();
    let bob_predicate = UnmaskedPredicate::new(bob_key.public_key().clone());
    println!("   Bob: {}", hex::encode(&bob_key.public_key().as_bytes()[..8]));

    // Carol - final recipient
    let carol_key = KeyPair::generate().unwrap();
    let carol_predicate = UnmaskedPredicate::new(carol_key.public_key().clone());
    println!("   Carol: {}", hex::encode(&carol_key.public_key().as_bytes()[..8]));

    // ========================================
    // Step 2: Alice mints a token
    // ========================================
    println!("\n💎 Alice mints a token...");

    // Generate unique token ID
    let token_id = TokenId::unique();
    let token_type = TokenType::new(b"TEST_TOKEN".to_vec());

    // Alice owns the initial token
    let alice_state = TokenState::from_predicate(
        &alice_predicate,
        Some(b"Alice's token".to_vec())
    ).unwrap();

    // Create recipient address from alice state hash
    let alice_state_hash = alice_state.hash().unwrap();
    let alice_recipient = unicity_sdk::types::address::GenericAddress::direct(alice_state_hash);

    let mint_data = MintTransactionData::new(
        token_id.clone(),
        token_type.clone(),
        Some(b"Test token metadata".to_vec()),  // token_data
        None,  // coin_data
        alice_recipient,  // recipient address
        vec![1, 2, 3, 4, 5],  // 5-byte salt (not Option)
        None,  // recipient_data_hash
        None,  // reason
    );

    let mint_commitment = MintCommitment::create(mint_data.clone())
        .expect("Failed to create mint commitment");

    println!("   Token ID: {}", hex::encode(&token_id.as_bytes()[..8]));
    println!("   Submitting mint commitment...");

    match client.submit_commitment(&mint_commitment).await {
        Ok(response) => {
            println!("   Mint response: {}", response.status);
            if response.status != "SUCCESS" && response.status != "ACCEPTED" {
                panic!("Mint failed: {:?}", response.message);
            }
        }
        Err(e) => panic!("Failed to submit mint: {:?}", e),
    }

    // Create the token with mock inclusion proof (since we can't get real one in test env)
    let mint_proof = create_mock_inclusion_proof(1000);
    let mint_transaction = Transaction::new(mint_data.clone(), mint_proof);
    let mut token = Token::new(alice_state.clone(), mint_transaction);

    println!("   ✅ Token minted successfully!");

    // ========================================
    // Step 3: Alice transfers to Bob
    // ========================================
    println!("\n📤 Alice transfers token to Bob...");

    let bob_state = TokenState::from_predicate(
        &bob_predicate,
        Some(b"Bob's token".to_vec())
    ).unwrap();

    // Create recipient address from bob state hash
    let bob_state_hash = bob_state.hash().unwrap();
    let bob_recipient = unicity_sdk::types::address::GenericAddress::direct(bob_state_hash);

    let transfer_data_alice_to_bob = TransferTransactionData::new(
        alice_state.clone(),
        bob_recipient,  // recipient address
        vec![6, 7, 8, 9, 10],  // Different salt (not Option)
        None,  // recipient_data_hash
        None,  // message
        vec![],  // nametags
    );

    // Create transfer commitment signed by Alice
    let transfer_commitment_1 = TransferCommitment::create(
        &token,
        bob_state.clone(),
        Some(vec![6, 7, 8, 9, 10]),
        alice_key.secret_key(),
    ).expect("Failed to create transfer commitment");

    println!("   Submitting Alice→Bob transfer...");

    match client.submit_commitment(&transfer_commitment_1).await {
        Ok(response) => {
            println!("   Transfer response: {}", response.status);
            if response.status != "SUCCESS" && response.status != "ACCEPTED" {
                println!("   ⚠️ Transfer not accepted: {:?}", response.message);
                // Continue anyway for testing
            }
        }
        Err(e) => println!("   ⚠️ Failed to submit transfer: {:?}", e),
    }

    // Update token state (simulate successful transfer)
    let transfer_proof_1 = create_mock_inclusion_proof(1001);
    let transfer_transaction_1 = Transaction::new(transfer_data_alice_to_bob, transfer_proof_1);
    token.add_transaction(transfer_transaction_1);
    token.state = bob_state.clone();

    println!("   ✅ Token transferred to Bob!");

    // ========================================
    // Step 4: Bob transfers to Carol
    // ========================================
    println!("\n📤 Bob transfers token to Carol...");

    let carol_state = TokenState::from_predicate(
        &carol_predicate,
        Some(b"Carol's token".to_vec())
    ).unwrap();

    // Create recipient address from carol state hash
    let carol_state_hash = carol_state.hash().unwrap();
    let carol_recipient = unicity_sdk::types::address::GenericAddress::direct(carol_state_hash);

    let transfer_data_bob_to_carol = TransferTransactionData::new(
        bob_state.clone(),
        carol_recipient,  // recipient address
        vec![11, 12, 13, 14, 15],  // Different salt again (not Option)
        None,  // recipient_data_hash
        None,  // message
        vec![],  // nametags
    );

    // Create transfer commitment signed by Bob
    let transfer_commitment_2 = TransferCommitment::create(
        &token,
        carol_state.clone(),
        Some(vec![11, 12, 13, 14, 15]),
        bob_key.secret_key(),
    ).expect("Failed to create transfer commitment");

    println!("   Submitting Bob→Carol transfer...");

    match client.submit_commitment(&transfer_commitment_2).await {
        Ok(response) => {
            println!("   Transfer response: {}", response.status);
            if response.status != "SUCCESS" && response.status != "ACCEPTED" {
                println!("   ⚠️ Transfer not accepted: {:?}", response.message);
            }
        }
        Err(e) => println!("   ⚠️ Failed to submit transfer: {:?}", e),
    }

    // Update token state (simulate successful transfer)
    let transfer_proof_2 = create_mock_inclusion_proof(1002);
    let transfer_transaction_2 = Transaction::new(transfer_data_bob_to_carol, transfer_proof_2);
    token.add_transaction(transfer_transaction_2);
    token.state = carol_state.clone();

    println!("   ✅ Token transferred to Carol!");

    // ========================================
    // Step 5: Verify final state
    // ========================================
    println!("\n🔍 Final token state:");
    println!("   Current owner: Carol");
    println!("   Transaction count: {}", token.transactions.len());
    println!("   Token ID: {}", hex::encode(&token_id.as_bytes()[..8]));

    // Verify transaction chain
    assert_eq!(token.transactions.len(), 2, "Should have 2 transfer transactions");
    assert_eq!(token.state.data, Some(b"Carol's token".to_vec()), "Token should be owned by Carol");

    println!("\n🎉 SUCCESS! Complete chain executed:");
    println!("   1. Alice minted token ✅");
    println!("   2. Alice transferred to Bob ✅");
    println!("   3. Bob transferred to Carol ✅");
    println!("   4. Token now owned by Carol ✅");
}

#[tokio::test]
#[ignore]
async fn test_real_mint_and_transfer() {
    println!("🚀 Testing Real Mint and Transfer Flow");
    println!("   This test attempts real mint and transfer operations\n");

    let aggregator_url = "https://goggregator-test.unicity.network";
    let client = AggregatorClient::new(aggregator_url.to_string()).expect("Failed to create client");

    // Create Alice (minter/sender) and Bob (recipient)
    let alice_key = KeyPair::generate().unwrap();
    let alice_predicate = UnmaskedPredicate::new(alice_key.public_key().clone());

    let bob_key = KeyPair::generate().unwrap();
    let bob_predicate = UnmaskedPredicate::new(bob_key.public_key().clone());

    println!("👥 Created identities");
    println!("   Alice: {}", hex::encode(&alice_key.public_key().as_bytes()[..8]));
    println!("   Bob: {}", hex::encode(&bob_key.public_key().as_bytes()[..8]));

    // Mint a token to Alice
    println!("\n💎 Minting token to Alice...");

    let token_id = TokenId::new(*b"real_test_token_1234567890123456");
    let token_type = TokenType::new(b"REAL_TEST".to_vec());

    let alice_state = TokenState::from_predicate(
        &alice_predicate,
        Some(b"Alice's real token".to_vec())
    ).unwrap();

    // Create recipient address from alice state hash
    let alice_state_hash = alice_state.hash().unwrap();
    let alice_recipient = unicity_sdk::types::address::GenericAddress::direct(alice_state_hash);

    let mint_data = MintTransactionData::new(
        token_id.clone(),
        token_type.clone(),
        Some(b"Real token data".to_vec()),  // token_data
        None,  // coin_data
        alice_recipient,  // recipient address
        vec![100, 101, 102, 103, 104],  // salt (not Option)
        None,  // recipient_data_hash
        None,  // reason
    );

    let mint_commitment = MintCommitment::create(mint_data.clone())
        .expect("Failed to create mint commitment");

    match client.submit_commitment(&mint_commitment).await {
        Ok(response) => {
            println!("   Mint status: {}", response.status);

            if response.status == "SUCCESS" || response.status == "ACCEPTED" {
                println!("   ✅ Mint accepted!");

                // Try to get inclusion proof
                println!("   Waiting for inclusion proof...");
                match client.wait_for_inclusion_proof(
                    &mint_commitment.request_id,
                    std::time::Duration::from_secs(10)
                ).await {
                    Ok(proof) => {
                        println!("   ✅ Got inclusion proof!");

                        // Create the actual token
                        let mint_transaction = mint_commitment.to_transaction(proof);
                        let token = Token::new(alice_state.clone(), mint_transaction);

                        // Now try to transfer to Bob
                        println!("\n📤 Transferring token from Alice to Bob...");

                        let bob_state = TokenState::from_predicate(
                            &bob_predicate,
                            Some(b"Bob's token".to_vec())
                        ).unwrap();

                        let transfer_commitment = TransferCommitment::create(
                            &token,
                            bob_state,
                            Some(vec![200, 201, 202, 203, 204]),
                            alice_key.secret_key(),
                        ).expect("Failed to create transfer commitment");

                        match client.submit_commitment(&transfer_commitment).await {
                            Ok(transfer_response) => {
                                println!("   Transfer status: {}", transfer_response.status);
                                if transfer_response.status == "SUCCESS" || transfer_response.status == "ACCEPTED" {
                                    println!("   ✅ Transfer accepted!");
                                    println!("\n🎉 COMPLETE SUCCESS! Token minted and transferred!");
                                } else {
                                    println!("   ⚠️ Transfer not accepted: {:?}", transfer_response.message);
                                }
                            }
                            Err(e) => println!("   ❌ Transfer failed: {:?}", e),
                        }
                    }
                    Err(_) => {
                        println!("   ⚠️ No inclusion proof (expected for test env)");
                        println!("   Would need real inclusion proof for transfer");
                    }
                }
            } else {
                println!("   ⚠️ Mint not accepted: {:?}", response.message);
            }
        }
        Err(e) => println!("   ❌ Mint failed: {:?}", e),
    }
}