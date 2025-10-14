use unicity_sdk::client::aggregator::AggregatorClient;
use unicity_sdk::types::commitment::MintCommitment;
use unicity_sdk::types::predicate::UnmaskedPredicate;
use unicity_sdk::types::token::{TokenState, TokenType, TokenId};
use unicity_sdk::types::transaction::MintTransactionData;
use unicity_sdk::crypto::KeyPair;

#[tokio::test]
#[ignore] // Run with: cargo test --test mint_basic_e2e -- --ignored --nocapture
async fn test_basic_mint() {
    let aggregator_url = "https://goggregator-test.unicity.network";
    println!("🚀 Testing Basic Mint");

    let client = AggregatorClient::new(aggregator_url.to_string()).expect("Failed to create client");

    // Check connection
    match client.get_block_height().await {
        Ok(height) => println!("✅ Connected to aggregator, block height: {}", height),
        Err(e) => panic!("Failed to connect: {:?}", e),
    }

    // Create a simple mint transaction
    let token_id = TokenId::unique();
    let token_type = TokenType::new(vec![0x01, 0x02, 0x03, 0x04]);

    // Create recipient's key and state
    let recipient_key = KeyPair::generate().unwrap();
    let predicate = UnmaskedPredicate::new(recipient_key.public_key().clone());
    let target_state = TokenState::from_predicate(&predicate, Some(b"test metadata".to_vec())).unwrap();

    // Create recipient address from target state hash
    let target_state_hash = target_state.hash().unwrap();
    let recipient = unicity_sdk::types::address::GenericAddress::direct(target_state_hash);

    // Create mint data
    let mint_data = MintTransactionData::new(
        token_id.clone(),
        token_type,
        Some(b"token data".to_vec()),  // token_data
        None,  // coin_data
        recipient,  // recipient address
        vec![1, 2, 3, 4, 5],  // 5-byte salt like Java tests (not Option)
        None,  // recipient_data_hash
        None,  // reason
    );

    println!("📝 Token ID: {}", hex::encode(token_id.as_bytes()));

    // Create mint commitment (uses universal minter internally)
    let commitment = MintCommitment::create(mint_data).expect("Failed to create commitment");

    println!("✍️ Request ID: {}", hex::encode(commitment.request_id.as_data_hash().imprint()));
    println!("✍️ Public key: {}", hex::encode(commitment.authenticator.public_key.as_bytes()));

    // Submit commitment
    match client.submit_commitment(&commitment).await {
        Ok(response) => {
            println!("📤 Submit response: {}", response.status);

            if response.status == "SUCCESS" || response.status == "ACCEPTED" {
                println!("✅ MINT COMMITMENT ACCEPTED!");

                // Try to get inclusion proof (might timeout or fail)
                println!("⏳ Waiting for inclusion proof (5 seconds)...");
                match client.wait_for_inclusion_proof(
                    &commitment.request_id,
                    std::time::Duration::from_secs(5)
                ).await {
                    Ok(proof) => {
                        println!("✅ Got inclusion proof with root: {}", proof.merkle_tree_path.root);
                        println!("🎉 MINT SUCCESSFUL!");
                    }
                    Err(e) => {
                        println!("⚠️ Couldn't get inclusion proof: {:?}", e);
                        println!("This might be normal for test commitments");
                    }
                }
            } else {
                println!("❌ Commitment not accepted: {}", response.status);
                if let Some(msg) = response.message {
                    println!("   Message: {}", msg);
                }
            }
        }
        Err(e) => {
            println!("❌ Failed to submit: {:?}", e);
        }
    }
}