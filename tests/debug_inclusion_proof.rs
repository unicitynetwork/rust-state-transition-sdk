use unicity_sdk::client::aggregator::AggregatorClient;
use unicity_sdk::types::commitment::MintCommitment;
use unicity_sdk::types::predicate::UnmaskedPredicate;
use unicity_sdk::types::token::{TokenState, TokenType, TokenId};
use unicity_sdk::types::transaction::MintTransactionData;
use unicity_sdk::crypto::KeyPair;

#[tokio::test]
#[ignore]
async fn test_debug_inclusion_proof() {
    let aggregator_url = "https://goggregator-test.unicity.network";
    let client = AggregatorClient::new(aggregator_url.to_string()).unwrap();

    println!("Creating and submitting a mint commitment...");

    // Create simple mint
    let token_id = TokenId::unique();
    let token_type = TokenType::new(b"DEBUG_TEST".to_vec());

    let key = KeyPair::generate().unwrap();
    let predicate = UnmaskedPredicate::new(key.public_key().clone());
    let state = TokenState::from_predicate(&predicate, Some(b"debug".to_vec())).unwrap();

    // Create recipient address from state hash
    let state_hash = state.hash().unwrap();
    let recipient = unicity_sdk::types::address::GenericAddress::direct(state_hash);

    let mint_data = MintTransactionData::new(
        token_id,
        token_type,
        Some(b"metadata".to_vec()),  // token_data
        None,  // coin_data (not Vec<u8>!)
        recipient,  // recipient address
        vec![1, 2, 3, 4, 5],  // salt (not Option)
        None,  // recipient_data_hash
        None,  // reason
    );

    let commitment = MintCommitment::create(mint_data).unwrap();

    println!("Request ID: {}", hex::encode(commitment.request_id.as_data_hash().imprint()));

    // Submit
    let response = client.submit_commitment(&commitment).await.unwrap();
    println!("Submit response: {}", response.status);

    if response.status == "SUCCESS" || response.status == "ACCEPTED" {
        println!("\nNow trying to get inclusion proof immediately...");

        // Try to get inclusion proof immediately
        match client.get_inclusion_proof(&commitment.request_id).await {
            Ok(Some(proof)) => {
                println!("✅ Got inclusion proof immediately!");
                println!("   Merkle root: {}", proof.merkle_tree_path.root);
            }
            Ok(None) => {
                println!("⏳ No inclusion proof yet (returned None)");

                // Wait a bit and try again
                println!("\nWaiting 3 seconds and trying again...");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;

                match client.get_inclusion_proof(&commitment.request_id).await {
                    Ok(Some(proof)) => {
                        println!("✅ Got inclusion proof after waiting!");
                        println!("   Merkle root: {}", proof.merkle_tree_path.root);
                    }
                    Ok(None) => {
                        println!("❌ Still no inclusion proof after 3 seconds");
                        println!("   This suggests the commitment is not being included");
                    }
                    Err(e) => {
                        println!("❌ Error getting proof: {:?}", e);
                    }
                }
            }
            Err(e) => {
                println!("❌ Error getting inclusion proof: {:?}", e);
            }
        }
    }
}