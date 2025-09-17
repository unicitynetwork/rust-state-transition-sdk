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

    let mint_data = MintTransactionData::new(
        token_id,
        token_type,
        state,
        Some(b"metadata".to_vec()),
        Some(vec![1, 2, 3, 4, 5]),
        None,
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
                println!("   Block height: {}", proof.block_height);
            }
            Ok(None) => {
                println!("⏳ No inclusion proof yet (returned None)");

                // Wait a bit and try again
                println!("\nWaiting 3 seconds and trying again...");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;

                match client.get_inclusion_proof(&commitment.request_id).await {
                    Ok(Some(proof)) => {
                        println!("✅ Got inclusion proof after waiting!");
                        println!("   Block height: {}", proof.block_height);
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