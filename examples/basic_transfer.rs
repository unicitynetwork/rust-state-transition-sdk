//! Basic token transfer example
//!
//! This example demonstrates:
//! - Creating test identities
//! - Minting a token
//! - Transferring the token between users

use unicity_sdk::client::StateTransitionClient;
use unicity_sdk::crypto::TestIdentity;
use unicity_sdk::types::predicate::{MaskedPredicate, UnmaskedPredicate};
use unicity_sdk::types::token::{TokenState, TokenType};
use unicity_sdk::types::transaction::MintTransactionData;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize SDK with logging
    unicity_sdk::init();
    println!("🚀 Unicity SDK - Basic Transfer Example\n");

    // Create client
    let aggregator_url = std::env::var("AGGREGATOR_URL")
        .unwrap_or_else(|_| "https://goggregator-test.unicity.network".to_string());

    println!("📡 Connecting to aggregator: {}", aggregator_url);
    let client = StateTransitionClient::new(aggregator_url)?;

    // Create test identities
    println!("\n👥 Creating test identities...");
    let alice = TestIdentity::alice()?;
    let bob = TestIdentity::bob()?;

    println!("  Alice public key: {}", alice.key_pair.public_hex());
    println!("  Bob public key: {}", bob.key_pair.public_hex());

    // Step 1: Mint token for Alice
    println!("\n🪙 Step 1: Minting token for Alice...");

    // Use masked predicate for initial ownership
    let nonce = b"alice_nonce_12345";
    let alice_masked =
        MaskedPredicate::from_public_key_and_nonce(alice.key_pair.public_key(), nonce);
    let alice_state = TokenState::from_predicate(&alice_masked, Some(b"Alice's token".to_vec()))?;

    let mint_data = MintTransactionData::new(
        TokenType::new(b"EXAMPLE_TOKEN".to_vec()),
        alice_state.clone(),
        Some(b"Initial token data".to_vec()),
        None,
    );

    match client
        .mint_token(mint_data, alice.key_pair.secret_key())
        .await
    {
        Ok(token) => {
            println!("  ✅ Token minted successfully!");
            println!("  Token ID: {}", token.id()?);

            // Step 2: Transfer to Bob
            println!("\n📤 Step 2: Transferring token from Alice to Bob...");

            let bob_predicate = UnmaskedPredicate::new(bob.key_pair.public_key().clone());
            let bob_state =
                TokenState::from_predicate(&bob_predicate, Some(b"Bob's token".to_vec()))?;

            match client
                .transfer_token(
                    &token,
                    bob_state,
                    Some(b"transfer_salt_123".to_vec()),
                    alice.key_pair.secret_key(),
                )
                .await
            {
                Ok(transferred_token) => {
                    println!("  ✅ Token transferred successfully!");
                    println!("  New state owner: Bob");
                    println!(
                        "  Transaction count: {}",
                        transferred_token.transactions.len()
                    );
                }
                Err(e) => {
                    println!("  ❌ Transfer failed: {}", e);
                }
            }
        }
        Err(e) => {
            println!("  ❌ Minting failed: {}", e);
            println!("  Note: This is expected if not connected to a running aggregator.");
        }
    }

    // Step 3: Health check
    println!("\n🏥 Checking aggregator health...");
    match client.health_check().await {
        Ok(healthy) => {
            if healthy {
                println!("  ✅ Aggregator is healthy");

                match client.get_block_height().await {
                    Ok(height) => println!("  📊 Current block height: {}", height),
                    Err(e) => println!("  ⚠️ Could not get block height: {}", e),
                }
            } else {
                println!("  ⚠️ Aggregator is not responding");
            }
        }
        Err(e) => {
            println!("  ❌ Health check failed: {}", e);
        }
    }

    println!("\n✨ Example completed!");
    Ok(())
}
