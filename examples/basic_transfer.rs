//! Basic token transfer example
//!
//! This example demonstrates:
//! - Creating test identities
//! - Minting a token
//! - Transferring the token between users
//! - Saving tokens to files

use unicity_sdk::client::StateTransitionClient;
use unicity_sdk::crypto::TestIdentity;
use unicity_sdk::types::predicate::{MaskedPredicate, UnmaskedPredicate};
use unicity_sdk::types::token::{TokenState, TokenType, TokenId};
use unicity_sdk::types::transaction::MintTransactionData;
use std::fs;

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

    // Use unmasked predicate for Alice's initial ownership
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let alice_predicate = UnmaskedPredicate::new(alice.key_pair.public_key().clone());
    let alice_state = TokenState::from_predicate(&alice_predicate, Some(b"Alice's token".to_vec()))?;

    let token_id = TokenId::unique();

    // Create recipient address from alice's state (predicate hash only, not including data)
    let address_hash = alice_state.address_hash()?;
    let recipient = unicity_sdk::types::address::GenericAddress::direct(address_hash);

    // Compute recipient_data_hash from state data (required when state has data)
    let recipient_data_hash = alice_state.data_hash();

    let mint_data = MintTransactionData::new(
        token_id,
        TokenType::new(b"EXAMPLE_TOKEN".to_vec()),
        Some(b"Initial token data".to_vec()),  // token_data
        None,  // coin_data (None for non-fungible tokens)
        recipient,  // recipient address
        format!("salt_{}", timestamp).into_bytes(),  // salt (not Option<Vec<u8>>)
        recipient_data_hash,  // recipient_data_hash (SHA256 of alice_state.data)
        None,  // reason
    );

    match client
        .mint_token(mint_data, alice_state)
        .await
    {
        Ok(token) => {
            println!("  ✅ Token minted successfully!");
            println!("  Token ID: {}", token.id()?);

            // Save minted token to file
            let minted_json = serde_json::to_string_pretty(&token)?;
            fs::write("minted_token.json", minted_json)?;
            println!("  💾 Saved to minted_token.json");

            // Step 2: Transfer to Bob
            println!("\n📤 Step 2: Transferring token from Alice to Bob...");

            let transfer_timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis();

            let bob_predicate = UnmaskedPredicate::new(bob.key_pair.public_key().clone());
            let bob_data = format!("Bob's token {}", transfer_timestamp).into_bytes();
            let bob_state =
                TokenState::from_predicate(&bob_predicate, Some(bob_data))?;

            let transfer_salt = format!("transfer_salt_{}", transfer_timestamp).into_bytes();

            match client
                .transfer_token(
                    &token,
                    bob_state,
                    Some(transfer_salt),
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

                    // Save transferred token to file
                    let transferred_json = serde_json::to_string_pretty(&transferred_token)?;
                    fs::write("transferred_token.json", transferred_json)?;
                    println!("  💾 Saved to transferred_token.json");
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
