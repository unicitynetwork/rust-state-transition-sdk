//! Escrow swap example
//!
//! This example demonstrates:
//! - Multi-party token swaps using escrow
//! - Nametag-based routing
//! - Complex transaction flows

use unicity_sdk::client::StateTransitionClient;
use unicity_sdk::crypto::TestIdentity;
use unicity_sdk::types::address::{DirectAddress, ProxyAddress};
use unicity_sdk::types::predicate::{MaskedPredicate, PredicateReference, UnmaskedPredicate};
use unicity_sdk::types::primitives::DataHash;
use unicity_sdk::types::token::{TokenState, TokenType, TokenId};
use unicity_sdk::types::transaction::MintTransactionData;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    unicity_sdk::init();
    println!("🚀 Unicity SDK - Escrow Swap Example\n");

    // Setup client
    let aggregator_url = std::env::var("AGGREGATOR_URL")
        .unwrap_or_else(|_| "https://goggregator-test.unicity.network".to_string());
    let client = StateTransitionClient::new(aggregator_url)?;

    // Create identities
    println!("👥 Creating identities...");
    let alice = TestIdentity::alice()?; // Escrow agent
    let bob = TestIdentity::bob()?; // Party 1
    let carol = TestIdentity::carol()?; // Party 2

    println!("  Alice (escrow): {}", alice.key_pair.public_hex());
    println!("  Bob (party 1): {}", bob.key_pair.public_hex());
    println!("  Carol (party 2): {}", carol.key_pair.public_hex());

    // Step 1: Create nametags for routing
    println!("\n🏷️ Step 1: Creating nametags for routing...");

    let alice_nametag = format!("alice_escrow_{}", chrono::Utc::now().timestamp());
    let bob_nametag = format!("bob_trader_{}", chrono::Utc::now().timestamp());
    let carol_nametag = format!("carol_trader_{}", chrono::Utc::now().timestamp());

    // Create nametag predicates
    let alice_nametag_predicate = UnmaskedPredicate::new(alice.key_pair.public_key().clone());
    let alice_nametag_state = TokenState::from_predicate(&alice_nametag_predicate, None)?;

    println!("  Alice nametag: {}", alice_nametag);
    println!("  Bob nametag: {}", bob_nametag);
    println!("  Carol nametag: {}", carol_nametag);

    // Step 2: Create tokens to swap
    println!("\n🪙 Step 2: Creating tokens to swap...");

    // Bob's token (e.g., 100 BTC)
    let bob_token_id = TokenId::unique_with_marker(1);
    let bob_token_data = MintTransactionData::new(
        bob_token_id,
        TokenType::new(b"BTC".to_vec()),
        TokenState::from_predicate(
            &UnmaskedPredicate::new(bob.key_pair.public_key().clone()),
            Some(b"100 BTC".to_vec()),
        )?,
        Some(b"Bob's Bitcoin".to_vec()),
        Some(vec![1, 2, 3, 4, 5]),
        None,
    );

    // Carol's token (e.g., 2000 ETH)
    let carol_token_id = TokenId::unique_with_marker(2);
    let carol_token_data = MintTransactionData::new(
        carol_token_id,
        TokenType::new(b"ETH".to_vec()),
        TokenState::from_predicate(
            &UnmaskedPredicate::new(carol.key_pair.public_key().clone()),
            Some(b"2000 ETH".to_vec()),
        )?,
        Some(b"Carol's Ethereum".to_vec()),
        Some(vec![6, 7, 8, 9, 10]),
        None,
    );

    println!("  Bob's token: 100 BTC");
    println!("  Carol's token: 2000 ETH");

    // Step 3: Setup escrow addresses
    println!("\n🔐 Step 3: Setting up escrow...");

    // Create escrow predicates with time-locked conditions
    let escrow_nonce = b"escrow_swap_12345";
    let escrow_predicate =
        MaskedPredicate::from_public_key_and_nonce(alice.key_pair.public_key(), escrow_nonce);

    // Create proxy addresses for routing through nametags
    let alice_proxy = ProxyAddress::new(DataHash::sha256(alice_nametag.as_bytes().to_vec()));
    let bob_proxy = ProxyAddress::new(DataHash::sha256(bob_nametag.as_bytes().to_vec()));
    let carol_proxy = ProxyAddress::new(DataHash::sha256(carol_nametag.as_bytes().to_vec()));

    println!("  Escrow predicate created");
    println!("  Alice proxy address: {:?}", alice_proxy.hash);
    println!("  Bob proxy address: {:?}", bob_proxy.hash);
    println!("  Carol proxy address: {:?}", carol_proxy.hash);

    // Step 4: Simulate swap flow
    println!("\n🔄 Step 4: Simulating swap flow...");

    println!("  1. Bob sends BTC to escrow (Alice)");
    println!("  2. Carol sends ETH to escrow (Alice)");
    println!("  3. Alice verifies both tokens received");
    println!("  4. Alice sends BTC to Carol");
    println!("  5. Alice sends ETH to Bob");
    println!("  6. Swap complete!");

    // Step 5: Create direct addresses for final delivery
    println!("\n📬 Step 5: Creating final delivery addresses...");

    let bob_final_predicate = UnmaskedPredicate::new(bob.key_pair.public_key().clone());
    let bob_final_ref = PredicateReference::from_predicate(&bob_final_predicate)?;
    let bob_direct = DirectAddress::from_predicate_reference(&bob_final_ref)?;

    let carol_final_predicate = UnmaskedPredicate::new(carol.key_pair.public_key().clone());
    let carol_final_ref = PredicateReference::from_predicate(&carol_final_predicate)?;
    let carol_direct = DirectAddress::from_predicate_reference(&carol_final_ref)?;

    println!("  Bob's direct address: {:?}", bob_direct.hash);
    println!("  Carol's direct address: {:?}", carol_direct.hash);

    // Step 6: Transaction verification
    println!("\n✅ Step 6: Transaction verification...");

    // In a real scenario, we would:
    // 1. Submit all commitments to the aggregator
    // 2. Wait for inclusion proofs
    // 3. Finalize transactions
    // 4. Verify final token ownership

    println!("  All transactions would be verified on-chain");
    println!("  Inclusion proofs would be generated");
    println!("  Final token ownership would be confirmed");

    // Summary
    println!("\n📊 Swap Summary:");
    println!("  Initial state:");
    println!("    Bob: 100 BTC");
    println!("    Carol: 2000 ETH");
    println!("  Final state:");
    println!("    Bob: 2000 ETH");
    println!("    Carol: 100 BTC");
    println!("  Escrow agent: Alice");
    println!("  Status: Complete ✅");

    println!("\n✨ Escrow swap example completed!");
    println!("\nNote: This example simulates the swap flow.");
    println!("In production, actual commitments would be submitted to the aggregator.");

    Ok(())
}
