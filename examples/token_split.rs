//! Token splitting example
//!
//! This example demonstrates:
//! - Creating fungible tokens with coin data
//! - Building Sparse Merkle Sum Trees
//! - Splitting tokens into multiple tokens

use num_bigint::BigInt;
use unicity_sdk::crypto::{sha256, TestIdentity};
use unicity_sdk::smt::SparseMerkleSumTree;
use unicity_sdk::types::token::TokenCoinData;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Unicity SDK - Token Split Example\n");

    // Create test identity
    let alice = TestIdentity::alice()?;
    println!("👤 Alice's public key: {}", alice.key_pair.public_hex());

    // Create token with multiple coin types
    println!("\n🪙 Creating token with multiple coin types...");
    let mut coin_data = TokenCoinData::new();
    coin_data.add_coin("BTC".to_string(), 1000);
    coin_data.add_coin("ETH".to_string(), 500);
    coin_data.add_coin("USDT".to_string(), 2500);

    println!("  Initial coins:");
    println!("    BTC: {}", coin_data.get_amount("BTC").unwrap_or(0));
    println!("    ETH: {}", coin_data.get_amount("ETH").unwrap_or(0));
    println!("    USDT: {}", coin_data.get_amount("USDT").unwrap_or(0));

    // Build Sparse Merkle Sum Tree for BTC
    println!("\n🌳 Building Sparse Merkle Sum Tree for BTC...");
    let mut btc_tree = SparseMerkleSumTree::new();

    // Add allocations for split (example: splitting BTC into 3 parts)
    btc_tree.add_leaf(
        BigInt::from(1),
        sha256(b"alice_btc_1"),
        BigInt::from(400),  // 400 BTC
    )?;
    btc_tree.add_leaf(
        BigInt::from(2),
        sha256(b"alice_btc_2"),
        BigInt::from(350),  // 350 BTC
    )?;
    btc_tree.add_leaf(
        BigInt::from(3),
        sha256(b"alice_btc_3"),
        BigInt::from(250),  // 250 BTC
    )?;

    btc_tree.build()?;
    let btc_root = btc_tree.root_hash()?;
    let btc_total = btc_tree.total_sum();

    println!("  BTC tree root: {}", btc_root);
    println!("  BTC total sum: {}", btc_total);
    println!("  Allocations: 400 + 350 + 250 = 1000 BTC ✅");

    // Build Sparse Merkle Sum Tree for ETH
    println!("\n🌳 Building Sparse Merkle Sum Tree for ETH...");
    let mut eth_tree = SparseMerkleSumTree::new();

    // Split ETH into 2 parts
    eth_tree.add_leaf(
        BigInt::from(1),
        sha256(b"alice_eth_1"),
        BigInt::from(300),  // 300 ETH
    )?;
    eth_tree.add_leaf(
        BigInt::from(2),
        sha256(b"alice_eth_2"),
        BigInt::from(200),  // 200 ETH
    )?;

    eth_tree.build()?;
    let eth_root = eth_tree.root_hash()?;
    let eth_total = eth_tree.total_sum();

    println!("  ETH tree root: {}", eth_root);
    println!("  ETH total sum: {}", eth_total);
    println!("  Allocations: 300 + 200 = 500 ETH ✅");

    // Build aggregation tree (maps coin types to their sum tree roots)
    println!("\n🌲 Building aggregation tree...");
    let mut aggregation_tree = SparseMerkleSumTree::new();

    // Add coin type mappings
    aggregation_tree.add_leaf(
        BigInt::from(1),
        sha256(b"BTC"),
        BigInt::from(1000),
    )?;
    aggregation_tree.add_leaf(
        BigInt::from(2),
        sha256(b"ETH"),
        BigInt::from(500),
    )?;
    aggregation_tree.add_leaf(
        BigInt::from(3),
        sha256(b"USDT"),
        BigInt::from(2500),  // Not split, kept whole
    )?;

    aggregation_tree.build()?;
    let aggregation_root = aggregation_tree.root_hash()?;
    let total_value = aggregation_tree.total_sum();

    println!("  Aggregation root: {}", aggregation_root);
    println!("  Total value across all coins: {}", total_value);

    // Generate inclusion proofs
    println!("\n🔍 Generating inclusion proofs...");

    // Proof for BTC allocation #2
    let btc_proof = btc_tree.get_proof(&BigInt::from(2))?;
    println!("  BTC allocation #2 proof: {} elements", btc_proof.len());

    // Proof for ETH in aggregation tree
    let eth_proof = aggregation_tree.get_proof(&BigInt::from(2))?;
    println!("  ETH aggregation proof: {} elements", eth_proof.len());

    // Verify proofs
    println!("\n✅ Verifying proofs...");

    let btc_leaf_hash = sha256(b"alice_btc_2");
    let btc_leaf_value = BigInt::from(350);
    let btc_valid = SparseMerkleSumTree::verify_proof(
        &btc_leaf_hash,
        &btc_leaf_value,
        &BigInt::from(2),
        &btc_proof,
        &btc_root,
        &btc_total,
    );

    println!("  BTC proof valid: {}", btc_valid);

    let eth_aggregation_hash = sha256(b"ETH");
    let eth_aggregation_value = BigInt::from(500);
    let eth_valid = SparseMerkleSumTree::verify_proof(
        &eth_aggregation_hash,
        &eth_aggregation_value,
        &BigInt::from(2),
        &eth_proof,
        &aggregation_root,
        &total_value,
    );

    println!("  ETH aggregation proof valid: {}", eth_valid);

    // Summary
    println!("\n📊 Split Summary:");
    println!("  Original token: 1000 BTC + 500 ETH + 2500 USDT");
    println!("  Split result:");
    println!("    - Token 1: 400 BTC + 300 ETH");
    println!("    - Token 2: 350 BTC + 200 ETH");
    println!("    - Token 3: 250 BTC");
    println!("    - Token 4: 2500 USDT (unsplit)");

    println!("\n✨ Token split example completed!");
    Ok(())
}