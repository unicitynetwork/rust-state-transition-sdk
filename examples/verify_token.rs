//! Token verification example
//!
//! Usage:
//!   cargo run --example generate_test_token -- --transactions 5 --output test-token.json
//!   cargo run --example verify_token < test-token.json
//!
//! With custom trust base:
//!   TRUST_BASE='{"version":1,...}' cargo run --example verify_token < token.json

use unicity_sdk::types::bft::RootTrustBase;
use unicity_sdk::types::token::Token;
use unicity_sdk::types::transaction::MintTransactionData;
use std::io::{self, Read};

const DEFAULT_TRUST_BASE: &str = include_str!("../tests/resources/trust-base.json");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    unicity_sdk::init();

    let mut stdin_input = String::new();
    io::stdin().read_to_string(&mut stdin_input)?;

    let token: Token<MintTransactionData> = serde_json::from_str(&stdin_input)
        .map_err(|e| format!("Failed to parse token JSON: {}", e))?;

    let trust_base_json = std::env::var("TRUST_BASE")
        .unwrap_or_else(|_| DEFAULT_TRUST_BASE.to_string());

    let trust_base = RootTrustBase::from_json(&trust_base_json)
        .map_err(|e| format!("Failed to parse trust base JSON: {}", e))?;

    match token.verify_with_trust_base(&trust_base) {
        Ok(_) => {
            let token_id = token.id()?;
            let token_type = token.genesis.data.token_type.as_bytes();
            let transaction_count = token.transactions.len();
            let state_hash = token.state.hash()?;

            println!("✅ TOKEN VERIFICATION PASSED\n");
            println!("Token Details:");
            println!("  Token ID: {}", token_id);
            println!("  Token Type: {}", String::from_utf8_lossy(token_type));
            println!("  Genesis + Transfers: {} total transactions", transaction_count + 1);
            println!("  Current State Hash: {}", hex::encode(state_hash.imprint()));
            Ok(())
        }
        Err(e) => {
            eprintln!("❌ TOKEN VERIFICATION FAILED\n");
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
