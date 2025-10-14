//! Token verification example
//!
//! - Reading a token from stdin (JSON format)
//! - Loading trust base (from env var or hardcoded test network)
//! - Token validation with verify_with_trust_base()
//! - Output token details: ID, type, transaction count, state hash
//!
//! Usage:
//!   cat minted_token.json | cargo run --example verify_token
//!
//! With custom trust base:
//!   TRUST_BASE='{"version":1,...}' cat token.json | cargo run --example verify_token

use unicity_sdk::types::bft::RootTrustBase;
use unicity_sdk::types::token::Token;
use unicity_sdk::types::transaction::MintTransactionData;
use std::io::{self, Read};

// Default trust base for test network
const DEFAULT_TRUST_BASE: &str = r#"{
    "version": 1,
    "networkId": 3,
    "epoch": 1,
    "epochStartRound": 1,
    "rootNodes": [
        {
            "nodeId": "16Uiu2HAkyQRiA7pMgzgLj9GgaBJEJa8zmx9dzqUDa6WxQPJ82ghU",
            "sigKey": "0x039afb2acb65f5fbc272d8907f763d0a5d189aadc9b97afdcc5897ea4dd112e68b",
            "stake": 1
        }
    ],
    "quorumThreshold": 1,
    "stateHash": "",
    "changeRecordHash": "",
    "previousEntryHash": "",
    "signatures": {
        "16Uiu2HAkyQRiA7pMgzgLj9GgaBJEJa8zmx9dzqUDa6WxQPJ82ghU": "0xf157c9fdd8a378e3ca70d354ccc4475ab2cd8de360127bc46b0aeab4b453a80f07fd9136a5843b60a8babaff23e20acc8879861f7651440a5e2829f7541b31f100"
    }
}"#;

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
            // Verification successful - output token details
            let token_id = token.id()?;
            let token_type = token.genesis.data.token_type.as_bytes();
            let transaction_count = token.transactions.len();
            let state_hash = token.state.hash()?;

            println!("Token OK");
            println!("Token ID: {}", token_id);
            println!(
                "Token Type: {}",
                String::from_utf8_lossy(token_type)
            );
            println!("Transactions: {}", transaction_count);
            println!("State Hash: {}", hex::encode(state_hash.imprint()));

            Ok(())
        }
        Err(e) => {
            eprintln!("Failed token verification");
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
