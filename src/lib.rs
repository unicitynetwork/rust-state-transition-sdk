//! # Unicity SDK for Rust
//!
//! This SDK provides a comprehensive implementation of the Unicity Protocol
//! for creating and managing off-chain token state transitions with on-chain commitments.
//!
//! ## Features
//!
//! - Token minting, transfer, and splitting operations
//! - Cryptographic predicates for ownership control
//! - Sparse Merkle Tree (SMT) implementation for inclusion proofs
//! - CBOR and JSON serialization
//! - Async aggregator client with JSON-RPC
//! - secp256k1 ECDSA signatures with recovery
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use unicity_sdk::client::StateTransitionClient;
//! use unicity_sdk::crypto::KeyPair;
//! use unicity_sdk::types::{TokenType, TokenState, MintTransactionData};
//! use unicity_sdk::types::predicate::UnmaskedPredicate;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create client
//!     let client = StateTransitionClient::new(
//!         "https://goggregator-test.unicity.network".to_string()
//!     )?;
//!
//!     // Generate key pair
//!     let key_pair = KeyPair::generate()?;
//!
//!     // Create token state
//!     let predicate = UnmaskedPredicate::new(key_pair.public_key().clone());
//!     let state = TokenState::from_predicate(&predicate, None)?;
//!
//!     // Create mint data
//!     let mint_data = MintTransactionData::new(
//!         TokenType::new(b"TEST".to_vec()),
//!         state,
//!         None,
//!         None,
//!     );
//!
//!     // Mint token
//!     let token = client.mint_token(mint_data, key_pair.secret_key()).await?;
//!
//!     Ok(())
//! }
//! ```

// Re-export all public modules
pub mod client;
pub mod crypto;
pub mod error;
pub mod minter;
pub mod smt;
pub mod types;

// Re-export commonly used items at crate root
pub use client::{AggregatorClient, StateTransitionClient};
pub use crypto::{KeyPair, SigningService};
pub use error::{Result, SdkError};
pub use types::{Token, TokenId, TokenState, TokenType};

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const VERSION_MAJOR: &str = env!("CARGO_PKG_VERSION_MAJOR");
pub const VERSION_MINOR: &str = env!("CARGO_PKG_VERSION_MINOR");
pub const VERSION_PATCH: &str = env!("CARGO_PKG_VERSION_PATCH");

/// Initialize the SDK (sets up logging if enabled)
pub fn init() {
    // Initialize tracing subscriber for logging
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .try_init();
}

/// SDK configuration
pub struct Config {
    pub aggregator_url: String,
    pub timeout_seconds: u64,
    pub retry_attempts: u32,
}

impl Config {
    /// Create a new configuration
    pub fn new(aggregator_url: String) -> Self {
        Self {
            aggregator_url,
            timeout_seconds: 30,
            retry_attempts: 3,
        }
    }

    /// Create configuration for test network
    pub fn test_network() -> Self {
        Self::new("https://goggregator-test.unicity.network".to_string())
    }

    /// Create configuration for local development
    pub fn local() -> Self {
        Self::new("http://localhost:3000".to_string())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::test_network()
    }
}
