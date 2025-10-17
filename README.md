# Unicity SDK for Rust

[![CI](https://github.com/unicitynetwork/rust-state-transition-sdk/workflows/CI/badge.svg)](https://github.com/unicitynetwork/rust-state-transition-sdk/actions/workflows/ci.yml)

A Rust implementation of the Unicity Protocol for creating and managing off-chain token state transitions with on-chain commitments.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
unicity-sdk = "0.1.0"
tokio = { version = "1.45", features = ["full"] }
```

## Quick Start

### Basic Token Minting

```rust
use unicity_sdk::client::StateTransitionClient;
use unicity_sdk::crypto::KeyPair;
use unicity_sdk::types::token::{TokenType, TokenState, TokenId};
use unicity_sdk::types::transaction::MintTransactionData;
use unicity_sdk::types::predicate::UnmaskedPredicate;
use unicity_sdk::types::GenericAddress;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the SDK
    unicity_sdk::init();

    // Create client connected to test network
    let client = StateTransitionClient::new(
        "https://goggregator-test.unicity.network".to_string()
    )?;

    // Generate a new key pair
    let key_pair = KeyPair::generate()?;

    // Create token state with unmasked predicate
    let predicate = UnmaskedPredicate::new(key_pair.public_key().clone());
    let state = TokenState::from_predicate(&predicate, None)?;

    // Create recipient address from state (predicate hash only, not including data)
    let address_hash = state.address_hash()?;
    let recipient = GenericAddress::direct(address_hash);

    // Create mint data with unique token ID
    let token_id = TokenId::unique();
    let mint_data = MintTransactionData::new(
        token_id,
        TokenType::new(b"MY_TOKEN".to_vec()),
        Some(b"Initial token data".to_vec()), // token_data
        None,                                   // coin_data
        recipient,                              // recipient address
        vec![1, 2, 3, 4, 5],                   // salt
        None,                                   // recipient_data_hash
        None,                                   // split reason
    );

    // Mint the token (uses universal minter)
    let token = client.mint_token(mint_data, state).await?;
    println!("Minted token with ID: {:?}", token.id()?);

    Ok(())
}
```

### Token Transfer

```rust
use unicity_sdk::client::StateTransitionClient;
use unicity_sdk::crypto::TestIdentity;
use unicity_sdk::types::token::TokenState;
use unicity_sdk::types::predicate::UnmaskedPredicate;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    unicity_sdk::init();

    let client = StateTransitionClient::new(
        "https://goggregator-test.unicity.network".to_string()
    )?;

    // Create identities
    let alice = TestIdentity::alice()?;
    let bob = TestIdentity::bob()?;

    // Assume alice has a token (minted previously)
    // let alice_token = ...;

    // Create Bob's receiving state
    let bob_predicate = UnmaskedPredicate::new(bob.key_pair.public_key().clone());
    let bob_state = TokenState::from_predicate(&bob_predicate, None)?;

    // Transfer token from Alice to Bob
    let transferred_token = client.transfer_token(
        &alice_token,
        bob_state,
        Some(b"transfer_salt".to_vec()),
        alice.key_pair.secret_key(),
    ).await?;

    println!("Token transferred to Bob!");

    Ok(())
}
```

### Using Test Identities

```rust
use unicity_sdk::crypto::TestIdentity;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Deterministic test identities
    let alice = TestIdentity::alice()?;
    let bob = TestIdentity::bob()?;
    let carol = TestIdentity::carol()?;

    println!("Alice public key: {}", alice.key_pair.public_hex());
    println!("Bob public key: {}", bob.key_pair.public_hex());
    println!("Carol public key: {}", carol.key_pair.public_hex());

    Ok(())
}
```

### Working with Predicates

```rust
use unicity_sdk::types::predicate::{UnmaskedPredicate, MaskedPredicate, BurnPredicate};
use unicity_sdk::types::token::TokenState;
use unicity_sdk::crypto::KeyPair;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_pair = KeyPair::generate()?;

    // Unmasked predicate (public key visible)
    let unmasked = UnmaskedPredicate::new(key_pair.public_key().clone());
    let state1 = TokenState::from_predicate(&unmasked, None)?;

    // Masked predicate (public key hidden with nonce for privacy)
    let nonce = b"secret_nonce_12345";
    let masked = MaskedPredicate::from_public_key_and_nonce(
        key_pair.public_key(),
        nonce
    );
    let state2 = TokenState::from_predicate(&masked, None)?;

    // Burn predicate (allows unconditional spending, used for token splitting)
    let burn = BurnPredicate::new();
    let state3 = TokenState::from_predicate(&burn, None)?;

    Ok(())
}
```

### Privacy-Preserving Transfers with MaskedPredicate

MaskedPredicate enables privacy-preserving token transfers where the recipient's public key remains hidden until they spend the token. This follows a two-step protocol:

```rust
use unicity_sdk::client::StateTransitionClient;
use unicity_sdk::crypto::{TestIdentity, KeyPair};
use unicity_sdk::types::token::{TokenState, TokenType, TokenId};
use unicity_sdk::types::transaction::{MintTransactionData, TransferTransactionData};
use unicity_sdk::types::predicate::{UnmaskedPredicate, MaskedPredicate};
use unicity_sdk::types::GenericAddress;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    unicity_sdk::init();

    let client = StateTransitionClient::new(
        "https://goggregator-test.unicity.network".to_string()
    )?;

    let alice = TestIdentity::alice()?;
    let bob = TestIdentity::bob()?;

    // STEP 1: Bob generates nonce and shares (nonce, public_key) with Alice off-chain
    let nonce = b"bobs_secret_nonce_123";

    // STEP 2: Alice creates token with MaskedPredicate for Bob
    let masked_predicate = MaskedPredicate::from_public_key_and_nonce(
        bob.key_pair.public_key(),
        nonce
    );
    let masked_state = TokenState::from_predicate(&masked_predicate, None)?;
    let address_hash = masked_state.address_hash()?;
    let recipient = GenericAddress::direct(address_hash);

    // Alice mints token to Bob's masked address (Bob's public key is hidden)
    let token_id = TokenId::unique();
    let mint_data = MintTransactionData::new(
        token_id,
        TokenType::new(b"PRIVATE_TOKEN".to_vec()),
        None,
        None,
        recipient,
        vec![1, 2, 3],
        None,
        None,
    );
    let masked_token = client.mint_token(mint_data, masked_state.clone()).await?;

    // STEP 3: Bob spends the token by revealing the nonce
    // Bob creates transfer with nonce_revelation
    let carol_predicate = UnmaskedPredicate::new(KeyPair::generate()?.public_key().clone());
    let carol_state = TokenState::from_predicate(&carol_predicate, None)?;
    let carol_address = GenericAddress::direct(carol_state.address_hash()?);

    // When Bob creates the transfer, the nonce must be included for verification
    let transfer_data = TransferTransactionData::with_nonce_revelation(
        masked_state.clone(),
        carol_address,
        vec![4, 5, 6],
        None,
        None,
        vec![],
        nonce.to_vec(), // Nonce revelation proves Bob can spend
    );

    println!("Privacy-preserving transfer completed!");
    println!("- Alice sent to masked address (Bob's identity hidden)");
    println!("- Bob spent by revealing nonce (proves ownership)");

    Ok(())
}
```


### Sparse Merkle Tree Operations

```rust
use unicity_sdk::smt::SparseMerkleTree;
use unicity_sdk::crypto::sha256;
use num_bigint::BigInt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = SparseMerkleTree::new();

    // Add leaves
    tree.add_leaf(BigInt::from(1), sha256(b"leaf1"))?;
    tree.add_leaf(BigInt::from(2), sha256(b"leaf2"))?;
    tree.add_leaf(BigInt::from(5), sha256(b"leaf5"))?;

    // Build the tree
    tree.build()?;

    // Get root hash
    let root = tree.root_hash()?;
    println!("Tree root: {}", root);

    // Generate inclusion proof
    let index = BigInt::from(2);
    let proof = tree.get_proof(&index)?;
    println!("Generated proof with {} elements", proof.len());

    Ok(())
}
```

## Configuration

### Using Different Networks

```rust
use unicity_sdk::Config;
use unicity_sdk::client::StateTransitionClient;

// Test network (default)
let config = Config::test_network();
let client = StateTransitionClient::new(config.aggregator_url)?;

// Local development
let config = Config::local();
let client = StateTransitionClient::new(config.aggregator_url)?;

// Custom aggregator
let config = Config::new("https://my-aggregator.example.com".to_string());
let client = StateTransitionClient::new(config.aggregator_url)?;
```

## Running Tests

### Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs))
- Access to Unicity test network (or local aggregator)

### Run All Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_health_check
```

### Unit Tests

```bash
# Run unit tests only
cargo test --lib

# Run tests for specific module
cargo test --lib crypto::
cargo test --lib types::
cargo test --lib smt::
```

### Integration Tests

Integration tests connect to the deployed test aggregator:

```bash
# Run integration tests
cargo test --test e2e_test

# Run specific integration test
cargo test --test e2e_test test_basic_token_mint

# Run with custom aggregator URL
AGGREGATOR_URL=http://localhost:3000 cargo test --test e2e_test
```

### Performance Tests

```bash
# Run performance tests (marked with #[ignore])
cargo test --test e2e_test test_performance -- --ignored --nocapture
```

### Test Categories

| Test | Description | Command |
|------|-------------|---------|
| `test_health_check` | Verify aggregator connectivity | `cargo test test_health_check` |
| `test_basic_token_mint` | Test token minting | `cargo test test_basic_token_mint` |
| `test_token_transfer_flow` | Test token transfers | `cargo test test_token_transfer_flow` |
| `test_concurrent_commitments` | Test concurrent operations | `cargo test test_concurrent_commitments` |
| `test_nametag_creation` | Test nametag tokens | `cargo test test_nametag_creation` |
| `test_performance` | Performance benchmarks | `cargo test test_performance -- --ignored` |

## API Documentation

Generate and view the API documentation:

```bash
# Generate docs
cargo doc --no-deps --open

# Generate docs with private items
cargo doc --no-deps --document-private-items --open
```

## Examples

Run the examples:

```bash
# Basic transfer example
cargo run --example basic_transfer

# Token splitting example
cargo run --example token_split

# Escrow swap example
cargo run --example escrow_swap
```


## Key Types

### Core Types
- `Token<T>` - Generic token with state and transaction history
- `TokenId` - 32-byte token identifier
- `TokenState` - Token state with unlock predicate
- `TokenType` - Token category identifier

### Transactions
- `Transaction<T>` - Transaction with inclusion proof
- `MintTransactionData` - Token creation data
- `TransferTransactionData` - Token transfer data with optional nonce revelation
- `InclusionProof` - Merkle tree inclusion proof with unicity certificate

### Commitments
- `MintCommitment` - Commitment for token minting
- `TransferCommitment` - Commitment for token transfer
- `Authenticator` - Signature with public key recovery

### Predicates
- `UnmaskedPredicate` - Direct public key ownership (public)
- `MaskedPredicate` - Nonce-masked ownership (private until spend)
- `BurnPredicate` - Burn condition for token splitting
- `Predicate::verify()` - Full predicate verification with nonce support

### Cryptography
- `KeyPair` - Secret/public key pair
- `SigningService` - Signature creation and verification
- `DataHash` - Algorithm-tagged hash

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AGGREGATOR_URL` | Aggregator endpoint | `https://goggregator-test.unicity.network` |
| `RUST_LOG` | Logging level | `info` |

## Troubleshooting

### Connection Issues

If you get connection errors:

1. Check network connectivity: `curl https://goggregator-test.unicity.network/health`
2. Verify the aggregator URL is correct
3. Check firewall settings
4. Try using a different network

### Compilation Errors

If you encounter compilation errors:

1. Update Rust: `rustup update`
2. Clean build: `cargo clean && cargo build`
3. Update dependencies: `cargo update`

### Test Failures

Integration test failures are often due to:

1. Network issues - Check connectivity to test aggregator
2. Rate limiting - Add delays between requests
3. Invalid test data - Ensure proper key generation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT OR Apache-2.0

## Support

For issues and questions:
- GitHub Issues: [github.com/unicitynetwork/rust-state-transition-sdk](https://github.com/unicitynetwork/rust-state-transition-sdk)


## Acknowledgments

This SDK is a Rust port of the [Java State Transition SDK](https://github.com/unicitynetwork/java-state-transition-sdk) and maintains full compatibility with the Unicity Protocol.
