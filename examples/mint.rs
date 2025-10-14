use unicity_sdk::client::StateTransitionClient;
use unicity_sdk::crypto::KeyPair;
use unicity_sdk::types::token::{TokenType, TokenState, TokenId};
use unicity_sdk::types::transaction::MintTransactionData;
use unicity_sdk::types::predicate::UnmaskedPredicate;

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

    // Generate a unique token ID
    let token_id = TokenId::unique();

    // Create recipient address from state (predicate hash only, not including data)
    let address_hash = state.address_hash()?;
    let recipient = unicity_sdk::types::address::GenericAddress::direct(address_hash);

    // Create mint data
    let mint_data = MintTransactionData::new(
        token_id,
        TokenType::new(b"MY_TOKEN".to_vec()),
        None, // token_data (optional token immutable data)
        None, // coin_data (for fungible tokens)
        recipient, // recipient address
        b"Initial token data".to_vec(), // salt (not Option<Vec<u8>>)
        None, // recipient_data_hash
        None, // reason (split_mint_reason)
    );

    // Mint the token (uses universal minter, no signing key needed)
    let token = client.mint_token(mint_data, state).await?;
    println!("Minted token with ID: {:?}", token.id()?);

    Ok(())
}
