use crate::error::{Result, SdkError};
use crate::types::predicate::{Predicate, PredicateReference};
use crate::types::primitives::DataHash;
use crate::types::transaction::Transaction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Token identifier - 32-byte hash
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenId([u8; 32]);

impl TokenId {
    /// Create a new token ID
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from slice
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 32 {
            return Err(SdkError::InvalidParameter(
                "TokenId must be 32 bytes".to_string(),
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Compute token ID from genesis transaction
    pub fn from_genesis_hash(hash: &DataHash) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&hash.imprint());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hasher.finalize());
        Self(bytes)
    }

    /// Generate a unique token ID using timestamp and random bytes
    /// This ensures uniqueness across test runs to avoid REQUEST_ID_EXISTS errors
    pub fn unique() -> Self {
        let mut bytes = [0u8; 32];
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        bytes[0..16].copy_from_slice(&timestamp.to_be_bytes());
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes[16..]);
        Self(bytes)
    }

    /// Generate a unique token ID with a marker byte for categorization
    /// Useful for distinguishing token types in tests
    pub fn unique_with_marker(marker: u8) -> Self {
        let mut bytes = [0u8; 32];
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        bytes[0..16].copy_from_slice(&timestamp.to_be_bytes());
        bytes[16] = marker;
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes[17..]);
        Self(bytes)
    }
}

impl std::fmt::Display for TokenId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// Token type identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenType(#[serde(with = "serde_bytes")] Vec<u8>);

impl TokenType {
    /// Create a new token type
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Token state containing unlock predicate and optional data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenState {
    pub unlock_predicate: PredicateReference,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
}

impl TokenState {
    /// Create a new token state
    pub fn new(unlock_predicate: PredicateReference, data: Option<Vec<u8>>) -> Self {
        Self {
            unlock_predicate,
            data,
        }
    }

    /// Create from a predicate
    pub fn from_predicate(predicate: &dyn Predicate, data: Option<Vec<u8>>) -> Result<Self> {
        Ok(Self {
            unlock_predicate: PredicateReference::from_predicate(predicate)?,
            data,
        })
    }

    /// Compute the hash of the token state
    pub fn hash(&self) -> Result<DataHash> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        // Hash the predicate reference
        hasher.update(&[self.unlock_predicate.predicate_type as u8]);
        hasher.update(&self.unlock_predicate.data);

        // Hash the optional data
        if let Some(ref data) = self.data {
            hasher.update(&[1u8]); // Marker for data presence
            hasher.update(data);
        } else {
            hasher.update(&[0u8]); // Marker for no data
        }

        Ok(DataHash::sha256(hasher.finalize().to_vec()))
    }
}

/// Token coin data for fungible tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCoinData {
    pub coins: HashMap<String, u64>,
}

impl TokenCoinData {
    /// Create new coin data
    pub fn new() -> Self {
        Self {
            coins: HashMap::new(),
        }
    }

    /// Add coins of a specific type
    pub fn add_coin(&mut self, coin_type: String, amount: u64) {
        *self.coins.entry(coin_type).or_insert(0) += amount;
    }

    /// Get the amount for a specific coin type
    pub fn get_amount(&self, coin_type: &str) -> Option<u64> {
        self.coins.get(coin_type).copied()
    }

    /// Get total number of coin types
    pub fn num_types(&self) -> usize {
        self.coins.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.coins.is_empty()
    }
}

impl Default for TokenCoinData {
    fn default() -> Self {
        Self::new()
    }
}

/// Generic token structure with state and transaction history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token<T> {
    pub state: TokenState,
    pub genesis: Transaction<T>,
    #[serde(default)]
    pub transactions: Vec<Transaction<crate::types::transaction::TransferTransactionData>>,
    #[serde(default)]
    pub nametags: Vec<Token<crate::types::transaction::NametagMintTransactionData>>,
}

impl<T> Token<T>
where
    T: Clone + Serialize + for<'de> Deserialize<'de>,
{
    /// Create a new token
    pub fn new(state: TokenState, genesis: Transaction<T>) -> Self {
        Self {
            state,
            genesis,
            transactions: Vec::new(),
            nametags: Vec::new(),
        }
    }

    /// Get the token ID
    pub fn id(&self) -> Result<TokenId> {
        let genesis_hash = self.genesis.hash()?;
        Ok(TokenId::from_genesis_hash(&genesis_hash))
    }

    /// Add a transfer transaction
    pub fn add_transaction(
        &mut self,
        transaction: Transaction<crate::types::transaction::TransferTransactionData>,
    ) {
        self.transactions.push(transaction);
    }

    /// Add a nametag token
    pub fn add_nametag(
        &mut self,
        nametag: Token<crate::types::transaction::NametagMintTransactionData>,
    ) {
        self.nametags.push(nametag);
    }

    /// Get the current state hash
    pub fn state_hash(&self) -> Result<DataHash> {
        self.state.hash()
    }

    /// Get the last transaction
    pub fn last_transaction(
        &self,
    ) -> Option<&Transaction<crate::types::transaction::TransferTransactionData>> {
        self.transactions.last()
    }

    /// Validate token consistency
    pub fn validate(&self) -> Result<()> {
        // Validate genesis transaction
        self.genesis.validate()?;

        // Validate all transfer transactions
        for tx in &self.transactions {
            tx.validate()?;
        }

        // Validate nametags
        for nametag in &self.nametags {
            nametag.validate()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::predicate::UnmaskedPredicate;

    #[test]
    fn test_token_id() {
        let bytes = [1u8; 32];
        let id = TokenId::new(bytes);
        assert_eq!(id.as_bytes(), &bytes);
        assert_eq!(id.to_string(), hex::encode(bytes));
    }

    #[test]
    fn test_token_state() {
        use crate::crypto::keys::KeyPair;
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let predicate = UnmaskedPredicate::new(public_key);
        let state = TokenState::from_predicate(&predicate, Some(vec![1, 2, 3])).unwrap();

        assert_eq!(state.data, Some(vec![1, 2, 3]));
        assert!(state.hash().is_ok());
    }

    #[test]
    fn test_token_coin_data() {
        let mut coin_data = TokenCoinData::new();
        coin_data.add_coin("BTC".to_string(), 100);
        coin_data.add_coin("ETH".to_string(), 50);
        coin_data.add_coin("BTC".to_string(), 25); // Add more BTC

        assert_eq!(coin_data.get_amount("BTC"), Some(125));
        assert_eq!(coin_data.get_amount("ETH"), Some(50));
        assert_eq!(coin_data.get_amount("XRP"), None);
        assert_eq!(coin_data.num_types(), 2);
    }

    #[test]
    fn test_unique_token_id() {
        // Generate multiple unique token IDs
        let id1 = TokenId::unique();
        let id2 = TokenId::unique();
        let id3 = TokenId::unique();

        // They should all be different
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);

        // Each should be 32 bytes
        assert_eq!(id1.as_bytes().len(), 32);
        assert_eq!(id2.as_bytes().len(), 32);
        assert_eq!(id3.as_bytes().len(), 32);
    }

    #[test]
    fn test_unique_token_id_with_marker() {
        // Generate IDs with different markers
        let id1 = TokenId::unique_with_marker(1);
        let id2 = TokenId::unique_with_marker(2);
        let id3 = TokenId::unique_with_marker(1);

        // They should all be different (even with same marker)
        assert_ne!(id1, id2);
        assert_ne!(id1, id3);

        // Check that marker is at position 16
        assert_eq!(id1.as_bytes()[16], 1);
        assert_eq!(id2.as_bytes()[16], 2);
        assert_eq!(id3.as_bytes()[16], 1);
    }
}
