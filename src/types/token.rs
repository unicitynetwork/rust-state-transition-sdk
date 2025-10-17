use crate::error::{Result, SdkError};
use crate::prelude::*;
use crate::types::predicate::{Predicate, PredicateReference};
use crate::types::primitives::DataHash;
use crate::types::transaction::{Transaction, TransactionDataTrait};
use serde::{Deserialize, Serialize};
use indexmap::IndexMap;

/// Helper to create an IndexMap with a default hasher for both std and no_std
#[cfg(feature = "std")]
fn new_index_map<K, V>() -> IndexMap<K, V>
where
    K: core::hash::Hash + Eq,
{
    IndexMap::new()
}

/// Helper to create an IndexMap with a default hasher for both std and no_std
#[cfg(not(feature = "std"))]
fn new_index_map<K, V>() -> IndexMap<K, V, foldhash::fast::RandomState>
where
    K: core::hash::Hash + Eq,
{
    IndexMap::with_hasher(foldhash::fast::RandomState::default())
}

/// Token identifier - 32-byte hash
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenId([u8; 32]);

// Custom serialization to match Java SDK (hex string format)
impl Serialize for TokenId {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for TokenId {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_string = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_string).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "TokenId must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(TokenId(array))
    }
}

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
    #[cfg(feature = "std")]
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
    /// Useful for distinguishing token types in e.g. tests
    #[cfg(feature = "std")]
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

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// Token type identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenType(Vec<u8>);

// Custom serialization to match Java SDK (hex string format)
impl Serialize for TokenType {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for TokenType {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_string = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_string).map_err(serde::de::Error::custom)?;
        Ok(TokenType(bytes))
    }
}

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

/// Token state containing unlock predicate and optional data payload
#[derive(Debug, Clone)]
pub struct TokenState {
    pub unlock_predicate: PredicateReference,
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

    /// Compute the address hash for this state (predicate reference hash only, without data)
    ///
    /// This is used to create recipient addresses. The address is derived from the predicate
    /// reference only, while the state data is tracked separately via recipient_data_hash.
    ///
    /// This matches Java SDK behavior where:
    /// - Recipient address = DirectAddress(predicate_reference.hash())
    /// - Recipient data hash = SHA256(state.data) if present
    pub fn address_hash(&self) -> Result<DataHash> {
        self.unlock_predicate.hash()
    }

    /// Compute the data hash for this state (if data is present)
    ///
    /// This is used to create recipient_data_hash in transactions.
    /// Returns None if the state has no data.
    pub fn data_hash(&self) -> Option<DataHash> {
        self.data.as_ref().map(|data| {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(data);
            DataHash::sha256(hasher.finalize().to_vec())
        })
    }
}

// Custom serialization for TokenState to match Java SDK format
impl Serialize for TokenState {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        // Serialize predicate as hex-encoded CBOR
        let predicate_cbor = self.unlock_predicate.to_cbor()
            .map_err(serde::ser::Error::custom)?;
        let predicate_hex = hex::encode(&predicate_cbor);

        let mut state = serializer.serialize_struct("TokenState", 2)?;
        state.serialize_field("predicate", &predicate_hex)?;
        state.serialize_field("data", &self.data)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for TokenState {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        struct TokenStateVisitor;

        impl<'de> Visitor<'de> for TokenStateVisitor {
            type Value = TokenState;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct TokenState")
            }

            fn visit_map<V>(self, mut map: V) -> core::result::Result<TokenState, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut predicate: Option<String> = None;
                let mut data: Option<Option<Vec<u8>>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "predicate" => {
                            predicate = Some(map.next_value()?);
                        }
                        "data" => {
                            data = Some(map.next_value()?);
                        }
                        _ => {
                            // Skip unknown fields
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                let predicate_hex = predicate.ok_or_else(|| de::Error::missing_field("predicate"))?;
                let predicate_cbor = hex::decode(&predicate_hex)
                    .map_err(|e| de::Error::custom(format!("Invalid predicate hex: {}", e)))?;

                let unlock_predicate = PredicateReference::from_cbor(&predicate_cbor)
                    .map_err(|e| de::Error::custom(format!("Invalid predicate CBOR: {}", e)))?;

                Ok(TokenState {
                    unlock_predicate,
                    data: data.unwrap_or(None),
                })
            }
        }

        deserializer.deserialize_struct("TokenState", &["predicate", "data"], TokenStateVisitor)
    }
}

/// Token coin data for fungible tokens
#[derive(Debug, Clone)]
#[cfg(feature = "std")]
pub struct TokenCoinData {
    pub coins: IndexMap<String, u64>,
}

/// Token coin data for fungible tokens
#[derive(Debug, Clone)]
#[cfg(not(feature = "std"))]
pub struct TokenCoinData {
    pub coins: IndexMap<String, u64, foldhash::fast::RandomState>,
}

// Custom serialization to match Java SDK format: [[coinId, amount], ...]
impl Serialize for TokenCoinData {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.coins.len()))?;
        for (coin_id, amount) in &self.coins {
            // Serialize as [coinId, amount] tuple
            seq.serialize_element(&(coin_id, amount.to_string()))?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for TokenCoinData {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize as array of [coinId, amount] tuples
        let coin_pairs: Vec<(String, String)> = Vec::deserialize(deserializer)?;
        let mut coins = new_index_map();
        for (coin_id, amount_str) in coin_pairs {
            let amount = amount_str.parse::<u64>()
                .map_err(|e| serde::de::Error::custom(format!("Invalid amount: {}", e)))?;
            coins.insert(coin_id, amount);
        }
        Ok(TokenCoinData { coins })
    }
}

impl TokenCoinData {
    /// Create new coin data
    pub fn new() -> Self {
        Self {
            coins: new_index_map(),
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

    /// Convert to CBOR Value matching Java SDK format
    /// Returns an array of [coinId (bytes), amount (string as bytes)] pairs
    /// Matches Java SDK TokenCoinData.toCbor() method
    pub fn to_cbor_value(&self) -> crate::error::Result<ciborium::Value> {
        use ciborium::Value;

        let mut coin_pairs = vec![];
        for (coin_id, amount) in &self.coins {
            // Decode coin_id from hex string to bytes
            let coin_id_bytes = hex::decode(coin_id)
                .map_err(|e| crate::error::SdkError::Serialization(format!("Invalid coin ID hex: {}", e)))?;

            // Convert amount to string and then to bytes
            let amount_string = amount.to_string();
            let amount_bytes = amount_string.into_bytes();

            // Create [coinId, amount] pair
            coin_pairs.push(Value::Array(vec![
                Value::Bytes(coin_id_bytes),
                Value::Bytes(amount_bytes),
            ]));
        }

        Ok(Value::Array(coin_pairs))
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
    #[serde(default = "default_version")]
    pub version: String,
}

fn default_version() -> String {
    "2.0".to_string()
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
            version: default_version(),
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
    ///
    /// **SECURITY WARNING**: This method is incomplete and does NOT perform proper verification.
    /// It only does basic structural validation. Use `verify()` for security-critical validation.
    pub fn validate(&self) -> Result<()> {
        // NOTE: This performs only basic structural validation
        // See verify_with_trust_base() for comprehensive cryptographic verification
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

    /// Verify the complete token state against a trust base
    ///
    /// This is the comprehensive security verification that should be used for all
    /// security-critical operations. It verifies:
    /// - Genesis transaction with inclusion proof and certificate
    /// - Complete cryptographic chain from genesis to current transaction
    /// - Each transaction's state transition is valid
    /// - Current token state is consistent with transaction history
    /// - All nametags
    ///
    /// The verification chain ensures:
    /// 1. Each transaction is cryptographically signed and included in a block (via inclusion proof)
    /// 2. Each transaction's source state matches the previous transaction's target state
    /// 3. The authenticator in each transaction proves authorization
    /// 4. The current state matches the last transaction's result
    ///
    /// Based on Java SDK Token.verify() at java-state-transition-sdk/src/main/java/org/unicitylabs/sdk/token/Token.java:251-287
    #[must_use = "Verification result must be checked - ignoring could lead to security vulnerabilities"]
    pub fn verify_with_trust_base(&self, trust_base: &crate::types::bft::RootTrustBase) -> Result<()>
    where
        T: TransactionDataTrait,
    {
        // STEP 1: Verify genesis transaction
        // This verifies the complete chain: Transaction → LeafValue → SMT Path → Root → Certificate → Trust Base
        // Based on Java SDK Token.verifyGenesis() at java-state-transition-sdk/src/main/java/org/unicitylabs/sdk/token/Token.java:325-376
        self.verify_genesis(trust_base)?;

        // STEP 2: Verify each transfer transaction in sequence
        // This ensures the cryptographic chain from genesis to current state
        //
        // Based on Java SDK Token.verify() at
        // java-state-transition-sdk/src/main/java/org/unicitylabs/sdk/token/Token.java:259-278
        for i in 0..self.transactions.len() {
            let transaction = &self.transactions[i];

            // 2a. Verify the transaction itself (inclusion proof, authenticator signature, etc.)
            // This verifies: Transaction → LeafValue → SMT Path → Root → Certificate → Trust Base
            // Create request_id from transaction hash for verification
            let transaction_hash = transaction.hash().unwrap_or_else(|_| DataHash::sha256(vec![0]));
            let request_id = crate::types::primitives::RequestId::from_data_hash(transaction_hash);

            if !transaction.inclusion_proof.verify_with_trust_base(&request_id, trust_base)? {
                return Err(SdkError::Validation(format!(
                    "Transaction at index {}: inclusion proof verification failed",
                    i
                )));
            }

            // 2b. Verify the transaction chain: the transaction's source state must be provably
            // linked to the previous transaction's recipient
            //
            // This implements the Java SDK logic where we:
            // 1. Create a "snapshot" token with the source state and previous transactions
            // 2. Verify the transaction against that snapshot
            // 3. Check that the source state's predicate-derived address matches the previous recipient
            //
            // Java SDK lines 266-277
            self.verify_transaction_chain(transaction, i, trust_base)?;

            // 2c. Verify transaction-specific constraints (including predicate authorization)
            // Note: Transaction-specific verification is handled in verify_transaction_chain
            // TODO: Add dedicated verify_transfer_specific method if needed

            // NOTE: Complete Authorization Chain
            // ==================================
            // At this point, we have verified:
            // 1. The transaction is cryptographically signed (authenticator signature verified)
            // 2. The transaction is included in a certified block (inclusion proof verified)
            // 3. The signing key can unlock the source state's predicate (predicate authorization)
            // 4. The source state is provably linked to the previous transaction's recipient
            //
            // Together, these checks form the complete security guarantee that:
            // - The transaction is authentic and hasn't been tampered with
            // - The transaction was created by someone authorized to transfer the token
            // - The transaction was accepted by the network and included in a block
            // - The token forms an unbroken chain from genesis to current state
        }

        // STEP 3: Verify current token state
        // Ensure the current state is consistent with transaction history
        self.verify_current_state()?;

        // STEP 4: Verify all nametags
        // Each nametag must be independently verified
        for nametag in &self.nametags {
            nametag.verify_with_trust_base(trust_base)?;
        }

        Ok(())
    }

    /// Performs genesis verification checks:
    /// 1. Authenticator presence
    /// 2. Transaction hash presence
    /// 3. Source state validity
    /// 4. Authenticator public key verification
    /// 5. Authenticator signature verification
    /// 6. Inclusion proof verification
    ///
    /// Based on Java SDK Token.verifyGenesis() at
    /// java-state-transition-sdk/src/main/java/org/unicitylabs/sdk/token/Token.java:325-376
    fn verify_genesis(&self, trust_base: &crate::types::bft::RootTrustBase) -> Result<()>
    where
        T: TransactionDataTrait,
    {
        // 1. Check authenticator is present
        let authenticator = self.genesis.inclusion_proof.authenticator.as_ref()
            .ok_or_else(|| SdkError::Validation(
                "Genesis transaction missing authenticator".to_string()
            ))?;

        // 2. Check transaction hash is present
        let transaction_hash = self.genesis.inclusion_proof.transaction_hash.as_ref()
            .ok_or_else(|| SdkError::Validation(
                "Genesis transaction missing transaction hash".to_string()
            ))?;

        // 3. Verify authenticator signature explicitly
        // While this is also checked in inclusion proof verification, we verify it separately
        //
        // NOTE: The transaction hash is a DataHash in imprint format: [algorithm (2 bytes)][hash (32 bytes)]
        // The signature is over the hash part only (getData() in Java SDK), not the full imprint.
        let transaction_hash_bytes = hex::decode(transaction_hash)
            .map_err(|e| SdkError::Serialization(format!("Invalid transaction hash hex: {}", e)))?;

        // Extract the hash data (skip algorithm prefix if present)
        let hash_to_verify = if transaction_hash_bytes.len() == 34 {
            &transaction_hash_bytes[2..] // Skip 2-byte algorithm prefix
        } else {
            &transaction_hash_bytes[..]
        };

        if !authenticator.verify(hash_to_verify)? {
            return Err(SdkError::Validation(
                "Genesis authenticator signature verification failed".to_string()
            ));
        }

        // 4. Verify inclusion proof (comprehensive check)
        // Create request_id from genesis transaction hash
        let genesis_hash = self.genesis.hash()?;
        let request_id = crate::types::primitives::RequestId::from_data_hash(genesis_hash);

        if !self.genesis.inclusion_proof.verify_with_trust_base(&request_id, trust_base)? {
            return Err(SdkError::Validation(
                "Genesis inclusion proof verification failed".to_string()
            ));
        }

        Ok(())
    }

    /// Verify transaction chain integrity
    ///
    /// This method verifies that the transaction chain is valid by checking:
    /// 1. The source state's predicate-derived address matches the previous transaction's recipient
    /// 2. The source state's data matches the previous transaction's recipient_data_hash
    ///
    /// This ensures that each transaction in the chain properly references the previous
    /// transaction's output, forming an unbroken chain from genesis to current state.
    ///
    /// Based on Java SDK Token.verifyTransaction() at
    /// java-state-transition-sdk/src/main/java/org/unicitylabs/sdk/token/Token.java:289-323
    fn verify_transaction_chain(
        &self,
        transaction: &Transaction<crate::types::transaction::TransferTransactionData>,
        transaction_index: usize,
        trust_base: &crate::types::bft::RootTrustBase,
    ) -> Result<()>
    where
        T: crate::types::transaction::TransactionDataTrait,
    {
        // SECURITY: Verify transaction nametags BEFORE using them for proxy resolution
        // Based on Java SDK Token.verifyTransaction() at lines 294-298
        // Nametags must be verified before they're used to resolve proxy addresses
        for nametag in &transaction.data.nametags {
            nametag.verify_with_trust_base(trust_base)?;
        }

        // Get the previous transaction's recipient and data
        // If this is the first transfer (index 0), previous is genesis
        // Otherwise, previous is transactions[transaction_index - 1]
        let (previous_recipient, previous_recipient_data_hash) = if transaction_index == 0 {
            // First transfer - previous is genesis
            (
                self.genesis.data.get_recipient(),
                self.genesis.data.get_recipient_data_hash(),
            )
        } else {
            // Not first transfer - previous is the transfer before this one
            let prev_tx = &self.transactions[transaction_index - 1];
            (prev_tx.data.get_recipient(), prev_tx.data.get_recipient_data_hash())
        };

        // STEP 1: Verify address chain
        // Get the expected recipient address from the current transaction's source state predicate
        // The source state's predicate should resolve to an address that matches the previous recipient
        let source_predicate_ref = &transaction.data.source_state.unlock_predicate;
        let expected_recipient_address =
            crate::types::address::DirectAddress::from_predicate_reference(source_predicate_ref)?;

        // Get the previous transaction's recipient address hash
        // For direct addresses, the hash is already available
        // For proxy addresses, we would need to resolve through nametags
        let previous_recipient_hash = previous_recipient.hash();

        // Verify the addresses match
        if &expected_recipient_address.hash != previous_recipient_hash {
            return Err(SdkError::Validation(format!(
                "Transaction chain broken at index {}: source state predicate address {} does not match previous recipient address {}",
                transaction_index,
                hex::encode(expected_recipient_address.hash.imprint()),
                hex::encode(previous_recipient_hash.imprint())
            )));
        }

        // STEP 2: Verify recipient data hash matches source state data
        // The previous transaction's recipient_data_hash should match the current transaction's source_state.data
        let source_state_data = transaction.data.source_state.data.as_deref();

        match (previous_recipient_data_hash, source_state_data) {
            (Some(expected_hash), Some(actual_data)) => {
                // Both present - compute hash and verify
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(actual_data);
                let computed_hash = DataHash::sha256(hasher.finalize().to_vec());

                if &computed_hash != expected_hash {
                    return Err(SdkError::Validation(format!(
                        "Transaction chain broken at index {}: source state data hash {} does not match previous recipient_data_hash {}",
                        transaction_index,
                        hex::encode(computed_hash.imprint()),
                        hex::encode(expected_hash.imprint())
                    )));
                }
            }
            (Some(_), None) => {
                // Hash present but no data - mismatch
                return Err(SdkError::Validation(format!(
                    "Transaction chain broken at index {}: previous transaction has recipient_data_hash but source state has no data",
                    transaction_index
                )));
            }
            (None, Some(_)) => {
                // SECURITY: Strict validation - reject data without explicit hash commitment
                // Data should always be explicitly committed in the previous transaction
                // This prevents data injection attacks
                return Err(SdkError::Validation(format!(
                    "Transaction chain broken at index {}: previous transaction has no recipient_data_hash but source state has data (security violation: uncommitted data)",
                    transaction_index
                )));
            }
            (None, None) => {
                // Both None - valid (no recipient data)
            }
        }

        // STEP 3: Resolve proxy addresses if needed
        // If the previous recipient is a proxy address, we need to resolve it through nametags
        // Based on Java SDK ProxyAddress.resolve() at
        // java-state-transition-sdk/src/main/java/org/unicitylabs/sdk/address/ProxyAddress.java:70-97
        if let crate::types::address::GenericAddress::Proxy(_) = previous_recipient {
            // Resolve the proxy address to a direct address using nametags
            // Use both token nametags and transaction-specific nametags
            let resolved_address = self.resolve_proxy_address_with_transaction_nametags(
                previous_recipient,
                &transaction.data.nametags
            )?;

            // Verify the resolved address matches the expected recipient address
            if resolved_address.hash() != &expected_recipient_address.hash {
                return Err(SdkError::Validation(format!(
                    "Transaction chain broken at index {}: resolved proxy address {} does not match expected recipient address {}",
                    transaction_index,
                    hex::encode(resolved_address.hash().imprint()),
                    hex::encode(expected_recipient_address.hash.imprint())
                )));
            }
        }

        // STEP 4: Verify predicate authorization
        // The source state's predicate must authorize this transaction
        // Based on Java SDK Token.verifyTransaction() at line 318-320
        let predicate = source_predicate_ref.to_predicate()?;
        let authenticator_public_key = transaction.inclusion_proof.authenticator.as_ref()
            .ok_or_else(|| SdkError::Validation(
                format!("Transaction at index {} missing authenticator", transaction_index)
            ))?;

        let transaction_hash = transaction.inclusion_proof.transaction_hash.as_ref()
            .ok_or_else(|| SdkError::Validation(
                format!("Transaction at index {} missing transaction hash", transaction_index)
            ))?;

        // Get nonce revelation from transaction data (for MaskedPredicate)
        let nonce = transaction.data.get_nonce_revelation();

        // Convert types for predicate verification
        if authenticator_public_key.public_key.len() != 33 {
            return Err(SdkError::Validation(format!(
                "Transaction at index {}: invalid public key length: expected 33, got {}",
                transaction_index,
                authenticator_public_key.public_key.len()
            )));
        }
        let mut public_key_array = [0u8; 33];
        public_key_array.copy_from_slice(&authenticator_public_key.public_key);
        let public_key = crate::types::primitives::PublicKey::new(public_key_array)?;

        let transaction_hash_bytes = hex::decode(transaction_hash)
            .map_err(|e| SdkError::Serialization(format!("Invalid transaction hash hex: {}", e)))?;
        let transaction_hash_data = DataHash::from_imprint(&transaction_hash_bytes)?;

        // Call the full predicate.verify() method with nonce support
        if !predicate.verify(&public_key, &transaction_hash_data, nonce)? {
            return Err(SdkError::Validation(format!(
                "Transaction at index {}: predicate verification failed - predicate does not authorize this transaction",
                transaction_index
            )));
        }

        Ok(())
    }

    /// Resolve a proxy address using both token nametags and transaction-specific nametags
    ///
    /// This is the primary resolution method that combines:
    /// - Token-level nametags (self.nametags)
    /// - Transaction-specific nametags (additional parameter)
    ///
    /// Based on Java SDK Token.verifyTransaction() at line 308
    fn resolve_proxy_address_with_transaction_nametags(
        &self,
        address: &crate::types::address::GenericAddress,
        transaction_nametags: &[Token<crate::types::transaction::NametagMintTransactionData>],
    ) -> Result<crate::types::address::GenericAddress> {
        // Build a map from proxy addresses to nametag tokens
        // Include BOTH token nametags and transaction nametags
        let mut nametag_map: IndexMap<DataHash, &Token<crate::types::transaction::NametagMintTransactionData>, _> =
            new_index_map();

        // Add token-level nametags
        for nametag in &self.nametags {
            let nametag_token_id = nametag.id()?;
            let proxy_hash = DataHash::sha256(nametag_token_id.as_bytes().to_vec());

            if nametag_map.contains_key(&proxy_hash) {
                return Err(SdkError::Validation(
                    format!("Duplicate nametag proxy address: {}", hex::encode(proxy_hash.imprint()))
                ));
            }

            nametag_map.insert(proxy_hash, nametag);
        }

        // Add transaction-specific nametags (these can override token nametags)
        for nametag in transaction_nametags {
            let nametag_token_id = nametag.id()?;
            let proxy_hash = DataHash::sha256(nametag_token_id.as_bytes().to_vec());

            if nametag_map.contains_key(&proxy_hash) {
                return Err(SdkError::Validation(
                    format!("Duplicate nametag proxy address in transaction: {}", hex::encode(proxy_hash.imprint()))
                ));
            }

            nametag_map.insert(proxy_hash, nametag);
        }

        // Perform resolution using the combined nametag map
        self.resolve_proxy_address_from_map(address, &nametag_map)
    }

    /// Resolve a proxy address to a direct address using nametag tokens
    ///
    /// This method implements proxy address resolution by looking up nametag tokens.
    /// Each nametag token maps a proxy address (derived from the nametag's token ID)
    /// to a target state, which contains the actual predicate/address.
    ///
    /// The resolution process:
    /// 1. Build a map from proxy addresses to nametag tokens
    /// 2. Look up the input address in the map
    /// 3. Get the target state from the nametag
    /// 4. Convert the target state's predicate to an address
    /// 5. If the result is also a proxy, repeat (iterative resolution)
    /// 6. Return the final direct address
    ///
    /// Based on Java SDK ProxyAddress.resolve() at
    /// java-state-transition-sdk/src/main/java/org/unicitylabs/sdk/address/ProxyAddress.java:70-97
    #[allow(dead_code)] // Used in tests and available for simple resolution scenarios
    fn resolve_proxy_address(
        &self,
        address: &crate::types::address::GenericAddress,
    ) -> Result<crate::types::address::GenericAddress> {
        // Build a map from proxy addresses to nametag tokens
        // For each nametag, the proxy address is created from the nametag's token ID
        let mut nametag_map: IndexMap<DataHash, &Token<crate::types::transaction::NametagMintTransactionData>, _> =
            new_index_map();

        for nametag in &self.nametags {
            // Get the nametag token's ID (computed from genesis hash)
            let nametag_token_id = nametag.id()?;

            // Create a proxy address from the token ID
            // The proxy address hash is the token ID itself (in the Java SDK, it's SHA256(token_id) with 4-byte checksum)
            // For simplicity, we use the token ID directly as the proxy address hash
            let proxy_hash = DataHash::sha256(nametag_token_id.as_bytes().to_vec());

            // Check for duplicates
            if nametag_map.contains_key(&proxy_hash) {
                return Err(SdkError::Validation(
                    format!("Duplicate nametag proxy address: {}", hex::encode(proxy_hash.imprint()))
                ));
            }

            nametag_map.insert(proxy_hash, nametag);
        }

        // Perform resolution using the nametag map
        self.resolve_proxy_address_from_map(address, &nametag_map)
    }

    /// Core proxy address resolution logic using a provided nametag map
    ///
    /// This is the low-level resolution method that performs the actual address resolution
    /// using a pre-built nametag map. It handles iterative resolution and circular reference detection.
    fn resolve_proxy_address_from_map<S: core::hash::BuildHasher>(
        &self,
        address: &crate::types::address::GenericAddress,
        nametag_map: &IndexMap<DataHash, &Token<crate::types::transaction::NametagMintTransactionData>, S>,
    ) -> Result<crate::types::address::GenericAddress> {
        // Iteratively resolve the address until we reach a direct address
        let mut current_address = address.clone();
        let max_iterations = 10; // Prevent infinite loops
        let mut iterations = 0;

        while let crate::types::address::GenericAddress::Proxy(proxy) = current_address {
            iterations += 1;
            if iterations > max_iterations {
                return Err(SdkError::Validation(
                    "Proxy address resolution exceeded maximum iterations (possible circular reference)".to_string()
                ));
            }

            // Look up the nametag for this proxy address
            let nametag = nametag_map.get(&proxy.hash)
                .ok_or_else(|| SdkError::Validation(
                    format!("Proxy address {} not found in nametags", hex::encode(proxy.hash.imprint()))
                ))?;

            // Get the target state from the nametag
            // The target state contains the predicate that the proxy resolves to
            let target_predicate_ref = &nametag.state.unlock_predicate;

            // Convert the predicate to an address
            // This could be either a direct address or another proxy address (for chained resolution)
            let target_address =
                crate::types::address::DirectAddress::from_predicate_reference(target_predicate_ref)?;

            // Update current address - in this implementation, we only support direct addresses
            // as the final resolution, so we convert to GenericAddress::Direct
            current_address = crate::types::address::GenericAddress::Direct(target_address);
        }

        Ok(current_address)
    }

    /// Verify the current token state is consistent with transaction history
    ///
    /// This method performs comprehensive consistency checks on the current token state:
    /// - Verifies the current state's data matches the last transaction's recipient_data_hash
    /// - Verifies the current state's predicate matches the last transaction's recipient address
    /// - Resolves proxy addresses if needed using nametags
    ///
    /// For genesis-only tokens (no transfers), the current state should match the genesis recipient.
    /// For tokens with transfers, the current state should match the last transfer's recipient.
    fn verify_current_state(&self) -> Result<()>
    where
        T: TransactionDataTrait,
    {
        // Verify the current state can be hashed (structural validation)
        let _current_state_hash = self.state.hash()?;

        // Get the recipient address we should verify against
        let (recipient_address, recipient_data_hash, transaction_nametags) = if self.transactions.is_empty() {
            // For genesis-only tokens, use genesis recipient
            (
                self.genesis.data.get_recipient(),
                self.genesis.data.get_recipient_data_hash(),
                &[] as &[Token<crate::types::transaction::NametagMintTransactionData>],
            )
        } else {
            // For tokens with transfers, use last transfer's recipient
            let last_transaction = self.transactions.last().unwrap();
            (
                last_transaction.data.get_recipient(),
                last_transaction.data.get_recipient_data_hash(),
                last_transaction.data.get_nametags(),
            )
        };

        // STEP 1: Verify recipient data hash matches current state data
        match (recipient_data_hash, &self.state.data) {
            (Some(expected_hash), Some(state_data)) => {
                // Both present - compute hash and verify
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(state_data);
                let computed_hash = DataHash::sha256(hasher.finalize().to_vec());

                if &computed_hash != expected_hash {
                    return Err(SdkError::Validation(
                        "Current state data does not match last transaction's recipient_data_hash".to_string(),
                    ));
                }
            }
            (Some(_), None) => {
                // Hash present but no data - mismatch
                return Err(SdkError::Validation(
                    "Last transaction has recipient_data_hash but current state has no data".to_string(),
                ));
            }
            (None, Some(_)) => {
                // SECURITY: Strict validation - reject data without explicit hash commitment
                // For genesis transactions, the state should not have uncommitted data
                // For transfer transactions, data must be explicitly committed
                return Err(SdkError::Validation(
                    "Current state has data but last transaction has no recipient_data_hash (security violation: uncommitted data)".to_string(),
                ));
            }
            (None, None) => {
                // Both None - valid (no state data)
            }
        }

        // STEP 2: Verify current state's predicate matches the recipient address
        // Convert the current state's predicate to an address
        let current_predicate_address = crate::types::address::DirectAddress::from_predicate_reference(
            &self.state.unlock_predicate
        )?;

        // Resolve the recipient address if it's a proxy
        let resolved_recipient_address = match recipient_address {
            crate::types::address::GenericAddress::Direct(direct) => {
                // Already direct, no resolution needed
                crate::types::address::GenericAddress::Direct(direct.clone())
            }
            crate::types::address::GenericAddress::Proxy(_) => {
                // Need to resolve the proxy address using nametags
                self.resolve_proxy_address_with_transaction_nametags(
                    recipient_address,
                    transaction_nametags
                )?
            }
        };

        // Compare the addresses
        let recipient_hash = resolved_recipient_address.hash();
        if &current_predicate_address.hash != recipient_hash {
            return Err(SdkError::Validation(format!(
                "Current state predicate address {} does not match recipient address {}",
                hex::encode(current_predicate_address.hash.imprint()),
                hex::encode(recipient_hash.imprint())
            )));
        }

        Ok(())
    }
}

/// Specialized verification for MintTransactionData tokens
impl Token<crate::types::transaction::MintTransactionData> {
    /// Verify mint-specific token constraints
    pub fn verify_mint_token(&self, trust_base: &crate::types::bft::RootTrustBase) -> Result<()> {
        // Do the generic verification which covers all mint-specific checks
        self.verify_with_trust_base(trust_base)?;

        // TODO: Add dedicated mint-specific verification if needed
        // (e.g., token type validation, coin data constraints, etc.)

        Ok(())
    }
}

/// Specialized verification for Transfer tokens (genesis is also MintTransactionData)
impl Token<crate::types::transaction::TransferTransactionData> {
    /// Verify transfer-specific token constraints
    pub fn verify_transfer_token(&self, trust_base: &crate::types::bft::RootTrustBase) -> Result<()> {
        // Do the generic verification which covers all transfer-specific checks
        self.verify_with_trust_base(trust_base)?;

        // TODO: Add dedicated transfer-specific verification if needed
        // (e.g., state transition validity, nametag constraints, etc.)

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

    #[test]
    fn test_token_state_hash_consistency() {
        // Test that the same token state produces the same hash
        use crate::crypto::keys::KeyPair;
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let predicate = UnmaskedPredicate::new(public_key);

        let state1 = TokenState::from_predicate(&predicate, Some(vec![1, 2, 3])).unwrap();
        let state2 = TokenState::from_predicate(&predicate, Some(vec![1, 2, 3])).unwrap();

        assert_eq!(state1.hash().unwrap(), state2.hash().unwrap());
    }

    #[test]
    fn test_token_state_hash_detects_data_tampering() {
        // Test that different data produces different hashes
        use crate::crypto::keys::KeyPair;
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let predicate = UnmaskedPredicate::new(public_key);

        let state_original = TokenState::from_predicate(&predicate, Some(vec![1, 2, 3])).unwrap();
        let state_tampered = TokenState::from_predicate(&predicate, Some(vec![1, 2, 99])).unwrap();

        // Hashes should be different - tampering detected
        assert_ne!(state_original.hash().unwrap(), state_tampered.hash().unwrap());
    }

    #[test]
    fn test_token_state_hash_detects_predicate_change() {
        // Test that changing the predicate produces a different hash
        use crate::crypto::keys::KeyPair;
        let key_pair1 = KeyPair::generate().unwrap();
        let key_pair2 = KeyPair::generate().unwrap();
        let predicate1 = UnmaskedPredicate::new(key_pair1.public_key().clone());
        let predicate2 = UnmaskedPredicate::new(key_pair2.public_key().clone());

        let state1 = TokenState::from_predicate(&predicate1, Some(vec![1, 2, 3])).unwrap();
        let state2 = TokenState::from_predicate(&predicate2, Some(vec![1, 2, 3])).unwrap();

        // Hashes should be different - predicate change detected
        assert_ne!(state1.hash().unwrap(), state2.hash().unwrap());
    }

    #[test]
    fn test_token_state_hash_none_vs_empty() {
        // Test that None data and empty data produce different hashes
        use crate::crypto::keys::KeyPair;
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let predicate = UnmaskedPredicate::new(public_key);

        let state_none = TokenState::from_predicate(&predicate, None).unwrap();
        let state_empty = TokenState::from_predicate(&predicate, Some(vec![])).unwrap();

        // These should produce different hashes as they represent different states
        assert_ne!(state_none.hash().unwrap(), state_empty.hash().unwrap());
    }

    #[test]
    fn test_resolve_direct_address() {
        // Test that direct addresses are returned as-is without resolution
        use crate::crypto::keys::KeyPair;
        use crate::types::address::GenericAddress;
        use crate::types::transaction::MintTransactionData;

        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let predicate = UnmaskedPredicate::new(public_key);
        let state = TokenState::from_predicate(&predicate, None).unwrap();

        // Create a token with no nametags
        let token_id = TokenId::unique();
        let recipient = GenericAddress::direct(DataHash::sha256(vec![1, 2, 3]));
        let mint_data = MintTransactionData::new(
            token_id,
            TokenType::new(vec![1, 2, 3]),
            None,
            None,
            recipient.clone(),
            vec![7, 8, 9],
            None,
            None,
        );

        let merkle_path = crate::types::transaction::MerkleTreePath {
            root: hex::encode(DataHash::sha256(vec![1]).imprint()),
            steps: vec![],
        };
        let proof = crate::types::transaction::InclusionProof::new(merkle_path);
        let genesis = crate::types::transaction::Transaction::new(mint_data, proof);
        let token = Token::new(state, genesis);

        // Direct address should be returned as-is
        let resolved = token.resolve_proxy_address(&recipient).unwrap();
        assert_eq!(resolved, recipient);
    }

    #[test]
    fn test_resolve_single_level_proxy() {
        // Test single-level proxy resolution
        use crate::crypto::keys::KeyPair;
        use crate::types::address::{GenericAddress, ProxyAddress};
        use crate::types::transaction::{MintTransactionData, NametagMintTransactionData};

        // Create target address for the nametag
        let target_key_pair = KeyPair::generate().unwrap();
        let target_predicate = UnmaskedPredicate::new(target_key_pair.public_key().clone());
        let target_state = TokenState::from_predicate(&target_predicate, None).unwrap();

        // Create a nametag token that maps to the target
        let nametag_token_id = TokenId::unique();
        let nametag_data = NametagMintTransactionData::new(
            "alice".to_string(),
            target_state.clone(),
        );
        let nametag_merkle_path = crate::types::transaction::MerkleTreePath {
            root: hex::encode(DataHash::sha256(vec![1]).imprint()),
            steps: vec![],
        };
        let nametag_proof = crate::types::transaction::InclusionProof::new(nametag_merkle_path);
        let nametag_genesis = crate::types::transaction::Transaction::new(nametag_data, nametag_proof);
        let nametag_token = Token::new(target_state.clone(), nametag_genesis);

        // Create main token with the nametag
        let main_key_pair = KeyPair::generate().unwrap();
        let main_predicate = UnmaskedPredicate::new(main_key_pair.public_key().clone());
        let main_state = TokenState::from_predicate(&main_predicate, None).unwrap();

        let main_token_id = TokenId::unique();
        let recipient = GenericAddress::direct(DataHash::sha256(vec![1, 2, 3]));
        let mint_data = MintTransactionData::new(
            main_token_id,
            TokenType::new(vec![1, 2, 3]),
            None,
            None,
            recipient.clone(),
            vec![7, 8, 9],
            None,
            None,
        );

        let merkle_path = crate::types::transaction::MerkleTreePath {
            root: hex::encode(DataHash::sha256(vec![1]).imprint()),
            steps: vec![],
        };
        let proof = crate::types::transaction::InclusionProof::new(merkle_path);
        let genesis = crate::types::transaction::Transaction::new(mint_data, proof);
        let mut token = Token::new(main_state, genesis);
        token.add_nametag(nametag_token);

        // Create a proxy address for the nametag
        let nametag_token_id_for_proxy = token.nametags[0].id().unwrap();
        let proxy_hash = DataHash::sha256(nametag_token_id_for_proxy.as_bytes().to_vec());
        let proxy_address = GenericAddress::Proxy(ProxyAddress::new(proxy_hash));

        // Resolve the proxy address
        let resolved = token.resolve_proxy_address(&proxy_address).unwrap();

        // Should resolve to the target state's address
        let expected_address = crate::types::address::DirectAddress::from_predicate_reference(
            &target_state.unlock_predicate
        ).unwrap();

        match resolved {
            GenericAddress::Direct(addr) => {
                assert_eq!(addr.hash, expected_address.hash);
            }
            _ => panic!("Expected direct address after resolution"),
        }
    }

    #[test]
    fn test_resolve_proxy_not_found() {
        // Test that resolution fails when proxy is not in nametags
        use crate::crypto::keys::KeyPair;
        use crate::types::address::{GenericAddress, ProxyAddress};
        use crate::types::transaction::MintTransactionData;

        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let predicate = UnmaskedPredicate::new(public_key);
        let state = TokenState::from_predicate(&predicate, None).unwrap();

        // Create a token with no nametags
        let token_id = TokenId::unique();
        let recipient = GenericAddress::direct(DataHash::sha256(vec![1, 2, 3]));
        let mint_data = MintTransactionData::new(
            token_id,
            TokenType::new(vec![1, 2, 3]),
            None,
            None,
            recipient.clone(),
            vec![7, 8, 9],
            None,
            None,
        );

        let merkle_path = crate::types::transaction::MerkleTreePath {
            root: hex::encode(DataHash::sha256(vec![1]).imprint()),
            steps: vec![],
        };
        let proof = crate::types::transaction::InclusionProof::new(merkle_path);
        let genesis = crate::types::transaction::Transaction::new(mint_data, proof);
        let token = Token::new(state, genesis);

        // Try to resolve a proxy that doesn't exist
        let proxy_hash = DataHash::sha256(vec![99, 99, 99]);
        let proxy_address = GenericAddress::Proxy(ProxyAddress::new(proxy_hash));

        let result = token.resolve_proxy_address(&proxy_address);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found in nametags"));
    }

    #[test]
    fn test_resolve_proxy_duplicate_detection() {
        // Test that duplicate nametag addresses are detected
        use crate::crypto::keys::KeyPair;
        use crate::types::transaction::{MintTransactionData, NametagMintTransactionData};

        // Create two nametag tokens with the same ID (which would create duplicate proxy addresses)
        let target_key_pair = KeyPair::generate().unwrap();
        let target_predicate = UnmaskedPredicate::new(target_key_pair.public_key().clone());
        let target_state = TokenState::from_predicate(&target_predicate, None).unwrap();

        // First nametag
        let nametag_data1 = NametagMintTransactionData::new(
            "alice".to_string(),
            target_state.clone(),
        );
        let nametag_merkle_path1 = crate::types::transaction::MerkleTreePath {
            root: hex::encode(DataHash::sha256(vec![1]).imprint()),
            steps: vec![],
        };
        let nametag_proof1 = crate::types::transaction::InclusionProof::new(nametag_merkle_path1);
        let nametag_genesis1 = crate::types::transaction::Transaction::new(nametag_data1, nametag_proof1);
        let nametag_token1 = Token::new(target_state.clone(), nametag_genesis1);

        // Second nametag with same genesis (will have same token ID)
        let nametag_data2 = NametagMintTransactionData::new(
            "alice".to_string(),
            target_state.clone(),
        );
        let nametag_merkle_path2 = crate::types::transaction::MerkleTreePath {
            root: hex::encode(DataHash::sha256(vec![1]).imprint()),
            steps: vec![],
        };
        let nametag_proof2 = crate::types::transaction::InclusionProof::new(nametag_merkle_path2);
        let nametag_genesis2 = crate::types::transaction::Transaction::new(nametag_data2, nametag_proof2);
        let nametag_token2 = Token::new(target_state.clone(), nametag_genesis2);

        // Create main token
        let main_key_pair = KeyPair::generate().unwrap();
        let main_predicate = UnmaskedPredicate::new(main_key_pair.public_key().clone());
        let main_state = TokenState::from_predicate(&main_predicate, None).unwrap();

        let main_token_id = TokenId::unique();
        let recipient = crate::types::address::GenericAddress::direct(DataHash::sha256(vec![1, 2, 3]));
        let mint_data = MintTransactionData::new(
            main_token_id,
            TokenType::new(vec![1, 2, 3]),
            None,
            None,
            recipient.clone(),
            vec![7, 8, 9],
            None,
            None,
        );

        let merkle_path = crate::types::transaction::MerkleTreePath {
            root: hex::encode(DataHash::sha256(vec![1]).imprint()),
            steps: vec![],
        };
        let proof = crate::types::transaction::InclusionProof::new(merkle_path);
        let genesis = crate::types::transaction::Transaction::new(mint_data, proof);
        let mut token = Token::new(main_state, genesis);

        // Add both nametags (they will have the same token ID, causing duplicate proxy addresses)
        token.add_nametag(nametag_token1);
        token.add_nametag(nametag_token2);

        // Try to resolve - should fail due to duplicate
        let nametag_token_id = token.nametags[0].id().unwrap();
        let proxy_hash = DataHash::sha256(nametag_token_id.as_bytes().to_vec());
        let proxy_address = crate::types::address::GenericAddress::Proxy(
            crate::types::address::ProxyAddress::new(proxy_hash)
        );

        let result = token.resolve_proxy_address(&proxy_address);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Duplicate nametag"));
    }
}
