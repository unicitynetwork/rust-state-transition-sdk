use crate::error::{Result, SdkError};
use crate::types::primitives::DataHash;
use crate::types::token::{TokenId, TokenState, TokenType};
use serde::{Deserialize, Serialize};

/// Trait for transaction data types that can have recipient data hashes
pub trait TransactionDataTrait {
    /// Get the recipient data hash if present
    fn get_recipient_data_hash(&self) -> Option<&DataHash>;

    /// Get the recipient address
    fn get_recipient(&self) -> &crate::types::address::GenericAddress;
}

/// Generic transaction wrapper with data and inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction<T> {
    pub data: T,
    #[serde(rename = "inclusionProof")]
    pub inclusion_proof: InclusionProof,
}

impl<T> Transaction<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    /// Create a new transaction
    pub fn new(data: T, inclusion_proof: InclusionProof) -> Self {
        Self {
            data,
            inclusion_proof,
        }
    }

    /// Compute the hash of the transaction
    pub fn hash(&self) -> Result<DataHash> {
        use sha2::{Digest, Sha256};
        let serialized =
            serde_json::to_vec(&self.data).map_err(|e| SdkError::Serialization(e.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        Ok(DataHash::sha256(hasher.finalize().to_vec()))
    }

    /// Validate the transaction
    pub fn validate(&self) -> Result<()> {
        self.inclusion_proof.validate()
    }
}

/// Authenticator for transaction signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authenticator {
    pub algorithm: String,
    #[serde(rename = "publicKey", with = "crate::types::hex_serde")]
    pub public_key: Vec<u8>,
    #[serde(with = "crate::types::hex_serde")]
    pub signature: Vec<u8>,
    #[serde(rename = "stateHash")]
    pub state_hash: DataHash,
}

impl Authenticator {
    /// Create a new authenticator
    pub fn new(
        algorithm: String,
        public_key: Vec<u8>,
        signature: Vec<u8>,
        state_hash: DataHash,
    ) -> Self {
        Self {
            algorithm,
            public_key,
            signature,
            state_hash,
        }
    }

    /// Verify the authenticator signature
    pub fn verify(&self, message: &[u8]) -> Result<bool> {
        use crate::crypto::signing::SigningService;
        use crate::types::primitives::{PublicKey, Signature};

        // Convert the public key bytes to PublicKey
        if self.public_key.len() != 33 {
            return Err(SdkError::Validation(format!(
                "Invalid public key length: expected 33, got {}",
                self.public_key.len()
            )));
        }
        let mut public_key_array = [0u8; 33];
        public_key_array.copy_from_slice(&self.public_key);
        let public_key = PublicKey::new(public_key_array)?;

        // Convert signature bytes to Signature
        if self.signature.len() != 65 {
            return Err(SdkError::Validation(format!(
                "Invalid signature length: expected 65, got {}",
                self.signature.len()
            )));
        }
        let mut signature_array = [0u8; 65];
        signature_array.copy_from_slice(&self.signature);
        let signature = Signature::new(signature_array);

        // Verify using SigningService
        let signing_service = SigningService::new();
        signing_service.verify(message, &signature, &public_key)
    }
}

/// Merkle tree path step for Java SDK compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTreePathStep {
    pub path: serde_json::Value, // Can be a number or string for large integers
    pub sibling: Vec<String>,
    pub branch: Vec<Option<String>>,
}

/// Merkle tree path for Java SDK compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTreePath {
    pub root: String,
    pub steps: Vec<MerkleTreePathStep>,
}

/// Inclusion proof for transaction verification (Java SDK format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    #[serde(rename = "merkleTreePath")]
    pub merkle_tree_path: MerkleTreePath,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator: Option<Authenticator>,
    #[serde(default, rename = "transactionHash", skip_serializing_if = "Option::is_none")]
    pub transaction_hash: Option<String>,
    #[serde(default, rename = "unicityCertificate", skip_serializing_if = "Option::is_none", with = "crate::types::hex_serde::option")]
    pub unicity_certificate: Option<Vec<u8>>, // CBOR encoded certificate
}

impl InclusionProof {
    /// Create a new inclusion proof with Java SDK structure
    pub fn new(merkle_tree_path: MerkleTreePath) -> Self {
        Self {
            merkle_tree_path,
            authenticator: None,
            transaction_hash: None,
            unicity_certificate: None,
        }
    }

    /// Create with certificate
    pub fn with_certificate(merkle_tree_path: MerkleTreePath, certificate: Vec<u8>) -> Self {
        Self {
            merkle_tree_path,
            authenticator: None,
            transaction_hash: None,
            unicity_certificate: Some(certificate),
        }
    }

    /// Create with authenticator
    pub fn with_authenticator(merkle_tree_path: MerkleTreePath, authenticator: Authenticator) -> Self {
        Self {
            merkle_tree_path,
            authenticator: Some(authenticator),
            transaction_hash: None,
            unicity_certificate: None,
        }
    }

    /// Validate the inclusion proof
    pub fn validate(&self) -> Result<()> {
        // Basic validation - ensure path is not empty for non-genesis
        if self.merkle_tree_path.steps.is_empty() {
            return Err(SdkError::Validation(
                "Merkle tree path steps cannot be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Verify the inclusion proof against a trust base
    pub fn verify_with_trust_base(&self, _request_id: &crate::types::primitives::RequestId, trust_base: &crate::types::bft::RootTrustBase) -> Result<bool> {
        // Parse root hash from hex string
        let root_bytes = hex::decode(&self.merkle_tree_path.root)
            .map_err(|e| SdkError::Serialization(format!("Invalid root hash hex: {}", e)))?;

        // Verify the root hash against trust base
        if !trust_base.verify_root_hash(&root_bytes)? {
            return Ok(false);
        }

        // If certificate is present, verify it
        if let Some(cert_data) = &self.unicity_certificate {
            let cert = crate::types::bft::UnicityCertificate::from_cbor(cert_data)?;
            if !cert.verify(trust_base)? {
                return Ok(false);
            }
        }

        // TODO: Verify merkle path
        // For now, return true if basic checks pass
        Ok(true)
    }

    /// Get the root hash as DataHash
    pub fn root_hash(&self) -> Result<DataHash> {
        let root_bytes = hex::decode(&self.merkle_tree_path.root)
            .map_err(|e| SdkError::Serialization(format!("Invalid root hash hex: {}", e)))?;
        DataHash::from_imprint(&root_bytes)
    }
}

/// Path element for Merkle tree inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathElement {
    pub direction: PathDirection,
    pub hash: DataHash,
}

impl PathElement {
    /// Create a new path element
    pub fn new(direction: PathDirection, hash: DataHash) -> Self {
        Self { direction, hash }
    }
}

/// Direction in Merkle tree path
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathDirection {
    Left,
    Right,
}

/// Mint transaction data for token creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintTransactionData {
    #[serde(rename = "tokenId")]
    pub token_id: TokenId,
    #[serde(rename = "tokenType")]
    pub token_type: TokenType,
    #[serde(default, rename = "tokenData", skip_serializing_if = "Option::is_none", with = "crate::types::hex_serde::option")]
    pub token_data: Option<Vec<u8>>,
    #[serde(default, rename = "coinData", skip_serializing_if = "Option::is_none")]
    pub coin_data: Option<crate::types::token::TokenCoinData>,
    pub recipient: crate::types::address::GenericAddress,
    #[serde(with = "crate::types::hex_serde")]
    pub salt: Vec<u8>,
    #[serde(default, rename = "recipientDataHash", skip_serializing_if = "Option::is_none")]
    pub recipient_data_hash: Option<DataHash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<SplitMintReason>,
}

impl TransactionDataTrait for MintTransactionData {
    fn get_recipient_data_hash(&self) -> Option<&DataHash> {
        self.recipient_data_hash.as_ref()
    }

    fn get_recipient(&self) -> &crate::types::address::GenericAddress {
        &self.recipient
    }
}

impl MintTransactionData {
    /// Create new mint transaction data
    pub fn new(
        token_id: TokenId,
        token_type: TokenType,
        token_data: Option<Vec<u8>>,
        coin_data: Option<crate::types::token::TokenCoinData>,
        recipient: crate::types::address::GenericAddress,
        salt: Vec<u8>,
        recipient_data_hash: Option<DataHash>,
        reason: Option<SplitMintReason>,
    ) -> Self {
        Self {
            token_id,
            token_type,
            token_data,
            coin_data,
            recipient,
            salt,
            recipient_data_hash,
            reason,
        }
    }

    /// Compute the hash of the mint data using CBOR like Java
    pub fn hash(&self) -> Result<DataHash> {
        use sha2::{Digest, Sha256};
        use ciborium::Value;

        // Create CBOR array with 8 elements matching Java SDK's toCbor():
        // [tokenId, tokenType, tokenData, coinData, recipient, salt, recipientDataHash, reason]
        let cbor_array = vec![
            // 0. tokenId as bytes
            Value::Bytes(self.token_id.as_bytes().to_vec()),

            // 1. tokenType as bytes
            Value::Bytes(self.token_type.as_bytes().to_vec()),

            // 2. tokenData - the data itself (not hashed), optional byte string
            if let Some(ref data) = self.token_data {
                Value::Bytes(data.clone())
            } else {
                Value::Null
            },

            // 3. coinData - CBOR representation if present
            if let Some(ref coin_data) = self.coin_data {
                coin_data.to_cbor_value()?
            } else {
                Value::Null
            },

            // 4. recipient address - text string matching Java SDK getAddress()
            Value::Text(self.recipient.get_address()),

            // 5. salt as bytes
            Value::Bytes(self.salt.clone()),

            // 6. recipientDataHash - DataHash imprint (34 bytes) if present
            if let Some(ref hash) = self.recipient_data_hash {
                Value::Bytes(hash.imprint())
            } else {
                Value::Null
            },

            // 7. reason - split mint reason CBOR if present
            if let Some(ref reason) = self.reason {
                Value::Bytes(reason.hash()?.imprint())
            } else {
                Value::Null
            },
        ];

        // Serialize the CBOR array
        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&Value::Array(cbor_array), &mut cbor_bytes)
            .map_err(|e| SdkError::Serialization(format!("CBOR serialization failed: {}", e)))?;

        // Hash the CBOR bytes
        let mut hasher = Sha256::new();
        hasher.update(&cbor_bytes);
        Ok(DataHash::sha256(hasher.finalize().to_vec()))
    }
}

/// Transfer transaction data for token transfers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferTransactionData {
    #[serde(rename = "sourceState")]
    pub source_state: TokenState,
    pub recipient: crate::types::address::GenericAddress,
    #[serde(with = "crate::types::hex_serde")]
    pub salt: Vec<u8>,
    #[serde(default, rename = "recipientDataHash", skip_serializing_if = "Option::is_none")]
    pub recipient_data_hash: Option<DataHash>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::types::hex_serde::option")]
    pub message: Option<Vec<u8>>,
    #[serde(default)]
    pub nametags: Vec<crate::types::token::Token<NametagMintTransactionData>>,
}

impl TransactionDataTrait for TransferTransactionData {
    fn get_recipient_data_hash(&self) -> Option<&DataHash> {
        self.recipient_data_hash.as_ref()
    }

    fn get_recipient(&self) -> &crate::types::address::GenericAddress {
        &self.recipient
    }
}

impl TransferTransactionData {
    /// Create new transfer transaction data
    pub fn new(
        source_state: TokenState,
        recipient: crate::types::address::GenericAddress,
        salt: Vec<u8>,
        recipient_data_hash: Option<DataHash>,
        message: Option<Vec<u8>>,
        nametags: Vec<crate::types::token::Token<NametagMintTransactionData>>,
    ) -> Self {
        Self {
            source_state,
            recipient,
            salt,
            recipient_data_hash,
            message,
            nametags,
        }
    }

    /// Get nametags for this transfer
    pub fn get_nametags(&self) -> &[crate::types::token::Token<NametagMintTransactionData>] {
        &self.nametags
    }

    /// Get nonce revelation for MaskedPredicate verification
    /// Returns the message field which may contain the nonce
    pub fn get_nonce_revelation(&self) -> Option<&[u8]> {
        self.message.as_deref()
    }

    /// Compute the hash of the transfer data
    pub fn hash(&self) -> Result<DataHash> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        // Hash source state
        hasher.update(&self.source_state.hash()?.imprint());

        // Hash recipient
        hasher.update(self.recipient.hash().imprint());

        // Hash salt
        hasher.update(&self.salt);

        Ok(DataHash::sha256(hasher.finalize().to_vec()))
    }
}

/// Nametag mint transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NametagMintTransactionData {
    pub nametag: String,
    pub target_state: TokenState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<crate::types::address::GenericAddress>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "recipientDataHash")]
    pub recipient_data_hash: Option<DataHash>,
}

impl TransactionDataTrait for NametagMintTransactionData {
    fn get_recipient_data_hash(&self) -> Option<&DataHash> {
        self.recipient_data_hash.as_ref()
    }

    fn get_recipient(&self) -> &crate::types::address::GenericAddress {
        // For nametags, derive address from target state if not explicitly set
        // This is a placeholder - in practice, nametags might not have explicit recipients
        self.recipient.as_ref().unwrap_or_else(|| {
            // Return a dummy address - this shouldn't be called in normal operation
            static DUMMY: std::sync::OnceLock<crate::types::address::GenericAddress> = std::sync::OnceLock::new();
            DUMMY.get_or_init(|| {
                crate::types::address::GenericAddress::Direct(
                    crate::types::address::DirectAddress::new(DataHash::sha256(vec![0]))
                )
            })
        })
    }
}

impl NametagMintTransactionData {
    /// Create new nametag mint data
    pub fn new(nametag: String, target_state: TokenState) -> Self {
        Self {
            nametag,
            target_state,
            recipient: None,
            recipient_data_hash: None,
        }
    }

    /// Compute the hash
    pub fn hash(&self) -> Result<DataHash> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.nametag.as_bytes());
        hasher.update(&self.target_state.hash()?.imprint());
        Ok(DataHash::sha256(hasher.finalize().to_vec()))
    }
}

/// Split mint reason for token splitting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitMintReason {
    pub source_token_id: TokenId,
    pub coin_type: String,
    pub aggregation_tree_root: DataHash,
    pub inclusion_path: Vec<PathElement>,
}

impl SplitMintReason {
    /// Create new split mint reason
    pub fn new(
        source_token_id: TokenId,
        coin_type: String,
        aggregation_tree_root: DataHash,
        inclusion_path: Vec<PathElement>,
    ) -> Self {
        Self {
            source_token_id,
            coin_type,
            aggregation_tree_root,
            inclusion_path,
        }
    }

    /// Compute the hash
    pub fn hash(&self) -> Result<DataHash> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.source_token_id.as_bytes());
        hasher.update(self.coin_type.as_bytes());
        hasher.update(&self.aggregation_tree_root.imprint());
        for element in &self.inclusion_path {
            hasher.update(&[element.direction as u8]);
            hasher.update(&element.hash.imprint());
        }
        Ok(DataHash::sha256(hasher.finalize().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::predicate::UnmaskedPredicate;

    #[test]
    fn test_inclusion_proof() {
        let merkle_tree_path = MerkleTreePath {
            root: hex::encode(vec![1, 2, 3]),
            steps: vec![
                MerkleTreePathStep {
                    path: serde_json::Value::Number(serde_json::Number::from(0)),
                    sibling: vec![hex::encode(vec![4, 5, 6])],
                    branch: vec![Some(hex::encode(vec![7, 8, 9]))],
                }
            ],
        };
        let proof = InclusionProof::new(merkle_tree_path);

        assert!(!proof.merkle_tree_path.steps.is_empty());
        assert!(proof.validate().is_ok());
    }

    #[test]
    fn test_mint_transaction_data() {
        use crate::crypto::keys::KeyPair;
        use crate::types::address::{GenericAddress, DirectAddress};

        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let predicate = UnmaskedPredicate::new(public_key);
        let state = TokenState::from_predicate(&predicate, None).unwrap();

        // Create recipient address from state hash
        let recipient = GenericAddress::Direct(DirectAddress::new(state.hash().unwrap()));

        let token_id = TokenId::new([1u8; 32]);
        let mint_data = MintTransactionData::new(
            token_id,
            TokenType::new(vec![1, 2, 3]),
            Some(vec![4, 5, 6]),  // token_data
            None,                 // coin_data
            recipient,            // recipient
            vec![7, 8, 9],        // salt
            None,                 // recipient_data_hash
            None,                 // reason
        );

        assert!(mint_data.hash().is_ok());
    }

    #[test]
    fn test_transfer_transaction_data() {
        use crate::crypto::keys::KeyPair;
        use crate::types::address::{GenericAddress, DirectAddress};

        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let predicate = UnmaskedPredicate::new(public_key);
        let source_state = TokenState::from_predicate(&predicate, None).unwrap();
        let target_state = TokenState::from_predicate(&predicate, Some(vec![1, 2, 3])).unwrap();

        // Create recipient address from target state hash
        let recipient = GenericAddress::Direct(DirectAddress::new(target_state.hash().unwrap()));

        let transfer_data = TransferTransactionData::new(
            source_state,
            recipient,
            vec![7, 8, 9],  // salt
            None,           // recipient_data_hash
            None,           // message
            vec![],         // nametags
        );

        assert!(transfer_data.hash().is_ok());
    }
}
