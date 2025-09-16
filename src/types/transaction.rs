use crate::error::{Result, SdkError};
use crate::types::primitives::DataHash;
use crate::types::token::{TokenId, TokenState, TokenType};
use serde::{Deserialize, Serialize};

/// Generic transaction wrapper with data and inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction<T> {
    pub data: T,
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
        let serialized = serde_json::to_vec(&self.data)
            .map_err(|e| SdkError::Serialization(e.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        Ok(DataHash::sha256(hasher.finalize().to_vec()))
    }

    /// Validate the transaction
    pub fn validate(&self) -> Result<()> {
        self.inclusion_proof.validate()
    }
}

/// Inclusion proof for transaction verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub block_height: u64,
    pub path: Vec<PathElement>,
    pub root: DataHash,
}

impl InclusionProof {
    /// Create a new inclusion proof
    pub fn new(block_height: u64, path: Vec<PathElement>, root: DataHash) -> Self {
        Self {
            block_height,
            path,
            root,
        }
    }

    /// Validate the inclusion proof
    pub fn validate(&self) -> Result<()> {
        // Basic validation - ensure path is not empty for non-genesis
        if self.block_height > 0 && self.path.is_empty() {
            return Err(SdkError::Validation(
                "Inclusion proof path cannot be empty for non-genesis block".to_string(),
            ));
        }
        Ok(())
    }

    /// Verify the proof for a given leaf
    pub fn verify(&self, leaf: &DataHash) -> Result<bool> {
        let computed_root = self.compute_root(leaf)?;
        Ok(computed_root == self.root)
    }

    /// Compute the root from a leaf using the path
    fn compute_root(&self, leaf: &DataHash) -> Result<DataHash> {
        use sha2::{Digest, Sha256};

        let mut current = leaf.clone();

        for element in &self.path {
            let mut hasher = Sha256::new();

            match element.direction {
                PathDirection::Left => {
                    hasher.update(&element.hash.imprint());
                    hasher.update(&current.imprint());
                }
                PathDirection::Right => {
                    hasher.update(&current.imprint());
                    hasher.update(&element.hash.imprint());
                }
            }

            current = DataHash::sha256(hasher.finalize().to_vec());
        }

        Ok(current)
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
    pub token_type: TokenType,
    pub target_state: TokenState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split_mint_reason: Option<SplitMintReason>,
}

impl MintTransactionData {
    /// Create new mint transaction data
    pub fn new(
        token_type: TokenType,
        target_state: TokenState,
        data: Option<Vec<u8>>,
        split_mint_reason: Option<SplitMintReason>,
    ) -> Self {
        Self {
            token_type,
            target_state,
            data,
            split_mint_reason,
        }
    }

    /// Compute the hash of the mint data
    pub fn hash(&self) -> Result<DataHash> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        // Hash token type
        hasher.update(self.token_type.as_bytes());

        // Hash target state
        hasher.update(&self.target_state.hash()?.imprint());

        // Hash optional data
        if let Some(ref data) = self.data {
            hasher.update(&[1u8]);
            hasher.update(data);
        } else {
            hasher.update(&[0u8]);
        }

        // Hash split mint reason if present
        if let Some(ref reason) = self.split_mint_reason {
            hasher.update(&[1u8]);
            hasher.update(&reason.hash()?.imprint());
        } else {
            hasher.update(&[0u8]);
        }

        Ok(DataHash::sha256(hasher.finalize().to_vec()))
    }
}

/// Transfer transaction data for token transfers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferTransactionData {
    pub source_state: TokenState,
    pub target_state: TokenState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<Vec<u8>>,
}

impl TransferTransactionData {
    /// Create new transfer transaction data
    pub fn new(
        source_state: TokenState,
        target_state: TokenState,
        salt: Option<Vec<u8>>,
    ) -> Self {
        Self {
            source_state,
            target_state,
            salt,
        }
    }

    /// Compute the hash of the transfer data
    pub fn hash(&self) -> Result<DataHash> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        // Hash source state
        hasher.update(&self.source_state.hash()?.imprint());

        // Hash target state
        hasher.update(&self.target_state.hash()?.imprint());

        // Hash optional salt
        if let Some(ref salt) = self.salt {
            hasher.update(&[1u8]);
            hasher.update(salt);
        } else {
            hasher.update(&[0u8]);
        }

        Ok(DataHash::sha256(hasher.finalize().to_vec()))
    }
}

/// Nametag mint transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NametagMintTransactionData {
    pub nametag: String,
    pub target_state: TokenState,
}

impl NametagMintTransactionData {
    /// Create new nametag mint data
    pub fn new(nametag: String, target_state: TokenState) -> Self {
        Self {
            nametag,
            target_state,
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
    use crate::types::primitives::PublicKey;

    #[test]
    fn test_inclusion_proof() {
        let root = DataHash::sha256(vec![1, 2, 3]);
        let path = vec![
            PathElement::new(PathDirection::Left, DataHash::sha256(vec![4, 5, 6])),
            PathElement::new(PathDirection::Right, DataHash::sha256(vec![7, 8, 9])),
        ];
        let proof = InclusionProof::new(100, path, root);

        assert_eq!(proof.block_height, 100);
        assert!(proof.validate().is_ok());
    }

    #[test]
    fn test_mint_transaction_data() {
        let key_bytes = [3u8; 33];
        let public_key = PublicKey::new(key_bytes).unwrap();
        let predicate = UnmaskedPredicate::new(public_key);
        let state = TokenState::from_predicate(&predicate, None).unwrap();

        let mint_data = MintTransactionData::new(
            TokenType::new(vec![1, 2, 3]),
            state,
            Some(vec![4, 5, 6]),
            None,
        );

        assert!(mint_data.hash().is_ok());
    }

    #[test]
    fn test_transfer_transaction_data() {
        let key_bytes = [3u8; 33];
        let public_key = PublicKey::new(key_bytes).unwrap();
        let predicate = UnmaskedPredicate::new(public_key);
        let source_state = TokenState::from_predicate(&predicate, None).unwrap();
        let target_state = TokenState::from_predicate(&predicate, Some(vec![1, 2, 3])).unwrap();

        let transfer_data = TransferTransactionData::new(
            source_state,
            target_state,
            Some(vec![7, 8, 9]),
        );

        assert!(transfer_data.hash().is_ok());
    }
}