use crate::error::{Result, SdkError};
use crate::prelude::*;
use crate::types::primitives::{DataHash, PublicKey, RequestId, Signature};
use crate::types::token::{Token, TokenId};
use crate::types::transaction::{
    InclusionProof, MintTransactionData, Transaction, TransferTransactionData,
};
use serde::{Deserialize, Serialize};

/// Base trait for commitments
pub trait Commitment: Send + Sync {
    /// Get the commitment type
    fn commitment_type(&self) -> CommitmentType;

    /// Get the request ID
    fn request_id(&self) -> &RequestId;

    /// Get the transaction hash (hash of transaction data)
    fn transaction_hash(&self) -> &DataHash;

    /// Get the authenticator
    fn authenticator(&self) -> &Authenticator;

    /// Serialize to JSON for transaction purposes
    fn serialize_for_transaction(&self) -> Result<serde_json::Value>;
}

/// Commitment type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommitmentType {
    Mint,
    Transfer,
}

/// Authenticator for commitment validation
/// This matches the Java SDK structure exactly
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authenticator {
    pub algorithm: String, // "secp256k1"
    pub public_key: PublicKey,
    pub signature: Signature,
    pub state_hash: DataHash, // The state hash that was signed
}

impl Authenticator {
    /// Create a new authenticator
    pub fn new(public_key: PublicKey, signature: Signature, state_hash: DataHash) -> Self {
        Self {
            algorithm: "secp256k1".to_string(),
            public_key,
            signature,
            state_hash,
        }
    }

    /// Verify the authenticator against data
    pub fn verify(&self, data: &[u8]) -> Result<bool> {
        use crate::crypto::SigningService;

        let signing_service = SigningService::new();

        // Recover the public key from the signature
        let recovered_key = signing_service.recover_public_key(data, &self.signature)?;

        // Check if the recovered key matches the expected public key
        Ok(recovered_key == self.public_key)
    }
}

/// Mint commitment for token creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintCommitment {
    pub mint_data: MintTransactionData,
    pub request_id: RequestId,
    pub transaction_hash: DataHash, // Changed from state_hash
    pub authenticator: Authenticator,
}

impl MintCommitment {
    /// Create a new mint commitment
    pub fn new(
        mint_data: MintTransactionData,
        public_key: PublicKey,
        signature: Signature,
        state_hash: DataHash,
    ) -> Result<Self> {
        let transaction_hash = mint_data.hash()?;
        let request_id = RequestId::new(&public_key, &state_hash);
        let authenticator = Authenticator::new(public_key, signature, state_hash);

        Ok(Self {
            mint_data,
            request_id,
            transaction_hash,
            authenticator,
        })
    }

    /// Create and sign a mint commitment using the universal minter
    pub fn create(mint_data: MintTransactionData) -> Result<Self> {
        use crate::minter::UniversalMinter;
        use crate::crypto::{SigningService, public_key_from_secret};

        // Use the universal minter to get the signing key for this token
        let signing_key = UniversalMinter::create_signing_key(mint_data.token_id.as_bytes())?;

        // Get public key from signing key
        let public_key = public_key_from_secret(&signing_key)?;

        // For mint, the state hash is derived from the token ID + MINT_SUFFIX
        // This matches Java's MintTransactionState.create(tokenId).getHash()
        // MINT_SUFFIX is a fixed constant used in Java
        const MINT_SUFFIX: &str = "9e82002c144d7c5796c50f6db50a0c7bbd7f717ae3af6c6c71a3e9eba3022730";
        let mint_suffix = hex::decode(MINT_SUFFIX)
            .map_err(|e| SdkError::Crypto(format!("Invalid mint suffix: {}", e)))?;

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(mint_data.token_id.as_bytes());
        hasher.update(&mint_suffix);
        let state_hash = DataHash::sha256(hasher.finalize().to_vec());

        // Calculate transaction hash
        let transaction_hash = mint_data.hash()?;

        // Calculate request ID
        let request_id = RequestId::new(&public_key, &state_hash);

        // Sign the transaction hash (not the state hash!)
        // The authenticator signs the transaction data, while state hash is stored for reference
        let signing_service = SigningService::new();
        let signature = signing_service.sign(transaction_hash.data(), &signing_key)?;

        let authenticator = Authenticator::new(public_key, signature, state_hash.clone());

        Ok(Self {
            mint_data,
            request_id,
            transaction_hash,
            authenticator,
        })
    }

    /// Convert to transaction with inclusion proof
    pub fn to_transaction(&self, proof: InclusionProof) -> Transaction<MintTransactionData> {
        Transaction::new(self.mint_data.clone(), proof)
    }
}

impl Commitment for MintCommitment {
    fn commitment_type(&self) -> CommitmentType {
        CommitmentType::Mint
    }

    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn transaction_hash(&self) -> &DataHash {
        &self.transaction_hash
    }

    fn authenticator(&self) -> &Authenticator {
        &self.authenticator
    }

    fn serialize_for_transaction(&self) -> Result<serde_json::Value> {
        serde_json::to_value(&self.mint_data).map_err(|e| SdkError::Serialization(e.to_string()))
    }
}

/// Transfer commitment for token transfers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferCommitment {
    pub transfer_data: TransferTransactionData,
    pub source_token_id: TokenId,
    pub request_id: RequestId,
    pub transaction_hash: DataHash, // Changed from state_hash
    pub authenticator: Authenticator,
}

impl TransferCommitment {
    /// Create a new transfer commitment
    pub fn new(
        transfer_data: TransferTransactionData,
        source_token_id: TokenId,
        public_key: PublicKey,
        signature: Signature,
        state_hash: DataHash,
    ) -> Result<Self> {
        let transaction_hash = transfer_data.hash()?;
        let request_id = RequestId::new(&public_key, &state_hash);
        let authenticator = Authenticator::new(public_key, signature, state_hash);

        Ok(Self {
            transfer_data,
            source_token_id,
            request_id,
            transaction_hash,
            authenticator,
        })
    }

    /// Create and sign a transfer commitment
    pub fn create<T>(
        token: &Token<T>,
        target_state: crate::types::token::TokenState,
        salt: Option<Vec<u8>>,
        signing_key: &k256::ecdsa::SigningKey,
    ) -> Result<Self>
    where
        T: Clone + Serialize + for<'de> Deserialize<'de>,
    {
        use crate::crypto::{SigningService, public_key_from_secret};

        // Get public key from signing key
        let public_key = public_key_from_secret(signing_key)?;

        // Create recipient address from target state (predicate hash only, not including data)
        let address_hash = target_state.address_hash()?;
        let recipient = crate::types::address::GenericAddress::direct(address_hash);

        // Compute recipient_data_hash from target state data (if present)
        let recipient_data_hash = target_state.data_hash();

        // Use provided salt or generate one
        let salt_vec = salt.unwrap_or_else(|| vec![0u8; 8]);

        let transfer_data = TransferTransactionData::new(
            token.state.clone(),
            recipient,
            salt_vec,
            recipient_data_hash,  // SHA256 of target_state.data if present
            None,  // message
            vec![], // nametags
        );

        // For transfer, state hash is the hash of the target state (full hash including data)
        let state_hash = target_state.hash()?;

        // Calculate transaction hash
        let transaction_hash = transfer_data.hash()?;

        let request_id = RequestId::new(&public_key, &state_hash);
        let source_token_id = token.id()?;

        // Sign the transaction hash (not the state hash!)
        // The authenticator signs the transaction data, while state hash is stored for reference
        let signing_service = SigningService::new();
        let signature = signing_service.sign(transaction_hash.data(), &signing_key)?;

        let authenticator = Authenticator::new(public_key, signature, state_hash.clone());

        Ok(Self {
            transfer_data,
            source_token_id,
            request_id,
            transaction_hash,
            authenticator,
        })
    }

    /// Convert to transaction with inclusion proof
    pub fn to_transaction(&self, proof: InclusionProof) -> Transaction<TransferTransactionData> {
        Transaction::new(self.transfer_data.clone(), proof)
    }
}

impl Commitment for TransferCommitment {
    fn commitment_type(&self) -> CommitmentType {
        CommitmentType::Transfer
    }

    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn transaction_hash(&self) -> &DataHash {
        &self.transaction_hash
    }

    fn authenticator(&self) -> &Authenticator {
        &self.authenticator
    }

    fn serialize_for_transaction(&self) -> Result<serde_json::Value> {
        serde_json::to_value(&self.transfer_data)
            .map_err(|e| SdkError::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyPair;
    use crate::types::predicate::UnmaskedPredicate;
    use crate::types::token::{TokenState, TokenType};

    #[test]
    fn test_mint_commitment_creation() {
        use crate::types::token::TokenId;

        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let predicate = UnmaskedPredicate::new(public_key);
        let target_state = TokenState::from_predicate(&predicate, None).unwrap();

        // Create recipient address from target state (predicate hash only, not including data)
        let address_hash = target_state.address_hash().unwrap();
        let recipient = crate::types::address::GenericAddress::direct(address_hash);

        let token_id = TokenId::new([1u8; 32]);
        let mint_data = MintTransactionData::new(
            token_id,
            TokenType::new(vec![1, 2, 3]),
            Some(vec![4, 5, 6]),  // token_data
            None,  // coin_data
            recipient,
            vec![7, 8, 9],  // salt
            None,  // recipient_data_hash
            None,  // reason
        );

        // MintCommitment::create uses universal minter, no secret key needed
        let commitment = MintCommitment::create(mint_data).unwrap();
        assert_eq!(commitment.commitment_type(), CommitmentType::Mint);
        assert_eq!(commitment.authenticator.algorithm, "secp256k1");
        // Verify signature is against transaction hash, not state hash
        assert!(commitment
            .authenticator
            .verify(commitment.transaction_hash.data())
            .unwrap());
    }

    #[test]
    fn test_authenticator_verification() {
        use crate::crypto::{SigningService, generate_secret_key, public_key_from_secret};
        use sha2::Digest;

        let secret_key = generate_secret_key();
        let public_key = public_key_from_secret(&secret_key).unwrap();

        let data = b"test data";
        let hash = sha2::Sha256::digest(data);
        let state_hash = DataHash::sha256(hash.to_vec());

        let signing_service = SigningService::new();
        let signature = signing_service.sign(&hash, &secret_key).unwrap();

        let authenticator = Authenticator::new(public_key, signature, state_hash.clone());
        assert_eq!(authenticator.algorithm, "secp256k1");
        assert!(authenticator.verify(&hash).unwrap());
    }
}
