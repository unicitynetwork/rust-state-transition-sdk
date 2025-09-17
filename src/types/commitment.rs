use crate::error::{Result, SdkError};
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
    pub algorithm: String,      // "secp256k1"
    pub public_key: PublicKey,
    pub signature: Signature,
    pub state_hash: DataHash,   // The state hash that was signed
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
        use secp256k1::{Message, Secp256k1};

        let secp = Secp256k1::new();
        let message = Message::from_digest(data.try_into().map_err(|_| SdkError::Crypto("Data must be 32 bytes".to_string()))?);

        let recovery_id = secp256k1::ecdsa::RecoveryId::from_u8_masked(self.signature.recovery_id());

        let recoverable_sig = secp256k1::ecdsa::RecoverableSignature::from_compact(
            &self.signature.as_bytes()[..64],
            recovery_id,
        )?;

        let recovered_key = secp.recover_ecdsa(message, &recoverable_sig)?;
        let expected_key = self.public_key.to_secp256k1()?;

        Ok(recovered_key == expected_key)
    }
}

/// Mint commitment for token creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintCommitment {
    pub mint_data: MintTransactionData,
    pub request_id: RequestId,
    pub transaction_hash: DataHash,  // Changed from state_hash
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

    /// Create and sign a mint commitment
    pub fn create(
        mint_data: MintTransactionData,
        signing_key: &secp256k1::SecretKey,
    ) -> Result<Self> {
        use secp256k1::{Message, Secp256k1};

        let secp = Secp256k1::new();
        let public_key_secp = secp256k1::PublicKey::from_secret_key(&secp, signing_key);
        let public_key_bytes = public_key_secp.serialize();
        let public_key = PublicKey::new(public_key_bytes)?;

        // Calculate state hash (for MintCommitment, it's the hash of target state)
        let state_hash = mint_data.target_state.hash()?;

        // Calculate transaction hash
        let transaction_hash = mint_data.hash()?;

        // Calculate request ID
        let request_id = RequestId::new(&public_key, &state_hash);

        // Sign the state hash (not the transaction hash!)
        let message = Message::from_digest(state_hash.data().try_into().map_err(|_| SdkError::Crypto("State hash must be 32 bytes".to_string()))?);
        let recoverable_sig = secp.sign_ecdsa_recoverable(message, signing_key);
        let (recovery_id, sig_bytes) = recoverable_sig.serialize_compact();

        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(&sig_bytes);
        signature_bytes[64] = recovery_id as u8;
        let signature = Signature::new(signature_bytes);

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
        serde_json::to_value(&self.mint_data)
            .map_err(|e| SdkError::Serialization(e.to_string()))
    }
}

/// Transfer commitment for token transfers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferCommitment {
    pub transfer_data: TransferTransactionData,
    pub source_token_id: TokenId,
    pub request_id: RequestId,
    pub transaction_hash: DataHash,  // Changed from state_hash
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
        signing_key: &secp256k1::SecretKey,
    ) -> Result<Self>
    where
        T: Clone + Serialize + for<'de> Deserialize<'de>,
    {
        use secp256k1::{Message, Secp256k1};

        let secp = Secp256k1::new();
        let public_key_secp = secp256k1::PublicKey::from_secret_key(&secp, signing_key);
        let public_key_bytes = public_key_secp.serialize();
        let public_key = PublicKey::new(public_key_bytes)?;

        let transfer_data = TransferTransactionData::new(
            token.state.clone(),
            target_state.clone(),
            salt,
        );

        // For transfer, state hash is the hash of the target state
        let state_hash = target_state.hash()?;

        // Calculate transaction hash
        let transaction_hash = transfer_data.hash()?;

        let request_id = RequestId::new(&public_key, &state_hash);
        let source_token_id = token.id()?;

        // Sign the state hash (not the transaction hash!)
        let message = Message::from_digest(state_hash.data().try_into().map_err(|_| SdkError::Crypto("State hash must be 32 bytes".to_string()))?);
        let recoverable_sig = secp.sign_ecdsa_recoverable(message, signing_key);
        let (recovery_id, sig_bytes) = recoverable_sig.serialize_compact();

        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(&sig_bytes);
        signature_bytes[64] = recovery_id as u8;
        let signature = Signature::new(signature_bytes);

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
    use crate::types::predicate::UnmaskedPredicate;
    use crate::types::token::{TokenState, TokenType};
    use crate::crypto::keys::KeyPair;

    #[test]
    fn test_mint_commitment_creation() {
        use secp256k1::Secp256k1;
        use secp256k1::rand;

        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut rand::rng());

        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let predicate = UnmaskedPredicate::new(public_key);
        let target_state = TokenState::from_predicate(&predicate, None).unwrap();

        let mint_data = MintTransactionData::new(
            TokenType::new(vec![1, 2, 3]),
            target_state,
            Some(vec![4, 5, 6]),
            None,
        );

        let commitment = MintCommitment::create(mint_data, &secret_key).unwrap();
        assert_eq!(commitment.commitment_type(), CommitmentType::Mint);
        assert_eq!(commitment.authenticator.algorithm, "secp256k1");
        assert!(commitment.authenticator.verify(commitment.authenticator.state_hash.data()).unwrap());
    }

    #[test]
    fn test_authenticator_verification() {
        use secp256k1::{Message, Secp256k1};
        use secp256k1::rand;
        use sha2::Digest;

        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut rand::rng());
        let public_key_secp = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let public_key = PublicKey::new(public_key_secp.serialize()).unwrap();

        let data = b"test data";
        let hash = sha2::Sha256::digest(data);
        let state_hash = DataHash::sha256(hash.to_vec());
        let message = Message::from_digest(hash.into());
        let recoverable_sig = secp.sign_ecdsa_recoverable(message, &secret_key);
        let (recovery_id, sig_bytes) = recoverable_sig.serialize_compact();

        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(&sig_bytes);
        signature_bytes[64] = recovery_id as u8;
        let signature = Signature::new(signature_bytes);

        let authenticator = Authenticator::new(public_key, signature, state_hash.clone());
        assert_eq!(authenticator.algorithm, "secp256k1");
        assert!(authenticator.verify(&hash).unwrap());
    }
}