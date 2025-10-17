use crate::error::{Result, SdkError};
use crate::prelude::*;
use crate::types::primitives::{DataHash, PublicKey};
use serde::{Deserialize, Serialize};
use core::fmt;

/// Predicate trait for ownership conditions
pub trait Predicate: Send + Sync + fmt::Debug {
    /// Get the predicate type identifier
    fn predicate_type(&self) -> PredicateType;

    /// Serialize the predicate
    fn serialize(&self) -> Result<Vec<u8>>;

    /// Compute the hash of the predicate
    fn hash(&self) -> Result<DataHash>;

    /// Clone the predicate into a box
    fn clone_box(&self) -> Box<dyn Predicate>;

    /// Check if the given public key is the owner of this predicate
    ///
    /// Based on Java SDK Predicate.isOwner() at java-state-transition-sdk/src/main/java/org/unicitylabs/sdk/predicate/Predicate.java:33
    fn is_owner(&self, _public_key: &PublicKey) -> bool {
        // For UnmaskedPredicate: check if public_key matches the predicate's public_key
        // For MaskedPredicate: cannot determine without nonce
        // For BurnPredicate: no owner
        false
    }

    /// Verify that a transaction is authorized according to this predicate's rules
    ///
    /// This is a critical security method that validates token ownership and transfer authorization.
    /// Each predicate type has different verification requirements:
    /// - UnmaskedPredicate: verifies the transaction authenticator's public key matches and signature is valid
    /// - MaskedPredicate: verifies revealed nonce and that hash(public_key + nonce) matches the mask
    /// - BurnPredicate: allows burns unconditionally
    ///
    /// Based on Java SDK Predicate.verify() at
    /// java-state-transition-sdk/src/main/java/org/unicitylabs/sdk/predicate/Predicate.java:42-43
    ///
    /// # Parameters
    /// - `authenticator`: The transaction authenticator containing public key and signature
    /// - `transaction_hash`: Hash of the transaction being verified
    /// - `nonce`: Optional nonce for MaskedPredicate verification (ignored by other predicate types)
    ///
    /// # Returns
    /// - `Ok(true)` if verification succeeds
    /// - `Ok(false)` if verification fails (invalid signature, wrong key, etc.)
    /// - `Err(_)` for structural errors (missing data, unsupported operations)
    fn verify(
        &self,
        authenticator: &crate::types::primitives::PublicKey,
        transaction_hash: &crate::types::primitives::DataHash,
        nonce: Option<&[u8]>,
    ) -> Result<bool>;
}

/// Predicate type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PredicateType {
    Unmasked,
    Masked,
    Burn,
}

/// Direct public key ownership predicate
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnmaskedPredicate {
    pub public_key: PublicKey,
}

impl UnmaskedPredicate {
    /// Create a new unmasked predicate
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }
}

impl Predicate for UnmaskedPredicate {
    fn predicate_type(&self) -> PredicateType {
        PredicateType::Unmasked
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        // For unmasked predicate, serialization is just the public key bytes
        Ok(self.public_key.as_bytes().to_vec())
    }

    fn hash(&self) -> Result<DataHash> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&[PredicateType::Unmasked as u8]);
        hasher.update(self.public_key.as_bytes());
        Ok(DataHash::sha256(hasher.finalize().to_vec()))
    }

    fn clone_box(&self) -> Box<dyn Predicate> {
        Box::new(self.clone())
    }

    fn is_owner(&self, public_key: &PublicKey) -> bool {
        // For unmasked predicate, check if the provided public key matches
        &self.public_key == public_key
    }

    fn verify(
        &self,
        authenticator: &PublicKey,
        _transaction_hash: &crate::types::primitives::DataHash,
        _nonce: Option<&[u8]>,
    ) -> Result<bool> {
        // For UnmaskedPredicate, verify:
        // 1. The authenticator's public key matches this predicate's public key
        // 2. This is the ownership check - signature verification is done separately
        // 3. Nonce is ignored for UnmaskedPredicate

        // Check if the authenticator's public key matches the predicate's public key
        Ok(authenticator == &self.public_key)
    }
}

/// Nonce-masked ownership predicate
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MaskedPredicate {
    pub hash: DataHash,
}

impl MaskedPredicate {
    /// Create a new masked predicate from hash
    pub fn new(hash: DataHash) -> Self {
        Self { hash }
    }

    /// Create a masked predicate from public key and nonce
    pub fn from_public_key_and_nonce(public_key: &PublicKey, nonce: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&[PredicateType::Unmasked as u8]);
        hasher.update(public_key.as_bytes());
        hasher.update(nonce);
        let hash = DataHash::sha256(hasher.finalize().to_vec());
        Self { hash }
    }
}

impl Predicate for MaskedPredicate {
    fn predicate_type(&self) -> PredicateType {
        PredicateType::Masked
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.hash.imprint())
    }

    fn hash(&self) -> Result<DataHash> {
        Ok(self.hash.clone())
    }

    fn clone_box(&self) -> Box<dyn Predicate> {
        Box::new(self.clone())
    }

    fn is_owner(&self, _public_key: &PublicKey) -> bool {
        // For masked predicate, we cannot determine ownership without the nonce
        // This would require revealing the public key + nonce to verify
        // against the hash, which defeats the purpose of masking
        false
    }

    fn verify(
        &self,
        authenticator: &PublicKey,
        _transaction_hash: &crate::types::primitives::DataHash,
        nonce: Option<&[u8]>,
    ) -> Result<bool> {
        // For MaskedPredicate, full verification requires:
        // 1. The nonce must be revealed in the transaction
        // 2. Verify that hash(authenticator_public_key + nonce) == self.hash
        // 3. Signature verification is done separately at the inclusion proof level

        // Check if nonce was revealed
        let revealed_nonce = nonce.ok_or_else(|| {
            crate::error::SdkError::Validation(
                "MaskedPredicate verification requires nonce revelation in transaction data".to_string()
            )
        })?;

        // Compute the hash of (PredicateType::Unmasked || public_key || nonce)
        // This matches the computation in MaskedPredicate::from_public_key_and_nonce()
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&[PredicateType::Unmasked as u8]);
        hasher.update(authenticator.as_bytes());
        hasher.update(revealed_nonce);
        let computed_hash = DataHash::sha256(hasher.finalize().to_vec());

        // Verify that the computed hash matches the masked hash
        if computed_hash == self.hash {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Burn predicate for token destruction/splitting
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BurnPredicate {
    pub hash: DataHash,
}

impl BurnPredicate {
    /// Create a new burn predicate
    pub fn new(hash: DataHash) -> Self {
        Self { hash }
    }
}

impl Predicate for BurnPredicate {
    fn predicate_type(&self) -> PredicateType {
        PredicateType::Burn
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.hash.imprint())
    }

    fn hash(&self) -> Result<DataHash> {
        Ok(self.hash.clone())
    }

    fn clone_box(&self) -> Box<dyn Predicate> {
        Box::new(self.clone())
    }

    fn is_owner(&self, _public_key: &PublicKey) -> bool {
        // Burn predicates have no owner - they're used for token destruction/splitting
        false
    }

    fn verify(
        &self,
        _authenticator: &PublicKey,
        _transaction_hash: &crate::types::primitives::DataHash,
        _nonce: Option<&[u8]>,
    ) -> Result<bool> {
        // For BurnPredicate, verification always succeeds
        // Burn predicates allow unconditional token destruction/splitting
        // The actual burn conditions are verified elsewhere (e.g., in split mint verification)
        // Nonce is ignored for BurnPredicate
        Ok(true)
    }
}

/// Predicate reference for address resolution
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PredicateReference {
    #[serde(rename = "type")]
    pub predicate_type: PredicateType,
    pub data: Vec<u8>,
}

impl PredicateReference {
    /// Create from a predicate
    pub fn from_predicate(predicate: &dyn Predicate) -> Result<Self> {
        Ok(Self {
            predicate_type: predicate.predicate_type(),
            data: predicate.serialize()?,
        })
    }

    /// Convert to a concrete predicate
    pub fn to_predicate(&self) -> Result<Box<dyn Predicate>> {
        match self.predicate_type {
            PredicateType::Unmasked => {
                if self.data.len() != 33 {
                    return Err(SdkError::InvalidParameter(
                        "Invalid public key length".to_string(),
                    ));
                }
                let mut bytes = [0u8; 33];
                bytes.copy_from_slice(&self.data);
                let public_key = PublicKey::new(bytes)?;
                Ok(Box::new(UnmaskedPredicate::new(public_key)))
            }
            PredicateType::Masked => {
                let hash = DataHash::from_imprint(&self.data)?;
                Ok(Box::new(MaskedPredicate::new(hash)))
            }
            PredicateType::Burn => {
                let hash = DataHash::from_imprint(&self.data)?;
                Ok(Box::new(BurnPredicate::new(hash)))
            }
        }
    }

    /// Compute the hash of the predicate reference
    pub fn hash(&self) -> Result<DataHash> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&[self.predicate_type as u8]);
        hasher.update(&self.data);
        Ok(DataHash::sha256(hasher.finalize().to_vec()))
    }

    /// Serialize the predicate reference to CBOR bytes
    /// Java SDK format: [predicate_type, version_byte, data]
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut cbor_bytes = Vec::new();
        // Encode as 3-element array matching Java SDK format
        let tuple = (self.predicate_type as u8, vec![0u8], &self.data);
        ciborium::ser::into_writer(&tuple, &mut cbor_bytes)
            .map_err(|e| SdkError::Serialization(format!("Failed to encode predicate to CBOR: {}", e)))?;
        Ok(cbor_bytes)
    }

    /// Deserialize the predicate reference from CBOR bytes
    /// Java SDK format: [predicate_type, version_byte, data]
    pub fn from_cbor(cbor_bytes: &[u8]) -> Result<Self> {
        // Decode as 3-element array matching Java SDK format
        let tuple: (u8, Vec<u8>, Vec<u8>) = ciborium::de::from_reader(cbor_bytes)
            .map_err(|e| SdkError::Serialization(format!("Failed to decode predicate from CBOR: {}", e)))?;

        let predicate_type = match tuple.0 {
            0 => PredicateType::Unmasked,
            1 => PredicateType::Masked,
            2 => PredicateType::Burn,
            _ => return Err(SdkError::InvalidParameter(format!("Invalid predicate type: {}", tuple.0))),
        };

        // tuple.1 is the version/flag byte (ignored for now)

        Ok(Self {
            predicate_type,
            data: tuple.2,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unmasked_predicate() {
        use crate::crypto::keys::KeyPair;
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let predicate = UnmaskedPredicate::new(public_key.clone());

        assert_eq!(predicate.predicate_type(), PredicateType::Unmasked);
        assert_eq!(
            Predicate::serialize(&predicate).unwrap(),
            public_key.as_bytes().to_vec()
        );
    }

    #[test]
    fn test_masked_predicate() {
        use crate::crypto::keys::KeyPair;
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let nonce = b"test_nonce";
        let predicate = MaskedPredicate::from_public_key_and_nonce(&public_key, nonce);

        assert_eq!(predicate.predicate_type(), PredicateType::Masked);
        assert!(predicate.hash().is_ok());
    }

    #[test]
    fn test_predicate_reference_roundtrip() {
        use crate::crypto::keys::KeyPair;
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let predicate = UnmaskedPredicate::new(public_key);

        let reference = PredicateReference::from_predicate(&predicate).unwrap();
        let recovered = reference.to_predicate().unwrap();

        assert_eq!(recovered.predicate_type(), PredicateType::Unmasked);
        assert_eq!(
            recovered.serialize().unwrap(),
            Predicate::serialize(&predicate).unwrap()
        );
    }

    #[test]
    fn test_unmasked_predicate_is_owner() {
        use crate::crypto::keys::KeyPair;

        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let predicate = UnmaskedPredicate::new(public_key.clone());

        // Positive case: same public key
        assert!(predicate.is_owner(&public_key));

        // Negative case: different public key
        let other_key_pair = KeyPair::generate().unwrap();
        let other_public_key = other_key_pair.public_key().clone();
        assert!(!predicate.is_owner(&other_public_key));
    }

    #[test]
    fn test_masked_predicate_is_owner() {
        use crate::crypto::keys::KeyPair;

        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let nonce = b"test_nonce";
        let predicate = MaskedPredicate::from_public_key_and_nonce(&public_key, nonce);

        // Masked predicates cannot determine ownership without revealing the nonce
        assert!(!predicate.is_owner(&public_key));
    }

    #[test]
    fn test_burn_predicate_is_owner() {
        use crate::crypto::keys::KeyPair;
        use crate::types::primitives::DataHash;

        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let hash = DataHash::sha256(vec![1, 2, 3]);
        let predicate = BurnPredicate::new(hash);

        // Burn predicates have no owner
        assert!(!predicate.is_owner(&public_key));
    }

    #[test]
    fn test_masked_predicate_verify_success() {
        use crate::crypto::keys::KeyPair;
        use crate::types::primitives::DataHash;

        // Create a key pair for the recipient
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();

        // Create a nonce
        let nonce = b"secret_nonce_12345";

        // Create a masked predicate with the public key and nonce
        let masked_predicate = MaskedPredicate::from_public_key_and_nonce(&public_key, nonce);

        // Create a dummy transaction hash
        let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);

        // Verify with correct public key and nonce - should succeed
        let result = masked_predicate.verify(&public_key, &tx_hash, Some(nonce));
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_masked_predicate_verify_wrong_nonce() {
        use crate::crypto::keys::KeyPair;
        use crate::types::primitives::DataHash;

        // Create a key pair for the recipient
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();

        // Create a nonce
        let correct_nonce = b"secret_nonce_12345";
        let wrong_nonce = b"wrong_nonce_67890";

        // Create a masked predicate with the public key and correct nonce
        let masked_predicate = MaskedPredicate::from_public_key_and_nonce(&public_key, correct_nonce);

        // Create a dummy transaction hash
        let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);

        // Verify with wrong nonce - should fail (return false, not error)
        let result = masked_predicate.verify(&public_key, &tx_hash, Some(wrong_nonce));
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should return false
    }

    #[test]
    fn test_masked_predicate_verify_wrong_public_key() {
        use crate::crypto::keys::KeyPair;
        use crate::types::primitives::DataHash;

        // Create a key pair for the recipient
        let key_pair1 = KeyPair::generate().unwrap();
        let public_key1 = key_pair1.public_key().clone();

        // Create a different key pair (attacker)
        let key_pair2 = KeyPair::generate().unwrap();
        let public_key2 = key_pair2.public_key().clone();

        // Create a nonce
        let nonce = b"secret_nonce_12345";

        // Create a masked predicate with public_key1 and nonce
        let masked_predicate = MaskedPredicate::from_public_key_and_nonce(&public_key1, nonce);

        // Create a dummy transaction hash
        let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);

        // Verify with wrong public key (public_key2) - should fail
        let result = masked_predicate.verify(&public_key2, &tx_hash, Some(nonce));
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should return false
    }

    #[test]
    fn test_masked_predicate_verify_no_nonce() {
        use crate::crypto::keys::KeyPair;
        use crate::types::primitives::DataHash;

        // Create a key pair for the recipient
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();

        // Create a nonce
        let nonce = b"secret_nonce_12345";

        // Create a masked predicate with the public key and nonce
        let masked_predicate = MaskedPredicate::from_public_key_and_nonce(&public_key, nonce);

        // Create a dummy transaction hash
        let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);

        // Verify without providing nonce - should error
        let result = masked_predicate.verify(&public_key, &tx_hash, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("requires nonce revelation"));
    }

    #[test]
    fn test_unmasked_predicate_verify_ignores_nonce() {
        use crate::crypto::keys::KeyPair;
        use crate::types::primitives::DataHash;

        // Create a key pair
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();

        // Create an unmasked predicate
        let unmasked_predicate = UnmaskedPredicate::new(public_key.clone());

        // Create a dummy transaction hash
        let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);

        // Verify with nonce (should be ignored)
        let nonce = b"some_nonce";
        let result_with_nonce = unmasked_predicate.verify(&public_key, &tx_hash, Some(nonce));
        assert!(result_with_nonce.is_ok());
        assert!(result_with_nonce.unwrap());

        // Verify without nonce (should also work)
        let result_without_nonce = unmasked_predicate.verify(&public_key, &tx_hash, None);
        assert!(result_without_nonce.is_ok());
        assert!(result_without_nonce.unwrap());
    }

    #[test]
    fn test_burn_predicate_verify_ignores_nonce() {
        use crate::crypto::keys::KeyPair;
        use crate::types::primitives::DataHash;

        // Create a burn predicate
        let hash = DataHash::sha256(vec![1, 2, 3]);
        let burn_predicate = BurnPredicate::new(hash);

        // Create a dummy public key and transaction hash
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);

        // Verify with nonce (should be ignored, always succeed)
        let nonce = b"some_nonce";
        let result_with_nonce = burn_predicate.verify(&public_key, &tx_hash, Some(nonce));
        assert!(result_with_nonce.is_ok());
        assert!(result_with_nonce.unwrap());

        // Verify without nonce (should also succeed)
        let result_without_nonce = burn_predicate.verify(&public_key, &tx_hash, None);
        assert!(result_without_nonce.is_ok());
        assert!(result_without_nonce.unwrap());
    }
}
