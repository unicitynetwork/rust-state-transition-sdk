use crate::error::{Result, SdkError};
use crate::types::primitives::{DataHash, PublicKey};
use serde::{Deserialize, Serialize};
use std::fmt;

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
}
