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
    /// Each predicate type has different verification requirements:
    /// - UnmaskedPredicate: verifies the transaction authenticator's public key matches and signature is valid
    /// - MaskedPredicate: verifies revealed nonce and that hash(public_key + nonce) matches the mask
    /// - BurnPredicate: no further transactions allowed
    ///
    /// Based on Java SDK Predicate.verify() at
    /// java-state-transition-sdk/src/main/java/org/unicitylabs/sdk/predicate/Predicate.java:42-43
    /// and DefaultPredicate.verify() at DefaultPredicate.java:160-188
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
        authenticator: &crate::types::transaction::Authenticator,
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
        authenticator: &crate::types::transaction::Authenticator,
        transaction_hash: &crate::types::primitives::DataHash,
        _nonce: Option<&[u8]>,
    ) -> Result<bool> {
        // For UnmaskedPredicate, verify (matching Java SDK DefaultPredicate.verify() at lines 171-178):
        // 1. The authenticator's public key matches this predicate's public key
        // 2. The authenticator's signature is valid for the transaction hash
        // 3. Nonce is ignored for UnmaskedPredicate

        // Step 1: Check if the authenticator's public key matches the predicate's public key
        // Convert authenticator public key bytes to PublicKey for comparison
        if authenticator.public_key.len() != 33 {
            return Ok(false);
        }
        let mut public_key_array = [0u8; 33];
        public_key_array.copy_from_slice(&authenticator.public_key);
        let authenticator_public_key = PublicKey::new(public_key_array)?;

        if authenticator_public_key != self.public_key {
            return Ok(false);
        }

        // Step 2: Verify the signature (CRITICAL SECURITY CHECK)
        // This matches Java SDK DefaultPredicate.verify() line 176-178
        if !authenticator.verify(transaction_hash.data())? {
            return Ok(false);
        }

        Ok(true)
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
        authenticator: &crate::types::transaction::Authenticator,
        transaction_hash: &crate::types::primitives::DataHash,
        nonce: Option<&[u8]>,
    ) -> Result<bool> {
        // For MaskedPredicate verification:
        // 1. If nonce is provided, verify the nonce commitment
        // 2. Always verify the signature is valid for the transaction hash
        //
        // Note: Nonce revelation is optional. When spending a MaskedPredicate, the owner
        // proves authorization through the signature. Nonce revelation would "unmask" the
        // predicate by proving knowledge of the nonce, but this is not required for spending.

        // Step 1: Optional nonce verification
        // If the nonce is revealed, verify that hash(public_key + nonce) matches
        if let Some(revealed_nonce) = nonce {
            // Verify the nonce commitment
            // Compute the hash of (PredicateType::Unmasked || public_key || nonce)
            // This matches the computation in MaskedPredicate::from_public_key_and_nonce()
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&[PredicateType::Unmasked as u8]);
            hasher.update(&authenticator.public_key);
            hasher.update(revealed_nonce);
            let computed_hash = DataHash::sha256(hasher.finalize().to_vec());

            // Verify that the computed hash matches the masked hash
            if computed_hash != self.hash {
                return Ok(false);
            }
        }

        // Step 2: Always verify the signature
        // This is the critical security check - proves the transaction was signed
        // by the owner of the private key corresponding to the public key
        // This matches Java SDK DefaultPredicate.verify() line 176-178
        if !authenticator.verify(transaction_hash.data())? {
            return Ok(false);
        }

        Ok(true)
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
        _authenticator: &crate::types::transaction::Authenticator,
        _transaction_hash: &crate::types::primitives::DataHash,
        _nonce: Option<&[u8]>,
    ) -> Result<bool> {
        // For BurnPredicate, verification always succeeds
        // Burn predicates allow unconditional token destruction/splitting
        // The actual burn conditions are verified elsewhere (e.g., in split mint verification)
        // Nonce and signature are ignored for BurnPredicate
        // This predicate type is used when tokens are intentionally destroyed or split,
        // and the authorization is checked at a higher level
        Ok(true)
    }
}

/// Predicate reference for address resolution
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PredicateReference {
    #[serde(rename = "type")]
    pub predicate_type: PredicateType,
    pub data: Vec<u8>,
    /// Raw CBOR bytes from JSON (for Java SDK compatibility)
    /// This stores the predicate in Java SDK format: [engine_ordinal, encode_bytes, encodeParameters_bytes]
    #[serde(skip)]
    pub raw_cbor: Option<Vec<u8>>,
}

impl PredicateReference {
    /// Create from a predicate
    pub fn from_predicate(predicate: &dyn Predicate) -> Result<Self> {
        Ok(Self {
            predicate_type: predicate.predicate_type(),
            data: predicate.serialize()?,
            raw_cbor: None,
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
        match self.predicate_type {
            PredicateType::Unmasked => {
                // UnmaskedPredicate: always compute SHA256([type_byte, public_key])
                // data is the 33-byte compressed public key
                if self.data.len() != 33 {
                    return Err(SdkError::InvalidParameter(format!(
                        "Unmasked predicate data must be 33 bytes (public key), got {} bytes",
                        self.data.len()
                    )));
                }
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&[self.predicate_type as u8]);
                hasher.update(&self.data);
                Ok(DataHash::sha256(hasher.finalize().to_vec()))
            },
            PredicateType::Masked | PredicateType::Burn => {
                // Masked/Burn predicates: data contains precomputed hash
                if self.data.len() == 32 {
                    // Token-bound: 32-byte hash from modified CBOR array
                    Ok(DataHash::sha256(self.data.clone()))
                } else if self.data.len() == 34 {
                    // Simple Masked/Burn: DataHash imprint (algorithm prefix + 32-byte hash)
                    DataHash::from_imprint(&self.data)
                } else {
                    Err(SdkError::InvalidParameter(format!(
                        "Masked/Burn predicate data must be 32 or 34 bytes, got {} bytes",
                        self.data.len()
                    )))
                }
            }
        }
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

    /// Deserialize the predicate reference from CBOR bytes (JSON format)
    /// JSON format: [engine_ordinal, encode_bytes, encodeParameters_bytes]
    /// This also transforms it to TokenState CBOR format: [engine_ordinal, encode_int, encodeParameters_array]
    pub fn from_cbor(cbor_bytes: &[u8]) -> Result<Self> {
        use ciborium::Value;

        // Decode as generic CBOR value first
        let value: Value = ciborium::de::from_reader(cbor_bytes)
            .map_err(|e| SdkError::Serialization(format!("Failed to decode predicate from CBOR: {}", e)))?;

        // Extract the 3-element array
        let array = match value {
            Value::Array(arr) if arr.len() == 3 => arr,
            _ => return Err(SdkError::Serialization("Predicate must be a 3-element array".to_string())),
        };

        // Element 0: engine_ordinal (should be 0 for EMBEDDED)
        let engine_ordinal = match &array[0] {
            Value::Integer(i) => {
                let val: i128 = (*i).into();
                val as u8
            },
            _ => return Err(SdkError::Serialization("Engine ordinal must be an integer".to_string())),
        };

        // Element 1: encode() - byte string that should contain a single byte
        let encode_byte = match &array[1] {
            Value::Bytes(b) if b.len() == 1 => b[0],
            _ => return Err(SdkError::Serialization("Encode must be a 1-byte string".to_string())),
        };

        // Element 2: encodeParameters() - byte string containing CBOR-encoded parameters
        let parameters_cbor = match &array[2] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(SdkError::Serialization("Parameters must be a byte string".to_string())),
        };

        // For predicate_type and data, we need to decode the parameters
        // Encode byte maps to PredicateType: 0=Unmasked, 1=Masked, 2=Burn
        let predicate_type = match encode_byte {
            0 => PredicateType::Unmasked,
            1 => PredicateType::Masked,
            2 => PredicateType::Burn,
            _ => return Err(SdkError::InvalidParameter(format!("Invalid encode byte: {}", encode_byte))),
        };

        // Parse the parameters CBOR
        let params: Value = ciborium::de::from_reader(&parameters_cbor[..])
            .map_err(|e| SdkError::Serialization(format!("Failed to decode parameters: {}", e)))?;

        // Extract predicate data based on type and parameter format:
        // - Unmasked: Always extract public key (element [2]), regardless of array size
        // - Masked/Burn: Compute token-bound hash from modified 6-element array
        let data = match predicate_type {
            PredicateType::Unmasked => {
                // For UnmaskedPredicate: always extract the public key
                // regardless of whether it's in a 6-element array or standalone bytes
                match params {
                    Value::Array(ref arr) if arr.len() == 6 => {
                        // Token parameters format: [tokenId, tokenType, pubKey, signingAlg, hashAlg, nonce]
                        // Extract public key (element 2)
                        match &arr[2] {
                            Value::Bytes(b) => b.clone(),
                            _ => return Err(SdkError::Serialization("Public key must be bytes".to_string())),
                        }
                    },
                    Value::Bytes(ref b) => {
                        // Simple format: just the public key bytes
                        b.clone()
                    },
                    _ => return Err(SdkError::Serialization(
                        "Unmasked predicate parameters must be either 6-element array or bytes".to_string()
                    )),
                }
            },
            PredicateType::Masked | PredicateType::Burn => {
                // For Masked/Burn: compute token-bound hash from modified CBOR array
                // Create modified array [encode_byte, tokenType, signingAlg, hashAlg, pubKey, nonce]
                // This omits tokenId (params[0]) and reorders the elements
                // IMPORTANT: tokenType gets double-CBOR-encoded (CBOR bytes wrapped as Value::Bytes)
                match params {
                    Value::Array(ref arr) if arr.len() == 6 => {
                        // Serialize tokenType (arr[1]) to CBOR bytes first
                        let mut token_type_cbor = Vec::new();
                        ciborium::ser::into_writer(&arr[1], &mut token_type_cbor)
                            .map_err(|e| SdkError::Serialization(format!("Failed to encode tokenType: {}", e)))?;

                        // Build modified array: [encode_byte, tokenTypeCbor, signingAlg, hashAlg, pubKey, nonce]
                        let modified_array = Value::Array(vec![
                            Value::Bytes(vec![encode_byte]),      // encode byte as byte string
                            Value::Bytes(token_type_cbor),        // tokenType CBOR bytes (double-encoded!)
                            arr[3].clone(),                       // signingAlg ("secp256k1")
                            arr[4].clone(),                       // hashAlg (0)
                            arr[2].clone(),                       // pubKey
                            arr[5].clone(),                       // nonce
                        ]);

                        // Encode to CBOR
                        let mut modified_cbor = Vec::new();
                        ciborium::ser::into_writer(&modified_array, &mut modified_cbor)
                            .map_err(|e| SdkError::Serialization(format!("Failed to encode modified array: {}", e)))?;

                        // Hash the CBOR bytes
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(&modified_cbor);
                        hasher.finalize().to_vec()
                    },
                    _ => return Err(SdkError::Serialization(
                        "Masked/Burn predicate parameters must be a 6-element array".to_string()
                    )),
                }
            }
        };

        // Create the transformed CBOR for TokenState: [engine_ordinal, encode_int, parameters_array]
        let params_value: Value = ciborium::de::from_reader(&parameters_cbor[..])
            .map_err(|e| SdkError::Serialization(format!("Failed to re-decode parameters: {}", e)))?;

        let transformed_pred = Value::Array(vec![
            Value::Integer(engine_ordinal.into()),
            Value::Integer(encode_byte.into()),
            params_value,
        ]);

        let mut transformed_cbor = Vec::new();
        ciborium::ser::into_writer(&transformed_pred, &mut transformed_cbor)
            .map_err(|e| SdkError::Serialization(format!("Failed to encode transformed predicate: {}", e)))?;

        Ok(Self {
            predicate_type,
            data,
            raw_cbor: Some(transformed_cbor),
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
        use crate::crypto::SigningService;
        use crate::types::primitives::DataHash;
        use crate::types::transaction::Authenticator;

        // Create a key pair for the recipient
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();

        // Create a nonce
        let nonce = b"secret_nonce_12345";

        // Create a masked predicate with the public key and nonce
        let masked_predicate = MaskedPredicate::from_public_key_and_nonce(&public_key, nonce);

        // Create a transaction hash and sign it
        let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);
        let signing_service = SigningService::new();
        let signature = signing_service.sign(tx_hash.data(), key_pair.secret_key()).unwrap();

        let authenticator = Authenticator::new(
            "secp256k1".to_string(),
            public_key.as_bytes().to_vec(),
            signature.as_bytes().to_vec(),
            tx_hash.clone(),
        );

        // Verify with correct public key, signature, and nonce - should succeed
        let result = masked_predicate.verify(&authenticator, &tx_hash, Some(nonce));
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_masked_predicate_verify_wrong_nonce() {
        use crate::crypto::keys::KeyPair;
        use crate::crypto::SigningService;
        use crate::types::primitives::DataHash;
        use crate::types::transaction::Authenticator;

        // Create a key pair for the recipient
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();

        let correct_nonce = b"secret_nonce_12345";
        let wrong_nonce = b"wrong_nonce_67890";

        // Create a masked predicate with the public key and correct nonce
        let masked_predicate = MaskedPredicate::from_public_key_and_nonce(&public_key, correct_nonce);

        // Create a transaction hash and sign it
        let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);
        let signing_service = SigningService::new();
        let signature = signing_service.sign(tx_hash.data(), key_pair.secret_key()).unwrap();

        let authenticator = Authenticator::new(
            "secp256k1".to_string(),
            public_key.as_bytes().to_vec(),
            signature.as_bytes().to_vec(),
            tx_hash.clone(),
        );

        // Verify with wrong nonce - should fail (return false, not error)
        // The signature is valid, but the nonce doesn't match the masked hash
        let result = masked_predicate.verify(&authenticator, &tx_hash, Some(wrong_nonce));
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should return false
    }

    #[test]
    fn test_masked_predicate_verify_wrong_public_key() {
        use crate::crypto::keys::KeyPair;
        use crate::crypto::SigningService;
        use crate::types::primitives::DataHash;
        use crate::types::transaction::Authenticator;

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

        // Create a transaction hash and sign it with key_pair2 (wrong key)
        let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);
        let signing_service = SigningService::new();
        let signature = signing_service.sign(tx_hash.data(), key_pair2.secret_key()).unwrap();

        // Create authenticator with public_key2 (wrong key)
        let authenticator = Authenticator::new(
            "secp256k1".to_string(),
            public_key2.as_bytes().to_vec(),
            signature.as_bytes().to_vec(),
            tx_hash.clone(),
        );

        // Verify with wrong public key (public_key2) - should fail
        let result = masked_predicate.verify(&authenticator, &tx_hash, Some(nonce));
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should return false
    }

    #[test]
    fn test_masked_predicate_verify_no_nonce() {
        use crate::crypto::keys::KeyPair;
        use crate::crypto::SigningService;
        use crate::types::primitives::DataHash;
        use crate::types::transaction::Authenticator;

        // Create a key pair for the recipient
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();

        let nonce = b"secret_nonce_12345";

        let masked_predicate = MaskedPredicate::from_public_key_and_nonce(&public_key, nonce);

        let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);
        let signing_service = SigningService::new();
        let signature = signing_service.sign(tx_hash.data(), key_pair.secret_key()).unwrap();

        let authenticator = Authenticator::new(
            "secp256k1".to_string(),
            public_key.as_bytes().to_vec(),
            signature.as_bytes().to_vec(),
            tx_hash.clone(),
        );

        // Verify without providing nonce - should error
        let result = masked_predicate.verify(&authenticator, &tx_hash, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("requires nonce revelation"));
    }

    #[test]
    fn test_unmasked_predicate_verify_ignores_nonce() {
        use crate::crypto::keys::KeyPair;
        use crate::crypto::SigningService;
        use crate::types::primitives::DataHash;
        use crate::types::transaction::Authenticator;

        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();

        let unmasked_predicate = UnmaskedPredicate::new(public_key.clone());

        let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);
        let signing_service = SigningService::new();
        let signature = signing_service.sign(tx_hash.data(), key_pair.secret_key()).unwrap();

        let authenticator = Authenticator::new(
            "secp256k1".to_string(),
            public_key.as_bytes().to_vec(),
            signature.as_bytes().to_vec(),
            tx_hash.clone(),
        );

        // Verify with nonce (should be ignored)
        let nonce = b"some_nonce";
        let result_with_nonce = unmasked_predicate.verify(&authenticator, &tx_hash, Some(nonce));
        assert!(result_with_nonce.is_ok());
        assert!(result_with_nonce.unwrap());

        // Verify without nonce (should also work)
        let result_without_nonce = unmasked_predicate.verify(&authenticator, &tx_hash, None);
        assert!(result_without_nonce.is_ok());
        assert!(result_without_nonce.unwrap());
    }

    #[test]
    fn test_burn_predicate_verify_ignores_nonce() {
        use crate::crypto::keys::KeyPair;
        use crate::crypto::SigningService;
        use crate::types::primitives::DataHash;
        use crate::types::transaction::Authenticator;

        // Create a burn predicate
        let hash = DataHash::sha256(vec![1, 2, 3]);
        let burn_predicate = BurnPredicate::new(hash);

        // Create a dummy public key and transaction hash
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let tx_hash = DataHash::sha256(vec![1, 2, 3, 4, 5]);

        // Create a signature (even though burn predicates don't check it)
        let signing_service = SigningService::new();
        let signature = signing_service.sign(tx_hash.data(), key_pair.secret_key()).unwrap();

        let authenticator = Authenticator::new(
            "secp256k1".to_string(),
            public_key.as_bytes().to_vec(),
            signature.as_bytes().to_vec(),
            tx_hash.clone(),
        );

        // Verify with nonce (should be ignored, always succeed)
        let nonce = b"some_nonce";
        let result_with_nonce = burn_predicate.verify(&authenticator, &tx_hash, Some(nonce));
        assert!(result_with_nonce.is_ok());
        assert!(result_with_nonce.unwrap());

        // Verify without nonce (should also succeed)
        let result_without_nonce = burn_predicate.verify(&authenticator, &tx_hash, None);
        assert!(result_without_nonce.is_ok());
        assert!(result_without_nonce.unwrap());
    }
}
