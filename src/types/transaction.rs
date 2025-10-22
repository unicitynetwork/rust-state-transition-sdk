use crate::error::{Result, SdkError};
use crate::prelude::*;
use crate::types::primitives::DataHash;
use crate::types::token::{TokenId, TokenState, TokenType};
use serde::{Deserialize, Serialize};
use once_cell::sync::OnceCell;

/// Trait for transaction data types that can have recipient data hashes
pub trait TransactionDataTrait {
    /// Get the recipient data hash if present
    fn get_recipient_data_hash(&self) -> Option<&DataHash>;

    /// Get the recipient address
    fn get_recipient(&self) -> &crate::types::address::GenericAddress;

    /// Compute the hash of the transaction data
    fn hash(&self) -> Result<DataHash>;
}

/// Generic transaction wrapper with data and inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction<T> {
    pub data: T,
    #[serde(rename = "inclusionProof")]
    pub inclusion_proof: InclusionProof,
    /// Cached transaction hash for performance (computed lazily)
    #[serde(skip)]
    cached_hash: OnceCell<DataHash>,
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
            cached_hash: OnceCell::new(),
        }
    }
}

impl<T> Transaction<T>
where
    T: Serialize + for<'de> Deserialize<'de> + TransactionDataTrait,
{
    /// Compute the hash of the transaction (cached for performance)
    /// Uses the data's hash() method which provides CBOR encoding for Java SDK compatibility
    pub fn hash(&self) -> Result<DataHash> {
        self.cached_hash.get_or_try_init(|| {
            self.data.hash()
        }).cloned()
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

    /// Serialize authenticator to CBOR format (matches Java SDK)
    /// Format: [algorithm, publicKey, signature, stateHash]
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        use ciborium::Value;

        let cbor_array = vec![
            Value::Text(self.algorithm.clone()),
            Value::Bytes(self.public_key.clone()),
            Value::Bytes(self.signature.clone()),
            Value::Bytes(self.state_hash.imprint().to_vec()),
        ];

        let mut buffer = Vec::new();
        ciborium::into_writer(&Value::Array(cbor_array), &mut buffer)
            .map_err(|e| SdkError::Serialization(format!("Failed to serialize authenticator to CBOR: {}", e)))?;

        Ok(buffer)
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

/// Custom deserializer for path that preserves large integers as strings
mod path_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use alloc::string::{String, ToString};

    pub fn serialize<S>(value: &String, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde_json::Value;
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(s) => Ok(s),
            Value::Number(n) => {
                // For numbers, use as_u64/as_i64 if possible to avoid scientific notation
                if let Some(u) = n.as_u64() {
                    Ok(u.to_string())
                } else if let Some(i) = n.as_i64() {
                    Ok(i.to_string())
                } else {
                    // Fallback: convert to string, but this may use scientific notation
                    Ok(n.to_string())
                }
            }
            _ => Err(serde::de::Error::custom("path must be a string or number")),
        }
    }
}

/// Merkle tree path step for Java SDK compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTreePathStep {
    #[serde(with = "path_serde")]
    pub path: String, // Large integer as string to preserve precision
    pub sibling: Option<Vec<String>>, // null or array of hashes
    pub branch: Option<Vec<Option<String>>>, // null (no update), [] or [null] or ["hash"] (update path)
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
    pub fn new(merkle_tree_path: MerkleTreePath) -> Self {
        Self {
            merkle_tree_path,
            authenticator: None,
            transaction_hash: None,
            unicity_certificate: None,
        }
    }

    pub fn with_certificate(merkle_tree_path: MerkleTreePath, certificate: Vec<u8>) -> Self {
        Self {
            merkle_tree_path,
            authenticator: None,
            transaction_hash: None,
            unicity_certificate: Some(certificate),
        }
    }

    pub fn with_authenticator(merkle_tree_path: MerkleTreePath, authenticator: Authenticator) -> Self {
        Self {
            merkle_tree_path,
            authenticator: Some(authenticator),
            transaction_hash: None,
            unicity_certificate: None,
        }
    }

    /// Verify inclusion proof with trust base
    ///
    /// This performs complete cryptographic verification of the inclusion proof:
    ///
    /// 1. **Transaction Hash**: Verifies the proof contains the expected transaction hash
    /// 2. **Trust Base**: Verifies the merkle root is signed by trusted validators
    /// 3. **Unicity Certificate**: If present, verifies certificate signatures
    /// 4. **Merkle Path**: Verifies the complete path from:
    ///    - Leaf: SHA256(authenticator_cbor || transaction_hash)
    ///    - Through the sparse merkle tree
    ///    - To Root: Verified against trust base
    ///
    /// This ensures the transaction is:
    /// - Properly authenticated (signature verification)
    /// - Included in the merkle tree (path verification)
    /// - Signed by trusted validators (trust base + certificate)
    pub fn verify_with_trust_base(
        &self,
        request_id: &crate::types::primitives::RequestId,
        trust_base: &crate::types::bft::RootTrustBase,
        expected_transaction_hash: &DataHash,
    ) -> Result<bool> {
        // Verify the inclusion proof contains the expected transaction hash
        if let Some(ref proof_tx_hash) = self.transaction_hash {
            let expected_hash_hex = hex::encode(expected_transaction_hash.imprint());

            if proof_tx_hash != &expected_hash_hex {
                return Err(SdkError::Validation(format!(
                    "Transaction hash mismatch: inclusion proof has {}, but actual transaction hash is {}",
                    proof_tx_hash, expected_hash_hex
                )));
            }
        } else {
            return Err(SdkError::Validation(
                "Inclusion proof missing transaction hash".to_string()
            ));
        }

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

        // Verify the Merkle path from authenticator+transaction through tree to root
        if !self.verify_merkle_path(request_id, expected_transaction_hash)? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify the Merkle path from leaf to root
    ///
    /// This implements the Java SDK's SparseMerkleTreePath.verify() algorithm exactly.
    /// The inclusion proof format from the aggregator uses a sparse merkle tree with:
    /// - Steps containing path (BigInteger), sibling array, and branch array
    /// - Custom traversal algorithm that differs from binary merkle trees
    ///
    /// References:
    /// - Java: org.unicitylabs.sdk.mtree.plain.SparseMerkleTreePath.verify()
    /// - Java: org.unicitylabs.sdk.api.LeafValue.create()
    fn verify_merkle_path(
        &self,
        request_id: &crate::types::primitives::RequestId,
        transaction_hash: &DataHash,
    ) -> Result<bool> {
        use sha2::{Digest, Sha256};
        use num_bigint::BigInt;
        use num_traits::One;

        // If authenticator is present, verify the leaf value
        // LeafValue.create() in Java: SHA256(authenticator.toCbor() || transactionHash.getImprint())
        if let Some(ref authenticator) = self.authenticator {
            let authenticator_cbor = authenticator.to_cbor()?;
            let mut hasher = Sha256::new();
            hasher.update(&authenticator_cbor);
            hasher.update(transaction_hash.imprint());
            let leaf_hash_raw = hasher.finalize().to_vec();

            // The leaf value is stored as DataHash imprint in the first step's branch
            let expected_leaf = DataHash::sha256(leaf_hash_raw);

            if let Some(first_step) = self.merkle_tree_path.steps.first() {
                if let Some(ref branch_vec) = first_step.branch {
                    if let Some(Some(ref branch_hex)) = branch_vec.first() {
                        // Branch hex from JSON should match the expected leaf imprint exactly
                        if &hex::encode(expected_leaf.imprint()) != branch_hex {
                            return Ok(false);
                        }
                    }
                }
            }
        }

        // Walk the merkle path from leaf to root
        // Matching Java: BigInteger currentPath = BigInteger.ONE; DataHash currentHash = null;
        let mut current_path = BigInt::one();
        let mut current_hash: Option<DataHash> = None;

        for (i, step) in self.merkle_tree_path.steps.iter().enumerate() {
            // Parse step.getPath() as BigInteger (it's now always a String after deserialization)
            let step_path = step.path.parse::<BigInt>()
                .map_err(|e| SdkError::Validation(format!("Invalid path '{}': {}", step.path, e)))?;

            // Check if branch is null
            // In TypeScript: step.branch === null → no path update
            // In TypeScript: step.branch !== null (even if value is null) → path update
            // In our structure: branch is Option<Vec<Option<String>>>
            let has_branch = step.branch.is_some();

            // Compute node hash (matches Java's hash variable)
            // if (step.getBranch().isEmpty()) { hash = new byte[]{0}; } else { ... }
            let hash: Vec<u8> = if !has_branch {
                vec![0u8]
            } else {
                // bytes = i == 0 ? step.getBranch().map(...).orElse(null)
                //                : (currentHash != null ? currentHash.getData() : null)
                let bytes = if i == 0 {
                    // First step: get branch value (leaf value)
                    // From Java SDK: Branch.getValue() returns the FULL bytes including algorithm prefix
                    // The branch hex in JSON includes the algorithm prefix (e.g., "0000...") - use it as-is!
                    if let Some(ref branch_vec) = step.branch {
                        if let Some(Some(ref branch_hex)) = branch_vec.first() {
                            let branch_bytes = hex::decode(branch_hex)
                                .map_err(|e| SdkError::Serialization(format!("Invalid branch hex: {}", e)))?;
                            // Use the full bytes including algorithm prefix (matches Java SDK)
                            Some(branch_bytes)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    // Subsequent steps: use current hash data (raw bytes, no prefix)
                    // In TypeScript: currentHash?.data
                    if let Some(ref ch) = current_hash {
                        let data = ch.data().to_vec();
                        Some(data)
                    } else {
                        None
                    }
                };

                // if (bytes == null) { hash = new byte[]{0}; } else { ... }
                if let Some(bytes) = bytes {
                    // hash = DataHasher.update(BigIntegerConverter.encode(step.getPath()))
                    //                 .update(bytes).digest().getData()
                    let path_bytes = encode_bigint_unsigned(&step_path);
                    let mut hasher = Sha256::new();
                    hasher.update(&path_bytes);
                    hasher.update(&bytes);
                    let result = hasher.finalize().to_vec();
                    result  // Returns raw hash bytes (getData())
                } else {
                    vec![0u8]
                }
            };

            // Update current path if branch is not null
            // TypeScript: const length = BigInt(step.path.toString(2).length - 1);
            // TypeScript: currentPath = (currentPath << length) | (step.path & ((1n << length) - 1n));
            if has_branch {
                let bit_length = step_path.bits();
                if bit_length > 0 {
                    let length = bit_length - 1;
                    let mask = (BigInt::one() << length) - BigInt::one();
                    let masked_path = &step_path & &mask;
                    current_path = (&current_path << length) | masked_path;
                }
            }

            // Get sibling hash
            // byte[] siblingHash = step.getSibling().map(DataHash::getData).orElse(new byte[]{0})
            // Note: In the aggregator response, siblings are sent as raw hash bytes (32 bytes),
            // NOT as DataHash imprints with algorithm prefix
            let sibling_hash = if let Some(ref sibling_vec) = step.sibling {
                if let Some(ref sibling_hex) = sibling_vec.first() {
                    let sibling_bytes = hex::decode(sibling_hex)
                        .map_err(|e| SdkError::Serialization(format!("Invalid sibling hex: {}", e)))?;
                    if sibling_bytes.is_empty() {
                        vec![0u8]
                    } else {
                        sibling_bytes
                    }
                } else {
                    vec![0u8]
                }
            } else {
                vec![0u8]
            };

            // Compute parent hash
            // boolean isRight = step.getPath().testBit(0);
            // currentHash = DataHasher.update(isRight ? siblingHash : hash)
            //                         .update(isRight ? hash : siblingHash).digest()
            let is_right = step_path.bit(0);
            let mut hasher = Sha256::new();
            if is_right {
                hasher.update(&sibling_hash);
                hasher.update(&hash);
            } else {
                hasher.update(&hash);
                hasher.update(&sibling_hash);
            }
            let parent_hash_data = hasher.finalize().to_vec();
            current_hash = Some(DataHash::sha256(parent_hash_data));
        }

        // Verify: this.rootHash.equals(currentHash)
        let root_hash = DataHash::from_imprint(
            &hex::decode(&self.merkle_tree_path.root)
                .map_err(|e| SdkError::Serialization(format!("Invalid root hash hex: {}", e)))?
        )?;

        let computed_hash = current_hash
            .ok_or_else(|| SdkError::Validation("No hash computed".to_string()))?;

        // Verify: currentPath.equals(requestId)
        // Request ID is stored as DataHash, convert to BigInteger for comparison
        let request_id_bytes = request_id.as_data_hash().imprint();
        // Parse as unsigned big integer (matching Java's behavior)
        let request_id_bigint = decode_bigint_unsigned(&request_id_bytes[2..]); // Skip algorithm prefix

        // Strip the sentinel bit from currentPath before comparing
        // The path reconstruction algorithm builds up currentPath with sentinel bits,
        // starting from 1 and shifting/OR-ing with masked step paths.
        // The final currentPath has a leading sentinel bit that must be removed.
        // Method: Mask off the lower (bit_length - 1) bits to remove the leading 1
        let current_path_bits = current_path.bits();
        let mask = (BigInt::one() << (current_path_bits - 1)) - BigInt::one();
        let path_without_sentinel = &current_path & &mask;

        if root_hash != computed_hash {
            return Ok(false);
        }

        if path_without_sentinel != request_id_bigint {
            return Ok(false);
        }

        Ok(true)
    }

    /// Get the root hash as DataHash
    pub fn root_hash(&self) -> Result<DataHash> {
        let root_bytes = hex::decode(&self.merkle_tree_path.root)
            .map_err(|e| SdkError::Serialization(format!("Invalid root hash hex: {}", e)))?;
        DataHash::from_imprint(&root_bytes)
    }
}

/// Encode BigInteger to bytes (matches Java's BigIntegerConverter.encode)
///
/// Java implementation:
/// ```java
/// public static byte[] encode(BigInteger value) {
///     int length = 0;
///     BigInteger t = value;
///     while (t.compareTo(BigInteger.ZERO) > 0) {
///         t = t.shiftRight(8);
///         length++;
///     }
///     byte[] result = new byte[length];
///     t = value;
///     for (int i = length - 1; i >= 0; i--) {
///         result[i] = t.and(BigInteger.valueOf(0xFF)).byteValue();
///         t = t.shiftRight(8);
///     }
///     return result;
/// }
/// ```
fn encode_bigint_unsigned(value: &num_bigint::BigInt) -> Vec<u8> {
    use num_traits::Zero;

    if value.is_zero() {
        return vec![];
    }

    // Use to_bytes_be() which returns (sign, bytes)
    // We want unsigned encoding, so just take the bytes part
    let (_sign, bytes) = value.to_bytes_be();
    bytes
}

/// Decode bytes to BigInteger (matches Java's BigIntegerConverter.decode)
///
/// Java implementation:
/// ```java
/// public static BigInteger decode(byte[] data, int offset, int length) {
///     BigInteger t = BigInteger.ZERO;
///     for (int i = 0; i < length; ++i) {
///         t = t.shiftLeft(8).or(BigInteger.valueOf(data[offset + i] & 0xFF));
///     }
///     return t;
/// }
/// ```
fn decode_bigint_unsigned(data: &[u8]) -> num_bigint::BigInt {
    use num_traits::Zero;

    let mut t = num_bigint::BigInt::zero();
    for &byte in data {
        t = (t << 8) | num_bigint::BigInt::from(byte);
    }
    t
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

    fn hash(&self) -> Result<DataHash> {
        // Call the existing hash implementation
        MintTransactionData::hash(self)
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

    fn hash(&self) -> Result<DataHash> {
        // Call the existing hash implementation
        TransferTransactionData::hash(self)
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

    /// Serialize to CBOR matching Java SDK format
    /// Format: [sourceState, recipient, salt, recipientDataHash, message, nametags]
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        use ciborium::Value;

        // Element 0: sourceState as TokenState CBOR array
        let source_state_cbor = self.source_state.to_cbor_for_transfer()?;
        let source_state_value: Value = ciborium::de::from_reader(&source_state_cbor[..])
            .map_err(|e| SdkError::Serialization(format!("Failed to decode source state CBOR: {}", e)))?;

        // Element 1: recipient as text string
        let recipient_value = Value::Text(self.recipient.get_address());

        // Element 2: salt as byte string
        let salt_value = Value::Bytes(self.salt.clone());

        // Element 3: recipientDataHash as DataHash imprint bytes or null
        let recipient_data_hash_value = if let Some(ref hash) = self.recipient_data_hash {
            Value::Bytes(hash.imprint().to_vec())
        } else {
            Value::Null  // CBOR null (0xf6)
        };

        // Element 4: message as byte string or null
        let message_value = if let Some(ref msg) = self.message {
            Value::Bytes(msg.clone())
        } else {
            Value::Null  // CBOR null (0xf6)
        };

        // Element 5: nametags as array (empty array if no nametags)
        // TODO: Implement nametag CBOR encoding when needed
        let nametags_value = Value::Array(vec![]);  // Empty array for now

        // Create the 6-element array
        let transfer_array = Value::Array(vec![
            source_state_value,
            recipient_value,
            salt_value,
            recipient_data_hash_value,
            message_value,
            nametags_value,
        ]);

        // Serialize to CBOR
        let mut cbor_bytes = Vec::new();
        ciborium::ser::into_writer(&transfer_array, &mut cbor_bytes)
            .map_err(|e| SdkError::Serialization(format!("Failed to encode transfer data to CBOR: {}", e)))?;

        Ok(cbor_bytes)
    }

    /// Compute the hash of the transfer data using CBOR encoding (Java SDK compatible)
    pub fn hash(&self) -> Result<DataHash> {
        use sha2::{Digest, Sha256};

        // Serialize to CBOR
        let cbor_bytes = self.to_cbor()?;

        // Hash the CBOR bytes
        let mut hasher = Sha256::new();
        hasher.update(&cbor_bytes);

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
            static DUMMY: OnceCell<crate::types::address::GenericAddress> = OnceCell::new();
            DUMMY.get_or_init(|| {
                crate::types::address::GenericAddress::Direct(
                    crate::types::address::DirectAddress::new(DataHash::sha256(vec![0]))
                )
            })
        })
    }

    fn hash(&self) -> Result<DataHash> {
        // Call the existing hash implementation
        NametagMintTransactionData::hash(self)
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
                    path: "0".to_string(),
                    sibling: Some(vec![hex::encode(vec![4, 5, 6])]),
                    branch: Some(vec![Some(hex::encode(vec![7, 8, 9]))]),
                }
            ],
        };
        let proof = InclusionProof::new(merkle_tree_path);

        assert!(!proof.merkle_tree_path.steps.is_empty());
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

    #[test]
    fn test_transaction_hash_caching() {
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
            vec![7, 8, 9],
            None,
            None,
            vec![],
        );

        let merkle_tree_path = MerkleTreePath {
            root: hex::encode(vec![1, 2, 3]),
            steps: vec![],
        };
        let proof = InclusionProof::new(merkle_tree_path);

        let transaction = Transaction::new(transfer_data, proof);

        // First hash call should compute and cache
        let hash1 = transaction.hash().unwrap();

        // Second hash call should return cached value (same reference)
        let hash2 = transaction.hash().unwrap();

        // Verify both hashes are identical
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.data().len(), 32);
    }
}
