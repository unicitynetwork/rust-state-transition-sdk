use crate::error::{Result, SdkError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// SHA256 algorithm identifier
pub const SHA256_ALGORITHM_ID: [u8; 2] = [0x00, 0x00];

/// SHA224 algorithm identifier
pub const SHA224_ALGORITHM_ID: [u8; 2] = [0x00, 0x01];

/// SHA384 algorithm identifier
pub const SHA384_ALGORITHM_ID: [u8; 2] = [0x00, 0x02];

/// SHA512 algorithm identifier
pub const SHA512_ALGORITHM_ID: [u8; 2] = [0x00, 0x03];

/// RIPEMD160 algorithm identifier
pub const RIPEMD160_ALGORITHM_ID: [u8; 2] = [0x00, 0x04];

/// Algorithm-tagged hash representation compatible with Java SDK
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataHash {
    algorithm: [u8; 2],
    data: Vec<u8>,
}

impl DataHash {
    /// Create a new DataHash with SHA256 algorithm
    pub fn sha256(data: Vec<u8>) -> Self {
        Self {
            algorithm: SHA256_ALGORITHM_ID,
            data,
        }
    }

    /// Create a new DataHash with specified algorithm
    pub fn new(algorithm: [u8; 2], data: Vec<u8>) -> Self {
        Self { algorithm, data }
    }

    /// Get the algorithm identifier
    pub fn algorithm(&self) -> [u8; 2] {
        self.algorithm
    }

    /// Get the hash data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the imprint (algorithm + data)
    pub fn imprint(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(2 + self.data.len());
        result.extend_from_slice(&self.algorithm);
        result.extend_from_slice(&self.data);
        result
    }

    /// Create from imprint bytes
    pub fn from_imprint(imprint: &[u8]) -> Result<Self> {
        if imprint.len() < 2 {
            return Err(SdkError::InvalidParameter(
                "Imprint too short".to_string(),
            ));
        }
        let algorithm = [imprint[0], imprint[1]];
        let data = imprint[2..].to_vec();
        Ok(Self { algorithm, data })
    }
}

impl fmt::Display for DataHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.imprint()))
    }
}

impl Serialize for DataHash {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // JSON: serialize as hex string
            serializer.serialize_str(&hex::encode(self.imprint()))
        } else {
            // CBOR: serialize as bytes
            serializer.serialize_bytes(&self.imprint())
        }
    }
}

impl<'de> Deserialize<'de> for DataHash {
    fn deserialize<D>(deserializer: D) -> std::result::Result<DataHash, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            // JSON: deserialize from hex string
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
            DataHash::from_imprint(&bytes).map_err(serde::de::Error::custom)
        } else {
            // CBOR: deserialize from bytes
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            DataHash::from_imprint(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

/// 65-byte signature format: R (32) || S (32) || recovery_id (1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature([u8; 65]);

impl Signature {
    /// Create a new signature from bytes
    pub fn new(bytes: [u8; 65]) -> Self {
        Self(bytes)
    }

    /// Create from R, S, and recovery ID components
    pub fn from_components(r: &[u8; 32], s: &[u8; 32], recovery_id: u8) -> Self {
        let mut bytes = [0u8; 65];
        bytes[..32].copy_from_slice(r);
        bytes[32..64].copy_from_slice(s);
        bytes[64] = recovery_id;
        Self(bytes)
    }

    /// Get the signature bytes
    pub fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }

    /// Get R component
    pub fn r(&self) -> &[u8] {
        &self.0[..32]
    }

    /// Get S component
    pub fn s(&self) -> &[u8] {
        &self.0[32..64]
    }

    /// Get recovery ID
    pub fn recovery_id(&self) -> u8 {
        self.0[64]
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // JSON: serialize as hex string
            serializer.serialize_str(&hex::encode(&self.0))
        } else {
            // CBOR: serialize as bytes
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            // JSON: deserialize from hex string
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 65 {
                return Err(serde::de::Error::custom("Invalid signature length"));
            }
            let mut arr = [0u8; 65];
            arr.copy_from_slice(&bytes);
            Ok(Signature(arr))
        } else {
            // CBOR: deserialize from bytes
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            if bytes.len() != 65 {
                return Err(serde::de::Error::custom("Invalid signature length"));
            }
            let mut arr = [0u8; 65];
            arr.copy_from_slice(&bytes);
            Ok(Signature(arr))
        }
    }
}

/// 33-byte compressed secp256k1 public key
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 33]);

impl PublicKey {
    /// Create a new public key from bytes
    pub fn new(bytes: [u8; 33]) -> Result<Self> {
        // Validate it's a valid compressed public key
        let _key = secp256k1::PublicKey::from_slice(&bytes)?;
        Ok(Self(bytes))
    }

    /// Get the public key bytes
    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    /// Convert to secp256k1 PublicKey
    pub fn to_secp256k1(&self) -> Result<secp256k1::PublicKey> {
        Ok(secp256k1::PublicKey::from_slice(&self.0)?)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // JSON: serialize as hex string
            serializer.serialize_str(&hex::encode(&self.0))
        } else {
            // CBOR: serialize as bytes
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            // JSON: deserialize from hex string
            let s = String::deserialize(deserializer)?;
            let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 33 {
                return Err(serde::de::Error::custom("Invalid public key length"));
            }
            let mut arr = [0u8; 33];
            arr.copy_from_slice(&bytes);
            PublicKey::new(arr).map_err(serde::de::Error::custom)
        } else {
            // CBOR: deserialize from bytes
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            if bytes.len() != 33 {
                return Err(serde::de::Error::custom("Invalid public key length"));
            }
            let mut arr = [0u8; 33];
            arr.copy_from_slice(&bytes);
            PublicKey::new(arr).map_err(serde::de::Error::custom)
        }
    }
}

/// Request ID for aggregator communication
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(DataHash);

impl RequestId {
    /// Create a new RequestId
    pub fn new(public_key: &PublicKey, state_hash: &DataHash) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        hasher.update(&state_hash.imprint());
        let hash = hasher.finalize().to_vec();
        Self(DataHash::sha256(hash))
    }

    /// Get the underlying DataHash
    pub fn as_data_hash(&self) -> &DataHash {
        &self.0
    }
}

impl Serialize for RequestId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<RequestId, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(RequestId(DataHash::deserialize(deserializer)?))
    }
}