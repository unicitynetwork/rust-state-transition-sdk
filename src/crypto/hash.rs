use crate::error::{Result, SdkError};
use crate::prelude::*;
use crate::types::primitives::{
    DataHash, RIPEMD160_ALGORITHM_ID, SHA224_ALGORITHM_ID, SHA256_ALGORITHM_ID,
    SHA384_ALGORITHM_ID, SHA512_ALGORITHM_ID,
};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

/// Hash algorithm enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha224,
    Sha384,
    Sha512,
    Ripemd160,
}

impl HashAlgorithm {
    /// Get the algorithm ID bytes
    pub fn algorithm_id(&self) -> [u8; 2] {
        match self {
            HashAlgorithm::Sha256 => SHA256_ALGORITHM_ID,
            HashAlgorithm::Sha224 => SHA224_ALGORITHM_ID,
            HashAlgorithm::Sha384 => SHA384_ALGORITHM_ID,
            HashAlgorithm::Sha512 => SHA512_ALGORITHM_ID,
            HashAlgorithm::Ripemd160 => RIPEMD160_ALGORITHM_ID,
        }
    }

    /// Create from algorithm ID bytes
    pub fn from_algorithm_id(id: [u8; 2]) -> Result<Self> {
        match id {
            SHA256_ALGORITHM_ID => Ok(HashAlgorithm::Sha256),
            SHA224_ALGORITHM_ID => Ok(HashAlgorithm::Sha224),
            SHA384_ALGORITHM_ID => Ok(HashAlgorithm::Sha384),
            SHA512_ALGORITHM_ID => Ok(HashAlgorithm::Sha512),
            RIPEMD160_ALGORITHM_ID => Ok(HashAlgorithm::Ripemd160),
            _ => Err(SdkError::InvalidParameter(format!(
                "Unknown algorithm ID: {:?}",
                id
            ))),
        }
    }
}

/// Data hasher service for computing hashes
pub struct DataHasher {
    algorithm: HashAlgorithm,
}

impl DataHasher {
    /// Create a new hasher with SHA256 (default)
    pub fn new() -> Self {
        Self {
            algorithm: HashAlgorithm::Sha256,
        }
    }

    /// Create a hasher with specific algorithm
    pub fn with_algorithm(algorithm: HashAlgorithm) -> Self {
        Self { algorithm }
    }

    /// Hash data and return DataHash
    pub fn hash(&self, data: &[u8]) -> DataHash {
        let hash_bytes = match self.algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha224 => {
                let mut hasher = Sha224::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Ripemd160 => {
                use ripemd::Ripemd160;
                let mut hasher = Ripemd160::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
        };

        DataHash::new(self.algorithm.algorithm_id(), hash_bytes)
    }

    /// Hash multiple pieces of data
    pub fn hash_all(&self, data: &[&[u8]]) -> DataHash {
        match self.algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                for piece in data {
                    hasher.update(piece);
                }
                DataHash::new(self.algorithm.algorithm_id(), hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha224 => {
                let mut hasher = Sha224::new();
                for piece in data {
                    hasher.update(piece);
                }
                DataHash::new(self.algorithm.algorithm_id(), hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                for piece in data {
                    hasher.update(piece);
                }
                DataHash::new(self.algorithm.algorithm_id(), hasher.finalize().to_vec())
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                for piece in data {
                    hasher.update(piece);
                }
                DataHash::new(self.algorithm.algorithm_id(), hasher.finalize().to_vec())
            }
            HashAlgorithm::Ripemd160 => {
                use ripemd::Ripemd160;
                let mut hasher = Ripemd160::new();
                for piece in data {
                    hasher.update(piece);
                }
                DataHash::new(self.algorithm.algorithm_id(), hasher.finalize().to_vec())
            }
        }
    }
}

impl Default for DataHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Quick SHA256 hash function
pub fn sha256(data: &[u8]) -> DataHash {
    DataHasher::new().hash(data)
}

/// Quick SHA256 hash of multiple pieces
pub fn sha256_all(data: &[&[u8]]) -> DataHash {
    DataHasher::new().hash_all(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hash() {
        let data = b"hello world";
        let hash = sha256(data);
        assert_eq!(hash.algorithm(), SHA256_ALGORITHM_ID);
        assert_eq!(hash.data().len(), 32); // SHA256 produces 32 bytes
    }

    #[test]
    fn test_sha224_hash() {
        let hasher = DataHasher::with_algorithm(HashAlgorithm::Sha224);
        let data = b"test data";
        let hash = hasher.hash(data);
        assert_eq!(hash.algorithm(), SHA224_ALGORITHM_ID);
        assert_eq!(hash.data().len(), 28); // SHA224 produces 28 bytes
    }

    #[test]
    fn test_hash_all() {
        let data1 = b"hello";
        let data2 = b" ";
        let data3 = b"world";
        let hash1 = sha256_all(&[data1, data2, data3]);
        let hash2 = sha256(b"hello world");
        assert_eq!(hash1.imprint(), hash2.imprint());
    }

    #[test]
    fn test_algorithm_conversion() {
        let algo = HashAlgorithm::from_algorithm_id(SHA256_ALGORITHM_ID).unwrap();
        assert_eq!(algo, HashAlgorithm::Sha256);

        let id = algo.algorithm_id();
        assert_eq!(id, SHA256_ALGORITHM_ID);
    }

    #[test]
    fn test_ripemd160_hash() {
        let hasher = DataHasher::with_algorithm(HashAlgorithm::Ripemd160);
        let data = b"test";
        let hash = hasher.hash(data);
        assert_eq!(hash.algorithm(), RIPEMD160_ALGORITHM_ID);
        assert_eq!(hash.data().len(), 20); // RIPEMD160 produces 20 bytes
    }
}
