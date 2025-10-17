pub mod hash;
pub mod keys;
pub mod signing;

// Re-export commonly used items
pub use hash::{sha256, sha256_all, DataHasher, HashAlgorithm};
pub use keys::{KeyPair, TestIdentity};
#[cfg(feature = "std")]
pub use keys::KeyStore;
pub use signing::{public_key_from_secret, SigningService};
#[cfg(feature = "rand")]
pub use signing::generate_secret_key;

// Re-export k256 types for convenience
pub use k256::ecdsa::{SigningKey, VerifyingKey};
