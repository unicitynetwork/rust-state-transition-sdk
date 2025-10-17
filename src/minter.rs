use crate::error::{Result, SdkError};
use crate::types::primitives::PublicKey;
use k256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use crate::prelude::*;


/// Universal minter secret - "I_AM_UNIVERSAL_MINTER_FOR_" in hex
pub const UNIVERSAL_MINTER_SECRET: &str = "495f414d5f554e4956455253414c5f4d494e5445525f464f525f";

/// Universal minter for token minting operations
pub struct UniversalMinter;

impl UniversalMinter {
    /// Create a signing key for a specific token ID
    /// This matches Java's SigningService.createFromMaskedSecret(MINTER_SECRET, tokenId.getBytes())
    pub fn create_signing_key(token_id: &[u8]) -> Result<SigningKey> {
        // Decode the universal minter secret from hex
        let minter_secret = hex::decode(UNIVERSAL_MINTER_SECRET)
            .map_err(|e| SdkError::Crypto(format!("Invalid minter secret: {}", e)))?;

        // Hash the secret + token_id to create a unique key
        let mut hasher = Sha256::new();
        hasher.update(&minter_secret);
        hasher.update(token_id);
        let hash = hasher.finalize();

        // Create a SigningKey from the hash
        let hash_bytes: [u8; 32] = hash.into();
        SigningKey::from_bytes(&hash_bytes.into())
            .map_err(|e| SdkError::Crypto(format!("Invalid private key: {}", e)))
    }

    /// Get the public key for a specific token ID
    pub fn get_public_key(token_id: &[u8]) -> Result<PublicKey> {
        use crate::crypto::public_key_from_secret;
        let secret_key = Self::create_signing_key(token_id)?;
        public_key_from_secret(&secret_key)
    }

    /// Check if a public key matches the expected minter key for a token ID
    pub fn verify_minter_key(token_id: &[u8], public_key: &PublicKey) -> Result<bool> {
        let expected_key = Self::get_public_key(token_id)?;
        Ok(expected_key == *public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_universal_minter_key_generation() {
        use crate::crypto::public_key_from_secret;

        // Test with a sample token ID
        let token_id = b"test_token_12345";

        // Generate signing key
        let signing_key = UniversalMinter::create_signing_key(token_id).unwrap();

        // Get public key
        let public_key = UniversalMinter::get_public_key(token_id).unwrap();

        // Verify the public key matches
        let expected_pubkey = public_key_from_secret(&signing_key).unwrap();
        assert_eq!(public_key.as_bytes(), expected_pubkey.as_bytes());
    }

    #[test]
    fn test_deterministic_key_generation() {
        let token_id = b"consistent_token";

        // Generate keys multiple times - should be the same
        let key1 = UniversalMinter::create_signing_key(token_id).unwrap();
        let key2 = UniversalMinter::create_signing_key(token_id).unwrap();

        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_different_tokens_different_keys() {
        let token_id1 = b"token1";
        let token_id2 = b"token2";

        let key1 = UniversalMinter::create_signing_key(token_id1).unwrap();
        let key2 = UniversalMinter::create_signing_key(token_id2).unwrap();

        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }
}