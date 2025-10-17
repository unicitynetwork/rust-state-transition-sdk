extern crate alloc;

use crate::error::{Result, SdkError};
use crate::prelude::*;
use crate::types::primitives::{PublicKey, Signature};
use k256::ecdsa::{
    SigningKey, VerifyingKey,
    signature::hazmat::PrehashVerifier,
    Signature as K256Signature,
    RecoveryId,
};

/// Signing service for secp256k1 operations using k256
#[derive(Clone)]
pub struct SigningService;

impl SigningService {
    /// Create a new signing service
    pub fn new() -> Self {
        Self
    }

    /// Sign data with a secret key
    pub fn sign(&self, data: &[u8], secret_key: &SigningKey) -> Result<Signature> {
        // Hash the data if not 32 bytes
        let msg_hash = if data.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(data);
            hash
        } else {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(data);
            hash.into()
        };

        // Sign using prehash since we already have a hash
        let (sig, recovery_id) = secret_key.sign_prehash_recoverable(&msg_hash)
            .map_err(|e| SdkError::Crypto(format!("Signing failed: {}", e)))?;
        let sig_bytes = sig.to_bytes();

        // Create 65-byte signature (r || s || v)
        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(sig_bytes.as_slice());
        signature_bytes[64] = recovery_id.to_byte();

        Ok(Signature::new(signature_bytes))
    }

    /// Sign a hash (already 32 bytes)
    pub fn sign_hash(&self, hash: &[u8; 32], secret_key: &SigningKey) -> Result<Signature> {
        // Sign using prehash_recoverable
        let (sig, recovery_id) = secret_key.sign_prehash_recoverable(hash)
            .map_err(|e| SdkError::Crypto(format!("Signing failed: {}", e)))?;
        let sig_bytes = sig.to_bytes();

        // Create 65-byte signature (r || s || v)
        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(sig_bytes.as_slice());
        signature_bytes[64] = recovery_id.to_byte();

        Ok(Signature::new(signature_bytes))
    }

    /// Verify a signature against data and public key
    ///
    /// This performs direct ECDSA verification matching Java SDK behavior,
    /// which verifies using the r,s signature components and public key directly
    /// (not using public key recovery).
    pub fn verify(
        &self,
        data: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<bool> {
        // Hash the data if not 32 bytes
        let msg_hash = if data.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(data);
            hash
        } else {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(data);
            hash.into()
        };

        // Extract r and s from signature (first 64 bytes)
        let sig_bytes = &signature.as_bytes()[..64];
        let ecdsa_sig = K256Signature::from_slice(sig_bytes)
            .map_err(|e| SdkError::Crypto(format!("Invalid signature: {}", e)))?;

        // Get k256 verifying key
        let verifying_key = public_key.to_verifying_key()?;

        // Direct ECDSA verification using prehash since we already hashed
        Ok(verifying_key.verify_prehash(&msg_hash, &ecdsa_sig).is_ok())
    }

    /// Recover public key from signature
    pub fn recover_public_key(&self, data: &[u8], signature: &Signature) -> Result<PublicKey> {
        // Hash the data if not 32 bytes
        let msg_hash = if data.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(data);
            hash
        } else {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(data);
            hash.into()
        };

        // Extract recovery ID
        let recovery_id_byte = signature.recovery_id();
        let recovery_id = RecoveryId::from_byte(recovery_id_byte)
            .ok_or_else(|| SdkError::Crypto("Invalid recovery ID".to_string()))?;

        // Extract signature from r || s
        let sig_bytes = &signature.as_bytes()[..64];
        let sig = K256Signature::from_slice(sig_bytes)
            .map_err(|e| SdkError::Crypto(format!("Invalid signature: {}", e)))?;

        // Recover public key
        let recovered_key = VerifyingKey::recover_from_prehash(&msg_hash, &sig, recovery_id)
            .map_err(|e| SdkError::Crypto(format!("Key recovery failed: {}", e)))?;

        PublicKey::from_verifying_key(&recovered_key)
    }

}

impl Default for SigningService {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a new random secret key
#[cfg(feature = "rand")]
pub fn generate_secret_key() -> SigningKey {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    SigningKey::from_bytes(&bytes.into()).expect("Failed to generate signing key")
}

/// Get public key from secret key
pub fn public_key_from_secret(secret_key: &SigningKey) -> Result<PublicKey> {
    let verifying_key = VerifyingKey::from(secret_key);
    PublicKey::from_verifying_key(&verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let service = SigningService::new();
        let secret_key = generate_secret_key();
        let public_key = public_key_from_secret(&secret_key).unwrap();

        let data = b"test message";
        let signature = service.sign(data, &secret_key).unwrap();

        assert!(service.verify(data, &signature, &public_key).unwrap());
    }

    #[test]
    fn test_sign_hash() {
        let service = SigningService::new();
        let secret_key = generate_secret_key();
        let public_key = public_key_from_secret(&secret_key).unwrap();

        let hash = [42u8; 32];
        let signature = service.sign_hash(&hash, &secret_key).unwrap();

        assert!(service.verify(&hash, &signature, &public_key).unwrap());
    }

    #[test]
    fn test_recover_public_key() {
        let service = SigningService::new();
        let secret_key = generate_secret_key();
        let public_key = public_key_from_secret(&secret_key).unwrap();

        let data = b"test data";
        let signature = service.sign(data, &secret_key).unwrap();

        let recovered = service.recover_public_key(data, &signature).unwrap();
        assert_eq!(recovered, public_key);
    }

    #[test]
    fn test_invalid_signature() {
        let service = SigningService::new();
        let secret_key1 = generate_secret_key();
        let secret_key2 = generate_secret_key();
        let public_key1 = public_key_from_secret(&secret_key1).unwrap();

        let data = b"test";
        let signature = service.sign(data, &secret_key2).unwrap();

        assert!(!service.verify(data, &signature, &public_key1).unwrap());
    }

    #[test]
    fn test_signature_deterministic() {
        // Note: We use deterministic k (RFC 6979) so signatures should be deterministic
        let service = SigningService::new();
        let secret_key = generate_secret_key();

        let data = b"test";
        let sig1 = service.sign(data, &secret_key).unwrap();
        let sig2 = service.sign(data, &secret_key).unwrap();

        assert_eq!(sig1.as_bytes(), sig2.as_bytes());
    }
}
