use crate::error::{Result, SdkError};
use crate::types::primitives::{PublicKey, Signature};
use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1, SecretKey};
use std::sync::Arc;

/// Signing service for creating and verifying signatures
#[derive(Clone)]
pub struct SigningService {
    secp: Arc<Secp256k1<secp256k1::All>>,
}

impl SigningService {
    /// Create a new signing service
    pub fn new() -> Self {
        Self {
            secp: Arc::new(Secp256k1::new()),
        }
    }

    /// Sign data with a secret key
    pub fn sign(&self, data: &[u8], secret_key: &SecretKey) -> Result<Signature> {
        // Create message from data (must be 32 bytes)
        let message = if data.len() == 32 {
            Message::from_digest(data.try_into().map_err(|_| SdkError::Crypto("Data must be 32 bytes".to_string()))?)
        } else {
            // Hash the data if not 32 bytes
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(data);
            Message::from_digest(hash.into())
        };

        // Sign with recovery
        let recoverable_sig = self.secp.sign_ecdsa_recoverable(message, secret_key);
        let (recovery_id, sig_bytes) = recoverable_sig.serialize_compact();

        // Ensure s-value is in lower half (malleability protection)
        let sig = self.normalize_signature(sig_bytes)?;

        // Create 65-byte signature
        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(&sig);
        signature_bytes[64] = recovery_id as u8;

        Ok(Signature::new(signature_bytes))
    }

    /// Sign a hash (already 32 bytes)
    pub fn sign_hash(&self, hash: &[u8; 32], secret_key: &SecretKey) -> Result<Signature> {
        let message = Message::from_digest(*hash);

        let recoverable_sig = self.secp.sign_ecdsa_recoverable(message, secret_key);
        let (recovery_id, sig_bytes) = recoverable_sig.serialize_compact();

        let sig = self.normalize_signature(sig_bytes)?;

        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(&sig);
        signature_bytes[64] = recovery_id as u8;

        Ok(Signature::new(signature_bytes))
    }

    /// Verify a signature against data and public key
    pub fn verify(
        &self,
        data: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<bool> {
        // Create message
        let message = if data.len() == 32 {
            Message::from_digest(data.try_into().map_err(|_| SdkError::Crypto("Data must be 32 bytes".to_string()))?)
        } else {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(data);
            Message::from_digest(hash.into())
        };

        // Extract signature components
        let recovery_id = secp256k1::ecdsa::RecoveryId::from_u8_masked(signature.recovery_id());

        let recoverable_sig = RecoverableSignature::from_compact(
            &signature.as_bytes()[..64],
            recovery_id,
        )?;

        // Recover public key from signature
        let recovered_key = self.secp.recover_ecdsa(message, &recoverable_sig)?;
        let expected_key = public_key.to_secp256k1()?;

        Ok(recovered_key == expected_key)
    }

    /// Recover public key from signature
    pub fn recover_public_key(&self, data: &[u8], signature: &Signature) -> Result<PublicKey> {
        // Create message
        let message = if data.len() == 32 {
            Message::from_digest(data.try_into().map_err(|_| SdkError::Crypto("Data must be 32 bytes".to_string()))?)
        } else {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(data);
            Message::from_digest(hash.into())
        };

        // Extract signature components
        let recovery_id = secp256k1::ecdsa::RecoveryId::from_u8_masked(signature.recovery_id());

        let recoverable_sig = RecoverableSignature::from_compact(
            &signature.as_bytes()[..64],
            recovery_id,
        )?;

        // Recover public key
        let recovered_key = self.secp.recover_ecdsa(message, &recoverable_sig)?;
        PublicKey::new(recovered_key.serialize())
    }

    /// Normalize signature to ensure s-value is in lower half (malleability protection)
    fn normalize_signature(&self, sig_bytes: [u8; 64]) -> Result<[u8; 64]> {
        use secp256k1::ecdsa::Signature as EcdsaSignature;

        let mut sig = EcdsaSignature::from_compact(&sig_bytes)?;
        sig.normalize_s();

        let normalized = sig.serialize_compact();
        Ok(normalized)
    }
}

impl Default for SigningService {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a new random secret key
pub fn generate_secret_key() -> SecretKey {
    use secp256k1::rand;
    let secp = Secp256k1::new();
    let (secret_key, _) = secp.generate_keypair(&mut rand::rng());
    secret_key
}

/// Get public key from secret key
pub fn public_key_from_secret(secret_key: &SecretKey) -> Result<PublicKey> {
    let secp = Secp256k1::new();
    let public_key_secp = secp256k1::PublicKey::from_secret_key(&secp, secret_key);
    PublicKey::new(public_key_secp.serialize())
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