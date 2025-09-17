use crate::error::{Result, SdkError};
use crate::types::primitives::PublicKey;
use secp256k1::{Secp256k1, SecretKey};

/// Key pair structure containing secret and public keys
pub struct KeyPair {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Result<Self> {
        use secp256k1::rand;
        let secp = Secp256k1::new();
        let (secret_key, public_key_secp) = secp.generate_keypair(&mut rand::rng());
        let public_key = PublicKey::new(public_key_secp.serialize())?;

        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Create from secret key bytes (32 bytes)
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let secret_key = SecretKey::from_byte_array(*bytes)?;
        let secp = Secp256k1::new();
        let public_key_secp = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let public_key = PublicKey::new(public_key_secp.serialize())?;

        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Create from hex-encoded secret key
    pub fn from_secret_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        if bytes.len() != 32 {
            return Err(SdkError::InvalidParameter(
                "Secret key must be 32 bytes".to_string(),
            ));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Self::from_secret_bytes(&array)
    }

    /// Create from a seed phrase (deterministic)
    pub fn from_seed(seed: &str) -> Result<Self> {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(seed.as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Self::from_secret_bytes(&bytes)
    }

    /// Get the secret key
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Export secret key as bytes
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret_key.secret_bytes()
    }

    /// Export secret key as hex string
    pub fn secret_hex(&self) -> String {
        hex::encode(self.secret_bytes())
    }

    /// Export public key as bytes
    pub fn public_bytes(&self) -> &[u8; 33] {
        self.public_key.as_bytes()
    }

    /// Export public key as hex string
    pub fn public_hex(&self) -> String {
        hex::encode(self.public_bytes())
    }
}

/// Test identities for development and testing
pub struct TestIdentity {
    pub name: String,
    pub key_pair: KeyPair,
}

impl TestIdentity {
    /// Create a deterministic test identity
    pub fn new(name: &str) -> Result<Self> {
        let key_pair = KeyPair::from_seed(name)?;
        Ok(Self {
            name: name.to_string(),
            key_pair,
        })
    }

    /// Get Alice test identity
    pub fn alice() -> Result<Self> {
        Self::new("Alice")
    }

    /// Get Bob test identity
    pub fn bob() -> Result<Self> {
        Self::new("Bob")
    }

    /// Get Carol test identity
    pub fn carol() -> Result<Self> {
        Self::new("Carol")
    }
}

/// Derive a child key from parent key (simple derivation)
pub fn derive_child_key(parent: &SecretKey, index: u32) -> Result<SecretKey> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(&parent.secret_bytes());
    hasher.update(&index.to_le_bytes());
    let hash = hasher.finalize();

    SecretKey::from_byte_array(hash.into()).map_err(|e| SdkError::Crypto(e.to_string()))
}

/// Simple key storage interface (for testing/demo purposes)
pub struct KeyStore {
    keys: std::collections::HashMap<String, KeyPair>,
}

impl KeyStore {
    /// Create a new key store
    pub fn new() -> Self {
        Self {
            keys: std::collections::HashMap::new(),
        }
    }

    /// Add a key pair with an alias
    pub fn add(&mut self, alias: &str, key_pair: KeyPair) {
        self.keys.insert(alias.to_string(), key_pair);
    }

    /// Get a key pair by alias
    pub fn get(&self, alias: &str) -> Option<&KeyPair> {
        self.keys.get(alias)
    }

    /// List all aliases
    pub fn list_aliases(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    /// Generate and store a new key pair
    pub fn generate_and_store(&mut self, alias: &str) -> Result<&KeyPair> {
        let key_pair = KeyPair::generate()?;
        self.keys.insert(alias.to_string(), key_pair);
        Ok(self.keys.get(alias).unwrap())
    }

    /// Import from hex and store
    pub fn import_hex(&mut self, alias: &str, secret_hex: &str) -> Result<&KeyPair> {
        let key_pair = KeyPair::from_secret_hex(secret_hex)?;
        self.keys.insert(alias.to_string(), key_pair);
        Ok(self.keys.get(alias).unwrap())
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_pair_generation() {
        let key_pair = KeyPair::generate().unwrap();
        assert_eq!(key_pair.secret_bytes().len(), 32);
        assert_eq!(key_pair.public_bytes().len(), 33);
    }

    #[test]
    fn test_key_pair_from_hex() {
        let secret_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key_pair = KeyPair::from_secret_hex(secret_hex).unwrap();
        assert_eq!(key_pair.secret_hex(), secret_hex);
    }

    #[test]
    fn test_deterministic_from_seed() {
        let key1 = KeyPair::from_seed("test seed").unwrap();
        let key2 = KeyPair::from_seed("test seed").unwrap();
        assert_eq!(key1.secret_bytes(), key2.secret_bytes());
        assert_eq!(key1.public_bytes(), key2.public_bytes());
    }

    #[test]
    fn test_test_identities() {
        let alice1 = TestIdentity::alice().unwrap();
        let alice2 = TestIdentity::alice().unwrap();
        assert_eq!(
            alice1.key_pair.secret_bytes(),
            alice2.key_pair.secret_bytes()
        );

        let bob = TestIdentity::bob().unwrap();
        assert_ne!(alice1.key_pair.secret_bytes(), bob.key_pair.secret_bytes());
    }

    #[test]
    fn test_child_key_derivation() {
        let parent = KeyPair::generate().unwrap();
        let child1 = derive_child_key(parent.secret_key(), 0).unwrap();
        let child2 = derive_child_key(parent.secret_key(), 1).unwrap();

        assert_ne!(child1.secret_bytes(), child2.secret_bytes());
        assert_ne!(parent.secret_bytes(), child1.secret_bytes());
    }

    #[test]
    fn test_key_store() {
        let mut store = KeyStore::new();

        let key = store.generate_and_store("main").unwrap();
        let public_hex = key.public_hex();

        let retrieved = store.get("main").unwrap();
        assert_eq!(retrieved.public_hex(), public_hex);

        let aliases = store.list_aliases();
        assert_eq!(aliases.len(), 1);
        assert!(aliases.contains(&"main".to_string()));
    }
}
