use crate::error::Result;
use crate::types::predicate::PredicateReference;
use crate::types::primitives::DataHash;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Address scheme enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AddressScheme {
    Direct,
    Proxy,
}

/// Base trait for addresses
pub trait Address: Send + Sync + fmt::Debug {
    /// Get the address scheme
    fn scheme(&self) -> AddressScheme;

    /// Get the address hash
    fn hash(&self) -> &DataHash;

    /// Clone the address into a box
    fn clone_box(&self) -> Box<dyn Address>;
}

/// Direct address - hash of predicate reference
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DirectAddress {
    pub hash: DataHash,
}

impl DirectAddress {
    /// Create a new direct address
    pub fn new(hash: DataHash) -> Self {
        Self { hash }
    }

    /// Create from a predicate reference
    pub fn from_predicate_reference(reference: &PredicateReference) -> Result<Self> {
        Ok(Self {
            hash: reference.hash()?,
        })
    }
}

impl Address for DirectAddress {
    fn scheme(&self) -> AddressScheme {
        AddressScheme::Direct
    }

    fn hash(&self) -> &DataHash {
        &self.hash
    }

    fn clone_box(&self) -> Box<dyn Address> {
        Box::new(self.clone())
    }
}

/// Proxy address - resolved through nametag tokens
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProxyAddress {
    pub hash: DataHash,
}

impl ProxyAddress {
    /// Create a new proxy address
    pub fn new(hash: DataHash) -> Self {
        Self { hash }
    }
}

impl Address for ProxyAddress {
    fn scheme(&self) -> AddressScheme {
        AddressScheme::Proxy
    }

    fn hash(&self) -> &DataHash {
        &self.hash
    }

    fn clone_box(&self) -> Box<dyn Address> {
        Box::new(self.clone())
    }
}

/// Generic address wrapper that can be either Direct or Proxy
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "scheme")]
pub enum GenericAddress {
    #[serde(rename = "DIRECT")]
    Direct(DirectAddress),
    #[serde(rename = "PROXY")]
    Proxy(ProxyAddress),
}

impl GenericAddress {
    /// Create a direct address
    pub fn direct(hash: DataHash) -> Self {
        Self::Direct(DirectAddress::new(hash))
    }

    /// Create a proxy address
    pub fn proxy(hash: DataHash) -> Self {
        Self::Proxy(ProxyAddress::new(hash))
    }

    /// Get the address scheme
    pub fn scheme(&self) -> AddressScheme {
        match self {
            Self::Direct(_) => AddressScheme::Direct,
            Self::Proxy(_) => AddressScheme::Proxy,
        }
    }

    /// Get the address hash
    pub fn hash(&self) -> &DataHash {
        match self {
            Self::Direct(addr) => &addr.hash,
            Self::Proxy(addr) => &addr.hash,
        }
    }

    /// Convert to trait object
    pub fn as_address(&self) -> &dyn Address {
        match self {
            Self::Direct(addr) => addr,
            Self::Proxy(addr) => addr,
        }
    }
}

impl fmt::Display for GenericAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}:{}", self.scheme(), self.hash())
    }
}

/// Address resolution result
#[derive(Debug, Clone)]
pub struct ResolvedAddress {
    pub address: GenericAddress,
    pub predicate_reference: Option<PredicateReference>,
}

impl ResolvedAddress {
    /// Create a resolved address
    pub fn new(address: GenericAddress, predicate_reference: Option<PredicateReference>) -> Self {
        Self {
            address,
            predicate_reference,
        }
    }

    /// Check if the address is resolved
    pub fn is_resolved(&self) -> bool {
        self.predicate_reference.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::predicate::UnmaskedPredicate;
    
    #[test]
    fn test_direct_address_from_predicate() {
        use crate::crypto::keys::KeyPair;
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let predicate = UnmaskedPredicate::new(public_key);
        let reference = PredicateReference::from_predicate(&predicate).unwrap();

        let address = DirectAddress::from_predicate_reference(&reference).unwrap();
        assert_eq!(address.scheme(), AddressScheme::Direct);
        assert_eq!(address.hash(), &reference.hash().unwrap());
    }

    #[test]
    fn test_generic_address_serialization() {
        let hash = DataHash::sha256(vec![1, 2, 3]);
        let address = GenericAddress::direct(hash.clone());

        let json = serde_json::to_string(&address).unwrap();
        assert!(json.contains("\"scheme\":\"DIRECT\""));

        let deserialized: GenericAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, address);
    }

    #[test]
    fn test_proxy_address() {
        let hash = DataHash::sha256(vec![4, 5, 6]);
        let address = ProxyAddress::new(hash.clone());

        assert_eq!(address.scheme(), AddressScheme::Proxy);
        assert_eq!(address.hash(), &hash);
    }
}