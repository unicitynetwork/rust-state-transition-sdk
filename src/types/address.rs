use crate::error::Result;
use crate::prelude::*;
use crate::types::predicate::PredicateReference;
use crate::types::primitives::DataHash;
use serde::{Deserialize, Serialize};
use core::fmt;

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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GenericAddress {
    Direct(DirectAddress),
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

    /// Get the address string in Java SDK format: "SCHEME://HASH_HEX"
    /// This matches Java SDK's getAddress() method and is used for CBOR serialization
    pub fn get_address(&self) -> String {
        let scheme = match self {
            Self::Direct(_) => "DIRECT",
            Self::Proxy(_) => "PROXY",
        };
        let hash_hex = hex::encode(self.hash().imprint());
        format!("{}://{}", scheme, hash_hex)
    }
}

impl fmt::Display for GenericAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}:{}", self.scheme(), self.hash())
    }
}

impl Serialize for GenericAddress {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Java SDK format: "SCHEME://HASH_HEX"
        let scheme = match self {
            Self::Direct(_) => "DIRECT",
            Self::Proxy(_) => "PROXY",
        };
        let hash_hex = hex::encode(self.hash().imprint());
        let address_string = format!("{}://{}", scheme, hash_hex);
        serializer.serialize_str(&address_string)
    }
}

impl<'de> Deserialize<'de> for GenericAddress {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Parse Java SDK format: "SCHEME://HASH_HEX"
        let address_string = String::deserialize(deserializer)?;

        let parts: Vec<&str> = address_string.split("://").collect();
        if parts.len() != 2 {
            return Err(serde::de::Error::custom(format!(
                "Invalid address format: expected SCHEME://HASH, got {}",
                address_string
            )));
        }

        let scheme = parts[0];
        let hash_hex = parts[1];

        let hash_bytes = hex::decode(hash_hex).map_err(serde::de::Error::custom)?;
        let hash = DataHash::from_imprint(&hash_bytes).map_err(serde::de::Error::custom)?;

        match scheme {
            "DIRECT" => Ok(Self::Direct(DirectAddress::new(hash))),
            "PROXY" => Ok(Self::Proxy(ProxyAddress::new(hash))),
            _ => Err(serde::de::Error::custom(format!(
                "Invalid address scheme: expected DIRECT or PROXY, got {}",
                scheme
            ))),
        }
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
        // Java SDK format: "DIRECT://HASH_HEX"
        assert!(json.contains("DIRECT://"));
        assert!(json.contains(&hex::encode(hash.imprint())));

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
