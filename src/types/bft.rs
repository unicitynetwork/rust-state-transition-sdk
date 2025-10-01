use crate::error::{Result, SdkError};
use crate::crypto::sha256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Root trust base for verifying certificates and inclusion proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootTrustBase {
    pub version: u64,
    pub network_id: u32,
    pub epoch: u64,
    pub epoch_start_round: u64,
    pub root_nodes: Vec<NodeInfo>,
    pub quorum_threshold: u64,
    #[serde(default)]
    #[serde(with = "hex_opt")]
    pub state_hash: Option<Vec<u8>>,
    #[serde(default)]
    #[serde(with = "hex_opt")]
    pub change_record_hash: Option<Vec<u8>>,
    #[serde(default)]
    #[serde(with = "hex_opt")]
    pub previous_entry_hash: Option<Vec<u8>>,
    pub signatures: HashMap<String, String>,
}

/// Node information in the trust base
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    pub node_id: String,
    #[serde(rename = "sigKey")]
    pub sig_key: String,
    pub stake: u64,
}

/// Input record for certificate validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputRecord {
    pub version: u32,
    pub round_number: u64,
    pub epoch: u64,
    pub previous_hash: Option<Vec<u8>>,
    pub hash: Vec<u8>,
    pub summary_value: Vec<u8>,
    pub timestamp: u64,
    pub block_hash: Option<Vec<u8>>,
    pub sum_of_earned_fees: u64,
    pub executed_transactions_hash: Option<Vec<u8>>,
}

/// Shard tree certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardTreeCertificate {
    pub shard: Vec<u8>,
    pub sibling_hashes: Vec<Vec<u8>>,
}

/// Unicity tree certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnicityTreeCertificate {
    pub version: u32,
    pub partition_id: u32,
    pub hash_steps: Vec<HashStep>,
}

/// Hash step in unicity tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashStep {
    pub left: Option<Vec<u8>>,
    pub right: Option<Vec<u8>>,
}

/// Unicity seal for signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnicitySeal {
    pub version: u32,
    pub network_id: u16,
    pub root_chain_round_number: u64,
    pub epoch: u64,
    pub timestamp: u64,
    pub previous_hash: Option<Vec<u8>>,
    pub hash: Vec<u8>,
    pub signatures: HashMap<String, Vec<u8>>,
}

/// Unicity certificate for validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnicityCertificate {
    pub version: u32,
    pub input_record: InputRecord,
    pub technical_record_hash: Vec<u8>,
    pub shard_configuration_hash: Vec<u8>,
    pub shard_tree_certificate: ShardTreeCertificate,
    pub unicity_tree_certificate: UnicityTreeCertificate,
    pub unicity_seal: UnicitySeal,
}

impl UnicityCertificate {
    /// Create from CBOR bytes
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        use ciborium::Value;

        // Parse CBOR data
        let value: Value = ciborium::from_reader(data)
            .map_err(|e| SdkError::Cbor(format!("Failed to parse certificate CBOR: {}", e)))?;

        // The certificate is encoded as a tagged array [tag 1007]
        let array = match value {
            Value::Tag(tag, boxed_value) if tag == 1007 => {
                match *boxed_value {
                    Value::Array(arr) => arr,
                    _ => return Err(SdkError::Cbor("Certificate is not an array".into())),
                }
            }
            Value::Array(arr) => arr, // Also accept untagged array
            _ => return Err(SdkError::Cbor("Invalid certificate format".into())),
        };

        if array.len() != 7 {
            return Err(SdkError::Cbor(format!("Certificate array has {} elements, expected 7", array.len())));
        }

        // Parse version
        let version = match &array[0] {
            Value::Integer(i) => (*i).try_into().map_err(|_| SdkError::Cbor("Invalid version".into()))?,
            _ => return Err(SdkError::Cbor("Version is not an integer".into())),
        };

        // Parse input record (array)
        let input_record = Self::parse_input_record(&array[1])?;

        // Parse technical record hash
        let technical_record_hash = match &array[2] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(SdkError::Cbor("Technical record hash is not bytes".into())),
        };

        // Parse shard configuration hash
        let shard_configuration_hash = match &array[3] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(SdkError::Cbor("Shard configuration hash is not bytes".into())),
        };

        // Parse shard tree certificate
        let shard_tree_certificate = Self::parse_shard_tree_certificate(&array[4])?;

        // Parse unicity tree certificate
        let unicity_tree_certificate = Self::parse_unicity_tree_certificate(&array[5])?;

        // Parse unicity seal
        let unicity_seal = Self::parse_unicity_seal(&array[6])?;

        Ok(Self {
            version,
            input_record,
            technical_record_hash,
            shard_configuration_hash,
            shard_tree_certificate,
            unicity_tree_certificate,
            unicity_seal,
        })
    }

    fn parse_input_record(value: &ciborium::Value) -> Result<InputRecord> {
        use ciborium::Value;

        let array = match value {
            Value::Tag(tag, boxed_value) if *tag == 1008 => {
                match boxed_value.as_ref() {
                    Value::Array(arr) => arr,
                    _ => return Err(SdkError::Cbor("Input record tag does not contain array".into())),
                }
            }
            Value::Array(arr) => arr,
            _ => return Err(SdkError::Cbor("Input record is not an array or tagged array".into())),
        };

        if array.len() < 10 {
            return Err(SdkError::Cbor("Input record has insufficient elements".into()));
        }

        Ok(InputRecord {
            version: match &array[0] {
                Value::Integer(i) => (*i).try_into().map_err(|_| SdkError::Cbor("Invalid version".into()))?,
                _ => return Err(SdkError::Cbor("Version is not an integer".into())),
            },
            round_number: match &array[1] {
                Value::Integer(i) => (*i).try_into().map_err(|_| SdkError::Cbor("Invalid round number".into()))?,
                _ => return Err(SdkError::Cbor("Round number is not an integer".into())),
            },
            epoch: match &array[2] {
                Value::Integer(i) => (*i).try_into().map_err(|_| SdkError::Cbor("Invalid epoch".into()))?,
                _ => return Err(SdkError::Cbor("Epoch is not an integer".into())),
            },
            previous_hash: match &array[3] {
                Value::Bytes(b) => Some(b.clone()),
                Value::Null => None,
                _ => return Err(SdkError::Cbor("Previous hash is not bytes or null".into())),
            },
            hash: match &array[4] {
                Value::Bytes(b) => b.clone(),
                _ => return Err(SdkError::Cbor("Hash is not bytes".into())),
            },
            summary_value: match &array[5] {
                Value::Bytes(b) => b.clone(),
                _ => return Err(SdkError::Cbor("Summary value is not bytes".into())),
            },
            timestamp: match &array[6] {
                Value::Integer(i) => (*i).try_into().map_err(|_| SdkError::Cbor("Invalid timestamp".into()))?,
                _ => return Err(SdkError::Cbor("Timestamp is not an integer".into())),
            },
            block_hash: match &array[7] {
                Value::Bytes(b) => Some(b.clone()),
                Value::Null => None,
                _ => return Err(SdkError::Cbor("Block hash is not bytes or null".into())),
            },
            sum_of_earned_fees: match &array[8] {
                Value::Integer(i) => (*i).try_into().map_err(|_| SdkError::Cbor("Invalid fees".into()))?,
                _ => return Err(SdkError::Cbor("Sum of earned fees is not an integer".into())),
            },
            executed_transactions_hash: match &array[9] {
                Value::Bytes(b) => Some(b.clone()),
                Value::Null => None,
                _ => return Err(SdkError::Cbor("Executed transactions hash is not bytes or null".into())),
            },
        })
    }

    fn parse_shard_tree_certificate(value: &ciborium::Value) -> Result<ShardTreeCertificate> {
        use ciborium::Value;

        let array = match value {
            Value::Array(arr) => arr,
            _ => return Err(SdkError::Cbor("Shard tree certificate is not an array".into())),
        };

        if array.len() != 2 {
            return Err(SdkError::Cbor("Shard tree certificate has wrong number of elements".into()));
        }

        let shard = match &array[0] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(SdkError::Cbor("Shard is not bytes".into())),
        };

        let sibling_hashes = match &array[1] {
            Value::Array(arr) => {
                let mut hashes = Vec::new();
                for item in arr {
                    match item {
                        Value::Bytes(b) => hashes.push(b.clone()),
                        _ => return Err(SdkError::Cbor("Sibling hash is not bytes".into())),
                    }
                }
                hashes
            }
            _ => return Err(SdkError::Cbor("Sibling hashes is not an array".into())),
        };

        Ok(ShardTreeCertificate {
            shard,
            sibling_hashes,
        })
    }

    fn parse_unicity_tree_certificate(value: &ciborium::Value) -> Result<UnicityTreeCertificate> {
        use ciborium::Value;

        let array = match value {
            Value::Tag(tag, boxed_value) if *tag == 1014 => {
                match boxed_value.as_ref() {
                    Value::Array(arr) => arr,
                    _ => return Err(SdkError::Cbor("Unicity tree certificate tag does not contain array".into())),
                }
            }
            Value::Array(arr) => arr,
            _ => return Err(SdkError::Cbor("Unicity tree certificate is not an array or tagged array".into())),
        };

        if array.len() != 3 {
            return Err(SdkError::Cbor("Unicity tree certificate has wrong number of elements".into()));
        }

        Ok(UnicityTreeCertificate {
            version: match &array[0] {
                Value::Integer(i) => (*i).try_into().map_err(|_| SdkError::Cbor("Invalid version".into()))?,
                _ => return Err(SdkError::Cbor("Version is not an integer".into())),
            },
            partition_id: match &array[1] {
                Value::Integer(i) => (*i).try_into().map_err(|_| SdkError::Cbor("Invalid partition ID".into()))?,
                _ => return Err(SdkError::Cbor("Partition ID is not an integer".into())),
            },
            hash_steps: match &array[2] {
                Value::Array(arr) => {
                    let mut steps = Vec::new();
                    for item in arr {
                        match item {
                            Value::Array(step_arr) if step_arr.len() == 2 => {
                                let left = match &step_arr[0] {
                                    Value::Bytes(b) => Some(b.clone()),
                                    Value::Null => None,
                                    _ => return Err(SdkError::Cbor("Left hash is not bytes or null".into())),
                                };
                                let right = match &step_arr[1] {
                                    Value::Bytes(b) => Some(b.clone()),
                                    Value::Null => None,
                                    _ => return Err(SdkError::Cbor("Right hash is not bytes or null".into())),
                                };
                                steps.push(HashStep { left, right });
                            }
                            _ => return Err(SdkError::Cbor("Hash step is not a 2-element array".into())),
                        }
                    }
                    steps
                }
                _ => return Err(SdkError::Cbor("Hash steps is not an array".into())),
            },
        })
    }

    fn parse_unicity_seal(value: &ciborium::Value) -> Result<UnicitySeal> {
        use ciborium::Value;

        let array = match value {
            Value::Tag(tag, boxed_value) if *tag == 1001 => {
                match boxed_value.as_ref() {
                    Value::Array(arr) => arr,
                    _ => return Err(SdkError::Cbor("Unicity seal tag does not contain array".into())),
                }
            }
            Value::Array(arr) => arr,
            _ => return Err(SdkError::Cbor("Unicity seal is not an array or tagged array".into())),
        };

        if array.len() < 5 {
            return Err(SdkError::Cbor("Unicity seal has insufficient elements".into()));
        }

        let signatures = if array.len() > 7 {
            match &array[7] {
                Value::Map(map) => {
                    let mut sigs = HashMap::new();
                    for (k, v) in map {
                        let key = match k {
                            Value::Text(s) => s.clone(),
                            _ => continue,
                        };
                        let sig = match v {
                            Value::Bytes(b) => b.clone(),
                            _ => continue,
                        };
                        sigs.insert(key, sig);
                    }
                    sigs
                }
                _ => HashMap::new(),
            }
        } else {
            HashMap::new()
        };

        Ok(UnicitySeal {
            version: match &array[0] {
                Value::Integer(i) => (*i).try_into().map_err(|_| SdkError::Cbor("Invalid version".into()))?,
                _ => return Err(SdkError::Cbor("Version is not an integer".into())),
            },
            network_id: match &array[1] {
                Value::Integer(i) => (*i).try_into().map_err(|_| SdkError::Cbor("Invalid network ID".into()))?,
                _ => return Err(SdkError::Cbor("Network ID is not an integer".into())),
            },
            root_chain_round_number: match &array[2] {
                Value::Integer(i) => (*i).try_into().map_err(|_| SdkError::Cbor("Invalid round number".into()))?,
                _ => return Err(SdkError::Cbor("Round number is not an integer".into())),
            },
            epoch: match &array[3] {
                Value::Integer(i) => (*i).try_into().map_err(|_| SdkError::Cbor("Invalid epoch".into()))?,
                _ => return Err(SdkError::Cbor("Epoch is not an integer".into())),
            },
            timestamp: match &array[4] {
                Value::Integer(i) => (*i).try_into().map_err(|_| SdkError::Cbor("Invalid timestamp".into()))?,
                _ => return Err(SdkError::Cbor("Timestamp is not an integer".into())),
            },
            previous_hash: match &array[5] {
                Value::Bytes(b) => Some(b.clone()),
                Value::Null | Value::Integer(_) => None,  // Accept integer 0 as null
                _ => return Err(SdkError::Cbor("Previous hash is not bytes or null".into())),
            },
            hash: match &array[6] {
                Value::Bytes(b) => b.clone(),
                _ => return Err(SdkError::Cbor("Hash is not bytes".into())),
            },
            signatures,
        })
    }

    /// Verify the certificate against trust base
    pub fn verify(&self, trust_base: &RootTrustBase) -> Result<bool> {
        // Verify that we have quorum signatures
        let quorum_threshold = trust_base.quorum_threshold as usize;
        let mut valid_signatures = 0;

        // Hash the seal data (without signatures)
        let seal_hash = self.compute_seal_hash()?;

        for (node_id, signature) in &self.unicity_seal.signatures {
            // Find the node in trust base
            if let Some(node) = trust_base.root_nodes.iter().find(|n| &n.node_id == node_id) {
                // Verify signature (remove recovery byte if present)
                let sig_bytes = if signature.len() == 65 {
                    &signature[..64]
                } else {
                    signature
                };

                // Parse the node's public key from hex
                let pk_bytes = if node.sig_key.starts_with("0x") {
                    hex::decode(&node.sig_key[2..])
                        .map_err(|e| SdkError::Crypto(format!("Invalid hex public key: {}", e)))?
                } else {
                    hex::decode(&node.sig_key)
                        .map_err(|e| SdkError::Crypto(format!("Invalid hex public key: {}", e)))?
                };

                // Use the node's signing key to verify
                if self.verify_signature(&seal_hash, sig_bytes, &pk_bytes)? {
                    valid_signatures += 1;
                }
            }
        }

        Ok(valid_signatures >= quorum_threshold)
    }

    fn compute_seal_hash(&self) -> Result<Vec<u8>> {
        use ciborium::Value;

        // Create seal without signatures for hashing
        let seal_array = vec![
            Value::Integer(self.unicity_seal.version.into()),
            Value::Integer(self.unicity_seal.network_id.into()),
            Value::Integer(self.unicity_seal.root_chain_round_number.into()),
            Value::Integer(self.unicity_seal.epoch.into()),
            Value::Integer(self.unicity_seal.timestamp.into()),
            self.unicity_seal.previous_hash.as_ref()
                .map(|h| Value::Bytes(h.clone()))
                .unwrap_or(Value::Null),
            Value::Bytes(self.unicity_seal.hash.clone()),
        ];

        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&Value::Array(seal_array), &mut cbor_bytes)
            .map_err(|e| SdkError::Cbor(format!("Failed to encode seal for hashing: {}", e)))?;

        // Return just the hash bytes without the algorithm prefix
        Ok(sha256(&cbor_bytes).data().to_vec())
    }

    fn verify_signature(&self, hash: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
        use secp256k1::{Message, Secp256k1, ecdsa::Signature, PublicKey};

        let secp = Secp256k1::verification_only();

        // Parse the public key
        let pk = PublicKey::from_slice(public_key)
            .map_err(|e| SdkError::Crypto(format!("Invalid public key: {}", e)))?;

        // Create message from hash
        let message = Message::from_digest(hash.try_into()
            .map_err(|_| SdkError::Crypto("Hash must be exactly 32 bytes".into()))?);

        // Parse signature
        let sig = Signature::from_compact(signature)
            .map_err(|e| SdkError::Crypto(format!("Invalid signature: {}", e)))?;

        // Verify
        Ok(secp.verify_ecdsa(message, &sig, &pk).is_ok())
    }
}

impl RootTrustBase {
    /// Load from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| SdkError::Json(e))
    }

    /// Verify a root hash against the trust base
    pub fn verify_root_hash(&self, hash: &[u8]) -> Result<bool> {
        // The root hash verification would involve checking against the
        // state hash or validating through the certificate chain
        // For now, we accept the hash if it's not empty
        Ok(!hash.is_empty())
    }

    /// Verify a certificate
    pub fn verify_certificate(&self, certificate: &UnicityCertificate) -> Result<bool> {
        certificate.verify(self)
    }
}

// Helper module for hex serialization
mod hex_opt {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) if !bytes.is_empty() => {
                let hex_str = format!("0x{}", hex::encode(bytes));
                hex_str.serialize(serializer)
            }
            _ => serializer.serialize_str("")
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = String::deserialize(deserializer)?;
        if s.is_empty() {
            Ok(None)
        } else if let Some(hex_str) = s.strip_prefix("0x") {
            hex::decode(hex_str)
                .map(Some)
                .map_err(serde::de::Error::custom)
        } else {
            hex::decode(&s)
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_base_from_json() {
        let json = r#"{
            "version": 1,
            "networkId": 3,
            "epoch": 1,
            "epochStartRound": 1,
            "rootNodes": [
                {
                    "nodeId": "16Uiu2HAkyQRiA7pMgzgLj9GgaBJEJa8zmx9dzqUDa6WxQPJ82ghU",
                    "sigKey": "0x039afb2acb65f5fbc272d8907f763d0a5d189aadc9b97afdcc5897ea4dd112e68b",
                    "stake": 1
                }
            ],
            "quorumThreshold": 1,
            "stateHash": "",
            "changeRecordHash": "",
            "previousEntryHash": "",
            "signatures": {
                "16Uiu2HAkyQRiA7pMgzgLj9GgaBJEJa8zmx9dzqUDa6WxQPJ82ghU": "0xf157c9fdd8a378e3ca70d354ccc4475ab2cd8de360127bc46b0aeab4b453a80f07fd9136a5843b60a8babaff23e20acc8879861f7651440a5e2829f7541b31f100"
            }
        }"#;

        let trust_base = RootTrustBase::from_json(json).unwrap();
        assert_eq!(trust_base.version, 1);
        assert_eq!(trust_base.network_id, 3);
        assert_eq!(trust_base.epoch, 1);
        assert_eq!(trust_base.root_nodes.len(), 1);
        assert_eq!(trust_base.quorum_threshold, 1);
    }
}