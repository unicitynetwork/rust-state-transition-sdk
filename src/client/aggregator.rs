use crate::client::jsonrpc::JsonRpcHttpTransport;
use crate::error::{Result, SdkError};
use crate::types::commitment::{Authenticator, Commitment};
use crate::types::primitives::{DataHash, RequestId};
use crate::types::transaction::InclusionProof;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

/// Submit commitment request
#[derive(Debug, Serialize)]
pub struct SubmitCommitmentRequest {
    pub request_id: String,
    pub state_hash: String,
    pub authenticator: AuthenticatorDto,
}

/// Authenticator DTO for JSON serialization
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorDto {
    pub public_key: String,
    pub signature: String,
}

impl From<&Authenticator> for AuthenticatorDto {
    fn from(auth: &Authenticator) -> Self {
        Self {
            public_key: hex::encode(auth.public_key.as_bytes()),
            signature: hex::encode(auth.signature.as_bytes()),
        }
    }
}

/// Submit commitment response
#[derive(Debug, Deserialize)]
pub struct SubmitCommitmentResponse {
    pub request_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Get inclusion proof response
#[derive(Debug, Deserialize)]
pub struct GetInclusionProofResponse {
    pub request_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<InclusionProofDto>,
}

/// Inclusion proof DTO
#[derive(Debug, Deserialize)]
pub struct InclusionProofDto {
    pub block_height: u64,
    pub path: Vec<PathElementDto>,
    pub root: String,
}

/// Path element DTO
#[derive(Debug, Deserialize)]
pub struct PathElementDto {
    pub direction: String,
    pub hash: String,
}

impl InclusionProofDto {
    /// Convert to domain model
    pub fn to_domain(&self) -> Result<InclusionProof> {
        use crate::types::transaction::{PathDirection, PathElement};

        let mut path = Vec::new();
        for element in &self.path {
            let direction = match element.direction.as_str() {
                "left" => PathDirection::Left,
                "right" => PathDirection::Right,
                _ => {
                    return Err(SdkError::InvalidParameter(format!(
                        "Invalid path direction: {}",
                        element.direction
                    )))
                }
            };

            let hash_bytes = hex::decode(&element.hash)?;
            let hash = DataHash::from_imprint(&hash_bytes)?;
            path.push(PathElement::new(direction, hash));
        }

        let root_bytes = hex::decode(&self.root)?;
        let root = DataHash::from_imprint(&root_bytes)?;

        Ok(InclusionProof::new(self.block_height, path, root))
    }
}

/// Block height response
#[derive(Debug, Deserialize)]
pub struct BlockHeightResponse {
    pub block_height: u64,
}

/// Aggregator client for low-level API access
#[derive(Clone)]
pub struct AggregatorClient {
    transport: JsonRpcHttpTransport,
}

impl AggregatorClient {
    /// Create a new aggregator client
    pub fn new(url: String) -> Result<Self> {
        let transport = JsonRpcHttpTransport::new(url)?;
        Ok(Self { transport })
    }

    /// Submit a commitment to the aggregator
    pub async fn submit_commitment(
        &self,
        commitment: &dyn Commitment,
    ) -> Result<SubmitCommitmentResponse> {
        let request_id = hex::encode(commitment.request_id().as_data_hash().imprint());
        let state_hash = hex::encode(commitment.state_hash().imprint());
        let authenticator = AuthenticatorDto::from(commitment.authenticator());

        let params = json!({
            "request_id": request_id,
            "state_hash": state_hash,
            "authenticator": authenticator,
        });

        let response = self.transport.send_request("submit_commitment", params).await?;
        serde_json::from_value(response).map_err(|e| SdkError::Json(e))
    }

    /// Submit raw commitment
    pub async fn submit_commitment_raw(
        &self,
        request_id: &RequestId,
        state_hash: &DataHash,
        authenticator: &Authenticator,
    ) -> Result<SubmitCommitmentResponse> {
        let request_id = hex::encode(request_id.as_data_hash().imprint());
        let state_hash = hex::encode(state_hash.imprint());
        let authenticator = AuthenticatorDto::from(authenticator);

        let params = json!({
            "request_id": request_id,
            "state_hash": state_hash,
            "authenticator": authenticator,
        });

        let response = self.transport.send_request("submit_commitment", params).await?;
        serde_json::from_value(response).map_err(|e| SdkError::Json(e))
    }

    /// Get inclusion proof for a request
    pub async fn get_inclusion_proof(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<InclusionProof>> {
        let request_id_hex = hex::encode(request_id.as_data_hash().imprint());

        let params = json!({
            "request_id": request_id_hex,
        });

        let response = self.transport.send_request("get_inclusion_proof", params).await?;
        let proof_response: GetInclusionProofResponse =
            serde_json::from_value(response).map_err(|e| SdkError::Json(e))?;

        if let Some(proof_dto) = proof_response.inclusion_proof {
            Ok(Some(proof_dto.to_domain()?))
        } else {
            Ok(None)
        }
    }

    /// Wait for inclusion proof with timeout
    pub async fn wait_for_inclusion_proof(
        &self,
        request_id: &RequestId,
        timeout: Duration,
    ) -> Result<InclusionProof> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(500);

        loop {
            if start.elapsed() > timeout {
                return Err(SdkError::Timeout(timeout.as_secs()));
            }

            match self.get_inclusion_proof(request_id).await {
                Ok(Some(proof)) => return Ok(proof),
                Ok(None) => {
                    tokio::time::sleep(poll_interval).await;
                }
                Err(e) => {
                    // Log error and retry
                    tracing::debug!("Error getting inclusion proof: {}", e);
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }
    }

    /// Get current block height
    pub async fn get_block_height(&self) -> Result<u64> {
        let response = self
            .transport
            .send_request("get_block_height", json!({}))
            .await?;
        let height_response: BlockHeightResponse =
            serde_json::from_value(response).map_err(|e| SdkError::Json(e))?;
        Ok(height_response.block_height)
    }

    /// Health check
    pub async fn health_check(&self) -> Result<bool> {
        match self.get_block_height().await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get the aggregator URL
    pub fn url(&self) -> &str {
        self.transport.url()
    }
}

/// Inclusion proof utilities
pub struct InclusionProofUtils;

impl InclusionProofUtils {
    /// Wait for inclusion proof with default timeout
    pub async fn wait_inclusion_proof(
        client: &AggregatorClient,
        request_id: &RequestId,
    ) -> Result<InclusionProof> {
        client
            .wait_for_inclusion_proof(request_id, Duration::from_secs(30))
            .await
    }

    /// Wait for inclusion proof with custom timeout
    pub async fn wait_inclusion_proof_with_timeout(
        client: &AggregatorClient,
        request_id: &RequestId,
        timeout: Duration,
    ) -> Result<InclusionProof> {
        client.wait_for_inclusion_proof(request_id, timeout).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authenticator_dto_conversion() {
        use crate::crypto::KeyPair;
        use crate::types::primitives::Signature;

        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let signature = Signature::new([0u8; 65]);
        let authenticator = Authenticator::new(public_key, signature);

        let dto = AuthenticatorDto::from(&authenticator);
        assert_eq!(dto.public_key.len(), 66); // 33 bytes hex encoded
        assert_eq!(dto.signature.len(), 130); // 65 bytes hex encoded
    }

    #[test]
    fn test_inclusion_proof_dto_conversion() {
        let dto = InclusionProofDto {
            block_height: 100,
            path: vec![
                PathElementDto {
                    direction: "left".to_string(),
                    hash: "0000".to_string() + &hex::encode(vec![1u8; 32]),
                },
                PathElementDto {
                    direction: "right".to_string(),
                    hash: "0000".to_string() + &hex::encode(vec![2u8; 32]),
                },
            ],
            root: "0000".to_string() + &hex::encode(vec![3u8; 32]),
        };

        let proof = dto.to_domain().unwrap();
        assert_eq!(proof.block_height, 100);
        assert_eq!(proof.path.len(), 2);
    }
}