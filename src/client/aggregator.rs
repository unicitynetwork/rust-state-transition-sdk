use crate::client::jsonrpc::JsonRpcHttpTransport;
use crate::error::{Result, SdkError};
use crate::types::commitment::{Authenticator, Commitment};
use crate::types::primitives::{DataHash, RequestId};
use crate::types::transaction::InclusionProof;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

/// Submit commitment request - matches Java SDK exactly
#[derive(Debug, Serialize)]
pub struct SubmitCommitmentRequest {
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    pub authenticator: AuthenticatorDto,
    pub receipt: bool,
}

/// Authenticator DTO for JSON serialization - matches Java SDK exactly
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorDto {
    pub algorithm: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub signature: String,
    #[serde(rename = "stateHash")]
    pub state_hash: String,
}

impl From<&Authenticator> for AuthenticatorDto {
    fn from(auth: &Authenticator) -> Self {
        Self {
            algorithm: auth.algorithm.clone(),
            public_key: hex::encode(auth.public_key.as_bytes()),
            signature: hex::encode(auth.signature.as_bytes()),
            state_hash: hex::encode(auth.state_hash.imprint()),
        }
    }
}

/// Submit commitment response
#[derive(Debug, Deserialize)]
pub struct SubmitCommitmentResponse {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl SubmitCommitmentResponse {
    /// Check if the response indicates success
    pub fn is_success(&self) -> bool {
        let status_lower = self.status.to_lowercase();
        status_lower == "success" || status_lower == "accepted"
    }

    /// Get a descriptive error message
    pub fn error_message(&self) -> String {
        if let Some(err) = &self.error {
            return err.clone();
        }
        if let Some(msg) = &self.message {
            return msg.clone();
        }
        if let Some(details) = &self.details {
            return format!("Status: {}, Details: {}", self.status, details);
        }
        format!("Status: {}", self.status)
    }
}

/// Inclusion proof response wrapper
#[derive(Debug, Deserialize)]
pub struct GetInclusionProofResponse {
    #[serde(default, rename = "inclusionProof")]
    pub inclusion_proof: Option<InclusionProofDto>,
}

/// Inclusion proof data
#[derive(Debug, Deserialize)]
pub struct InclusionProofDto {
    #[serde(rename = "merkleTreePath")]
    pub merkle_tree_path: MerkleTreePathDto,
    #[serde(default)]
    pub authenticator: Option<serde_json::Value>, // Can be null
    #[serde(default, rename = "transactionHash")]
    pub transaction_hash: Option<String>, // Can be null
    #[serde(default, rename = "unicityCertificate")]
    pub unicity_certificate: Option<String>, // Certificate data
}

/// Merkle tree path DTO
#[derive(Debug, Deserialize)]
pub struct MerkleTreePathDto {
    pub root: String,
    pub steps: Vec<MerkleStepDto>,
}

/// Merkle step DTO
#[derive(Debug, Deserialize)]
pub struct MerkleStepDto {
    pub branch: Vec<String>,
    pub path: String,
    pub sibling: Vec<String>,
}


/// Block height response
#[derive(Debug, Deserialize)]
pub struct BlockHeightResponse {
    #[serde(rename = "blockNumber")]
    pub block_number: String, // Note: returned as string, not u64
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
        // Build request matching Java SDK structure exactly
        let request_id = hex::encode(commitment.request_id().as_data_hash().imprint());
        let transaction_hash = hex::encode(commitment.transaction_hash().imprint());
        let authenticator = AuthenticatorDto::from(commitment.authenticator());

        let params = json!({
            "requestId": request_id,
            "transactionHash": transaction_hash,
            "authenticator": authenticator,
            "receipt": false,
        });

        let response = self
            .transport
            .send_request("submit_commitment", params)
            .await?;

        // Debug: Print raw response
        tracing::debug!("Raw response from aggregator: {:?}", response);

        let parsed: SubmitCommitmentResponse = serde_json::from_value(response).map_err(|e| SdkError::Json(e))?;

        tracing::info!(
            "Commitment submission result: status={}, message={:?}, error={:?}",
            parsed.status,
            parsed.message,
            parsed.error
        );

        Ok(parsed)
    }

    /// Submit raw commitment
    pub async fn submit_commitment_raw(
        &self,
        request_id: &RequestId,
        transaction_hash: &DataHash,
        authenticator: &Authenticator,
    ) -> Result<SubmitCommitmentResponse> {
        let request_id = hex::encode(request_id.as_data_hash().imprint());
        let transaction_hash = hex::encode(transaction_hash.imprint());
        let authenticator = AuthenticatorDto::from(authenticator);

        let params = json!({
            "requestId": request_id,
            "transactionHash": transaction_hash,
            "authenticator": authenticator,
            "receipt": false,
        });

        let response = self
            .transport
            .send_request("submit_commitment", params)
            .await?;

        // Debug: Print raw response
        tracing::debug!("Raw response from aggregator: {:?}", response);

        let parsed: SubmitCommitmentResponse = serde_json::from_value(response).map_err(|e| SdkError::Json(e))?;

        tracing::info!(
            "Commitment submission result: status={}, message={:?}, error={:?}",
            parsed.status,
            parsed.message,
            parsed.error
        );

        Ok(parsed)
    }

    /// Get inclusion proof for a request
    pub async fn get_inclusion_proof(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<InclusionProof>> {
        let request_id_hex = hex::encode(request_id.as_data_hash().imprint());

        let params = json!({
            "requestId": request_id_hex,
        });

        let response = self
            .transport
            .send_request("get_inclusion_proof", params)
            .await?;

        let proof_response: GetInclusionProofResponse =
            serde_json::from_value(response).map_err(|e| SdkError::Json(e))?;

        // Convert the inclusion proof response to our domain model
        if let Some(inclusion_proof_dto) = proof_response.inclusion_proof {
            use crate::types::transaction::{MerkleTreePath, MerkleTreePathStep};

            // Convert MerkleTreePathDto to MerkleTreePath
            let steps: Vec<MerkleTreePathStep> = inclusion_proof_dto.merkle_tree_path.steps
                .into_iter()
                .map(|step| MerkleTreePathStep {
                    path: serde_json::Value::String(step.path),
                    sibling: step.sibling,
                    branch: step.branch.into_iter().map(Some).collect(),
                })
                .collect();

            let merkle_tree_path = MerkleTreePath {
                root: inclusion_proof_dto.merkle_tree_path.root,
                steps,
            };

            // Parse certificate if present
            let certificate = if let Some(cert_hex) = inclusion_proof_dto.unicity_certificate {
                Some(hex::decode(cert_hex)?)
            } else {
                None
            };

            if let Some(cert) = certificate {
                Ok(Some(InclusionProof::with_certificate(merkle_tree_path, cert)))
            } else {
                Ok(Some(InclusionProof::new(merkle_tree_path)))
            }
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
                    // No proof yet, continue polling
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

        // Parse the string block number to u64
        height_response
            .block_number
            .parse::<u64>()
            .map_err(|e| SdkError::InvalidParameter(format!("Invalid block number: {}", e)))
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
    use crate::crypto::KeyPair;
    use crate::types::primitives::Signature;

    #[test]
    fn test_authenticator_dto_conversion() {
        let key_pair = KeyPair::generate().unwrap();
        let public_key = key_pair.public_key().clone();
        let signature = Signature::new([0u8; 65]);
        let state_hash = crate::crypto::sha256(b"test");
        let authenticator = Authenticator::new(public_key, signature, state_hash);

        let dto = AuthenticatorDto::from(&authenticator);
        assert_eq!(dto.algorithm, "secp256k1");
        assert_eq!(dto.public_key.len(), 66); // 33 bytes hex encoded
        assert_eq!(dto.signature.len(), 130); // 65 bytes hex encoded
        assert_eq!(dto.state_hash.len(), 68); // 34 bytes (2 algo + 32 hash) hex encoded
    }

}
