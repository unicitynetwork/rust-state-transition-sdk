use crate::error::{Result, SdkError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};

/// JSON-RPC version
const JSONRPC_VERSION: &str = "2.0";

/// JSON-RPC request
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Value,
    pub id: u64,
}

impl JsonRpcRequest {
    /// Create a new JSON-RPC request
    pub fn new(method: String, params: Value, id: u64) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method,
            params,
            id,
        }
    }
}

/// JSON-RPC response
#[derive(Debug, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: u64,
}

/// JSON-RPC error
#[derive(Debug, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// JSON-RPC HTTP transport
#[derive(Clone)]
pub struct JsonRpcHttpTransport {
    client: reqwest::Client,
    url: String,
    request_id: std::sync::Arc<AtomicU64>,
}

impl JsonRpcHttpTransport {
    /// Create a new JSON-RPC HTTP transport
    pub fn new(url: String) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| SdkError::Network(e.to_string()))?;

        Ok(Self {
            client,
            url,
            request_id: std::sync::Arc::new(AtomicU64::new(1)),
        })
    }

    /// Send a JSON-RPC request
    pub async fn send_request(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.request_id.fetch_add(1, Ordering::SeqCst);
        let request = JsonRpcRequest::new(method.to_string(), params, id);

        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| SdkError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(SdkError::Network(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        let json_response: JsonRpcResponse = response
            .json()
            .await
            .map_err(|e| SdkError::Network(e.to_string()))?;

        if let Some(error) = json_response.error {
            return Err(SdkError::JsonRpc {
                code: error.code,
                message: error.message,
            });
        }

        json_response
            .result
            .ok_or_else(|| SdkError::Network("Empty response".to_string()))
    }

    /// Send a batch of JSON-RPC requests
    pub async fn send_batch(&self, requests: Vec<(&str, Value)>) -> Result<Vec<Result<Value>>> {
        let mut batch_requests = Vec::new();

        for (method, params) in requests {
            let id = self.request_id.fetch_add(1, Ordering::SeqCst);
            batch_requests.push(JsonRpcRequest::new(method.to_string(), params, id));
        }

        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .json(&batch_requests)
            .send()
            .await
            .map_err(|e| SdkError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(SdkError::Network(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        let json_responses: Vec<JsonRpcResponse> = response
            .json()
            .await
            .map_err(|e| SdkError::Network(e.to_string()))?;

        let mut results = Vec::new();
        for response in json_responses {
            if let Some(error) = response.error {
                results.push(Err(SdkError::JsonRpc {
                    code: error.code,
                    message: error.message,
                }));
            } else if let Some(result) = response.result {
                results.push(Ok(result));
            } else {
                results.push(Err(SdkError::Network("Empty response".to_string())));
            }
        }

        Ok(results)
    }

    /// Get the URL
    pub fn url(&self) -> &str {
        &self.url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_creation() {
        let request = JsonRpcRequest::new(
            "test_method".to_string(),
            serde_json::json!({"param": "value"}),
            1,
        );

        assert_eq!(request.jsonrpc, "2.0");
        assert_eq!(request.method, "test_method");
        assert_eq!(request.id, 1);
    }

    #[test]
    fn test_error_deserialization() {
        let error_json = r#"{
            "code": -32600,
            "message": "Invalid Request",
            "data": {"detail": "Missing parameter"}
        }"#;

        let error: JsonRpcError = serde_json::from_str(error_json).unwrap();
        assert_eq!(error.code, -32600);
        assert_eq!(error.message, "Invalid Request");
        assert!(error.data.is_some());
    }

    #[test]
    fn test_response_deserialization() {
        let response_json = r#"{
            "jsonrpc": "2.0",
            "result": {"value": 42},
            "id": 1
        }"#;

        let response: JsonRpcResponse = serde_json::from_str(response_json).unwrap();
        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.result.is_some());
        assert!(response.error.is_none());
        assert_eq!(response.id, 1);
    }
}