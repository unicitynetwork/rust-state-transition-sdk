use thiserror::Error;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Token operation error: {0}")]
    TokenOperation(String),

    #[error("SMT error: {0}")]
    SparseMerkleTree(String),

    #[error("Address resolution error: {0}")]
    AddressResolution(String),

    #[error("JSON-RPC error: {code}: {message}")]
    JsonRpc { code: i32, message: String },

    #[error("Timeout error: operation timed out after {0} seconds")]
    Timeout(u64),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("State transition error: {0}")]
    StateTransition(String),

    #[error("Aggregator error: {status} - {message}")]
    Aggregator { status: String, message: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("CBOR error: {0}")]
    Cbor(String),

    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

pub type Result<T> = std::result::Result<T, SdkError>;
