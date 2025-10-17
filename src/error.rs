use crate::prelude::*;

#[cfg(feature = "std")]
use thiserror::Error;

extern crate alloc;
use alloc::string::String;
use core::fmt;

#[cfg_attr(feature = "std", derive(Error))]
#[derive(Debug)]
pub enum SdkError {
    #[cfg_attr(feature = "std", error("Cryptographic error: {0}"))]
    Crypto(String),

    #[cfg_attr(feature = "std", error("Serialization error: {0}"))]
    Serialization(String),

    #[cfg_attr(feature = "std", error("Network error: {0}"))]
    Network(String),

    #[cfg_attr(feature = "std", error("Validation error: {0}"))]
    Validation(String),

    #[cfg_attr(feature = "std", error("Token operation error: {0}"))]
    TokenOperation(String),

    #[cfg_attr(feature = "std", error("SMT error: {0}"))]
    SparseMerkleTree(String),

    #[cfg_attr(feature = "std", error("Address resolution error: {0}"))]
    AddressResolution(String),

    #[cfg_attr(feature = "std", error("JSON-RPC error: {code}: {message}"))]
    JsonRpc { code: i32, message: String },

    #[cfg_attr(feature = "std", error("Timeout error: operation timed out after {0} seconds"))]
    Timeout(u64),

    #[cfg_attr(feature = "std", error("Invalid parameter: {0}"))]
    InvalidParameter(String),

    #[cfg_attr(feature = "std", error("State transition error: {0}"))]
    StateTransition(String),

    #[cfg_attr(feature = "std", error("Aggregator error: {status} - {message}"))]
    Aggregator { status: String, message: String },

    #[cfg(feature = "std")]
    #[cfg_attr(feature = "std", error("IO error: {0}"))]
    Io(#[from] std::io::Error),

    #[cfg_attr(feature = "std", error("Hex decode error: {0}"))]
    #[cfg(feature = "std")]
    HexDecode(#[from] hex::FromHexError),

    #[cfg_attr(feature = "std", error("Hex decode error: {0}"))]
    #[cfg(not(feature = "std"))]
    HexDecode(hex::FromHexError),

    #[cfg(feature = "std")]
    #[cfg_attr(feature = "std", error("Base64 decode error: {0}"))]
    Base64Decode(#[from] base64::DecodeError),

    #[cfg_attr(feature = "std", error("Secp256k1 error: {0}"))]
    #[cfg(feature = "std")]
    Secp256k1(#[from] secp256k1::Error),

    #[cfg_attr(feature = "std", error("Secp256k1 error: {0}"))]
    #[cfg(not(feature = "std"))]
    Secp256k1(secp256k1::Error),

    #[cfg_attr(feature = "std", error("JSON error: {0}"))]
    #[cfg(feature = "std")]
    Json(#[from] serde_json::Error),

    #[cfg_attr(feature = "std", error("JSON error: {0}"))]
    #[cfg(not(feature = "std"))]
    Json(serde_json::Error),

    #[cfg_attr(feature = "std", error("CBOR error: {0}"))]
    Cbor(String),

    #[cfg(feature = "std")]
    #[cfg_attr(feature = "std", error("HTTP request error: {0}"))]
    Http(#[from] reqwest::Error),

    #[cfg_attr(feature = "std", error("Not implemented: {0}"))]
    NotImplemented(String),
}

// Implement Display for no_std environments
#[cfg(not(feature = "std"))]
impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SdkError::Crypto(msg) => write!(f, "Cryptographic error: {}", msg),
            SdkError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            SdkError::Network(msg) => write!(f, "Network error: {}", msg),
            SdkError::Validation(msg) => write!(f, "Validation error: {}", msg),
            SdkError::TokenOperation(msg) => write!(f, "Token operation error: {}", msg),
            SdkError::SparseMerkleTree(msg) => write!(f, "SMT error: {}", msg),
            SdkError::AddressResolution(msg) => write!(f, "Address resolution error: {}", msg),
            SdkError::JsonRpc { code, message } => write!(f, "JSON-RPC error: {}: {}", code, message),
            SdkError::Timeout(secs) => write!(f, "Timeout error: operation timed out after {} seconds", secs),
            SdkError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            SdkError::StateTransition(msg) => write!(f, "State transition error: {}", msg),
            SdkError::Aggregator { status, message } => write!(f, "Aggregator error: {} - {}", status, message),
            SdkError::HexDecode(e) => write!(f, "Hex decode error: {}", e),
            SdkError::Secp256k1(e) => write!(f, "Secp256k1 error: {}", e),
            SdkError::Json(e) => write!(f, "JSON error: {}", e),
            SdkError::Cbor(msg) => write!(f, "CBOR error: {}", msg),
            SdkError::NotImplemented(msg) => write!(f, "Not implemented: {}", msg),
        }
    }
}

pub type Result<T> = core::result::Result<T, SdkError>;

// Manual From implementations for no_std mode
#[cfg(not(feature = "std"))]
impl From<secp256k1::Error> for SdkError {
    fn from(err: secp256k1::Error) -> Self {
        SdkError::Secp256k1(err)
    }
}

#[cfg(not(feature = "std"))]
impl From<hex::FromHexError> for SdkError {
    fn from(err: hex::FromHexError) -> Self {
        SdkError::HexDecode(err)
    }
}

#[cfg(not(feature = "std"))]
impl From<serde_json::Error> for SdkError {
    fn from(err: serde_json::Error) -> Self {
        SdkError::Json(err)
    }
}
