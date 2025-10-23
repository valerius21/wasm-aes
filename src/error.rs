//! Error types and codes for AES encryption operations.
//!
//! This module provides structured error handling with specific error codes
//! that can be used by both Rust and JavaScript consumers.

use wasm_bindgen::prelude::*;
use std::fmt;

/// Error codes for AES encryption/decryption operations
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Invalid input data (e.g., empty, too short)
    InvalidInput = 1000,
    /// Invalid encryption parameters
    InvalidParameters = 1001,
    /// Encryption operation failed
    EncryptionFailed = 2000,
    /// Decryption operation failed (wrong password or corrupted data)
    DecryptionFailed = 2001,
    /// Invalid encrypted data format
    InvalidFormat = 3000,
    /// Data too short to be valid encrypted data
    DataTooShort = 3001,
    /// Invalid configuration values
    InvalidConfiguration = 4000,
}

/// Detailed error information for AES operations
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct AesError {
    code: ErrorCode,
    message: String,
}

#[wasm_bindgen]
impl AesError {
    /// Create a new AesError with the given code and message
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Get the error code
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> u32 {
        self.code as u32
    }

    /// Get the error message
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> String {
        self.message.clone()
    }

    /// Get the full error description
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string_js(&self) -> String {
        format!("[Error {}] {}", self.code as u32, self.message)
    }
}

impl fmt::Display for AesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[Error {}] {}", self.code as u32, self.message)
    }
}

impl std::error::Error for AesError {}

/// Convenience type alias for Results in this crate
pub type Result<T> = std::result::Result<T, AesError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = AesError::new(ErrorCode::InvalidInput, "Test error");
        assert_eq!(err.code(), 1000);
        assert_eq!(err.message(), "Test error");
    }

    #[test]
    fn test_error_display() {
        let err = AesError::new(ErrorCode::DecryptionFailed, "Bad password");
        let display = err.to_string();
        assert!(display.contains("2001"));
        assert!(display.contains("Bad password"));
    }

    #[test]
    fn test_error_codes_unique() {
        let codes = vec![
            ErrorCode::InvalidInput as u32,
            ErrorCode::InvalidParameters as u32,
            ErrorCode::EncryptionFailed as u32,
            ErrorCode::DecryptionFailed as u32,
            ErrorCode::InvalidFormat as u32,
            ErrorCode::DataTooShort as u32,
            ErrorCode::InvalidConfiguration as u32,
        ];

        let unique_count = codes.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(unique_count, codes.len(), "Error codes must be unique");
    }
}
