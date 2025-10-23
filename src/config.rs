//! Configuration settings for AES encryption operations.
//!
//! This module provides configurable parameters for encryption/decryption
//! operations, including salt size, IV size, key size, and PBKDF2 iterations.

use wasm_bindgen::prelude::*;
use crate::error::{AesError, ErrorCode, Result};

/// Default salt size in bytes
pub const DEFAULT_SALT_SIZE: usize = 16;

/// Default initialization vector size in bytes
pub const DEFAULT_IV_SIZE: usize = 16;

/// Default key size in bytes (256 bits = 32 bytes)
pub const DEFAULT_KEY_SIZE: usize = 32;

/// Default PBKDF2 iterations for key derivation
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 100_000;

/// Minimum allowed PBKDF2 iterations (for security)
pub const MIN_PBKDF2_ITERATIONS: u32 = 10_000;

/// Maximum allowed PBKDF2 iterations (to prevent DoS)
pub const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;

/// Configuration for AES encryption operations.
///
/// This struct allows customization of encryption parameters while
/// maintaining secure defaults. All sizes are in bytes.
///
/// # Examples
///
/// ```ignore
/// // Use default configuration
/// let config = AesConfig::default();
///
/// // Create custom configuration
/// let config = AesConfig::new()
///     .with_pbkdf2_iterations(200_000)
///     .build();
/// ```
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesConfig {
    salt_size: usize,
    iv_size: usize,
    key_size: usize,
    pbkdf2_iterations: u32,
}

#[wasm_bindgen]
impl AesConfig {
    /// Create a new configuration with default values.
    ///
    /// # Returns
    ///
    /// A new `AesConfig` instance with secure defaults:
    /// - Salt size: 16 bytes
    /// - IV size: 16 bytes
    /// - Key size: 32 bytes (AES-256)
    /// - PBKDF2 iterations: 100,000
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the salt size in bytes.
    #[wasm_bindgen(getter, js_name = saltSize)]
    pub fn salt_size(&self) -> usize {
        self.salt_size
    }

    /// Get the IV (Initialization Vector) size in bytes.
    #[wasm_bindgen(getter, js_name = ivSize)]
    pub fn iv_size(&self) -> usize {
        self.iv_size
    }

    /// Get the key size in bytes.
    #[wasm_bindgen(getter, js_name = keySize)]
    pub fn key_size(&self) -> usize {
        self.key_size
    }

    /// Get the number of PBKDF2 iterations.
    #[wasm_bindgen(getter, js_name = pbkdf2Iterations)]
    pub fn pbkdf2_iterations(&self) -> u32 {
        self.pbkdf2_iterations
    }

    /// Set the number of PBKDF2 iterations.
    ///
    /// # Arguments
    ///
    /// * `iterations` - Number of iterations (must be between 10,000 and 10,000,000)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if valid, or an error if the value is out of range.
    ///
    /// # Errors
    ///
    /// Returns `InvalidConfiguration` if iterations are outside the valid range.
    #[wasm_bindgen(js_name = setPbkdf2Iterations)]
    pub fn set_pbkdf2_iterations(&mut self, iterations: u32) -> std::result::Result<(), JsValue> {
        self.validate_pbkdf2_iterations(iterations)
            .map_err(|e| JsValue::from(e))?;
        self.pbkdf2_iterations = iterations;
        Ok(())
    }

    /// Get the minimum header size (salt + IV) in bytes.
    #[wasm_bindgen(getter, js_name = headerSize)]
    pub fn header_size(&self) -> usize {
        self.salt_size + self.iv_size
    }

    /// Get the minimum encrypted data size in bytes.
    #[wasm_bindgen(getter, js_name = minEncryptedSize)]
    pub fn min_encrypted_size(&self) -> usize {
        self.header_size() + 16 // minimum one block
    }

    /// Validate that the given data size is sufficient for encrypted data.
    ///
    /// # Arguments
    ///
    /// * `size` - The size to validate
    ///
    /// # Returns
    ///
    /// Returns `true` if the size is valid, `false` otherwise.
    #[wasm_bindgen(js_name = isValidEncryptedSize)]
    pub fn is_valid_encrypted_size(&self, size: usize) -> bool {
        size >= self.min_encrypted_size()
    }
}

impl AesConfig {
    /// Validate PBKDF2 iterations value.
    fn validate_pbkdf2_iterations(&self, iterations: u32) -> Result<()> {
        if iterations < MIN_PBKDF2_ITERATIONS {
            return Err(AesError::new(
                ErrorCode::InvalidConfiguration,
                format!(
                    "PBKDF2 iterations ({}) below minimum ({}). This is insecure.",
                    iterations, MIN_PBKDF2_ITERATIONS
                ),
            ));
        }
        if iterations > MAX_PBKDF2_ITERATIONS {
            return Err(AesError::new(
                ErrorCode::InvalidConfiguration,
                format!(
                    "PBKDF2 iterations ({}) exceeds maximum ({}). This could cause performance issues.",
                    iterations, MAX_PBKDF2_ITERATIONS
                ),
            ));
        }
        Ok(())
    }

    /// Validate the entire configuration.
    pub fn validate(&self) -> Result<()> {
        // Validate PBKDF2 iterations
        self.validate_pbkdf2_iterations(self.pbkdf2_iterations)?;

        // Validate salt size
        if self.salt_size < 8 {
            return Err(AesError::new(
                ErrorCode::InvalidConfiguration,
                format!("Salt size ({}) is too small. Minimum is 8 bytes.", self.salt_size),
            ));
        }

        // Validate IV size (must be 16 for AES)
        if self.iv_size != 16 {
            return Err(AesError::new(
                ErrorCode::InvalidConfiguration,
                format!("IV size must be 16 bytes for AES-CBC, got {}", self.iv_size),
            ));
        }

        // Validate key size (must be 32 for AES-256)
        if self.key_size != 32 {
            return Err(AesError::new(
                ErrorCode::InvalidConfiguration,
                format!("Key size must be 32 bytes for AES-256, got {}", self.key_size),
            ));
        }

        Ok(())
    }
}

impl Default for AesConfig {
    fn default() -> Self {
        Self {
            salt_size: DEFAULT_SALT_SIZE,
            iv_size: DEFAULT_IV_SIZE,
            key_size: DEFAULT_KEY_SIZE,
            pbkdf2_iterations: DEFAULT_PBKDF2_ITERATIONS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AesConfig::default();
        assert_eq!(config.salt_size(), 16);
        assert_eq!(config.iv_size(), 16);
        assert_eq!(config.key_size(), 32);
        assert_eq!(config.pbkdf2_iterations(), 100_000);
    }

    #[test]
    fn test_header_size() {
        let config = AesConfig::default();
        assert_eq!(config.header_size(), 32); // 16 + 16
    }

    #[test]
    fn test_min_encrypted_size() {
        let config = AesConfig::default();
        assert_eq!(config.min_encrypted_size(), 48); // 32 + 16
    }

    #[test]
    fn test_valid_encrypted_size() {
        let config = AesConfig::default();
        assert!(!config.is_valid_encrypted_size(0));
        assert!(!config.is_valid_encrypted_size(32));
        assert!(config.is_valid_encrypted_size(48));
        assert!(config.is_valid_encrypted_size(100));
    }

    #[test]
    fn test_set_pbkdf2_iterations_valid() {
        let mut config = AesConfig::default();
        assert!(config.set_pbkdf2_iterations(200_000).is_ok());
        assert_eq!(config.pbkdf2_iterations(), 200_000);
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_set_pbkdf2_iterations_too_low() {
        let mut config = AesConfig::default();
        let result = config.set_pbkdf2_iterations(5_000);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_set_pbkdf2_iterations_too_high() {
        let mut config = AesConfig::default();
        let result = config.set_pbkdf2_iterations(20_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_default_config() {
        let config = AesConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_pbkdf2_iterations() {
        let config = AesConfig {
            pbkdf2_iterations: 5_000,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }
}
