//! # WASM AES-256 File Encryption Library
//!
//! A WebAssembly library for secure file encryption using AES-256-CBC.
//!
//! ## Features
//!
//! - **AES-256-CBC encryption** with PKCS7 padding
//! - **PBKDF2-HMAC-SHA256** key derivation with configurable iterations
//! - **Random salt and IV** generation for each encryption
//! - **Configurable parameters** exposed to JavaScript
//! - **Comprehensive error handling** with error codes
//! - **Well-documented** with examples and tests
//!
//! ## Security
//!
//! - Uses industry-standard cryptographic algorithms
//! - Default 100,000 PBKDF2 iterations (configurable)
//! - Random salt and IV for each encryption operation
//! - No data transmitted to servers (client-side only)
//!
//! ## Usage from JavaScript
//!
//! ```javascript
//! import init, { AesConfig, encrypt_aes256, decrypt_aes256 } from "./pkg/wasm_aes.js";
//!
//! await init();
//!
//! // Use default configuration
//! const config = new AesConfig();
//! const data = new Uint8Array([1, 2, 3, 4, 5]);
//! const password = "my_secure_password";
//!
//! // Encrypt
//! const encrypted = encrypt_aes256(data, password, config);
//!
//! // Decrypt
//! const decrypted = decrypt_aes256(encrypted, password, config);
//!
//! // Custom configuration
//! const customConfig = new AesConfig();
//! customConfig.setPbkdf2Iterations(200000);
//! ```
//!
//! ## Usage from Rust
//!
//! ```ignore
//! use wasm_aes::{AesConfig, encrypt_aes256, decrypt_aes256};
//!
//! let data = b"Hello, World!";
//! let password = "my_secure_password";
//! let config = AesConfig::default();
//!
//! let encrypted = encrypt_aes256(data, password, &config)?;
//! let decrypted = decrypt_aes256(&encrypted, password, &config)?;
//! ```

use wasm_bindgen::prelude::*;

// Module declarations
mod config;
mod crypto;
mod error;

// Re-export public API
pub use config::AesConfig;
pub use error::{AesError, ErrorCode};

// Import crypto functions
use crypto::{encrypt_aes256 as encrypt_impl, decrypt_aes256 as decrypt_impl};

/// Encrypts data using AES-256-CBC with a password.
///
/// This function provides a WebAssembly interface to the encryption functionality.
///
/// # Arguments
///
/// * `data` - The plaintext data to encrypt
/// * `password` - The password to derive the encryption key from
/// * `config` - Configuration parameters for encryption
///
/// # Returns
///
/// Returns encrypted data in the format: `[salt | iv | ciphertext]`
///
/// # Errors
///
/// Returns a JavaScript error if:
/// - Input data is empty
/// - Password is empty
/// - Configuration is invalid
/// - Encryption fails
///
/// # Examples
///
/// ```javascript
/// const data = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
/// const password = "secure_password";
/// const config = new AesConfig();
///
/// try {
///   const encrypted = encrypt_aes256(data, password, config);
///   console.log("Encrypted:", encrypted);
/// } catch (error) {
///   console.error("Encryption failed:", error);
/// }
/// ```
#[wasm_bindgen]
pub fn encrypt_aes256(data: &[u8], password: &str, config: &AesConfig) -> Result<Vec<u8>, JsValue> {
    encrypt_impl(data, password, config)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Decrypts data that was encrypted with `encrypt_aes256`.
///
/// This function provides a WebAssembly interface to the decryption functionality.
///
/// # Arguments
///
/// * `encrypted_data` - The encrypted data (format: `[salt | iv | ciphertext]`)
/// * `password` - The password used during encryption
/// * `config` - Configuration parameters (must match encryption config)
///
/// # Returns
///
/// Returns the original plaintext data.
///
/// # Errors
///
/// Returns a JavaScript error if:
/// - Password is incorrect
/// - Data is corrupted
/// - Data format is invalid
/// - Configuration is invalid
///
/// # Examples
///
/// ```javascript
/// const encrypted = encrypt_aes256(data, password, config);
///
/// try {
///   const decrypted = decrypt_aes256(encrypted, password, config);
///   console.log("Decrypted:", decrypted);
/// } catch (error) {
///   console.error("Decryption failed:", error);
/// }
/// ```
#[wasm_bindgen]
pub fn decrypt_aes256(encrypted_data: &[u8], password: &str, config: &AesConfig) -> Result<Vec<u8>, JsValue> {
    decrypt_impl(encrypted_data, password, config)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Get the library version.
///
/// # Returns
///
/// Returns the version string from Cargo.toml.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Get information about the default configuration.
///
/// # Returns
///
/// Returns a human-readable string describing the default configuration.
#[wasm_bindgen]
pub fn default_config_info() -> String {
    let config = AesConfig::default();
    format!(
        "AES-256-CBC Encryption\n\
         Salt Size: {} bytes\n\
         IV Size: {} bytes\n\
         Key Size: {} bytes (AES-256)\n\
         PBKDF2 Iterations: {}\n\
         Min Encrypted Size: {} bytes",
        config.salt_size(),
        config.iv_size(),
        config.key_size(),
        config.pbkdf2_iterations(),
        config.min_encrypted_size()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let version = version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_default_config_info() {
        let info = default_config_info();
        assert!(info.contains("AES-256"));
        assert!(info.contains("100000"));
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_wasm_encrypt_decrypt() {
        let data = b"Test data for WASM";
        let password = "test_password";
        let config = AesConfig::default();

        // Test through WASM interface
        let encrypted = encrypt_aes256(data, password, &config).unwrap();
        let decrypted = decrypt_aes256(&encrypted, password, &config).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_wasm_error_handling() {
        let config = AesConfig::default();

        // Test empty data
        let result = encrypt_aes256(&[], "password", &config);
        assert!(result.is_err());

        // Test empty password
        let result = encrypt_aes256(b"data", "", &config);
        assert!(result.is_err());

        // Test decrypt with wrong password
        let encrypted = encrypt_aes256(b"data", "password", &config).unwrap();
        let result = decrypt_aes256(&encrypted, "wrong", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_module_structure() {
        // Test that all modules are accessible
        let _config = AesConfig::default();
        let _error_code = ErrorCode::InvalidInput;
    }
}
