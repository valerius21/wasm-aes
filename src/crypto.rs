//! Core cryptographic operations for AES-256-CBC encryption.
//!
//! This module provides the main encryption and decryption functionality
//! using AES-256 in CBC mode with PBKDF2 key derivation.

use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use pbkdf2::pbkdf2_hmac_array;
use rand::Rng;
use sha2::Sha256;

use crate::config::AesConfig;
use crate::error::{AesError, ErrorCode, Result};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// Encrypts data using AES-256-CBC with password-based key derivation.
///
/// The encryption process:
/// 1. Generates a random salt for PBKDF2
/// 2. Generates a random IV (Initialization Vector)
/// 3. Derives a 256-bit key from the password using PBKDF2-HMAC-SHA256
/// 4. Encrypts the data using AES-256-CBC with PKCS7 padding
/// 5. Returns: [salt | iv | encrypted_data]
///
/// # Arguments
///
/// * `data` - The plaintext data to encrypt
/// * `password` - The password to derive the encryption key from
/// * `config` - Configuration parameters for encryption
///
/// # Returns
///
/// Returns a `Vec<u8>` containing: [salt (16 bytes) | iv (16 bytes) | encrypted_data]
///
/// # Errors
///
/// Returns an error if:
/// - Input data is empty
/// - Password is empty
/// - Encryption operation fails
///
/// # Examples
///
/// ```ignore
/// let data = b"Hello, World!";
/// let password = "my_secure_password";
/// let config = AesConfig::default();
/// let encrypted = encrypt_aes256(data, password, &config)?;
/// ```
pub fn encrypt_aes256(data: &[u8], password: &str, config: &AesConfig) -> Result<Vec<u8>> {
    // Validate inputs
    if data.is_empty() {
        return Err(AesError::new(
            ErrorCode::InvalidInput,
            "Cannot encrypt empty data",
        ));
    }

    if password.is_empty() {
        return Err(AesError::new(
            ErrorCode::InvalidInput,
            "Password cannot be empty",
        ));
    }

    // Validate configuration
    config.validate()?;

    // Generate random salt
    let mut rng = rand::thread_rng();
    let mut salt = vec![0u8; config.salt_size()];
    rng.fill(&mut salt[..]);

    // Generate random IV (must be 16 bytes for AES)
    let mut iv = [0u8; 16];
    rng.fill(&mut iv);

    // Derive key from password using PBKDF2-HMAC-SHA256
    let key = pbkdf2_hmac_array::<Sha256, 32>(
        password.as_bytes(),
        &salt,
        config.pbkdf2_iterations(),
    );

    // Prepare buffer for encryption (needs extra space for PKCS7 padding)
    let mut buffer = vec![0u8; data.len() + 16];
    buffer[..data.len()].copy_from_slice(data);

    // Encrypt data
    let cipher = Aes256CbcEnc::new(&key.into(), &iv.into());
    let encrypted_len = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len())
        .map_err(|e| {
            AesError::new(
                ErrorCode::EncryptionFailed,
                format!("Encryption failed: {:?}", e),
            )
        })?
        .len();

    // Combine salt + iv + encrypted_data
    let total_size = config.salt_size() + config.iv_size() + encrypted_len;
    let mut result = Vec::with_capacity(total_size);
    result.extend_from_slice(&salt);
    result.extend_from_slice(&iv);
    result.extend_from_slice(&buffer[..encrypted_len]);

    Ok(result)
}

/// Decrypts data that was encrypted with `encrypt_aes256`.
///
/// The decryption process:
/// 1. Extracts salt and IV from the encrypted data
/// 2. Derives the decryption key using PBKDF2-HMAC-SHA256
/// 3. Decrypts the data using AES-256-CBC
/// 4. Removes PKCS7 padding
/// 5. Returns the original plaintext
///
/// # Arguments
///
/// * `encrypted_data` - The encrypted data in format: [salt | iv | ciphertext]
/// * `password` - The password used for encryption
/// * `config` - Configuration parameters (must match encryption config)
///
/// # Returns
///
/// Returns a `Vec<u8>` containing the decrypted plaintext data.
///
/// # Errors
///
/// Returns an error if:
/// - Encrypted data is too short
/// - Invalid data format
/// - Wrong password
/// - Data is corrupted
/// - Padding is invalid
///
/// # Examples
///
/// ```ignore
/// let encrypted = encrypt_aes256(data, password, &config)?;
/// let decrypted = decrypt_aes256(&encrypted, password, &config)?;
/// assert_eq!(data, decrypted.as_slice());
/// ```
pub fn decrypt_aes256(encrypted_data: &[u8], password: &str, config: &AesConfig) -> Result<Vec<u8>> {
    // Validate inputs
    if password.is_empty() {
        return Err(AesError::new(
            ErrorCode::InvalidInput,
            "Password cannot be empty",
        ));
    }

    // Validate configuration
    config.validate()?;

    // Check minimum size
    let min_size = config.min_encrypted_size();
    if encrypted_data.len() < min_size {
        return Err(AesError::new(
            ErrorCode::DataTooShort,
            format!(
                "Encrypted data too short: {} bytes. Expected at least {} bytes (salt: {}, IV: {}, data: 16+)",
                encrypted_data.len(),
                min_size,
                config.salt_size(),
                config.iv_size()
            ),
        ));
    }

    // Extract salt, IV, and ciphertext
    let salt_end = config.salt_size();
    let iv_end = salt_end + config.iv_size();

    let salt = &encrypted_data[0..salt_end];
    let iv_slice = &encrypted_data[salt_end..iv_end];
    let ciphertext = &encrypted_data[iv_end..];

    if ciphertext.is_empty() {
        return Err(AesError::new(
            ErrorCode::InvalidFormat,
            "No ciphertext found in encrypted data",
        ));
    }

    // Convert IV slice to fixed-size array (must be 16 bytes for AES)
    let mut iv = [0u8; 16];
    iv.copy_from_slice(iv_slice);

    // Derive key from password using PBKDF2-HMAC-SHA256
    let key = pbkdf2_hmac_array::<Sha256, 32>(
        password.as_bytes(),
        salt,
        config.pbkdf2_iterations(),
    );

    // Create buffer for decryption
    let mut buffer = vec![0u8; ciphertext.len()];
    buffer.copy_from_slice(ciphertext);

    // Decrypt data
    let cipher = Aes256CbcDec::new(&key.into(), &iv.into());
    let decrypted_data = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer).map_err(|e| {
        AesError::new(
            ErrorCode::DecryptionFailed,
            format!(
                "Decryption failed: {:?}. This usually means the password is incorrect or the data is corrupted.",
                e
            ),
        )
    })?;

    Ok(decrypted_data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let original_data = b"Hello, World! This is a test message.";
        let password = "test_password_123";
        let config = AesConfig::default();

        // Encrypt
        let encrypted = encrypt_aes256(original_data, password, &config).unwrap();

        // Verify encrypted data is different and has correct size
        assert_ne!(encrypted.as_slice(), original_data);
        assert!(encrypted.len() >= original_data.len() + config.header_size());

        // Decrypt
        let decrypted = decrypt_aes256(&encrypted, password, &config).unwrap();

        // Verify decrypted matches original
        assert_eq!(decrypted.as_slice(), original_data);
    }

    #[test]
    fn test_encrypt_empty_data() {
        let data = b"";
        let password = "test_password";
        let config = AesConfig::default();

        let result = encrypt_aes256(data, password, &config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidInput as u32);
    }

    #[test]
    fn test_encrypt_empty_password() {
        let data = b"Some data";
        let password = "";
        let config = AesConfig::default();

        let result = encrypt_aes256(data, password, &config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidInput as u32);
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let data = b"Secret message";
        let password = "correct_password";
        let wrong_password = "wrong_password";
        let config = AesConfig::default();

        // Encrypt with correct password
        let encrypted = encrypt_aes256(data, password, &config).unwrap();

        // Try to decrypt with wrong password
        let result = decrypt_aes256(&encrypted, wrong_password, &config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::DecryptionFailed as u32);
    }

    #[test]
    fn test_decrypt_data_too_short() {
        let data = b"short";
        let password = "test_password";
        let config = AesConfig::default();

        let result = decrypt_aes256(data, password, &config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::DataTooShort as u32);
    }

    #[test]
    fn test_decrypt_corrupted_data() {
        let data = b"Some data";
        let password = "test_password";
        let config = AesConfig::default();

        // Encrypt
        let mut encrypted = encrypt_aes256(data, password, &config).unwrap();

        // Corrupt the data (change a byte in the ciphertext)
        if let Some(byte) = encrypted.get_mut(config.header_size() + 5) {
            *byte = byte.wrapping_add(1);
        }

        // Try to decrypt corrupted data
        let result = decrypt_aes256(&encrypted, password, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_large_data() {
        let large_data = vec![42u8; 1024 * 100]; // 100 KB
        let password = "test_password";
        let config = AesConfig::default();

        let encrypted = encrypt_aes256(&large_data, password, &config).unwrap();
        let decrypted = decrypt_aes256(&encrypted, password, &config).unwrap();

        assert_eq!(decrypted, large_data);
    }

    #[test]
    fn test_encrypt_special_characters() {
        let data = "Hello 世界! 🔒🔓".as_bytes();
        let password = "пароль密码";
        let config = AesConfig::default();

        let encrypted = encrypt_aes256(data, password, &config).unwrap();
        let decrypted = decrypt_aes256(&encrypted, password, &config).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_different_passwords_different_output() {
        let data = b"Same data";
        let password1 = "password1";
        let password2 = "password2";
        let config = AesConfig::default();

        let encrypted1 = encrypt_aes256(data, password1, &config).unwrap();
        let encrypted2 = encrypt_aes256(data, password2, &config).unwrap();

        // Even with same data, different passwords should produce different ciphertext
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_same_password_different_output() {
        let data = b"Same data";
        let password = "password";
        let config = AesConfig::default();

        let encrypted1 = encrypt_aes256(data, password, &config).unwrap();
        let encrypted2 = encrypt_aes256(data, password, &config).unwrap();

        // Due to random IV, same data+password should produce different ciphertext
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt correctly
        let decrypted1 = decrypt_aes256(&encrypted1, password, &config).unwrap();
        let decrypted2 = decrypt_aes256(&encrypted2, password, &config).unwrap();
        assert_eq!(decrypted1, data);
        assert_eq!(decrypted2, data);
    }

    #[test]
    fn test_custom_iterations() {
        let data = b"Test data";
        let password = "password";
        let mut config = AesConfig::default();
        config.set_pbkdf2_iterations(200_000).unwrap();

        let encrypted = encrypt_aes256(data, password, &config).unwrap();
        let decrypted = decrypt_aes256(&encrypted, password, &config).unwrap();

        assert_eq!(decrypted, data);
    }
}
