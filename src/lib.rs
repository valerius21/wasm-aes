use wasm_bindgen::prelude::*;
use sha2::{Sha256, Digest};
use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use cbc::cipher::{KeyIvInit, BlockEncryptMut, BlockDecryptMut, block_padding::Pkcs7};
use pbkdf2::pbkdf2_hmac_array;
use rand::Rng;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

const SALT_SIZE: usize = 16;
const IV_SIZE: usize = 16;
const KEY_SIZE: usize = 32; // 256 bits
const PBKDF2_ITERATIONS: u32 = 100000;

#[wasm_bindgen]
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[wasm_bindgen]
pub fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
}

/// Encrypts data using AES-256-CBC with a password
/// Returns: [salt (16 bytes) | iv (16 bytes) | encrypted_data]
#[wasm_bindgen]
pub fn encrypt_aes256(data: &[u8], password: &str) -> Result<Vec<u8>, JsValue> {
    // Generate random salt
    let mut rng = rand::thread_rng();
    let mut salt = [0u8; SALT_SIZE];
    rng.fill(&mut salt);

    // Generate random IV
    let mut iv = [0u8; IV_SIZE];
    rng.fill(&mut iv);

    // Derive key from password using PBKDF2
    let key = pbkdf2_hmac_array::<Sha256, KEY_SIZE>(
        password.as_bytes(),
        &salt,
        PBKDF2_ITERATIONS
    );

    // Prepare buffer for encryption (needs to be larger for padding)
    let mut buffer = vec![0u8; data.len() + 16]; // Add extra space for padding
    buffer[..data.len()].copy_from_slice(data);

    // Encrypt data
    let cipher = Aes256CbcEnc::new(&key.into(), &iv.into());
    let encrypted_len = cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, data.len())
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {:?}", e)))?
        .len();

    // Combine salt + iv + encrypted_data
    let mut result = Vec::with_capacity(SALT_SIZE + IV_SIZE + encrypted_len);
    result.extend_from_slice(&salt);
    result.extend_from_slice(&iv);
    result.extend_from_slice(&buffer[..encrypted_len]);

    Ok(result)
}

/// Decrypts data using AES-256-CBC with a password
/// Input format: [salt (16 bytes) | iv (16 bytes) | encrypted_data]
#[wasm_bindgen]
pub fn decrypt_aes256(encrypted_data: &[u8], password: &str) -> Result<Vec<u8>, JsValue> {
    // Check minimum size
    if encrypted_data.len() < SALT_SIZE + IV_SIZE {
        return Err(JsValue::from_str("Invalid encrypted data: too short"));
    }

    // Extract salt, iv, and encrypted data
    let salt = &encrypted_data[0..SALT_SIZE];
    let iv = &encrypted_data[SALT_SIZE..SALT_SIZE + IV_SIZE];
    let ciphertext = &encrypted_data[SALT_SIZE + IV_SIZE..];

    // Derive key from password using PBKDF2
    let key = pbkdf2_hmac_array::<Sha256, KEY_SIZE>(
        password.as_bytes(),
        salt,
        PBKDF2_ITERATIONS
    );

    // Create buffer for decryption
    let mut buffer = vec![0u8; ciphertext.len()];
    buffer.copy_from_slice(ciphertext);

    // Decrypt data
    let cipher = Aes256CbcDec::new(&key.into(), iv.into());
    let decrypted_data = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|e| JsValue::from_str(&format!("Decryption failed: {:?}", e)))?;

    Ok(decrypted_data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }

    #[test]
    fn test_encryption_decryption() {
        let original_data = b"Hello, World! This is a test message.";
        let password = "test_password_123";

        // Encrypt
        let encrypted = encrypt_aes256(original_data, password).unwrap();

        // Verify encrypted data is different and longer (due to salt, iv, and padding)
        assert_ne!(encrypted.as_slice(), original_data);
        assert!(encrypted.len() >= original_data.len() + SALT_SIZE + IV_SIZE);

        // Decrypt
        let decrypted = decrypt_aes256(&encrypted, password).unwrap();

        // Verify decrypted data matches original
        assert_eq!(decrypted.as_slice(), original_data);
    }

    #[test]
    fn test_wrong_password() {
        let original_data = b"Secret message";
        let password = "correct_password";
        let wrong_password = "wrong_password";

        // Encrypt with correct password
        let encrypted = encrypt_aes256(original_data, password).unwrap();

        // Try to decrypt with wrong password - should fail
        let result = decrypt_aes256(&encrypted, wrong_password);
        assert!(result.is_err());
    }
}
