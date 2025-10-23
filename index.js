// Import our outputted wasm ES6 module
import init, { AesConfig, encrypt_aes256, decrypt_aes256, version, default_config_info } from "./pkg/wasm_aes.js";

/**
 * Downloads a file with the given content and filename
 */
function downloadFile(content, filename, mimeType = 'application/octet-stream') {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Sets the status message with appropriate styling
 */
function setStatus(elementId, message, type = 'info') {
  const statusDiv = document.getElementById(elementId);
  statusDiv.textContent = message;
  statusDiv.className = `status ${type}`;
}

/**
 * Validates password strength
 */
function validatePassword(password) {
  if (!password || password.length === 0) {
    return { valid: false, message: 'Password cannot be empty' };
  }
  if (password.length < 8) {
    return { valid: false, message: 'Password should be at least 8 characters long' };
  }
  return { valid: true };
}

/**
 * Parse error from WASM and extract useful information
 */
function parseWasmError(error) {
  const errorStr = error.toString();
  // Try to extract error code
  const codeMatch = errorStr.match(/\[Error (\d+)\]/);
  if (codeMatch) {
    return {
      code: parseInt(codeMatch[1]),
      message: errorStr
    };
  }
  return { code: null, message: errorStr };
}

const runWasm = async () => {
  try {
    // Instantiate our wasm module
    await init("./pkg/wasm_aes_bg.wasm");

    // Log library info
    console.log(`WASM AES Library v${version()}`);
    console.log(default_config_info());

    // Create default configuration
    const config = new AesConfig();
    console.log(`Configuration: PBKDF2 iterations = ${config.pbkdf2Iterations}`);

    // Get DOM elements
    const encryptFileInput = document.getElementById('encrypt-file');
    const encryptPasswordInput = document.getElementById('encrypt-password');
    const encryptBtn = document.getElementById('encrypt-btn');

    const decryptFileInput = document.getElementById('decrypt-file');
    const decryptPasswordInput = document.getElementById('decrypt-password');
    const decryptBtn = document.getElementById('decrypt-btn');

    // Set initial status
    setStatus('encrypt-status', 'Ready to encrypt files', 'info');
    setStatus('decrypt-status', 'Ready to decrypt files', 'info');

    // Encryption handler
    encryptBtn.addEventListener('click', async () => {
      const file = encryptFileInput.files[0];
      const password = encryptPasswordInput.value;

      // Validate inputs
      if (!file) {
        setStatus('encrypt-status', 'Please select a file to encrypt', 'warning');
        return;
      }

      const passwordValidation = validatePassword(password);
      if (!passwordValidation.valid) {
        setStatus('encrypt-status', passwordValidation.message, 'warning');
        return;
      }

      try {
        // Disable button and show processing status
        encryptBtn.disabled = true;
        setStatus('encrypt-status', `Encrypting ${file.name}...`, 'info');

        // Read file as ArrayBuffer
        const arrayBuffer = await file.arrayBuffer();
        const uint8Array = new Uint8Array(arrayBuffer);

        // Encrypt using WASM with configuration
        const startTime = performance.now();
        const encryptedData = encrypt_aes256(uint8Array, password, config);
        const endTime = performance.now();
        const processingTime = ((endTime - startTime) / 1000).toFixed(2);

        // Generate filename for encrypted file
        const encryptedFilename = file.name + '.encrypted';

        // Download encrypted file
        downloadFile(encryptedData, encryptedFilename);

        // Show success message
        const sizeKB = (encryptedData.length / 1024).toFixed(2);
        setStatus(
          'encrypt-status',
          `✓ Successfully encrypted! File: ${encryptedFilename} (${sizeKB} KB) - Processing time: ${processingTime}s`,
          'success'
        );

        // Clear password field for security
        encryptPasswordInput.value = '';

      } catch (error) {
        const errInfo = parseWasmError(error);
        let errorMessage = `Encryption failed: ${errInfo.message}`;
        if (errInfo.code) {
          errorMessage = `Encryption failed (Error ${errInfo.code}): ${errInfo.message}`;
        }
        setStatus('encrypt-status', errorMessage, 'error');
        console.error('Encryption error:', error);
      } finally {
        encryptBtn.disabled = false;
      }
    });

    // Decryption handler
    decryptBtn.addEventListener('click', async () => {
      const file = decryptFileInput.files[0];
      const password = decryptPasswordInput.value;

      // Validate inputs
      if (!file) {
        setStatus('decrypt-status', 'Please select a file to decrypt', 'warning');
        return;
      }

      const passwordValidation = validatePassword(password);
      if (!passwordValidation.valid) {
        setStatus('decrypt-status', passwordValidation.message, 'warning');
        return;
      }

      try {
        // Disable button and show processing status
        decryptBtn.disabled = true;
        setStatus('decrypt-status', `Decrypting ${file.name}...`, 'info');

        // Read file as ArrayBuffer
        const arrayBuffer = await file.arrayBuffer();
        const uint8Array = new Uint8Array(arrayBuffer);

        // Check if file is large enough
        if (uint8Array.length < config.minEncryptedSize) {
          throw new Error(`File is too small to be a valid encrypted file (minimum: ${config.minEncryptedSize} bytes)`);
        }

        // Decrypt using WASM with configuration
        const startTime = performance.now();
        const decryptedData = decrypt_aes256(uint8Array, password, config);
        const endTime = performance.now();
        const processingTime = ((endTime - startTime) / 1000).toFixed(2);

        // Generate filename for decrypted file (remove .encrypted extension if present)
        let decryptedFilename = file.name;
        if (decryptedFilename.endsWith('.encrypted')) {
          decryptedFilename = decryptedFilename.slice(0, -10); // Remove '.encrypted'
        } else {
          decryptedFilename = decryptedFilename + '.decrypted';
        }

        // Download decrypted file
        downloadFile(decryptedData, decryptedFilename);

        // Show success message
        const sizeKB = (decryptedData.length / 1024).toFixed(2);
        setStatus(
          'decrypt-status',
          `✓ Successfully decrypted! File: ${decryptedFilename} (${sizeKB} KB) - Processing time: ${processingTime}s`,
          'success'
        );

        // Clear password field for security
        decryptPasswordInput.value = '';

      } catch (error) {
        const errInfo = parseWasmError(error);
        let errorMessage = 'Decryption failed';

        // Provide helpful error messages based on error code
        if (errInfo.code === 2001) {
          errorMessage = 'Decryption failed: Wrong password or corrupted file';
        } else if (errInfo.code === 3001) {
          errorMessage = 'File is too small to be a valid encrypted file';
        } else if (errInfo.code) {
          errorMessage = `Decryption failed (Error ${errInfo.code})`;
        }

        errorMessage += `. ${errInfo.message}`;

        setStatus('decrypt-status', errorMessage, 'error');
        console.error('Decryption error:', error);
      } finally {
        decryptBtn.disabled = false;
      }
    });

    // Add keyboard support (Enter key to submit)
    encryptPasswordInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        encryptBtn.click();
      }
    });

    decryptPasswordInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        decryptBtn.click();
      }
    });

  } catch (error) {
    console.error('Failed to initialize WASM module:', error);
    setStatus('encrypt-status', 'Failed to load encryption module', 'error');
    setStatus('decrypt-status', 'Failed to load decryption module', 'error');
  }
};

runWasm();
