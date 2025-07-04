import forge from 'node-forge';

export function generateKeyPair() {
  try {
    console.log('🔑 Generating RSA key pair...');
    const keyPair = forge.pki.rsa.generateKeyPair(2048);
    const publicKeyPem = forge.pki.publicKeyToPem(keyPair.publicKey);
    const privateKeyPem = forge.pki.privateKeyToPem(keyPair.privateKey);
    
    console.log('✅ Key pair generated successfully');
    return {
      publicKey: publicKeyPem,
      privateKey: privateKeyPem
    };
  } catch (error) {
    console.error('❌ Key generation failed:', error);
    throw new Error('Failed to generate key pair: ' + error.message);
  }
}

export function encryptMessage(message, publicKeyPem) {
  try {
    console.log('🔐 Starting message encryption...');
    console.log('Message length:', message.length);
    console.log('Public key preview:', publicKeyPem.substring(0, 100) + '...');

    // Validate inputs
    if (!message || typeof message !== 'string') {
      throw new Error('Message must be a non-empty string');
    }
    
    if (!publicKeyPem || typeof publicKeyPem !== 'string') {
      throw new Error('Public key must be a valid PEM string');
    }

    if (!publicKeyPem.includes('-----BEGIN PUBLIC KEY-----')) {
      throw new Error('Invalid public key format - missing PEM headers');
    }

    // Parse and validate public key first
    let publicKey;
    try {
      publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
      console.log('✅ Public key parsed successfully');
    } catch (keyError) {
      console.error('❌ Invalid public key format:', keyError);
      throw new Error('Invalid public key format: ' + keyError.message);
    }

    // Generate AES key and IV using forge for consistency
    const aesKey = forge.random.getBytesSync(32); // 256-bit key
    const iv = forge.random.getBytesSync(16); // 128-bit IV
    
    console.log('🔑 Generated AES key and IV using forge');

    // Encrypt message with AES using forge
    const cipher = forge.cipher.createCipher('AES-CBC', aesKey);
    cipher.start({ iv: iv });
    cipher.update(forge.util.createBuffer(message, 'utf8'));
    cipher.finish();
    
    const encryptedContent = forge.util.encode64(cipher.output.getBytes());
    console.log('🔒 Message encrypted with AES-CBC');

    // Encrypt AES key with RSA using forge
    let encryptedKey;
    try {
      console.log('🔑 AES key length (bytes):', aesKey.length);

      encryptedKey = publicKey.encrypt(aesKey, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: {
          md: forge.md.sha256.create()
        }
      });
      console.log('🔑 AES key encrypted with RSA-OAEP');
    } catch (rsaError) {
      console.error('❌ RSA encryption failed:', rsaError);
      throw new Error('RSA encryption failed: ' + rsaError.message);
    }

    const result = {
      encryptedContent,
      encryptedKey: forge.util.encode64(encryptedKey),
      iv: forge.util.encode64(iv),
      algorithm: 'AES-256-CBC+RSA-OAEP'
    };

    console.log('✅ Encryption completed successfully');
    console.log('Result keys:', Object.keys(result));
    return result;
    
  } catch (error) {
    console.error('❌ Encryption error:', error);
    console.error('Error details:', {
      name: error.name,
      message: error.message,
      stack: error.stack
    });
    throw new Error('Encryption failed: ' + error.message);
  }
}

export function decryptMessage(encryptedData, privateKeyPem) {
  try {
    console.log('🔓 Starting message decryption...');
    
    // Validate inputs
    if (!encryptedData || typeof encryptedData !== 'object') {
      throw new Error('Encrypted data must be a valid object');
    }
    
    if (!privateKeyPem || typeof privateKeyPem !== 'string') {
      throw new Error('Private key must be a valid PEM string');
    }

    if (!privateKeyPem.includes('-----BEGIN RSA PRIVATE KEY-----') && 
        !privateKeyPem.includes('-----BEGIN PRIVATE KEY-----')) {
      throw new Error('Invalid private key format - missing PEM headers');
    }

    const { encryptedContent, encryptedKey, iv } = encryptedData;
    
    if (!encryptedContent || !encryptedKey) {
      throw new Error('Missing encrypted content or encrypted key');
    }

    console.log('Encrypted data structure:', {
      hasContent: !!encryptedContent,
      hasKey: !!encryptedKey,
      hasIv: !!iv,
      contentLength: encryptedContent?.length,
      keyLength: encryptedKey?.length
    });

    // Parse private key
    let privateKey;
    try {
      privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
      console.log('✅ Private key parsed successfully');
    } catch (keyError) {
      console.error('❌ Invalid private key format:', keyError);
      throw new Error('Invalid private key format: ' + keyError.message);
    }
    
    // Decrypt AES key with RSA
    let aesKey;
    try {
      const encryptedKeyBinary = forge.util.decode64(encryptedKey);
      aesKey = privateKey.decrypt(encryptedKeyBinary, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: {
          md: forge.md.sha256.create()
        }
      });
      console.log('🔑 AES key decrypted with RSA');
    } catch (rsaError) {
      console.error('❌ RSA decryption failed:', rsaError);
      throw new Error('RSA decryption failed: ' + rsaError.message);
    }
    
    // Decrypt content with AES using forge
    let decryptedContent;
    try {
      const decipher = forge.cipher.createDecipher('AES-CBC', aesKey);
      const ivBytes = iv ? forge.util.decode64(iv) : forge.random.getBytesSync(16);
      
      decipher.start({ iv: ivBytes });
      decipher.update(forge.util.createBuffer(forge.util.decode64(encryptedContent)));
      const success = decipher.finish();
      
      if (!success) {
        throw new Error('AES decryption failed - cipher finish returned false');
      }
      
      decryptedContent = decipher.output.toString('utf8');
      console.log('✅ Message decrypted successfully');
    } catch (aesError) {
      console.error('❌ AES decryption failed:', aesError);
      throw new Error('AES decryption failed: ' + aesError.message);
    }
    
    return decryptedContent;
    
  } catch (error) {
    console.error('❌ Decryption error:', error);
    console.error('Error details:', {
      name: error.name,
      message: error.message,
      stack: error.stack
    });
    throw new Error('Decryption failed: ' + error.message);
  }
}

export function signMessage(message, privateKeyPem) {
  try {
    console.log('✍️ Creating digital signature...');
    
    if (!message || typeof message !== 'string') {
      throw new Error('Message must be a non-empty string');
    }
    
    if (!privateKeyPem || typeof privateKeyPem !== 'string') {
      throw new Error('Private key must be a valid PEM string');
    }

    if (!privateKeyPem.includes('-----BEGIN RSA PRIVATE KEY-----') && 
        !privateKeyPem.includes('-----BEGIN PRIVATE KEY-----')) {
      throw new Error('Invalid private key format - missing PEM headers');
    }

    // Parse private key
    let privateKey;
    try {
      privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
      console.log('✅ Private key parsed for signing');
    } catch (keyError) {
      console.error('❌ Invalid private key for signing:', keyError);
      throw new Error('Invalid private key format: ' + keyError.message);
    }
    
    // Create hash
    const md = forge.md.sha256.create();
    md.update(message, 'utf8');
    
    // Sign the hash
    let signature;
    try {
      signature = privateKey.sign(md);
      console.log('✅ Digital signature created');
    } catch (signError) {
      console.error('❌ Signing operation failed:', signError);
      throw new Error('Signing operation failed: ' + signError.message);
    }
    
    const signatureBase64 = forge.util.encode64(signature);
    return signatureBase64;
    
  } catch (error) {
    console.error('❌ Signing error:', error);
    console.error('Error details:', {
      name: error.name,
      message: error.message,
      stack: error.stack
    });
    throw new Error('Signing failed: ' + error.message);
  }
}

export function verifySignature(message, signature, publicKeyPem) {
  try {
    console.log('🔍 Verifying digital signature...');
    
    if (!message || !signature || !publicKeyPem) {
      console.log('❌ Missing required parameters for verification');
      return false;
    }

    if (!publicKeyPem.includes('-----BEGIN PUBLIC KEY-----')) {
      console.log('❌ Invalid public key format for verification');
      return false;
    }

    // Parse public key
    let publicKey;
    try {
      publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
      console.log('✅ Public key parsed for verification');
    } catch (keyError) {
      console.error('❌ Invalid public key for verification:', keyError);
      return false;
    }
    
    // Create hash of message
    const md = forge.md.sha256.create();
    md.update(message, 'utf8');
    
    // Decode signature
    let decodedSignature;
    try {
      decodedSignature = forge.util.decode64(signature);
    } catch (decodeError) {
      console.error('❌ Invalid signature format:', decodeError);
      return false;
    }
    
    // Verify signature
    let isValid;
    try {
      isValid = publicKey.verify(md.digest().bytes(), decodedSignature);
      console.log('✅ Signature verification result:', isValid);
    } catch (verifyError) {
      console.error('❌ Signature verification failed:', verifyError);
      return false;
    }
    
    return isValid;
    
  } catch (error) {
    console.error('❌ Signature verification error:', error);
    return false;
  }
}