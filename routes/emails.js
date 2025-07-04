import express from 'express';
import { getDatabase } from '../database.js';
import { encryptMessage, decryptMessage, signMessage, verifySignature } from '../crypto/encryption.js';

const router = express.Router();

router.post('/send', async (req, res) => {
  try {
    console.log('📧 Email send request received');
    console.log('Request body keys:', Object.keys(req.body || {}));

    const { fromEmail, toEmail, subject, content, privateKey } = req.body;
    
    // Validate required fields with detailed logging
    const missingFields = [];
    if (!fromEmail) missingFields.push('fromEmail');
    if (!toEmail) missingFields.push('toEmail');
    if (!subject) missingFields.push('subject');
    if (!content) missingFields.push('content');
    if (!privateKey) missingFields.push('privateKey');
    
    if (missingFields.length > 0) {
      console.log('❌ Missing required fields:', missingFields);
      return res.status(400).json({ 
        error: 'Missing required fields',
        missing: missingFields,
        received: Object.keys(req.body || {})
      });
    }

    console.log('✅ All required fields present');
    console.log('From:', fromEmail);
    console.log('To:', toEmail);
    console.log('Subject:', subject);
    console.log('Content length:', content.length);
    console.log('Private key length:', privateKey.length);

    // Validate private key format
    if (!privateKey.includes('-----BEGIN RSA PRIVATE KEY-----') && 
        !privateKey.includes('-----BEGIN PRIVATE KEY-----')) {
      console.log('❌ Invalid private key format');
      return res.status(400).json({ 
        error: 'Invalid private key format',
        details: 'Private key must be in PEM format'
      });
    }

    const db = getDatabase();
    if (!db) {
      console.log('❌ Database not available');
      return res.status(500).json({ 
        error: 'Database not available',
        details: 'Database connection is not established'
      });
    }

    console.log('🔍 Looking up recipient:', toEmail);

    // Get recipient's public key with error handling
    let recipient;
    try {
      recipient = await db.get(
        'SELECT public_key, name FROM users WHERE email = ? AND is_active = 1', 
        [toEmail]
      );
    } catch (dbError) {
      console.error('❌ Database query failed:', dbError);
      return res.status(500).json({ 
        error: 'Database query failed',
        details: dbError.message
      });
    }

    if (!recipient) {
      console.log('❌ Recipient not found:', toEmail);
      return res.status(404).json({ 
        error: 'Recipient not found',
        details: `No active user found with email: ${toEmail}`
      });
    }

    console.log('✅ Recipient found:', recipient.name);
    console.log('Recipient public key length:', recipient.public_key.length);

    // Validate recipient's public key
    console.log('Recipient public key (first 100 chars):', recipient.public_key.slice(0, 100));

    if (!recipient.public_key.includes('-----BEGIN PUBLIC KEY-----')) {
      console.log('❌ Invalid recipient public key format');
      return res.status(500).json({ 
        error: 'Invalid recipient public key',
        details: 'Recipient public key is not in valid PEM format'
      });
    }

    // Validate sender exists
    let sender;
    try {
      sender = await db.get(
        'SELECT id, name FROM users WHERE email = ? AND is_active = 1',
        [fromEmail]
      );
    } catch (dbError) {
      console.error('❌ Sender lookup failed:', dbError);
      return res.status(500).json({ 
        error: 'Sender lookup failed',
        details: dbError.message
      });
    }

    if (!sender) {
      console.log('❌ Sender not found:', fromEmail);
      return res.status(404).json({ 
        error: 'Sender not found',
        details: `No active user found with email: ${fromEmail}`
      });
    }

    console.log('✅ Sender validated:', sender.name);

    // Encrypt the message
    console.log('🔐 Starting encryption process...');
    let encryptedData;
    try {
      encryptedData = encryptMessage(content, recipient.public_key);
      console.log('✅ Message encrypted successfully');
      console.log('Encrypted data keys:', Object.keys(encryptedData));
    } catch (encryptError) {
      console.error('❌ Encryption failed:', encryptError);
      return res.status(500).json({ 
      error: 'Encryption failed',
      message: encryptError.message,
      details: encryptError.stack || encryptError.message,
      step: 'message_encryption'
      });

    }

    // Sign the message
    console.log('✍️ Creating digital signature...');
    let signature;
    try {
      const messageToSign = `${subject}|${content}|${fromEmail}|${toEmail}`;
      signature = signMessage(messageToSign, privateKey);
      console.log('✅ Message signed successfully');
      console.log('Signature length:', signature.length);
    } catch (signError) {
      console.error('❌ Signing failed:', signError);
      return res.status(500).json({ 
        error: 'Digital signing failed',
        details: signError.message,
        step: 'message_signing'
      });
    }

    // Store the email
    console.log('💾 Storing email in database...');
    try {
      const encryptedContentJson = JSON.stringify(encryptedData);
      console.log('Encrypted content JSON length:', encryptedContentJson.length);
      
      const result = await db.run(`
        INSERT INTO emails (from_email, to_email, subject, encrypted_content, signature, sent_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
      `, [
        fromEmail,
        toEmail,
        subject,
        encryptedContentJson,
        signature
      ]);

      console.log('✅ Email stored with ID:', result.lastID);

      res.json({
        success: true,
        message: 'Email sent successfully',
        emailId: result.lastID,
        encrypted: true,
        signed: true,
        encryptionAlgorithm: encryptedData.algorithm || 'AES-256-CBC+RSA-OAEP',
        signatureAlgorithm: 'SHA-256+RSA'
      });

    } catch (dbError) {
      console.error('❌ Database storage error:', dbError);
      return res.status(500).json({ 
        error: 'Failed to store email',
        details: dbError.message,
        step: 'database_storage'
      });
    }

  } catch (error) {
    console.error('❌ Unexpected error in email send:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ 
      error: 'Internal server error',
      details: error.message,
      step: 'unexpected_error',
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

router.get('/inbox/:email', async (req, res) => {
  try {
    const { email } = req.params;
    console.log('📥 Fetching inbox for:', email);
    
    const db = getDatabase();
    if (!db) {
      return res.status(500).json({ 
        error: 'Database not available',
        details: 'Database connection is not established'
      });
    }

    const emails = await db.all(`
      SELECT 
        e.id,
        e.from_email,
        e.to_email,
        e.subject,
        e.encrypted_content,
        e.signature,
        e.sent_at,
        u.name as sender_name,
        u.public_key as sender_public_key
      FROM emails e
      JOIN users u ON e.from_email = u.email
      WHERE e.to_email = ?
      ORDER BY e.sent_at DESC
    `, [email]);

    console.log(`✅ Found ${emails.length} emails for ${email}`);
    res.json(emails);
  } catch (error) {
    console.error('❌ Inbox fetch error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch inbox',
      details: error.message
    });
  }
});

router.get('/sent/:email', async (req, res) => {
  try {
    const { email } = req.params;
    console.log('📤 Fetching sent emails for:', email);
    
    const db = getDatabase();
    if (!db) {
      return res.status(500).json({ 
        error: 'Database not available',
        details: 'Database connection is not established'
      });
    }

    const emails = await db.all(`
      SELECT 
        e.id,
        e.from_email,
        e.to_email,
        e.subject,
        e.encrypted_content,
        e.signature,
        e.sent_at,
        u.name as recipient_name
      FROM emails e
      JOIN users u ON e.to_email = u.email
      WHERE e.from_email = ?
      ORDER BY e.sent_at DESC
    `, [email]);

    console.log(`✅ Found ${emails.length} sent emails for ${email}`);
    res.json(emails);
  } catch (error) {
    console.error('❌ Sent emails fetch error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch sent emails',
      details: error.message
    });
  }
});

router.post('/decrypt', async (req, res) => {
  try {
    console.log('🔓 Decryption request received');
    const { encryptedContent, privateKey } = req.body;
    
    if (!encryptedContent || !privateKey) {
      return res.status(400).json({ 
        error: 'Missing encrypted content or private key',
        details: 'Both encryptedContent and privateKey are required'
      });
    }
    
    // Validate private key format
    if (!privateKey.includes('-----BEGIN RSA PRIVATE KEY-----') && 
        !privateKey.includes('-----BEGIN PRIVATE KEY-----')) {
      return res.status(400).json({ 
        error: 'Invalid private key format',
        details: 'Private key must be in PEM format'
      });
    }
    
    let encryptedData;
    try {
      encryptedData = JSON.parse(encryptedContent);
      console.log('✅ Encrypted content parsed');
      console.log('Encrypted data keys:', Object.keys(encryptedData));
    } catch (parseError) {
      console.error('❌ Failed to parse encrypted content:', parseError);
      return res.status(400).json({ 
        error: 'Invalid encrypted content format',
        details: 'Encrypted content must be valid JSON'
      });
    }
    
    const decryptedContent = decryptMessage(encryptedData, privateKey);
    console.log('✅ Message decrypted successfully');
    
    res.json({ 
      content: decryptedContent,
      success: true
    });
  } catch (error) {
    console.error('❌ Decryption error:', error);
    res.status(500).json({ 
      error: 'Failed to decrypt email',
      details: error.message
    });
  }
});

router.post('/verify', async (req, res) => {
  try {
    console.log('🔍 Signature verification request received');
    const { subject, content, fromEmail, toEmail, signature, senderPublicKey } = req.body;
    
    const missingFields = [];
    if (!subject) missingFields.push('subject');
    if (!content) missingFields.push('content');
    if (!fromEmail) missingFields.push('fromEmail');
    if (!toEmail) missingFields.push('toEmail');
    if (!signature) missingFields.push('signature');
    if (!senderPublicKey) missingFields.push('senderPublicKey');
    
    if (missingFields.length > 0) {
      return res.status(400).json({ 
        error: 'Missing required verification data',
        missing: missingFields
      });
    }
    
    // Validate public key format
    if (!senderPublicKey.includes('-----BEGIN PUBLIC KEY-----')) {
      return res.status(400).json({ 
        error: 'Invalid sender public key format',
        details: 'Public key must be in PEM format'
      });
    }
    
    const messageToVerify = `${subject}|${content}|${fromEmail}|${toEmail}`;
    const isValid = verifySignature(messageToVerify, signature, senderPublicKey);
    
    console.log('✅ Signature verification result:', isValid);
    
    res.json({ 
      isValid, 
      verified: isValid,
      message: isValid ? 'Signature is valid' : 'Signature verification failed',
      algorithm: 'SHA-256+RSA'
    });
  } catch (error) {
    console.error('❌ Verification error:', error);
    res.status(500).json({ 
      error: 'Failed to verify signature',
      details: error.message
    });
  }
});

export { router as emailRoutes };