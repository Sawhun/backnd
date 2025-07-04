import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { getDatabase } from '../database.js';
import { generateKeyPair } from '../crypto/encryption.js';
import { issueCertificate } from '../crypto/ca.js';

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'secure-email-pki-secret-key';

router.post('/register', async (req, res) => {
  try {
    const { email, name, password } = req.body;
    const db = getDatabase();

    // Check if user already exists
    const existingUser = await db.get('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Generate key pair
    const keyPair = generateKeyPair();
    
    // Issue certificate
    const certData = issueCertificate(keyPair.publicKey, email, name);
    
    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);
    
    // Encrypt private key with password (simplified - in production, use proper key derivation)
    const encryptedPrivateKey = Buffer.from(keyPair.privateKey).toString('base64');

    // Store user
    const result = await db.run(`
      INSERT INTO users (email, name, password_hash, public_key, private_key_encrypted, certificate, certificate_serial)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [email, name, passwordHash, keyPair.publicKey, encryptedPrivateKey, certData.certificate, certData.serialNumber]);

    // Store certificate in CA database
    await db.run(`
      INSERT INTO certificates (serial_number, subject_email, subject_name, public_key, certificate_pem, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [certData.serialNumber, email, name, keyPair.publicKey, certData.certificate, certData.expiresAt]);

    const token = jwt.sign({ userId: result.lastID, email }, JWT_SECRET, { expiresIn: '24h' });

    console.log('✅ User registered successfully:', email);

    res.json({
      message: 'User registered successfully',
      token,
      user: {
        id: result.lastID,
        email,
        name,
        certificate: certData.certificate,
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey // Include private key in response
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const db = getDatabase();

    console.log('🔐 Login attempt for:', email);

    const user = await db.get(`
      SELECT id, email, name, password_hash, public_key, private_key_encrypted, certificate
      FROM users WHERE email = ? AND is_active = 1
    `, [email]);

    if (!user) {
      console.log('❌ User not found:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordValid = await bcrypt.compare(password, user.password_hash);
    if (!passwordValid) {
      console.log('❌ Invalid password for:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Decrypt private key
    const privateKey = Buffer.from(user.private_key_encrypted, 'base64').toString('utf8');

    const token = jwt.sign({ userId: user.id, email }, JWT_SECRET, { expiresIn: '24h' });

    console.log('✅ Login successful for:', email);
    console.log('Private key available:', !!privateKey);

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        certificate: user.certificate,
        publicKey: user.public_key,
        privateKey: privateKey // Ensure private key is included
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

router.get('/users', async (req, res) => {
  try {
    const db = getDatabase();
    const users = await db.all(`
      SELECT id, email, name, public_key, certificate
      FROM users WHERE is_active = 1
    `);
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

export { router as authRoutes };