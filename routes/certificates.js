import express from 'express';
import forge from 'node-forge';
import { getDatabase } from '../database.js';
import { verifyCertificate, getCACertificate } from '../crypto/ca.js';

const router = express.Router();

router.get('/ca', (req, res) => {
  try {
    const caCert = getCACertificate();
    res.json({ certificate: caCert });
  } catch (error) {
    console.error('CA certificate error:', error);
    res.status(500).json({ error: 'Failed to get CA certificate' });
  }
});

router.post('/verify', async (req, res) => {
  try {
    const { certificate } = req.body;
    const isValid = verifyCertificate(certificate);
    
    // Check if certificate is revoked
    const db = getDatabase();
    const cert = forge.pki.certificateFromPem(certificate);
    const revokedCert = await db.get(
      'SELECT * FROM crl_entries WHERE serial_number = ?',
      [cert.serialNumber]
    );
    
    res.json({
      isValid: isValid && !revokedCert,
      isRevoked: !!revokedCert,
      revokedAt: revokedCert?.revoked_at,
      reason: revokedCert?.reason
    });
  } catch (error) {
    console.error('Certificate verification error:', error);
    res.status(500).json({ error: 'Failed to verify certificate' });
  }
});

router.post('/revoke', async (req, res) => {
  try {
    const { serialNumber, reason = 'unspecified' } = req.body;
    const db = getDatabase();
    
    // Add to CRL
    await db.run(
      'INSERT INTO crl_entries (serial_number, reason) VALUES (?, ?)',
      [serialNumber, reason]
    );
    
    // Update certificate status
    await db.run(
      'UPDATE certificates SET is_revoked = 1, revoked_at = CURRENT_TIMESTAMP, revocation_reason = ? WHERE serial_number = ?',
      [reason, serialNumber]
    );
    
    res.json({ message: 'Certificate revoked successfully' });
  } catch (error) {
    console.error('Certificate revocation error:', error);
    res.status(500).json({ error: 'Failed to revoke certificate' });
  }
});

router.get('/crl', async (req, res) => {
  try {
    const db = getDatabase();
    const revokedCerts = await db.all('SELECT * FROM crl_entries ORDER BY revoked_at DESC');
    res.json(revokedCerts);
  } catch (error) {
    console.error('CRL error:', error);
    res.status(500).json({ error: 'Failed to get certificate revocation list' });
  }
});

export { router as certificateRoutes };