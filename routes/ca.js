import express from 'express';
import { getDatabase } from '../database.js';
import { getCACertificate } from '../crypto/ca.js';

const router = express.Router();

router.get('/certificate', (req, res) => {
  try {
    const caCert = getCACertificate();
    res.json({ certificate: caCert });
  } catch (error) {
    console.error('CA certificate error:', error);
    res.status(500).json({ error: 'Failed to get CA certificate' });
  }
});

router.get('/certificates', async (req, res) => {
  try {
    const db = getDatabase();
    const certificates = await db.all(`
      SELECT serial_number, subject_email, subject_name, issued_at, expires_at, is_revoked
      FROM certificates
      ORDER BY issued_at DESC
    `);
    res.json(certificates);
  } catch (error) {
    console.error('Certificates list error:', error);
    res.status(500).json({ error: 'Failed to get certificates' });
  }
});

export { router as caRoutes };