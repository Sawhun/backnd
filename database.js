import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let db;

export async function initializeDatabase() {
  try {
    db = await open({
      filename: path.join(__dirname, '..', 'secure_email.db'),
      driver: sqlite3.Database
    });

    // Users table
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        private_key_encrypted TEXT NOT NULL,
        certificate TEXT NOT NULL,
        certificate_serial TEXT UNIQUE NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
      )
    `);

    // Certificates table (for CA management)
    await db.exec(`
      CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        serial_number TEXT UNIQUE NOT NULL,
        subject_email TEXT NOT NULL,
        subject_name TEXT NOT NULL,
        public_key TEXT NOT NULL,
        certificate_pem TEXT NOT NULL,
        issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        is_revoked BOOLEAN DEFAULT 0,
        revoked_at DATETIME NULL,
        revocation_reason TEXT NULL
      )
    `);

    // Emails table
    await db.exec(`
      CREATE TABLE IF NOT EXISTS emails (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_email TEXT NOT NULL,
        to_email TEXT NOT NULL,
        subject TEXT NOT NULL,
        encrypted_content TEXT NOT NULL,
        signature TEXT NOT NULL,
        signature_algorithm TEXT DEFAULT 'SHA256withRSA',
        sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_verified BOOLEAN DEFAULT 0,
        verification_status TEXT NULL
      )
    `);

    // Certificate Revocation List
    await db.exec(`
      CREATE TABLE IF NOT EXISTS crl_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        serial_number TEXT NOT NULL,
        revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        reason TEXT NOT NULL
      )
    `);

    console.log('📊 Database initialized successfully');
    return db;
  } catch (error) {
    console.error('Database initialization error:', error);
    throw error;
  }
}

export function getDatabase() {
  return db;
}