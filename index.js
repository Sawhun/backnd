import express from 'express';
import cors from 'cors';
import { initializeDatabase } from './database.js';
import { initializeCA } from './crypto/ca.js';
import { certificateRoutes } from './routes/certificates.js';
import { authRoutes } from './routes/auth.js';
import { emailRoutes } from './routes/emails.js';
import { caRoutes } from './routes/ca.js';

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));

// Add request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Initialize database and CA
try {
  await initializeDatabase();
  initializeCA();
  console.log('🔐 PKI System initialized successfully');
} catch (error) {
  console.error('❌ Initialization failed:', error);
  process.exit(1);
}

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/certificates', certificateRoutes);
app.use('/api/emails', emailRoutes);
app.use('/api/ca', caRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Secure Email PKI System API is running',
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('❌ Server error:', error);
  res.status(500).json({ 
    error: 'Internal server error',
    message: error.message
  });
});

app.listen(PORT, () => {
  console.log(`🔐 Secure Email PKI Server running on port ${PORT}`);
  console.log(`📧 Ready to handle secure email communications`);
  console.log(`🌐 CORS enabled for localhost:5173 and localhost:3000`);
});