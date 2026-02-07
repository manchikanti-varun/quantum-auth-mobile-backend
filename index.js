/**
 * QSafe backend – Express server, auth, TOTP, devices, MFA routes.
 */
require('dotenv').config({ silent: true, override: true }); // .env overrides system env for local dev
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const authRoutes = require('./authRoutes');
const totpRoutes = require('./totpRoutes');
const deviceRoutes = require('./deviceRoutes');
const mfaRoutes = require('./mfaRoutes');

const isProd = process.env.NODE_ENV === 'production';

// Fail fast in production if critical env vars are missing
if (isProd) {
  const required = ['JWT_SECRET', 'FIREBASE_PROJECT_ID', 'FIREBASE_CLIENT_EMAIL', 'FIREBASE_PRIVATE_KEY'];
  const missing = required.filter((k) => !process.env[k]?.trim());
  if (missing.length > 0) {
    console.error('Production requires these env vars:', missing.join(', '));
    process.exit(1);
  }
  const weak = ['dev_secret', 'change_me', 'your_jwt_secret', 'secret', 'test'];
  const sec = (process.env.JWT_SECRET || '').toLowerCase();
  if (sec.length < 32 || weak.some((w) => sec.includes(w))) {
    console.error('Production requires a strong JWT_SECRET (32+ chars, no weak values)');
    process.exit(1);
  }
}

const app = express();
const PORT = process.env.PORT || 4000;

app.use(helmet());
const corsOrigin = process.env.CORS_ORIGIN;
app.use(cors(corsOrigin ? { origin: corsOrigin.split(',').map((o) => o.trim()) } : {}));
app.use(express.json());

// Rate limit auth endpoints (brute force protection)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30, // 30 requests per window per IP
  message: { message: 'Too many attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Health check
const { db } = require('./firebase');
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'qsafe-backend',
    firestore: !!db,
  });
});

// API routes (auth routes are rate-limited)
app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/totp', totpRoutes);
app.use('/api/devices', deviceRoutes);
app.use('/api/mfa', mfaRoutes);

app.listen(PORT, () => {
  console.log(`QSafe backend listening on port ${PORT}`);
}).on('error', (err) => {
  console.error('Server failed to start:', err.message);
  process.exit(1);
});

