/**
 * QSafe Backend – Express server. Auth, TOTP, devices, MFA routes.
 * @module index
 */

require('dotenv').config({ silent: true, override: true });
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const authRoutes = require('./authRoutes');
const totpRoutes = require('./totpRoutes');
const deviceRoutes = require('./deviceRoutes');
const mfaRoutes = require('./mfaRoutes');

const isProd = process.env.NODE_ENV === 'production';

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

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { message: 'Too many attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authPollLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 6000, // ~400/min for 150ms poll
  message: { message: 'Too many attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const { db } = require('./firebase');
const { cleanupDuplicateDevices } = require('./services/deviceCleanup');

const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;
function scheduleDeviceCleanup() {
  if (!db) return;
  cleanupDuplicateDevices().catch(() => {});
  setInterval(() => {
    cleanupDuplicateDevices().catch(() => {});
  }, TWENTY_FOUR_HOURS_MS);
}
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'qsafe-backend',
    firestore: !!db,
  });
});

app.use('/api/auth', (req, res, next) => {
  if (req.originalUrl.includes('login-status') && req.method === 'GET') {
    return authPollLimiter(req, res, next);
  }
  return authLimiter(req, res, next);
}, authRoutes);
app.use('/api/totp', totpRoutes);
app.use('/api/devices', deviceRoutes);
app.use('/api/mfa', mfaRoutes);

app.listen(PORT, () => {
  scheduleDeviceCleanup();
}).on('error', (err) => {
  process.exit(1);
});

