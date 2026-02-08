/**
 * QSafe Backend – Express API server.
 * Auth (register/login), devices, MFA (polling), TOTP, PQC JWT/Kyber.
 */
require('dotenv').config({ silent: true, override: true });

process.on('uncaughtException', (err) => console.error('[uncaughtException]', err));
process.on('unhandledRejection', (reason) => console.error('[unhandledRejection]', reason));

if (!process.env.PQC_JWT_PUBLIC_KEY || !process.env.PQC_JWT_PRIVATE_KEY) {
  console.error('PQC JWT keys not configured. Run: npm run generate:pqc and add keys to .env');
  process.exit(1);
}

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
  const required = [
    'PQC_JWT_PUBLIC_KEY',
    'PQC_JWT_PRIVATE_KEY',
    'PQC_KYBER_PUBLIC_KEY',
    'PQC_KYBER_PRIVATE_KEY',
    'FIREBASE_PROJECT_ID',
    'FIREBASE_CLIENT_EMAIL',
    'FIREBASE_PRIVATE_KEY',
  ];
  const missing = required.filter((k) => !process.env[k]?.trim());
  if (missing.length > 0) {
    console.error('Production requires these env vars:', missing.join(', '));
    console.error('Run: npm run generate:pqc');
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
  max: 6000,
  message: { message: 'Too many attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const { db } = require('./firebase');
const { cleanupDuplicateDevices } = require('./services/deviceCleanup');

const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;
function scheduleDeviceCleanup() {
  if (!db) return;
  cleanupDuplicateDevices().catch((err) => console.error('[deviceCleanup]', err?.message || err));
  setInterval(() => {
    cleanupDuplicateDevices().catch((err) => console.error('[deviceCleanup]', err?.message || err));
  }, TWENTY_FOUR_HOURS_MS);
}
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'qsafe-backend',
    firestore: !!db,
  });
});

app.get('/api/pqc/kyber-public-key', async (req, res) => {
  try {
    const kyber = require('./services/kyber');
    const pkHex = await kyber.getServerPublicKey();
    res.json({ publicKey: pkHex, algorithm: 'ML-KEM-768' });
  } catch (err) {
    res.status(500).json({ message: 'PQC Kyber not configured' });
  }
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
  console.log(`QSafe backend running at http://localhost:${PORT}`);
}).on('error', (err) => {
  process.exit(1);
});

