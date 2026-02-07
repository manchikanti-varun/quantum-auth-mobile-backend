/**
 * QSafe backend – Express server, auth, TOTP, devices, MFA routes.
 */
require('dotenv').config(); // loads .env locally; Railway vars override
const express = require('express');
const cors = require('cors');
const authRoutes = require('./authRoutes');
const totpRoutes = require('./totpRoutes');
const deviceRoutes = require('./deviceRoutes');
const mfaRoutes = require('./mfaRoutes');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

// Health check
const { db } = require('./firebase');
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'qsafe-backend',
    firestore: !!db,
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/totp', totpRoutes);
app.use('/api/devices', deviceRoutes);
app.use('/api/mfa', mfaRoutes);

app.listen(PORT, () => {
  console.log(`QSafe backend listening on port ${PORT}`);
}).on('error', (err) => {
  console.error('Server failed to start:', err.message);
  process.exit(1);
});

