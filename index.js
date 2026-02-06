require('dotenv').config();
const express = require('express');
const cors = require('cors');
const authRoutes = require('./authRoutes');
const totpRoutes = require('./totpRoutes');
const deviceRoutes = require('./deviceRoutes');
const mfaRoutes = require('./mfaRoutes');

const app = express();
const PORT = process.env.PORT || 4000;

// Middlewares
app.use(cors());
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'qsafe-backend' });
});

// Auth routes
app.use('/api/auth', authRoutes);

// TOTP / QR provisioning routes
app.use('/api/totp', totpRoutes);

// Device registration / PQC key routes
app.use('/api/devices', deviceRoutes);

// MFA challenge routes
app.use('/api/mfa', mfaRoutes);

app.listen(PORT, () => {
  console.log(`QSafe backend listening on port ${PORT}`);
});

