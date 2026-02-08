/**
 * TOTP routes. Provision QR for TOTP enrollment. Requires JWT.
 * @module totpRoutes
 */
const express = require('express');
const QRCode = require('qrcode');
const crypto = require('crypto');
const { authMiddleware } = require('./authMiddleware');

const router = express.Router();

function randomBase32(len = 16) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = crypto.randomBytes(len);
  let result = '';
  for (let i = 0; i < len; i++) {
    result += alphabet[bytes[i] % 32];
  }
  return result;
}

router.post('/provision', authMiddleware, async (req, res) => {
  try {
    const { issuer, accountName, secret: secretParam } = req.body;

    if (!issuer || !accountName) {
      return res
        .status(400)
        .json({ message: 'issuer and accountName are required' });
    }

    const secret = secretParam || randomBase32();

    const label = `${issuer}:${accountName}`;
    const otpauth = `otpauth://totp/${encodeURIComponent(
      label,
    )}?secret=${encodeURIComponent(
      secret,
    )}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

    const qrDataUrl = await QRCode.toDataURL(otpauth);

    return res.status(200).json({
      otpauth,
      qrDataUrl,
    });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to generate TOTP QR' });
  }
});

module.exports = router;

