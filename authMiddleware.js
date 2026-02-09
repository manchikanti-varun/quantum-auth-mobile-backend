/**
 * Verifies PQC JWT (Dilithium2), attaches req.user { uid, email }. Returns 401 if invalid.
 * If X-Device-Id header is present, checks revokedDevices so revoked devices get 401 immediately.
 */
const pqcJwt = require('./services/pqcJwt');
const { db } = require('./firebase');

async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authorization required' });
  }

  const token = authHeader.slice(7);
  try {
    const decoded = pqcJwt.verify(token);
    req.user = { uid: decoded.uid, email: decoded.email };

    const deviceId = req.headers['x-device-id'];
    if (deviceId && db) {
      const revokedDoc = await db.collection('users').doc(decoded.uid).collection('revokedDevices').doc(deviceId).get();
      if (revokedDoc.exists) {
        return res.status(401).json({ message: 'This device has been revoked. Please log in again.' });
      }
    }
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

module.exports = { authMiddleware };
