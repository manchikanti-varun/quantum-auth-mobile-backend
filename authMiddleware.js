/**
 * Auth middleware – verify JWT; attach req.user (uid, email).
 */
const jwt = require('jsonwebtoken');

const WEAK_SECRETS = ['dev_secret', 'change_me', 'your_jwt_secret', 'secret', 'test'];
function isWeakSecret(s) {
  if (!s || s.length < 32) return true;
  const lower = s.toLowerCase();
  return WEAK_SECRETS.some((w) => lower.includes(w));
}

function authMiddleware(req, res, next) {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    if (process.env.NODE_ENV === 'production') return res.status(500).json({ message: 'Server misconfiguration' });
    console.error('[authMiddleware] JWT_SECRET is not set');
    return res.status(500).json({ message: 'Server misconfiguration' });
  }
  if (process.env.NODE_ENV === 'production' && isWeakSecret(secret)) {
    return res.status(500).json({ message: 'Server misconfiguration' });
  }
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authorization required' });
  }

  const token = authHeader.slice(7);
  try {
    const decoded = jwt.verify(token, secret);
    req.user = { uid: decoded.uid, email: decoded.email };
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

module.exports = { authMiddleware };
