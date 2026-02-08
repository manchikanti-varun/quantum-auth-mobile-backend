/**
 * Verifies PQC JWT (Dilithium2), attaches req.user { uid, email }. Returns 401 if invalid.
 */
const pqcJwt = require('./services/pqcJwt');

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authorization required' });
  }

  const token = authHeader.slice(7);
  try {
    const decoded = pqcJwt.verify(token);
    req.user = { uid: decoded.uid, email: decoded.email };
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

module.exports = { authMiddleware };
