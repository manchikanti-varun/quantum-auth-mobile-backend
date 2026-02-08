/**
 * Firebase Admin SDK. Firestore for users, devices, MFA challenges.
 * Supports FIREBASE_PRIVATE_KEY with escaped \\n (e.g. Railway).
 */
const admin = require('firebase-admin');

let app;

if (!admin.apps.length) {
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  let privateKey = process.env.FIREBASE_PRIVATE_KEY;
  if (privateKey) {
    privateKey = privateKey.trim().replace(/^["']+|["']+$/g, '');
    privateKey = privateKey.replace(/\\n/g, '\n');
  }

  if (projectId && clientEmail && privateKey) {
    try {
      app = admin.initializeApp({
        credential: admin.credential.cert({
          projectId,
          clientEmail,
          privateKey,
        }),
      });
    } catch (e) {
      console.error('[Firebase] Init failed:', e.message);
    }
  } else {
    const missing = [];
    if (!projectId) missing.push('FIREBASE_PROJECT_ID');
    if (!clientEmail) missing.push('FIREBASE_CLIENT_EMAIL');
    if (!privateKey) missing.push('FIREBASE_PRIVATE_KEY');
    if (missing.length) console.error('[Firebase] Missing:', missing.join(', '));
  }
}

const db = app ? admin.firestore() : null;

module.exports = {
  admin,
  db,
};

