/**
 * Firebase – Firestore init; handles Railway env (quoted private key).
 */
const admin = require('firebase-admin');

let app;

if (!admin.apps.length) {
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  let privateKey = process.env.FIREBASE_PRIVATE_KEY;
  if (privateKey) {
    // Railway and many hosts: value may be wrapped in quotes and use literal \n
    privateKey = privateKey.trim().replace(/^["']|["']$/g, '');
    privateKey = privateKey.replace(/\\n/g, '\n');
  }

  if (!projectId || !clientEmail || !privateKey) {
    if (process.env.NODE_ENV !== 'production') {
      console.warn('Firebase environment variables are not fully set. Firestore will not be available.');
    }
  } else {
    try {
      app = admin.initializeApp({
        credential: admin.credential.cert({
          projectId,
          clientEmail,
          privateKey,
        }),
      });
    } catch (e) {
      if (process.env.NODE_ENV === 'production') {
        console.error('Firebase init failed');
      } else {
        console.error('Firebase init failed (check FIREBASE_PRIVATE_KEY format):', e.message);
      }
    }
  }
}

const db = app ? admin.firestore() : null;

module.exports = {
  admin,
  db,
};

