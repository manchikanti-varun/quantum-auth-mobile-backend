/**
 * Firebase Admin SDK initialization. Firestore for users, devices, MFA challenges.
 * Handles Railway env (quoted FIREBASE_PRIVATE_KEY with escaped newlines).
 * @module firebase
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
    } catch (e) {}
  }
}

const db = app ? admin.firestore() : null;

module.exports = {
  admin,
  db,
};

