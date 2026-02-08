/**
 * MFA routes. Pending challenges, resolve with PQC signature, generate backup OTP, history.
 * @module mfaRoutes
 */
const express = require('express');
const { db } = require('./firebase');
const { Expo } = require('expo-server-sdk');
const { authMiddleware } = require('./authMiddleware');
const {
  DilithiumLevel,
  DilithiumPublicKey,
  DilithiumSignature,
} = require('@asanrom/dilithium');

const router = express.Router();
const MFA_CHALLENGES_COLLECTION = 'mfaChallenges';
const expo = new Expo();

router.get('/pending', authMiddleware, async (req, res) => {
  try {
    if (!db) {
      return res
        .status(500)
        .json({ message: 'Firestore is not configured on the server' });
    }

    const { deviceId } = req.query;
    if (!deviceId) {
      return res.status(400).json({ message: 'deviceId is required' });
    }

    const uid = req.user.uid;

    const revokedDoc = await db.collection('users').doc(uid).collection('revokedDevices').doc(deviceId).get();
    if (revokedDoc.exists) {
      return res.status(401).json({ message: 'This device has been revoked. Please log in again.' });
    }

    // Verify device belongs to authenticated user
    const deviceSnap = await db
      .collection('devices')
      .where('deviceId', '==', deviceId)
      .where('uid', '==', uid)
      .limit(1)
      .get();

    if (deviceSnap.empty) {
      return res.status(404).json({ message: 'Device not found' });
    }

    // Find pending challenge for this user
    const challengeSnap = await db
      .collection(MFA_CHALLENGES_COLLECTION)
      .where('uid', '==', uid)
      .where('status', '==', 'pending')
      .limit(1)
      .get();

    if (challengeSnap.empty) {
      return res.status(200).json({ challenge: null });
    }

    const challenge = challengeSnap.docs[0].data();

    if (challenge.requestingDeviceId === deviceId) {
      return res.status(200).json({ challenge: null });
    }

    const allDevicesSnap = await db
      .collection('devices')
      .where('uid', '==', uid)
      .get();
    const sorted = allDevicesSnap.docs
      .map((d) => d.data())
      .sort((a, b) => (a.createdAt || '').localeCompare(b.createdAt || ''));
    const firstDeviceId = sorted[0]?.deviceId;
    if (firstDeviceId !== deviceId) {
      return res.status(200).json({ challenge: null });
    }

    // Check expiration
    if (new Date(challenge.expiresAt) < new Date()) {
      await challengeSnap.docs[0].ref.update({ status: 'expired' });
      return res.status(200).json({ challenge: null });
    }

    return res.status(200).json({ challenge });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to check pending challenges' });
  }
});

router.post('/resolve', authMiddleware, async (req, res) => {
  try {
    if (!db) {
      return res
        .status(500)
        .json({ message: 'Firestore is not configured on the server' });
    }

    const { challengeId, decision, signature, deviceId, flagged } = req.body;

    if (!challengeId || !decision || !signature) {
      return res.status(400).json({
        message: 'challengeId, decision, and signature are required',
      });
    }

    if (decision !== 'approved' && decision !== 'denied') {
      return res.status(400).json({ message: 'decision must be approved or denied' });
    }

    const challengeSnap = await db
      .collection(MFA_CHALLENGES_COLLECTION)
      .where('challengeId', '==', challengeId)
      .limit(1)
      .get();

    if (challengeSnap.empty) {
      return res.status(404).json({ message: 'Challenge not found' });
    }

    const challengeDoc = challengeSnap.docs[0];
    const challenge = challengeDoc.data();

    if (challenge.status !== 'pending') {
      return res.status(400).json({
        message: `Challenge already ${challenge.status}`,
      });
    }

    if (new Date(challenge.expiresAt) < new Date()) {
      await challengeDoc.ref.update({ status: 'expired' });
      return res.status(400).json({ message: 'Challenge has expired' });
    }

    if (challenge.uid !== req.user.uid) {
      return res.status(403).json({ message: 'Challenge does not belong to you' });
    }
    let deviceDoc = null;
    if (deviceId) {
      const deviceSnap = await db
        .collection('devices')
        .where('deviceId', '==', deviceId)
        .where('uid', '==', req.user.uid)
        .limit(1)
        .get();
      if (deviceSnap.empty) {
        return res.status(403).json({ message: 'Device does not belong to you' });
      }
      deviceDoc = deviceSnap.docs[0].data();
    }

    if (!/^[a-fA-F0-9]+$/.test(signature) || signature.length < 64) {
      return res.status(400).json({ message: 'Invalid signature format' });
    }

    if (deviceDoc?.pqcAlgorithm === 'Dilithium2' && deviceDoc?.pqcPublicKey) {
      try {
        const level = DilithiumLevel.get(2);
        const publicKey = DilithiumPublicKey.fromHex(deviceDoc.pqcPublicKey, level);
        const sig = DilithiumSignature.fromHex(signature, level);
        const message = `${challengeId}:${decision}`;
        const messageBytes = Buffer.from(message, 'utf8');
        const valid = sig.verify(messageBytes, publicKey);
        if (!valid) {
          return res.status(400).json({ message: 'Invalid PQC signature' });
        }
      } catch (err) {
        return res.status(400).json({ message: 'Signature verification failed' });
      }
    } else if (deviceDoc?.pqcAlgorithm === 'Mock-Dilithium') {
    } else if (deviceId && (!deviceDoc?.pqcPublicKey || !deviceDoc?.pqcAlgorithm)) {
      return res.status(400).json({
        message: 'Device missing PQC keys. Please log in again to re-register.',
      });
    } else if (signature.length > 1000 && !deviceDoc?.pqcPublicKey) {
      return res.status(400).json({
        message: 'deviceId required for PQC signature verification',
      });
    }

    await challengeDoc.ref.update({
      status: decision,
      resolvedAt: new Date().toISOString(),
      deviceId: deviceId || null,
      signature: signature || null,
    });

    await db.collection('users').doc(challenge.uid).collection('mfaHistory').add({
      challengeId,
      decision,
      deviceId: deviceId || null,
      timestamp: new Date().toISOString(),
      flagged: !!flagged,
      context: challenge.context || {},
    });

    return res.status(200).json({
      challengeId,
      status: decision,
      message: `Challenge ${decision}`,
    });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to resolve MFA challenge' });
  }
});

router.post('/generate-code', authMiddleware, async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Firestore is not configured' });
    }
    const { challengeId } = req.body;
    if (!challengeId) {
      return res.status(400).json({ message: 'challengeId is required' });
    }
    const uid = req.user.uid;

    const challengeSnap = await db
      .collection(MFA_CHALLENGES_COLLECTION)
      .where('challengeId', '==', challengeId)
      .limit(1)
      .get();

    if (challengeSnap.empty) {
      return res.status(404).json({ message: 'Challenge not found' });
    }

    const challengeDoc = challengeSnap.docs[0];
    const challenge = challengeDoc.data();

    if (challenge.uid !== uid || challenge.status !== 'pending') {
      return res.status(403).json({ message: 'Challenge not yours or already resolved' });
    }
    if (new Date(challenge.expiresAt) < new Date()) {
      return res.status(400).json({ message: 'Challenge expired' });
    }

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const codeExpiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    await challengeDoc.ref.update({
      oneTimeCode: code,
      oneTimeCodeExpiresAt: codeExpiresAt,
    });

    return res.status(200).json({ code, expiresIn: 300 });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to generate code' });
  }
});


router.get('/history', authMiddleware, async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Firestore is not configured' });
    }
    const uid = req.user?.uid;
    if (!uid) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const snap = await db
      .collection('users')
      .doc(uid)
      .collection('mfaHistory')
      .orderBy('timestamp', 'desc')
      .limit(50)
      .get();
    const items = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
    return res.status(200).json({ history: items });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to get MFA history' });
  }
});

module.exports = router;
