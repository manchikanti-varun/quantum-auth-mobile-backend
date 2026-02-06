const express = require('express');
const { v4: uuidv4 } = require('uuid');
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

// Create an MFA challenge and send push notification
router.post('/challenge', async (req, res) => {
  try {
    if (!db) {
      return res
        .status(500)
        .json({ message: 'Firestore is not configured on the server' });
    }

    const { uid, context } = req.body; // context: { ip, userAgent, etc }

    if (!uid) {
      return res.status(400).json({ message: 'uid is required' });
    }

    // Find user's devices (polling-based, so pushToken not required)
    const devicesSnap = await db
      .collection('devices')
      .where('uid', '==', uid)
      .get();

    if (devicesSnap.empty) {
      return res.status(404).json({
        message: 'No registered devices found for this user',
      });
    }

    const challengeId = uuidv4();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    // Create challenge document
    await db.collection(MFA_CHALLENGES_COLLECTION).add({
      challengeId,
      uid,
      status: 'pending', // pending | approved | denied | expired
      context: context || {},
      expiresAt: expiresAt.toISOString(),
      createdAt: new Date().toISOString(),
    });

    // Send push notifications to all user's devices
    const messages = [];
    devicesSnap.docs.forEach((doc) => {
      const device = doc.data();
      if (Expo.isExpoPushToken(device.pushToken)) {
        messages.push({
          to: device.pushToken,
          sound: 'default',
          title: 'QSafe Login Request',
          body: `Login attempt detected. Tap to approve or deny.`,
          data: {
            type: 'mfa_challenge',
            challengeId,
            context,
          },
        });
      }
    });

    if (messages.length > 0) {
      const chunks = expo.chunkPushNotifications(messages);
      for (const chunk of chunks) {
        try {
          await expo.sendPushNotificationsAsync(chunk);
        } catch (error) {
          console.error('Error sending push notification:', error);
        }
      }
    }

    return res.status(201).json({
      challengeId,
      message: 'MFA challenge created and push notifications sent',
      expiresAt: expiresAt.toISOString(),
    });
  } catch (err) {
    console.error('Error in /api/mfa/challenge:', err);
    return res.status(500).json({ message: 'Failed to create MFA challenge' });
  }
});

// Get pending challenge for a device (polling endpoint, requires JWT)
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

    // Find pending challenge for this user (get most recent)
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

    // Check expiration
    if (new Date(challenge.expiresAt) < new Date()) {
      await challengeSnap.docs[0].ref.update({ status: 'expired' });
      return res.status(200).json({ challenge: null });
    }

    return res.status(200).json({ challenge });
  } catch (err) {
    console.error('Error in /api/mfa/pending:', err);
    return res.status(500).json({ message: 'Failed to check pending challenges' });
  }
});

// Resolve an MFA challenge (approve/deny, requires JWT)
router.post('/resolve', authMiddleware, async (req, res) => {
  try {
    if (!db) {
      return res
        .status(500)
        .json({ message: 'Firestore is not configured on the server' });
    }

    const { challengeId, decision, signature, deviceId } = req.body;

    if (!challengeId || !decision || !signature) {
      return res.status(400).json({
        message: 'challengeId, decision, and signature are required',
      });
    }

    if (decision !== 'approved' && decision !== 'denied') {
      return res.status(400).json({ message: 'decision must be approved or denied' });
    }

    // Find challenge
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

    // Check expiration
    if (new Date(challenge.expiresAt) < new Date()) {
      await challengeDoc.ref.update({ status: 'expired' });
      return res.status(400).json({ message: 'Challenge has expired' });
    }

    // Verify device belongs to authenticated user and challenge is for that user
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

    // Validate signature format: hex string
    // Mock-Dilithium: 64 chars (SHA256); Dilithium2: ~2420 bytes = 4840 hex chars
    if (!/^[a-fA-F0-9]+$/.test(signature) || signature.length < 64) {
      return res.status(400).json({ message: 'Invalid signature format' });
    }

    // PQC signature verification
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
        console.error('PQC verification error:', err);
        return res.status(400).json({ message: 'Signature verification failed' });
      }
    } else if (deviceDoc?.pqcAlgorithm === 'Mock-Dilithium') {
      // Legacy mock: trust JWT + device ownership; signature stored for audit
    } else if (deviceId && (!deviceDoc?.pqcPublicKey || !deviceDoc?.pqcAlgorithm)) {
      return res.status(400).json({
        message: 'Device missing PQC keys. Please log in again to re-register.',
      });
    } else if (signature.length > 1000 && !deviceDoc?.pqcPublicKey) {
      // Dilithium2-style signature without device context - cannot verify
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

    return res.status(200).json({
      challengeId,
      status: decision,
      message: `Challenge ${decision}`,
    });
  } catch (err) {
    console.error('Error in /api/mfa/resolve:', err);
    return res.status(500).json({ message: 'Failed to resolve MFA challenge' });
  }
});

module.exports = router;
