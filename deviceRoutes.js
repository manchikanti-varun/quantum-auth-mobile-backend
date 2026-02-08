/**
 * Device routes – register device, PQC public key; list devices; delete.
 */
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db } = require('./firebase');
const { authMiddleware } = require('./authMiddleware');

const router = express.Router();
const DEVICES_COLLECTION = 'devices';

// Register or update a device's PQC public key for a user (requires JWT)
router.post('/register', authMiddleware, async (req, res) => {
  try {
    if (!db) {
      return res
        .status(500)
        .json({ message: 'Firestore is not configured on the server' });
    }

    const uid = req.user.uid;
    const { deviceId, pqcPublicKey, pqcAlgorithm, platform, pushToken, rememberDevice } =
      req.body;

    if (!pqcPublicKey || !pqcAlgorithm) {
      return res.status(400).json({
        message: 'pqcPublicKey and pqcAlgorithm are required',
      });
    }

    const finalDeviceId = deviceId || uuidv4();
    const now = new Date().toISOString();

    const trustedUntil = rememberDevice
      ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
      : null;

    // Use deterministic doc ID (uid_deviceId) to prevent duplicates from concurrent register calls
    const docId = `${uid}_${finalDeviceId}`;
    const docRef = db.collection(DEVICES_COLLECTION).doc(docId);
    const existing = await docRef.get();

    const payload = {
      uid,
      deviceId: finalDeviceId,
      pqcPublicKey,
      pqcAlgorithm,
      platform: platform || null,
      pushToken: pushToken || null,
      trustedUntil: rememberDevice ? trustedUntil : null,
      updatedAt: now,
      lastSeenAt: now,
    };

    if (!existing.exists) {
      await docRef.set({ ...payload, createdAt: now });
    } else {
      const update = { ...payload };
      if (!rememberDevice) update.trustedUntil = null;
      await docRef.update(update);
    }

    return res.status(200).json({
      deviceId: finalDeviceId,
      message: 'Device registered successfully',
    });
  } catch (err) {
    console.error('Error in /api/devices/register:', err);
    return res.status(500).json({ message: 'Failed to register device' });
  }
});

// Revoke this device's trust – next login will require MFA approval on another device
router.post('/revoke', authMiddleware, async (req, res) => {
  try {
    if (!db) return res.status(500).json({ message: 'Firestore is not configured' });
    const uid = req.user.uid;
    const { deviceId } = req.body;
    if (!deviceId) return res.status(400).json({ message: 'deviceId required' });

    const docRef = db.collection(DEVICES_COLLECTION).doc(`${uid}_${deviceId}`);
    const doc = await docRef.get();
    if (doc.exists) {
      await docRef.update({ trustedUntil: null, updatedAt: new Date().toISOString() });
    } else {
      // Fallback for legacy docs with auto-generated IDs
      const snap = await db
        .collection(DEVICES_COLLECTION)
        .where('uid', '==', uid)
        .where('deviceId', '==', deviceId)
        .limit(1)
        .get();
      if (!snap.empty) {
        await snap.docs[0].ref.update({ trustedUntil: null, updatedAt: new Date().toISOString() });
      }
    }
    return res.status(200).json({ message: 'Device trust revoked' });
  } catch (err) {
    console.error('Error in /api/devices/revoke:', err);
    return res.status(500).json({ message: 'Failed to revoke' });
  }
});

module.exports = router;

