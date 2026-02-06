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
    const { deviceId, pqcPublicKey, pqcAlgorithm, platform, pushToken } =
      req.body;

    if (!pqcPublicKey || !pqcAlgorithm) {
      return res.status(400).json({
        message: 'pqcPublicKey and pqcAlgorithm are required',
      });
    }

    const finalDeviceId = deviceId || uuidv4();
    const now = new Date().toISOString();

    const querySnap = await db
      .collection(DEVICES_COLLECTION)
      .where('uid', '==', uid)
      .where('deviceId', '==', finalDeviceId)
      .limit(1)
      .get();

    if (querySnap.empty) {
      await db.collection(DEVICES_COLLECTION).add({
        uid,
        deviceId: finalDeviceId,
        pqcPublicKey,
        pqcAlgorithm,
        platform: platform || null,
        pushToken: pushToken || null,
        createdAt: now,
        updatedAt: now,
        lastSeenAt: now,
      });
    } else {
      const docRef = querySnap.docs[0].ref;
      await docRef.update({
        pqcPublicKey,
        pqcAlgorithm,
        platform: platform || null,
        pushToken: pushToken || null,
        updatedAt: now,
        lastSeenAt: now,
      });
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

module.exports = router;

