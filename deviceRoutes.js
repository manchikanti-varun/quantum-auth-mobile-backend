/** Device registration (PQC key), list, revoke. */
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db } = require('./firebase');
const { authMiddleware } = require('./authMiddleware');

const router = express.Router();
const DEVICES_COLLECTION = 'devices';

router.get('/', authMiddleware, async (req, res) => {
  try {
    if (!db) {
      return res
        .status(500)
        .json({ message: 'Firestore is not configured on the server' });
    }
    const uid = req.user.uid;
    const snap = await db
      .collection(DEVICES_COLLECTION)
      .where('uid', '==', uid)
      .get();
    const sorted = snap.docs
      .map((d) => ({ id: d.id, ...d.data() }))
      .sort((a, b) => (a.createdAt || '').localeCompare(b.createdAt || ''));
    const seen = new Set();
    const unique = sorted.filter((d) => {
      if (seen.has(d.deviceId)) return false;
      seen.add(d.deviceId);
      return true;
    });
    const devices = unique.map((d, i) => ({
      deviceId: d.deviceId,
      platform: d.platform || null,
      createdAt: d.createdAt,
      lastSeenAt: d.lastSeenAt,
      trustedUntil: d.trustedUntil || null,
      deviceNumber: i + 1,
    }));
    return res.status(200).json({ devices });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to list devices' });
  }
});

router.post('/register', authMiddleware, async (req, res) => {
  try {
    if (!db) {
      return res
        .status(500)
        .json({ message: 'Firestore is not configured on the server' });
    }

    const uid = req.user.uid;
    const { deviceId, pqcPublicKey, pqcAlgorithm, kyberPublicKey, kyberAlgorithm, platform, pushToken, rememberDevice } =
      req.body;

    if (!deviceId || typeof deviceId !== 'string' || !deviceId.trim()) {
      return res.status(400).json({
        message: 'deviceId is required',
      });
    }
    const finalDeviceId = String(deviceId).trim();

    if (!pqcPublicKey || !pqcAlgorithm) {
      return res.status(400).json({
        message: 'pqcPublicKey and pqcAlgorithm are required',
      });
    }
    const now = new Date().toISOString();

    const trustedUntil = rememberDevice
      ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
      : null;

    const docId = `${uid}_${finalDeviceId}`;
    const docRef = db.collection(DEVICES_COLLECTION).doc(docId);

    const dupesSnap = await db
      .collection(DEVICES_COLLECTION)
      .where('uid', '==', uid)
      .where('deviceId', '==', finalDeviceId)
      .get();
    const toDelete = dupesSnap.docs.filter((d) => d.id !== docId);
    for (const d of toDelete) {
      await d.ref.delete();
    }

    const existing = await docRef.get();

    const payload = {
      uid,
      deviceId: finalDeviceId,
      pqcPublicKey,
      pqcAlgorithm,
      kyberPublicKey: kyberPublicKey || null,
      kyberAlgorithm: kyberAlgorithm || null,
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
    return res.status(500).json({ message: 'Failed to register device' });
  }
});

router.post('/revoke', authMiddleware, async (req, res) => {
  try {
    if (!db) return res.status(500).json({ message: 'Firestore is not configured' });
    const uid = req.user.uid;
    const { deviceId } = req.body;
    if (!deviceId) return res.status(400).json({ message: 'deviceId required' });

    const allDevicesSnap = await db.collection(DEVICES_COLLECTION).where('uid', '==', uid).get();
    if (allDevicesSnap.size <= 1) {
      return res.status(200).json({ message: 'Device trust revoked' });
    }

    const docRef = db.collection(DEVICES_COLLECTION).doc(`${uid}_${deviceId}`);
    const doc = await docRef.get();
    if (doc.exists) {
      await docRef.update({ trustedUntil: null, updatedAt: new Date().toISOString() });
    } else {
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

    // Add to revokedDevices so revoked device gets 401 on next API call
    const revokedRef = db.collection('users').doc(uid).collection('revokedDevices').doc(deviceId);
    await revokedRef.set({
      revokedAt: new Date().toISOString(),
      revokedBy: req.headers['x-device-id'] || req.body.currentDeviceId || uid,
    });

    return res.status(200).json({ message: 'Device trust revoked' });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to revoke' });
  }
});

module.exports = router;

