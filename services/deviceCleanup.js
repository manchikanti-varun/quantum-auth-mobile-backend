/**
 * Removes duplicate device records (same uid+deviceId). Keeps most recent per key.
 * @module services/deviceCleanup
 */
const { db } = require('../firebase');

const DEVICES_COLLECTION = 'devices';

async function cleanupDuplicateDevices() {
  if (!db) return { deleted: 0 };

  const snap = await db.collection(DEVICES_COLLECTION).get();
  const docs = snap.docs;

  const byKey = {};
  for (const doc of docs) {
    const d = doc.data();
    const key = `${d.uid}_${d.deviceId}`;
    if (!byKey[key]) byKey[key] = [];
    byKey[key].push({ ref: doc.ref, ...d, _id: doc.id });
  }

  let deleted = 0;
  for (const [key, group] of Object.entries(byKey)) {
    if (group.length <= 1) continue;
    group.sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
    for (let i = 1; i < group.length; i++) {
      await group[i].ref.delete();
      deleted++;
    }
  }

  return { deleted };
}

module.exports = { cleanupDuplicateDevices };
