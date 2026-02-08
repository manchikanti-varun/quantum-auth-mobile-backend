/**
 * Remove duplicate device records (same uid+deviceId).
 * Keeps the most recent doc per uid+deviceId, deletes the rest.
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
      if (process.env.NODE_ENV !== 'production') {
        console.log(`[DeviceCleanup] Deleted duplicate: ${key} (doc ${group[i]._id})`);
      }
    }
  }

  if (deleted > 0) {
    console.log(`[DeviceCleanup] Removed ${deleted} duplicate device(s)`);
  }
  return { deleted };
}

module.exports = { cleanupDuplicateDevices };
