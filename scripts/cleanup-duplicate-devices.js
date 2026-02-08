/**
 * Cleanup duplicate device records (CLI).
 * Run: node scripts/cleanup-duplicate-devices.js
 */
require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });
const { cleanupDuplicateDevices } = require('../services/deviceCleanup');

cleanupDuplicateDevices()
  .then(({ deleted }) => console.log(`Done. Removed ${deleted} duplicate device(s).`))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
