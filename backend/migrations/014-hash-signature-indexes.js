require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');

// Alerts already have company/capability/time indexes. Reuse them because the
// long-lived alerts collection can be at MongoDB's per-collection index limit.
const ALERT_INDEXES = [];

const BASELINE_INDEXES = [
  [{ companyId: 1, endpointId: 1, filePath: 1 }, { name: 'hash_baseline_identity', unique: true }],
  [{ companyId: 1, sha256: 1 }, { name: 'hash_baseline_sha256' }],
];

async function createIndexes(collection, indexes) {
  const existing = await collection.indexes();
  const names = [];
  for (const [keys, options] of indexes) {
    const equivalent = existing.find(index => JSON.stringify(index.key) === JSON.stringify(keys));
    if (equivalent) {
      if (options.unique === true && equivalent.unique !== true) {
        throw new Error(`Existing index ${equivalent.name} must be unique before hash/signature migration can continue`);
      }
      names.push(equivalent.name);
    } else {
      names.push(await collection.createIndex(keys, options));
    }
  }
  return names;
}

async function run() {
  await connectDB();
  const db = mongoose.connection.db;
  const alertsCollection = db.collection('alerts');
  const backfill = await alertsCollection.updateMany({
    isSynthetic: { $ne: true },
    $or: [
      { fileHash: { $exists: true, $ne: '' } },
      { sha256: { $exists: true, $ne: '' } },
      { processExecutableSha256: { $exists: true, $ne: '' } },
      { signatureStatus: { $exists: true, $nin: ['', null] } },
      { 'rawEvent.file_hash': { $exists: true, $ne: '' } },
      { 'rawEvent.sha256': { $exists: true, $ne: '' } },
      { 'rawEvent.executable_sha256': { $exists: true, $ne: '' } },
      { 'rawEvent.signature_status': { $exists: true, $nin: ['', null] } },
    ],
  }, { $addToSet: { capabilityIds: 25 } });
  const [alertIndexes, baselineIndexes] = await Promise.all([
    createIndexes(alertsCollection, ALERT_INDEXES),
    createIndexes(db.collection('hashsignaturebaselines'), BASELINE_INDEXES),
  ]);
  console.log(JSON.stringify({
    backfilled: backfill.modifiedCount,
    matched: backfill.matchedCount,
    alertIndexes,
    baselineIndexes,
  }));
}

if (require.main === module) {
  run()
    .catch(error => {
      console.error(error);
      process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
}

module.exports = { run, ALERT_INDEXES, BASELINE_INDEXES };
