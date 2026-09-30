'use strict';

require('dotenv').config();
const mongoose = require('mongoose');
const fs = require('node:fs');
const path = require('node:path');

const NETWORK_SUMMARY_RULES = [
  'NET_CONNECTION_SUMMARY',
  'NET_DNS_SUMMARY',
  'NET_EXPOSURE_SUMMARY',
  'NET_THREAT_INTEL_SUMMARY',
];

async function main() {
  const apply = process.argv.includes('--apply');
  await mongoose.connect(process.env.MONGO_URI);
  const collection = mongoose.connection.db.collection('alerts');
  const cursor = collection.find({
    ruleId: { $in: NETWORK_SUMMARY_RULES },
    'rawEvent.timestamp': { $type: 'string' },
  }, { projection: { createdAt: 1, 'rawEvent.timestamp': 1 } });

  let inspected = 0;
  let skipped = 0;
  const repairs = [];
  for await (const row of cursor) {
    inspected += 1;
    const observedAt = new Date(row.rawEvent.timestamp);
    if (Number.isNaN(observedAt.getTime())) {
      skipped += 1;
      continue;
    }
    if (row.createdAt instanceof Date && row.createdAt.getTime() === observedAt.getTime()) continue;
    repairs.push({
      id: row._id,
      previousCreatedAt: row.createdAt,
      sourceCreatedAt: observedAt,
    });
  }

  if (!apply) {
    console.log(JSON.stringify({ inspected, wouldRepair: repairs.length, skipped, apply: false }));
    await mongoose.disconnect();
    return;
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupPath = path.join('/tmp', `soc-network-event-times-${stamp}.json`);
  fs.writeFileSync(backupPath, JSON.stringify(repairs.map(row => ({
    _id: String(row.id),
    createdAt: row.previousCreatedAt,
  }))), { mode: 0o600 });

  let repaired = 0;
  for (let index = 0; index < repairs.length; index += 500) {
    const operations = repairs.slice(index, index + 500).map(row => ({
      updateOne: {
        filter: { _id: row.id },
        update: { $set: { createdAt: row.sourceCreatedAt } },
      },
    }));
    const result = await collection.bulkWrite(operations, { ordered: false });
    repaired += result.modifiedCount;
  }
  console.log(JSON.stringify({ inspected, repaired, skipped, apply: true, backupPath }));
  await mongoose.disconnect();
}

main().catch(async error => {
  console.error(error.message);
  await mongoose.disconnect().catch(() => {});
  process.exit(1);
});
