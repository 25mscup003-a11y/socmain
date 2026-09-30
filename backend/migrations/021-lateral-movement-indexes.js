'use strict';

require('dotenv').config();
const mongoose = require('mongoose');

async function run() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
  await mongoose.connect(process.env.MONGO_URI);
  const alerts = mongoose.connection.collection('alerts');
  const indexes = [
    [{ companyId: 1, capabilityId: 1, createdAt: -1 }, { name: 'lateral_capability_time' }],
    [{ companyId: 1, capabilityIds: 1, createdAt: -1 }, { name: 'lateral_capabilities_time' }],
  ];
  const existing = await alerts.indexes();
  let created = 0;
  let reused = 0;
  for (const [keys, options] of indexes) {
    const equivalent = existing.find(index => JSON.stringify(index.key) === JSON.stringify(keys));
    if (equivalent) {
      reused += 1;
      console.log(`Reusing index ${equivalent.name} for ${options.name}`);
      continue;
    }
    await alerts.createIndex(keys, options);
    created += 1;
  }
  console.log(`Lateral movement indexes ready: ${created} created, ${reused} reused`);
  await mongoose.disconnect();
}

run().catch(async error => {
  console.error(error.message);
  try { await mongoose.disconnect(); } catch (_) { /* no-op */ }
  process.exitCode = 1;
});
