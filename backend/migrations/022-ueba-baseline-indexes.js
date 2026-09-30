'use strict';

require('dotenv').config();
const mongoose = require('mongoose');

async function ensureIndex(collection, keys, options) {
  const existing = await collection.indexes();
  const equivalent = existing.find(index => JSON.stringify(index.key) === JSON.stringify(keys));
  if (equivalent) {
    console.log(`Reusing ${collection.collectionName}.${equivalent.name}`);
    return false;
  }
  await collection.createIndex(keys, options);
  return true;
}

async function run() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
  await mongoose.connect(process.env.MONGO_URI);
  const db = mongoose.connection;
  const created = [];
  if (await ensureIndex(db.collection('systems'),
    { companyId: 1, departmentId: 1, isActive: 1, lastSeen: -1 },
    { name: 'ueba_agent_scope_last_seen' })) created.push('systems.ueba_agent_scope_last_seen');
  // Reuse the existing capability/time index. The alerts collection can be at
  // MongoDB's 64-index limit, so this migration must not add another index.
  await ensureIndex(db.collection('alerts'),
    { companyId: 1, capabilityIds: 1, createdAt: -1 },
    { name: 'companyId_1_capabilityIds_1_createdAt_-1' });
  console.log(`UEBA baseline indexes ready: ${created.length} created`);
  await mongoose.disconnect();
}

run().catch(async error => {
  console.error(error.message);
  try { await mongoose.disconnect(); } catch (_) { /* no-op */ }
  process.exitCode = 1;
});
