'use strict';

require('dotenv').config();
const mongoose = require('mongoose');

async function run() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
  await mongoose.connect(process.env.MONGO_URI);
  const alerts = mongoose.connection.collection('alerts');
  const indexes = [
    [{ companyId: 1, departmentId: 1, capabilityIds: 1, authResult: 1, createdAt: -1 }, { name: 'auth_scope_result_time' }],
    [{ companyId: 1, capabilityIds: 1, username: 1, riskScore: -1, createdAt: -1 }, { name: 'auth_user_risk_time' }],
    [{ companyId: 1, capabilityIds: 1, srcip: 1, authType: 1, createdAt: -1 }, { name: 'auth_source_protocol_time' }],
  ];
  const existing = await alerts.indexes(); let created = 0;
  for (const [keys, options] of indexes) {
    if (existing.some(index => JSON.stringify(index.key) === JSON.stringify(keys))) continue;
    await alerts.createIndex(keys, options); created += 1;
  }
  console.log(`Authentication monitoring ready: ${created} indexes created`);
  await mongoose.disconnect();
}

run().catch(async error => {
  console.error(error.message);
  try { await mongoose.disconnect(); } catch (_) { /* no-op */ }
  process.exitCode = 1;
});

module.exports = { run };
