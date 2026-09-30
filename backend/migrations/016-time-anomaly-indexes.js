require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');

const POLICY_INDEXES = [
  [{ companyId: 1, departmentId: 1, enabled: 1, priority: 1 }, { name: 'time_policy_scope_priority' }],
  [{ companyId: 1, systemIds: 1, enabled: 1 }, { name: 'time_policy_agent_scope' }],
];

const EXCEPTION_INDEXES = [
  [{ companyId: 1, systemIds: 1, enabled: 1, startsAt: 1, expiresAt: 1 }, { name: 'time_exception_active_agent' }],
  [{ companyId: 1, expiresAt: -1 }, { name: 'time_exception_expiry' }],
];

async function createIndexes(collection, indexes) {
  const existing = await collection.indexes().catch(() => []);
  const names = [];
  for (const [keys, options] of indexes) {
    const equivalent = existing.find(index => JSON.stringify(index.key) === JSON.stringify(keys));
    names.push(equivalent?.name || await collection.createIndex(keys, options));
  }
  return names;
}

async function run() {
  await connectDB();
  const db = mongoose.connection.db;
  const backfill = await db.collection('alerts').updateMany({
    isSynthetic: { $ne: true },
    $or: [
      { source: 'time_anomaly' },
      { ruleId: { $regex: '^TIME_' } },
      { 'rawEvent.source': 'time_anomaly' },
      { 'rawEvent.rule_id': { $regex: '^TIME_' } },
    ],
  }, { $addToSet: { capabilityIds: 22 } });
  const policyIndexes = await createIndexes(db.collection('timeanomalypolicies'), POLICY_INDEXES);
  const exceptionIndexes = await createIndexes(db.collection('timeanomalyexceptions'), EXCEPTION_INDEXES);
  console.log(JSON.stringify({ matched: backfill.matchedCount, backfilled: backfill.modifiedCount, policyIndexes, exceptionIndexes }));
}

if (require.main === module) {
  run()
    .catch(error => {
      console.error(error);
      process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
}

module.exports = { run, POLICY_INDEXES, EXCEPTION_INDEXES };
